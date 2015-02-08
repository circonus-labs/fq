/*
 * Copyright (c) 2013 OmniTI Computer Consulting, Inc.
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <ck_pr.h>

#include <sqlite3.h>
#include <openssl/sha.h>

#include "fq.h"
#include "fqd.h"
#include "fqd_private.h"
#include "fq_dtrace.h"

#define CONFIG_RING_SIZE 3
#define CONFIG_ROTATE_NS (100*1000*1000) /*100ms*/
#define DEFAULT_CLIENT_CNT 128

const char *fq_version_string = FQ_VERSION;
const char *fqd_config_path = VARLIBFQDIR "/fqd.sqlite";
const char *fqd_queue_path = VARLIBFQDIR "/queues";

/* A ring of three configs
 *
 * [cycleout] [currentread] [currentwrite]
 *
 */

fqd_exchange_stats_t global_counters = { 0, 0, 0, 0, 0, 0 };

struct fqd_config {
  uint64_t gen;
  int n_clients;
  remote_client **clients;
  int n_queues;
  fqd_queue **queues;
  int n_exchanges;
  fqd_exchange **exchanges;
};

static sqlite3 *configdb = NULL;
static uint64_t global_gen = 0;
static uint32_t global_nodeid = 0;
uint32_t fqd_config_get_nodeid() { return global_nodeid; }

typedef struct fqd_config_ref {
  fqd_config        config;
  uint32_t          readers;
  uint32_t          dirty;
} fqd_config_ref;

static struct {
  fqd_config_ref    configs[CONFIG_RING_SIZE];

  /* protected by writelock */
  pthread_mutex_t   writelock;
  uint32_t          current_config;
  /* end writelock protected things */
} global_config;

#define FQGC(i) global_config.configs[i]

static void *config_rotation(void *);
static void setup_config(void);
static void setup_initial_config(void);

void
fqd_config_init(uint32_t nodeid, const char *config_path, const char *qpath) {
  int i;
  pthread_t t;
  pthread_attr_t attr;

  global_nodeid = nodeid;
  if(config_path) fqd_config_path = config_path;
  if(qpath) fqd_queue_path = qpath;
  memset(&global_config, 0, sizeof(global_config));

  pthread_mutex_init(&global_config.writelock, NULL);

  for(i=0;i<CONFIG_RING_SIZE;i++)
    global_config.configs[i].config.gen = ++global_gen;

  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_create(&t, &attr, config_rotation, NULL);

  setup_config();
}

extern fqd_config *
fqd_config_get() {
  int lcc = global_config.current_config;
  ck_pr_inc_32(&global_config.configs[lcc].readers);
  return (fqd_config *)&global_config.configs[lcc];
}

extern void
fqd_config_release(fqd_config *fake) {
  fqd_config_ref *real = (fqd_config_ref *)fake;
  ck_pr_dec_32(&real->readers);
}

int
fqd_config_construct_queue_path(char *path, size_t pathlen,
                                fq_rk *qname) {
  int i;
  char *qout, qhex[MAX_RK_LEN * 2 + 1];
  qout = qhex;
  for(i=0; i<qname->len; i++) {
    snprintf(qout, 3, "%02x", (int)qname->name[i]);
    qout += 2;
  }
  *qout = '\0';
  return snprintf(path, pathlen, "%s/%s", fqd_queue_path, qhex);
}

fqd_queue *
fqd_config_get_registered_queue(fqd_config *c, fq_rk *qname) {
  int i;
  fqd_queue *q = NULL;
  for(i=0;i<c->n_queues;i++) {
    if(c->queues[i] && fq_rk_cmp(qname, fqd_queue_name(c->queues[i])) == 0) {
      q = c->queues[i];
      break;
    }
  }
  fq_debug(FQ_DEBUG_CONFIG, "referencing queue -> (%p)\n", (void *)q);
  return q;
}

remote_client *
fqd_config_get_registered_client(fqd_config *c, fq_rk *key) {
  int i;
  remote_client *client = NULL;
  for(i=0;i<c->n_clients;i++) {
    if(c->clients[i] && fq_rk_cmp(key, &c->clients[i]->key) == 0) {
      client = c->clients[i];
      break;
    }
  }
  return client;
}

fqd_exchange *
fqd_config_get_exchange(fqd_config *c, fq_rk *exchange) {
  int i;
  for(i=0;i<c->n_exchanges;i++)
    if(c->exchanges[i] &&
       fq_rk_cmp(exchange, &c->exchanges[i]->exchange) == 0)
      return c->exchanges[i];
  return NULL;
}

/* This is static b/c no one but us should be calling it
 * we we need to hold a lock whilst calling it.
 */
static fqd_exchange *
fqd_config_add_exchange(fqd_config *c, fq_rk *exchange) {
  int i;
  for(i=0;i<c->n_exchanges;i++) {
    if(c->exchanges[i] == NULL) break;
    if(fq_rk_cmp(exchange, &c->exchanges[i]->exchange) == 0)
      return c->exchanges[i];
  }
  if(i == c->n_exchanges) {
    fqd_exchange **nlist;
    int ncnt = c->n_exchanges * 2;
    if(ncnt == 0) ncnt = 16;
    nlist = calloc(ncnt, sizeof(*c->exchanges));
    if(c->n_exchanges) {
      memcpy(nlist, c->exchanges, c->n_exchanges * sizeof(*c->exchanges));
      free(c->exchanges);
    }
    c->n_exchanges = ncnt;
    c->exchanges = nlist;
  }
  c->exchanges[i] = calloc(1, sizeof(*c->exchanges[i]));
  memcpy(&c->exchanges[i]->exchange, exchange, sizeof(*exchange));
  c->exchanges[i]->stats = calloc(1, sizeof(*c->exchanges[i]->stats));
  c->exchanges[i]->set = fqd_routemgr_ruleset_alloc();
  fq_debug(FQ_DEBUG_CONFIG, "Adding new exchange[%.*s] -> %d\n",
           exchange->len, exchange->name, i);
  return c->exchanges[i];
}

void fqd_config_wait(uint64_t gen, int us) {
  while(1) {
    int which;
    which = ck_pr_load_uint(&global_config.current_config);
    if(FQGC(which).config.gen >= gen) return;
    if(us>0) usleep(us);
  }
}
/* config modification */
#define BEGIN_CONFIG_MODIFY(conf) \
  fqd_config_ref *conf ## _ref; \
  fqd_config *conf; \
  pthread_mutex_lock(&global_config.writelock); \
  conf ## _ref = &FQGC((global_config.current_config + 1) % CONFIG_RING_SIZE); \
  conf = &conf ## _ref->config
#define MARK_CONFIG(conf) do { conf ## _ref->dirty = 1; } while(0)
#define END_CONFIG_MODIFY() pthread_mutex_unlock(&global_config.writelock)

extern uint32_t
fqd_config_bind(fq_rk *exchange, uint16_t flags, const char *program,
                fqd_queue *q, uint64_t *gen) {
  uint32_t route_id;
  fqd_exchange *x;
  fqd_route_rule *rule;
  int peermode = ((flags & FQ_BIND_PEER) == FQ_BIND_PEER);
  int isnew = 0;
  rule = fqd_routemgr_compile(program, peermode, q);
  if(!rule) return FQ_BIND_ILLEGAL;
  BEGIN_CONFIG_MODIFY(config);
  x = fqd_config_get_exchange(config, exchange);
  if(!x) x = fqd_config_add_exchange(config, exchange);
  route_id = fqd_routemgr_ruleset_add_rule(x->set, rule, &isnew);
  if(flags & FQ_BIND_PERM) {
    if((flags & FQ_BIND_PERM) == FQ_BIND_PERM) {
      fqd_routemgr_perm_route_id(x->set, route_id);
    }
    else if((flags & FQ_BIND_PERM) == FQ_BIND_TRANS) {
      fqd_routemgr_trans_route_id(x->set, route_id);
    }
  }
  fq_debug(FQ_DEBUG_CONFIG,
           "rule %u \"%s\" for exchange \"%.*s\" -> Q[%p]\n", route_id,
           program, exchange->len, exchange->name, (void *)q);
  if(gen) *gen = config->gen;
  MARK_CONFIG(config);
  END_CONFIG_MODIFY();

  /* if these bits are set, we have configdb work to do */
  if(flags & FQ_BIND_PERM) {
    if((flags & FQ_BIND_PERM) == FQ_BIND_PERM) {
      fqd_config_make_perm_binding(exchange, q, peermode, program);
    }
    else if((flags & FQ_BIND_PERM) == FQ_BIND_TRANS) {
      fqd_config_make_trans_binding(exchange, q, peermode, program);
    }
  }
  return route_id;
}

extern int
fqd_config_unbind(fq_rk *exchange, uint32_t route_id,
                  fqd_queue *c, uint64_t *gen) {
  int i, dropped = 0;
	BEGIN_CONFIG_MODIFY(config);
  for(i=0;i<config->n_exchanges;i++) {
    if(config->exchanges[i] != NULL &&
       fq_rk_cmp(exchange, &config->exchanges[i]->exchange) == 0) {
      dropped = fqd_routemgr_drop_rules_by_route_id(config->exchanges[i]->set,
                                                    c, route_id);
      if(gen) *gen = config->gen;
      break;
    }
  }
  if(dropped) MARK_CONFIG(config);
	END_CONFIG_MODIFY();
  fq_debug(FQ_DEBUG_CONFIG,
           "unbind rule %u %s for exchange \"%.*s\" -> Q[%p]\n", route_id,
           dropped ? "successful" : "failed", exchange->len, exchange->name,
           (void *)c);
  return dropped;
}

extern int
fqd_config_register_client(remote_client *c, uint64_t *gen) {
  int i, rv = 0, available_slot = -1;
  BEGIN_CONFIG_MODIFY(config);
  for(i=0; i<config->n_clients; i++) {
    assert(c != config->clients[i]);
    if(available_slot == -1 && config->clients[i] == NULL)
      available_slot = i;
  }
  if(available_slot < 0) {
    remote_client **f;
    f = calloc(sizeof(*f), config->n_clients + 128);
    if(f == NULL) goto oom;
    if(config->n_clients)
      memcpy(f, config->clients, sizeof(*f) * config->n_clients);
    available_slot = config->n_clients;
    config->n_clients += 128;
    free(config->clients);
    config->clients = f;
  }
  config->clients[available_slot] = c;
  fq_debug(FQ_DEBUG_CONFIG, "registering client -> (%p)\n", (void *)c);
  fqd_remote_client_ref(c);
  if(gen) *gen = config->gen;
  MARK_CONFIG(config);
  rv = 0;
 oom:
  END_CONFIG_MODIFY();
  return rv;
}

extern int
fqd_config_deregister_client(remote_client *c, uint64_t *gen) {
  int i;
  remote_client *toderef = NULL;
  BEGIN_CONFIG_MODIFY(config);
  for(i=0; i<config->n_clients; i++) {
    if(c == config->clients[i]) {
      config->clients[i] = NULL;
      toderef = c;
      fq_debug(FQ_DEBUG_CONFIG, "deregistering client -> (%p)\n", (void *)c);
      break;
    }
  }
  if(i == config->n_clients)
    fq_debug(FQ_DEBUG_CONFIG,
             "FAILED deregistering client -> (%p)\n", (void *)c);
  assert(i != config->n_clients);
  MARK_CONFIG(config);
  if(gen) *gen = config->gen;
  END_CONFIG_MODIFY();

  if(toderef) {
    /* Do this work without holding the lock */
    if(toderef->queue) {
      if(fqd_queue_deregister_client(toderef->queue, c)) {
        fqd_config_deregister_queue(toderef->queue, NULL);
      }
    }
    toderef->queue = NULL;
    fqd_remote_client_deref(toderef);
  }
  return 0;
}

extern fqd_queue *
fqd_config_register_queue(fqd_queue *c, uint64_t *gen) {
  int i, available_slot = -1;
  BEGIN_CONFIG_MODIFY(config);
  for(i=0; i<config->n_queues; i++) {
    if(config->queues[i] && fqd_queue_cmp(c, config->queues[i]) == 0) {
      if(gen) *gen = config->gen;
      c = config->queues[i];
      goto out;
    }
    if(available_slot == -1 && config->queues[i] == NULL)
      available_slot = i;
  }
  if(available_slot < 0) {
    fqd_queue **f;
    f = calloc(sizeof(*f), config->n_queues + 128);
    if(f == NULL) goto out;
    if(config->n_queues)
      memcpy(f, config->queues, sizeof(*f) * config->n_queues);
    available_slot = config->n_queues;
    config->n_queues += 128;
    free(config->queues);
    config->queues = f;
  }
  config->queues[available_slot] = c;
  fqd_queue_ref(c);
  if(gen) *gen = config->gen;
  MARK_CONFIG(config);
 out:
  END_CONFIG_MODIFY();
  fq_debug(FQ_DEBUG_CONFIG, "registering queues -> (%p)\n", (void *)c);
  return c;
}

extern int
fqd_config_deregister_queue(fqd_queue *c, uint64_t *gen) {
  int i;
  fqd_queue *toderef = NULL;
  BEGIN_CONFIG_MODIFY(config);
  for(i=0; i<config->n_queues; i++) {
    if(config->queues[i] && fqd_queue_cmp(c, config->queues[i]) == 0) {
      config->queues[i] = NULL;
      toderef = c;
      fq_debug(FQ_DEBUG_CONFIG, "deregistering queue -> (%p)\n", (void *)c);
      break;
    }
  }
  if(i == config->n_queues)
    fq_debug(FQ_DEBUG_CONFIG, "FAILED deregistering queue -> (%p)\n", (void *)c);
  assert(i != config->n_queues);
  for(i=0;i<config->n_exchanges;i++) {
    if(config->exchanges[i] != NULL) {
      fqd_routemgr_drop_rules_by_queue(config->exchanges[i]->set, toderef);
    }
  }
  MARK_CONFIG(config);
  if(gen) *gen = config->gen;
  END_CONFIG_MODIFY();
  if(toderef)
    fqd_queue_deref(toderef);
  return 0;
}

/* This section deals with managing the rings */
static void
fqd_internal_copy_config(fqd_config_ref *src, fqd_config_ref *tgt) {
  int i;
  /* First clients */
  if(tgt->config.clients) {
    for(i=0;i<tgt->config.n_clients;i++)
      if(tgt->config.clients[i])
        fqd_remote_client_deref(tgt->config.clients[i]);
    free(tgt->config.clients);
    tgt->config.clients = NULL;
  }
  if(src->config.clients) {
    tgt->config.n_clients = src->config.n_clients;
    tgt->config.clients =
      malloc(sizeof(*tgt->config.clients) * tgt->config.n_clients);
    assert(tgt->config.clients);
    memcpy(tgt->config.clients, src->config.clients,
           sizeof(*tgt->config.clients) * tgt->config.n_clients);
    for(i=0;i<tgt->config.n_clients;i++)
      if(tgt->config.clients[i])
        fqd_remote_client_ref(tgt->config.clients[i]);
  }

  /* Now the same thing of queues */
  if(tgt->config.queues) {
    for(i=0;i<tgt->config.n_queues;i++)
      if(tgt->config.queues[i])
        fqd_queue_deref(tgt->config.queues[i]);
    free(tgt->config.queues);
    tgt->config.queues = NULL;
  }
  if(src->config.queues) {
    tgt->config.n_queues = src->config.n_queues;
    tgt->config.queues =
      malloc(sizeof(*tgt->config.queues) * tgt->config.n_queues);
    assert(tgt->config.queues);
    memcpy(tgt->config.queues, src->config.queues,
           sizeof(*tgt->config.queues) * tgt->config.n_queues);
    for(i=0;i<tgt->config.n_queues;i++)
      if(tgt->config.queues[i])
        fqd_queue_ref(tgt->config.queues[i]);
  }

  /* next the exchang/routemaps */
  if(tgt->config.exchanges) {
    for(i=0;i<tgt->config.n_exchanges;i++) {
      if(tgt->config.exchanges[i] && tgt->config.exchanges[i]->set) {
        fqd_routemgr_ruleset_free(tgt->config.exchanges[i]->set);
        free(tgt->config.exchanges[i]);
      }
    }
    free(tgt->config.exchanges);
    tgt->config.exchanges = NULL;
  }
  if(src->config.exchanges) {
    tgt->config.n_exchanges = src->config.n_exchanges;
    tgt->config.exchanges =
      malloc(sizeof(*tgt->config.exchanges) * tgt->config.n_exchanges);
    assert(tgt->config.exchanges);
    for(i=0;i<tgt->config.n_exchanges;i++) {
      if(src->config.exchanges[i]) {
        tgt->config.exchanges[i] = malloc(sizeof(*tgt->config.exchanges[i]));
        memcpy(tgt->config.exchanges[i], src->config.exchanges[i],
               sizeof(*tgt->config.exchanges[i]));
        tgt->config.exchanges[i]->set =
          fqd_routemgr_ruleset_copy(src->config.exchanges[i]->set);
      }
      else tgt->config.exchanges[i] = NULL;
    }
  }
}

static void
fixup_config_write_context(void) {
  uint32_t current, next, nextnext;

  current = global_config.current_config;
  next = (current + 1) % CONFIG_RING_SIZE;
  nextnext = (current + 2) % CONFIG_RING_SIZE;

  FQ_CONFIG_ROTATE(FQGC(next).dirty);
  if(!FQGC(next).dirty) return;

  fq_debug(FQ_DEBUG_CONFIG, "Swapping to next running config\n");
  pthread_mutex_lock(&global_config.writelock);

  /* We've locked writing... let the world use the new config */
  global_config.current_config = next;

  /* Wait until the next(next) has no readers so we can copy into it */
  while(ck_pr_load_uint(&FQGC(nextnext).readers) != 0)
    ck_pr_stall();

  /* Safe to do the copy */
  fqd_internal_copy_config(&FQGC(next), &FQGC(nextnext));
  /* Mark that new write target as clean */
  FQGC(nextnext).config.gen = ++global_gen;
  FQGC(nextnext).dirty = 0;

  pthread_mutex_unlock(&global_config.writelock);
  fq_debug(FQ_DEBUG_CONFIG, "Swapped to next running config\n");
}

static void *config_rotation(void *unused) {
  while(1) {
    fixup_config_write_context();
    usleep(CONFIG_ROTATE_NS / 1000);
  }
  (void)unused;
  return NULL;
}

#define cprintf(client, fmt, ...) do { \
  char scratch[1024]; \
  int len; \
  len = snprintf(scratch, sizeof(scratch), fmt, __VA_ARGS__); \
  while(write(client->fd, scratch, len) == -1 && errno == EINTR); \
} while(0)
#define cwrite(client, str) write(client->fd, str, strlen(str))

int fqd_config_http_routes(struct fqd_route_rule *r, int rv, void *closure) {
  remote_client *client = closure;
  char *program_encoded, *cp, *tcp;
  int len;
  unsigned char hash[SHA256_DIGEST_LENGTH];
  char hashhex[SHA256_DIGEST_LENGTH * 2 + 1];
  SHA256_CTX sha256;

  SHA256_Init(&sha256);
  SHA256_Update(&sha256, r->program, strlen(r->program));
  SHA256_Final(hash, &sha256);
  for(len = 0; len < SHA256_DIGEST_LENGTH; len++)
    snprintf(hashhex + len*2, 3, "%02x", hash[len]);

  len = strlen(r->program)*2+1;
  program_encoded = malloc(len);
  for(cp = r->program, tcp = program_encoded; *cp; cp++) {
    switch(*cp) {
      case '\\': *tcp++ = '\\'; *tcp++ = *cp; break;
      case '\"': *tcp++ = '\\'; *tcp++ = *cp; break;
      default: *tcp++ = *cp; break;
    }
  }
  *tcp = '\0';

  cprintf(client, "   %s\"%s\": {\n", rv ? "," : " ", hashhex);
  cprintf(client, "     \"route_id\": %u,\n", r->route_id);
  cprintf(client, "     \"prefix\": \"%.*s\",\n", r->prefix.len, r->prefix.name);
  cprintf(client, "     \"queue\": \"%.*s\",\n", r->queue->name.len, r->queue->name.name);
  cprintf(client, "     \"permanent\": %s,\n", r->permanent ? "true" : "false");
  cprintf(client, "     \"invocations\": %llu,\n", (unsigned long long)r->stats->invocations);
  cprintf(client, "     \"avg_ns\": %u,\n", r->stats->avg_ns);
  cprintf(client, "     \"program\": \"%s\"\n", program_encoded);
  cwrite(client, "    }\n");
  free(program_encoded);
  return 1;
}
void fqd_config_http_stats(remote_client *client) {
  int i;
  const char *headers = "HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: text/json\r\n\r\n";
  fqd_config *config;
  while(write(client->fd, headers, strlen(headers)) == -1 && errno == EINTR);
  config = fqd_config_get();
  cwrite(client, "{\n");
  cprintf(client, " \"version\": \"%s\",\n", fq_version_string);
  cwrite(client, " \"exchanges\": {\n");
  for(i=0;i<config->n_exchanges;i++) {
    if(config->exchanges[i]) {
      fqd_exchange *e = config->exchanges[i];
      cprintf(client, "  \"%.*s\": {\n", e->exchange.len, e->exchange.name);
      cprintf(client, "   \"messages\": %llu,\n", (long long unsigned int) e->stats->n_messages);
      cprintf(client, "   \"octets\": %llu,\n", (long long unsigned int) e->stats->n_bytes);
      cprintf(client, "   \"no_route\": %llu,\n", (long long unsigned int) e->stats->n_no_route);
      cprintf(client, "   \"routed\": %llu,\n", (long long unsigned int) e->stats->n_routed);
      cprintf(client, "   \"dropped\": %llu,\n", (long long unsigned int) e->stats->n_dropped);
      cwrite(client, "   \"routes\": {\n");
      for_each_route_rule_do(e->set, fqd_config_http_routes, client);
      cwrite(client, "   }\n");
      cwrite(client, "  },\n");
    }
  }
  cwrite(client, "  \"_aggregate\": {\n");
  cprintf(client, "   \"no_exchange\": %llu,\n", (long long unsigned int) global_counters.n_no_exchange);
  cprintf(client, "   \"messages\": %llu,\n", (long long unsigned int) global_counters.n_messages);
  cprintf(client, "   \"octets\": %llu,\n", (long long unsigned int) global_counters.n_bytes);
  cprintf(client, "   \"no_route\": %llu,\n", (long long unsigned int) global_counters.n_no_route);
  cprintf(client, "   \"routed\": %llu,\n", (long long unsigned int) global_counters.n_routed);
  cprintf(client, "   \"dropped\": %llu\n", (long long unsigned int) global_counters.n_dropped);
  cwrite(client, "  }\n");
  cwrite(client, " },\n");
  cwrite(client, " \"queues\": {\n");
  int seen = 0;
  for(i=0;i<config->n_queues;i++) {
    if(config->queues[i]) {
      fqd_queue *q = config->queues[i];
      fq_rk *qname = fqd_queue_name(q);
      if(seen++) cwrite(client, ",\n");
      cprintf(client, "  \"%.*s\": \n", qname->len, qname->name);
      fqd_queue_write_json(client->fd, q);
    }
  }
  cwrite(client, " }\n");
  cwrite(client, "}\n");
  fqd_config_release(config);
}

void fqd_exchange_messages(fqd_exchange *e, uint64_t n) {
  if(e) ck_pr_add_64(&e->stats->n_messages, n);
  ck_pr_add_64(&global_counters.n_messages, n);
}
void fqd_exchange_message_octets(fqd_exchange *e, uint64_t n) {
  if(e) ck_pr_add_64(&e->stats->n_bytes, n);
  ck_pr_add_64(&global_counters.n_bytes, n);
}
void fqd_exchange_no_route(fqd_exchange *e, uint64_t n) {
  if(e) ck_pr_add_64(&e->stats->n_no_route, n);
  ck_pr_add_64(&global_counters.n_no_route, n);
}
void fqd_exchange_routed(fqd_exchange *e, uint64_t n) {
  assert(e);
  ck_pr_add_64(&e->stats->n_routed, n);
  ck_pr_add_64(&global_counters.n_routed, n);
}
void fqd_exchange_dropped(fqd_exchange *e, uint64_t n) {
  if(e) ck_pr_add_64(&e->stats->n_dropped, n);
  ck_pr_add_64(&global_counters.n_dropped, n);
}
void fqd_exchange_no_exchange(fqd_exchange *e, uint64_t n) {
  assert(!e);
  ck_pr_add_64(&global_counters.n_no_exchange, n);
}

#define bail(...) do {fprintf(stderr, __VA_ARGS__); exit(-2);} while(0)

static void setup_initial_config() {
  char *SQL, *errmsg = NULL;
  int rv;
  int flags = SQLITE_OPEN_CREATE|SQLITE_OPEN_READWRITE|SQLITE_OPEN_EXCLUSIVE;
  if((rv = sqlite3_open_v2(fqd_config_path, &configdb, flags, NULL)) != 0)
    bail("... failed to open %s: %s\n", fqd_config_path,
         sqlite3_errmsg(configdb));

  sqlite3_exec(configdb, "PRAGMA foreign_keys = ON", 0, 0, &errmsg);
  if(errmsg) bail("sqlite error: %s\n", sqlite3_errmsg(configdb));

  SQL = sqlite3_mprintf(
    "CREATE TABLE queue (name TEXT NOT NULL PRIMARY KEY,"
    " type TEXT NOT NULL DEFAULT \"mem\", attributes TEXT)"
  );
  sqlite3_exec(configdb, SQL, 0, 0, &errmsg);
  sqlite3_free(SQL);
  if(errmsg && strcmp(errmsg, "table queue already exists"))
    bail("sqlite error: %s\n", sqlite3_errmsg(configdb));
  if(errmsg) sqlite3_free(errmsg);

  SQL = sqlite3_mprintf(
    "CREATE TABLE binding ( "
    " exchange TEXT NOT NULL, "
    " queue TEXT NOT NULL, "
    " peermode BOOLEAN NOT NULL DEFAULT FALSE, program TEXT, "
    " UNIQUE(exchange, queue, peermode, program), "
    " FOREIGN KEY(queue) REFERENCES queue(name) "
    ")"
  );
  sqlite3_exec(configdb, SQL, 0, 0, &errmsg);
  sqlite3_free(SQL);
  if(errmsg && strcmp(errmsg, "table binding already exists"))
    bail("sqlite error: %s\n", sqlite3_errmsg(configdb));
  if(errmsg) sqlite3_free(errmsg);
}

int fqd_config_make_perm_queue(fqd_queue *q) {
  sqlite3_stmt *stmt;
  fq_rk *qname;
  const char *insertSQL;
  char qtype[1024], *attrs;
  fqd_queue_sprint(qtype, sizeof(qtype), q);
  attrs = strchr(qtype, ':');
  if(attrs == NULL) return -1;
  *attrs++ = '\0';
  insertSQL = "INSERT INTO queue VALUES(?,?,?)";
  qname = fqd_queue_name(q);
  sqlite3_prepare_v2(configdb, insertSQL, strlen(insertSQL), &stmt, NULL);
  sqlite3_bind_text(stmt, 1, (char *)qname->name, qname->len, NULL);
  sqlite3_bind_text(stmt, 2, qtype, strlen(qtype), NULL);
  sqlite3_bind_text(stmt, 3, attrs, strlen(attrs), NULL);
  switch(sqlite3_step(stmt)) {
    case SQLITE_DONE:
      if(sqlite3_changes(configdb) > 0) {
        fq_debug(FQ_DEBUG_CONFIG, "Queue %.*s made permanent\n",
                 qname->len, qname->name);
        fqd_queue_ref(q);
      }
      break;
    default:
      fq_debug(FQ_DEBUG_CONFIG, "Queue %.*s not made permanent: %s\n",
               qname->len, qname->name, sqlite3_errmsg(configdb));
      break;
  }
  sqlite3_finalize(stmt);
  return 0;
}

int fqd_config_make_trans_queue(fqd_queue *q) {
  sqlite3_stmt *stmt;
  fq_rk *qname;
  const char *insertSQL;
  char qtype[1024], *attrs;
  fqd_queue_sprint(qtype, sizeof(qtype), q);
  attrs = strchr(qtype, ':');
  if(attrs == NULL) return -1;
  *attrs++ = '\0';
  insertSQL = "DELETE FROM queue WHERE name = ?";
  qname = fqd_queue_name(q);
  sqlite3_prepare_v2(configdb, insertSQL, strlen(insertSQL), &stmt, NULL);
  sqlite3_bind_text(stmt, 1, (char *)qname->name, qname->len, NULL);
  switch(sqlite3_step(stmt)) {
    case SQLITE_DONE:
      if(sqlite3_changes(configdb) > 0) {
        fq_debug(FQ_DEBUG_CONFIG, "Queue %.*s made transient\n",
                 qname->len, qname->name);
        fqd_queue_deref(q);
        break;
      }
      fq_debug(FQ_DEBUG_CONFIG, "Queue %.*s not made transient: not found\n",
               qname->len, qname->name);
      break;
    default:
      fq_debug(FQ_DEBUG_CONFIG, "Queue %.*s not made transient: %s\n",
               qname->len, qname->name, sqlite3_errmsg(configdb));
      break;
  }
  sqlite3_finalize(stmt);
  return 0;
}
static int sql_make_queues(void *c, int n, char **row, char **col) {
  fqd_queue *queue;
  char err[1024];
  fq_rk q;
  assert(n == 3);
  (void)c;
  (void)col;
  q.len = strlen(row[0]);
  if(q.len != strlen(row[0])) return 0;
  memcpy(q.name, row[0], q.len);
 
  queue = fqd_queue_get(&q, row[1], row[2],  sizeof(err), err);
  if(!queue) {
    fprintf(stderr, "queue(%s) -> %s\n", row[0], err);
    return 0;
  }
  fqd_queue_ref(queue);
  return 0;
}
int fqd_config_make_perm_binding(fq_rk *exchange, fqd_queue *q,
                                 int peermode, const char *program) {
  sqlite3_stmt *stmt;
  fq_rk *qname;
  const char *insertSQL;
  const char *pmstr = peermode ? "true" : "false";
  char qtype[1024], *attrs;
  fqd_queue_sprint(qtype, sizeof(qtype), q);
  attrs = strchr(qtype, ':');
  if(attrs == NULL) return -1;
  *attrs++ = '\0';
  insertSQL = "INSERT INTO binding (exchange,queue,peermode,program) "
              "VALUES(?,?,?,?)";
  qname = fqd_queue_name(q);
  sqlite3_prepare_v2(configdb, insertSQL, strlen(insertSQL), &stmt, NULL);
  sqlite3_bind_text(stmt, 1, (char *)exchange->name, exchange->len, NULL);
  sqlite3_bind_text(stmt, 2, (char *)qname->name, qname->len, NULL);
  sqlite3_bind_text(stmt, 3, pmstr, strlen(pmstr), NULL);
  sqlite3_bind_text(stmt, 4, program, strlen(program), NULL);
  switch(sqlite3_step(stmt)) {
    case SQLITE_DONE:
      if(sqlite3_changes(configdb) > 0) {
        fq_debug(FQ_DEBUG_CONFIG, "Binding %.*s made permanent\n",
                 qname->len, qname->name);
        fqd_queue_ref(q);
      }
      break;
    default:
      fq_debug(FQ_DEBUG_CONFIG, "Binding %.*s not made permanent: %s\n",
               qname->len, qname->name, sqlite3_errmsg(configdb));
      break;
  }
  sqlite3_finalize(stmt);
  return 0;
}
int fqd_config_make_trans_binding(fq_rk *exchange, fqd_queue *q,
                                  int peermode, const char *program) {
  sqlite3_stmt *stmt;
  fq_rk *qname;
  const char *delSQL;
  const char *pmstr = peermode ? "true" : "false";
  char qtype[1024], *attrs;
  fqd_queue_sprint(qtype, sizeof(qtype), q);
  attrs = strchr(qtype, ':');
  if(attrs != NULL) *attrs++ = '\0';
  delSQL = "DELETE FROM binding WHERE exchange=? AND queue=? "
              "  AND peermode=? AND program=?";
  qname = fqd_queue_name(q);
  sqlite3_prepare_v2(configdb, delSQL, strlen(delSQL), &stmt, NULL);
  sqlite3_bind_text(stmt, 1, (char *)exchange->name, exchange->len, NULL);
  sqlite3_bind_text(stmt, 2, (char *)qname->name, qname->len, NULL);
  sqlite3_bind_text(stmt, 3, pmstr, strlen(pmstr), NULL);
  sqlite3_bind_text(stmt, 4, program, strlen(program), NULL);
  switch(sqlite3_step(stmt)) {
    case SQLITE_DONE:
      if(sqlite3_changes(configdb) > 0) {
        fq_debug(FQ_DEBUG_CONFIG, "Binding %.*s made transient\n",
                 qname->len, qname->name);
        fqd_queue_ref(q);
        break;
      }
      fq_debug(FQ_DEBUG_CONFIG, "Binding %.*s not made transient: not found\n",
               qname->len, qname->name);
      break;
    default:
      fq_debug(FQ_DEBUG_CONFIG, "Binding %.*s not made transient: %s\n",
               qname->len, qname->name, sqlite3_errmsg(configdb));
      break;
  }
  sqlite3_finalize(stmt);
  return 0;
}

static int sql_make_bindings(void *c, int n, char **row, char **col) {
  int *nbindings = (int *)c;
  fqd_queue *queue;
  fq_rk q, x;
  uint16_t flags;
  BEGIN_CONFIG_MODIFY(config);

  assert(n == 4);
  (void)c;
  (void)col;

  x.len = strlen(row[0]);
  if(x.len != strlen(row[0])) return 0;
  memcpy(x.name, row[0], x.len);

  q.len = strlen(row[1]);
  if(q.len != strlen(row[1])) return 0;
  memcpy(q.name, row[1], q.len);

  queue = fqd_config_get_registered_queue(config, &q);
  MARK_CONFIG(config);
  END_CONFIG_MODIFY();

  if(queue == NULL) return 1;
  flags = !strcmp(row[2],"true") ? FQ_BIND_PEER : 0;
  flags |= FQ_BIND_PERM;
  fqd_config_bind(&x, flags, row[3], queue, NULL);
  (*nbindings)++;
  return 0;
}
static void setup_config() {
  fqd_config *config;
  int i, nexchanges = 0, nqueues = 0, nbindings = 0;
  char *errmsg = NULL;
  int flags = SQLITE_OPEN_READWRITE|SQLITE_OPEN_EXCLUSIVE;

  fprintf(stderr, "Opening configdb %s\n", fqd_config_path);
  if(sqlite3_open_v2(fqd_config_path, &configdb, flags, NULL)) {
    flags = SQLITE_OPEN_CREATE|SQLITE_OPEN_READWRITE|SQLITE_OPEN_EXCLUSIVE;
    if(sqlite3_open_v2(fqd_config_path, &configdb, flags, NULL))
      bail("... failed to open %s: %s\n", fqd_config_path,
           sqlite3_errmsg(configdb));
  }
  setup_initial_config();

  sqlite3_exec(configdb,
    "SELECT name, type, attributes FROM queue",
    sql_make_queues, NULL, &errmsg
  );
  if(errmsg) bail("sqlite error: %s\n", sqlite3_errmsg(configdb));

  sqlite3_exec(configdb,
    "SELECT exchange, queue, peermode, program FROM binding",
    sql_make_bindings, &nbindings, &errmsg
  );
  if(errmsg) bail("sqlite error: %s\n", sqlite3_errmsg(configdb));

  // Summarize
  {
  BEGIN_CONFIG_MODIFY(tc);
  (void)tc;
  MARK_CONFIG(tc);
  END_CONFIG_MODIFY();
  }
  fqd_config_wait(global_gen-1, 1000);
  config = fqd_config_get();
  for(i=0;i<config->n_exchanges;i++) if(config->exchanges[i]) nexchanges++;
  for(i=0;i<config->n_queues;i++) if(config->queues[i]) nqueues++;
  fprintf(stderr, "Established %d exchanges, %d queues, %d bindings\n",
          nexchanges, nqueues, nbindings);
  fqd_config_release(config);
}
