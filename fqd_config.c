#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <ck_pr.h>

#include "fq.h"
#include "fqd.h"

#define CONFIG_RING_SIZE 3
#define CONFIG_ROTATE_NS (100*1000*1000) /*100ms*/
#define DEFAULT_CLIENT_CNT 128
/* A ring of three configs
 *
 * [cycleout] [currentread] [currentwrite]
 *
 */
struct fqd_config {
  u_int64_t gen;
  int n_clients;
  remote_client **clients;
  int n_queues;
  fqd_queue **queues;
};

static u_int64_t global_gen = 0;

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

void
fqd_config_init() {
  int i;
  pthread_t t;
  pthread_attr_t attr;

  memset(&global_config, 0, sizeof(global_config));

  pthread_mutex_init(&global_config.writelock, NULL);

  for(i=0;i<CONFIG_RING_SIZE;i++)
    global_config.configs[i].config.gen = ++global_gen;

  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_create(&t, &attr, config_rotation, NULL);
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

fqd_queue *
fqd_config_get_registered_queue(fqd_config *c, fq_rk *qname) {
  int i;
  for(i=0;i<c->n_queues;i++)
    if(c->queues[i] && fq_rk_cmp(qname, fqd_queue_name(c->queues[i])) == 0)
      return c->queues[i];
  return NULL;
}

remote_client *
fqd_config_get_registered_client(fqd_config *c, fq_rk *key) {
  int i;
  for(i=0;i<c->n_clients;i++)
    if(c->clients[i] && fq_rk_cmp(key, &c->clients[i]->key) == 0)
      return c->clients[i];
  return NULL;
}

void fqd_config_wait(u_int64_t gen, int us) {
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

extern int
fqd_config_register_client(remote_client *c, u_int64_t *gen) {
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
#ifdef DEBUG
  fq_debug("registering client -> (%p)\n", (void *)c);
#endif
  fqd_remote_client_ref(c);
  if(gen) *gen = config->gen;
  MARK_CONFIG(config);
  rv = 0;
 oom:
  END_CONFIG_MODIFY();
  return rv;
}

extern int
fqd_config_deregister_client(remote_client *c, u_int64_t *gen) {
  int i;
  remote_client *toderef = NULL;
  BEGIN_CONFIG_MODIFY(config);
  for(i=0; i<config->n_clients; i++) {
    if(c == config->clients[i]) {
      config->clients[i] = NULL;
      toderef = c;
#ifdef DEBUG
      fq_debug("deregistering client -> (%p)\n", (void *)c);
#endif
      break;
    }
  }
#ifdef DEBUG
  if(i == config->n_clients)
    fq_debug("FAILED deregistering client -> (%p)\n", (void *)c);
#else
  assert(i != config->n_clients);
#endif
  MARK_CONFIG(config);
  if(gen) *gen = config->gen;
  END_CONFIG_MODIFY();

  if(toderef) {
    /* Do this work without holding the lock */
    if(toderef->queue) fqd_queue_deregister_client(toderef->queue, c);
    toderef->queue = NULL;
    fqd_remote_client_deref(toderef);
  }
  return 0;
}

extern fqd_queue *
fqd_config_register_queue(fqd_queue *c, u_int64_t *gen) {
  int i, rv = 0, available_slot = -1;
  BEGIN_CONFIG_MODIFY(config);
  for(i=0; i<config->n_queues; i++) {
    if(config->queues[i] && fqd_queue_cmp(c, config->queues[i]) == 0) {
      if(gen) *gen = config->gen;
      END_CONFIG_MODIFY();
      return config->queues[i];
    }
    if(available_slot == -1 && config->queues[i] == NULL)
      available_slot = i;
  }
  if(available_slot < 0) {
    fqd_queue **f;
    f = calloc(sizeof(*f), config->n_queues + 128);
    if(f == NULL) goto oom;
    if(config->n_queues)
      memcpy(f, config->queues, sizeof(*f) * config->n_queues);
    available_slot = config->n_queues;
    config->n_queues += 128;
    free(config->queues);
    config->queues = f;
  }
  config->queues[available_slot] = c;
#ifdef DEBUG
  fq_debug("registering queues -> (%p)\n", (void *)c);
#endif
  fqd_queue_ref(c);
  if(gen) *gen = config->gen;
  MARK_CONFIG(config);
  rv = 0;
 oom:
  END_CONFIG_MODIFY();
  return c;
}

extern int
fqd_config_deregister_queue(fqd_queue *c, u_int64_t *gen) {
  int i;
  fqd_queue *toderef = NULL;
  BEGIN_CONFIG_MODIFY(config);
  for(i=0; i<config->n_queues; i++) {
    if(config->queues[i] && fqd_queue_cmp(c, config->queues[i]) == 0) {
      config->clients[i] = NULL;
      toderef = c;
#ifdef DEBUG
      fq_debug("deregistering queue -> (%p)\n", (void *)c);
#endif
      break;
    }
  }
#ifdef DEBUG
  if(i == config->n_queues)
    fq_debug("FAILED deregistering queue -> (%p)\n", (void *)c);
#else
  assert(i != config->n_queues);
#endif
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
}

static void
fixup_config_write_context(void) {
  uint32_t current, next, nextnext;

  current = global_config.current_config;
  next = (current + 1) % CONFIG_RING_SIZE;
  nextnext = (current + 2) % CONFIG_RING_SIZE;

  if(!FQGC(next).dirty) return;

#ifdef DEBUG
  fq_debug("Swapping to next running config\n");
#endif
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
#ifdef DEBUG
  fq_debug("Swapped to next running config\n");
#endif
}

static void *config_rotation(void *unused) {
  while(1) {
    fixup_config_write_context();
    usleep(CONFIG_ROTATE_NS / 1000);
  }
  (void)unused;
  return NULL;
}
