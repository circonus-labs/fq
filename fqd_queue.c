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
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "fqd.h"
#include "fqd_private.h"
#include "ck_pr.h"
#include "fq_dtrace.h"

#define DEFAULT_QUEUE_LIMIT 16384

#define cprintf(fd, fmt, ...) do { \
  char scratch[1024]; \
  int len; \
  len = snprintf(scratch, sizeof(scratch), fmt, __VA_ARGS__); \
  write(fd, scratch, len); \
} while(0)
#define cwrite(fd, str) write(fd, str, strlen(str))
int fqd_queue_write_json(int fd, fqd_queue *q) {
  int i, seen = 0;
  cwrite(fd, "{\n");
  cprintf(fd, "  \"private\": %s,\n", q->private ? "true" : "false");
  cprintf(fd, "  \"type\": \"%s\",\n", q->impl->name);
  cprintf(fd, "  \"policy\": \"%s\",\n", (q->policy == FQ_POLICY_DROP) ? "drop" : "block");
  cprintf(fd, "  \"backlog_limit\": %d,\n", q->backlog_limit);
  cprintf(fd, "  \"backlog\": %d,\n", q->backlog);
  cprintf(fd, "  \"refcnt\": %d,\n", q->refcnt);
  cwrite(fd, "  \"clients\": [");
  for(i=0;i<MAX_QUEUE_CLIENTS;i++) {
    remote_client *c = q->downstream[i];
    if(c) {
      char buf[INET6_ADDRSTRLEN+1];
      buf[0] = '\0';
      inet_ntop(AF_INET, &c->remote.sin_addr, buf, sizeof(buf));
      if(seen++) cwrite(fd, "    ,{\n");
      else       cwrite(fd, "    {\n");
      cprintf(fd, "    \"user\": \"%.*s\"\n", c->user.len, c->user.name);
      cprintf(fd, "   ,\"remote_addr\": \"%s\"\n", buf);
      cprintf(fd, "   ,\"remote_port\": \"%d\"\n", ntohs(c->remote.sin_port));
      if(c->data) {
        cprintf(fd, "   ,\"mode\": \"%s\"\n", (c->data->mode == FQ_PROTO_DATA_MODE) ? "client" : "peer");
        cprintf(fd, "   ,\"no_exchange\": \"%u\"\n", c->data->no_exchange);
        cprintf(fd, "   ,\"no_route\": \"%u\"\n", c->data->no_route);
        cprintf(fd, "   ,\"routed\": \"%u\"\n", c->data->routed);
        cprintf(fd, "   ,\"dropped\": \"%u\"\n", c->data->dropped);
        cprintf(fd, "   ,\"size_dropped\": \"%u\"\n", c->data->size_dropped);
        cprintf(fd, "   ,\"msgs_in\": \"%u\"\n", c->data->msgs_in);
        cprintf(fd, "   ,\"msgs_out\": \"%u\"\n", c->data->msgs_out);
        cprintf(fd, "   ,\"octets_in\": \"%u\"\n", c->data->octets_in);
        cprintf(fd, "   ,\"octets_out\": \"%u\"\n", c->data->octets_out);
      }
      cwrite(fd, "    }\n");
    }
  }
  cwrite(fd, "]\n");
  cwrite(fd, "}");
  return 0;
}

int fqd_queue_sprint(char *buf, int len, fqd_queue *q) {
  return
    snprintf(buf, len, "%s:%s,%s,backlog=%d",
             q->impl->name, q->private ? "private" : "public",
             (q->policy == FQ_POLICY_DROP) ? "drop" : "block",
             q->backlog_limit);
}

void fqd_queue_dtrace_pack(fq_dtrace_queue_t *d, fqd_queue *s) {
  d->name = (char *)s->name.name;
  d->private = s->private;
  d->policy = s->policy;
  d->type = (char *)s->impl->name;
}

static void fqd_queue_free(fqd_queue *q);

fq_rk *
fqd_queue_name(fqd_queue *q) {
  return &q->name;
}

void
fqd_queue_enqueue(fqd_queue *q, fq_msg *m, int *dropped) {
  while(1) {
    uint32_t backlog;
    if(q->backlog_limit) {
      backlog = ck_pr_load_uint(&q->backlog);
      if(backlog < q->backlog_limit) break;
    }
    if(q->policy == FQ_POLICY_DROP) {
      if(dropped) (*dropped)++;
      if(FQ_QUEUE_DROP_ENABLED()) {
        fq_dtrace_msg_t dm;
        fq_dtrace_queue_t dq;
        DTRACE_PACK_MSG(&dm, m);
        DTRACE_PACK_QUEUE(&dq, q);
        FQ_QUEUE_DROP(&dq, &dm);
      }
      return;
    }
    else {
      pthread_mutex_lock(&q->lock);
    again:
      if(q->backlog_limit) {
        backlog = ck_pr_load_uint(&q->backlog);
        if(backlog < q->backlog_limit) {
          pthread_mutex_unlock(&q->lock);
          break;
        }
      }
      if(FQ_QUEUE_BLOCK_ENABLED()) {
        fq_dtrace_msg_t dm;
        fq_dtrace_queue_t dq;
        DTRACE_PACK_MSG(&dm, m);
        DTRACE_PACK_QUEUE(&dq, q);
        FQ_QUEUE_BLOCK(&dq, &dm);
      }
      pthread_cond_wait(&q->cv, &q->lock);
      goto again;
    }
  }
  ck_pr_inc_32(&q->backlog);
  if(FQ_QUEUE_ENQUEUE_ENABLED()) {
    fq_dtrace_msg_t dm;
    fq_dtrace_queue_t dq;
    DTRACE_PACK_MSG(&dm, m);
    DTRACE_PACK_QUEUE(&dq, q);
    FQ_QUEUE_ENQUEUE(&dq, &dm);
  }
  q->impl->enqueue(q->impl_data, m);
}

fq_msg *
fqd_queue_dequeue(fqd_queue *q) {
  fq_msg *msg = q->impl->dequeue(q->impl_data);
  if(msg) {
    ck_pr_dec_32(&q->backlog);
    if(q->policy == FQ_POLICY_BLOCK) pthread_cond_signal(&q->cv);
  }
  return msg;
}

int
fqd_queue_register_client(fqd_queue *q, remote_client *c) {
  int i;
  int max_clients = q->private ? 1 : MAX_QUEUE_CLIENTS;
  fqd_queue_ref(q);
  fqd_remote_client_ref(c);
  for(i=0;i<max_clients;i++) {
    if(q->downstream[i] == NULL) {
      if(ck_pr_cas_ptr(&q->downstream[i], NULL, c) == true) {
#ifdef DEBUG
        fq_debug(FQ_DEBUG_CONFIG, "%.*s adding %s\n",
                 q->name.len, q->name.name, c->pretty);
#endif
        return 0;
      }
    }
  }
  if(fqd_remote_client_deref(c)) abort();
  if(fqd_queue_deref(q)) abort();
  return -1;
}
bool
fqd_queue_deregister_client(fqd_queue *q, remote_client *c) {
  int i;
  bool found = false;
  int max_clients = q->private ? 1 : MAX_QUEUE_CLIENTS;
  for(i=0;i<max_clients;i++) {
    if(q->downstream[i] == c) {
      q->downstream[i] = NULL;
      fq_debug(FQ_DEBUG_CONFIG, "%.*s dropping %s\n",
              q->name.len, q->name.name, c->pretty);
      if(fqd_remote_client_deref(c)) abort();
      if(fqd_queue_deref(q)) abort();
      if(found) abort();
      found = true;
    }
  }
  if(q->permanent) return false;
  for(i=0;i<max_clients;i++) if(q->downstream[i]) return false;
  return true;
}
int
fqd_queue_cmp(const fqd_queue *a, const fqd_queue *b) {
  return fq_rk_cmp(&a->name, &b->name);
}

void
fqd_queue_ref(fqd_queue *q) {
  fq_stacktrace(FQ_DEBUG_MEM,"fqd_queue_ref",1,2);
  ck_pr_inc_uint(&q->refcnt);
  fq_debug(FQ_DEBUG_MEM, "Q[%.*s] -> refcnt:%u\n", q->name.len, q->name.name, q->refcnt);
}
bool
fqd_queue_deref(fqd_queue *q) {
  bool zero;
  fq_stacktrace(FQ_DEBUG_MEM,"fqd_queue_deref",1,2);
  ck_pr_dec_uint_zero(&q->refcnt, &zero);
  fq_debug(FQ_DEBUG_MEM, "Q[%.*s] -> refcnt:%u\n", q->name.len, q->name.name, q->refcnt);
  if(zero) {
    FQ_QUEUE_DESTROY(q->name.len, (char *)q->name.name);
    fq_debug(FQ_DEBUG_CONFIG, "dropping queue(%p) %.*s\n",
            (void *)q, q->name.len, q->name.name);
    fqd_queue_free(q);
    return true;
  }
  return false;
}
uint32_t
fqd_queue_get_backlog_limit(fqd_queue *q) {
  return q->backlog_limit;
}
void
fqd_queue_set_backlog_limit(fqd_queue *q, uint32_t l) {
  q->backlog_limit = l;
}
queue_policy_t
fqd_queue_get_policy(fqd_queue *q) {
  return q->policy;
}
void
fqd_queue_set_policy(fqd_queue *q, queue_policy_t p) {
  q->policy = p;
}
static void
fqd_queue_free(fqd_queue *q) {
  pthread_mutex_destroy(&q->lock);
  pthread_cond_destroy(&q->cv);
  q->impl->dispose(&q->name, q->impl_data);
  free(q);
}
fqd_queue *
fqd_queue_get(fq_rk *qname, const char *type, const char *params,
              int errlen, char *err) {
  bool error = false, created = false;
  fqd_queue *q = NULL;
  fqd_queue *nq = NULL;
  fqd_config *config;
  char *params_copy, *lastsep = NULL, *tok;
  int permanent = -1; /* unset */
  bool private = true;
  queue_policy_t policy = FQ_POLICY_DROP;
  uint32_t backlog_limit = DEFAULT_QUEUE_LIMIT;
  fqd_queue_impl *queue_impl = &fqd_queue_mem_impl;

  if(!type) type = FQ_DEFAULT_QUEUE_TYPE;
  if(!strcmp(type, "disk")) {
    queue_impl = &fqd_queue_jlog_impl;
  }
  else if(strcmp(type, "mem")) {
    snprintf(err, errlen, "invalid queue type: %s", type);
    return NULL;
  }
  params_copy = strdup(params ? params : "");
  if(!params_copy) {
    snprintf(err, errlen, "memory exhaustion");
    return NULL;
  }
  for (tok = strtok_r(params_copy, ",", &lastsep);
       tok;
       tok = strtok_r(NULL, ",", &lastsep)) {
    if(!strcmp(tok, "private")) private = true;
    else if(!strcmp(tok, "public")) private = false;
    else if(!strcmp(tok, "drop")) policy = FQ_POLICY_DROP;
    else if(!strcmp(tok, "block")) policy = FQ_POLICY_BLOCK;
    else if(!strncmp(tok, "backlog=", 8)) {
      backlog_limit = atoi(tok + 8);
    }
    else if(!strcmp(tok, "permanent")) permanent = 1;
    else if(!strcmp(tok, "transient")) permanent = 0;
    else {
      error = true;
      snprintf(err, errlen, "invalid queue param: %s", tok);
      break;
    }
    if(lastsep == NULL) break;
  }
  free(params_copy);
  if(error) return NULL;

  config = fqd_config_get();
  nq = q = fqd_config_get_registered_queue(config, qname);
  if(q) {
    if(q->private) {
      int i;
      for(i=0; i<MAX_QUEUE_CLIENTS; i++) {
        if(q->downstream[i]) {
          snprintf(err, errlen, "requested queue is private and in use\n");
          fqd_config_release(config);
          return NULL;
        }
      }
    }
  }
  else {
    nq = calloc(1, sizeof(*nq));
    nq->refcnt = 0;
    nq->private = private;
    nq->policy = policy;
    nq->backlog_limit = backlog_limit;
    if(permanent == 1) nq->permanent = true;
    pthread_mutex_init(&nq->lock, NULL);
    pthread_cond_init(&nq->cv, NULL);
    memcpy(&nq->name, qname, sizeof(*qname));
    nq->impl = queue_impl;
    nq->impl_data = nq->impl->setup(qname, &nq->backlog);
    if(nq->impl_data == NULL) {
      snprintf(err, errlen, "initialization of %s queue failed",
               nq->impl->name);
      fqd_queue_free(nq);
      nq = q = NULL;
    }
  }
  fqd_config_release(config);

  if(nq != NULL) {
    q = fqd_config_register_queue(nq, NULL);
    if(nq != q) {
      fqd_queue_free(nq);
    }
    else {
      created = true;
    }
  }
  if(q && q->impl != queue_impl) {
    snprintf(err, errlen, "requested type %s, queue is %s",
             type, q->impl->name);
    q = NULL;
  }
  else if(q && q->private != private) {
    snprintf(err, errlen, "requested %s, queue is %s",
             private ? "private" : "public",
             q->private ? "private" : "public");
    q = NULL;
  }
  else if(q && q->policy != policy) {
    snprintf(err, errlen, "request %s, queue is %s",
             (policy == FQ_POLICY_DROP) ? "drop" : "block",
             (q->policy == FQ_POLICY_DROP) ? "drop" : "block");
    q = NULL;
  }
  /* We don't actually enforce a backlog difference */

  if(q && permanent >= 0) {
    if(!permanent) {
      fqd_config_make_trans_queue(q);
      q->permanent = false;
    }
    else {
      fqd_config_make_perm_queue(q);
      q->permanent = true;
    }
  }
  if(q) {
    (void)created;
    FQ_QUEUE_CREATE_SUCCESS(qname->len, (char *)qname->name, created,
                            (char *)q->impl->name, q->private, q->policy);
  }
  else {
    (void)err;
    FQ_QUEUE_CREATE_FAILURE(qname->len, (char *)qname->name, err);
  }
  return q;
}

