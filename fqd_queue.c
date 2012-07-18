#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <pthread.h>

#include "fqd.h"
#include "ck_pr.h"

#define MAX_QUEUE_CLIENTS 16
#define DEFAULT_QUEUE_LIMIT 16384

struct fqd_queue {
  fq_rk               name;
  bool                private;
  remote_client      *downstream[MAX_QUEUE_CLIENTS];
  /* referenced by: routes and connections */
  queue_policy_t      policy;
  uint32_t            backlog_limit;
  uint32_t            backlog;

  /* These are only use for FQ_POLICY_BLOCK */
  pthread_cond_t      cv;
  pthread_mutex_t     lock;

  uint32_t            refcnt;
  fqd_queue_impl      *impl;
  fqd_queue_impl_data *impl_data;
};

static void fqd_queue_free(fqd_queue *q);

fq_rk *
fqd_queue_name(fqd_queue *q) {
  return &q->name;
}

void
fqd_queue_enqueue(fqd_queue *q, fq_msg *m, int *dropped) {
  while(1) {
    uint32_t backlog;
    backlog = ck_pr_load_uint(&q->backlog);
    if(backlog < q->backlog_limit) break;
    if(q->policy == FQ_POLICY_DROP) {
      if(dropped) (*dropped)++;
      fq_msg_deref(m);
      return;
    }
    else {
      pthread_mutex_lock(&q->lock);
    again:
      backlog = ck_pr_load_uint(&q->backlog);
      if(backlog < q->backlog_limit) {
        pthread_mutex_unlock(&q->lock);
        break;
      }
      pthread_cond_wait(&q->cv, &q->lock);
      goto again;
    }
  }
  ck_pr_inc_32(&q->backlog);
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
  fqd_remote_client_deref(c);
  fqd_queue_deref(q);
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
#ifdef DEBUG
      fq_debug(FQ_DEBUG_CONFIG, "%.*s dropping %s\n",
              q->name.len, q->name.name, c->pretty);
#endif
      fqd_remote_client_deref(c);
      fqd_queue_deref(q);
      if(found) abort();
      found = true;
    }
  }
  return (found && q->private) ? true : false;
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
void
fqd_queue_deref(fqd_queue *q) {
  bool zero;
  fq_stacktrace(FQ_DEBUG_MEM,"fqd_queue_deref",1,2);
  ck_pr_dec_uint_zero(&q->refcnt, &zero);
  fq_debug(FQ_DEBUG_MEM, "Q[%.*s] -> refcnt:%u\n", q->name.len, q->name.name, q->refcnt);
  if(zero) {
    fq_debug(FQ_DEBUG_CONFIG, "dropping queue(%p) %.*s\n",
            (void *)q, q->name.len, q->name.name);
    fqd_queue_free(q);
  }
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
  q->impl->dispose(q->impl_data);
  free(q);
}
fqd_queue *
fqd_queue_get(fq_rk *qname, const char *type, const char *params,
              int errlen, char *err) {
  bool error = false;
  fqd_queue *q = NULL;
  fqd_config *config;
  char *params_copy, *lastsep = NULL, *tok;

  bool private = true;
  queue_policy_t policy = FQ_POLICY_DROP;
  uint32_t backlog_limit = DEFAULT_QUEUE_LIMIT;
  fqd_queue_impl *queue_impl = &fqd_queue_mem_impl;

  if(!type) type = FQ_DEFAULT_QUEUE_TYPE;
  if(strcmp(type, "mem")) {
    snprintf(err, errlen, "invalid queue type: %s", type);
    return NULL;
  }
  params_copy = strdup(params ? params : "");
  tok = NULL;
  while(NULL != (tok = strtok_r(tok ? NULL : params_copy, ":", &lastsep))) {
    if(!strcmp(tok, "private")) private = true;
    else if(!strcmp(tok, "public")) private = false;
    else if(!strcmp(tok, "drop")) policy = FQ_POLICY_DROP;
    else if(!strcmp(tok, "block")) policy = FQ_POLICY_BLOCK;
    else if(!strncmp(tok, "backlog=", 8)) {
      backlog_limit = atoi(tok + 8);
    }
    else {
      error = true;
      snprintf(err, errlen, "invalid queue param: %s", tok);
      break;
    }
  }
  free(params_copy);
  if(error) return NULL;

  config = fqd_config_get();

  q = fqd_config_get_registered_queue(config, qname);
  if(q == NULL) {
    fqd_queue *nq;
    nq = calloc(1, sizeof(*nq));
    nq->refcnt = 0;
    nq->private = private;
    nq->policy = policy;
    nq->backlog_limit = backlog_limit;
    pthread_mutex_init(&nq->lock, NULL);
    pthread_cond_init(&nq->cv, NULL);
    memcpy(&nq->name, qname, sizeof(*qname));
    nq->impl = queue_impl;
    nq->impl_data = nq->impl->setup(qname, &nq->backlog);
    q = fqd_config_register_queue(nq, NULL);
    if(nq != q) {
      fqd_queue_free(nq);
    }
  }
  if(q->impl != queue_impl) {
    snprintf(err, errlen, "requested type %s, queue is %s",
             type, q->impl->name);
    q = NULL;
  }
  else if(q->private != private) {
    snprintf(err, errlen, "requested %s, queue is %s",
             private ? "private" : "public",
             q->private ? "private" : "public");
    q = NULL;
  }
  else if(q->policy != policy) {
    snprintf(err, errlen, "request %s, queue is %s",
             (policy == FQ_POLICY_DROP) ? "drop" : "block",
             (q->policy == FQ_POLICY_DROP) ? "drop" : "block");
    q = NULL;
  }
  /* We don't actually enforce a backlog difference */

  fqd_config_release(config);
  return q;
}

