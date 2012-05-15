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
  fqd_remote_client_ref(c);
  for(i=0;i<MAX_QUEUE_CLIENTS;i++) {
    if(q->downstream[i] == NULL) {
      if(ck_pr_cas_ptr(&q->downstream[i], NULL, c) == true) {
        fqd_queue_ref(q);
#ifdef DEBUG
        fq_debug(FQ_DEBUG_CONFIG, "%.*s adding %s\n",
                 q->name.len, q->name.name, c->pretty);
#endif
        return 0;
      }
    }
  }
  fqd_remote_client_deref(c);
  return -1;
}
int
fqd_queue_deregister_client(fqd_queue *q, remote_client *c) {
  int i;
  for(i=0;i<MAX_QUEUE_CLIENTS;i++) {
    if(q->downstream[i] == c) {
      q->downstream[i] = NULL;
#ifdef DEBUG
      fq_debug(FQ_DEBUG_CONFIG, "%.*s dropping %s\n",
              q->name.len, q->name.name, c->pretty);
#endif
      fqd_remote_client_deref(c);
      fqd_queue_deref(q);
      return 0;
    }
  }
  abort();
}
int
fqd_queue_cmp(const fqd_queue *a, const fqd_queue *b) {
  return fq_rk_cmp(&a->name, &b->name);
}

void
fqd_queue_ref(fqd_queue *q) {
  ck_pr_inc_uint(&q->refcnt);
}
void
fqd_queue_deref(fqd_queue *q) {
  bool zero;
  ck_pr_dec_uint_zero(&q->refcnt, &zero);
  if(zero) {
    fq_debug(FQ_DEBUG_CONFIG, "dropping queue(%p) %.*s\n",
            (void *)q, q->name.len, q->name.name);
    free(q);
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
  free(q);
}
fqd_queue *
fqd_queue_get(fq_rk *qname) {
  fqd_queue *q = NULL;
  fqd_config *config;
  config = fqd_config_get();

  q = fqd_config_get_registered_queue(config, qname);
  if(q == NULL) {
    fqd_queue *nq;
    nq = calloc(1, sizeof(*nq));
    nq->refcnt = 1;
    nq->policy = FQ_POLICY_DROP;
    nq->backlog_limit = DEFAULT_QUEUE_LIMIT;
    pthread_mutex_init(&nq->lock, NULL);
    pthread_cond_init(&nq->cv, NULL);
    memcpy(&nq->name, qname, sizeof(*qname));
    nq->impl = &fqd_queue_mem_impl;
    nq->impl_data = nq->impl->setup(qname, &nq->backlog);
    q = fqd_config_register_queue(nq, NULL);
    if(nq != q) {
      /* race */
      nq->impl->dispose(nq->impl_data);
      fqd_queue_free(nq);
    }
  }

  fqd_config_release(config);
  return q;
}

