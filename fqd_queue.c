#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "fqd.h"
#include "ck_pr.h"

#define MAX_QUEUE_CLIENTS 16

struct fqd_queue {
  fq_rk               name;
  remote_client      *downstream[MAX_QUEUE_CLIENTS];
  /* referenced by: routes and connections */
  uint32_t            refcnt;
  fqd_queue_impl      *impl;
  fqd_queue_impl_data *impl_data;
};

fq_rk *
fqd_queue_name(fqd_queue *q) {
  return &q->name;
}

void
fqd_queue_enqueue(fqd_queue *q, fq_msg *m) {
  q->impl->enqueue(q->impl_data, m);
}
fq_msg *
fqd_queue_dequeue(fqd_queue *q) {
  return q->impl->dequeue(q->impl_data);
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
    memcpy(&nq->name, qname, sizeof(*qname));
    nq->impl = &fqd_queue_mem_impl;
    nq->impl_data = nq->impl->setup(qname);
    q = fqd_config_register_queue(nq, NULL);
    if(nq != q) {
      /* race */
      nq->impl->dispose(nq->impl_data);
      free(nq);
    }
  }

  fqd_config_release(config);
  return q;
}

