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

int
fqd_queue_register_client(fqd_queue *q, remote_client *c) {
  int i;
  fqd_remote_client_ref(c);
  for(i=0;i<MAX_QUEUE_CLIENTS;i++) {
    if(q->downstream[i] == NULL) {
      if(ck_pr_cas_ptr(&q->downstream[i], NULL, c) == true) {
#ifdef DEBUG
      fprintf(stderr, "%.*s adding %s\n",
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
      fprintf(stderr, "%.*s dropping %s\n",
              q->name.len, q->name.name, c->pretty);
#endif
      fqd_remote_client_deref(c);
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
#ifdef DEBUG
    fprintf(stderr, "dropping queue(%p) %.*s\n",
            (void *)q, q->name.len, q->name.name);
#endif
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
    q = fqd_config_register_queue(nq);
    if(nq != q) {
      /* race */
      free(nq);
    }
  }

  fqd_config_release(config);
  return q;
}

