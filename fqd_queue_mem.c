#include "fqd.h"
#include <stdlib.h>
#include <ck_fifo.h>

struct queue_mem {
  uint32_t              qlen;
  ck_fifo_mpmc_t        q;
  ck_fifo_mpmc_entry_t *qhead;
};

static void queue_mem_enqueue(fqd_queue_impl_data f, fq_msg *m) {
  struct queue_mem *d = (struct queue_mem *)f;
  ck_fifo_mpmc_entry_t *fifo_entry;
  fifo_entry = malloc(sizeof(ck_fifo_mpmc_entry_t));
  fq_msg_ref(m);
  ck_fifo_mpmc_enqueue(&d->q, fifo_entry, m);
  ck_pr_inc_uint(&d->qlen);
}
static fq_msg *queue_mem_dequeue(fqd_queue_impl_data f) {
  struct queue_mem *d = (struct queue_mem *)f;
  ck_fifo_mpmc_entry_t *garbage;
  fq_msg *m;
  if(ck_fifo_mpmc_dequeue(&d->q, &m, &garbage) == true) {
    ck_pr_dec_uint(&d->qlen);
    free(garbage);
    return m;
  }
  return NULL;
}
static fqd_queue_impl_data queue_mem_setup(fq_rk *qname, uint32_t *count) {
  struct queue_mem *d;
  d = calloc(1, sizeof(*d));
  d->qhead = malloc(sizeof(ck_fifo_mpmc_entry_t));
  *count = 0;
  ck_fifo_mpmc_init(&d->q, d->qhead);
  (void)qname;
  return d;
}
static void queue_mem_dispose(fqd_queue_impl_data f) {
  struct queue_mem *d = (struct queue_mem *)f;
  fq_msg *m;
  while(NULL != (m = queue_mem_dequeue(d))) {
    fq_msg_deref(m);
  }
  free(d->qhead);
  free(d);
}

fqd_queue_impl fqd_queue_mem_impl = {
  .setup = queue_mem_setup,
  .enqueue = queue_mem_enqueue,
  .dequeue = queue_mem_dequeue,
  .dispose = queue_mem_dispose
};
