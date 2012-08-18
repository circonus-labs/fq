#include "fqd.h"
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include "jlog/jlog.h"
#include "jlog/jlog_private.h"
#include "ck_pr.h"

struct queue_jlog {
  bool      auto_chkpt;
  uint32_t  nenqueued;
  uint32_t  last_seen_nenqueued;
  char     *qpath;
  jlog_ctx *writer;
  jlog_ctx *reader;
  jlog_id   start;
  jlog_id   finish;
  jlog_id   last_dequeued;
  int       count;

  uint32_t  errors;
};

static void queue_jlog_enqueue(fqd_queue_impl_data f, fq_msg *m) {
  struct queue_jlog *d = (struct queue_jlog *)f;
  size_t wlen;
  wlen = offsetof(fq_msg, payload) + m->payload_len;
  if(jlog_ctx_write(d->writer, m, wlen) != 0) {
    ck_pr_inc_uint(&d->errors);
  }
  ck_pr_inc_uint(&d->nenqueued);
}
static fq_msg *queue_jlog_dequeue(fqd_queue_impl_data f) {
  struct queue_jlog *d = (struct queue_jlog *)f;
  jlog_message msg;
  fq_msg *m;
  if(d->count == 0 && d->last_seen_nenqueued == d->nenqueued) return NULL;
 retry:
  if(d->count <= 0) {
    d->count = jlog_ctx_read_interval(d->reader, &d->start, &d->finish);
fq_debug(FQ_DEBUG_IO, "jlog read batch count -> %d\n", d->count);
    if(d->count < 0) {
      char idxfile[PATH_MAX];
      fq_debug(FQ_DEBUG_IO, "jlog_ctx_read_interval: %s\n",
               jlog_ctx_err_string(d->reader));
      switch (jlog_ctx_err(d->reader)) {
        case JLOG_ERR_FILE_CORRUPT:
        case JLOG_ERR_IDX_CORRUPT:
          jlog_repair_datafile(d->reader, d->start.log);
          jlog_repair_datafile(d->reader, d->start.log + 1);
          fq_debug(FQ_DEBUG_IO,
                "jlog reconstructed, deleting corresponding index.\n");
          STRSETDATAFILE(d->reader, idxfile, d->start.log);
          strlcat(idxfile, INDEX_EXT, sizeof(idxfile));
          unlink(idxfile);
          STRSETDATAFILE(d->reader, idxfile, d->start.log + 1);
          strlcat(idxfile, INDEX_EXT, sizeof(idxfile));
          unlink(idxfile);
          break;
        default:
          break;
      }
    }
    if(d->count <= 0) return NULL;
  }
  if(jlog_ctx_read_message(d->reader, &d->start, &msg) == -1) {
    d->count = 0;
    return NULL;
  }
  if(d->last_dequeued.log > d->start.log ||
     (d->last_dequeued.log == d->start.log &&
      d->last_dequeued.marker > d->start.marker)) {
    d->count--;
    JLOG_ID_ADVANCE(&d->start);
    goto retry;
  }
  if(msg.mess_len < sizeof(fq_msg)-1)
    m = NULL;
  else {
    off_t expected_len;
    uint32_t payload_len;
    m = (fq_msg *)msg.mess;
    memcpy(&payload_len, &m->payload_len, sizeof(m->payload_len));
    expected_len = offsetof(fq_msg, payload) + payload_len;
    if(expected_len != msg.mess_len) m = NULL;
    else {
      m = malloc(expected_len);
      memcpy(m, msg.mess, expected_len);
      m->sender_msgid.id.u32.p3 = d->start.log;
      m->sender_msgid.id.u32.p4 = d->start.marker;
    }
  }
  d->count--;
fq_debug(FQ_DEBUG_IO, "jlog batch count -> %d\n", d->count);
  if(d->count == 0) {
    if(d->auto_chkpt) {
      jlog_ctx_read_checkpoint(d->reader, &d->start);
    }
  }
  d->last_dequeued = d->start;
  JLOG_ID_ADVANCE(&d->start);
  ck_pr_inc_uint(&d->last_seen_nenqueued);
  return m;
}

static fqd_queue_impl_data queue_jlog_setup(fq_rk *qname, uint32_t *count) {
  char qpath[PATH_MAX];
  jlog_id chkpt;
  struct queue_jlog *d;

  d = calloc(1, sizeof(*d));
  d->auto_chkpt = true;
  fqd_config_construct_queue_path(qpath, sizeof(qpath), qname);
  d->qpath = strdup(qpath);
  d->writer = jlog_new(d->qpath);
  if(jlog_ctx_open_writer(d->writer) != 0) {
    jlog_ctx_close(d->writer);
    d->writer = jlog_new(d->qpath);
    if(jlog_ctx_init(d->writer) != 0) {
      fq_debug(FQ_DEBUG_IO, "jlog init: %s\n", jlog_ctx_err_string(d->writer));
      goto bail;
    }
    jlog_ctx_close(d->writer);
    d->writer = jlog_new(d->qpath);
    if(jlog_ctx_open_writer(d->writer) != 0) {
      fq_debug(FQ_DEBUG_IO, "jlog writer: %s\n", jlog_ctx_err_string(d->writer));
      goto bail;
    }
  }
  d->reader = jlog_new(d->qpath);
  if(jlog_get_checkpoint(d->reader, "fq", &chkpt) != 0) {
    if(jlog_ctx_add_subscriber(d->reader, "fq", JLOG_BEGIN) != 0) {
      fq_debug(FQ_DEBUG_IO, "jlog add sub: %s\n", jlog_ctx_err_string(d->reader));
      goto bail;
    }
  }
  if(jlog_ctx_open_reader(d->reader, "fq") != 0) {
    fq_debug(FQ_DEBUG_IO, "jlog: %s\n", jlog_ctx_err_string(d->reader));
    goto bail;
  }
  *count = 0;
  (void)qname;
  return d;

 bail:
  if(d->writer) jlog_ctx_close(d->writer);
  if(d->reader) jlog_ctx_close(d->reader);
  free(d->qpath);
  free(d);
  return NULL;
}
static void queue_jlog_dispose(fqd_queue_impl_data f) {
  struct queue_jlog *d = (struct queue_jlog *)f;
  free(d);
}

fqd_queue_impl fqd_queue_jlog_impl = {
  .name = "disk",
  .setup = queue_jlog_setup,
  .enqueue = queue_jlog_enqueue,
  .dequeue = queue_jlog_dequeue,
  .dispose = queue_jlog_dispose
};
