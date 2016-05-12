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

#include "fqd.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <uuid/uuid.h>
#include <ftw.h>
#include <jlog.h>
#include <jlog_private.h>
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

  uuid_t    uuid;
  /*
   * If we create a transient queue, diconnect and reconnect with the same
   * transient queue then we expose a condition where the original queue
   * has not been reaped (as it exists in older config version, but the
   * new queue has the same name.
   *
   * For in-memory queues, this is no issue.  Because the jlog implementation
   * stores the queue on disk (and must find it later on restart) there is a
   * chance that the disposal of an old queue would wipe the new queue's
   * on-disk structure rendering it completely busted.
   *
   * When a jlog queue is initially setup here, we generate a uuid and store
   * that in the path/.sig file.  If we have a race such as above, then
   * the disposal will come along and notice that the .sig does not match
   * its uuid.  This indicates to the disposal that another queue owns the
   * on-disk structure and it should skip the unlink/rmdir removal.
   */
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
          strncpy(idxfile + strlen(idxfile), INDEX_EXT, sizeof(idxfile) - strlen(idxfile));
          unlink(idxfile);
          STRSETDATAFILE(d->reader, idxfile, d->start.log + 1);
          strncpy(idxfile + strlen(idxfile), INDEX_EXT, sizeof(idxfile) - strlen(idxfile));
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

/*
 * returns -1 when the incoming checkpoint is out of range of the log
 * returns -2 if there was an error actually setting the checkpoint
 */
static int queue_log_add_checkpoint(fqd_queue_impl_data data, const char *name, const fq_msgid *id)
{
  struct queue_jlog *d = (struct queue_jlog *)data;

  jlog_id jid = {
    .log = id->id.u32.p1,
    .marker = id->id.u32.p2
  };

  /* ensure the checkpoint makes sense */
  jlog_id first = {
    .log = 0,
    .marker = 0
  };
  jlog_id last = {
    .log = 0,
    .marker = 0
  };
  jlog_ctx_first_log_id(d->reader, &first);
  jlog_ctx_last_log_id(d->reader, &last);

  if (! (jid.log >= first.log && jid.log <= last.log &&
         jid.marker >= first.marker && jid.marker <= last.marker)) {
    return -1;
  }

  char **subs;
  int sub_count = jlog_ctx_list_subscribers(d->reader, &subs);

  int have_it = 0;
  for (int i = 0; i < sub_count; i++) {
    have_it += strcmp(subs[i], name) == 0 ? 1 : 0;
  }

  if (have_it == 0) {
    jlog_ctx_add_subscriber(d->reader, name, JLOG_BEGIN);
  }

  if (jlog_ctx_read_checkpoint(d->reader, &jid) == -1) {
    /*
       If we failed to checkpoint we are in a situation where the 'add_subscriber' call above put
       them at the beginning of the log so we have to remove the subscriber if we just added them

       However, if they already existed and had a previous good checkpoint, leave it alone
    */
    if (have_it == 0) {
      jlog_ctx_remove_subscriber(d->reader, name);
    }
    return -2;
  }
  return 0;
}

/*
 * return -1 if the subscriber doesn't exist
 * return 0 on success
 */
static int queue_log_remove_checkpoint(fqd_queue_impl_data data, const char *name)
{
  struct queue_jlog *d = (struct queue_jlog *)data;

  if (jlog_ctx_remove_subscriber(d->reader, name) == 0) {
    return -1;
  }
  return 0;
}

/*
 * return -1 if the subscriber doesn't exist
 * return -2 if we can't reset the checkpoint
 * return 0 on success
 */
static int queue_log_reset_to_checkpoint(fqd_queue_impl_data data, const char *name)
{
  struct queue_jlog *d = (struct queue_jlog *)data;

  char **subs;
  int sub_count = jlog_ctx_list_subscribers(d->reader, &subs);

  int have_it = 0;
  for (int i = 0; i < sub_count; i++) {
    have_it += strcmp(subs[i], name) == 0 ? 1 : 0;
  }

  if (have_it == 0) {
    return -1;
  }

  jlog_id checkpoint;
  if (jlog_get_checkpoint(d->reader, name, &checkpoint) == -1) {
    return -2;
  }

  if (jlog_ctx_read_checkpoint(d->reader, &checkpoint) == -1) {
    return -2;
  }
  return 0;
}


static int write_sig(struct queue_jlog *d) {
  char sigfile[PATH_MAX];
  int fd;
  snprintf(sigfile, sizeof(sigfile), "%s/.sig", d->qpath);
  fd = open(sigfile, O_CREAT|O_TRUNC|O_WRONLY, 0640);
  if(fd < 0) return -1;
  write(fd, d->uuid, 16);
  close(fd);
  return 0;
}
static int read_sig(struct queue_jlog *d, uuid_t out) {
  char sigfile[PATH_MAX];
  int fd, rv;
  snprintf(sigfile, sizeof(sigfile), "%s/.sig", d->qpath);
  fd = open(sigfile, O_RDONLY);
  if(fd < 0) return -1;
  rv = read(fd, out, 16);
  close(fd);
  return (rv == 16) ? 0 : -1;
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
  jlog_ctx_set_use_compression(d->writer, 1);

  if(jlog_ctx_open_writer(d->writer) != 0) {
    jlog_ctx_close(d->writer);
    d->writer = jlog_new(d->qpath);
    jlog_ctx_set_use_compression(d->writer, 1);
    if(jlog_ctx_init(d->writer) != 0) {
      fq_debug(FQ_DEBUG_IO, "jlog init: %s\n", jlog_ctx_err_string(d->writer));
      goto bail;
    }
    jlog_ctx_close(d->writer);
    d->writer = jlog_new(d->qpath);
    jlog_ctx_set_use_compression(d->writer, 1);
    if(jlog_ctx_open_writer(d->writer) != 0) {
      fq_debug(FQ_DEBUG_IO, "jlog writer: %s\n", jlog_ctx_err_string(d->writer));
      goto bail;
    }
  }

  /* 128MB journal chunks */
  jlog_ctx_alter_journal_size(d->writer, 128 * 1024 * 1024);

  d->reader = jlog_new(d->qpath);
  jlog_ctx_set_use_compression(d->reader, 1);
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
  uuid_generate(d->uuid);
  write_sig(d);
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

static int
multi_unlink(const char *path, const struct stat *sb, int d, struct FTW *f) {
  (void)sb;
  (void)f;
  if(d == FTW_D) rmdir(path);
  else unlink(path);
  return 0;
}

static void queue_jlog_dispose(fq_rk *qname, fqd_queue_impl_data f)
{
  struct queue_jlog *d = (struct queue_jlog *)f;
  uuid_t exist;
  (void)qname;

  if (d == NULL) {
    /* there was likely a total failure to init this queue type
       due to file system permissions, bail
    */
    return;
  }

  uuid_clear(exist);
  read_sig(d, exist);
  if(uuid_compare(d->uuid, exist) == 0) {
    /* This is my jlog queue ... I can delete it */
    fq_debug(FQ_DEBUG_IO, "jlog: removing %s\n", d->qpath);
    nftw(d->qpath, multi_unlink, 2, FTW_DEPTH);
    rmdir(d->qpath);
  }
  free(d);
}

fqd_queue_impl fqd_queue_jlog_impl = {
  .name = "disk",
  .setup = queue_jlog_setup,
  .enqueue = queue_jlog_enqueue,
  .dequeue = queue_jlog_dequeue,
  .dispose = queue_jlog_dispose,
  .add_checkpoint = queue_log_add_checkpoint,
  .remove_checkpoint = queue_log_remove_checkpoint,
  .reset_checkpoint = queue_log_reset_to_checkpoint
};
