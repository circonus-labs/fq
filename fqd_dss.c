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

#include "fq.h"
#include "fqd.h"
#include "fq_dtrace.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>

#include <ck_fifo.h>
#include <ck_pr.h>

#define IN_READ_BUFFER_SIZE 1024*256

static ck_fifo_spsc_t *work_queues;
static uint32_t *work_queue_backlogs;
static int *worker_thread_ids;
static int worker_thread_count = 0;
static pthread_t *worker_threads;
static bool worker_thread_shutdown = false;

struct incoming_message
{
  remote_data_client *client;
  fq_msg *msg;
};

void *
fqd_worker_thread(void *arg)
{
  struct incoming_message *m;
  int tindex = *(int*) arg;

  ck_fifo_spsc_t *q = &work_queues[tindex];
  uint32_t *backlog = &work_queue_backlogs[tindex];

  while (!worker_thread_shutdown) {
    if (!CK_FIFO_SPSC_ISEMPTY(q)) {
      bool success;
      ck_fifo_spsc_dequeue_lock(q);
      success = ck_fifo_spsc_dequeue(q, &m);
      ck_fifo_spsc_dequeue_unlock(q);
      if (success) {
        if (m != NULL) {
          ck_pr_dec_32(backlog);
          fq_msg *copy = fq_msg_alloc_BLANK(m->msg->payload_len);
          if (copy == NULL) {
            continue;
          }
          memcpy(copy, m->msg, sizeof(fq_msg) + m->msg->payload_len);
          /* reset the refcnt on the copy since the memcpy above will have overwritten it */
          copy->refcnt = 1;
          /* the copy will be freed as normal so eliminate cleanup_stack pointer */
          copy->free_fn = NULL;
          copy->cleanup_handle = NULL;

          /* we are done with the incoming message, deref */
          fq_msg_deref(m->msg);

          fqd_inject_message(m->client, copy);
	  fqd_remote_client_deref((remote_client *)m->client);
          free(m);
        }
      }
    } else {
      usleep(1000);
    }
  }

  /* drain the queue before exiting */
  if (!CK_FIFO_SPSC_ISEMPTY(q)) {
    bool success;
    ck_fifo_spsc_dequeue_lock(q);
    success = ck_fifo_spsc_dequeue(q, &m);
    ck_fifo_spsc_dequeue_unlock(q);
    if (success) {
      if (m != NULL) {
        ck_pr_dec_32(backlog);
        fq_msg *copy = fq_msg_alloc_BLANK(m->msg->payload_len);
        memcpy(copy, m->msg, sizeof(fq_msg) + m->msg->payload_len);
        /* the copy will be freed as normal so eliminate cleanup_stack pointer */
        copy->cleanup_handle = NULL;
        /* we are done with the incoming message, drop it on it's cleanup stack */
        fqd_inject_message(m->client, copy);
        fq_msg_deref(m->msg);
        free(m);
      }
    }
  }
  usleep(10);
  return NULL;
}

void 
fqd_start_worker_threads(int thread_count) 
{
  int i = 0;
  worker_thread_count = thread_count;
  work_queues = calloc(thread_count, sizeof(ck_fifo_spsc_t));
  work_queue_backlogs = calloc(thread_count, sizeof(uint32_t));
  worker_threads = calloc(thread_count, sizeof(pthread_t));
  worker_thread_ids = calloc(thread_count, sizeof(int));
  
  for ( ; i < thread_count; i++) {
    worker_thread_ids[i] = i;
    ck_fifo_spsc_init(&work_queues[i], malloc(sizeof(ck_fifo_spsc_entry_t)));
    pthread_create(&worker_threads[i], NULL, fqd_worker_thread, &worker_thread_ids[i]);
  }
}

void 
fqd_stop_worker_threads() 
{
  int i = 0;
  worker_thread_shutdown = true;

  for ( ; i < worker_thread_count; i++) {
    pthread_join(worker_threads[i], NULL);
  }
}

static void 
fqd_queue_message_process(remote_data_client *me, fq_msg *msg)
{
  ck_fifo_spsc_t *work_queue = NULL;
  ck_fifo_spsc_entry_t *entry = NULL, *tofree = NULL;
  int i = 0, tindex = 0;
  uint32_t blmin = UINT_MAX;
  struct incoming_message *m = malloc(sizeof(struct incoming_message));
  
  m->client = me;
  m->msg = msg;

  /* while we live in this queue, we ref the client so it can't be destroyed until the queue is cleared of it */
  fqd_remote_client_ref((remote_client *) m->client);

  /* find the least loaded queue */
  for ( ; i < worker_thread_count; i++) {
    uint32_t x = work_queue_backlogs[i];
    if (x < blmin) {
      blmin = x;
      tindex = i;
    }
  }
    
  ck_pr_inc_32(&work_queue_backlogs[tindex]);
  work_queue = &work_queues[tindex];
  ck_fifo_spsc_enqueue_lock(work_queue);
  entry = ck_fifo_spsc_recycle(work_queue);
  if (entry == NULL) {
    ck_fifo_spsc_enqueue_unlock(work_queue);
    tofree = malloc(sizeof(ck_fifo_spsc_entry_t));
    ck_fifo_spsc_enqueue_lock(work_queue);
    entry = ck_fifo_spsc_recycle(work_queue);
    if(entry == NULL) {
      entry = tofree;
      tofree = NULL;
    }
  }
  ck_fifo_spsc_enqueue(work_queue, entry, m);
  ck_fifo_spsc_enqueue_unlock(work_queue);
  free(tofree);
}

static void
fqd_dss_read_complete(void *closure, fq_msg *msg) {
  int i;
  remote_client *parent = closure;
  remote_data_client *me = parent->data;
  msg->hops[0] = fqd_config_get_nodeid();
  if(me->mode == FQ_PROTO_DATA_MODE) {
    memcpy(&msg->sender, &parent->user, sizeof(parent->user));
    memcpy(&msg->hops[1], &me->remote.sin_addr, sizeof(uint32_t));
  }
  if(msg->payload_len > MAX_MESSAGE_SIZE) {
    me->size_dropped++;
    fqd_size_dropped(1);
    fq_msg_deref(msg);
    return;
  }
  me->msgs_in++;
  me->octets_in += (1 + msg->exchange.len) +
                   (1 + msg->route.len) +
                   sizeof(fq_msgid) +
                   (4 + msg->payload_len);
  if(me->mode == FQ_PROTO_PEER_MODE) {
    me->octets_in += 1 + msg->sender.len;
    me->octets_in += 1; /* nhops */
    for(i=0;i<MAX_HOPS;i++) {
      if(msg->hops[i] != 0) {
        me->octets_in += 4;
      }
    }
  }
  if(FQ_MESSAGE_RECEIVE_ENABLED()) {
    fq_dtrace_msg_t dmsg;
    fq_dtrace_remote_client_t dpc;
    fq_dtrace_remote_data_client_t dme;
    DTRACE_PACK_MSG(&dmsg, msg);
    DTRACE_PACK_CLIENT(&dpc, parent);
    DTRACE_PACK_DATA_CLIENT(&dme, me);
    FQ_MESSAGE_RECEIVE(&dpc, &dme, &dmsg);
  }

  /* don't do any work here, just drop the message on one of N processing queues */
  fqd_queue_message_process(me, msg);

}

static void
fqd_data_driver(remote_client *parent) {
  remote_data_client *me = parent->data;
  fq_msg *inflight = NULL;
  size_t inflight_sofar = 0;
  buffered_msg_reader *ctx = NULL;
  int had_msgs = 1, flags, needs_write = 1;

  if(((flags = fcntl(me->fd, F_GETFL, 0)) == -1) ||
     (fcntl(me->fd, F_SETFL, flags | O_NONBLOCK) == -1))
    return;

  ctx = fq_buffered_msg_reader_alloc(me->fd, (me->mode == FQ_PROTO_PEER_MODE));
  while(1) {
    uint32_t msgs_in = me->msgs_in, msgs_out = me->msgs_out;
    int rv, timeout_ms = 1000;
    struct pollfd pfd;
    pfd.fd = me->fd;
    pfd.events = POLLIN|POLLHUP;
    if(needs_write) pfd.events |= POLLOUT;
    pfd.revents = 0;
    if(parent->heartbeat_ms && parent->heartbeat_ms < timeout_ms)
      timeout_ms = parent->heartbeat_ms;
    /* if we had msgs, but aren't waiting for write,
     * then we set a very short timeout
     */
    if(had_msgs && !needs_write) timeout_ms = 1;

    rv = poll(&pfd, 1, timeout_ms);
    if(rv < 0) break;

    had_msgs = 0;
    if(rv > 0 && (pfd.revents & POLLIN)) {
      me->last_heartbeat = me->last_activity = fq_gethrtime();
      if(fq_buffered_msg_read(ctx, fqd_dss_read_complete, parent) < 0) {
        fq_debug(FQ_DEBUG_IO, "client read error\n");
        break;
      }
      had_msgs = 1;
    }

    if(!needs_write || (rv > 0 && (pfd.revents & POLLOUT))) {
      fq_msg *m;
      needs_write = 0;
     haveanother:
      m = inflight ? inflight
                   : parent->queue ? fqd_queue_dequeue(parent->queue)
                                   : NULL;

      /* If we're in peer mode, we can just toss messages the remote has seen */
      if(m && me->mode == FQ_PROTO_PEER_MODE &&
         fq_find_in_hops(me->peer_id, m) >= 0) {
        fq_msg_deref(m);
        goto haveanother;
      }

      inflight = NULL;
      while(m) {
        int written;
        size_t octets_out = 0;
        had_msgs = 1;
        written = fq_client_write_msg(me->fd, 1, m, inflight_sofar, &octets_out);
        if(written > 0) inflight_sofar += written;
        if(octets_out) me->octets_out += octets_out;

        if(written > 0 || (written < 0 && errno == EAGAIN)) {
          inflight = m;
          needs_write = 1;
          break;
        }
        else if(written < 0) {
          fq_debug(FQ_DEBUG_IO, "client write error\n");
          goto broken;
        }

        if(FQ_MESSAGE_DELIVER_ENABLED()) {
          fq_dtrace_msg_t dmsg;
          fq_dtrace_remote_client_t dpc;
          fq_dtrace_remote_data_client_t dme;
          DTRACE_PACK_MSG(&dmsg, m);
          DTRACE_PACK_CLIENT(&dpc, parent);
          DTRACE_PACK_DATA_CLIENT(&dme, me);
          FQ_MESSAGE_DELIVER(&dpc, &dme, &dmsg);
        }
        fq_msg_deref(m);
        me->msgs_out++;
        inflight_sofar = 0;
        m = parent->queue ? fqd_queue_dequeue(parent->queue) : NULL;
      }
    }

    if(me->msgs_in != msgs_in || me->msgs_out != msgs_out)
      fq_debug(FQ_DEBUG_MSG, "Round.... %d in, %d out\n", me->msgs_in, me->msgs_out);
  }
broken:
  if(inflight) {
    /* We're screwed here... we might have delivered it. so just toss it */
    fq_msg_deref(inflight);
  }
  if(ctx) fq_buffered_msg_reader_free(ctx);
  parent->data = NULL;
  fq_debug(FQ_DEBUG_IO, "data path from client ended: %s\n", parent->pretty);
}

extern void
fqd_data_subscription_server(remote_data_client *client) {
  int len;
  char buf[260];
  fqd_config *config;
  remote_client *parent;
  fq_rk key;
  fq_debug(FQ_DEBUG_CONN, "--> dss thread [%s]\n",
           client->mode == FQ_PROTO_DATA_MODE ? "client" : "peer");
  if((len = fq_read_short_cmd(client->fd, sizeof(key.name), key.name)) < 0)
    return;
  if(len > (int)sizeof(key.name)) return;
  key.len = len;

  fq_rk_to_hex(buf, sizeof(buf), &key);
  fq_debug(FQ_DEBUG_CONN, "data conn w/ key:\n%s\n", buf);

  config = fqd_config_get();
  parent = fqd_config_get_registered_client(config, &key);
  fqd_config_release(config);
  if(!parent) return;
  if(parent->data) return;
  ck_pr_cas_ptr(&parent->data, NULL, client);
  if(parent->data != client) {
    fq_debug(FQ_DEBUG_CONN, "%s dss double gang rejected\n", parent->pretty);
    return;
  }
  if(FQ_CLIENT_AUTH_DATA_ENABLED()) {
    fq_dtrace_remote_data_client_t dclient;
    DTRACE_PACK_DATA_CLIENT(&dclient, client);
    FQ_CLIENT_AUTH_DATA(&dclient);
  }
  fqd_remote_client_ref(parent);
  fqd_data_driver(parent);
  fq_clear_message_cleanup_stack();
  fqd_remote_client_deref(parent);
  fq_debug(FQ_DEBUG_CONN, "<-- dss thread\n");
}
