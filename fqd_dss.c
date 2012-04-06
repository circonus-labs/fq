#include "fqd.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <assert.h>

#include <ck_pr.h>

#define IN_READ_BUFFER_SIZE 1024*256

static void
fqd_dss_read_complete(void *closure, fq_msg *msg) {
  int i;
  remote_client *parent = closure;
  remote_data_client *me = parent->data;
  if(me->mode == FQ_PROTO_DATA_MODE) {
    memcpy(&msg->sender, &parent->user, sizeof(parent->user));
    memcpy(msg->hops, &me->remote.sin_addr, sizeof(uint32_t));
  }
  for(i=0;i<MAX_HOPS;i++) {
    if(msg->hops[i] == 0) {
      msg->hops[i] = fqd_config_get_nodeid();
      break;
    }
  }
  fqd_inject_message(parent, msg);
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
    int rv, timeout_ms = 1000;
    struct pollfd pfd;
    pfd.fd = me->fd;
    pfd.events = POLLIN;
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

    if(rv > 0 && (pfd.revents & POLLIN)) {
      me->last_heartbeat = me->last_activity = fq_gethrtime();
      if(fq_buffered_msg_read(ctx, fqd_dss_read_complete, parent) < 0) {
        fq_debug("client read error\n");
        break;
      }
    }

    if(!needs_write || (rv > 0 && (pfd.revents & POLLOUT))) {
      fq_msg *m;
      needs_write = 0;
      m = inflight ? inflight : fqd_queue_dequeue(parent->queue);
      inflight = NULL;
      while(m) {
        int written;
        written = fq_client_write_msg(me->fd, 1, m, inflight_sofar);
        if(written > 0) inflight_sofar += written;

        if(written > 0 || (written < 0 && errno == EAGAIN)) {
          inflight = m;
          needs_write = 1;
          break;
        }
        else if(written < 0) {
          fq_debug("client write error\n");
          goto broken;
        }

        inflight_sofar = 0;
        m = fqd_queue_dequeue(parent->queue);
      }
    }
  }
broken:
  if(inflight) {
    /* We're screwed here... we might have delivered it. so just toss it */
    fq_msg_deref(inflight);
  }
  if(ctx) fq_buffered_msg_reader_free(ctx);
  parent->data = NULL;
#ifdef DEBUG
  fq_debug("data path from client ended: %s\n", parent->pretty);
#endif
}

extern void
fqd_data_subscription_server(remote_data_client *client) {
  int len;
  fqd_config *config;
  remote_client *parent;
  fq_rk key;
  fq_debug("--> dss thread [%s]\n",
           client->mode == FQ_PROTO_DATA_MODE ? "client" : "peer");
  if((len = fq_read_short_cmd(client->fd, sizeof(key.name), key.name)) < 0)
    return;
  if(len > (int)sizeof(key.name)) return;
  key.len = len;
#ifdef DEBUG
  {
    char buf[260];
    fq_rk_to_hex(buf, sizeof(buf), &key);
    fq_debug("data conn w/ key:\n%s\n", buf);
  }
#endif

  config = fqd_config_get();
  parent = fqd_config_get_registered_client(config, &key);
  fqd_config_release(config);
  if(!parent) return;
  if(parent->data) return;
  ck_pr_cas_ptr(&parent->data, NULL, client);
  if(parent->data != client) {
    fq_debug("%s dss double gang rejected\n", parent->pretty);
    return;
  }
  fqd_remote_client_ref(parent);
  fqd_data_driver(parent);
  fqd_remote_client_deref(parent);
  fq_debug("<-- dss thread\n");
}
