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

static int
parse_message_headers(unsigned char *d, int dlen,
                        fq_rk *exchange, fq_msg *msg) {
  int ioff = 0;
  unsigned char exchange_len, route_len;
#define BAIL_UNLESS_LEFT(d) do { \
  if((dlen-ioff) < (int)(d)) return 0; \
} while(0)

  BAIL_UNLESS_LEFT(sizeof(exchange_len));
  memcpy(&exchange_len, d+ioff, sizeof(exchange_len));
  ioff += sizeof(exchange_len);
  if(exchange_len > sizeof(exchange->name)) return -1;
  exchange->len = exchange_len;

  BAIL_UNLESS_LEFT(exchange_len);
  memcpy(exchange->name, d+ioff, exchange_len);
  ioff += exchange_len;

  BAIL_UNLESS_LEFT(sizeof(route_len));
  memcpy(&route_len, d+ioff, sizeof(route_len));
  ioff += sizeof(route_len);
  if(route_len > sizeof(msg->route.name)) return -2;
  msg->route.len = route_len;

  BAIL_UNLESS_LEFT(route_len);
  memcpy(msg->route.name, d+ioff, route_len);
  ioff += route_len;

  BAIL_UNLESS_LEFT(sizeof(msg->sender_msgid));
  memcpy(&msg->sender_msgid, d+ioff, sizeof(msg->sender_msgid));
  ioff += sizeof(msg->sender_msgid);

  BAIL_UNLESS_LEFT(sizeof(msg->payload_len));
  memcpy(&msg->payload_len, d+ioff, sizeof(msg->payload_len));
  msg->payload_len = ntohl(msg->payload_len);
  ioff += sizeof(msg->payload_len);

  return ioff;
}
static  void
fqd_data_driver(remote_client *parent) {
  remote_data_client *me = parent->data;
  unsigned char scratch[IN_READ_BUFFER_SIZE];
  int flags, off = 0;
  ssize_t nread = 0, into_body = 0;
  fq_rk exchange;
  fq_msg msg, *copy = NULL;

  if(((flags = fcntl(me->fd, F_GETFL, 0)) == -1) ||
     (fcntl(me->fd, F_SETFL, flags | O_NONBLOCK) == -1))
    return;

  memset(&msg, 0, sizeof(msg));
  while(1) {
    int rv;
    struct pollfd pfd;
    pfd.fd = me->fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    rv = poll(&pfd, 1, parent->heartbeat_ms ? parent->heartbeat_ms : 1000);
    if(rv < 0) break;

    if(rv > 0 && (pfd.revents & POLLIN)) {
      me->last_heartbeat = me->last_activity = fq_gethrtime();
      if(into_body < msg.payload_len) {
        assert(copy);
        /* we need to be reading a largish payload */
        while((rv = read(me->fd, msg.payload + into_body,
                         msg.payload_len - into_body)) == -1 && errno == EINTR);
        if(rv == -1 && errno == EAGAIN) goto write_path;
        if(rv <= 0) break;
#ifdef DEBUG
        fq_debug("%s <-- %d bytes for payload\n", parent->pretty, rv);
#endif
        into_body += rv;
        if(into_body == msg.payload_len) {
          into_body = 0;
          goto message_done;
        }
      }
      while((rv = read(me->fd, scratch+nread, sizeof(scratch)-nread)) == -1 &&
            errno == EINTR);
#ifdef DEBUG
      fq_debug("%s <-- %d bytes @ %d (%d)\n", parent->pretty, rv, (int)nread,
              (int)nread + (rv > 0) ? rv : 0);
#endif
      if(rv == -1 && errno == EAGAIN) goto write_path;
      if(rv <= 0) break;
      nread += rv;

      while(nread>0) {
        uint32_t body_available;
        int body_start;
        body_start = parse_message_headers(scratch+off, nread-off, &exchange, &msg);
        into_body = 0;
#ifdef DEBUG
        fq_debug("%d = parse(+%d, %d) -> %d\n",
                body_start, off, (int)nread-off, body_start ? (int)msg.payload_len : 0);
#endif
        if(body_start < 0) return;
        if(!body_start) {
#ifdef DEBUG
          fq_debug("incomplete message header...\n");
#endif
          memmove(scratch, scratch + off, nread - off);
          nread -= off;
          off = 0;
          goto write_path;
        }

        /* We have a message... or the formal beginnings of one */
        copy = fq_msg_alloc_BLANK(msg.payload_len);
        memcpy(copy, &msg, sizeof(msg));

        off += body_start;
        body_available = nread - off;
        if(copy->payload_len < body_available) body_available = copy->payload_len;
        memcpy(copy->payload, scratch+off, body_available);
        if(body_available == copy->payload_len) {
          off += body_available;
         message_done:
          copy->refcnt = 1;
#ifdef DEBUG
          fq_debug("message read... injecting\n");
#endif
          fqd_inject_message(parent, &exchange, copy);
          copy = NULL;
          memset(&msg, 0, sizeof(msg));
        }
        else {
          nread = 0;
          off = 0;
          into_body = body_available;
#ifdef DEBUG
          fq_debug("incomplete message... (%d needed)\n",
                 (int)msg.payload_len - (int)into_body);
#endif
          goto write_path;
        }
      }
    }

   write_path:
    if(rv > 0 && (pfd.revents & POLLOUT)) {
    }
  }
  if(copy) free(copy);
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
  fq_debug("--> dss thread\n");
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
