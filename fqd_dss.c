#include "fqd.h"

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>

#define IN_READ_BUFFER_SIZE 1025*128

static int
deparse_message_headers(unsigned char *d, int dlen,
                        fq_rk *exchange, fq_msg *msg) {
  int ioff = 0;
  unsigned short exchange_len, route_len;
#define BAIL_UNLESS_LEFT(d) do { \
  if((dlen-ioff) < (int)(d)) return 0; \
} while(0)

  BAIL_UNLESS_LEFT(sizeof(exchange_len));
  memcpy(&exchange_len, d+ioff, sizeof(exchange_len));
  ioff += sizeof(exchange_len);
  exchange_len = ntohs(exchange_len);
  if(exchange_len > sizeof(exchange->name)) return -1;
  exchange->len = exchange_len;

  BAIL_UNLESS_LEFT(exchange_len);
  memcpy(exchange->name, d+ioff, exchange_len);
  ioff += exchange_len;

  BAIL_UNLESS_LEFT(sizeof(route_len));
  memcpy(&route_len, d+ioff, sizeof(route_len));
  ioff += sizeof(route_len);
  route_len = ntohs(route_len);
  if(route_len > sizeof(msg->route.name)) return -1;
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
  int flags;
  ssize_t nread = 0, into_body = 0;
  fq_rk exchange;
  fq_msg msg;

  if(((flags = fcntl(me->fd, F_GETFL, 0)) == -1) ||
     (fcntl(me->fd, F_SETFL, flags | O_NONBLOCK) == -1))
    return;

  memset(&msg, 0, sizeof(msg));
  while(1) {
    int rv, off;
    struct pollfd pfd;
    pfd.fd = me->fd;
    pfd.events = POLL_IN;
    pfd.revents = 0;
    rv = poll(&pfd, 1, parent->heartbeat_ms ? parent->heartbeat_ms : 1000);
    if(rv < 0) break;
    if(rv > 0) {
      me->last_heartbeat = me->last_activity = fq_gethrtime();
      if(into_body < msg.payload_len) {
        /* we need to be reading a largish payload */
        while((rv = read(me->fd, msg.payload + into_body,
                         msg.payload_len - into_body)) == -1 && errno == EINTR);
        if(rv == -1 && errno != EAGAIN) break;
        into_body += rv;
        if(into_body == msg.payload_len) {
          fq_msg *copy;
          copy = malloc(sizeof(*copy));
          memcpy(copy, &msg, sizeof(msg));
          msg.refcnt = 1;
          fqd_inject_message(parent, &exchange, copy);
          memset(&msg, 0, sizeof(msg));
        }
      }
      while((rv = read(me->fd, scratch+nread, sizeof(scratch)-nread)) == -1 &&
            errno == EINTR);
      if(rv == -1 && errno != EAGAIN) break;
      nread += rv;

      off = 0;
      while(1) {
        uint32_t body_available;
        int body_start = deparse_message_headers(scratch+off, nread-off, &exchange, &msg);
        into_body = 0;
        if(!body_start) {
          memmove(scratch, scratch + off, nread - off);
          nread -= off;
          break;
        }
        off += body_start;
        body_available = nread - off;
        if(msg.payload_len < body_available) body_available = msg.payload_len;
        memcpy(msg.payload, scratch+off, body_available);
        if(body_available == msg.payload_len) {
          fq_msg *copy;
          copy = malloc(sizeof(*copy));
          memcpy(copy, &msg, sizeof(msg));
          msg.refcnt = 1;
          fqd_inject_message(parent, &exchange, copy);
          memset(&msg, 0, sizeof(msg));
        }
      }
    }
  }
  parent->data = NULL;
  fqd_remote_client_deref(parent);
  free(me);
}

extern void
fqd_data_subscription_server(remote_data_client *client) {
  unsigned short len;
  fqd_config *config;
  remote_client *parent;
  fq_rk key;
  if(fq_read_uint16(client->fd, &len)) return;
  if(len > sizeof(key.name)) return;
  key.len = len;
  if(fq_read_short_cmd(client->fd, key.len, key.name) != key.len)
    return;

  config = fqd_config_get();
  parent = fqd_config_get_registered_client(config, &key);
  fqd_config_release(config);
  if(!parent) return;
  parent->data = client;
  fqd_remote_client_ref(parent);

  fqd_data_driver(parent);
}
