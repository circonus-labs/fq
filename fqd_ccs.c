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
#include "fq_dtrace.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <errno.h>
#include <uuid/uuid.h>

#include <openssl/rand.h>

static int
fqd_ccs_auth(remote_client *client) {
  uint16_t cmd, method;
  fq_rk queue_name;

  if(fq_read_uint16(client->fd, &cmd) ||
     ntohs(cmd) != FQ_PROTO_AUTH_CMD) {
    ERRTOFD(client->fd, "auth command expected");
    return -1;
  }
  if(fq_read_uint16(client->fd, &method)) {
    ERRTOFD(client->fd, "auth method read failed");
    return -2;
  }
  method = ntohs(method);
  if(method == 0) {
    char buf[128];
    unsigned char pass[10240];
    char queue_detail[1024], *end_of_qd;
    char *qtype = NULL, *qparams = NULL;
    char *replace_params = NULL;
    int len;
    len = fq_read_short_cmd(client->fd, sizeof(client->user.name),
                            client->user.name);
    if(len < 0 || len > (int)sizeof(client->user.name)) {
      ERRTOFD(client->fd, "user name is too long");
      return -3;
    }
    client->user.len = len & 0xff;
    len = fq_read_short_cmd(client->fd, sizeof(queue_detail)-1,
                            queue_detail);
    if(len < 0) return -4;
    queue_detail[len] = '\0';
    end_of_qd = memchr(queue_detail, '\0', len);
    if(!end_of_qd) {
      if(len < 0 || len > (int)sizeof(queue_name.name)) {
        ERRTOFD(client->fd, "queue name is too long");
        return -4;
      }
      queue_name.len = len & 0xff;
      memcpy(queue_name.name, queue_detail, queue_name.len);
      if(queue_name.len < sizeof(queue_name.name))
       memset(queue_name.name + queue_name.len, 0,
              sizeof(queue_name.name) - queue_name.len);
    }
    else if(end_of_qd - queue_detail <= 0xff) {
      queue_name.len = end_of_qd - queue_detail;
      memcpy(queue_name.name, queue_detail, queue_name.len);
      if(queue_name.len < sizeof(queue_name.name))
       memset(queue_name.name + queue_name.len, 0,
              sizeof(queue_name.name) - queue_name.len);
      qtype = end_of_qd + 1;
      if(*qtype) qparams = strchr(qtype, ':');
      else qtype = NULL;
      if(qparams) *qparams++ = '\0';
    }
    else {
      ERRTOFD(client->fd, "queue name is too long");
      return -4;
    }
    if(queue_name.len == 0) {
      uuid_t autogen;
      static const char *DYNAMIC_QUEUE_FORCE_OPTIONS = "transient,private";
      int rlen = strlen(DYNAMIC_QUEUE_FORCE_OPTIONS)+1;
      if(!qparams || *qparams == '\0') {
        replace_params = malloc(rlen);
        memcpy(replace_params, DYNAMIC_QUEUE_FORCE_OPTIONS, rlen);
      }
      else {
        rlen += strlen(qparams)+1;
        replace_params = malloc(rlen);
        snprintf(replace_params, rlen, "%s,%s",
                 qparams, DYNAMIC_QUEUE_FORCE_OPTIONS);
      }
      qparams = replace_params;
      uuid_generate(autogen);
      memcpy(queue_name.name, "auto-", 5);
      uuid_unparse_lower(autogen, (void *)(queue_name.name+5));
      queue_name.len = 5 + 36; /* 5 + 36 uuid, no trailing \0 */
    }
    len = fq_read_short_cmd(client->fd, sizeof(pass), pass);
    if(len < 0 || len > (int)sizeof(queue_name.name)) {
      ERRTOFD(client->fd, "queue name is too long");
      free(replace_params);
      return -4;
    }

    client->queue = fqd_queue_get(&queue_name, qtype, qparams,
                                  sizeof(buf), buf);
    if(client->queue == NULL) {
      ERRTOFD(client->fd, buf);
      free(replace_params);
      return -6;
    }

    /* do AUTH */
    buf[0] = '\0';
    inet_ntop(AF_INET, &client->remote.sin_addr, buf, sizeof(buf));
    snprintf(client->pretty, sizeof(client->pretty), "%.*s/%.*s@%s:%d",
             client->user.len, client->user.name,
             queue_name.len, queue_name.name,
             buf, ntohs(client->remote.sin_port));
    if(FQ_CLIENT_AUTH_ENABLED()) {
      fq_dtrace_remote_client_t dclient;
      DTRACE_PACK_CLIENT(&dclient, client);
      FQ_CLIENT_AUTH(&dclient);
    }
    free(replace_params);
    return 0;
  }
  ERRTOFD(client->fd, "unsupported auth method");
  return -1;
}

static int
fqd_ccs_key_client(remote_client *client) {
  int fd = client->fd;

  client->key.len = sizeof(client->key.name);
  if(RAND_bytes(client->key.name, client->key.len) != 1) {
    if(RAND_pseudo_bytes(client->key.name, client->key.len) != 1) {
      ERRTOFD(fd, "can't generate random key");
      return -1;
    }
  }

  if(fqd_queue_register_client(client->queue, client)) {
    ERRTOFD(fd, "can't add you to queue");
    return -1;
  }

  if(fq_write_uint16(client->fd, FQ_PROTO_AUTH_RESP) ||
     fq_write_short_cmd(client->fd,
                        client->key.len, client->key.name) < 0) {
    return -2;
  }
#ifdef DEBUG
    {
      char hex[260];
      if(fq_rk_to_hex(hex, sizeof(hex), &client->key) >= 0)
        fq_debug(FQ_DEBUG_CONN, "client keyed:\n%s\n", hex);
    }
#endif

  return 0;
}

static int
fqd_css_heartbeat(remote_client *client) {
#ifdef DEBUG
  fq_debug(FQ_DEBUG_CONN, "heartbeat -> %s\n", client->pretty);
#endif
  return fq_write_uint16(client->fd, FQ_PROTO_HB);
}

static int
fqd_css_status(remote_client *client) {
  remote_data_client *data = client->data;
#ifdef DEBUG
  fq_debug(FQ_DEBUG_CONN, "status -> %s\n", client->pretty);
#endif
  if(fq_write_uint16(client->fd, FQ_PROTO_STATUS) < 0) return -1;
#define write_uintkey(name, v) do { \
  if(fq_write_short_cmd(client->fd, strlen(name), name) < 0) return -1; \
  if(fq_write_uint32(client->fd, v) < 0) return -1; \
} while(0)
  if(data) {
    write_uintkey("no_exchange", data->no_exchange);
    write_uintkey("no_route", data->no_route);
    write_uintkey("routed", data->routed);
    write_uintkey("dropped", data->dropped);
    write_uintkey("size_dropped", data->size_dropped);
    write_uintkey("msgs_in", data->msgs_in);
    write_uintkey("msgs_out", data->msgs_out);
    write_uintkey("octets_in", data->octets_in);
    write_uintkey("octets_out", data->octets_out);
  }
  if(fq_write_uint16(client->fd, 0) < 0) return -1;
  return 0;
}

static int
fqd_ccs_loop(remote_client *client) {
  int poll_timeout = 10;
  while(1) {
    int rv;
    struct pollfd pfd;
    uint16_t cmd;
    unsigned long long hb_us;
    hrtime_t t;
    pfd.fd = client->fd;
    pfd.events = POLLIN|POLLHUP;
    pfd.revents = 0;
    rv = poll(&pfd, 1, poll_timeout);
    if(rv < 0) {
#ifdef DEBUG
      fq_debug(FQ_DEBUG_CONN, "poll() failed on %s: %s\n", client->pretty,
               strerror(errno));
#endif
      break;
    }
    if(rv > 0) poll_timeout = 10;
    else poll_timeout *= 2;
    if(poll_timeout > 4000) poll_timeout = 4000;
    t = fq_gethrtime();
    hb_us = ((unsigned long long)client->heartbeat_ms) * 1000000ULL;
    if(client->heartbeat_ms &&
       (unsigned long long)client->last_heartbeat < (unsigned long long)(t - hb_us)) {
      if(fqd_css_heartbeat(client)) break;
      client->last_heartbeat = t;
    }
    if(hb_us &&
       (unsigned long long)client->last_activity < (unsigned long long)(t - hb_us * 3)) {
      ERRTOFD(client->fd, "heartbeat failed");
#ifdef DEBUG
      fq_debug(FQ_DEBUG_CONN, "heartbeat failed from %s\n", client->pretty);
#endif
      break;
    }
    if(rv > 0) {
      if(fq_read_uint16(client->fd, &cmd) != 0) break;
      client->last_heartbeat = client->last_activity = fq_gethrtime();
      switch(cmd) {
        case FQ_PROTO_HB:
#ifdef DEBUG
          fq_debug(FQ_DEBUG_CONN, "heartbeat <- %s\n", client->pretty);
#endif
          break;
        case FQ_PROTO_HBREQ:
        {
          uint16_t ms;
          if(fq_read_uint16(client->fd, &ms) < 0) return -1;
#ifdef DEBUG
          fq_debug(FQ_DEBUG_CONN, "setting client(%p) heartbeat to %d\n",
                  (void *)client, ms);
#endif
          client->heartbeat_ms = ms;
          break;
        }
        case FQ_PROTO_STATUSREQ:
          if(fqd_css_status(client)) return -1;
          break;
        case FQ_PROTO_BINDREQ:
        {
          int len;
          uint16_t flags;
          uint32_t route_id;
          uint64_t cgen;
          char program[0xffff];
          fq_rk exchange;
          if(fq_read_uint16(client->fd, &flags)) return -1;
          len = fq_read_short_cmd(client->fd, sizeof(exchange.name),
                                  exchange.name);
          if(len < 0 || len > (int)sizeof(exchange.name)) return -3;
          exchange.len = len & 0xff;
          len = fq_read_short_cmd(client->fd, sizeof(program)-1, program);
          if(len < 0 || len > (int)sizeof(program)-1) return -1;
          program[len] = '\0';
          route_id = fqd_config_bind(&exchange, flags, program,
                                     client->queue, &cgen);
          if(route_id != FQ_BIND_ILLEGAL)
            fqd_config_wait(cgen, 100);
          if(fq_write_uint16(client->fd, FQ_PROTO_BIND) != 0) return -1;
          if(fq_write_uint32(client->fd, route_id) != 0) return -1;
          break;
        }
        case FQ_PROTO_UNBINDREQ:
        {
          uint32_t route_id;
          fq_rk exchange;
          int success, len;
          if(fq_read_uint32(client->fd, &route_id)) return -1;
          len = fq_read_short_cmd(client->fd, sizeof(exchange.name),
                                  exchange.name);
          if(len < 0 || len > (int)sizeof(exchange.name)) return -1;
          exchange.len = len & 0xff;
          success = fqd_config_unbind(&exchange, route_id, client->queue, NULL);
          if(fq_write_uint16(client->fd, FQ_PROTO_UNBIND) != 0) return -1;
          if(fq_write_uint32(client->fd, success ? route_id : FQ_BIND_ILLEGAL))
            return -1;
          break;
        }
        default:
          return -1;
      }
    }
  }
  return -1;
}

extern void
fqd_command_and_control_server(remote_client *client) {
  /* auth */
  int rv, registered = 0;
  uint64_t cgen;
  fq_debug(FQ_DEBUG_CONN, "--> ccs thread\n");
  if((rv = fqd_ccs_auth(client)) != 0) {
    fq_debug(FQ_DEBUG_CONN, "client auth failed: %d\n", rv);
    (void)rv;
    goto out;
  }
  if(fqd_config_register_client(client, &cgen)) {
    fq_debug(FQ_DEBUG_CONN, "client registration failed\n");
    goto out;
  }
  registered = 1;
  fqd_config_wait(cgen, 100);
  if(fqd_ccs_key_client(client) != 0) {
    fq_debug(FQ_DEBUG_CONN, "client keying failed: %d\n", rv);
    goto out;
  }
  fqd_ccs_loop(client);
out:
  if(registered) fqd_config_deregister_client(client, NULL);
  fq_debug(FQ_DEBUG_CONN, "<-- ccs thread\n");
}
