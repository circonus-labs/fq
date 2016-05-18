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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <ck_pr.h>

#include "fq.h"
#include "fqd.h"
#include "fq_dtrace.h"

void
fqd_remote_client_ref(remote_client *r) {
  ck_pr_inc_uint(&r->refcnt);
}
void
fqd_remote_client_deref(remote_client *r) {
  bool zero;
  ck_pr_dec_uint_zero(&r->refcnt, &zero);
  fq_debug(FQ_DEBUG_CONN, "deref client -> %u%s\n",
           r->refcnt, zero ? " dropping" : "");
  if(zero) {
    close(r->fd);
    free(r);
  }
}

static void *
conn_handler(void *vc) {
  uint32_t cmd;
  uint32_t peer_id = 0;
  int rv, on = 1;
  remote_anon_client *client = vc;
  char buf[40];
  buf[0] = '\0';
  inet_ntop(AF_INET, &client->remote.sin_addr, buf, sizeof(buf));
  snprintf(client->pretty, sizeof(client->pretty),
           "(pre-auth)@%s:%d", buf, ntohs(client->remote.sin_port));
  gettimeofday(&client->connect_time, NULL);
  fq_debug(FQ_DEBUG_CONN, "client(%s) connected\n", client->pretty);

  setsockopt(client->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

  while((rv = read(client->fd, &cmd, sizeof(cmd))) == -1 && errno == EINTR);
  if(rv != 4) goto disconnect;
  if(FQ_CLIENT_DISCONNECT_ENABLED()) {
    fq_dtrace_remote_anon_client_t dc;
    DTRACE_PACK_ANON_CLIENT(&dc, client);
    FQ_CLIENT_CONNECT(&dc, ntohl(cmd));
  }
  fq_debug(FQ_DEBUG_CONN, "read(%d) cmd -> %08x\n", client->fd, ntohl(cmd));
  switch(ntohl(cmd)) {
    case FQ_PROTO_CMD_MODE:
    {
      remote_client *newc = calloc(1, sizeof(*newc));
      memcpy(newc, client, sizeof(*client));
      newc->refcnt = 1;
      fqd_command_and_control_server(newc);
      fqd_remote_client_deref((remote_client *)newc);
    }
    break;

    case FQ_PROTO_PEER_MODE:
      while((rv = read(client->fd, &peer_id, sizeof(peer_id))) == -1 && errno == EINTR);
      if(rv != 4) goto disconnect;
    case FQ_PROTO_OLD_PEER_MODE:
      cmd = FQ_PROTO_PEER_MODE;
    case FQ_PROTO_DATA_MODE:
    {
      remote_data_client *newc = calloc(1, sizeof(*newc));
      memcpy(newc, client, sizeof(*client));
      newc->mode = ntohl(cmd);
      newc->peer_id = peer_id;
      newc->refcnt=1;
      fqd_data_subscription_server(newc);
      fqd_remote_client_deref((remote_client *)newc);
    }
    break;

    case FQ_PROTO_HTTP_GET:
    case FQ_PROTO_HTTP_HEAD:
    case FQ_PROTO_HTTP_POST:
    case FQ_PROTO_HTTP_PUT:
    {
      remote_client *newc = calloc(1, sizeof(*newc));
      memcpy(newc, client, sizeof(*client));
      newc->refcnt = 1;
      fqd_http_loop(newc, cmd);
      fqd_remote_client_deref((remote_client *)newc);
    }
    break;

    default:
      fq_debug(FQ_DEBUG_CONN, "client protocol violation in initial cmd\n");
      close(client->fd);
      break;
  }

 disconnect:
  if(FQ_CLIENT_DISCONNECT_ENABLED()) {
    fq_dtrace_remote_anon_client_t dc;
    DTRACE_PACK_ANON_CLIENT(&dc, client);
    FQ_CLIENT_DISCONNECT(&dc, ntohl(cmd));
  }
  free(client);
  return NULL;
}

int
fqd_listener(const char *host, unsigned short port) {
  int fd;
  remote_anon_client *client = NULL;
  unsigned int on = 1;
  struct sockaddr_in laddr;

  memset(&laddr, 0, sizeof(laddr));
  laddr.sin_family = AF_INET;
  laddr.sin_addr.s_addr = INADDR_ANY;
  if(host && inet_pton(AF_INET, host, &laddr.sin_addr) != 0) {
    return -1;
  }
  laddr.sin_port = htons(port);

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if(fd < 0) return -1;
  if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) return -1;
  if(bind(fd, (struct sockaddr *)&laddr, sizeof(laddr)) < 0) return -1;
  if(listen(fd, 16) < 0) return -1;

  while(1) {
    pthread_t client_task;
    pthread_attr_t client_task_attr;
    struct sockaddr_in raddr;
    socklen_t raddr_len;

    if(client == NULL) client = calloc(1, sizeof(*client));
    raddr_len = sizeof(raddr);
    pthread_attr_init(&client_task_attr);
    pthread_attr_setdetachstate(&client_task_attr, PTHREAD_CREATE_DETACHED);
    client->fd = accept(fd, (struct sockaddr *)&client->remote, &raddr_len);
    if(client->fd < -1) continue;
    client->refcnt = 1;
    if(pthread_create(&client_task, &client_task_attr,
                      conn_handler, client) != 0) {
      close(client->fd);
    }
    client = NULL;
  }
  return -1;
}
