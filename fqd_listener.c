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
#include <assert.h>
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
#include "fqd_private.h"
#include "fq_dtrace.h"

void
fqd_remote_client_ref(remote_client *r) {
  ck_pr_inc_uint(&r->refcnt);
}
bool
fqd_remote_client_deref(remote_client *r) {
  bool zero;
  ck_pr_dec_uint_zero(&r->refcnt, &zero);
  fq_debug(FQ_DEBUG_CONN, "deref client -> %u%s\n",
           r->refcnt, zero ? " dropping" : "");
  if(zero) {
    close(r->fd);
    free(r);
    return true;
  }
  return false;
}

static void
service_connection(remote_anon_client *client) {
  uint32_t cmd;
  uint32_t peer_id = 0;
  int rv, on = 1;
  char buf[40];
  buf[0] = '\0';
  inet_ntop(AF_INET, &client->remote.sin_addr, buf, sizeof(buf));
  fq_thread_setname("fqd:c:%s", client->pretty);
  snprintf(client->pretty, sizeof(client->pretty),
           "(pre-auth)@%s:%d", buf, ntohs(client->remote.sin_port));
  gettimeofday(&client->connect_time, NULL);
  fq_debug(FQ_DEBUG_CONN, "client(%s) connected\n", client->pretty);

  /* We do nothing if this fails. */
  (void)setsockopt(client->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

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
      (void)fqd_remote_client_deref((remote_client *)newc);
    }
    break;

    case FQ_PROTO_PEER_MODE:
      while((rv = read(client->fd, &peer_id, sizeof(peer_id))) == -1 && errno == EINTR);
      if(rv != 4) goto disconnect;
      /* FALLTHROUGH */
    case FQ_PROTO_OLD_PEER_MODE:
      cmd = FQ_PROTO_PEER_MODE;
      /* FALLTHROUGH */
    case FQ_PROTO_DATA_MODE:
    {
      remote_data_client *newc = calloc(1, sizeof(*newc));
      memcpy(newc, client, sizeof(*client));
      newc->mode = ntohl(cmd);
      newc->peer_id = peer_id;
      newc->refcnt=1;
      fqd_data_subscription_server(newc);
      (void)fqd_remote_client_deref((remote_client *)newc);
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
      (void)fqd_remote_client_deref((remote_client *)newc);
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
}

static void *
conn_handler(void *vc) {
  fqd_bcd_attach();
  while(1) {
    fq_thread_setname("fqd:c:idle");
    remote_anon_client *client = fqd_ccs_dequeue_work();
    service_connection(client);
  }
  return NULL;
}

typedef struct fqd_ccs_work_queue {
  remote_anon_client *client;
  struct fqd_ccs_work_queue *next;
} fqd_ccs_work_queue_t;

static pthread_mutex_t fqd_ccs_work_queue_lock;
static pthread_cond_t fqd_ccs_work_queue_cv;
static volatile fqd_ccs_work_queue_t *fqd_ccs_work_queue;
static volatile int fqd_ccs_idle_threads = 0;

static void
fqd_ccs_enqueue_work(remote_anon_client *client) {
  fqd_ccs_work_queue_t *node = calloc(sizeof(*client), 1);
  node->client = client;
  if(pthread_mutex_lock(&fqd_ccs_work_queue_lock) != 0) {
    fprintf(stderr, "pthread_mutex_lock: %s\n", strerror(errno));
    exit(2);
  }
  if(fqd_ccs_idle_threads < 1) {
    pthread_t client_task;
    assert(pthread_create(&client_task, NULL, conn_handler, NULL) == 0);
  }
  node->next = (fqd_ccs_work_queue_t *)fqd_ccs_work_queue;
  fqd_ccs_work_queue = node;
  if(pthread_mutex_unlock(&fqd_ccs_work_queue_lock) != 0) {
    fprintf(stderr, "pthread_mutex_unlock: %s\n", strerror(errno));
    exit(2);
  }
  if(pthread_cond_signal(&fqd_ccs_work_queue_cv) != 0) {
    fprintf(stderr, "pthread_cond_signal: %s\n", strerror(errno));
    exit(2);
  }
}

remote_anon_client *
fqd_ccs_dequeue_work(void) {
  remote_anon_client *client = NULL;
  if(pthread_mutex_lock(&fqd_ccs_work_queue_lock) != 0) {
    fprintf(stderr, "pthread_mutex_lock: %s\n", strerror(errno));
    exit(2);
  }
  fqd_ccs_idle_threads++;
  while(fqd_ccs_work_queue == NULL) {
    if(pthread_cond_wait(&fqd_ccs_work_queue_cv, &fqd_ccs_work_queue_lock) != 0) {
      fprintf(stderr, "pthread_cond_wait: %s\n", strerror(errno));
      exit(2);
    }
  }
  client = fqd_ccs_work_queue->client;
  fqd_ccs_work_queue_t *tofree = (fqd_ccs_work_queue_t *)fqd_ccs_work_queue;
  fqd_ccs_work_queue = fqd_ccs_work_queue->next;
  fqd_ccs_idle_threads--;
  if(pthread_mutex_unlock(&fqd_ccs_work_queue_lock) != 0) {
    fprintf(stderr, "pthread_mutex_unlock: %s\n", strerror(errno));
    exit(2);
  }
  free(tofree);
  return client;
}

int
fqd_listener(const char *host, unsigned short port) {
  int fd;
  remote_anon_client *client = NULL;
  unsigned int on = 1;
  struct sockaddr_in laddr;

  pthread_mutex_init(&fqd_ccs_work_queue_lock, NULL);
  pthread_cond_init(&fqd_ccs_work_queue_cv, NULL);

  memset(&laddr, 0, sizeof(laddr));
  laddr.sin_family = AF_INET;
  laddr.sin_addr.s_addr = INADDR_ANY;
  if(host && inet_pton(AF_INET, host, &laddr.sin_addr) != 0) {
    return -1;
  }
  laddr.sin_port = htons(port);

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if(fd < 0) return -1;
  if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0 ||
#ifdef SO_REUSEPORT
     setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) != 0 ||
#endif
     bind(fd, (struct sockaddr *)&laddr, sizeof(laddr)) < 0 ||
     listen(fd, 16) < 0) {
    close(fd);
    return -1;
  }

  while(1) {
    struct sockaddr_in raddr;
    socklen_t raddr_len;

    if(client == NULL) client = calloc(1, sizeof(*client));
    raddr_len = sizeof(raddr);
    client->fd = accept(fd, (struct sockaddr *)&client->remote, &raddr_len);
    if(client->fd < 0) continue;
    fq_keepalive_fd(client->fd, 10, 5, 2);
    client->refcnt = 1;
    fqd_ccs_enqueue_work(client);
    client = NULL;
  }
  return -1;
}
