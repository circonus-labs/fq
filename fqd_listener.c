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
#include <netdb.h>
#include <ck_pr.h>

#include "fq.h"
#include "fqd.h"

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
  int rv;
  remote_anon_client *client = vc;
  char buf[40];
  buf[0] = '\0';
  inet_ntop(AF_INET, &client->remote.sin_addr, buf, sizeof(buf));
  snprintf(client->pretty, sizeof(client->pretty),
           "(pre-auth)@%s:%d", buf, ntohs(client->remote.sin_port));
  gettimeofday(&client->connect_time, NULL);
#ifdef DEBUG
  fq_debug(FQ_DEBUG_CONN, "client connected\n");
#endif

  while((rv = read(client->fd, &cmd, sizeof(cmd))) == -1 && errno == EINTR);
  if(rv != 4) goto disconnect;
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

    case FQ_PROTO_DATA_MODE:
    case FQ_PROTO_PEER_MODE:
    {
      remote_data_client *newc = calloc(1, sizeof(*newc));
      memcpy(newc, client, sizeof(*client));
      newc->mode = ntohl(cmd);
      newc->refcnt=1;
      fqd_data_subscription_server(newc);
      fqd_remote_client_deref((remote_client *)newc);
    }
    break;

    case FQ_PROTO_READ_STAT:
    {
      remote_client *newc = calloc(1, sizeof(*newc));
      memcpy(newc, client, sizeof(*client));
      newc->refcnt = 1;
      fqd_config_http_stats(newc);
      fqd_remote_client_deref((remote_client *)newc);
    }
    break;

    default:
#ifdef DEBUG
      fq_debug(FQ_DEBUG_CONN, "client protocol violation in initial cmd\n");
#endif
      break;
  }

 disconnect:
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
