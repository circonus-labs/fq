#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ck_fifo.h>

#include "fq.h"

#define CONNERR_S(c) do { \
  if(c->errorlog) c->errorlog(c->error); \
} while(0)

#define CONNERR(c, s) do { \
  strncpy(c->error, s, sizeof(c->error)); \
  if(c->errorlog) c->errorlog(c->error); \
} while(0)

struct fq_conn_s {
  struct         sockaddr_in remote;
  char           error[128];
  char          *user;
  char          *pass;
  char          *queue;
  int            cmd_fd;
  int            data_fd;
  pthread_t      worker;
  int            stop;
  ck_fifo_mpmc_t q;
  uint32_t       qlen;

  void         (*errorlog)(const char *);
  ck_fifo_mpmc_entry_t *qhead;
};
typedef struct fq_conn_s fq_conn_s;

static int
fq_socket_connect(fq_conn_s *conn_s) {
  int fd, rv;
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if(fd == -1) return -1;
  rv = connect(fd, (struct sockaddr *)&conn_s->remote,
               sizeof(conn_s->remote));
  if(rv == -1) {
    snprintf(conn_s->error, sizeof(conn_s->error),
             "socket: %s", strerror(errno));
    CONNERR_S(conn_s);
    close(fd);
    return -1;
  }
  return fd;
}

static void
fq_client_disconnect(fq_conn_s *conn_s) {
  if(conn_s->cmd_fd >= 0) close(conn_s->data_fd);
  if(conn_s->data_fd >= 0) close(conn_s->data_fd);
}

static int
fq_client_connect(fq_conn_s *conn_s) {
  fq_client_disconnect(conn_s);
  conn_s->cmd_fd = fq_socket_connect(conn_s);
  if(conn_s->cmd_fd < 0) return -1;
  return 0;
}

static void *
fq_conn_worker(void *u) {
  int backoff = 0;
  fq_conn_s *conn_s = (fq_conn_s *)u;
  while(conn_s->stop == 0) {
    if(fq_client_connect(conn_s) == 0) {
      backoff = 0; /* we're good, restart our backoff */
    }

    if(backoff < 1000000) backoff += 10000;
#ifdef DEBUG
    fprintf(stderr, "connection failed: %s\n", conn_s->error);
#endif
    usleep(backoff);
  }
  fq_client_disconnect(conn_s);
  return (void *)NULL;
}

int
fq_client_init(fq_client *conn_ptr, void (*logger)(const char *)) {
  fq_conn_s *conn_s;
  conn_s = *conn_ptr = calloc(1, sizeof(*conn_s));
  if(!conn_s) return -1;
  /* make the sockets as disconnected */
  conn_s->cmd_fd = conn_s->data_fd = -1;
  conn_s->errorlog = logger;
  return 0;
}

int
fq_client_creds(fq_client conn, const char *host, unsigned short port,
                const char *sender, const char *pass) {
  fq_conn_s *conn_s;
  conn_s = conn;

  /* make the sockets as disconnected */
  conn_s->cmd_fd = conn_s->data_fd = -1;

  /* parse the user info */
  conn_s->user = strdup(sender);
  conn_s->queue = strchr(sender, '/');
  if(conn_s->queue) *conn_s->queue++ = '\0';
  conn_s->pass = strdup(pass);

  /* determine our endpoint */
  conn_s->remote.sin_port = htons(port);
  if(inet_pton(AF_INET, host, &conn_s->remote.sin_addr) != 0) {
#ifdef HAVE_GETHOSTBYNAME_R
    struct hostent hostbuf, *hp;
    struct in_addr **addr_list;
    int buflen = 1024, herr, hres;
    char *buf;
    if((buf = malloc(buflen)) == NULL) {
      CONNERR(conn_s, "out of memory");
      return -1;
    }
    while((hres = gethostbyname_r(host, &hostbuf, 
                                  buf, buflen, &hp, &herr)) == ERANGE) {
      buflen *= 2;
      if((buf = realloc(buf, buflen)) == NULL) {
        CONNERR(conn_s, "out of memory");
        return -1;
      }
    }
    if(!hp) {
      CONNERR(conn_s, "host lookup failed");
      return -1;
    }
    addr_list = (struct in_addr **)hp->h_addr_list;
    if(*addr_list == 0) {
      CONNERR(conn_s, "no address for host");
      return -1;
    }
    memcpy(&conn_s->remote.sin_addr, *addr_list, sizeof(struct in_addr));
    free(buf);
#else
    struct hostent *hp;
    struct in_addr **addr_list;
    hp = gethostbyname(host);
    if(!hp) {
      CONNERR(conn_s, "host lookup failed");
      return -1;
    }
    addr_list = (struct in_addr **)hp->h_addr_list;
    if(*addr_list == 0) {
      CONNERR(conn_s, "no address for host");
      return -1;
    }
    memcpy(&conn_s->remote.sin_addr, *addr_list, sizeof(struct in_addr));
#endif
  }
  conn_s->qhead = malloc(sizeof(ck_fifo_mpmc_entry_t));
  ck_fifo_mpmc_init(&conn_s->q, conn_s->qhead);

  if(pthread_create(&conn_s->worker, NULL, fq_conn_worker, conn_s) != 0) {
      CONNERR(conn_s, "could not start worker thread");
    return -1;
  }
  return 0;
}

int
fq_client_publish(fq_client *conn, fq_msg *msg) {
  fq_conn_s *conn_s = *conn;
  ck_fifo_mpmc_entry_t *fifo_entry;
  fifo_entry = malloc(sizeof(ck_fifo_mpmc_entry_t));
  ck_fifo_mpmc_enqueue(&conn_s->q, fifo_entry, msg);
  return ck_pr_faa_32(&conn_s->qlen, 1);
}
