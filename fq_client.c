#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <poll.h>
#include <ck_fifo.h>

#include "fq.h"

#define CONNERR_S(c) do { \
  if(c->errorlog) c->errorlog(c->error); \
} while(0)

#define CONNERR(c, s) do { \
  strncpy(c->error, s, sizeof(c->error)); \
  if(c->errorlog) c->errorlog(c->error); \
} while(0)

static inline int
fq_client_wfr_internal(int fd, uint64_t ms) {
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN;
  return poll(&pfd, 1, ms);
}

struct fq_conn_s {
  struct         sockaddr_in remote;
  char           error[128];
  char          *user;
  char          *pass;
  char          *queue;
  fq_rk          key;
  int            cmd_fd;
  int            cmd_hb_needed;
  unsigned short cmd_hb_ms;
  hrtime_t       cmd_hb_last;
  int            data_fd;
  pthread_t      worker;
  pthread_t      data_worker;
  int            stop;
  ck_fifo_mpmc_t cmdq;
  ck_fifo_mpmc_t q;
  uint32_t       qlen;
  int            connected;
  int            data_ready;
  fq_msg        *tosend;

  void         (*errorlog)(const char *);
  ck_fifo_mpmc_entry_t *cmdqhead;
  ck_fifo_mpmc_entry_t *qhead;
};
typedef struct fq_conn_s fq_conn_s;

typedef struct {
  unsigned short cmd;
  union {
    struct {
      uint16_t       ms;
    } heartbeat;
  } data;
} cmd_instr;

static void
fq_client_signal(fq_client conn, cmd_instr *e) {
  fq_conn_s *conn_s = conn;
  ck_fifo_mpmc_entry_t *fifo_entry;
  fifo_entry = malloc(sizeof(ck_fifo_mpmc_entry_t));
  ck_fifo_mpmc_enqueue(&conn_s->cmdq, fifo_entry, e);
}

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
fq_client_disconnect_internal(fq_conn_s *conn_s) {
  if(conn_s->cmd_fd >= 0) {
#ifdef DEBUG
    fprintf(stderr, "close(cmd_fd)\n");
#endif
    close(conn_s->data_fd);
  }
  if(conn_s->data_fd >= 0) {
#ifdef DEBUG
    fprintf(stderr, "close(data_fd)\n");
#endif
    close(conn_s->data_fd);
  }
  conn_s->data_ready = 0;
  if(conn_s->cmd_hb_ms) {
    unsigned short hb;
    hb = conn_s->cmd_hb_ms;
    conn_s->cmd_hb_ms = 0;
    fq_client_heartbeat(conn_s, hb);
    conn_s->cmd_hb_last = 0;
  }
}

static int
fq_client_do_auth(fq_conn_s *conn_s) {
  int len;
  uint16_t cmd;
  char error[1024];
  if(fq_write_uint16(conn_s->cmd_fd, FQ_PROTO_AUTH_CMD)) return -1;
  if(fq_write_uint16(conn_s->cmd_fd, FQ_PROTO_AUTH_PLAIN)) return -2;
  if(fq_write_short_cmd(conn_s->cmd_fd, strlen(conn_s->user), conn_s->user) < 0)
    return -3;
  if(fq_write_short_cmd(conn_s->cmd_fd, strlen(conn_s->user), conn_s->queue) < 0)
    return -4;
  if(fq_write_short_cmd(conn_s->cmd_fd, strlen(conn_s->pass), conn_s->pass) < 0)
    return -5;
  if(fq_read_uint16(conn_s->cmd_fd, &cmd)) return -6;
  switch(cmd) {
    case FQ_PROTO_ERROR:
      len = fq_read_short_cmd(conn_s->cmd_fd, sizeof(error)-1, error);
      if(conn_s->errorlog) {
        if(len > (int)sizeof(error)-1) len = sizeof(error)-1;
        if(len < 0) conn_s->errorlog("error reading error");
        else conn_s->errorlog(error);
      }
      return -7;
    case FQ_PROTO_AUTH_RESP:
      len = fq_read_short_cmd(conn_s->cmd_fd,
                              sizeof(conn_s->key.name), conn_s->key.name);
      if(len < 0 || len > (int)sizeof(conn_s->key.name)) return -8;
      conn_s->key.len = len;
#ifdef DEBUG
      {
        char hex[260];
        if(fq_rk_to_hex(hex, sizeof(hex), &conn_s->key) >= 0)
          fprintf(stderr, "client keyed:\n%s\n", hex);
      }
#endif
      conn_s->data_ready = 1;
      break;
    default:
      if(conn_s->errorlog) {
        snprintf(error, sizeof(error),
                 "server auth response 0x%04x unknown\n", cmd);
        conn_s->errorlog(error);
      }
      return -9;
  }
  return 0;
}

static int
fq_client_data_connect_internal(fq_conn_s *conn_s) {
  int flags;
  uint32_t cmd = htonl(FQ_PROTO_DATA_MODE);
  /* We don't support data connections when the cmd connection is down */
  if(conn_s->cmd_fd < 0) return -1;

  if(conn_s->data_fd >= 0) {
    close(conn_s->data_fd);
    conn_s->data_fd = -1;
  }
  conn_s->data_fd = fq_socket_connect(conn_s);
  if(conn_s->data_fd < 0) goto shutdown;
  if(write(conn_s->data_fd, &cmd, sizeof(cmd)) != sizeof(cmd))
    goto shutdown;
#ifdef DEBUG
      {
        char hex[260];
        if(fq_rk_to_hex(hex, sizeof(hex), &conn_s->key) >= 0)
          fprintf(stderr, "client keying:\n%s\n", hex);
      }
#endif
  if(fq_write_short_cmd(conn_s->data_fd,
                        conn_s->key.len, conn_s->key.name) < 0) {
    goto shutdown;
  }
  if(((flags = fcntl(conn_s->data_fd, F_GETFL, 0)) == -1) ||
     (fcntl(conn_s->data_fd, F_SETFL, flags | O_NONBLOCK) == -1))
    goto shutdown;

  return 0;

 shutdown:
  if(conn_s->data_fd >= 0) {
    close(conn_s->data_fd);
    conn_s->data_fd = -1;
  }
  return -1;
}

static int
fq_client_connect_internal(fq_conn_s *conn_s) {
  int rv;
  uint32_t cmd = htonl(FQ_PROTO_CMD_MODE);
  fq_client_disconnect_internal(conn_s);
  conn_s->cmd_fd = fq_socket_connect(conn_s);
  if(conn_s->cmd_fd < 0) goto shutdown;
  if(write(conn_s->cmd_fd, &cmd, sizeof(cmd)) != sizeof(cmd))
    goto shutdown;
  if((rv = fq_client_do_auth(conn_s)) < 0) {
#ifdef DEBUG
    fprintf(stderr, "fq_client_do_auth -> %d\n", rv);
#endif
    goto shutdown;
  }
  return 0;

 shutdown:
  if(conn_s->cmd_fd >= 0) {
    close(conn_s->cmd_fd);
    conn_s->cmd_fd = -1;
  }
  return -1;
}

/* frame */
/*
 *    1 x <nstring>      exchange
 *    1 x fq_rk<nstring> route
 *    1 x uint32_t<net>  payload_len
 *    1 x data
 */
static int
fq_client_write_msg(int fd, fq_msg *m) {
  struct iovec pv[7];
  int expect, rv;
  unsigned char exchange_len = m->exchange.len;
  unsigned char route_len = m->route.len;
  uint32_t      data_len = htonl(m->payload_len);

  expect = 1 + m->exchange.len + 1 + m->route.len +
           sizeof(data_len) + m->payload_len;
  pv[0].iov_len = 1;
  pv[0].iov_base = &exchange_len;
  pv[1].iov_len = m->exchange.len;
  pv[1].iov_base = m->exchange.name;
  pv[2].iov_len = 1;
  pv[2].iov_base = &route_len;
  pv[3].iov_len = m->route.len;
  pv[3].iov_base = m->route.name;
  pv[4].iov_len = sizeof(m->sender_msgid);
  pv[4].iov_base = &m->sender_msgid;
  pv[5].iov_len = sizeof(data_len);
  pv[5].iov_base = &data_len;
  pv[6].iov_len = m->payload_len;
  pv[6].iov_base = m->payload;
  rv = writev(fd, pv, 7);
  if(rv != expect) return rv;
  if(rv == 0) return -1;
  return 0;
}

static void
fq_data_worker_loop(fq_conn_s *conn_s) {
  while(conn_s->cmd_fd >= 0 && conn_s->stop == 0) {
    int rv;
    int wait_ms = 500;
    ck_fifo_mpmc_entry_t *garbage;
    while(conn_s->tosend ||
          ck_fifo_mpmc_dequeue(&conn_s->q, &conn_s->tosend, &garbage) == true) {
#ifdef DEBUG
      fprintf(stderr, "dequeue message to submit to server\n");
#endif
      if(fq_client_write_msg(conn_s->data_fd, conn_s->tosend) < 0) return;
      fq_msg_deref(conn_s->tosend);
      conn_s->tosend = NULL;
      wait_ms = 0;
    }
    rv = fq_client_wfr_internal(conn_s->data_fd, wait_ms);
    if(rv < 0) return;
    if(rv > 0) {
      unsigned char c = 0;
      rv = read(conn_s->data_fd, &c, sizeof(c));
      if(rv == 0) return;
      fprintf(stderr, "read(%d) -> 0x%02x\n", rv, c);
    }
  }
#ifdef DEBUG
  fprintf(stderr, "cmd_fd -> %d, stop -> %d\n", conn_s->cmd_fd, conn_s->stop);
#endif
}
static void *
fq_data_worker(void *u) {
  int backoff = 0;
  fq_conn_s *conn_s = (fq_conn_s *)u;
  while(conn_s->stop == 0) {
    if(conn_s->data_ready) {
      if(fq_client_data_connect_internal(conn_s) == 0) {
        backoff = 0; /* we're good, restart our backoff */
      }

      fq_data_worker_loop(conn_s);
#ifdef DEBUG
      fprintf(stderr, "[data] connection failed: %s\n", conn_s->error);
#endif
    }
    if(backoff < 1000000) backoff += 10000;
    if(backoff) usleep(backoff);
  }
  if(conn_s->data_fd >= 0) {
    close(conn_s->data_fd);
    conn_s->data_fd = -1;
  }
  return (void *)NULL;
}
static void *
fq_conn_worker(void *u) {
  int backoff = 0;
  fq_conn_s *conn_s = (fq_conn_s *)u;
  while(conn_s->stop == 0) {
   restart:
    if(fq_client_connect_internal(conn_s) == 0) {
      backoff = 0; /* we're good, restart our backoff */
    }

    while(conn_s->data_ready) {
      hrtime_t t;
      unsigned long long hb_us;
      struct timeval tv;
      int rv;
      cmd_instr *entry;
      ck_fifo_mpmc_entry_t *garbage;

      while(ck_fifo_mpmc_dequeue(&conn_s->cmdq, &entry, &garbage) == true) {
        free(garbage);
#ifdef DEBUG
        fprintf(stderr, "client acting on user req 0x%04x\n", entry->cmd);
#endif
        switch(entry->cmd) {
          case FQ_PROTO_HBREQ:
            if(fq_write_uint16(conn_s->cmd_fd, entry->cmd) ||
               fq_write_uint16(conn_s->cmd_fd, entry->data.heartbeat.ms)) {
              free(entry);
              goto restart;
            }
            conn_s->cmd_hb_ms = entry->data.heartbeat.ms;
            tv.tv_sec = (unsigned long)entry->data.heartbeat.ms / 1000;
            tv.tv_usec = 1000UL * (entry->data.heartbeat.ms % 1000);
            if(setsockopt(conn_s->cmd_fd, SOL_SOCKET, SO_RCVTIMEO,
                          &tv, sizeof(tv)))
              CONNERR(conn_s, strerror(errno));
            tv.tv_sec = (unsigned long)entry->data.heartbeat.ms / 1000;
            tv.tv_usec = 1000UL * (entry->data.heartbeat.ms % 1000);
            if(setsockopt(conn_s->cmd_fd, SOL_SOCKET, SO_SNDTIMEO,
                          &tv, sizeof(tv)))
              CONNERR(conn_s, strerror(errno));
            conn_s->cmd_hb_last = fq_gethrtime();
            break;
          default:
            if(conn_s->errorlog) conn_s->errorlog("unknown user-side cmd");
        }
        free(entry);
      }

      if(conn_s->cmd_hb_needed) {
#ifdef DEBUG
          fprintf(stderr, "-> heartbeat\n");
#endif
        if(fq_write_uint16(conn_s->cmd_fd, FQ_PROTO_HB)) break;
        conn_s->cmd_hb_needed = 0;
      }

      rv = fq_client_wfr_internal(conn_s->cmd_fd, 50);
      t = fq_gethrtime();
      hb_us = (unsigned long long)conn_s->cmd_hb_ms * 3 * 1000000ULL;
      if(conn_s->cmd_hb_last && hb_us &&
         conn_s->cmd_hb_last < (t - hb_us)) {
        CONNERR(conn_s, "heartbeat failed");
        break;
      }
      if(rv < 0) {
        CONNERR(conn_s, strerror(errno));
        break;
      }
      if(rv > 0) {
        uint16_t hb;
        if(fq_read_uint16(conn_s->cmd_fd, &hb)) break;
        if(hb == FQ_PROTO_HB) {
#ifdef DEBUG
          fprintf(stderr, "<- heartbeat\n");
#endif
          conn_s->cmd_hb_last = fq_gethrtime();
          conn_s->cmd_hb_needed = 1;
        }
        else {
          if(conn_s->errorlog) conn_s->errorlog("protocol violation");
          break;
        }
      }
    }

    if(backoff < 1000000) backoff += 10000;
#ifdef DEBUG
    fprintf(stderr, "[cmd] connection failed: %s\n", conn_s->error);
#endif
    usleep(backoff);
  }
  fq_client_disconnect_internal(conn_s);
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
  conn_s->queue = strchr(conn_s->user, '/');
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
  conn_s->cmdqhead = malloc(sizeof(ck_fifo_mpmc_entry_t));
  ck_fifo_mpmc_init(&conn_s->cmdq, conn_s->cmdqhead);

  conn_s->qhead = malloc(sizeof(ck_fifo_mpmc_entry_t));
  ck_fifo_mpmc_init(&conn_s->q, conn_s->qhead);

  return 0;
}

void
fq_client_heartbeat(fq_client conn, unsigned short heartbeat_ms) {
  cmd_instr *e;
  e = malloc(sizeof(*e));
  e->cmd = FQ_PROTO_HBREQ;
  e->data.heartbeat.ms = heartbeat_ms;
  fq_client_signal(conn, e);
}

int
fq_client_connect(fq_client conn) {
  fq_conn_s *conn_s = conn;
  if(conn_s->connected != 0) return -1;

  conn_s->connected = 1;
  if(pthread_create(&conn_s->worker, NULL, fq_conn_worker, conn_s) != 0) {
      CONNERR(conn_s, "could not start command thread");
    return -1;
  }
  if(pthread_create(&conn_s->data_worker, NULL, fq_data_worker, conn_s) != 0) {
      CONNERR(conn_s, "could not start data thread");
    return -1;
  }
  return 0;
}

void
fq_client_publish(fq_client conn, fq_msg *msg) {
  fq_conn_s *conn_s = conn;
  ck_fifo_mpmc_entry_t *fifo_entry;
  fifo_entry = malloc(sizeof(ck_fifo_mpmc_entry_t));
  fq_msg_ref(msg);
  ck_fifo_mpmc_enqueue(&conn_s->q, fifo_entry, msg);
  ck_pr_inc_uint(&conn_s->qlen);
}


