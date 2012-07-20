#include "fq.h"
#include "fqd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>
#include <errno.h>
#include <pthread.h>
#include <assert.h>
#include <stdarg.h>
#include <execinfo.h>

uint32_t fq_debug_bits = 0;

void fq_debug_set_bits(uint32_t bits) {
  fq_debug_bits = bits;
}

#define IN_READ_BUFFER_SIZE 1024*128
struct buffered_msg_reader {
  unsigned char scratch[IN_READ_BUFFER_SIZE];
  int fd;
  int off;
  int peermode;
  ssize_t nread;
  ssize_t into_body;
  fq_msg msg;
  fq_msg *copy;
};

buffered_msg_reader *fq_buffered_msg_reader_alloc(int fd, int peermode) {
  buffered_msg_reader *br;
  br = calloc(1, sizeof(*br));
  br->fd = fd;
  br->peermode = peermode;
  return br;
}
void fq_buffered_msg_reader_free(buffered_msg_reader *f) {
  if(f->copy) free(f->copy);
  free(f);
}
static int
parse_message_headers(int peermode, unsigned char *d, int dlen,
                      fq_msg *msg) {
  int ioff = 0;
  unsigned char exchange_len, route_len, sender_len, nhops;
#define BAIL_UNLESS_LEFT(d) do { \
  if((dlen-ioff) < (int)(d)) return 0; \
} while(0)

  BAIL_UNLESS_LEFT(sizeof(exchange_len));
  memcpy(&exchange_len, d+ioff, sizeof(exchange_len));
  ioff += sizeof(exchange_len);
  if(exchange_len > sizeof(msg->exchange.name)) return -1;
  msg->exchange.len = exchange_len;

  BAIL_UNLESS_LEFT(exchange_len);
  memcpy(msg->exchange.name, d+ioff, exchange_len);
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

  if(peermode) {
    /* Peer mode includes the sender and the hops */
    BAIL_UNLESS_LEFT(sizeof(sender_len));
    memcpy(&sender_len, d+ioff, sizeof(sender_len));
    ioff += sizeof(sender_len);
    if(sender_len > sizeof(msg->sender.name)) return -3;
    msg->sender.len = sender_len;

    BAIL_UNLESS_LEFT(sender_len);
    memcpy(msg->sender.name, d+ioff, sender_len);
    ioff += sender_len;

    BAIL_UNLESS_LEFT(sizeof(nhops));
    memcpy(&nhops, d+ioff, sizeof(nhops));
    ioff += sizeof(nhops);
    if(nhops > MAX_HOPS) return -4;

    if(nhops > 0) {
      BAIL_UNLESS_LEFT(sizeof(uint32_t) * nhops);
      memcpy(msg->hops, d+ioff, sizeof(uint32_t) * nhops);
      ioff += sizeof(uint32_t) * nhops;
    }
  }

  BAIL_UNLESS_LEFT(sizeof(msg->payload_len));
  memcpy(&msg->payload_len, d+ioff, sizeof(msg->payload_len));
  msg->payload_len = ntohl(msg->payload_len);
  ioff += sizeof(msg->payload_len);
  assert(msg->payload_len < (1024*128));

  return ioff;
}
/*
 * return 0: keep going (to write path)
 * return -1: busted
 */
int
fq_buffered_msg_read(buffered_msg_reader *f,
                     void (*f_msg_handler)(void *, fq_msg *),
                     void *closure) {
  int rv;
  if(f->into_body < f->msg.payload_len) {
    assert(f->copy);
    /* we need to be reading a largish payload */
    while((rv = read(f->fd, f->copy->payload + f->into_body,
                     f->copy->payload_len - f->into_body)) == -1 && errno == EINTR);
    if(rv < 0 && errno == EAGAIN) return 0;
    if(rv <= 0) {
      fq_debug(FQ_DEBUG_IO, "read error: %s\n", rv < 0 ? strerror(errno) : "end-of-line");
      return -1;
    }
    fq_debug(FQ_DEBUG_MSG, "%p <-- %d bytes for payload\n", (void *)f, rv);
    f->into_body += rv;
    if(f->into_body == f->copy->payload_len) {
      f->into_body = 0;
      goto message_done;
    }
  }
  while((rv = read(f->fd, f->scratch+f->nread, sizeof(f->scratch)-f->nread)) == -1 &&
        errno == EINTR);
  fq_debug(FQ_DEBUG_IO, "%p <-- %d bytes @ %d (%d)\n", (void *)f, rv, (int)f->nread,
          (int)f->nread + (rv > 0) ? rv : 0);
  if(rv == -1 && errno == EAGAIN) return 0;
  if(rv <= 0) return -1;
  f->nread += rv;

  while(f->nread>0) {
    uint32_t body_available;
    int body_start;
    body_start = parse_message_headers(f->peermode,
                                       f->scratch+f->off, f->nread-f->off,
                                       &f->msg);
    f->into_body = 0;
    fq_debug(FQ_DEBUG_MSG, "%d = parse(+%d, %d) -> %d\n",
            body_start, f->off, (int)f->nread-f->off,
            body_start ? (int)f->msg.payload_len : 0);
    if(body_start < 0) return -1;
    if(!body_start) {
      fq_debug(FQ_DEBUG_MSG, "incomplete message header...\n");
      memmove(f->scratch, f->scratch + f->off, f->nread - f->off);
      f->nread -= f->off;
      f->off = 0;
      return 0;
    }

    /* We have a message... or the formal beginnings of one */
    f->copy = fq_msg_alloc_BLANK(f->msg.payload_len);
    memcpy(f->copy, &f->msg, sizeof(f->msg));

    f->off += body_start;
    body_available = f->nread - f->off;
    if(f->copy->payload_len < body_available) body_available = f->copy->payload_len;
    memcpy(f->copy->payload, f->scratch+f->off, body_available);
    if(body_available == f->copy->payload_len) {
      f->off += body_available;
     message_done:
      f->copy->refcnt = 1;
      fq_debug(FQ_DEBUG_MSG, "message read... injecting\n");
      f_msg_handler(closure, f->copy);
      f->copy = NULL;
      memset(&f->msg, 0, sizeof(f->msg));
    }
    else {
      f->nread = 0;
      f->off = 0;
      f->into_body = body_available;
      fq_debug(FQ_DEBUG_MSG, "incomplete message... (%d needed)\n",
             (int)f->msg.payload_len - (int)f->into_body);
      return 0;
    }
  }
  return 0;
}

#ifdef __MACH__
#include <mach/mach.h>
#include <mach/clock.h>

static int initialized = 0;
static clock_serv_t clk_system;
static mach_port_t myport;
hrtime_t fq_gethrtime() {
  mach_timespec_t now;
  if(!initialized) {
    kern_return_t kr;
    myport = mach_host_self();
    kr = host_get_clock_service(myport, SYSTEM_CLOCK, &clk_system);
    if(kr == KERN_SUCCESS) initialized = 1;
  }
  clock_get_time(clk_system, &now);
  return ((uint64_t)now.tv_sec * 1000000000ULL) +
         (uint64_t)now.tv_nsec;
}
#else
hrtime_t fq_gethrtime() {
  return gethrtime();
}
#endif

int fq_rk_to_hex(char *buf, int len, fq_rk *k) {
  int i;
  unsigned char *bout = (unsigned char *)buf;
  if(k->len * 2 + 4 > len) return -1;
  *bout++ = '0';
  *bout++ = 'x';
  for (i=0; i<k->len; i++) {
    snprintf((char *)bout, 3, "%02x", k->name[i]);
    bout+=2;
  }
  *bout = '\0';
  return (bout - (unsigned char *)buf);
}
int
fq_read_uint16(int fd, unsigned short *v) {
  unsigned short nlen;
  int rv;
  while((rv = read(fd, &nlen, sizeof(nlen))) == -1 && errno == EINTR);
  if(rv != sizeof(nlen)) return -1;
  *v = ntohs(nlen);
  return 0;
}
int
fq_write_uint16(int fd, unsigned short v) {
  uint16_t nv;
  int rv;
  nv = htons(v);
  while((rv = write(fd, &nv, sizeof(nv))) == -1 && errno == EINTR);
  return (rv == sizeof(nv)) ? 0 : -1;
}
int
fq_read_uint32(int fd, uint32_t *v) {
  uint32_t nlen;
  int rv;
  while((rv = read(fd, &nlen, sizeof(nlen))) == -1 && errno == EINTR);
  if(rv != sizeof(nlen)) return -1;
  *v = ntohl(nlen);
  return 0;
}
int
fq_write_uint32(int fd, uint32_t v) {
  uint32_t nv;
  int rv;
  nv = htonl(v);
  while((rv = write(fd, &nv, sizeof(nv))) == -1 && errno == EINTR);
  return (rv == sizeof(nv)) ? 0 : -1;
}
int
fq_read_short_cmd(int fd, unsigned short buflen, void *buf) {
  void *tgt = buf;
  unsigned char  scratch[0xffff];
  unsigned short nlen, len;
  int rv;
  while((rv = read(fd, &nlen, sizeof(nlen))) == -1 && errno == EINTR);
  if(rv < 0 || rv != sizeof(nlen)) return -1;
  len = ntohs(nlen);
  if(len == 0) return 0;
  if(len > buflen)
    tgt = scratch;
  while((rv = read(fd, tgt, len)) == -1 && errno == EINTR);
  if(rv != len) {
    return -1;
  }
  if(tgt != buf) memcpy(buf, tgt, buflen); /* truncated */
  return rv;
}
int
fq_read_status(int fd, void (*f)(char *, uint32_t, void *), void *closure) {
  while(1) {
    char key[0x10000];
    int len;
    uint32_t value;

    len = fq_read_short_cmd(fd, 0xffff, key);
    if(len < 0) return -1;
    if(len == 0) break;
    key[len] = '\0';
    if(fq_read_uint32(fd, &value) < 0) return -1;
    f(key, value, closure);
  }
  return 0;
}
int
fq_write_short_cmd(int fd, unsigned short buflen, const void *buf) {
  unsigned short nlen;
  int rv;
  nlen = htons(buflen);
  while((rv = write(fd, &nlen, sizeof(nlen))) == -1 && errno == EINTR);
  if(rv != sizeof(nlen)) return -1;
  if(buflen == 0) return 0;
  while((rv = write(fd, buf, buflen)) == -1 && errno == EINTR);
  if(rv != buflen) return -1;
  return rv;
}

int
fq_read_long_cmd(int fd, int *rlen, void **rbuf) {
  unsigned int nlen;
  int rv, len;
  while((rv = read(fd, &nlen, sizeof(nlen))) == -1 && errno == EINTR);
  if(rv < 0 || rv != sizeof(nlen)) return -1;
  len = ntohl(nlen);
  *rlen = 0;
  *rbuf = NULL;
  if(len < 0) {
    return -1;
  }
  else if(len > 0) {
    *rbuf = malloc(len);
    while((rv = read(fd, *rbuf, len)) == -1 && errno == EINTR);
    if(rv != len) {
      free(*rbuf);
      *rlen = 0;
      *rbuf = NULL;
      return -1;
    }
    *rlen = rv;
  }
  return *rlen;
}

int
fq_debug_fl(const char *file, int line, fq_debug_bits_t b, const char *fmt, ...) {
  int rv;
  va_list argp;
  static hrtime_t epoch = 0;
  hrtime_t now;
  char fmtstring[1024];
  uint64_t p = (uint64_t)pthread_self();
  uint32_t ps = p & 0xffffffff;

  (void)b;
  now = fq_gethrtime();
  if(!epoch) epoch = now;

  snprintf(fmtstring, sizeof(fmtstring), "[%llu] [%08x] %s",
           (now-epoch)/1000, ps, fmt);
  va_start(argp, fmt);
  rv = vfprintf(stderr, fmtstring, argp);
  va_end(argp);
  (void)file;
  (void)line;
  return rv;
}

void
fq_debug_stacktrace(fq_debug_bits_t b, const char *tag, int start, int end) {
#define STACK_DEPTH 16
  int i, cnt;
  void *bti[STACK_DEPTH + 1], **bt = bti+1;
  char **btname;
  cnt = backtrace(bti, STACK_DEPTH + 1);
  if(cnt < 1) {
    fq_debug(b, "track trace failed\n");
    return;
  }
  btname = backtrace_symbols(bt, cnt);
  if(start > cnt) start = cnt;
  if(end > cnt) end = cnt;
  for(i=start;i!=end;i += (start > end) ? -1 : 1) {
    if(btname && btname[i])
      fq_debug(b, "[%2d] %s %s\n", i, tag, btname[i]);
    else
      fq_debug(b, "[%2d] %s %p\n", i, tag, bt[i]);
  }
  if(btname) free(btname);
}

int
fq_client_write_msg(int fd, int peermode, fq_msg *m, size_t off) {
  struct iovec pv[11]; /* 7 for normal + 4 for peer */
  int rv, i, writev_start = 0, idx = 0;
  size_t expect;
  unsigned char nhops = 0;
  unsigned char sender_len = m->sender.len;
  unsigned char exchange_len = m->exchange.len;
  unsigned char route_len = m->route.len;
  uint32_t      data_len = htonl(m->payload_len);

  expect = 1 + m->exchange.len + 1 + m->route.len +
           sizeof(m->sender_msgid) +
           sizeof(data_len) + m->payload_len;

  if(peermode) {
    for(i=0;i<MAX_HOPS;i++) {
      if(m->hops[i] == 0) break;
      nhops++;
    }
    expect += 1 + m->sender.len + 1 + (nhops * sizeof(uint32_t));
  }
  assert(off < expect);
  expect -= off;
  pv[idx  ].iov_len = 1;
  pv[idx++].iov_base = &exchange_len;
  pv[idx  ].iov_len = m->exchange.len;
  pv[idx++].iov_base = m->exchange.name;
  pv[idx  ].iov_len = 1;
  pv[idx++].iov_base = &route_len;
  pv[idx  ].iov_len = m->route.len;
  pv[idx++].iov_base = m->route.name;
  pv[idx  ].iov_len = sizeof(m->sender_msgid);
  pv[idx++].iov_base = &m->sender_msgid;
  if(peermode) {
    pv[idx  ].iov_len = 1;
    pv[idx++].iov_base = &sender_len;
    pv[idx  ].iov_len = m->sender.len;
    pv[idx++].iov_base = m->sender.name;
    pv[idx  ].iov_len = 1;
    pv[idx++].iov_base = &nhops;
    pv[idx  ].iov_len = nhops * sizeof(uint32_t);
    pv[idx++].iov_base = m->hops;
  }
  pv[idx  ].iov_len = sizeof(data_len);
  pv[idx++].iov_base = &data_len;
  pv[idx  ].iov_len = m->payload_len;
  pv[idx++].iov_base = m->payload;
  if(off > 0) {
    for(i=0;i<idx;i++) {
      if(off >= pv[i].iov_len) {
        off -= pv[i].iov_len;
        writev_start++;
      }
      else {
        pv[i].iov_len -= off;
        pv[i].iov_base = ((unsigned char *)pv[i].iov_base) + off;
        off = 0;
        break;
      }
    }
  }
  rv = writev(fd, pv+writev_start, idx-writev_start);
  fq_debug(FQ_DEBUG_IO, "writev(%d bytes [%d data]) -> %d\n",
           (int)expect, (int)m->payload_len, rv);
  if(rv != (int)expect) {
    return rv;
  }
  if(rv == 0) return -1;
  return 0;
}

