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

#include "fq.h"
#include "fqd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/uio.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <execinfo.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <assert.h>

struct free_message_stack {
   ck_stack_t stack;
   uint32_t size;
   uint32_t max_size;
   size_t alloc_size;
};

/* this is actually in <sys/sysmacros.h> on illumos but flagged off for some reason */
#ifndef container_of
#define container_of(m, s, name)                        \
  (void *)((uintptr_t)(m) - (uintptr_t)offsetof(s, name))
#endif

uint32_t fq_debug_bits = FQ_DEBUG_PANIC;

void fq_debug_set_bits(uint32_t bits) {
  fq_debug_bits = bits | FQ_DEBUG_PANIC;
}

static void
fq_init_free_message_stack(free_message_stack *stack, const size_t max_free_count,
                           const size_t alloc_size)
{
  ck_stack_init(&stack->stack);
  stack->size = 0;
  stack->max_size = max_free_count;
  stack->alloc_size = alloc_size;
}

static inline fq_msg *
fq_pop_free_message_stack(struct free_message_stack *stack)
{
  fq_msg *rv = NULL;
  if (stack == NULL) {
    return rv;
  }

  ck_stack_entry_t *ce = ck_stack_pop_mpmc(&stack->stack);
  if (ce != NULL) {
    ck_pr_dec_32(&stack->size);
    rv = container_of(ce, fq_msg, cleanup_stack_entry);
  }
  return rv;
}

static inline void 
fq_push_free_message_stack(struct free_message_stack *stack, fq_msg *m) 
{
  if (stack == NULL) {
    return;
  }

  while(ck_pr_load_32(&stack->size) > stack->max_size) {
    ck_stack_entry_t *ce = ck_stack_batch_pop_mpmc(&stack->stack);
    while (ce != NULL) {
      fq_msg *m = container_of(ce, fq_msg, cleanup_stack_entry);
      ce = ce->next;
      free(m);
    }
  }
  uint32_t c = ck_pr_load_32(&stack->size);
  if (c >= stack->max_size) {
    free(m);
    return;
  }

  ck_pr_inc_32(&stack->size);
  ck_stack_push_mpmc(&stack->stack, &m->cleanup_stack_entry);
}

static void
fq_free_msg_fn(fq_msg *m) 
{
  if (m->cleanup_stack) {
    fq_push_free_message_stack(m->cleanup_stack, m);
  } else {
    free(m);
  }
}

void fq_debug_set_string(const char *s) {
  char *lastsep, *tok = NULL;
  char copy[128];
  unsigned long nv;
  int slen;

  if(!s) return;
  /* then comma separated named */
  slen = strlen(s);
  if(slen < 0 || slen > sizeof(copy) - 1) return;
  /* copy including null terminator */
  memcpy(copy,s,slen+1);

  /* First try decimal */
  nv = strtoul(copy,&lastsep,10);
  if(*lastsep == '\0') {
    fq_debug_set_bits(nv);
    return;
  }

  /* Then try hex */
  nv = strtoul(copy,&lastsep,16);
  if(*lastsep == '\0') {
    fq_debug_set_bits(nv);
    return;
  }

  for (tok = strtok_r(copy, ",", &lastsep);
       tok;
       tok = strtok_r(NULL, ",", &lastsep)) {
#define SETBIT(tok, A) do { \
  if(!strcasecmp(tok, #A + 9)) fq_debug_bits |= A; \
} while(0)
    SETBIT(tok, FQ_DEBUG_MEM);
    SETBIT(tok, FQ_DEBUG_MSG);
    SETBIT(tok, FQ_DEBUG_ROUTE);
    SETBIT(tok, FQ_DEBUG_IO);
    SETBIT(tok, FQ_DEBUG_CONN);
    SETBIT(tok, FQ_DEBUG_CONFIG);
    SETBIT(tok, FQ_DEBUG_PEER);
    SETBIT(tok, FQ_DEBUG_HTTP);
  }
}

#define IN_READ_BUFFER_SIZE 1024*128
#define FREE_MSG_LIST_SIZE 100000000 /* in bytes */
#define CAPPED(x) (((x)<(MAX_MESSAGE_SIZE))?(x):(MAX_MESSAGE_SIZE))
struct buffered_msg_reader {
  unsigned char scratch[IN_READ_BUFFER_SIZE];
  int fd;
  int off;
  uint32_t peermode;
  ssize_t nread;
  ssize_t into_body;
  fq_msg *copy;
  fq_msg *msg;
};

/* We support separate stacks for separate msg sizes...
 * containers are from 2^10 (1k) to 2^16 (65k).
 * Messages are allocated from the smallest stack that can cotain them.
 * Otherwise, they are traditionally allocated.
 */
#define MSG_FREE_BASE 10
#define MSG_FREE_CEILING 16

#define MSG_FREE_STACKS (MSG_FREE_CEILING-MSG_FREE_BASE+1)
static inline int msg_free_stack_select(ssize_t in) {
  int i;
  if(in <= (1 << MSG_FREE_BASE)) return 0;
  in--;
  in >>= MSG_FREE_BASE+1;
  for(i = 1; i < MSG_FREE_STACKS && in; i++, in >>= 1);
  if(i < MSG_FREE_STACKS) return i;
  return -1;
}


static __thread free_message_stack *tls_free_message_stacks[MSG_FREE_STACKS] = { NULL };

buffered_msg_reader *fq_buffered_msg_reader_alloc(int fd, uint32_t peermode) {
  buffered_msg_reader *br;
  br = calloc(1, sizeof(*br));
  br->fd = fd;
  br->peermode = peermode;
  br->msg = fq_msg_alloc_BLANK(0);
  return br;
}
void fq_buffered_msg_reader_free(buffered_msg_reader *f) {
  assert(f->msg->refcnt == 1);
  fq_msg_deref(f->msg);
  if(f->copy) fq_msg_deref(f->copy);
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

  return ioff;
}

void 
fq_clear_message_cleanup_stack()
{
  int i;
  for(i=0; i<MSG_FREE_STACKS; i++) {
    if (tls_free_message_stacks[i]) {
      tls_free_message_stacks[i]->max_size = 0;
      ck_stack_entry_t *ce = ck_stack_batch_pop_mpmc(&tls_free_message_stacks[i]->stack);
      while (ce != NULL) {
        fq_msg *m = container_of(ce, fq_msg, cleanup_stack_entry);
        ce = ce->next;
        free(m);
      }
    }
  }
}

/*
 * return 0: keep going (to write path)
 * return -1: busted
 * 
 * Read into one of N buffers so the processing thread 
 * can do the work separate from the read
 */
int
fq_buffered_msg_read(buffered_msg_reader *f,
                     void (*f_msg_handler)(void *, fq_msg *),
                     void *closure) {
  int rv;
  static char scratch_buf[IN_READ_BUFFER_SIZE];
  while(f->into_body < f->msg->payload_len) {
    fq_assert(f->copy);
    /* we need to be reading a largish payload */
    if(f->into_body >= MAX_MESSAGE_SIZE) {
      /* read into a scratch buffer */
      size_t readsize = f->copy->payload_len - f->into_body;
      if(readsize > sizeof(scratch_buf)) readsize = sizeof(scratch_buf);
      while((rv = read(f->fd, scratch_buf, readsize)) == -1 && errno == EINTR);
    }
    else {
      while((rv = read(f->fd, f->copy->payload + f->into_body,
                       CAPPED(f->copy->payload_len) - f->into_body)) == -1 && errno == EINTR);
    }
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
          (int)f->nread + ((rv > 0) ? rv : 0));
  if(rv == -1 && errno == EAGAIN) return 0;
  if(rv <= 0) return -1;
  f->nread += rv;

  while(f->nread>0) {
    uint32_t body_available;
    int body_start;
    body_start = parse_message_headers(f->peermode,
                                       f->scratch+f->off, f->nread-f->off,
                                       f->msg);
    f->into_body = 0;
    fq_debug(FQ_DEBUG_MSG, "%d = parse(+%d, %d) -> %d\n",
            body_start, f->off, (int)f->nread-f->off,
            body_start ? (int)f->msg->payload_len : 0);
    if(body_start < 0) return -1;
    if(!body_start) {
      fq_debug(FQ_DEBUG_MSG, "incomplete message header...\n");
      memmove(f->scratch, f->scratch + f->off, f->nread - f->off);
      f->nread -= f->off;
      f->off = 0;
      return 0;
    }

    free_message_stack *tls_free_message_stack = NULL;
    int msg_stack_idx = msg_free_stack_select(f->msg->payload_len);
    if(msg_stack_idx >= 0) {
      if(tls_free_message_stacks[msg_stack_idx] == NULL) {
        /* lazy create/init the cleanup stack */
        tls_free_message_stacks[msg_stack_idx] = malloc(sizeof(free_message_stack));
        fq_init_free_message_stack(tls_free_message_stacks[msg_stack_idx],
                                   FREE_MSG_LIST_SIZE/(1 << (msg_stack_idx + MSG_FREE_BASE)),
                                   (1 << (msg_stack_idx + MSG_FREE_BASE)));
      }
      tls_free_message_stack = tls_free_message_stacks[msg_stack_idx];
    }

    if(tls_free_message_stack) {
      /* We have a message... or the formal beginnings of one */
      f->copy = fq_pop_free_message_stack(tls_free_message_stack);
      if (f->copy == NULL) {
        /* ran out of entries in free list */
        f->copy = fq_msg_alloc_BLANK(tls_free_message_stack->alloc_size);
        if (f->copy == NULL) {
          /* this is bad, we can't alloc */
          fq_debug(FQ_DEBUG_MSG, "unable to malloc, OOM?\n");
          return -1;
        }
      }

      /* always 1 as this msg only lives until it's copied by a worker thread */
      memcpy(f->copy, f->msg, sizeof(fq_msg));
      f->copy->refcnt = 1;
      f->copy->free_fn = fq_free_msg_fn;

    } else {
      f->copy = fq_msg_alloc_BLANK(CAPPED(f->msg->payload_len));
      if (f->copy == NULL) {
        /* this is bad, we can't alloc */
        fq_debug(FQ_DEBUG_MSG, "unable to malloc, OOM?\n");
        return -1;
      }

      memcpy(f->copy, f->msg, sizeof(fq_msg));
      f->copy->refcnt = 1;
      f->copy->free_fn = NULL;
    }

    /* assign the cleanup stack for this message */
    f->copy->cleanup_stack = tls_free_message_stack;
    memset(&f->copy->cleanup_stack_entry, 0, sizeof(ck_stack_entry_t));

    f->off += body_start;
    body_available = f->nread - f->off;
    if(f->copy->payload_len < body_available) body_available = f->copy->payload_len;
    memcpy(f->copy->payload, f->scratch+f->off, CAPPED(body_available));
    if(body_available == f->copy->payload_len) {
      f->off += body_available;
     message_done:
      f->copy->refcnt = 1;
      f->copy->payload_len = CAPPED(f->copy->payload_len);
      fq_debug(FQ_DEBUG_MSG, "message read... injecting\n");
      f->copy->arrival_time = fq_gethrtime();
      f_msg_handler(closure, f->copy);
      f->copy = NULL;
      memset(f->msg, 0, sizeof(fq_msg));
      /* It is still allocated and we are the sole owner, refcnt must be 1 */
      f->msg->refcnt = 1;
    }
    else {
      f->nread = 0;
      f->off = 0;
      f->into_body = body_available;
      fq_debug(FQ_DEBUG_MSG, "incomplete message... (%d needed)\n",
             (int)f->msg->payload_len - (int)f->into_body);
      return 0;
    }
  }
  return 0;
}

#if defined(BSD) || defined(__FreeBSD__)
#include <time.h>
#define NANOSEC	1000000000

hrtime_t fq_gethrtime() {
  struct timespec ts;
  clock_gettime(CLOCK_UPTIME,&ts);
  return (((u_int64_t) ts.tv_sec) * NANOSEC + ts.tv_nsec);
}
#elif defined(linux)
#include <time.h>
hrtime_t fq_gethrtime() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  return ((ts.tv_sec * 1000000000) + ts.tv_nsec);
}
#elif defined(__MACH__)
#include <mach/mach.h>
#include <mach/mach_time.h>

static int initialized = 0;
static mach_timebase_info_data_t    sTimebaseInfo;
hrtime_t fq_gethrtime() {
  uint64_t t;
  if(!initialized) {
    if(sTimebaseInfo.denom == 0)
      (void) mach_timebase_info(&sTimebaseInfo);
  }
  t = mach_absolute_time();
  return t * sTimebaseInfo.numer / sTimebaseInfo.denom;
}
#else
inline hrtime_t fq_gethrtime() {
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

  snprintf(fmtstring, sizeof(fmtstring), "[%" PRIu64 "] [%08x] %s",
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

int fq_serialize(struct iovec **vecs, int *vec_count, uint32_t peermode, size_t off, fq_msg *m) 
{
  int      i, writev_start = 0, idx = 0;
  size_t   expect = 0;
  uint32_t data_len = htonl(m->payload_len);
  uint8_t  nhops = 0;
  uint8_t  sender_len = m->sender.len;
  uint8_t  exchange_len = m->exchange.len;
  uint8_t  route_len = m->route.len;

  if (vecs == NULL) {
    return -1;
  }

  *vec_count = 7 + (peermode ? 4 : 0);
  /* 7 for normal + 4 for peer */
  *vecs = calloc(*vec_count, sizeof(struct iovec));

  struct iovec *pv = *vecs;

  expect = 1 + m->exchange.len + 1 + m->route.len +
           sizeof(m->sender_msgid) +
           sizeof(data_len) + m->payload_len;

  if(peermode) {
    for(i = 0; i < MAX_HOPS; i++) {
      if(m->hops[i] == 0) break;
      nhops++;
    }
    expect += 1 + m->sender.len + 1 + (nhops * sizeof(uint32_t));
  }
  fq_assert(off < expect);
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
    for(i = 0; i < idx; i++) {
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
  return 0;
}

int
fq_client_write_msg(int fd, uint32_t peermode, fq_msg *m, size_t off, size_t *written) {
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
  fq_assert(off < expect);
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
  if(rv > 0 && written) *written = rv;
  if(rv != (int)expect) {
    return rv;
  }
  if(rv == 0) return -1;
  return 0;
}

int
fq_find_in_hops(uint32_t needle, fq_msg *m) {
  int i;
  for(i=0; i<MAX_HOPS; i++) {
    if(m->hops[i] == needle) return i;
  }
  return -1;
}

