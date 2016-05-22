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

#ifndef FQ_H
#define FQ_H

#ifndef _REENTRANT
#error "You must compile with -D_REENTRANT"
#endif

#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ck_fifo.h>
#include <ck_stack.h>

#define FQ_PROTO_CMD_MODE  0xcc50cafe
#define FQ_PROTO_DATA_MODE 0xcc50face
#define FQ_PROTO_PEER_MODE 0xcc50feed
#define FQ_PROTO_OLD_PEER_MODE 0xcc50fade
#define FQ_PROTO_READ_STAT 0x47455420 /* "GET " */
#define FQ_PROTO_HTTP_GET  0x47455420 /* "GET " */
#define FQ_PROTO_HTTP_PUT  0x50555420 /* "PUT " */
#define FQ_PROTO_HTTP_POST 0x504f5354 /* "POST" */
#define FQ_PROTO_HTTP_HEAD 0x48454144 /* "HEAD" */

#define FQ_BIND_PEER       0x00000001
#define FQ_BIND_PERM       0x00000110
#define FQ_BIND_TRANS      0x00000100

#define FQ_PROTO_ERROR     0xeeee
#define FQ_PROTO_AUTH_CMD  0xaaaa
#define FQ_PROTO_AUTH_PLAIN 0
#define FQ_PROTO_AUTH_RESP 0xaa00
#define FQ_PROTO_HBREQ     0x4848
#define FQ_PROTO_HB        0xbea7
#define FQ_PROTO_BINDREQ   0xb170
#define FQ_PROTO_BIND      0xb171
#define FQ_PROTO_UNBINDREQ 0x071b
#define FQ_PROTO_UNBIND    0x171b
#define FQ_PROTO_STATUS    0x57a7
#define FQ_PROTO_STATUSREQ 0xc7a7

#define FQ_DEFAULT_QUEUE_TYPE "mem"

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#define MAX_RK_LEN 127
typedef struct fq_rk {
  unsigned char  name[MAX_RK_LEN];
  uint8_t        len;
} fq_rk;

static inline void
fq_rk_from_str(fq_rk *rk, const char *str) {
  size_t len = strlen(str);
  memset(rk->name, 0, MAX_RK_LEN);
  rk->len = min(len, MAX_RK_LEN - 1);
  memcpy(rk->name, str, rk->len);
}

static inline int
fq_rk_cmp(const fq_rk * const a, const fq_rk * const b) {
  if(a->len < b->len) return -1;
  if(a->len > b->len) return 1;
  return memcmp(a->name, b->name, a->len);
}

#define FQ_BIND_ILLEGAL (uint32_t)0xffffffff

typedef struct {
  fq_rk exchange;
  uint32_t flags;
  char *program;

  uint32_t out__route_id;
} fq_bind_req;

typedef struct {
  fq_rk exchange;
  uint32_t route_id;

  uint32_t out__success;
} fq_unbind_req;

typedef struct fq_msgid {
  union {
    struct {
      uint32_t p1; /* user(sender) */
      uint32_t p2; /* user(sender) */
      uint32_t p3; /* reserved */
      uint32_t p4; /* reserved */
    } u32;
    unsigned char d[16];
  } id;
} fq_msgid;

typedef struct free_message_stack {
  ck_stack_t stack;
  uint32_t size;
  uint32_t max_size;
} free_message_stack;

#define MAX_HOPS 32
typedef struct fq_msg {
  uint32_t       hops[MAX_HOPS];
  fq_rk          route;
  fq_rk          sender;
  fq_rk          exchange;
  fq_msgid       sender_msgid;
  uint32_t       refcnt;
  uint32_t       payload_len;
  uint64_t       arrival_time;

  ck_stack_entry_t cleanup_stack_entry;
  free_message_stack *cleanup_stack;

  /* define a free function as an alternative to `free()` */
  void           (*free_fn)(struct fq_msg *m);
  unsigned char  payload[];  /* over allocated */
} fq_msg;


extern void fq_init_free_message_stack(free_message_stack *stack, const size_t max_free_count);
extern fq_msg *fq_pop_free_message_stack(free_message_stack *stack);
extern void fq_push_free_message_stack(free_message_stack *stack, fq_msg *m);
extern void fq_clear_message_cleanup_stack();

extern fq_msg *fq_msg_alloc(const void *payload,
                            size_t payload_size);
extern fq_msg *fq_msg_alloc_BLANK(size_t payload_size);
extern void    fq_msg_ref(fq_msg *);
extern void    fq_msg_deref(fq_msg *);
#define fq_msg_free(a) fq_msg_deref(a)
extern void    fq_msg_exchange(fq_msg *, const void *key, int klen);
extern void    fq_msg_route(fq_msg *, const void *key, int klen);
extern void    fq_msg_id(fq_msg *, fq_msgid *id);
extern int     fq_find_in_hops(uint32_t, fq_msg *);

typedef struct buffered_msg_reader buffered_msg_reader;

extern buffered_msg_reader *
  fq_buffered_msg_reader_alloc(int fd, uint32_t peermode);
extern void fq_buffered_msg_reader_free(buffered_msg_reader *f);
extern int
  fq_buffered_msg_read(buffered_msg_reader *f,
                       void (*f_msg_handler)(void *, fq_msg *),
                       void *);

/* frame */
/*
 *    1 x uint8_t<net>   hops
 * hops x uint32_t<net>  node
 *    1 x <nstring>      exchange
 *    1 x fq_rk<nstring> sender
 *    1 x fq_rk<nstring> route
 *    1 x uint32_t<net>  payload_len
 *    1 x data
 */


typedef struct fq_conn_s *fq_client;

#define FQ_HOOKS_V1 1
#define FQ_HOOKS_V2 2
#define FQ_HOOKS_V3 3
#define FQ_HOOKS_V4 4
typedef struct fq_hooks {
  int version;
  /* V1 */
  void (*auth)(fq_client, int);
  void (*bind)(fq_client, fq_bind_req *);
  /* V2 */
  void (*unbind)(fq_client, fq_unbind_req *);
  /* V3 */
  int sync;
  /* V4 */
  bool (*message)(fq_client, fq_msg *m);
  void (*cleanup)(fq_client);
  void (*disconnect)(fq_client);
} fq_hooks;

extern int
  fq_client_hooks(fq_client conn, fq_hooks *hooks);

extern void
  fq_client_set_userdata(fq_client, void *);

extern void *
  fq_client_get_userdata(fq_client);

extern int
  fq_client_init(fq_client *, uint32_t peermode,
                 void (*)(fq_client, const char *));

extern int
  fq_client_creds(fq_client,
                  const char *host, unsigned short port,
                  const char *source, const char *pass);

extern void
  fq_client_status(fq_client conn,
                   void (*f)(char *, uint32_t, void *), void *c);

extern void
  fq_client_heartbeat(fq_client conn, unsigned short ms);

extern void
  fq_client_bind(fq_client conn, fq_bind_req *req);

extern void
  fq_client_unbind(fq_client conn, fq_unbind_req *req);

extern void
  fq_client_set_backlog(fq_client conn, uint32_t len, uint32_t stall);

extern void
  fq_client_set_nonblock(fq_client conn, bool nonblock);

extern int
  fq_client_connect(fq_client conn);

extern int
  fq_client_publish(fq_client, fq_msg *msg);

extern fq_msg *
  fq_client_receive(fq_client conn);

extern void
  fq_client_destroy(fq_client conn);

extern int
  fq_client_data_backlog(fq_client conn);

extern int
  fq_rk_to_hex(char *buf, int len, fq_rk *k);

extern int
  fq_read_status(int fd, void (*f)(char *, uint32_t, void *), void *);

extern int
  fq_read_uint16(int fd, unsigned short *v);

extern int
  fq_write_uint16(int fd, unsigned short hs);

extern int
  fq_read_uint32(int fd, uint32_t *v);

extern int
  fq_write_uint32(int fd, uint32_t hs);

extern int
  fq_read_short_cmd(int fd, unsigned short buflen, void *buf);

extern int
  fq_write_short_cmd(int fd, unsigned short buflen, const void *buf);

extern int
  fq_read_long_cmd(int fd, int *len, void **buf);

/* This function returns 0 on success, -1 on failure or a positive
 * integer indicating that a partial write as happened.
 * The initial call should be made with off = 0, if a positive
 * value is returned, a subsequent call should be made with
 * off = (off + return value).
 * The caller must be able to keep track of an accumulated offset
 * in the event that several invocations are required to send the
 * message.
 */
extern int
  fq_client_write_msg(int fd, uint32_t peermode, fq_msg *m,
                      size_t off, size_t *written);

typedef enum {
  FQ_POLICY_DROP = 0,
  FQ_POLICY_BLOCK = 1,
} queue_policy_t;

typedef enum {
  FQ_DEBUG_MEM =     0x00000001,
  FQ_DEBUG_MSG =     0x00000002,
  FQ_DEBUG_ROUTE =   0x00000004,
  FQ_DEBUG_IO =      0x00000008,
  FQ_DEBUG_CONN =    0x00000010,
  FQ_DEBUG_CONFIG =  0x00000020,
  FQ_DEBUG        =  0x00000040,
  FQ_DEBUG_PEER =    0x00000080,
  FQ_DEBUG_HTTP =    0x00000100,
  FQ_DEBUG_PANIC =   0x40000000
} fq_debug_bits_t;

extern uint32_t fq_debug_bits;

void fq_debug_set_bits(uint32_t bits);
/* string can be integer, hex or comma separated string (e.g. "mem,io") */
void fq_debug_set_string(const char *s);

extern int
  fq_debug_fl(const char *file, int line, fq_debug_bits_t, const char *fmt, ...)
  __attribute__((format(printf, 4, 5)));

#define fq_debug(type, ...) do { \
  if(0 != (type & fq_debug_bits)) { \
    fq_debug_fl(__FILE__, __LINE__, type, __VA_ARGS__); \
  } \
} while(0)

#define fq_stacktrace(b,t,s,e) do { \
  if(0 != (b & fq_debug_bits)) { \
    fq_debug_stacktrace(b,t,s,e); \
  } \
} while(0)

extern void fq_debug_stacktrace(fq_debug_bits_t b, const char *tag, int start, int end);

#if defined(__MACH__)
typedef uint64_t hrtime_t;
#elif defined(linux) || defined(__linux) || defined(__linux__)
typedef long long unsigned int hrtime_t;
#endif
extern hrtime_t fq_gethrtime(void);


/* DTrace helpers */
typedef struct {
  char *route;
  char *sender;
  char *exchange;
  char *payload;
  uint32_t payload_len;
  uint64_t latency;
} fq_dtrace_msg_t;

#define DTRACE_PACK_MSG(dmsg, msg) do { \
    (dmsg)->route = (char *)(msg)->route.name; \
    (dmsg)->sender = (char *)(msg)->sender.name; \
    (dmsg)->exchange = (char *)(msg)->exchange.name; \
    (dmsg)->payload_len = (uint32_t)(msg)->payload_len; \
    (dmsg)->payload = (char *)(msg)->payload; \
    (dmsg)->latency = fq_gethrtime() - (msg)->arrival_time; \
} while(0)

#define fq_assert(A) do { \
    if(!(A)) { \
        fq_debug_stacktrace(FQ_DEBUG_PANIC, "assert", 1, 1000); \
        (void)fprintf (stderr, "%s:%s:%u: failed assertion `%s'\n", __func__, __FILE__, __LINE__, #A); \
        abort(); \
    } \
} while(0)

#endif
