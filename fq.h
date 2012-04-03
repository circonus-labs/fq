#ifndef FQ_H
#define FQ_H

#ifndef _REENTRANT
#error "You must compile with -D_REENTRANT"
#endif

#include <string.h>
#include <sys/types.h>
#include <stdint.h>

#define FQ_PROTO_CMD_MODE  0xcc50cafe
#define FQ_PROTO_DATA_MODE 0xcc50face
#define FQ_PROTO_PEER_MODE 0xcc50fade

#define FQ_PROTO_ERROR     0xeeee
#define FQ_PROTO_AUTH_CMD  0xaaaa
#define FQ_PROTO_AUTH_PLAIN 0
#define FQ_PROTO_AUTH_RESP 0xaa00
#define FQ_PROTO_HBREQ     0x4848
#define FQ_PROTO_HB        0xbea7

#define MAX_RK_LEN 127
typedef struct fq_rk {
  unsigned char  name[MAX_RK_LEN];
  uint8_t        len;
} fq_rk;

static inline int
fq_rk_cmp(const fq_rk * const a, const fq_rk * const b) {
  if(a->len < b->len) return -1;
  if(a->len > b->len) return 1;
  return memcmp(a->name, b->name, a->len);
}

typedef struct fq_msgid {
  union {
    struct {
      uint32_t p1;
      uint32_t p2;
      uint32_t p3;
      uint32_t p4;
    } u32;
    unsigned char d[16];
  } id;
} fq_msgid;

#define MAX_HOPS 32
typedef struct fq_msg {
  uint32_t       hops[MAX_HOPS];
  fq_rk          route;
  fq_rk          sender;
  fq_rk          exchange;
  fq_msgid       sender_msgid;
  uint32_t       refcnt;
  uint32_t       payload_len;
  unsigned char  payload[1];  /* over allocated */
} fq_msg;

extern fq_msg *fq_msg_alloc(const void *payload,
                            size_t payload_size);
extern fq_msg *fq_msg_alloc_BLANK(size_t payload_size);
extern void    fq_msg_ref(fq_msg *);
extern void    fq_msg_deref(fq_msg *);
#define fq_msg_free(a) fq_msg_deref(a)
extern void    fq_msg_route(fq_msg *, const void *key, int klen);
extern void    fq_msg_id(fq_msg *, fq_msgid *id);

typedef struct buffered_msg_reader buffered_msg_reader;

extern buffered_msg_reader *fq_buffered_msg_reader_alloc(int fd, int peermode);
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

extern int
  fq_client_init(fq_client *, int peermode, void (*)(const char *));

extern int
  fq_client_creds(fq_client,
                  const char *host, unsigned short port,
                  const char *source, const char *pass);

extern void
  fq_client_heartbeat(fq_client conn, unsigned short ms);

extern void
  fq_client_set_backlog(fq_client conn, uint32_t len, uint32_t stall);

extern int
  fq_client_connect(fq_client conn);

extern void
  fq_client_publish(fq_client, fq_msg *msg);

extern int
  fq_client_data_backlog(fq_client conn);

extern int
  fq_rk_to_hex(char *buf, int len, fq_rk *k);

extern int
  fq_read_uint16(int fd, unsigned short *v);

extern int
  fq_write_uint16(int fd, unsigned short hs);

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
  fq_client_write_msg(int fd, int peermode, fq_msg *m, size_t off);

extern int
  fq_debug_fl(const char *file, int line, const char *fmt, ...)
  __printflike(3, 4);

#define fq_debug(...) fq_debug_fl(__FILE__, __LINE__, __VA_ARGS__)

#ifdef __MACH__
typedef uint64_t hrtime_t;
#endif
extern hrtime_t fq_gethrtime(void);
#endif
