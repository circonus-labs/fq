#ifndef FQ_H
#define FQ_H

#include <stdint.h>
#include <ck_ring.h>

#define MAX_RK_LEN 127
typedef struct fq_rk {
  uint8_t        len;
  unsigned char  name[MAX_RK_LEN];
} fq_rk;

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

typedef struct fq_msg {
  fq_rk          route;
  fq_rk          sender;
  fq_msgid       sender_msgid;
  uint32_t       ref_cnt;
  ssize_t        payload_len;
  unsigned char  payload[1];  /* over allocated */
} fq_msg;

#define fq_msg_alloc(s) malloc(offsetof(fq_msg, payload) + (a))
#define fq_msg_free(msg) free(msg)

typedef struct fq_sub {
  fq_rk          sub;
  ck_ring_t      queue;
} fq_sub;

/* frame */
#define MAX_HOPS 32
/*
 *    1 x uint8_t<net>   hops
 * hops x uint32_t<net>  node
 *    1 x fq_rk          sender
 *    1 x fq_rk          route
 *    1 x uint32_t<net>  payload_len
 *    1 x data
 */
typedef struct fq_conn_s *fq_client;

extern int
  fq_client_init(fq_client *, void (*)(const char *));

extern int
  fq_client_creds(fq_client,
                  const char *host, unsigned short port,
                  const char *source, const char *pass);

#endif
