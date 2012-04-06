#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include "fq.h"
#include "ck_pr.h"

static fq_msgid local_msgid = {
  .id = {
    .u32 = {
      .p1 = 0,
      .p2 = 0,
      .p3 = 0,
      .p4 = 0
    }
  }
};

static void
pull_next_local_msgid(fq_msgid *msgid) {
  uint32_t last;
  fq_msgid g;
again:
  memcpy(&g, &local_msgid, sizeof(fq_msgid));
  last = ck_pr_faa_32(&local_msgid.id.u32.p1, 1);
  msgid->id.u32.p1 = last + 1;
  if(last == 0xffffffffUL) {
    last = ck_pr_faa_32(&local_msgid.id.u32.p2, 1);
    msgid->id.u32.p2 = last + 1;
    if(last == 0xffffffffUL) {
      last = ck_pr_faa_32(&local_msgid.id.u32.p3, 1);
      msgid->id.u32.p3 = last + 1;
      if(last == 0xffffffffUL) {
        last = ck_pr_faa_32(&local_msgid.id.u32.p4, 1);
        msgid->id.u32.p4 = last + 1;
      }
    }
  }
  if(msgid->id.u32.p4 < g.id.u32.p4) goto again;
  if(msgid->id.u32.p4 > g.id.u32.p4) return;
  if(msgid->id.u32.p3 < g.id.u32.p3) goto again;
  if(msgid->id.u32.p3 > g.id.u32.p3) return;
  if(msgid->id.u32.p2 < g.id.u32.p2) goto again;
  if(msgid->id.u32.p2 > g.id.u32.p2) return;
  if(msgid->id.u32.p1 > g.id.u32.p1) return;
  goto again;
}

fq_msg *
fq_msg_alloc(const void *data, size_t s) {
  fq_msg *m;
  m = malloc(offsetof(fq_msg, payload) + (s));
  if(!m) return NULL;
  m->payload_len = s;
  memset(m, 0, offsetof(fq_msg, payload));
  if(s) memcpy(m->payload, data, s);
#ifdef DEBUG
    fq_debug("msg(%p) -> alloc\n", (void *)m);
#endif
  m->refcnt = 1;
  return m;
}
fq_msg *
fq_msg_alloc_BLANK(size_t s) {
  fq_msg *m;
  m = calloc(offsetof(fq_msg, payload) + (s), 1);
  if(!m) return NULL;
  m->payload_len = s;
#ifdef DEBUG
    fq_debug("msg(%p) -> alloc\n", (void *)m);
#endif
  m->refcnt = 1;
  return m;
}
void
fq_msg_ref(fq_msg *msg) {
  ck_pr_inc_uint(&msg->refcnt);
}
void
fq_msg_deref(fq_msg *msg) {
  bool zero;

  ck_pr_dec_uint_zero(&msg->refcnt, &zero);
  if(zero) {
#ifdef DEBUG
    fq_debug("msg(%p) -> free\n", (void *)msg);
#endif
    free(msg);
  }
}
void
fq_msg_exchange(fq_msg *msg, const void *exchange, int rlen) {
  if(rlen <= 0) {
    msg->exchange.len = 0;
    return;
  }
  if(rlen > MAX_RK_LEN) rlen = MAX_RK_LEN;
  msg->exchange.len = rlen;
  memcpy(msg->exchange.name, exchange, rlen);
}
void
fq_msg_route(fq_msg *msg, const void *route, int rlen) {
  if(rlen <= 0) {
    msg->route.len = 0;
    return;
  }
  if(rlen > MAX_RK_LEN) rlen = MAX_RK_LEN;
  msg->route.len = rlen;
  memcpy(msg->route.name, route, rlen);
}
void
fq_msg_id(fq_msg *msg, fq_msgid *id) {
  if(!id) pull_next_local_msgid(&msg->sender_msgid);
  else memcpy(&msg->sender_msgid, id, sizeof(*id));
}
