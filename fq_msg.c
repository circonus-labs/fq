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

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include "fq.h"
#include "ck_pr.h"
#include "ck_malloc.h"
#include "ck_hs.h"
#include "ck_fifo.h"

#define MSG_ALIGN sizeof(void *)
#define MAX_FREE_LIST_SIZE 1000000

#define unlikely(x)    __builtin_expect(!!(x), 0)

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
  memcpy(msgid, &g, sizeof(fq_msgid));
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

static inline fq_msg*
msg_allocate(const size_t s, bool zero) 
{
  fq_msg *m = calloc(1, offsetof(fq_msg, payload) + s);
  if(!m) return NULL;
  m->payload_len = s;
  return m;
}

static inline void
msg_free(fq_msg *m)
{
  if (m->free_fn != NULL) {
    m->free_fn(m);
  } else {
    free(m);
  }
}

fq_msg *
fq_msg_alloc(const void *data, size_t s) {
  fq_msg *m = msg_allocate(s, false);
  if (unlikely(m == NULL)) {
    return NULL;
  }
  if(s) memcpy(m->payload, data, s);
#ifdef DEBUG
  fq_debug(FQ_DEBUG_MSG, "msg(%p) -> alloc\n", (void *)m);
#endif
  m->arrival_time = fq_gethrtime();
  m->refcnt = 1;
  return m;
}

fq_msg *
fq_msg_alloc_BLANK(size_t s) {
  fq_msg *m = msg_allocate(s, true);
  if (unlikely(m == NULL)) {
    return NULL;
  }
#ifdef DEBUG
  fq_debug(FQ_DEBUG_MSG, "msg(%p) -> alloc\n", (void *)m);
#endif
  m->arrival_time = fq_gethrtime();
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
    fq_debug(FQ_DEBUG_MSG, "msg(%p) -> free\n", (void *)msg);
#endif
    msg_free(msg);
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
