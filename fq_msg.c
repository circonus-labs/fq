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

static bool msg_free_list_inited = false;
static ck_hs_t msg_free_lists;
static pthread_mutex_t msg_free_list_mutex;

struct free_list {
  uint32_t size_bound;
  uint32_t fifo_len;
  ck_fifo_spsc_t fifo;
};

static inline unsigned long 
msg_free_list_hash_cb(const void* a, unsigned long seed) 
{
  return (unsigned long) a;
}

static inline  bool
msg_free_list_compare_cb(const void *c1, const void *c2) 
{
  const struct free_list *a = c1;
  const struct free_list *b = c2;

  return a->size_bound == b->size_bound;
}

static void *
malloc_wrapper(size_t s) {
  return malloc(s);
}

static void *
realloc_wrapper(void *o, size_t s, size_t x, bool b) {
  return realloc(o, s);
}

static void
free_wrapper(void *s, size_t size, bool b) {
  free(s);
}

struct ck_malloc hs_allocator = {
  .malloc = &malloc_wrapper,
  .realloc = &realloc_wrapper,
  .free = &free_wrapper
};

void 
fq_msg_init_free_list()
{
  if (!msg_free_list_inited) {
    ck_hs_init(&msg_free_lists, CK_HS_MODE_OBJECT | CK_HS_MODE_SPMC, msg_free_list_hash_cb,
             msg_free_list_compare_cb, &hs_allocator, 24, 23409238432L); /* randomly entered */
    pthread_mutex_init(&msg_free_list_mutex, NULL);
    msg_free_list_inited = true;
  }
}

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

static inline uint32_t 
next_power_of_2(uint32_t num)
{
  int count = 0;

  /* already a power of 2 */
  if (num != 0 && (num & (num-1)) == 0) {
    return num;
  }

  while (num != 0) {
    num >>= 1;
    count++;
  }
  return (1 << count);
}

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

/**
 * Will consult a hashset of fifos to grab the fifo that is next power of 2 larger
 * than the requested incoming size.  If we find one and that fifo has items in it, 
 * we blank out and return that fq_msg pointer.  If not we fall back on malloc.
 * 
 * The returned message payload_len is guaranteed to be at least `s` or larger.
 */
static fq_msg*
msg_allocate(const size_t s, bool zero) 
{
  fq_msg *m = NULL;
  uint32_t npot = next_power_of_2(s);
  /* always allocate to the next pow2 for each message so it fits neatly in a bucket */
  m = malloc(offsetof(fq_msg, payload) + npot);
  if(!m) return NULL;
  memset(m, 0, offsetof(fq_msg, payload));
  m->payload_len = s;
  if (zero) {
    memset(m->payload, 0, npot);
  }
  return m;
}

static void
msg_free(fq_msg *m)
{
  if (m->cleanup_stack != NULL) {
    ck_stack_push_mpmc(m->cleanup_stack, &m->cleanup_stack_entry);
  } else {
    free(m);
  }
}

fq_msg *
fq_msg_alloc(const void *data, size_t s) {
  fq_msg *m = msg_allocate(s, false);
  if(s) memcpy(m->payload, data, s);
#ifdef DEBUG
  fq_debug(FQ_DEBUG_MSG, "msg(%p) -> alloc\n", (void *)m);
#endif
  //m->arrival_time = fq_gethrtime();
  m->refcnt = 1;
  return m;
}

fq_msg *
fq_msg_alloc_BLANK(size_t s) {
  fq_msg *m = msg_allocate(s, true);
#ifdef DEBUG
  fq_debug(FQ_DEBUG_MSG, "msg(%p) -> alloc\n", (void *)m);
#endif
  //m->arrival_time = fq_gethrtime();
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
