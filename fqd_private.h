/*
 * Copyright (c) 2013 Circonus, Inc.
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

#ifndef FQD_PRIVATE_H
#define FQD_PRIVATE_H

#include "fq.h"

#define MAX_QUEUE_CLIENTS 16

struct fqd_route_stats {
  /* These are just estimates */
  uint64_t invocations;
  uint32_t avg_ns;
  uint32_t refcnt;
};
struct fqd_route_rule {
  fq_rk prefix;
  int match_maxlen;
  char *program;
  rulenode_t *compiled_program;
  uint32_t route_id;
  bool permanent;
  int peermode;
  fqd_queue *queue;
  struct fqd_route_stats *stats;
  struct fqd_route_rule *next;
};

struct prefix_jumptable {
  enum { JUMPTABLE, RULETABLE } tabletype;
  struct fqd_route_rule *rules;
  struct {
    uint64_t pattern;
    uint64_t checkbits;
    struct prefix_jumptable *jt;
  } *pats;
  int pat_len;
};

struct fqd_route_rules {
  struct prefix_jumptable master;
};

struct fqd_queue {
  fq_rk               name;
  bool                permanent;
  bool                private;
  remote_client      *downstream[MAX_QUEUE_CLIENTS];
  /* referenced by: routes and connections */
  queue_policy_t      policy;
  uint32_t            backlog_limit;
  uint32_t            backlog;

  /* These are only use for FQ_POLICY_BLOCK */
  pthread_cond_t      cv;
  pthread_mutex_t     lock;

  uint32_t            refcnt;
  fqd_queue_impl      *impl;
  fqd_queue_impl_data *impl_data;
};

extern int
  for_each_route_rule_do(struct fqd_route_rules *set,
                         int (*f)(struct fqd_route_rule *, int, void *),
                         void *closure);

void fqd_start_worker_threads(int thread_count);
void fqd_stop_worker_threads(void);

#endif
