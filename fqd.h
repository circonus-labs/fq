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

#ifndef FQD_H
#define FQD_H

#ifndef _REENTRANT
#error "You must compile with -D_REENTRANT"
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/time.h>
#include <netinet/in.h>

#define FQ_VERSION_MAJOR 0
#define FQ_VERSION_MINOR 8
#define FQ_VERSION_PATCH 2
#define FQ_VERSION "0.8.2"

#include "fq.h"

#ifndef VARLIBFQDIR
#define VARLIBFQDIR "/var/lib/fq"
#endif

typedef void * fqd_queue_impl_data;

typedef struct fqd_queue_impl {
  const char *name;
  fqd_queue_impl_data (*setup)(fq_rk *, uint32_t *count);
  void (*enqueue)(fqd_queue_impl_data, fq_msg *);
  fq_msg *(*dequeue)(fqd_queue_impl_data);
  void (*dispose)(fq_rk *, fqd_queue_impl_data);
} fqd_queue_impl;

/* implememted in fqd_queue_mem.c */
extern fqd_queue_impl fqd_queue_mem_impl;
/* implememted in fqd_queue_jlog.c */
extern fqd_queue_impl fqd_queue_jlog_impl;

typedef struct fqd_queue fqd_queue;
typedef struct fqd_route_rules fqd_route_rules;
typedef struct fqd_route_rule fqd_route_rule;
typedef struct fqd_config fqd_config;

typedef struct fqd_exchange_stats {
  uint64_t n_messages;
  uint64_t n_bytes;
  uint64_t n_routed;
  uint64_t n_no_route;
  uint64_t n_dropped;
  uint64_t n_no_exchange;
  uint64_t n_loops;
} fqd_exchange_stats_t;

typedef struct fqd_exchange {
  fq_rk exchange;
  fqd_exchange_stats_t *stats;
  fqd_route_rules *set;
} fqd_exchange;

extern int fqd_queue_write_json(int fd, fqd_queue *q);
extern int fqd_queue_sprint(char *buf, int len, fqd_queue *q);
extern void fqd_queue_ref(fqd_queue *);
extern void fqd_queue_deref(fqd_queue *);
extern int fqd_queue_cmp(const fqd_queue *, const fqd_queue *);
extern int fqd_config_make_perm_queue(fqd_queue *q);
extern int fqd_config_make_trans_queue(fqd_queue *q);
extern int fqd_config_make_perm_binding(fq_rk *exchange, fqd_queue *q,
                                        int peermode, const char *program);
extern int fqd_config_make_trans_binding(fq_rk *exchange, fqd_queue *q,
                                         int peermode, const char *program);

#define CLIENT_SHARED \
  uint32_t refcnt; \
  int fd; \
  struct timeval connect_time; \
  struct sockaddr_in remote; \
  hrtime_t last_activity; \
  hrtime_t last_heartbeat; \
  char  pretty[80];

typedef struct {
  CLIENT_SHARED
} remote_anon_client;

typedef struct {
  CLIENT_SHARED
  uint32_t mode;
  uint32_t peer_id;
  uint32_t no_exchange;
  uint32_t no_route;
  uint32_t routed;
  uint32_t dropped;
  uint32_t msgs_in;
  uint32_t msgs_out;
  uint32_t octets_in;
  uint32_t octets_out;
} remote_data_client;

typedef struct remote_client {
  CLIENT_SHARED

  fq_rk user;
  fq_rk key;
  fqd_queue *queue;
  remote_data_client *data;
  unsigned short heartbeat_ms;
} remote_client;

/* You can read around in this... but can't modify it */
extern void fqd_config_init(uint32_t, const char *config_path,
                            const char *queue_path);
extern int fqd_config_construct_queue_path(char *, size_t, fq_rk *);
extern uint32_t fqd_config_get_nodeid(void);
extern fqd_config *fqd_config_get(void);
extern void fqd_config_release(fqd_config *);
extern int fqd_config_register_client(remote_client *, uint64_t *gen);
extern int fqd_config_deregister_client(remote_client *, uint64_t *gen);
extern fqd_queue *fqd_config_register_queue(fqd_queue *, uint64_t *gen);
extern int fqd_config_deregister_queue(fqd_queue *, uint64_t *gen);
extern fqd_queue *fqd_config_get_registered_queue(fqd_config *, fq_rk *);
extern remote_client *fqd_config_get_registered_client(fqd_config *, fq_rk *key);
extern fqd_exchange *fqd_config_get_exchange(fqd_config *c, fq_rk *exchange);

extern void fqd_exchange_messages(fqd_exchange *, uint64_t);
extern void fqd_exchange_message_octets(fqd_exchange *, uint64_t);
extern void fqd_exchange_no_route(fqd_exchange *, uint64_t);
extern void fqd_exchange_routed(fqd_exchange *, uint64_t);
extern void fqd_exchange_dropped(fqd_exchange *, uint64_t);
extern void fqd_exchange_no_exchange(fqd_exchange *, uint64_t);

extern uint32_t fqd_config_bind(fq_rk *exchange, uint16_t flags,
                                const char *program,
                                fqd_queue *q, uint64_t *gen);
extern int fqd_config_unbind(fq_rk *exchange, uint32_t route_id,
                             fqd_queue *q, uint64_t *gen);
extern void fqd_config_wait(uint64_t gen, int us);
extern void fqd_config_http_stats(remote_client *client);

extern void fqd_command_and_control_server(remote_client *);
extern void fqd_data_subscription_server(remote_data_client *);

extern int fqd_listener(const char *ip, unsigned short port);
extern void fqd_remote_client_ref(remote_client *);
extern void fqd_remote_client_deref(remote_client *);

extern fq_rk *fqd_queue_name(fqd_queue *q);
extern fqd_queue *fqd_queue_get(fq_rk *, const char *, const char *,
                                int, char *);
extern uint32_t fqd_queue_get_backlog_limit(fqd_queue *);
extern void fqd_queue_set_backlog_limit(fqd_queue *, uint32_t);
extern queue_policy_t fqd_queue_get_policy(fqd_queue *);
extern void fqd_queue_set_policy(fqd_queue *, queue_policy_t);
extern void fqd_queue_enqueue(fqd_queue *q, fq_msg *m, int *dropped);
extern fq_msg *fqd_queue_dequeue(fqd_queue *q);
extern int fqd_queue_register_client(fqd_queue *q, remote_client *c);
extern bool fqd_queue_deregister_client(fqd_queue *q, remote_client *c);

extern void fqd_inject_message(remote_data_client *c, fq_msg *m);
extern struct fqd_route_rule *
  fqd_routemgr_compile(const char *program, int peermode, fqd_queue *q);
extern void fqd_routemgr_rule_free(fqd_route_rule *rule);
extern fqd_route_rules *fqd_routemgr_ruleset_alloc(void);
extern uint32_t fqd_routemgr_ruleset_add_rule(fqd_route_rules *set,
                                          fqd_route_rule *r, int *isnew);
extern int
  fqd_routemgr_drop_rules_by_route_id(fqd_route_rules *set, fqd_queue *q,
                                      uint32_t route_id);
extern int
  fqd_routemgr_perm_route_id(fqd_route_rules *set, uint32_t route_id);
extern int
  fqd_routemgr_trans_route_id(fqd_route_rules *set, uint32_t route_id);
extern void
  fqd_routemgr_drop_rules_by_queue(fqd_route_rules *set, fqd_queue *q);
extern fqd_route_rules *fqd_routemgr_ruleset_copy(fqd_route_rules *set);
extern void fqd_routemgr_ruleset_free(fqd_route_rules *set);

extern int
  fqd_add_peer(uint64_t gen,
               const char *host, int port,
               const char *user, const char *pass,
               fq_rk *exchange, const char *prog,
               bool perm);

extern int
  fqd_remove_peers(uint64_t current_gen);

extern int
  fqd_remove_peer(const char *host, int port,
                  const char *user, const char *pass,
                  fq_rk *exchange, const char *prog);

#define ERRTOFD(fd, error) do { \
  (void)fq_write_uint16(fd, htons(FQ_PROTO_ERROR)); \
  (void)fq_write_short_cmd(fd, strlen(error), error); \
} while(0)

/* programming:
 *
 *  PROGRAM: <prefix|exact>:string RULES*
 *  RULE: (RULE)
 *  RULE: (RULE && RULE)
 *  RULE: (RULE || RULE)
 *  RULE: EXPR
 *  EXPR: function(args)
 *  args: arg
 *  args: arg, args
 *  arg: "string"
 *  arg: true|false
 *  arg: [0-9][0-9]*(?:.[0-9]*)
 *
 *  functions are dynamically loadable with type signature
 *  strings: s, booleans: b, integers: d
 *  function: substr_eq(9.3,10,"tailorings",true)
 *  C symbol: fqd_route_prog__substr_eq__ddsb(int nargs, valnode_t *args);
 */

typedef struct valnode {
  enum {
    RP_VALUE_STRING = 1,
    RP_VALUE_BOOLEAN = 2,
    RP_VALUE_DOUBLE = 3
  } value_type;
  union {
    char  *s;
    bool   b;
    double d;
  } value;
} valnode_t;

#define MAX_VALNODE_ARGS 16

typedef struct exprnode {
  bool     (*match)(fq_msg *m, int nargs, valnode_t *args);
  int        nargs;
  valnode_t *args;
} exprnode_t;

typedef struct rulenode {
  uint32_t refcnt;
  char   oper;
  struct rulenode *left;
  struct rulenode *right;
  struct exprnode *expr;
} rulenode_t;

/* DTrace helpers */
typedef struct {
  int fd;
  char *pretty;
} fq_dtrace_remote_anon_client_t;

typedef struct {
  int fd;
  char *pretty;
  char *user;
} fq_dtrace_remote_client_t;

typedef struct {
  int fd;
  char *pretty;
  uint32_t mode;
  uint32_t no_exchange;
  uint32_t no_route;
  uint32_t routed;
  uint32_t dropped;
  uint32_t msgs_in;
  uint32_t msgs_out;
} fq_dtrace_remote_data_client_t;

#define DTRACE_PACK_ANON_CLIENT(dc, c) do { \
  (dc)->fd = (int32_t)(c)->fd; \
  (dc)->pretty = (c)->pretty; \
} while(0)

#define DTRACE_PACK_CLIENT(dc, c) do { \
  (dc)->fd = (int32_t)(c)->fd; \
  (dc)->pretty = (c)->pretty; \
  (dc)->user = (char *)(c)->user.name; \
} while(0)

#define DTRACE_PACK_DATA_CLIENT(dc, c) do { \
  (dc)->fd = (int32_t)(c)->fd; \
  (dc)->pretty = (c)->pretty; \
  (dc)->mode = (c)->mode; \
  (dc)->no_exchange = (c)->no_exchange; \
  (dc)->no_route = (c)->no_route; \
  (dc)->routed = (c)->routed; \
  (dc)->dropped = (c)->dropped; \
  (dc)->msgs_in = (c)->msgs_in; \
  (dc)->msgs_out = (c)->msgs_out; \
} while(0)

typedef struct {
  char   *name;
  int32_t private;
  int32_t policy;
  char   *type;
} fq_dtrace_queue_t;

void fqd_queue_dtrace_pack(fq_dtrace_queue_t *, fqd_queue *);

void fqd_http_loop(remote_client *c, uint32_t bytes_four);

void fqd_http_set_root(const char *newpath);

#define DTRACE_PACK_QUEUE(dq, c) fqd_queue_dtrace_pack(dq, c)

#endif
