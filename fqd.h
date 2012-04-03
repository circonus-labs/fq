#ifndef FQD_H
#define FQD_H

#ifndef _REENTRANT
#error "You must compile with -D_REENTRANT
#endif

#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "fq.h"

typedef void * fqd_queue_impl_data;

typedef struct fqd_queue_impl {
  fqd_queue_impl_data (*setup)(fq_rk *);
  void (*enqueue)(fqd_queue_impl_data, fq_msg *);
  fq_msg *(*dequeue)(fqd_queue_impl_data);
  void (*dispose)(fqd_queue_impl_data);
} fqd_queue_impl;

/* implememted in fqd_queue_mem.c */
extern fqd_queue_impl fqd_queue_mem_impl;

typedef struct fqd_queue fqd_queue;

extern void fqd_queue_ref(fqd_queue *);
extern void fqd_queue_deref(fqd_queue *);
extern int fqd_queue_cmp(const fqd_queue *, const fqd_queue *);

typedef struct fqd_config fqd_config;

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
} remote_data_client;

typedef struct remote_client {
  CLIENT_SHARED

  unsigned short heartbeat_ms;
  fq_rk user;
  fq_rk key;
  fqd_queue *queue;
  remote_data_client *data;
} remote_client;

typedef struct fqd_route_rules fqd_route_rules;
typedef struct fqd_route_rule fqd_route_rule;

/* You can read around in this... but can't modify it */
extern void fqd_config_init(uint32_t);
extern uint32_t fqd_config_get_nodeid(void);
extern fqd_config *fqd_config_get(void);
extern void fqd_config_release(fqd_config *);
extern int fqd_config_register_client(remote_client *, u_int64_t *gen);
extern int fqd_config_deregister_client(remote_client *, u_int64_t *gen);
extern fqd_queue *fqd_config_register_queue(fqd_queue *, u_int64_t *gen);
extern int fqd_config_deregister_queue(fqd_queue *, u_int64_t *gen);
extern fqd_queue *fqd_config_get_registered_queue(fqd_config *, fq_rk *);
extern remote_client *fqd_config_get_registered_client(fqd_config *, fq_rk *key);
extern void fqd_config_wait(u_int64_t gen, int us);

extern void fqd_command_and_control_server(remote_client *);
extern void fqd_data_subscription_server(remote_data_client *);

extern int fqd_listener(const char *ip, unsigned short port);
extern void fqd_remote_client_ref(remote_client *);
extern void fqd_remote_client_deref(remote_client *);

extern fq_rk *fqd_queue_name(fqd_queue *q);
extern fqd_queue *fqd_queue_get(fq_rk *);
extern int fqd_queue_register_client(fqd_queue *q, remote_client *c);
extern int fqd_queue_deregister_client(fqd_queue *q, remote_client *c);

extern void fqd_inject_message(remote_client *c, fq_msg *m);
extern fqd_route_rules *fqd_routemgr_ruleset_alloc(void);
extern void fqd_routemgr_rulesset_add_rule(fqd_route_rules *set,
                                           fqd_route_rule *r);
extern fqd_route_rules *fqd_routemgr_ruleset_copy(fqd_route_rules *set);
extern void fqd_routemgr_ruleset_free(fqd_route_rules *set);

#define ERRTOFD(fd, error) do { \
  (void)fq_write_uint16(fd, htons(FQ_PROTO_ERROR)); \
  (void)fq_write_short_cmd(fd, strlen(error), error); \
} while(0)

#endif
