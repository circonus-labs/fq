#ifndef FQD_H
#define FQD_H

#include <stdint.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "fq.h"

typedef void * fqd_queue_impl_data;

typedef struct fqd_queue_impl {
  int (*enqueue)(fqd_queue_impl_data, fq_msg *); /* cannot block */
  fq_msg *(*dequeue)(fqd_queue_impl_data);       /* can block */
  void (*dispose)(fqd_queue_impl_data);
} fqd_queue_impl;

typedef struct fqd_queue fqd_queue;

extern void fqd_queue_ref(fqd_queue *);
extern void fqd_queue_deref(fqd_queue *);
extern int fqd_queue_cmp(const fqd_queue *, const fqd_queue *);

typedef struct fqd_config fqd_config;

typedef struct remote_client {
  uint32_t refcnt;
  int fd;
  struct timeval connect_time;
  struct sockaddr_in remote;
  unsigned short heartbeat_ms;
  fq_rk user;
  fq_rk key;
  char  pretty[80];
  fqd_queue *queue;
} remote_client;

/* You can read around in this... but can't modify it */
struct fqd_config {
  int n_clients;
  remote_client **clients;
  int n_queues;
  fqd_queue **queues;
};

extern void fqd_config_init(void);
extern fqd_config *fqd_config_get(void);
extern void fqd_config_release(fqd_config *);
extern int fqd_config_register_client(remote_client *);
extern int fqd_config_deregister_client(remote_client *);
extern fqd_queue *fqd_config_register_queue(fqd_queue *);
extern int fqd_config_deregister_queue(fqd_queue *);
extern fqd_queue *fqd_config_get_registered_queue(fqd_config *, fq_rk *);

extern void fqd_command_and_control_server(remote_client *);
extern void fqd_data_subscription_server(remote_client *);

extern int fqd_listener(const char *ip, unsigned short port);
extern void fqd_remote_client_ref(remote_client *);
extern void fqd_remote_client_deref(remote_client *);

extern fqd_queue *fqd_queue_get(fq_rk *);
extern int fqd_queue_register_client(fqd_queue *q, remote_client *c);
extern int fqd_queue_deregister_client(fqd_queue *q, remote_client *c);

#define ERRTOFD(fd, error) do { \
  (void)fq_write_uint16(fd, htons(FQ_PROTO_ERROR)); \
  (void)fq_write_short_cmd(fd, strlen(error), error); \
} while(0)

#endif
