#ifndef FQD_H
#define FQD_H

#include <stdint.h>
#include <sys/time.h>
#include <netinet/in.h>

#ifdef __MACH__
typedef uint64_t hrtime_t;
extern hrtime_t gethrtime(void);
#endif

typedef struct fqd_config fqd_config;

typedef struct remote_client {
  uint32_t refcnt;
  struct timeval connect_time;
  int fd;
  struct sockaddr_in remote;
} remote_client;

extern void fqd_config_init(void);
extern fqd_config *fqd_config_get(void);
extern void fqd_config_release(fqd_config *);
extern int fqd_config_register_client(remote_client *);
extern int fqd_config_deregister_client(remote_client *);

extern void fqd_command_and_control_server(remote_client *);
extern void fqd_data_subscription_server(remote_client *);

extern int fqd_listener(const char *ip, unsigned short port);
extern void fqd_remote_client_ref(remote_client *);
extern void fqd_remote_client_deref(remote_client *);

#endif
