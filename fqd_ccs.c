#include "fqd.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

extern void
fqd_command_and_control_server(remote_client *client) {
  /* auth */
  if(fqd_config_register_client(client)) {
#ifdef DEBUG
    fprintf(stderr, "client registration failed\n");
#endif
    return;
  }
  fqd_config_deregister_client(client);
}
