#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include "fqd.h"

static void *listener_thread(void *unused) {
  (void)unused;
  fqd_listener(NULL, 8765);
  return NULL;
}
int main(int argc, char **argv) {
  pthread_t tid;
  char buff[128];
  fqd_config_init();
  signal(SIGPIPE, SIG_IGN);
  pthread_create(&tid, NULL, listener_thread, NULL);
  fgets(buff, sizeof(buff), stdin);
  return 0;
}
