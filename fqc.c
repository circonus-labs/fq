#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include "fq.h"

void logger(const char *);

void logger(const char *s) {
  fprintf(stderr, "fq_logger: %s\n", s);
}
int main(int argc, char **argv) {
  fq_client c;
  fq_msg *m;
  signal(SIGPIPE, SIG_IGN);
  fq_client_init(&c, logger);
  fq_client_creds(c, argv[1], atoi(argv[2]), argv[3], argv[4]);
  fq_client_heartbeat(c, 250);
  fq_client_connect(c);

  m = fq_msg_alloc("Hello", 5);
  fq_msg_route(m, "check.9", 7);
  fq_msg_id(m, NULL);
  fq_client_publish(c, m);
  fq_msg_free(m);
  fprintf(stderr, "publish ->");

  pause();
  (void) argc;
  return 0;
}
