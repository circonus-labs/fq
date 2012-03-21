#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "fq.h"

void logger(const char *s) {
  fprintf(stderr, "fq_logger: %s\n", s);
}
int main(int argc, char **argv) {
  fq_client c;
  fq_client_init(&c, logger);
  fq_client_creds(c, argv[1], atoi(argv[2]), argv[3], argv[4]);
  sleep(1);
  return 0;
}
