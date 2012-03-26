#include <stdio.h>
#include <signal.h>
#include "fqd.h"

int main(int argc, char **argv) {
  fqd_config_init();
  signal(SIGPIPE, SIG_IGN);
  fqd_listener(NULL, 8765);
  return 0;
}
