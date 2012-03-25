#include <stdio.h>
#include "fqd.h"

int main(int argc, char **argv) {
  fqd_config_init();
  fqd_listener(NULL, 8765);
  return 0;
}
