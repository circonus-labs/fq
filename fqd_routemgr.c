#include "fqd.h"

void
fqd_inject_message(remote_client *c, fq_msg *m) {
  fq_msg_deref(m);
}


