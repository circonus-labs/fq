#include <assert.h>
#include "fqd.h"

bool fqd_route_prog__true__(fq_msg *, int, valnode_t *);
bool fqd_route_prog__sample__d(fq_msg *, int, valnode_t *);



bool fqd_route_prog__true__(fq_msg *m, int nargs, valnode_t *args) {
  assert(nargs == 0);
  (void)m;
  (void)nargs;
  (void)args;
  return true;
}

bool
fqd_route_prog__sample__d(fq_msg *m, int nargs, valnode_t *args) {
  (void)m;
  assert(nargs == 1);
  assert(args[0].value_type == RP_VALUE_DOUBLE);
  if(drand48() < args[0].value.d) return true;
  return false;
}
