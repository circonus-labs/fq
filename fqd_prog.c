/*
 * Copyright (c) 2013 OmniTI Computer Consulting, Inc.
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "fqd.h"

bool fqd_route_prog__true__(fq_msg *, int, valnode_t *);
bool fqd_route_prog__sample__d(fq_msg *, int, valnode_t *);
bool fqd_route_prog__route_contains__s(fq_msg *, int, valnode_t *);
bool fqd_route_prog__payload_prefix__s(fq_msg *, int, valnode_t *);


bool fqd_route_prog__true__(fq_msg *m, int nargs, valnode_t *args) {
  fq_assert(nargs == 0);
  (void)m;
  (void)nargs;
  (void)args;
  return true;
}

bool
fqd_route_prog__sample__d(fq_msg *m, int nargs, valnode_t *args) {
  (void)m;
  fq_assert(nargs == 1);
  fq_assert(args[0].value_type == RP_VALUE_DOUBLE);
  if(drand48() < args[0].value.d) return true;
  return false;
}

bool
fqd_route_prog__route_contains__s(fq_msg *m, int nargs, valnode_t *args) {
  int flen, i;
  fq_assert(nargs == 1);
  fq_assert(args[0].value_type == RP_VALUE_STRING);
  flen = strlen(args[0].value.s);
  if(flen > m->route.len) return false;
  for(i=0;i<=m->route.len - flen;i++)
    if(memcmp(args[0].value.s, m->route.name+i, flen) == 0)
      return true;
  return false;
}

bool
fqd_route_prog__payload_prefix__s(fq_msg *m, int nargs, valnode_t *args) {
  uint32_t flen;
  fq_assert(nargs == 1);
  fq_assert(args[0].value_type == RP_VALUE_STRING);
  flen = strlen(args[0].value.s);
  if(flen > m->payload_len) return false;
  if(memcmp(args[0].value.s, m->payload, flen) == 0)
    return true;
  return false;
}
