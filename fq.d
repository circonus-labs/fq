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

typedef struct {
  uintptr_t  route;
  uintptr_t  sender;
  uintptr_t  exchange;
  uintptr_t  payload;
  uint32_t   payload_len;
} fq_dtrace_msg_t;

typedef struct {
  string    route;
  string    exchange;
  string    sender;
  string    payload;
  uint32_t  payload_len;
} fq_msg_t;

translator fq_msg_t <fq_dtrace_msg_t *m> {
  route = copyinstr(*(uintptr_t *)copyin((uintptr_t)&m->route, sizeof(uintptr_t)));
  exchange = copyinstr(*(uintptr_t *)copyin((uintptr_t)&m->exchange, sizeof(uintptr_t)));
  sender = copyinstr(*(uintptr_t *)copyin((uintptr_t)&m->sender, sizeof(uintptr_t)));
  payload_len = *(uint32_t *)copyin((uintptr_t)&m->payload_len, sizeof(uint32_t));
  payload = copyinstr(*(uintptr_t *)copyin((uintptr_t)&m->payload, sizeof(uintptr_t)), *(uint32_t *)copyin((uintptr_t)&m->payload_len, sizeof(uint32_t)));
};

typedef struct {
  uintptr_t  name;
  int32_t    isprivate;
  int32_t    policy;
  uintptr_t  type;
} fq_dtrace_queue_t;

typedef struct {
  string     name;
  int32_t    isprivate;
  int32_t    policy;
  string     type;
} fq_queue_t;

translator fq_queue_t <fq_dtrace_queue_t *m> {
  name = copyinstr(*(uintptr_t *)copyin((uintptr_t)&m->name, sizeof(uintptr_t)));
  type = copyinstr(*(uintptr_t *)copyin((uintptr_t)&m->type, sizeof(uintptr_t)));
  isprivate = *(uint32_t *)copyin((uintptr_t)&m->isprivate, sizeof(int32_t));
  policy = *(uint32_t *)copyin((uintptr_t)&m->policy, sizeof(int32_t));
};

typedef struct {
  int32_t   fd;
  uintptr_t pretty;
} fq_dtrace_remote_anon_client_t;

typedef struct {
  int32_t  fd;
  string pretty;
} fq_remote_anon_client_t;

typedef struct {
  int32_t   fd;
  uintptr_t pretty;
} fq_dtrace_remote_client_t;

typedef struct {
  int32_t  fd;
  string pretty;
} fq_remote_client_t;

typedef struct {
  int32_t   fd;
  uintptr_t pretty;
} fq_dtrace_remote_data_client_t;

typedef struct {
  int32_t  fd;
  string pretty;
} fq_remote_data_client_t;

translator fq_remote_anon_client_t <fq_dtrace_remote_anon_client_t *c> {
  fd = *(uint32_t *)copyin((uintptr_t)&c->fd, sizeof(int32_t));
  pretty = copyinstr(*(uintptr_t *)copyin((uintptr_t)&c->pretty, sizeof(uintptr_t)));
};

