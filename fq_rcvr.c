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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include "fq.h"

char *exchange = "maryland";
char *program = "prefix:\"\"";
int output = 1;

void logger(fq_client, const char *);

void logger(fq_client c, const char *s) {
  (void)c;
  fprintf(stderr, "fq_logger: %s\n", s);
}
static void
print_rate(fq_client c, hrtime_t s, hrtime_t f, uint64_t cnt, uint64_t icnt) {
  double d;
  if(cnt) {
    d = (double)cnt * 1000000000;
    d /= (double)(f-s);
    printf("[%d backlog] output %0.2f msg/sec\n",
           fq_client_data_backlog(c), d);
  }
  if(icnt) {
    d = (double)icnt * 1000000000;
    d /= (double)(f-s);
    printf("[%d backlog]  input %0.2f msg/sec\n",
           fq_client_data_backlog(c), d);
  }
}


static void
my_auth_handler(fq_client c, int error) {
  fq_bind_req *breq;
 
  if(error) return;

  printf("attempting bind\n"); 
  breq = malloc(sizeof(*breq));
  memset(breq, 0, sizeof(*breq));
  int exchange_len = strlen(exchange);
  memcpy(breq->exchange.name, exchange, exchange_len);
  breq->exchange.len = exchange_len;
  breq->flags = FQ_BIND_TRANS;
  breq->program = program;
  fq_client_bind(c, breq);
}

static void
my_bind_handler(fq_client c, fq_bind_req *breq) {
  (void)c;
  printf("route set -> %u\n", breq->out__route_id);
  if(breq->out__route_id == FQ_BIND_ILLEGAL) {
    fprintf(stderr, "Failure to bind...\n");
    exit(-1);
  }
}

fq_hooks hooks = {
 .version = FQ_HOOKS_V1,
 .auth = my_auth_handler,
 .bind = my_bind_handler
};

int main(int argc, char **argv) {
  hrtime_t s, f;
  uint64_t cnt = 0, icnt = 0, icnt_total = 0;
  int rcvd = 0;
  fq_client c;
  fq_msg *m;

  char *fq_debug = getenv("FQ_DEBUG");
  if(fq_debug) fq_debug_set_bits(atoi(fq_debug));
  signal(SIGPIPE, SIG_IGN);
  fq_client_init(&c, 0, logger);
  if(fq_client_hooks(c, &hooks)) {
    fprintf(stderr, "Can't register hooks\n");
    exit(-1);
  }

  char *host = "localhost";
  int port = 8765;
  char *user = "guest";
  char *pass = "guest";
  int o;
  while(-1 != (o = getopt(argc, argv, "h:p:u:P:e:b:s"))) {
    switch(o) {
    case 'h': host = strdup(optarg); break;
    case 'p': port = atoi(optarg); break;
    case 'u': user = strdup(optarg); break;
    case 'P': pass = strdup(optarg); break;
    case 'e': exchange = strdup(optarg); break;
    case 'b': program = strdup(optarg); break;
    case 's': output = 2; break;
    default:
     fprintf(stderr, "%s [-h host] [-p port] [-u user] [-P pass] [-e exchange] [-b program] [-s]\n",
            argv[0]);
     exit(-1);
     break;
    }
  }
  fq_client_hooks(c, &hooks);
  fq_client_creds(c, host, port, user, pass);
  fq_client_heartbeat(c, 1000);
  fq_client_set_backlog(c, 10000, 100);
  fq_client_connect(c);

  s = fq_gethrtime();
  while(1) {
    f = fq_gethrtime();
    while(NULL != (m = fq_client_receive(c))) {
      icnt++;
      icnt_total++;
      rcvd++;
      if(output == 1) {
        int ending = m->payload[m->payload_len-1] == '\n' ? 1 : 0;
        printf("[%.*s] %.*s\n", m->route.len, m->route.name, m->payload_len - ending, m->payload);
      }
      fq_msg_deref(m);
    }
    usleep(1000);
    if(f-s > 1000000000) {
      if(output == 2) {
        print_rate(c, s, f, cnt, icnt);
        printf("total: %llu\n", (unsigned long long)icnt_total);
      }
      icnt = 0;
      cnt = 0;
      s = f;
    }
  }
  (void) argc;
  return 0;
}
