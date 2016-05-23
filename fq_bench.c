/*
 * Copyright (c) 2016 Circonus
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include "fq.h"

void logger(fq_client c, const char *s) {
  (void)c;
  fprintf(stderr, "fq_logger: %s\n", s);
}

static void
debug_status(char *key, uint32_t value, void *unused) {
  (void)unused;
  fq_debug(FQ_DEBUG_CONN, " ---> %s : %u\n", key, value);
}

static void
print_rate(fq_client c, hrtime_t s, hrtime_t f, uint64_t cnt, uint64_t icnt) {
  double d;
  fq_client_status(c, debug_status, NULL);
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

static void usage(const char *prog) {
  printf("%s:\n", prog);
  printf("\t-H\t\tthis help message\n");
  printf("\t-h\t\tthe fq host to connect to\n");
  printf("\t-p <port>\tspecify connecting port (default: 8765)\n");
  printf("\t-u <user>\tuser name\n");
  printf("\t-P <password>\tpassword\n");
  printf("\t-t <type>\t'disk' or 'mem' for type of queue to test\n");
  printf("\t-q <queue>\tname of queue to test (default: benchmark_queue)\n");
  printf("\t-c <count>\tnumber of messages to bench with\n");
  printf("\t-s <size>\tsize of each message\n");
}

static char *host = "localhost";
static int port = 8765;
static char *user = "user";
static char *exchange = "maryland";
static char *pass = "pass";
static char *type = "mem";
static char *queue_name = "benchmark_queue";
static int count = 100000;
static int size = 100;

static void parse_cli(int argc, char **argv) {
  int c;
  const char *debug = getenv("FQ_DEBUG");
  while((c = getopt(argc, argv, "Hh:p:u:P:t:q:e:c:s:")) != EOF) {
    switch(c) {
      case 'H':
        usage(argv[0]);
        exit(0);
      case 'h':
        host = strdup(optarg);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        user = strdup(optarg);
        break;
      case 'P':
        pass = strdup(optarg);
        break;
      case 't':
        type = strdup(optarg);
        break;
      case 'q':
        queue_name = strdup(optarg);
        break;
      case 'e':
        exchange = strdup(optarg);
        break;
      case 'c':
        count = atoi(optarg);
        break;
      case 's':
        size = atoi(optarg);
        break;
      default:
        usage(argv[0]);
        exit(-1);
    }
  }
  if(debug) fq_debug_set_string(debug);
}


/**
 * Benchmark a single thread against a type of queue at some host.
 */
int main(int argc, char **argv) {
  char queue[256] = {0};
  hrtime_t s0, s, f, f0;
  uint64_t cnt = 0, icnt = 0;
  int i = 0;
  fq_client c;
  fq_msg *m;
  char *fq_debug = getenv("FQ_DEBUG");
  if(fq_debug) fq_debug_set_bits(atoi(fq_debug));
  signal(SIGPIPE, SIG_IGN);
  fq_client_init(&c, 0, logger);

  parse_cli(argc, argv);

  sprintf(queue, "%s/%s/%s:public,drop,backlog=10000,permanent", user, queue_name, type);

  printf("using queue -> %s\n", queue); 

  fq_client_creds(c, host, port, queue, pass);
  fq_client_heartbeat(c, 1000);
  fq_client_set_backlog(c, 10000, 100);
  fq_client_connect(c);

  printf("payload size -> %d\n", size);
  printf("message count -> %d\n", count);

  s0 = s = fq_gethrtime();
  f = s;

  m = fq_msg_alloc_BLANK(size);
  memset(m->payload, 'X', size);
  fq_msg_exchange(m, exchange, strlen(exchange));
  fq_msg_route(m, "test.bench.foo", 14);

  while(i < count || fq_client_data_backlog(c) > 0) {
    if(i < count) {
      m->arrival_time = fq_gethrtime();
      fq_msg_id(m, NULL);
      fq_client_publish(c, m);
      cnt++;
      i++;
    }
    else usleep(10);

    if (i % 1000 == 0) {
      f = fq_gethrtime();
    }

    if(f-s > 1000000000) {
      print_rate(c, s, f, cnt, icnt);
      icnt = 0;
      cnt = 0;
      s = f;
    }
  }
  f0 = fq_gethrtime();
  print_rate(c, s0, f0, i, 0);
  return 0;
}
