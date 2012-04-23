#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include "fq.h"

void logger(const char *);

void logger(const char *s) {
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
int main(int argc, char **argv) {
  hrtime_t s0, s, f;
  uint64_t cnt = 0, icnt = 0, icnt_total = 0;
  int rcvd = 0;
  fq_client c;
  fq_bind_req breq;
  fq_msg *m;
  signal(SIGPIPE, SIG_IGN);
  fq_client_init(&c, 0, logger);
  if(argc < 5) {
    fprintf(stderr, "%s <host> <port> <user> <pass> [size [count]]\n",
            argv[0]);
    exit(-1);
  }
  fq_client_creds(c, argv[1], atoi(argv[2]), argv[3], argv[4]);
  fq_client_heartbeat(c, 1000);
  fq_client_set_backlog(c, 10000, 100);
  fq_client_connect(c);

  memset(&breq, 0, sizeof(breq));
  memcpy(breq.exchange.name, "maryland", 8);
  breq.exchange.len = 8;
  breq.peermode = 0;
  breq.program = (char *)"prefix:\"test.prefix.\"";

  fq_client_bind(c, &breq);
  while(breq.out__route_id == 0) usleep(100);
  printf("route set -> %u\n", breq.out__route_id);
  if(breq.out__route_id == FQ_BIND_ILLEGAL) {
    fprintf(stderr, "Failure to bind...\n");
    exit(-1);
  }

  s0 = s = fq_gethrtime();
  while(1) {
    f = fq_gethrtime();
    while(m = fq_client_receive(c)) {
      icnt++;
      icnt_total++;
      rcvd++;
      fq_msg_deref(m);
    }
    usleep(1000);
    if(f-s > 1000000000) {
      print_rate(c, s, f, cnt, icnt);
      printf("total: %llu\n", (unsigned long long)icnt_total);
      icnt = 0;
      cnt = 0;
      s = f;
    }
  }
  (void) argc;
  return 0;
}
