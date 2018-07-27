/*
 * fqs
 *
 * Usage:
 *
 *     fqs <host> <port> <user> <pass> <exchange> <route>
 *
 * fqs reads messages from stdin, one pre line, and sends it to the specified fq exchange.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include "fq.h"

void logger(fq_client c, const char *s) {
  fprintf(stderr, "fq_logger: %s\n", s);
}

int main(int argc, char **argv) {
  fq_client c;
  fq_msg *m;
  char *exchange, *route;
  size_t exchange_len, route_len;
  signal(SIGPIPE, SIG_IGN);  // ignore SIGPIPE
  fq_client_init(&c, 0, logger);
  if(argc < 7) {
    fprintf(stderr, "%s <host> <port> <user> <pass> <exchange> <route>\n",
            argv[0]);
    exit(-1);
  }
  fq_client_creds(c, argv[1], atoi(argv[2]), argv[3], argv[4]);
  fq_client_heartbeat(c, 1000);
  fq_client_set_backlog(c, 10000, 100);
  fq_client_connect(c);
  exchange=argv[5];
  exchange_len=strlen(exchange);
  route=argv[6];
  route_len=strlen(route);
  while(true) {
    char *line = NULL;
    size_t line_cap = 0;
    int line_len;
    line_len = getline(&line, &line_cap, stdin);
    if(line_len < 0) {
      // wait for queues to drain
      while(fq_client_data_backlog(c) > 0) {
        usleep(100);
      }
      exit(0);
    }
    line_len++; // include \0 terminal character
    m = fq_msg_alloc(line, line_len);
    fq_msg_exchange(m, exchange, exchange_len);
    fq_msg_route(m, route, route_len);
    fq_msg_id(m, NULL);
    fq_client_publish(c, m);
    fq_msg_free(m);
  }
  return 0;
}
