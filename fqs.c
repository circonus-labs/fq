/*
 * fqs
 *
 * fqs reads messages from stdin, one pre line, and sends it to the specified fq exchange.
 *
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

static void usage(const char *prog) {
  printf("%s:\n", prog);
  printf("\t-h \tshow this help message\n");
  printf("\t-a <host>:<port>\tspecify the address to connect to (default: 127.0.0.1:8765)\n");
  printf("\t-x <exchange>\tspecify the exchange to relay messages on (required)\n");
  printf("\t-r <route>\tspecify the message route (required)\n");
  printf("\t-u <user>\tspecify the user (default: user)\n");
  printf("\t-p <pass>\tspecify the password (default: pass)\n");
}

int main(int argc, char **argv) {
  char *host = NULL, *exchange = NULL, *route = NULL;
  char *address = strdup("127.0.0.1:8765");
  char *user = "user";
  char *pass = "pass";
  int port = 0;
  int c = 0;
  if (argc == 1) {
    usage(argv[0]);
    exit(-1);
  }
  while((c = getopt(argc, argv, "ha:x:r:u:p:")) != EOF) {
    switch(c) {
    case 'h':
      usage(argv[0]);
      exit(0);
      break;
    case 'a':
      address = strdup(optarg);
      break;
    case 'x':
      exchange = strdup(optarg);
      break;
    case 'r':
      route = strdup(optarg);
      break;
    case 'u':
      user = strdup(optarg);
      break;
    case 'p':
      pass = strdup(optarg);
      break;
    default:
      usage(argv[0]);
      exit(-1);
    }
  }
  // Separate host and port in address string
  // We have strdup'ed address so we can mutate it
  host = address;
  for (char *p = address; *p != 0; p++) {
    if (*p == ':') {
      *p = 0;
      port = strtol(p+1, NULL, 10);
      break;
    }
  }
  if (!port) {
    printf("Illegal port specification\n");
    exit(-1);
  }
  if (!exchange) {
    printf("Exchange argument required");
    exit(-1);
  }
  if (!route) {
    printf("Route argument required");
    exit(-1);
  }

  fq_client cli;
  fq_msg *m = NULL;
  size_t exchange_len = strlen(exchange);
  size_t route_len = strlen(route);
  signal(SIGPIPE, SIG_IGN); // ignore SIGPIPE
  fq_client_init(&cli, 0, logger);
  fq_client_creds(cli, host, port, user, pass);
  fq_client_heartbeat(cli, 1000);
  fq_client_set_backlog(cli, 10000, 100);
  fq_client_connect(cli);
  while(true) {
    char *line = NULL;
    size_t line_cap = 0;
    int line_len;
    line_len = getline(&line, &line_cap, stdin);
    if(line_len < 0) {
      // wait for queues to drain
      while(fq_client_data_backlog(cli) > 0) {
        usleep(100);
      }
      exit(0);
    }
    m = fq_msg_alloc(line, line_len);
    fq_msg_exchange(m, exchange, exchange_len);
    fq_msg_route(m, route, route_len);
    fq_msg_id(m, NULL);
    fq_client_publish(cli, m);
    fq_msg_free(m);
  }
  return 0;
}
