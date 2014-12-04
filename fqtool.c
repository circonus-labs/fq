/*
 * Copyright (c) 2014 Circonus, Inc.
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
#include "getopt.h"
#include "fq.h"

int usage(const char *);
void logger(fq_client, const char *);

void logger(fq_client c, const char *s) {
  (void)c;
  fprintf(stderr, "fq_logger: %s\n", s);
}

int permanent = 1;
int binding_trans = 1;
char *binding_prog = NULL;
char *exchange = NULL;

static void
my_auth_handler(fq_client c, int error) {
  fq_bind_req *breq;
 
  if(error) {
    fprintf(stderr, "Error encoutered.\n");
    exit(-1);
  }

  printf("Queue made %s.\n", permanent ? "permanent" : "transient");
  if(!binding_prog) exit(0);

  breq = malloc(sizeof(*breq));
  memset(breq, 0, sizeof(*breq));
  memcpy(breq->exchange.name, exchange, strlen(exchange));
  breq->exchange.len = strlen(exchange);
  breq->flags = binding_trans ? FQ_BIND_TRANS : FQ_BIND_PERM;
  breq->program = binding_prog;
  fq_client_bind(c, breq);
}

static void
my_bind_handler(fq_client c, fq_bind_req *breq) {
  (void)c;
  if(breq->out__route_id == FQ_BIND_ILLEGAL) {
    fprintf(stderr, "Failure to bind...\n");
    exit(-1);
  }
  printf("Binding made %s.\n", binding_trans ? "transient" : "permanent");
  exit(0);
}

fq_hooks hooks = {
 .version = FQ_HOOKS_V1,
 .auth = my_auth_handler,
 .bind = my_bind_handler
};

int usage(const char *prog) {
  printf("%s [-h host] [-P port] [-u user] [-p pass]\n", prog);
  printf("\t<-e name> <-q name> [-t <mem|disk>] [-D]\n");
  printf("\t[-(b|B) 'program'] <-d backlog>\n");
  printf("\n");
  printf("\t-h <host>\t\tdefault: localhost\n");
  printf("\t-e <name>\t\texchange name\n");
  printf("\t-P <port>\t\tdefault: 8765\n");
  printf("\t-u <port>\t\tdefault: nobody\n");
  printf("\t-p <pass>\t\tdefault: nopass\n");
  printf("\t-q <name>\t\tqueue name\n");
  printf("\t-t <type>\t\tqueue type\n");
  printf("\t-d <n>\t\t\tdefine queue depth (backlog)\n");
  printf("\t-D\t\t\tdelete queue (make transient)\n");
  printf("\t-B <prog>\t\tinstall binding\n");
  printf("\t-b <prog>\t\tuninstall binding\n");
  return 0;
}

int main(int argc, char **argv) {
  int opt;
  char *user = (char *)"nobody";
  char *pass = (char *)"nopass";
  char *host = (char *)"localhost";
  int port = 8765;
  char *queuename = NULL;
  char *qtype = (char *)"mem";
  int backlog = -1;
  char connstr[256];
  fq_client c;

  while((opt = getopt(argc, argv, "Dh:e:P:u:p:q:t:B:b:d:")) != EOF) {
    switch(opt) {
    case 'e': exchange = strdup(optarg); break;
    case 'h': host = strdup(optarg); break;
    case 'P': port = atoi(optarg); break;
    case 'u': user = strdup(optarg); break;
    case 'p': pass = strdup(optarg); break;
    case 'q': queuename = strdup(optarg); break;
    case 't': qtype = strdup(optarg); break;
    case 'D': permanent = 0; break;
    case 'B': binding_prog = strdup(optarg);
              binding_trans = 0; break;
    case 'b': binding_prog = strdup(optarg);
              binding_trans = 1; break;
    case 'd': backlog = atoi(optarg); break;
    default: exit(usage(argv[0]));
    }
  }

  if(!queuename) exit(usage(argv[0]));
  if(!exchange) exit(usage(argv[0]));
  snprintf(connstr, sizeof(connstr), "%s/%s/%s:%s,public,backlog=%d",
           user, queuename, qtype, permanent ? "permanent" : "transient",
           backlog);

  char *fq_debug = getenv("FQ_DEBUG");
  if(fq_debug) fq_debug_set_bits(atoi(fq_debug));
  signal(SIGPIPE, SIG_IGN);
  fq_client_init(&c, 0, logger);
  if(fq_client_hooks(c, &hooks)) {
    fprintf(stderr, "Can't register hooks\n");
    exit(-1);
  }
  fq_client_hooks(c, &hooks);
  fq_client_creds(c, host, port, connstr, pass);
  fq_client_heartbeat(c, 1000);
  fq_client_set_backlog(c, 10000, 100);
  fq_client_connect(c);

  pause();
  
  return 0;
}
