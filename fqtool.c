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
#include <sys/uio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
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
char *output = NULL;
char *format = "payload";

enum {
  M_ROUTE = 0,
  M_HOST,
  M_PAYLOAD,
  M_NONE
} o_fmt[M_NONE];
#define M_COUNT M_NONE
int output_fd = -1;
bool inject_json = true;

static void
my_auth_handler(fq_client c, int error) {
  fq_bind_req *breq;
 
  if(error) {
    fprintf(stderr, "Error encoutered.\n");
    exit(-1);
  }

  if(!output)
    fprintf(stderr, "Queue made %s.\n", permanent ? "permanent" : "transient");
  if(!binding_prog && !output) exit(0);

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
  if(!output) {
    fprintf(stderr, "Binding made %s.\n", binding_trans ? "transient" : "permanent");
    exit(0);
  }
}

static bool
my_message_handler(fq_client c, fq_msg *m) {
  int i;
  char *payload = (char *)m->payload;
  long payload_len = m->payload_len;
  char host[32] = "";
  bool lineend = true;
  bool started = false;
  if(payload_len > 0 && payload[payload_len-1] == '\n') {
    payload_len--;
  }

  struct in_addr addr;
  for(i=0;i<MAX_HOPS-1;i++)
    if(m->hops[i+1] == 0 ||  /* IN ADDR ANY */
       m->hops[i+1] == 0xffffffff ||  /* IN ADDR ANY */
       (ntohl(m->hops[i+1]) & 0xff000000) == 0x7f000000) /* LOCALHOST */
      break;
  memcpy(&addr, m->hops+i, sizeof(unsigned int));
  snprintf(host, sizeof(host), "%s", inet_ntoa(addr));

#define OUTSTART() do { \
  if(started) write(output_fd, " ", 1); started = true; \
} while(0)
  for(i=0;i<M_COUNT;i++) {
    switch(o_fmt[i]) {
    case M_NONE: break;
    case M_HOST: 
      OUTSTART();
      write(output_fd, host, strlen(host));
      break;
    case M_ROUTE:
      OUTSTART();
      write(output_fd, m->route.name, m->route.len);
      break;
    case M_PAYLOAD:
      OUTSTART();
      if(inject_json && payload[0] == '{' && payload[payload_len-1] == '}') {
        struct iovec iov[8];
        write(output_fd, payload, payload_len-1);
        iov[0].iov_base = "\"_host\":\""; iov[0].iov_len = 9;
        if(payload_len > 2) {
          iov[0].iov_base = ",\"_host\":\""; iov[0].iov_len = 10;
        }
        iov[1].iov_base = host; iov[1].iov_len = strlen(host);
        iov[2].iov_base = "\""; iov[2].iov_len = 1;
        writev(output_fd, iov, 3);
        iov[0].iov_base = ",\"_route\":\""; iov[0].iov_len = 11;
        iov[1].iov_base = m->route.name; iov[1].iov_len = m->route.len;
        iov[2].iov_base = "\""; iov[2].iov_len = 1;
        writev(output_fd, iov, 3);
        write(output_fd, "}", 1);
      }
      else {
        write(output_fd, payload, payload_len);
      }
      break;
    }
  }
  if(started && lineend) write(output_fd, "\n", 1);
  return true;
}

fq_hooks hooks = {
 .version = FQ_HOOKS_V4,
 .auth = my_auth_handler,
 .bind = my_bind_handler,
 .message = my_message_handler
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
  printf("\t-o <outfile>\t\toutput file (- for stdout)\n");
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

  while((opt = getopt(argc, argv, "Jo:f:Dh:e:P:u:p:q:t:B:b:d:")) != EOF) {
    switch(opt) {
    case 'o': output = strdup(optarg); break;
    case 'f': format = strdup(optarg); break;
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
    case 'J': inject_json = false; break;
    default: exit(usage(argv[0]));
    }
  }
  if(format) {
    char *word, *brkt;
    int o_i = 0;
    for (word = strtok_r(format, ",", &brkt);
         word && o_i < M_COUNT;
         word = strtok_r(NULL, ",", &brkt)) {
      if(!strcmp(word, "host")) o_fmt[o_i++] = M_HOST;
      else if(!strcmp(word, "route")) o_fmt[o_i++] = M_ROUTE;
      else if(!strcmp(word, "payload")) o_fmt[o_i++] = M_PAYLOAD;
      else {
        fprintf(stderr, "Error: unknown format '%s'\n", word);
        exit(-2);
      }
    }
    for(;o_i<M_COUNT;o_i++) o_fmt[o_i] = M_NONE;
  }
  if(output) {
    if(!strcmp(output, "-")) output_fd = STDOUT_FILENO;
    else {
      output_fd = open(output, O_CREAT|O_APPEND|O_WRONLY);
      if(output_fd < 0) {
        fprintf(stderr, "Error opening output: %s\n", strerror(errno));
        exit(-2);
      }
    }
  }
  if(!permanent && !queuename) {
    struct utsname utsn;
    char tqname[128];
    char *progname;
    char *nodename = "unknown";
    progname = strrchr(argv[0], '/');
    if(!progname) progname = argv[0];
    else progname++;
    if(uname(&utsn) == 0) nodename = utsn.nodename;
    snprintf(tqname, sizeof(tqname), "q-%s-%s-%d", progname, nodename, getpid());
    queuename = strdup(tqname);
  }
  if(!queuename) {
    fprintf(stderr, "Error: no queuename specified, but -D omitted.\n\n");
    exit(usage(argv[0]));
  }
  if(!exchange) {
    fprintf(stderr, "Error: no exchange specified.\n\n");
    exit(usage(argv[0]));
  }
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
