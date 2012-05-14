#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "getopt.h"
#include "fqd.h"

static uint32_t nodeid = 0;
static void *listener_thread(void *unused) {
  (void)unused;
  fqd_listener(NULL, 8765);
  return NULL;
}
static void usage(const char *prog) {
  printf("%s:\n", prog);
  printf("\t-h\t\tthis help message\n");
  printf("\t-n <ip>\t\tnode self identifier (IPv4)\n");
}
static void parse_cli(int argc, char **argv) {
  int c;
  const char *debug = getenv("FQ_DEBUG");
  if(debug) fq_debug_set_bits(atoi(debug));
  while((c = getopt(argc, argv, "hn:")) != EOF) {
    switch(c) {
      case 'h':
        usage(argv[0]);
        exit(0);
      case 'n':
        if(inet_pton(AF_INET, optarg, &nodeid) != 1) {
          fprintf(stderr, "Bad argument to -n, must be an IPv4 address.\n");
          exit(-1);
        }
        if(nodeid == 0 || nodeid == htonl(0x7f000001)) {
          fprintf(stderr, "nodeid cannot be INADDR_ANY or loopback\n");
          exit(-1);
        }
        break;
      default:
        usage(argv[0]);
        exit(-1);
    }
  }
}
static uint32_t get_my_ip(void) {
  uint32_t ip;
  struct hostent *h;
  char buff[128];
  gethostname(buff, sizeof(buff));
  h = gethostbyname(buff);
  if(h && h->h_addrtype == AF_INET && h->h_length == 4) {
    memcpy(&ip, h->h_addr_list[0], h->h_length);
    if(ip == htonl(0x7f000001)) return 0;
    return ip;
  }
  return 0;
}
int main(int argc, char **argv) {
  pthread_t tid;
  nodeid = get_my_ip();
  parse_cli(argc,argv);
  if(nodeid == 0) {
    fprintf(stderr, "Could not determine host address, use -n <ip>\n");
    exit(-1);
  }
  fqd_config_init(nodeid);
  signal(SIGPIPE, SIG_IGN);
  pthread_create(&tid, NULL, listener_thread, NULL);
  pause();
  return 0;
}
