#include "fq.h"
#include "fqd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#ifdef __MACH__
#include <mach/mach.h>
#include <mach/clock.h>

static int initialized = 0;
static clock_serv_t clk_system;
static mach_port_t myport;
hrtime_t fq_gethrtime() {
  mach_timespec_t now;
  if(!initialized) {
    kern_return_t kr;
    myport = mach_host_self();
    kr = host_get_clock_service(myport, SYSTEM_CLOCK, &clk_system);
    if(kr == KERN_SUCCESS) initialized = 1;
  }
  clock_get_time(clk_system, &now);
  return ((uint64_t)now.tv_sec * 1000000000ULL) +
         (uint64_t)now.tv_nsec;
}
#endif

int fq_rk_to_hex(char *buf, int len, fq_rk *k) {
  int i;
  unsigned char *bout = (unsigned char *)buf;
  if(k->len * 2 + 4 > len) return -1;
  *bout++ = '0';
  *bout++ = 'x';
  for (i=0; i<k->len; i++) {
    snprintf((char *)bout, 3, "%02x", k->name[i]);
    bout+=2;
  }
  *bout = '\0';
  return (bout - (unsigned char *)buf);
}
int
fq_read_uint16(int fd, unsigned short *v) {
  unsigned short nlen;
  int rv;
  while((rv = read(fd, &nlen, sizeof(nlen))) == -1 && errno == EINTR);
  if(rv != sizeof(nlen)) return -1;
  *v = ntohs(nlen);
  return 0;
}
int
fq_write_uint16(int fd, unsigned short v) {
  uint16_t nv;
  int rv;
  nv = htons(v);
  while((rv = write(fd, &nv, sizeof(nv))) == -1 && errno == EINTR);
  return (rv == sizeof(nv)) ? 0 : -1;
}
int
fq_read_short_cmd(int fd, unsigned short buflen, void *buf) {
  void *tgt = buf;
  unsigned char  scratch[0xffff];
  unsigned short nlen, len;
  int rv;
  while((rv = read(fd, &nlen, sizeof(nlen))) == -1 && errno == EINTR);
  if(rv < 0 || rv != sizeof(nlen)) return -1;
  len = ntohs(nlen);
  if(len == 0) return 0;
  if(len > buflen)
    tgt = scratch;
  while((rv = read(fd, tgt, len)) == -1 && errno == EINTR);
  if(rv != len) {
    return -1;
  }
  if(tgt != buf) memcpy(buf, tgt, buflen); /* truncated */
  return rv;
}
int
fq_write_short_cmd(int fd, unsigned short buflen, const void *buf) {
  unsigned short nlen;
  int rv;
  nlen = htons(buflen);
  while((rv = write(fd, &nlen, sizeof(nlen))) == -1 && errno == EINTR);
  if(rv != sizeof(nlen)) return -1;
  if(buflen == 0) return 0;
  while((rv = write(fd, buf, buflen)) == -1 && errno == EINTR);
  if(rv != buflen) return -1;
  return rv;
}

int
fq_read_long_cmd(int fd, int *rlen, void **rbuf) {
  unsigned int nlen;
  int rv, len;
  while((rv = read(fd, &nlen, sizeof(nlen))) == -1 && errno == EINTR);
  if(rv < 0 || rv != sizeof(nlen)) return -1;
  len = ntohl(nlen);
  *rlen = 0;
  *rbuf = NULL;
  if(len < 0) {
    return -1;
  }
  else if(len > 0) {
    *rbuf = malloc(len);
    while((rv = read(fd, *rbuf, len)) == -1 && errno == EINTR);
    if(rv != len) {
      free(*rbuf);
      *rlen = 0;
      *rbuf = NULL;
      return -1;
    }
    *rlen = rv;
  }
  return *rlen;
}

int
fq_debug_fl(const char *file, int line, const char *fmt, ...) {
  int rv;
  va_list argp;
  static hrtime_t epoch = 0;
  hrtime_t now;
  char fmtstring[1024];
  u_int64_t p = (u_int64_t)pthread_self();
  u_int32_t ps = p & 0xffffffff;

  now = fq_gethrtime();
  if(!epoch) epoch = now;

  snprintf(fmtstring, sizeof(fmtstring), "[%llu] [%08x] %s",
           (now-epoch)/1000, ps, fmt);
  va_start(argp, fmt);
  rv = vfprintf(stderr, fmtstring, argp);
  va_end(argp);
  return rv;
}
