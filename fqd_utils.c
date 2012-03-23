#include "fqd.h"

#ifdef __MACH__
#include <mach/mach.h>
#include <mach/clock.h>

static int initialized = 0;
static clock_serv_t clk_system;
static mach_port_t myport;
hrtime_t gethrtime() {
  mach_timespec_t now;
  if(!initialized) {
    kern_return_t kr;
    myport = mach_host_self();
    kr = host_get_clock_service(myport, SYSTEM_CLOCK, &clk_system);
    if(kr == KERN_SUCCESS) initialized = 1;
  }
  clock_get_time(clk_system, &now);
  return (now.tv_sec * 1000000000) + now.tv_nsec;
}

#endif
