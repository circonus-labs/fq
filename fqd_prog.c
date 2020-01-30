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

#define _GNU_SOURCE
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dlfcn.h>
#include <dirent.h>
#include "fqd.h"
#include "fqd_private.h"

bool fqd_route_prog__true__(fq_msg *, int, valnode_t *);
bool fqd_route_prog__route_contains__s(fq_msg *, int, valnode_t *);
bool fqd_route_prog__payload_prefix__s(fq_msg *, int, valnode_t *);

void fqd_route_load_module(const char *libexecdir, const char *file, const char *ext) {
  char path[PATH_MAX];
  if(*file != '/') {
    snprintf(path, sizeof(path), "%s/%s%s", libexecdir, file, ext ? ext : "");
    file = path;
  }
  void *handle = dlopen(file, RTLD_NOW|RTLD_GLOBAL);
  if(handle == NULL) {
    fprintf(stderr, "Failed to load %s: %s\n", file, dlerror());
  }
  fqd_routemgr_add_handle(handle);
}

void global_functions_init(const char *libexecdir) {
#define GFR(a) global_function_register(#a, (void (*)(void))a)
  GFR(fqd_route_prog__true__);
  GFR(fqd_route_prog__route_contains__s);
  GFR(fqd_route_prog__payload_prefix__s);
#undef GFR

  DIR *dir = opendir(libexecdir);
  if(!dir) return;
  struct dirent *de;
  while(NULL != (de = readdir(dir))) {
    char path[PATH_MAX];
    struct stat sb;
    int namelen = strlen(de->d_name);
    if(namelen < 4 || memcmp(de->d_name + namelen - 3, ".so", 3)) continue;
    snprintf(path, sizeof(path), "%s/%s", libexecdir, de->d_name);
    if(stat(path, &sb) == -1) continue;
    if((sb.st_mode & S_IFMT) == S_IFREG || (sb.st_mode & S_IFMT) == S_IFLNK) {
      fqd_route_load_module(libexecdir, de->d_name, NULL);
    }
  }
  closedir(dir);
}

bool fqd_route_prog__true__(fq_msg *m, int nargs, valnode_t *args) {
  fq_assert(nargs == 0);
  (void)m;
  (void)nargs;
  (void)args;
  return true;
}

bool
fqd_route_prog__route_contains__s(fq_msg *m, int nargs, valnode_t *args) {
  int flen;
  fq_assert(nargs == 1);
  fq_assert(args[0].value_type == RP_VALUE_STRING);
  flen = strlen(args[0].value.s);
  if(flen > m->route.len) return false;
  return memmem(m->route.name, m->route.len, args[0].value.s, flen) != NULL;
}

bool
fqd_route_prog__payload_prefix__s(fq_msg *m, int nargs, valnode_t *args) {
  uint32_t flen;
  fq_assert(nargs == 1);
  fq_assert(args[0].value_type == RP_VALUE_STRING);
  flen = strlen(args[0].value.s);
  if(flen > m->payload_len) return false;
  if(memcmp(args[0].value.s, m->payload, flen) == 0)
    return true;
  return false;
}

bool
fqd_route_prog__payload_contains__s(fq_msg *m, int nargs, valnode_t *args) {
    int flen;
    fq_assert(nargs == 1);
    fq_assert(args[0].value_type == RP_VALUE_STRING);
    flen = strlen(args[0].value.s);
    if(flen > m->payload_len) return false;
    return memmem(m->payload, m->payload_len, args[0].value.s, flen) != NULL;
}
