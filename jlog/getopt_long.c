/*
 * Copyright (c) 2005-2008, Message Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *    * Neither the name Message Systems, Inc. nor the names
 *      of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "jlog_config.h"
#include "getopt_long.h"
#include <stdarg.h>
#include <stdio.h>

int optind = 1;
int opterr = 1;
char *optarg = NULL;

static void ec_error_func(const char *msg, ...) {
  va_list arg;
  va_start(arg, msg);
  vfprintf(stderr, msg, arg);
  va_end(arg);
}

getopt_error_func opterrfunc = ec_error_func;

static int _getopt_long(int my_argc,
                char * const *my_argv,
                const char *optstring,
                const struct option *longopts,
                int *longindex)
{
  const char *cur = NULL;
  const char *cur_longopt = NULL;
  int cur_longopt_len;
  char *argument = NULL;
  int i;

  cur = my_argv[optind];
  cur_longopt = cur + 2;
 
  optind++;
  /* check for options that have an embedded '=' in them */
  if((argument = strchr(cur_longopt, '=')) != NULL) {
    cur_longopt_len = argument - cur_longopt;
    argument++;
  } else {
    cur_longopt_len = strlen(cur_longopt);
  }
  for(i = 0; longopts[i].name; i++) {
    if(strlen(longopts[i].name) == cur_longopt_len &&
       !strncmp(longopts[i].name, cur_longopt, cur_longopt_len)) 
    {
      switch(longopts[i].has_arg) {
        case no_argument:
          if(argument) {
            /* error */
            opterrfunc("argument --%.*s requires no arguments\n", cur_longopt_len, cur_longopt);
            return GETOPT_INVALID_OPTION;
          }
          /* no break, we fall through */
          break;
        case required_argument:
          optarg = argument?argument:my_argv[optind];
          if(!optarg) {
            /* error */
            opterrfunc("argument %s requires an argument\n", cur);
            return GETOPT_INVALID_OPTION;
          }
          if(!argument) optind++;
          break;
        case optional_argument:
          optarg = argument;
          break;
      }
      if(longindex) *longindex = i;
      if(longopts[i].flag) {
        *longopts[i].flag = longopts[i].val;
        return 0;
      } else {
        return longopts[i].val;
      }
    }
  }
  /* we can only reach here if we have an unknown option */
  opterrfunc("unknown long option %s\n", cur);
  return GETOPT_INVALID_OPTION;
}

static int _getopt(int my_argc, char * const *my_argv, const char *optstring)
{
  const char *cur;
  char *optstring_off;
  char cur_shortopt;

  cur = my_argv[optind];
  /* search simple option texts */
  cur_shortopt = cur[1];
  if(cur_shortopt == GETOPT_MISSING_OPTION ||
     cur_shortopt == GETOPT_INVALID_OPTION ||
     (optstring_off = strchr(optstring, cur_shortopt)) == NULL) 
  {
    /* error case, none found */
    opterrfunc("unknown option: %c\n", cur_shortopt);
    return GETOPT_INVALID_OPTION;
  }
  optind++;
  if(optstring_off[1] == ':') {
    /* takes an option */
    if(cur[2]) {
      /* argument is concatenated with the option */
      optarg = (char *) cur + 2;
    } else {
      if(optind >= my_argc) {
        /* end of args */
        opterrfunc("option %c requires an argument\n", cur_shortopt);
        return GETOPT_INVALID_OPTION;
      }
      optarg = my_argv[optind];
      optind++;
    }
  } else {
    if(cur[2]) {
      /* we have a concatenated argument, but our parameter takes no args */
      opterrfunc("option %c does not take an argument\n", cur_shortopt);
      return GETOPT_INVALID_OPTION;
    }
    /* does not take an option */
  }
  return cur_shortopt;
}

int getopt_long(int my_argc, 
                char * const *my_argv, 
                const char *optstring, 
                const struct option *longopts, 
                int *longindex)
{
  const char *cur;

  if(optind >= my_argc) {
    /* end of args */
    return -1;
  }
  cur = my_argv[optind];
  if(cur[0] != '-' || (cur[1] == '-' && cur[2] == '\0')) {
    /* end of args */
    /* need to handle POSIXLY_CORRECT case */
    return -1;
  }
  if(cur[1] == '-') {
    /* this is a long option, dispatch appropriately */
    return _getopt_long(my_argc, my_argv, optstring, longopts, longindex);
  } else {
    /* short opt */
    return _getopt(my_argc, my_argv, optstring);
  }
}

#if defined(_WIN32)
int getopt(int my_argc, char * const *my_argv, const char *optstring)
{
  const char *cur;

  if(optind >= my_argc) {
    /* end of args */
    return -1;
  }
  cur = my_argv[optind];
  if(cur[0] != '-' || (cur[1] == '-' && cur[2] == '\0')) {
    /* end of args */
    /* need to handle POSIXLY_CORRECT case */
    return -1;
  }
  return _getopt(my_argc, my_argv, optstring);
}
#endif
