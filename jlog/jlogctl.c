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
#include "jlog_private.h"
#include "getopt_long.h"
#include <stdio.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif
#if HAVE_DIRENT_H
#include <dirent.h>
#endif

static int verbose = 0;
static int show_progress = 0;
static int show_subscribers = 0;
static int show_files = 0;
static int show_index_info = 0;
static int analyze_datafiles = 0;
static int repair_datafiles = 0;
static int cleanup = 0;
static int quiet = 0;
static char *add_subscriber = NULL;
static char *remove_subscriber = NULL;

static void usage(const char *prog) {
  printf("Usage:\n    %s <options> logpath1 [logpath2 [...]]\n",
         prog);
  printf("\t-a <sub>:\tAdd <sub> as a log subscriber\n");
  printf("\t-e <sub>:\tErase <sub> as a log subscriber\n");
  printf("\t-p <sub>:\tShow the perspective of the subscriber <sub>\n");
  printf("\t      -l:\tList all log segments with sizes and readers\n");
  printf("\t      -i:\tList index information\n");
  printf("\t      -c:\tClean all log segments with no pending readers\n");
  printf("\t      -s:\tShow all subscribers\n");
  printf("\t      -d:\tAnalyze datafiles\n");
  printf("\t      -r:\tAnalyze datafiles and repair if needed\n");
  printf("\t      -v:\tVerbose output\n");
  printf("\nWARNING: the -r option can't be used on jlogs that are "
         "open by another process\n");
}
static int is_datafile(const char *f, u_int32_t *logid) {
  int i;
  u_int32_t l = 0;
  for(i=0; i<8; i++) {
    if((f[i] >= '0' && f[i] <= '9') ||
       (f[i] >= 'a' && f[i] <= 'f')) {
      l <<= 4;
      l |= (f[i] < 'a') ? (f[i] - '0') : (f[i] - 'a' + 10);
    }
    else
      return 0;
  }
  if(f[i] != '\0') return 0;
  if(logid) *logid = l;
  return 1;
}
static void analyze_datafile(jlog_ctx *ctx, u_int32_t logid) {
  char idxfile[MAXPATHLEN];

  if (jlog_inspect_datafile(ctx, logid) > 0) {
    fprintf(stderr, "One or more errors were found.\n");
    if(repair_datafiles) {
      jlog_repair_datafile(ctx, logid);
      fprintf(stderr,
              "Log file reconstructed, deleting the corresponding idx file.\n");
      STRSETDATAFILE(ctx, idxfile, logid);
      strcat(idxfile, INDEX_EXT);
      unlink(idxfile);
    }
  }
}
static void process_jlog(const char *file, const char *sub) {
  jlog_ctx *log;
  log = jlog_new(file);

  if(add_subscriber) {
    if(jlog_ctx_add_subscriber(log, add_subscriber, JLOG_BEGIN)) {
      fprintf(stderr, "Could not add subscriber '%s': %s\n", add_subscriber,
              jlog_ctx_err_string(log));
    } else {
      if(!quiet) printf("Added subscriber '%s'\n", add_subscriber);
    }
  }
  if(remove_subscriber) {
    if(jlog_ctx_remove_subscriber(log, remove_subscriber) <= 0) {
      fprintf(stderr, "Could not erase subscriber '%s': %s\n",
              remove_subscriber, jlog_ctx_err_string(log));
    } else {
      if(!quiet) printf("Erased subscriber '%s'\n", remove_subscriber);
    }
  }
  if(!sub) {
    if(jlog_ctx_open_writer(log)) {
      fprintf(stderr, "error opening '%s'\n", file);
      return;
    }
  } else {
    if(jlog_ctx_open_reader(log, sub)) {
      fprintf(stderr, "error opening '%s'\n", file);
      return;
    }
  }
  if(show_progress) {
    jlog_id id, id2, id3;
    char buff[20], buff2[20], buff3[20];
    jlog_get_checkpoint(log, sub, &id);
    if(jlog_ctx_last_log_id(log, &id3)) {
      fprintf(stderr, "jlog_error: %s\n", jlog_ctx_err_string(log));
      fprintf(stderr, "error callign jlog_ctx_last_log_id\n");
    }
    jlog_snprint_logid(buff, sizeof(buff), &id);
    jlog_snprint_logid(buff3, sizeof(buff3), &id3);
    if(!quiet) printf("--------------------\n");
    if(!quiet) printf("  Perspective of the '%s' subscriber\n", sub);
    if(!quiet) printf("    current checkpoint: %s\n", buff);
    if(!quiet) printf("Last write: %s\n", buff3);
    if(jlog_ctx_read_interval(log, &id, &id2) < 0) {
      fprintf(stderr, "jlog_error: %s\n", jlog_ctx_err_string(log));
    }
    jlog_snprint_logid(buff, sizeof(buff), &id);
    jlog_snprint_logid(buff2, sizeof(buff2), &id2);
    if(!quiet) printf("\t     next interval: [%s, %s]\n", buff, buff2);
    if(!quiet) printf("--------------------\n\n");
  }
  if(show_subscribers) {
    char **list;
    int i;
    jlog_ctx_list_subscribers(log, &list);
    for(i=0; list[i]; i++) {
      jlog_id id;
      char buff[20];
      jlog_get_checkpoint(log, list[i], &id);
      jlog_snprint_logid(buff, sizeof(buff), &id);
      if(!quiet) printf("\t%32s @ %s\n", list[i], buff);
    }
    jlog_ctx_list_subscribers_dispose(log, list);
  }
  if(show_files) {
    DIR *dir;
    struct dirent *de;
    dir = opendir(file);
    if(!dir) {
      fprintf(stderr, "error opening '%s'\n", file);
      return;
    }
    while((de = readdir(dir)) != NULL) {
      u_int32_t logid;
      if(is_datafile(de->d_name, &logid)) {
        char fullfile[MAXPATHLEN];
        char fullidx[MAXPATHLEN];
        struct stat st;
        int readers;
        snprintf(fullfile, sizeof(fullfile), "%s/%s", file, de->d_name);
        snprintf(fullidx, sizeof(fullidx), "%s/%s" INDEX_EXT, file, de->d_name);
        if(stat(fullfile, &st)) {
          if(!quiet) printf("\t%8s [error statting file: %s\n", de->d_name, strerror(errno));
        } else {
          readers = __jlog_pending_readers(log, logid);
          if(!quiet) printf("\t%8s [%9llu bytes] %d pending readers\n",
                            de->d_name, (unsigned long long)st.st_size, readers);
          if(show_index_info && !quiet) {
            struct stat sb;
            if (stat(fullidx, &sb)) {
              printf("\t\t idx: none\n");
            } else {
              u_int32_t marker;
              int closed;
              if (jlog_idx_details(log, logid, &marker, &closed)) {
                printf("\t\t idx: error\n");
              } else {
                printf("\t\t idx: %u messages (%08x), %s\n",
                       marker, marker, closed?"closed":"open");
              }
            }
          }
          if (analyze_datafiles) analyze_datafile(log, logid);
          if((readers == 0) && cleanup) {
            unlink(fullfile);
            unlink(fullidx);
          }
        }
      }
    }
    closedir(dir);
  }
  jlog_ctx_close(log);
}
int main(int argc, char **argv) {
  int i, c;
  int option_index = 0;
  char *subscriber = NULL;
  while((c = getopt_long(argc, argv, "a:e:dsilrcp:v",
                         NULL, &option_index)) != EOF) {
    switch(c) {
     case 'v':
      verbose = 1;
      break;
     case 'i':
      show_files = 1;
      show_index_info = 1;
      break;
     case 'r':
      show_files = 1;
      analyze_datafiles = 1;
      repair_datafiles = 1;
      break;
     case 'd':
      show_files = 1;
      analyze_datafiles = 1;
      break;
     case 'a':
      add_subscriber = optarg;
      break;
     case 'e':
      remove_subscriber = optarg;
      break;
     case 'p':
      show_progress = 1;
      subscriber = optarg;
      break;
     case 's':
      show_subscribers = 1;
      break;
     case 'c':
      show_files = 1;
      quiet = 1;
      cleanup = 1;
      break;
     case 'l':
      show_files = 1;
      break;
     default:
      usage(argv[0]);
      exit(-1);
    }
  }
  if(optind == argc) {
    usage(argv[0]);
    exit(-1);
  }
  for(i=optind; i<argc; i++) {
    if(!quiet) printf("%s\n", argv[i]);
    process_jlog(argv[i], subscriber);
  }
  return 0;
}
