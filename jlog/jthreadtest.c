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

#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#include "jlog_config.h"
#include "jlog.h"

#define MASTER     "master"
#define LOGNAME    "/tmp/jtest.foo"

int writer_done = 0;
int only_read = 0;
int only_write = 0;

static void _croak(int lineno)
{
  fprintf(stderr, "croaked at line %d\n", lineno);
  exit(2);
}
#define croak() _croak(__LINE__)

void jcreate(jlog_safety s) {
  jlog_ctx *ctx;
  const char *label = NULL;
  
  switch (s) {
    case JLOG_ALMOST_SAFE: label = "almost safe"; break;
    case JLOG_UNSAFE:      label = "unsafe"; break;
    case JLOG_SAFE:        label = "safe"; break;
  }
  fprintf(stderr, "jcreate %s in %s mode\n", LOGNAME, label);
  
  ctx = jlog_new(LOGNAME);
  jlog_ctx_alter_journal_size(ctx, 102400);
  jlog_ctx_alter_safety(ctx, s);
  if(jlog_ctx_init(ctx) != 0) {
    fprintf(stderr, "jlog_ctx_init failed: %d %s\n", jlog_ctx_err(ctx), jlog_ctx_err_string(ctx));
    if(jlog_ctx_err(ctx) != JLOG_ERR_CREATE_EXISTS) exit(0);
  } else {
    jlog_ctx_add_subscriber(ctx, MASTER, JLOG_BEGIN);
  }
  jlog_ctx_close(ctx);
}

void *writer(void *unused) {
  jlog_ctx *ctx;
  int i;
  char foo[1523];
  ctx = jlog_new(LOGNAME);
  memset(foo, 'X', sizeof(foo)-1);
  foo[sizeof(foo)-1] = '\0';
  if(jlog_ctx_open_writer(ctx) != 0) {
    fprintf(stderr, "jlog_ctx_open_writer failed: %d %s\n", jlog_ctx_err(ctx), jlog_ctx_err_string(ctx));
    croak();
  }
  for(i=0;i<1000;i++) {
    int rv;
    fprintf(stderr, "writer...\n");
    rv = jlog_ctx_write(ctx, foo, strlen(foo));
    if(rv != 0) {
      fprintf(stderr, "jlog_ctx_write_message failed: %d %s\n", jlog_ctx_err(ctx), jlog_ctx_err_string(ctx));
      /* abort(); */
    }
  }
  jlog_ctx_close(ctx);
  writer_done = 1;
  return 0;
}

void *reader(void *unused) {
  jlog_ctx *ctx;
  char subname[32];
  int tcount = 0;
  int prev_err = 0;
  int subno = (int)unused;
  snprintf(subname, sizeof(subname), "sub-%02d", subno);
reader_retry:
  ctx = jlog_new(LOGNAME);
  if(jlog_ctx_open_reader(ctx, subname) != 0) {
    if(prev_err == 0) {
      prev_err = jlog_ctx_err(ctx);
      jlog_ctx_close(ctx);
      ctx = jlog_new(LOGNAME);
      if(prev_err == JLOG_ERR_INVALID_SUBSCRIBER) {
        fprintf(stderr, "[%02d] invalid subscriber, init...\n", subno);
        if(jlog_ctx_open_writer(ctx) != 0) {
          fprintf(stderr, "[%02d] jlog_ctx_open_writer failed: %d %s\n", subno, jlog_ctx_err(ctx), jlog_ctx_err_string(ctx));
        } else {
          if(jlog_ctx_add_subscriber(ctx, subname, JLOG_BEGIN) != 0) {
            fprintf(stderr, "[%02d] jlog_ctx_add_subscriber failed: %d %s\n", subno, jlog_ctx_err(ctx), jlog_ctx_err_string(ctx));
          } else {
            jlog_ctx_close(ctx);
            goto reader_retry;
          }
        }
      }
    }
    fprintf(stderr, "[%02d] jlog_ctx_open_reader failed: %d %s\n", subno, jlog_ctx_err(ctx), jlog_ctx_err_string(ctx));
    croak();
  }
  fprintf(stderr, "[%02d] reader started\n", subno);
  while(1) {
    char begins[20], ends[20];
    jlog_id begin, end;
    int count;
    jlog_message message;
    if((count = jlog_ctx_read_interval(ctx, &begin, &end)) == -1) {
      fprintf(stderr, "jlog_ctx_read_interval failed: %d %s\n", jlog_ctx_err(ctx), jlog_ctx_err_string(ctx));
      croak();
    }
    jlog_snprint_logid(begins, sizeof(begins), &begin);
    jlog_snprint_logid(ends, sizeof(ends), &end);
    if(count > 0) {
      int i;
      fprintf(stderr, "[%02d] reader (%s, %s] count: %d\n", subno, begins, ends, count);
      for(i=0; i<count; i++, JLOG_ID_ADVANCE(&begin)) {
        end = begin;
        if(jlog_ctx_read_message(ctx, &begin, &message) != 0) {
          jlog_snprint_logid(begins, sizeof(begins), &begin);
          fprintf(stderr, "[%02d] read failed @ %s: %d %s\n", subno, begins, jlog_ctx_err(ctx), jlog_ctx_err_string(ctx));
        } else {
          tcount++;
          jlog_snprint_logid(begins, sizeof(begins), &begin);
          /* fprintf(stderr, "[%02d] read: [%s]\n\t'%.*s'\n", subno, begins,
                  message.mess_len, (char *)message.mess); */
        }
      }
      if(jlog_ctx_read_checkpoint(ctx, &end) != 0) {
        fprintf(stderr, "[%02d] checkpoint failed: %d %s\n", subno, jlog_ctx_err(ctx), jlog_ctx_err_string(ctx));
      } else {
        /* fprintf(stderr, "[%02d] \tcheckpointed...\n", subno); */
      }
    } else {
      if(writer_done == 1) break;
    }
  }
  jlog_ctx_close(ctx);
  return (void *)tcount;
}

static void usage(void)
{
  fprintf(stderr,
          "usage: jthreadtest safety [safe|unsafe|almost_safe]\n"
          "       jthreadtest remove [subscriber]\n\n");
  exit(1);
}

#define THRCNT 20
int main(int argc, char **argv) {
  int i;
  char *toremove = NULL;
  jlog_safety safety = JLOG_ALMOST_SAFE;
  pthread_t tid[THRCNT];
  void *foo;
 
#if _WIN32 
  mem_init();
#endif

  if(argc == 3) {
    if(!strcmp(argv[1], "safety")) {
      if(!strcmp(argv[2], "unsafe"))
        safety = JLOG_UNSAFE;
      else if(!strcmp(argv[2], "almost_safe"))
        safety = JLOG_ALMOST_SAFE;
      else if(!strcmp(argv[2], "safe"))
        safety = JLOG_SAFE;
      else {
        fprintf(stderr, "invalid safety option\n");
        usage();
      }
    } else if(!strcmp(argv[1], "only")) {
      if(!strcmp(argv[2], "read")) only_read = 1;
      else if(!strcmp(argv[2], "write")) only_write = 1;
      else usage();
    } else if(!strcmp(argv[1], "remove")) {
      toremove = argv[2];
    } else {
      usage();
    }
  } else if(argc < 3 || argc > 3) {
    usage();
  }

  jcreate(safety);

  if(toremove) {
    jlog_ctx *ctx;
    ctx = jlog_new(LOGNAME);
    if(jlog_ctx_open_writer(ctx) != 0) {
      fprintf(stderr, "jlog_ctx_open_writer failed: %d %s\n", jlog_ctx_err(ctx), jlog_ctx_err_string(ctx));
      croak();
    }
    jlog_ctx_remove_subscriber(ctx, argv[2]);
    jlog_ctx_close(ctx);
    exit(0);
  }
  if(!only_write) {
    for(i=0; i<THRCNT; i++) {
      pthread_create(&tid[i], NULL, reader, (void *)i);
      fprintf(stderr, "[%d] started reader\n", (int)tid[i]);
    }
  }
  if(!only_read) {
    fprintf(stderr, "starting writer...\n");
    writer(NULL);
  } else {
    sleep(5);
    writer_done = 1;
  }
  if(!only_write) {
    for(i=0; i<THRCNT; i++) {
      pthread_join(tid[i], &foo);
      fprintf(stderr, "[%d] joined, read %d\n", i, (int)foo);
    }
  }
  return 0;
}
/* vim:se ts=2 sw=2 et: */
