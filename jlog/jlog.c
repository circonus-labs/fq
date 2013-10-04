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

/*****************************************************************

  Journaled logging... append only.

      (1) find current file, or allocate a file, extendible and mark
          it current.
 
      (2) Write records to it, records include their size, so
          a simple inspection can detect and incomplete trailing
          record.
    
      (3) Write append until the file reaches a certain size.

      (4) Allocate a file, extensible.

      (5) RESYNC INDEX on 'finished' file (see reading:3) and postpend
          an offset '0' to the index.
    
      (2) goto (1)
    
  Reading journals...

      (1) find oldest checkpoint of all subscribers, remove all older files.

      (2) (file, last_read) = find_checkpoint for this subscriber

      (3) RESYNC INDEX:
          open record index for file, seek to the end -  off_t.
          this is the offset of the last noticed record in this file.
          open file, seek to this point, roll forward writing the index file
          _do not_ write an offset for the last record unless it is found
          complete.

      (4) read entries from last_read+1 -> index of record index

*/
#include <stdio.h>

#include "jlog_config.h"
#include "jlog_private.h"
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_DIRENT_H
#include <dirent.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif
#if HAVE_TIME_H
#include <time.h>
#endif
#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#define BUFFERED_INDICES 1024

static jlog_file *__jlog_open_writer(jlog_ctx *ctx);
static int __jlog_close_writer(jlog_ctx *ctx);
static jlog_file *__jlog_open_reader(jlog_ctx *ctx, u_int32_t log);
static int __jlog_close_reader(jlog_ctx *ctx);
static int __jlog_close_checkpoint(jlog_ctx *ctx);
static jlog_file *__jlog_open_indexer(jlog_ctx *ctx, u_int32_t log);
static int __jlog_close_indexer(jlog_ctx *ctx);
static int __jlog_resync_index(jlog_ctx *ctx, u_int32_t log, jlog_id *last, int *c);
static jlog_file *__jlog_open_named_checkpoint(jlog_ctx *ctx, const char *cpname, int flags);
static int __jlog_mmap_reader(jlog_ctx *ctx, u_int32_t log);
static int __jlog_munmap_reader(jlog_ctx *ctx);

int jlog_snprint_logid(char *b, int n, const jlog_id *id) {
  return snprintf(b, n, "%08x:%08x", id->log, id->marker);
}

int jlog_repair_datafile(jlog_ctx *ctx, u_int32_t log)
{
  jlog_message_header hdr;
  char *this, *next, *afternext = NULL, *mmap_end;
  int i, invalid_count = 0;
  struct {
    off_t start, end;
  } *invalid = NULL;
  off_t orig_len, src, dst, len;

#define TAG_INVALID(s, e) do { \
  if (invalid_count) \
    invalid = realloc(invalid, (invalid_count + 1) * sizeof(*invalid)); \
  else \
    invalid = malloc(sizeof(*invalid)); \
  invalid[invalid_count].start = s - (char *)ctx->mmap_base; \
  invalid[invalid_count].end = e - (char *)ctx->mmap_base; \
  invalid_count++; \
} while (0)

  ctx->last_error = JLOG_ERR_SUCCESS;

  /* we want the reader's open logic because this runs in the read path
   * the underlying fds are always RDWR anyway */
  __jlog_open_reader(ctx, log);
  if (!ctx->data) {
    ctx->last_error = JLOG_ERR_FILE_OPEN;
    ctx->last_errno = errno;
    return -1;
  }
  if (!jlog_file_lock(ctx->data)) {
    ctx->last_error = JLOG_ERR_LOCK;
    ctx->last_errno = errno;
    return -1;
  }
  if (__jlog_mmap_reader(ctx, log) != 0)
    SYS_FAIL(JLOG_ERR_FILE_READ);

  orig_len = ctx->mmap_len;
  mmap_end = (char*)ctx->mmap_base + ctx->mmap_len;
  /* these values will cause us to fall right into the error clause and
   * start searching for a valid header from offset 0 */
  this = (char*)ctx->mmap_base - sizeof(hdr);
  hdr.reserved = 0;
  hdr.mlen = 0;

  while (this + sizeof(hdr) <= mmap_end) {
    next = this + sizeof(hdr) + hdr.mlen;
    if (next <= (char *)ctx->mmap_base) goto error;
    if (next == mmap_end) {
      this = next;
      break;
    }
    if (next + sizeof(hdr) > mmap_end) goto error;
    memcpy(&hdr, next, sizeof(hdr));
    if (hdr.reserved != 0) goto error;
    this = next;
    continue;
  error:
    for (next = this + sizeof(hdr); next + sizeof(hdr) <= mmap_end; next++) {
      if (!next[0] && !next[1] && !next[2] && !next[3]) {
        memcpy(&hdr, next, sizeof(hdr));
        afternext = next + sizeof(hdr) + hdr.mlen;
        if (afternext <= (char *)ctx->mmap_base) continue;
        if (afternext == mmap_end) break;
        if (afternext + sizeof(hdr) > mmap_end) continue;
        memcpy(&hdr, afternext, sizeof(hdr));
        if (hdr.reserved == 0) break;
      }
    }
    /* correct for while loop entry condition */
    if (this < (char *)ctx->mmap_base) this = ctx->mmap_base;
    if (next + sizeof(hdr) > mmap_end) break;
    if (next > this) TAG_INVALID(this, next);
    this = afternext;
  }
  if (this != mmap_end) TAG_INVALID(this, mmap_end);

#undef TAG_INVALID

#define MOVE_SEGMENT do { \
  char cpbuff[4096]; \
  off_t chunk; \
  while(len > 0) { \
    chunk = len; \
    if (chunk > (off_t)sizeof(cpbuff)) chunk = sizeof(cpbuff); \
    if (!jlog_file_pread(ctx->data, &cpbuff, chunk, src)) \
      SYS_FAIL(JLOG_ERR_FILE_READ); \
    if (!jlog_file_pwrite(ctx->data, &cpbuff, chunk, dst)) \
      SYS_FAIL(JLOG_ERR_FILE_WRITE); \
    src += chunk; \
    dst += chunk; \
    len -= chunk; \
  } \
} while (0)

  if (invalid_count > 0) {
    __jlog_munmap_reader(ctx);
    dst = invalid[0].start;
    for (i = 0; i < invalid_count - 1; ) {
      src = invalid[i].end;
      len = invalid[++i].start - src;
      MOVE_SEGMENT;
    }
    src = invalid[invalid_count - 1].end;
    len = orig_len - src;
    if (len > 0) MOVE_SEGMENT;
    if (!jlog_file_truncate(ctx->data, dst))
      SYS_FAIL(JLOG_ERR_FILE_WRITE);
  }

#undef MOVE_SEGMENT

finish:
  jlog_file_unlock(ctx->data);
  if (invalid) free(invalid);
  if (ctx->last_error != JLOG_ERR_SUCCESS) return -1;
  return invalid_count;
}

int jlog_inspect_datafile(jlog_ctx *ctx, u_int32_t log)
{
  jlog_message_header hdr;
  char *this, *next, *mmap_end;
  int i;
  time_t timet;
  struct tm tm;
  char tbuff[128];

  ctx->last_error = JLOG_ERR_SUCCESS;

  __jlog_open_reader(ctx, log);
  if (!ctx->data)
    SYS_FAIL(JLOG_ERR_FILE_OPEN);
  if (__jlog_mmap_reader(ctx, log) != 0)
    SYS_FAIL(JLOG_ERR_FILE_READ);

  mmap_end = (char*)ctx->mmap_base + ctx->mmap_len;
  this = ctx->mmap_base;
  i = 0;
  while (this + sizeof(hdr) <= mmap_end) {
    memcpy(&hdr, this, sizeof(hdr));
    i++;
    if (hdr.reserved != 0) {
      fprintf(stderr, "Message %d at [%ld] has invalid reserved value %u\n",
              i, (long int)(this - (char *)ctx->mmap_base), hdr.reserved);
      return 1;
    }

    fprintf(stderr, "Message %d at [%ld] of (%lu+%u)", i, 
            (long int)(this - (char *)ctx->mmap_base),
            (long unsigned int)sizeof(hdr), hdr.mlen);

    next = this + sizeof(hdr) + hdr.mlen;
    if (next <= (char *)ctx->mmap_base) {
      fprintf(stderr, " WRAPPED TO NEGATIVE OFFSET!\n");
      return 1;
    }
    if (next > mmap_end) {
      fprintf(stderr, " OFF THE END!\n");
      return 1;
    }

    timet = hdr.tv_sec;
    localtime_r(&timet, &tm);
    strftime(tbuff, sizeof(tbuff), "%c", &tm);
    fprintf(stderr, "\n\ttime: %s\n\tmlen: %u\n", tbuff, hdr.mlen);
    this = next;
  }
  if (this < mmap_end) {
    fprintf(stderr, "%ld bytes of junk at the end\n",
            (long int)(mmap_end - this));
    return 1;
  }

  return 0;
finish:
  return -1;
}

int jlog_idx_details(jlog_ctx *ctx, u_int32_t log,
                     u_int32_t *marker, int *closed)
{
  off_t index_len;
  u_int64_t index;

  __jlog_open_indexer(ctx, log);
  if (!ctx->index)
    SYS_FAIL(JLOG_ERR_IDX_OPEN);
  if ((index_len = jlog_file_size(ctx->index)) == -1)
    SYS_FAIL(JLOG_ERR_IDX_SEEK);
  if (index_len % sizeof(u_int64_t))
    SYS_FAIL(JLOG_ERR_IDX_CORRUPT);
  if (index_len > (off_t)sizeof(u_int64_t)) {
    if (!jlog_file_pread(ctx->index, &index, sizeof(u_int64_t),
                         index_len - sizeof(u_int64_t)))
    {
      SYS_FAIL(JLOG_ERR_IDX_READ);
    }
    if (index) {
      *marker = index_len / sizeof(u_int64_t);
      *closed = 0;
    } else {
      *marker = (index_len / sizeof(u_int64_t)) - 1;
      *closed = 1;
    }
  } else {
    *marker = index_len / sizeof(u_int64_t);
    *closed = 0;
  }

  return 0;
finish:
  return -1;
}

static int __jlog_unlink_datafile(jlog_ctx *ctx, u_int32_t log) {
  char file[MAXPATHLEN];
  int len;

  if(ctx->current_log == log) {
    __jlog_close_reader(ctx);
    __jlog_close_indexer(ctx);
  }

  STRSETDATAFILE(ctx, file, log);
#ifdef JLOG_DEBUG
  fprintf(stderr, "unlinking %s\n", file);
#endif
  unlink(file);

  len = strlen(file);
  if((len + sizeof(INDEX_EXT)) > sizeof(file)) return -1;
  memcpy(file + len, INDEX_EXT, sizeof(INDEX_EXT));
#ifdef JLOG_DEBUG
  fprintf(stderr, "unlinking %s\n", file);
#endif
  unlink(file);
  return 0;
}

static int __jlog_open_metastore(jlog_ctx *ctx)
{
  char file[MAXPATHLEN];
  int len;

#ifdef JLOG_DEBUG
  fprintf(stderr, "__jlog_open_metastore\n");
#endif
  len = strlen(ctx->path);
  if((len + 1 /* IFS_CH */ + 9 /* "metastore" */ + 1) > MAXPATHLEN) {
#ifdef ENAMETOOLONG
    ctx->last_errno = ENAMETOOLONG;
#endif
    ctx->last_error = JLOG_ERR_CREATE_META;
    return -1;
  }
  memcpy(file, ctx->path, len);
  file[len++] = IFS_CH;
  memcpy(&file[len], "metastore", 10); /* "metastore" + '\0' */

  ctx->metastore = jlog_file_open(file, O_CREAT, ctx->file_mode);

  if (!ctx->metastore) {
    ctx->last_errno = errno;
    ctx->last_error = JLOG_ERR_CREATE_META;
    return -1;
  }

  return 0;
}

/* exported */
int __jlog_pending_readers(jlog_ctx *ctx, u_int32_t log) {
  int readers;
  DIR *dir;
  struct dirent *ent;
  char file[MAXPATHLEN];
  int len;
  jlog_id id;

  readers = 0;

  dir = opendir(ctx->path);
  if (!dir) return -1;
  
  len = strlen(ctx->path);
  if(len + 2 > (int)sizeof(file)) return -1;
  memcpy(file, ctx->path, len);
  file[len++] = IFS_CH;
  file[len] = '\0';

  while ((ent = readdir(dir))) {
    if (ent->d_name[0] == 'c' && ent->d_name[1] == 'p' && ent->d_name[2] == '.') {
      jlog_file *cp;
      int dlen;

      dlen = strlen(ent->d_name);
      if((len + dlen + 1) > (int)sizeof(file)) continue;
      memcpy(file + len, ent->d_name, dlen + 1); /* include \0 */
#ifdef JLOG_DEBUG
      fprintf(stderr, "Checking if %s needs %s...\n", ent->d_name, ctx->path);
#endif
      if ((cp = jlog_file_open(file, 0, ctx->file_mode))) {
        if (jlog_file_lock(cp)) {
          jlog_file_pread(cp, &id, sizeof(id), 0);
#ifdef JLOG_DEBUG
          fprintf(stderr, "\t%u <= %u (pending reader)\n", id.log, log);
#endif
          if (id.log <= log) {
            readers++;
          }
          jlog_file_unlock(cp);
        }
        jlog_file_close(cp);
      }
    }
  }
  closedir(dir);
  return readers;
}
struct _jlog_subs {
  char **subs;
  int used;
  int allocd;
};

int jlog_ctx_list_subscribers_dispose(jlog_ctx *ctx, char **subs) {
  char *s;
  (void)ctx;
  int i = 0;
  if(subs) {
    while((s = subs[i++]) != NULL) free(s);
    free(subs);
  }
  return 0;
}

int jlog_ctx_list_subscribers(jlog_ctx *ctx, char ***subs) {
  struct _jlog_subs js = { NULL, 0, 0 };
  DIR *dir;
  struct dirent *ent;
  unsigned char file[MAXPATHLEN];
  char *p;
  int len;

  js.subs = calloc(16, sizeof(char *));
  js.allocd = 16;

  dir = opendir(ctx->path);
  if (!dir) return -1;
  while ((ent = readdir(dir))) {
    if (ent->d_name[0] == 'c' && ent->d_name[1] == 'p' && ent->d_name[2] == '.') {

      for (len = 0, p = ent->d_name + 3; *p;) {
        unsigned char c;
        int i;

        for (c = 0, i = 0; i < 16; i++) {
          if (__jlog_hexchars[i] == *p) {
            c = i << 4;
            break;
          }
        }
        p++;
        for (i = 0; i < 16; i++) {
          if (__jlog_hexchars[i] == *p) {
            c |= i;
            break;
          }
        }
        p++;
        file[len++] = c;
      }
      file[len] = '\0';

      js.subs[js.used++] = strdup((char *)file);
      if(js.used == js.allocd) {
        js.allocd *= 2;
        js.subs = realloc(js.subs, js.allocd*sizeof(char *));
      }
      js.subs[js.used] = NULL;
    }
  }
  closedir(dir);
  *subs = js.subs;
  return js.used;
}

static int __jlog_save_metastore(jlog_ctx *ctx, int ilocked)
{
  struct _jlog_meta_info info;
#ifdef JLOG_DEBUG
  fprintf(stderr, "__jlog_save_metastore\n");
#endif

  if (!ilocked && !jlog_file_lock(ctx->metastore)) {
    return -1;
  }

  info.storage_log = ctx->storage.log;
  info.unit_limit = ctx->unit_limit;
  info.safety = ctx->safety;

  if (!jlog_file_pwrite(ctx->metastore, &info, sizeof(info), 0)) {
    if (!ilocked) jlog_file_unlock(ctx->metastore);
    return -1;
  }
  if (ctx->safety == JLOG_SAFE) {
    jlog_file_sync(ctx->metastore);
  }

  if (!ilocked) jlog_file_unlock(ctx->metastore);
  return 0;
}

static int __jlog_restore_metastore(jlog_ctx *ctx, int ilocked)
{
  struct _jlog_meta_info info;
#ifdef JLOG_DEBUG
  fprintf(stderr, "__jlog_restore_metastore\n");
#endif

  if (!ilocked && !jlog_file_lock(ctx->metastore)) {
    return -1;
  }

  if (!jlog_file_pread(ctx->metastore, &info, sizeof(info), 0)) {
    if (!ilocked) jlog_file_unlock(ctx->metastore);
    return -1;
  }

  if (!ilocked) jlog_file_unlock(ctx->metastore);

  ctx->storage.log = info.storage_log;
  ctx->unit_limit = info.unit_limit;
  ctx->safety = info.safety;

  return 0;
}

int jlog_get_checkpoint(jlog_ctx *ctx, const char *s, jlog_id *id) {
  jlog_file *f;
  int rv = -1;

  if(ctx->subscriber_name && !strcmp(ctx->subscriber_name, s)) {
    if(!ctx->checkpoint) {
      ctx->checkpoint = __jlog_open_named_checkpoint(ctx, s, 0);
    }
    f = ctx->checkpoint;
  } else
    f = __jlog_open_named_checkpoint(ctx, s, 0);

  if (f) {
    if (jlog_file_lock(f)) {
      if (jlog_file_pread(f, id, sizeof(*id), 0)) rv = 0;
      jlog_file_unlock(f);
    }
  }
  if (f && f != ctx->checkpoint) jlog_file_close(f);
  return rv;
}

static int __jlog_set_checkpoint(jlog_ctx *ctx, const char *s, const jlog_id *id)
{
  jlog_file *f;
  int rv = -1;
  jlog_id old_id;
  u_int32_t log;

  if(ctx->subscriber_name && !strcmp(ctx->subscriber_name, s)) {
    if(!ctx->checkpoint) {
      ctx->checkpoint = __jlog_open_named_checkpoint(ctx, s, 0);
    }
    f = ctx->checkpoint;
  } else
    f = __jlog_open_named_checkpoint(ctx, s, 0);

  if(!f) return -1;
  if (!jlog_file_lock(f))
    goto failset;

  if (jlog_file_size(f) == 0) {
    /* we're setting it for the first time, no segments were pending on it */
    old_id.log = id->log;
  } else {
    if (!jlog_file_pread(f, &old_id, sizeof(old_id), 0))
      goto failset;
  }
  if (!jlog_file_pwrite(f, id, sizeof(*id), 0))
    goto failset;
  if (ctx->safety == JLOG_SAFE) {
    jlog_file_sync(f);
  }
  jlog_file_unlock(f);
  rv = 0;

  for (log = old_id.log; log < id->log; log++) {
    if (__jlog_pending_readers(ctx, log) == 0) {
      __jlog_unlink_datafile(ctx, log);
    }
  }

 failset:
  if (f && f != ctx->checkpoint) jlog_file_close(f);
  return rv;
}

static int __jlog_close_metastore(jlog_ctx *ctx) {
  if (ctx->metastore) {
    jlog_file_close(ctx->metastore);
    ctx->metastore = NULL;
  }
  return 0;
}

/* path is assumed to be MAXPATHLEN */
static char *compute_checkpoint_filename(jlog_ctx *ctx, const char *subscriber, char *name)
{
  const char *sub;
  int len;

  /* build checkpoint filename */
  len = strlen(ctx->path);
  memcpy(name, ctx->path, len);
  name[len++] = IFS_CH;
  name[len++] = 'c';
  name[len++] = 'p';
  name[len++] = '.';
  for (sub = subscriber; *sub; ) {
    name[len++] = __jlog_hexchars[((*sub & 0xf0) >> 4)];
    name[len++] = __jlog_hexchars[(*sub & 0x0f)];
    sub++;
  }
  name[len] = '\0';

#ifdef JLOG_DEBUG
  fprintf(stderr, "checkpoint %s filename is %s\n", subscriber, name);
#endif
  return name;
}

static jlog_file *__jlog_open_named_checkpoint(jlog_ctx *ctx, const char *cpname, int flags)
{
  char name[MAXPATHLEN];
  compute_checkpoint_filename(ctx, cpname, name);
  return jlog_file_open(name, flags, ctx->file_mode);
}

static jlog_file *__jlog_open_reader(jlog_ctx *ctx, u_int32_t log) {
  char file[MAXPATHLEN];

  if(ctx->current_log != log) {
    __jlog_close_reader(ctx);
    __jlog_close_indexer(ctx);
  }
  if(ctx->data) {
    return ctx->data;
  }
  STRSETDATAFILE(ctx, file, log);
#ifdef JLOG_DEBUG
  fprintf(stderr, "opening log file[ro]: '%s'\n", file);
#endif
  ctx->data = jlog_file_open(file, 0, ctx->file_mode);
  ctx->current_log = log;
  return ctx->data;
}

static int __jlog_munmap_reader(jlog_ctx *ctx) {
  if(ctx->mmap_base) {
    munmap(ctx->mmap_base, ctx->mmap_len);
    ctx->mmap_base = NULL;
    ctx->mmap_len = 0;
  }
  return 0;
}

static int __jlog_mmap_reader(jlog_ctx *ctx, u_int32_t log) {
  if(ctx->current_log == log && ctx->mmap_base) return 0;
  __jlog_open_reader(ctx, log);
  if(!ctx->data)
    return -1;
  if (!jlog_file_map_read(ctx->data, &ctx->mmap_base, &ctx->mmap_len)) {
    ctx->mmap_base = NULL;
    ctx->last_error = JLOG_ERR_FILE_READ;
    ctx->last_errno = errno;
    return -1;
  }
  return 0;
}

static jlog_file *__jlog_open_writer(jlog_ctx *ctx) {
  char file[MAXPATHLEN];

  if(ctx->data) {
    /* Still open */
    return ctx->data;
  }

  if(!jlog_file_lock(ctx->metastore))
    SYS_FAIL(JLOG_ERR_LOCK);
  if(__jlog_restore_metastore(ctx, 1))
    SYS_FAIL(JLOG_ERR_META_OPEN);
  STRSETDATAFILE(ctx, file, ctx->storage.log);
#ifdef JLOG_DEBUG
  fprintf(stderr, "opening log file[rw]: '%s'\n", file);
#endif
  ctx->data = jlog_file_open(file, O_CREAT, ctx->file_mode);
 finish:
  jlog_file_unlock(ctx->metastore);
  return ctx->data;
}

static int __jlog_close_writer(jlog_ctx *ctx) {
  if (ctx->data) {
    jlog_file_close(ctx->data);
    ctx->data = NULL;
  }
  return 0;
}

static int __jlog_close_reader(jlog_ctx *ctx) {
  __jlog_munmap_reader(ctx);
  if (ctx->data) {
    jlog_file_close(ctx->data);
    ctx->data = NULL;
  }
  return 0;
}

static int __jlog_close_checkpoint(jlog_ctx *ctx) {
  if (ctx->checkpoint) {
    jlog_file_close(ctx->checkpoint);
    ctx->checkpoint = NULL;
  }
  return 0;
}

static jlog_file *__jlog_open_indexer(jlog_ctx *ctx, u_int32_t log) {
  char file[MAXPATHLEN];
  int len;

  if(ctx->current_log != log) {
    __jlog_close_reader(ctx);
    __jlog_close_indexer(ctx);
  }
  if(ctx->index) {
    return ctx->index;
  }
  STRSETDATAFILE(ctx, file, log);

  len = strlen(file);
  if((len + sizeof(INDEX_EXT)) > sizeof(file)) return NULL;
  memcpy(file + len, INDEX_EXT, sizeof(INDEX_EXT));
#ifdef JLOG_DEBUG
  fprintf(stderr, "opening index file: '%s'\n", file);
#endif
  ctx->index = jlog_file_open(file, O_CREAT, ctx->file_mode);
  ctx->current_log = log;
  return ctx->index;
}

static int __jlog_close_indexer(jlog_ctx *ctx) {
  if (ctx->index) {
    jlog_file_close(ctx->index);
    ctx->index = NULL;
  }
  return 0;
}

static int
___jlog_resync_index(jlog_ctx *ctx, u_int32_t log, jlog_id *last,
                     int *closed) {
  jlog_message_header logmhdr;
  int i, second_try = 0;
  off_t index_off, data_off, data_len;
  u_int64_t index;
  u_int64_t indices[BUFFERED_INDICES];

  ctx->last_error = JLOG_ERR_SUCCESS;
  if(closed) *closed = 0;

  __jlog_open_reader(ctx, log);
  if (!ctx->data) {
    ctx->last_error = JLOG_ERR_FILE_OPEN;
    ctx->last_errno = errno;
    return -1;
  }

#define RESTART do { \
  if (second_try == 0) { \
    jlog_file_truncate(ctx->index, 0); \
    jlog_file_unlock(ctx->index); \
    second_try = 1; \
    ctx->last_error = JLOG_ERR_SUCCESS; \
    goto restart; \
  } \
  SYS_FAIL(JLOG_ERR_IDX_CORRUPT); \
} while (0)

restart:
  __jlog_open_indexer(ctx, log);
  if (!ctx->index) {
    ctx->last_error = JLOG_ERR_IDX_OPEN;
    ctx->last_errno = errno;
    return -1;
  }
  if (!jlog_file_lock(ctx->index)) {
    ctx->last_error = JLOG_ERR_LOCK;
    ctx->last_errno = errno;
    return -1;
  }

  data_off = 0;
  if ((data_len = jlog_file_size(ctx->data)) == -1)
    SYS_FAIL(JLOG_ERR_FILE_SEEK);
  if ((index_off = jlog_file_size(ctx->index)) == -1)
    SYS_FAIL(JLOG_ERR_IDX_SEEK);

  if (index_off % sizeof(u_int64_t)) {
#ifdef JLOG_DEBUG
    fprintf(stderr, "corrupt index [%llu]\n", index_off);
#endif
    RESTART;
  }

  if ((size_t)index_off > sizeof(u_int64_t)) {
    if (!jlog_file_pread(ctx->index, &index, sizeof(index),
                         index_off - sizeof(u_int64_t)))
    {
      SYS_FAIL(JLOG_ERR_IDX_READ);
    }
    if (index == 0) {
      /* This log file has been "closed" */
#ifdef JLOG_DEBUG
      fprintf(stderr, "index closed\n");
#endif
      if(last) {
        last->log = log;
        last->marker = (index_off / sizeof(u_int64_t)) - 1;
      }
      if(closed) *closed = 1;
      goto finish;
    } else {
      if ((off_t)index > data_len) {
#ifdef JLOG_DEBUG
        fprintf(stderr, "index told me to seek somehwere I can't\n");
#endif
        RESTART;
      }
      data_off = index;
    }
  }

  if (index_off > 0) {
    /* We are adding onto a partial index so we must advance a record */
    if (!jlog_file_pread(ctx->data, &logmhdr, sizeof(logmhdr), data_off))
      SYS_FAIL(JLOG_ERR_FILE_READ);
    if ((data_off += sizeof(logmhdr) + logmhdr.mlen) > data_len)
      RESTART;
  }

  i = 0;
  while (data_off + sizeof(logmhdr) <= (unsigned long long)data_len) {
    off_t next_off = data_off;

    if (!jlog_file_pread(ctx->data, &logmhdr, sizeof(logmhdr), data_off))
      SYS_FAIL(JLOG_ERR_FILE_READ);
    if (logmhdr.reserved != 0)
      SYS_FAIL(JLOG_ERR_FILE_CORRUPT);
    if ((next_off += sizeof(logmhdr) + logmhdr.mlen) > data_len)
      break;

    /* Write our new index offset */
    indices[i++] = data_off;
    if(i >= BUFFERED_INDICES) {
#ifdef JLOG_DEBUG
      fprintf(stderr, "writing %i offsets\n", i);
#endif
      if (!jlog_file_pwrite(ctx->index, indices, i * sizeof(u_int64_t), index_off))
        RESTART;
      index_off += i * sizeof(u_int64_t);
      i = 0;
    }
    data_off = next_off;
  }
  if(i > 0) {
#ifdef JLOG_DEBUG
    fprintf(stderr, "writing %i offsets\n", i);
#endif
    if (!jlog_file_pwrite(ctx->index, indices, i * sizeof(u_int64_t), index_off))
      RESTART;
    index_off += i * sizeof(u_int64_t);
  }
  if(last) {
    last->log = log;
    last->marker = index_off / sizeof(u_int64_t);
  }
  if(log < ctx->storage.log) {
    if (data_off != data_len) {
#ifdef JLOG_DEBUG
      fprintf(stderr, "closing index, but %llu != %llu\n", data_off, data_len);
#endif
      SYS_FAIL(JLOG_ERR_FILE_CORRUPT);
    }
    /* Special case: if we are closing, we next write a '0'
     * we can't write the closing marker if the data segment had no records
     * in it, since it will be confused with an index to offset 0 by the
     * next reader; this only happens when segments are repaired */
    if (index_off) {
      index = 0;
      if (!jlog_file_pwrite(ctx->index, &index, sizeof(u_int64_t), index_off))
        RESTART;
    }
    if(closed) *closed = 1;
  }
#undef RESTART

finish:
  jlog_file_unlock(ctx->index);
#ifdef JLOG_DEBUG
  fprintf(stderr, "index is %s\n", closed?(*closed?"closed":"open"):"unknown");
#endif
  if(ctx->last_error == JLOG_ERR_SUCCESS) return 0;
  return -1;
}

static int __jlog_resync_index(jlog_ctx *ctx, u_int32_t log, jlog_id *last, int *closed) {
  int attempts, rv = -1;
  for(attempts=0; attempts<4; attempts++) {
    rv = ___jlog_resync_index(ctx, log, last, closed);
    if(ctx->last_error == JLOG_ERR_SUCCESS) break;
    if(ctx->last_error == JLOG_ERR_FILE_OPEN ||
       ctx->last_error == JLOG_ERR_IDX_OPEN) break;

    /* We can't fix the file if someone may write to it again */
    if(log >= ctx->storage.log) break;

    jlog_file_lock(ctx->index);
    /* it doesn't really matter what jlog_repair_datafile returns
     * we'll keep retrying anyway */
    jlog_repair_datafile(ctx, log);
    jlog_file_truncate(ctx->index, 0);
    jlog_file_unlock(ctx->index);
  }
  return rv;
}

jlog_ctx *jlog_new(const char *path) {
  jlog_ctx *ctx;
  ctx = calloc(1, sizeof(*ctx));
  ctx->unit_limit = DEFAULT_UNIT_LIMIT;
  ctx->file_mode = DEFAULT_FILE_MODE;
  ctx->safety = DEFAULT_SAFETY;
  ctx->context_mode = JLOG_NEW;
  ctx->path = strdup(path);
  return ctx;
}

void jlog_set_error_func(jlog_ctx *ctx, jlog_error_func Func, void *ptr) {
  ctx->error_func = Func;
  ctx->error_ctx = ptr;
}

size_t jlog_raw_size(jlog_ctx *ctx) {
  DIR *d;
  struct dirent *de;
  size_t totalsize = 0;
  int ferr, len;
  char filename[MAXPATHLEN];

  d = opendir(ctx->path);
  if(!d) return 0;
  len = strlen(ctx->path);
  memcpy(filename, ctx->path, len);
  filename[len++] = IFS_CH;
  while((de = readdir(d)) != NULL) {
    struct stat sb;
    int dlen;

    dlen = strlen(de->d_name);
    if((len + dlen + 1) > (int)sizeof(filename)) continue;
    memcpy(filename+len, de->d_name, dlen + 1); /* include \0 */
    while((ferr = stat(filename, &sb)) == -1 && errno == EINTR);
    if(ferr == 0 && S_ISREG(sb.st_mode)) totalsize += sb.st_size;
  }
  closedir(d);
  return totalsize;
}

const char *jlog_ctx_err_string(jlog_ctx *ctx) {
  switch (ctx->last_error) {
#define MSG_O_MATIC(x)  case x: return #x;
    MSG_O_MATIC( JLOG_ERR_SUCCESS);
    MSG_O_MATIC( JLOG_ERR_ILLEGAL_INIT);
    MSG_O_MATIC( JLOG_ERR_ILLEGAL_OPEN);
    MSG_O_MATIC( JLOG_ERR_OPEN);
    MSG_O_MATIC( JLOG_ERR_NOTDIR);
    MSG_O_MATIC( JLOG_ERR_CREATE_PATHLEN);
    MSG_O_MATIC( JLOG_ERR_CREATE_EXISTS);
    MSG_O_MATIC( JLOG_ERR_CREATE_MKDIR);
    MSG_O_MATIC( JLOG_ERR_CREATE_META);
    MSG_O_MATIC( JLOG_ERR_LOCK);
    MSG_O_MATIC( JLOG_ERR_IDX_OPEN);
    MSG_O_MATIC( JLOG_ERR_IDX_SEEK);
    MSG_O_MATIC( JLOG_ERR_IDX_CORRUPT);
    MSG_O_MATIC( JLOG_ERR_IDX_WRITE);
    MSG_O_MATIC( JLOG_ERR_IDX_READ);
    MSG_O_MATIC( JLOG_ERR_FILE_OPEN);
    MSG_O_MATIC( JLOG_ERR_FILE_SEEK);
    MSG_O_MATIC( JLOG_ERR_FILE_CORRUPT);
    MSG_O_MATIC( JLOG_ERR_FILE_READ);
    MSG_O_MATIC( JLOG_ERR_FILE_WRITE);
    MSG_O_MATIC( JLOG_ERR_META_OPEN);
    MSG_O_MATIC( JLOG_ERR_ILLEGAL_WRITE);
    MSG_O_MATIC( JLOG_ERR_ILLEGAL_CHECKPOINT);
    MSG_O_MATIC( JLOG_ERR_INVALID_SUBSCRIBER);
    MSG_O_MATIC( JLOG_ERR_ILLEGAL_LOGID);
    MSG_O_MATIC( JLOG_ERR_SUBSCRIBER_EXISTS);
    MSG_O_MATIC( JLOG_ERR_CHECKPOINT);
    MSG_O_MATIC( JLOG_ERR_NOT_SUPPORTED);
    default: return "Unknown";
  }
}

int jlog_ctx_err(jlog_ctx *ctx) {
  return ctx->last_error;
}

int jlog_ctx_errno(jlog_ctx *ctx) {
  return ctx->last_errno;
}

int jlog_ctx_alter_safety(jlog_ctx *ctx, jlog_safety safety) {
  if(ctx->context_mode != JLOG_NEW) return -1;
  ctx->safety = safety;
  return 0;
}
int jlog_ctx_alter_journal_size(jlog_ctx *ctx, size_t size) {
  if(ctx->context_mode != JLOG_NEW) return -1;
  ctx->unit_limit = size;
  return 0;
}
int jlog_ctx_alter_mode(jlog_ctx *ctx, int mode) {
  ctx->file_mode = mode;
  return 0;
}
int jlog_ctx_open_writer(jlog_ctx *ctx) {
  int rv;
  struct stat sb;

  ctx->last_error = JLOG_ERR_SUCCESS;
  if(ctx->context_mode != JLOG_NEW) {
    ctx->last_error = JLOG_ERR_ILLEGAL_OPEN;
    return -1;
  }
  ctx->context_mode = JLOG_APPEND;
  while((rv = stat(ctx->path, &sb)) == -1 && errno == EINTR);
  if(rv == -1) SYS_FAIL(JLOG_ERR_OPEN);
  if(!S_ISDIR(sb.st_mode)) SYS_FAIL(JLOG_ERR_NOTDIR);
  if(__jlog_open_metastore(ctx) != 0) SYS_FAIL(JLOG_ERR_META_OPEN);
  if(__jlog_restore_metastore(ctx, 0)) SYS_FAIL(JLOG_ERR_META_OPEN);
 finish:
  if(ctx->last_error == JLOG_ERR_SUCCESS) return 0;
  ctx->context_mode = JLOG_INVALID;
  return -1;
}
int jlog_ctx_open_reader(jlog_ctx *ctx, const char *subscriber) {
  int rv;
  struct stat sb;
  jlog_id dummy;

  ctx->last_error = JLOG_ERR_SUCCESS;
  if(ctx->context_mode != JLOG_NEW) {
    ctx->last_error = JLOG_ERR_ILLEGAL_OPEN;
    return -1;
  }
  ctx->context_mode = JLOG_READ;
  ctx->subscriber_name = strdup(subscriber);
  while((rv = stat(ctx->path, &sb)) == -1 && errno == EINTR);
  if(rv == -1) SYS_FAIL(JLOG_ERR_OPEN);
  if(!S_ISDIR(sb.st_mode)) SYS_FAIL(JLOG_ERR_NOTDIR);
  if(__jlog_open_metastore(ctx) != 0) SYS_FAIL(JLOG_ERR_META_OPEN);
  if(jlog_get_checkpoint(ctx, ctx->subscriber_name, &dummy))
    SYS_FAIL(JLOG_ERR_INVALID_SUBSCRIBER);
  if(__jlog_restore_metastore(ctx, 0)) SYS_FAIL(JLOG_ERR_META_OPEN);
 finish:
  if(ctx->last_error == JLOG_ERR_SUCCESS) return 0;
  ctx->context_mode = JLOG_INVALID;
  return -1;
}
int jlog_ctx_init(jlog_ctx *ctx) {
  int rv;
  struct stat sb;
  int dirmode;

  ctx->last_error = JLOG_ERR_SUCCESS;
  if(strlen(ctx->path) > MAXLOGPATHLEN-1) {
    ctx->last_error = JLOG_ERR_CREATE_PATHLEN;
    return -1;
  }
  if(ctx->context_mode != JLOG_NEW) {
    ctx->last_error = JLOG_ERR_ILLEGAL_INIT;
    return -1;
  }
  ctx->context_mode = JLOG_INIT;
  while((rv = stat(ctx->path, &sb)) == -1 && errno == EINTR);
  if(rv == 0 || errno != ENOENT) {
    SYS_FAIL_EX(JLOG_ERR_CREATE_EXISTS, 0);
  }
  dirmode = ctx->file_mode;
  if(dirmode & 0400) dirmode |= 0100;
  if(dirmode & 040) dirmode |= 010;
  if(dirmode & 04) dirmode |= 01;
  if(mkdir(ctx->path, dirmode) == -1)
    SYS_FAIL(JLOG_ERR_CREATE_MKDIR);
  chmod(ctx->path, dirmode);
  /* Setup our initial state and store our instance metadata */
  if(__jlog_open_metastore(ctx) != 0)
    SYS_FAIL(JLOG_ERR_CREATE_META);
  if(__jlog_save_metastore(ctx, 0) != 0)
    SYS_FAIL(JLOG_ERR_CREATE_META);
 finish:
  if(ctx->last_error == JLOG_ERR_SUCCESS) return 0;
  return -1;
}
int jlog_ctx_close(jlog_ctx *ctx) {
  __jlog_close_indexer(ctx);
  __jlog_close_reader(ctx);
  __jlog_close_metastore(ctx);
  __jlog_close_checkpoint(ctx);
  if(ctx->subscriber_name) free(ctx->subscriber_name);
  if(ctx->path) free(ctx->path);
  free(ctx);
  return 0;
}

static int __jlog_metastore_atomic_increment(jlog_ctx *ctx) {
  u_int32_t saved_storage_log = ctx->storage.log;
#ifdef JLOG_DEBUG
  fprintf(stderr, "atomic increment on %u\n", saved_storage_log);
#endif
  if (!jlog_file_lock(ctx->metastore))
    SYS_FAIL(JLOG_ERR_LOCK);
  if(__jlog_restore_metastore(ctx, 1))
    SYS_FAIL(JLOG_ERR_META_OPEN);
  if(ctx->storage.log == saved_storage_log) {
    /* We're the first ones to it, so we get to increment it */
    ctx->storage.log++;
    if(__jlog_save_metastore(ctx, 1))
      SYS_FAIL(JLOG_ERR_META_OPEN);
  }
 finish:
  jlog_file_unlock(ctx->metastore);
  if(ctx->last_error == JLOG_ERR_SUCCESS) return 0;
  return -1;
}
int jlog_ctx_write_message(jlog_ctx *ctx, jlog_message *mess, struct timeval *when) {
  struct timeval now;
  jlog_message_header hdr;
  off_t current_offset;

  ctx->last_error = JLOG_ERR_SUCCESS;
  if(ctx->context_mode != JLOG_APPEND) {
    ctx->last_error = JLOG_ERR_ILLEGAL_WRITE;
    ctx->last_errno = EPERM;
    return -1;
  }
 begin:
  __jlog_open_writer(ctx);
  if(!ctx->data) {
    ctx->last_error = JLOG_ERR_FILE_OPEN;
    ctx->last_errno = errno;
    return -1;
  }
  if (!jlog_file_lock(ctx->data)) {
    ctx->last_error = JLOG_ERR_LOCK;
    ctx->last_errno = errno;
    return -1;
  }

  if ((current_offset = jlog_file_size(ctx->data)) == -1)
    SYS_FAIL(JLOG_ERR_FILE_SEEK);
  if(ctx->unit_limit <= (unsigned long long)current_offset) {
    jlog_file_unlock(ctx->data);
    __jlog_close_writer(ctx);
    __jlog_metastore_atomic_increment(ctx);
    goto begin;
  }

  hdr.reserved = 0;
  if (when) {
    hdr.tv_sec = when->tv_sec;
    hdr.tv_usec = when->tv_usec;
  } else {
    gettimeofday(&now, NULL);
    hdr.tv_sec = now.tv_sec;
    hdr.tv_usec = now.tv_usec;
  }
  hdr.mlen = mess->mess_len;
  if (!jlog_file_pwrite(ctx->data, &hdr, sizeof(hdr), current_offset))
    SYS_FAIL(JLOG_ERR_FILE_WRITE);
  current_offset += sizeof(hdr);
  if (!jlog_file_pwrite(ctx->data, mess->mess, mess->mess_len, current_offset))
    SYS_FAIL(JLOG_ERR_FILE_WRITE);
  current_offset += mess->mess_len;

  if(ctx->unit_limit <= (unsigned long long)current_offset) {
    jlog_file_unlock(ctx->data);
    __jlog_close_writer(ctx);
    __jlog_metastore_atomic_increment(ctx);
    return 0;
  }
 finish:
  jlog_file_unlock(ctx->data);
  if(ctx->last_error == JLOG_ERR_SUCCESS) return 0;
  return -1;
}
int jlog_ctx_read_checkpoint(jlog_ctx *ctx, const jlog_id *chkpt) {
  ctx->last_error = JLOG_ERR_SUCCESS;
  
  if(ctx->context_mode != JLOG_READ) {
    ctx->last_error = JLOG_ERR_ILLEGAL_CHECKPOINT;
    ctx->last_errno = EPERM;
    return -1;
  }
  if(__jlog_set_checkpoint(ctx, ctx->subscriber_name, chkpt) != 0) {
    ctx->last_error = JLOG_ERR_CHECKPOINT;
    ctx->last_errno = 0;
    return -1;
  }
  return 0;
}

int jlog_ctx_remove_subscriber(jlog_ctx *ctx, const char *s) {
  char name[MAXPATHLEN];
  int rv;

  compute_checkpoint_filename(ctx, s, name);
  rv = unlink(name);

  if (rv == 0) {
    ctx->last_error = JLOG_ERR_SUCCESS;
    return 1;
  }
  if (errno == ENOENT) {
    ctx->last_error = JLOG_ERR_INVALID_SUBSCRIBER;
    return 0;
  }
  return -1;
}

int jlog_ctx_add_subscriber(jlog_ctx *ctx, const char *s, jlog_position whence) {
  jlog_id chkpt;
  jlog_ctx *tmpctx = NULL;
  jlog_file *jchkpt;
  ctx->last_error = JLOG_ERR_SUCCESS;

  jchkpt = __jlog_open_named_checkpoint(ctx, s, O_CREAT|O_EXCL);
  if(!jchkpt) {
    ctx->last_error = JLOG_ERR_SUBSCRIBER_EXISTS;
    ctx->last_errno = EEXIST;
    return -1;
  }
  jlog_file_close(jchkpt);
  
  if(whence == JLOG_BEGIN) {
    memset(&chkpt, 0, sizeof(chkpt));
    jlog_ctx_first_log_id(ctx, &chkpt);
    if(__jlog_set_checkpoint(ctx, s, &chkpt) != 0) {
      ctx->last_error = JLOG_ERR_CHECKPOINT;
      ctx->last_errno = 0;
      return -1;
    }
    return 0;
  }
  if(whence == JLOG_END) {
    jlog_id start, finish;
    memset(&chkpt, 0, sizeof(chkpt));
    if(__jlog_open_metastore(ctx) != 0) SYS_FAIL(JLOG_ERR_META_OPEN);
    if(__jlog_restore_metastore(ctx, 0))
      SYS_FAIL(JLOG_ERR_META_OPEN);
    chkpt.log = ctx->storage.log;
    if(__jlog_set_checkpoint(ctx, s, &chkpt) != 0)
      SYS_FAIL(JLOG_ERR_CHECKPOINT);
    tmpctx = jlog_new(ctx->path);
    if(jlog_ctx_open_reader(tmpctx, s) < 0) goto finish;
    if(jlog_ctx_read_interval(tmpctx, &start, &finish) < 0) goto finish;
    jlog_ctx_close(tmpctx);
    tmpctx = NULL;
    if(__jlog_set_checkpoint(ctx, s, &finish) != 0)
      SYS_FAIL(JLOG_ERR_CHECKPOINT);
    return 0;
  }
  ctx->last_error = JLOG_ERR_NOT_SUPPORTED;
 finish:
  if(tmpctx) jlog_ctx_close(tmpctx);
  return -1;
}

int jlog_ctx_write(jlog_ctx *ctx, const void *data, size_t len) {
  jlog_message m;
  m.mess = (void *)data;
  m.mess_len = len;
  return jlog_ctx_write_message(ctx, &m, NULL);
}

static int __jlog_find_first_log_after(jlog_ctx *ctx, jlog_id *chkpt,
                                jlog_id *start, jlog_id *finish) {
  jlog_id last;
  int closed;
  
  memcpy(start, chkpt, sizeof(*chkpt));
 attempt:
  if(__jlog_resync_index(ctx, start->log, &last, &closed) != 0) {
    if(ctx->last_error == JLOG_ERR_FILE_OPEN &&
        ctx->last_errno == ENOENT) {
      char file[MAXPATHLEN];
      int ferr, len;
      struct stat sb;

      memset(&sb, 0, sizeof(sb));
      STRSETDATAFILE(ctx, file, start->log + 1);
      while((ferr = stat(file, &sb)) == -1 && errno == EINTR);
      /* That file doesn't exist... bad, but we can fake a recovery by
         advancing the next file that does exist */
      ctx->last_error = JLOG_ERR_SUCCESS;
      if(start->log >= ctx->storage.log || ferr != 0 || sb.st_size == 0) {
        /* We don't advance past where people are writing */
        memcpy(finish, start, sizeof(*start));
        return 0;
      }
      if(__jlog_resync_index(ctx, start->log + 1, &last, &closed) != 0) {
        /* We don't advance past where people are writing */
        memcpy(finish, start, sizeof(*start));
        return 0;
      }
      len = strlen(file);
      if((len + sizeof(INDEX_EXT)) > sizeof(file)) return -1;
      memcpy(file + len, INDEX_EXT, sizeof(INDEX_EXT));
      while((ferr = stat(file, &sb)) == -1 && errno == EINTR);
      if(ferr != 0 || sb.st_size == 0) {
        /* We don't advance past where people are writing */
        memcpy(finish, start, sizeof(*start));
        return 0;
      }
      start->marker = 0;
      start->log++;  /* BE SMARTER! */
      goto attempt;
    }
    return -1; /* Just persist resync's error state */
  }

  /* If someone checkpoints off the end, be nice */
  if(last.log == start->log && last.marker < start->marker)
    memcpy(start, &last, sizeof(*start));

  if(!memcmp(start, &last, sizeof(last)) && closed) {
    char file[MAXPATHLEN];
    int ferr, len;
    struct stat sb;

    memset(&sb, 0, sizeof(sb));
    STRSETDATAFILE(ctx, file, start->log + 1);
    while((ferr = stat(file, &sb)) == -1 && errno == EINTR);
    if(start->log >= ctx->storage.log || ferr != 0 || sb.st_size == 0) {
      /* We don't advance past where people are writing */
      memcpy(finish, start, sizeof(*start));
      return 0;
    }
    if(__jlog_resync_index(ctx, start->log + 1, &last, &closed) != 0) {
      /* We don't advance past where people are writing */
      memcpy(finish, start, sizeof(*start));
      return 0;
    }
    len = strlen(file);
    if((len + sizeof(INDEX_EXT)) > sizeof(file)) return -1;
    memcpy(file + len, INDEX_EXT, sizeof(INDEX_EXT));
    while((ferr = stat(file, &sb)) == -1 && errno == EINTR);
    if(ferr != 0 || sb.st_size == 0) {
      /* We don't advance past where people are writing */
      memcpy(finish, start, sizeof(*start));
      return 0;
    }
    start->marker = 0;
    start->log++;
    goto attempt;
  }
  memcpy(finish, &last, sizeof(last));
  return 0;
}
int jlog_ctx_read_message(jlog_ctx *ctx, const jlog_id *id, jlog_message *m) {
  off_t index_len;
  u_int64_t data_off;

  ctx->last_error = JLOG_ERR_SUCCESS;
  if (ctx->context_mode != JLOG_READ)
    SYS_FAIL(JLOG_ERR_ILLEGAL_WRITE);
  if (id->marker < 1) {
    SYS_FAIL(JLOG_ERR_ILLEGAL_LOGID);
  }

  __jlog_open_reader(ctx, id->log);
  if(!ctx->data)
    SYS_FAIL(JLOG_ERR_FILE_OPEN);
  __jlog_open_indexer(ctx, id->log);
  if(!ctx->index)
    SYS_FAIL(JLOG_ERR_IDX_OPEN);

  if ((index_len = jlog_file_size(ctx->index)) == -1)
    SYS_FAIL(JLOG_ERR_IDX_SEEK);
  if (index_len % sizeof(u_int64_t))
    SYS_FAIL(JLOG_ERR_IDX_CORRUPT);
  if (id->marker * sizeof(u_int64_t) > (unsigned long long)index_len) {
    SYS_FAIL(JLOG_ERR_ILLEGAL_LOGID);
  }

  if (!jlog_file_pread(ctx->index, &data_off, sizeof(u_int64_t),
                       (id->marker - 1) * sizeof(u_int64_t)))
  {
    SYS_FAIL(JLOG_ERR_IDX_READ);
  }
  if (data_off == 0 && id->marker != 1) {
    if (id->marker * sizeof(u_int64_t) == (unsigned long long)index_len) {
      /* close tag; not a real offset */
      SYS_FAIL(JLOG_ERR_ILLEGAL_LOGID);
    } else {
      /* an offset of 0 in the middle of an index means curruption */
      SYS_FAIL(JLOG_ERR_IDX_CORRUPT);
    }
  }

  if(__jlog_mmap_reader(ctx, id->log) != 0)
    SYS_FAIL(JLOG_ERR_FILE_READ);

  if(data_off > ctx->mmap_len - sizeof(jlog_message_header)) {
#ifdef JLOG_DEBUG
    fprintf(stderr, "read idx off end: %llu\n", data_off);
#endif
    SYS_FAIL(JLOG_ERR_IDX_CORRUPT);
  }

  memcpy(&m->aligned_header, ((u_int8_t *)ctx->mmap_base) + data_off,
         sizeof(jlog_message_header));

  if(data_off + sizeof(jlog_message_header) + m->aligned_header.mlen > ctx->mmap_len) {
#ifdef JLOG_DEBUG
    fprintf(stderr, "read idx off end: %llu %zd\n", data_off, ctx->mmap_len);
#endif
    SYS_FAIL(JLOG_ERR_IDX_CORRUPT);
  }

  m->header = &m->aligned_header;
  m->mess_len = m->header->mlen;
  m->mess = (((u_int8_t *)ctx->mmap_base) + data_off + sizeof(jlog_message_header));

 finish:
  if(ctx->last_error == JLOG_ERR_SUCCESS) return 0;
  if (ctx->last_error == JLOG_ERR_IDX_CORRUPT) {
    if (jlog_file_lock(ctx->index)) {
      jlog_file_truncate(ctx->index, 0);
      jlog_file_unlock(ctx->index);
    }
  }
  return -1;
}
int jlog_ctx_read_interval(jlog_ctx *ctx, jlog_id *start, jlog_id *finish) {
  jlog_id chkpt;
  int count = 0;

  ctx->last_error = JLOG_ERR_SUCCESS;
  if(ctx->context_mode != JLOG_READ) {
    ctx->last_error = JLOG_ERR_ILLEGAL_WRITE;
    ctx->last_errno = EPERM;
    return -1;
  }

  __jlog_restore_metastore(ctx, 0);
  if(jlog_get_checkpoint(ctx, ctx->subscriber_name, &chkpt))
    SYS_FAIL(JLOG_ERR_INVALID_SUBSCRIBER);
  if(__jlog_find_first_log_after(ctx, &chkpt, start, finish) != 0)
    goto finish; /* Leave whatever error was set in find_first_log_after */
  if(start->log != chkpt.log) start->marker = 0;
  else start->marker = chkpt.marker;
  if(start->log != chkpt.log) {
    /* We've advanced our checkpoint, let's not do this work again */
    if(__jlog_set_checkpoint(ctx, ctx->subscriber_name, start) != 0)
      SYS_FAIL(JLOG_ERR_CHECKPOINT);
  }
  /* Here 'start' is actually the checkpoint, so we must advance it one.
     However, that may not be possible, if there are no messages, so first
     make sure finish is bigger */
  count = finish->marker - start->marker;
  if(finish->marker > start->marker) start->marker++;

  /* We need to munmap it, so that we can remap it with more data if needed */
  __jlog_munmap_reader(ctx);
 finish:
  if(ctx->last_error == JLOG_ERR_SUCCESS) return count;
  return -1;
}

int jlog_ctx_first_log_id(jlog_ctx *ctx, jlog_id *id) {
  DIR *d;
  struct dirent *de;
  ctx->last_error = JLOG_ERR_SUCCESS;
  u_int32_t log;
  int found = 0;

  id->log = 0xffffffff;
  id->marker = 0;
  d = opendir(ctx->path);
  if (!d) return -1;

  while ((de = readdir(d))) {
    int i;
    char *cp = de->d_name;
    if(strlen(cp) != 8) continue;
    log = 0;
    for(i=0;i<8;i++) {
      log <<= 4;
      if(cp[i] >= '0' && cp[i] <= '9') log |= (cp[i] - '0');
      else if(cp[i] >= 'a' && cp[i] <= 'f') log |= (cp[i] - 'a' + 0xa);
      else if(cp[i] >= 'A' && cp[i] <= 'F') log |= (cp[i] - 'A' + 0xa);
      else break;
    }
    if(i != 8) continue;
    found = 1;
    if(log < id->log) id->log = log;
  }
  if(!found) id->log = 0;
  closedir(d);
  return 0;
}

int jlog_ctx_last_log_id(jlog_ctx *ctx, jlog_id *id) {
  ctx->last_error = JLOG_ERR_SUCCESS;
  if(ctx->context_mode != JLOG_READ) {
    ctx->last_error = JLOG_ERR_ILLEGAL_WRITE;
    ctx->last_errno = EPERM;
    return -1;
  }
  if (__jlog_restore_metastore(ctx, 0) != 0) return -1;
  ___jlog_resync_index(ctx, ctx->storage.log, id, NULL);
  if(ctx->last_error == JLOG_ERR_SUCCESS) return 0;
  return -1;
}

int jlog_ctx_advance_id(jlog_ctx *ctx, jlog_id *cur, 
                        jlog_id *start, jlog_id *finish)
{
  int rv;
  if(memcmp(cur, finish, sizeof(jlog_id))) {
    start->marker++;
  } else {
    if((rv = __jlog_find_first_log_after(ctx, cur, start, finish)) != 0) {
      return rv;
    }
    if(cur->log != start->log) {
      start->marker = 1;
    }
    else start->marker = cur->marker;
  }
  return 0;
}

/* vim:se ts=2 sw=2 et: */
