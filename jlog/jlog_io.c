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

/*
 * We want the single unix spec, so this define is needed on
 * the identity crisis that is Linux. pread()/pwrite()
 */
#include "jlog_config.h"
#include "jlog_hash.h"
#include "jlog_io.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static pthread_mutex_t jlog_files_lock = PTHREAD_MUTEX_INITIALIZER;
static jlog_hash_table jlog_files = JLOG_HASH_EMPTY;

typedef struct {
  dev_t st_dev;
  ino_t st_ino;
} jlog_file_id;

struct _jlog_file {
  jlog_file_id id;
  int fd;
  int refcnt;
  int locked;
  pthread_mutex_t lock;
};

jlog_file *jlog_file_open(const char *path, int flags, int mode)
{
  struct stat sb;
  jlog_file_id id;
  jlog_file *f = NULL;
  union {
    jlog_file *f;
    void *vptr;
  } pun;
  int fd, realflags = O_RDWR;

  if (flags & O_CREAT) realflags |= O_CREAT;
  if (flags & O_EXCL) realflags |= O_EXCL;

  if (pthread_mutex_lock(&jlog_files_lock) != 0) return NULL;

  if (stat(path, &sb) == 0) {
    if (!S_ISREG(sb.st_mode)) goto out;
    memset(&id, 0, sizeof(id));
    id.st_dev = sb.st_dev;
    id.st_ino = sb.st_ino;
    if (jlog_hash_retrieve(&jlog_files, (void *)&id, sizeof(jlog_file_id),
                           &pun.vptr))
    {
      if (!(flags & O_EXCL)) {
        f = pun.f;
        f->refcnt++;
      }
      goto out;
    }
  }

  if ((fd = open(path, realflags, mode)) == -1) goto out;
  if (fstat(fd, &sb) != 0) {
    while (close(fd) == -1 && errno == EINTR) ;
    goto out;
  }
  id.st_dev = sb.st_dev;
  id.st_ino = sb.st_ino;
  if (!(f = malloc(sizeof(jlog_file)))) {
    while (close(fd) == -1 && errno == EINTR) ;
    goto out;
  }
  memset(f, 0, sizeof(jlog_file));
  f->id = id;
  f->fd = fd;
  f->refcnt = 1;
  f->locked = 0;
  pthread_mutex_init(&(f->lock), NULL);
  if (!jlog_hash_store(&jlog_files, (void *)&f->id, sizeof(jlog_file_id), f)) {
    while (close(f->fd) == -1 && errno == EINTR) ;
    free(f);
    f = NULL;
  }
out:
  pthread_mutex_unlock(&jlog_files_lock);
  return f;
}

int jlog_file_close(jlog_file *f)
{
  if (pthread_mutex_lock(&jlog_files_lock) != 0) return 0;
  if (--f->refcnt == 0) {
    assert(jlog_hash_delete(&jlog_files, (void *)&f->id, sizeof(jlog_file_id),
                            NULL, NULL));
    while (close(f->fd) == -1 && errno == EINTR) ;
    free(f);
  }
  pthread_mutex_unlock(&jlog_files_lock);  
  return 1;
}

int jlog_file_lock(jlog_file *f)
{
  struct flock fl;
  int frv;

  memset(&fl, 0, sizeof(fl));
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 0;

  if (pthread_mutex_lock(&(f->lock)) != 0) return 0;
  while ((frv = fcntl(f->fd, F_SETLKW, &fl)) == -1 && errno == EINTR) ;
  if (frv != 0) {
    int save = errno;
    pthread_mutex_unlock(&(f->lock));
    errno = save;
    return 0;
  }
  f->locked = 1;
  return 1;
}

int jlog_file_unlock(jlog_file *f)
{
  struct flock fl;
  int frv;

  if (!f->locked) return 0;

  memset(&fl, 0, sizeof(fl));
  fl.l_type = F_UNLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 0;

  while ((frv = fcntl(f->fd, F_SETLKW, &fl)) == -1 && errno == EINTR) ;
  if (frv != 0) return 0;
  f->locked = 0;
  pthread_mutex_unlock(&(f->lock));
  return 1;
}

int jlog_file_pread(jlog_file *f, void *buf, size_t nbyte, off_t offset)
{
  while (nbyte > 0) {
    ssize_t rv = pread(f->fd, buf, nbyte, offset);
    if (rv == -1 && errno == EINTR) continue;
    if (rv <= 0) return 0;
    nbyte -= rv;
    offset += rv;
  }
  return 1;
}

int jlog_file_pwrite(jlog_file *f, const void *buf, size_t nbyte, off_t offset)
{
  while (nbyte > 0) {
    ssize_t rv = pwrite(f->fd, buf, nbyte, offset);
    if (rv == -1 && errno == EINTR) continue;
    if (rv <= 0) return 0;
    nbyte -= rv;
    offset += rv;
  }
  return 1;
}

int jlog_file_sync(jlog_file *f)
{
  int rv;

#ifdef HAVE_FDATASYNC
  while((rv = fdatasync(f->fd)) == -1 && errno == EINTR) ;
#else
  while((rv = fsync(f->fd)) == -1 && errno == EINTR) ;
#endif
  if (rv == 0) return 1;
  return 0;
}

int jlog_file_map_read(jlog_file *f, void **base, size_t *len)
{
  struct stat sb;
  void *my_map;
  int flags = 0;

#ifdef MAP_SHARED
  flags = MAP_SHARED;
#endif
  if (fstat(f->fd, &sb) != 0) return 0;
  my_map = mmap(NULL, sb.st_size, PROT_READ, flags, f->fd, 0);
  if (my_map == MAP_FAILED) return 0;
  *base = my_map;
  *len = sb.st_size;
  return 1;
}

off_t jlog_file_size(jlog_file *f)
{
  struct stat sb;
  int rv;
  while ((rv = fstat(f->fd, &sb) != 0) == -1 && errno == EINTR) ;
  if (rv != 0) return -1;
  return sb.st_size;
}

int jlog_file_truncate(jlog_file *f, off_t len)
{
  int rv;
  while ((rv = ftruncate(f->fd, len)) == -1 && errno == EINTR) ;
  if (rv == 0) return 1;
  return 0;
}

/* vim:se ts=2 sw=2 et: */
