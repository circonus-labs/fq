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

#ifndef _JLOG_HASH_H
#define _JLOG_HASH_H

#include "jlog_config.h"

typedef void (*JLogHashFreeFunc)(void *);

typedef struct _jlog_hash_bucket {
  const char *k;
  int klen;
  void *data;
  struct _jlog_hash_bucket *next;
} jlog_hash_bucket;

typedef struct {
  jlog_hash_bucket **buckets;
  u_int32_t table_size;
  u_int32_t initval;
  u_int32_t num_used_buckets;
  u_int32_t size;
  unsigned dont_rebucket:1;
  unsigned _spare:31;
} jlog_hash_table;

#define JLOG_HASH_EMPTY { NULL, 0, 0, 0, 0, 0, 0 }

typedef struct {
  void *p2;
  int p1;
} jlog_hash_iter;

#define JLOG_HASH_ITER_ZERO { NULL, 0 }

void jlog_hash_init(jlog_hash_table *h);
/* NOTE! "k" and "data" MUST NOT be transient buffers, as the hash table
 * implementation does not duplicate them.  You provide a pair of
 * JLogHashFreeFunc functions to free up their storage when you call
 * jlog_hash_delete(), jlog_hash_delete_all() or jlog_hash_destroy().
 * */
int jlog_hash_store(jlog_hash_table *h, const char *k, int klen, void *data);
int jlog_hash_replace(jlog_hash_table *h, const char *k, int klen, void *data,
                      JLogHashFreeFunc keyfree, JLogHashFreeFunc datafree);
int jlog_hash_retrieve(jlog_hash_table *h, const char *k, int klen, void **data);
int jlog_hash_delete(jlog_hash_table *h, const char *k, int klen,
                     JLogHashFreeFunc keyfree, JLogHashFreeFunc datafree);
void jlog_hash_delete_all(jlog_hash_table *h, JLogHashFreeFunc keyfree,
                          JLogHashFreeFunc datafree);
void jlog_hash_destroy(jlog_hash_table *h, JLogHashFreeFunc keyfree,
                       JLogHashFreeFunc datafree);

/* This is an iterator and requires the hash to not be written to during the
   iteration process.
   To use:
     jlog_hash_iter iter = JLOG_HASH_ITER_ZERO;

     const char *k;
     int klen;
     void *data;

     while(jlog_hash_next(h, &iter, &k, &klen, &data)) {
       .... use k, klen and data ....
     }
*/
int jlog_hash_next(jlog_hash_table *h, jlog_hash_iter *iter,
                   const char **k, int *klen, void **data);
int jlog_hash_firstkey(jlog_hash_table *h, const char **k, int *klen);
int jlog_hash_nextkey(jlog_hash_table *h, const char **k, int *klen, const char *lk, int lklen);

/* This function serves no real API use sans calculating expected buckets
   for keys (or extending the hash... which is unsupported) */
u_int32_t jlog_hash__hash(const char *k, u_int32_t length, u_int32_t initval);
jlog_hash_bucket *jlog_hash__new_bucket(const char *k, int klen, void *data);
void jlog_hash__rebucket(jlog_hash_table *h, int newsize);
#endif
