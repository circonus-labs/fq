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

#include "fqd.h"
#include "http_parser.h"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <ctype.h>
#include <ck_ht.h>

const char *fqd_web_path = VARLIBFQDIR "/web";
const char *index_file = "index.html";

/* Linux I hate you. */
#if defined(linux) || defined(__linux) || defined(__linux__)
static size_t strlcpy(char *dst, const char *src, size_t size)
{
  if(size) {
    strncpy(dst, src, size-1);
    dst[size-1] = '\0';
  } else {
    dst[0] = '\0';
  }
  return strlen(src);
}
static size_t strlcat(char *dst, const char *src, size_t size)
{
  int dl = strlen(dst);
  int sz = size-dl-1;

  if(sz >= 0) {
    strncat(dst, src, sz);
    dst[dl+sz] = '\0';
  }

  return dl+strlen(src);
}
#endif

void fqd_http_set_root(const char *newpath) {
  char path[PATH_MAX];
  if(realpath(newpath, path) != NULL)
    fqd_web_path = strdup(path);
}

static inline int ends_with(const char *str, const char *end) {
  int elen = strlen(end);
  int slen = strlen(str);
  if(slen < elen) return 0;
  return !strcasecmp(str + slen - elen, end);
}
static const char *
fqd_http_mime_type(const char *url) {
  if(ends_with(url, ".js")) return "text/javascript";
  if(ends_with(url, ".json")) return "application/json";
  if(ends_with(url, ".css")) return "text/css";
  if(ends_with(url, ".jpg") || ends_with(url, ".jpeg")) return "image/jpeg";
  if(ends_with(url, ".gif")) return "image/gif";
  if(ends_with(url, ".png")) return "image/png";
  if(ends_with(url, "/") || ends_with(url, ".html") || ends_with(url, ".htm"))
    return "text/html";
  return "application/octet-stream";
}

struct http_req {
  remote_client *client;
  enum http_method method;
  char *url;
  char *qs;
  char *status;
  char *fldname;
  ck_ht_t headers;
  char *body;
  int close;
};

static void *
ht_malloc(size_t r)
{ return malloc(r); }

static void
ht_free(void *p, size_t b, bool r)
{ (void)b; (void)r; free(p); return; }

static struct ck_malloc my_alloc = {
  .malloc = ht_malloc,
  .free = ht_free
};

static void
http_req_clean(struct http_req *req) {
  ck_ht_entry_t *cursor;
  ck_ht_iterator_t iterator = CK_HT_ITERATOR_INITIALIZER;

  while(ck_ht_next(&req->headers, &iterator, &cursor)) {
    ck_ht_hash_t hv;
    char *key = ck_ht_entry_key(cursor);
    char *value = ck_ht_entry_value(cursor);
    ck_ht_hash(&hv, &req->headers, key, strlen(key));
    ck_ht_remove_spmc(&req->headers, hv, cursor);
    if(key) free(key);
    if(value) free(value);
  }

  if(req->url) free(req->url);
  /* req->qs isn't allocated */
  if(req->status) free(req->status);
  if(req->fldname) free(req->fldname);
  if(req->body) free(req->body);

  req->url = NULL;
  req->qs = NULL;
  req->status = NULL;
  req->fldname = NULL;
  req->body = NULL;
}

static int
fqd_http_message_url(http_parser *p, const char *at, size_t len) {
  struct http_req *req = p->data;
  req->url = malloc(len+1);
  strlcpy(req->url, at, len+1);
  req->qs = strchr(req->url, '?');
  if(req->qs) *(req->qs++) = '\0';
  fq_debug(FQ_DEBUG_CONN, ".on_url -> '%s'\n", req->url);
  return 0;
}
static int
fqd_http_message_status(http_parser *p, const char *at, size_t len) {
  struct http_req *req = p->data;
  req->status = malloc(len+1);
  strlcpy(req->status, at, len+1);
  fq_debug(FQ_DEBUG_CONN, ".on_status -> '%s'\n", req->status);
  return 0;
}
static int
fqd_http_message_header_field(http_parser *p, const char *at, size_t len) {
  char *cp;
  struct http_req *req = p->data;
  req->fldname = malloc(len+1);
  strlcpy(req->fldname, at, len+1);
  for(cp=req->fldname;*cp;cp++) *cp = tolower(*cp);
  fq_debug(FQ_DEBUG_CONN, ".on_header_field -> '%s'\n", req->fldname);
  return 0;
}
static int
fqd_http_message_header_value(http_parser *p, const char *at, size_t len) {
  struct http_req *req = p->data;
  ck_ht_entry_t entry;
  ck_ht_hash_t hv;
  char *val;
  if(!req->fldname) return -1;
  val = malloc(len+1);
  strlcpy(val, at, len+1);
  fq_debug(FQ_DEBUG_CONN, ".on_header_value -> '%s'\n", val);

  ck_ht_hash(&hv, &req->headers, req->fldname, strlen(req->fldname));
  ck_ht_entry_set(&entry, hv, req->fldname, strlen(req->fldname), val);

  if(ck_ht_set_spmc(&req->headers, hv, &entry) && !ck_ht_entry_empty(&entry)) {
    char *key = ck_ht_entry_key(&entry);
    char *value = ck_ht_entry_value(&entry);
    if(key && key != req->fldname) free(key);
    if(value && value != val) free(value);
  }
  req->fldname = NULL;
  return 0;
}
static int
fqd_http_message_complete(http_parser *p) {
  char file[PATH_MAX], rfile[PATH_MAX];
  struct http_req *req = p->data;

  /* programmatic endpoints */
  if(!strcmp(req->url, "/stats.json")) {
    fqd_config_http_stats(req->client);
    req->close = 1;
    return 0;
  }

  /* Files */
  if(strlen(fqd_web_path)) {
    int fd, rv;
    int drlen = strlen(fqd_web_path);
    char http_header[1024];
    void *contents;
    struct stat st;
    strlcpy(file, fqd_web_path, sizeof(file));
    if(file[drlen-1] != '/') strlcat(file, "/", sizeof(file));
    strlcat(file, req->url, sizeof(file));
    if(file[strlen(file) - 1] == '/') strlcat(file, index_file, sizeof(file));

    if(realpath(file, rfile) == NULL) goto not_found;
    if(strncmp(rfile, fqd_web_path, drlen)) goto not_found;
    if(rfile[drlen] != '/' && rfile[drlen + 1] != '/') goto not_found;

    while((rv = stat(rfile, &st)) < 0 && errno == EINTR);
    if(rv < 0) goto not_found;
    fd = open(rfile, O_RDONLY);
    if(fd >= 0) {
      contents = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
      close(fd);
      snprintf(http_header, sizeof(http_header), "HTTP/1.0 200 OK\r\nContent-Length: %lu\r\n"
               "Content-Type: %s\r\n\r\n", (long int)st.st_size,
               fqd_http_mime_type(req->url));
      drlen = strlen(http_header);
      while(write(req->client->fd, http_header, drlen) == -1 && errno == EINTR);
      while(write(req->client->fd, contents, st.st_size) == -1 && errno == EINTR);
      munmap(contents, st.st_size);
      return 0;
    }
  }
  /* 404 */
 not_found:
  {
    const char *headers = "HTTP/1.0 404 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n";
    while(write(req->client->fd, headers, strlen(headers)) == -1 && errno == EINTR);
    req->close = 1;
  }

  return 0;
}
void
fqd_http_loop(remote_client *client, uint32_t bytes) {
  ssize_t rv, len = 4;
  char inbuff[4096];
  struct http_req req = { .client = client };
  http_parser parser;
  http_parser_settings settings;

  assert(ck_ht_init(&req.headers, CK_HT_MODE_BYTESTRING, NULL, &my_alloc, 8, lrand48()));
  http_parser_init(&parser, HTTP_REQUEST);
  http_parser_settings_init(&settings);

  parser.data = &req;
  settings.on_url = fqd_http_message_url;
  settings.on_status = fqd_http_message_status;
  settings.on_header_field = fqd_http_message_header_field;
  settings.on_header_value = fqd_http_message_header_value;
  settings.on_message_complete = fqd_http_message_complete;

  memcpy(inbuff, &bytes, 4);
  while((rv = http_parser_execute(&parser, &settings, inbuff, len)) == len && !req.close) {
    struct pollfd pfd;
    pfd.fd = client->fd;
    pfd.events = POLLIN|POLLHUP;
    poll(&pfd, 1, 0);
    len = recv(client->fd, inbuff, 4096, 0);
    fq_debug(FQ_DEBUG_CONN, "recv() -> %d\n", (int)len);
    if(len <= 0) break;
  }

  http_req_clean(&req);
  ck_ht_destroy(&req.headers);
  (void)bytes;
}
