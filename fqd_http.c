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
#include "fqd_private.h"
#include "http_parser.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <errno.h>
#include <poll.h>
#include <ctype.h>
#include <ck_ht.h>

const char *fqd_web_path = VARLIBFQDIR "/web";
const char *index_file = "index.html";

static remote_data_client web_data_client = {
  .refcnt = 1,
  .fd = -1,
  .pretty = "_web_data",
  .mode = FQ_PROTO_DATA_MODE
};

/* Linux I hate you. */
#if defined(linux) || defined(__linux) || defined(__linux__)
static size_t strlcpy(char *dst, const char *src, size_t size)
{
  if(size > 0) {
    strncpy(dst, src, size-1);
    dst[size-1] = '\0';
    return size;
  }

  dst[0] = '\0';
  return 0;
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
  char *error;
  ck_ht_t headers;
  ck_ht_t query_params;
  size_t body_len;
  size_t body_read;
  fq_msg *msg;
  enum {
    HTTP_EXPECT_NONE = 0,
    HTTP_EXPECT_CONTINUE,
    HTTP_EXPECT_SENT
  } expect_continue;
  int close;
};

static int fqd_http_submit_msg(struct http_req *req);
static int fqd_http_add_checkpoint(struct http_req *req);
static int fqd_http_remove_checkpoint(struct http_req *req);
static int fqd_http_reset_to_checkpoint(struct http_req *req);

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

  ck_ht_iterator_init(&iterator);

  while(ck_ht_next(&req->query_params, &iterator, &cursor)) {
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
  if(req->error) free(req->error);
  if(req->msg) fq_msg_deref(req->msg);

  req->url = NULL;
  req->qs = NULL;
  req->status = NULL;
  req->fldname = NULL;
  req->error = NULL;
  req->body_len = 0;
  req->body_read = 0;
  req->msg = NULL;
  req->expect_continue = HTTP_EXPECT_NONE;
}

/* split incoming string by '=' and store the left as key and right as value in the table */
static void
store_kv(ck_ht_t *table, char *kv_string) {
  ck_ht_entry_t entry;
  ck_ht_hash_t hv;

  const char *key = kv_string;
  char *eq = strchr(kv_string, '=');
  eq[0] = '\0';
  const char *val = eq + 1;

  ck_ht_hash(&hv, table, key, strlen(key));
  ck_ht_entry_set(&entry, hv, strdup(key), strlen(key), strdup(val));

  if(ck_ht_set_spmc(table, hv, &entry)) {
    fq_debug(FQ_DEBUG_HTTP, ".store_kv -> added (%s, %s)\n", key, val);
  }

  /* be non-destructive */
  eq[0] = '=';
}

static const char *
get_ht_value(ck_ht_t *table, const char *key) {
  ck_ht_entry_t entry;
  ck_ht_hash_t hv;

  ck_ht_hash(&hv, table, key, strlen(key));
  ck_ht_entry_key_set(&entry, key, strlen(key));

  if (ck_ht_get_spmc(table, hv, &entry)) {
    return ck_ht_entry_value(&entry);
  }
  return NULL;
}

static int
fqd_http_message_url(http_parser *p, const char *at, size_t len) {
  struct http_req *req = p->data;
  req->url = malloc(len+1);
  strlcpy(req->url, at, len+1);
  req->qs = strchr(req->url, '?');
  if(req->qs) *(req->qs++) = '\0';

  if (req->qs != NULL) {
    char *trailing = req->qs;
    for (uint32_t i = 0; i < strlen(req->qs); i++) {
      if (req->qs[i] == '&') {
        req->qs[i] = '\0';
        store_kv(&req->query_params, trailing);
        req->qs[i] = '&';
        trailing = &req->qs[i+1];
      }
    }
    store_kv(&req->query_params, trailing);
  }

  fq_debug(FQ_DEBUG_HTTP, ".on_url -> '%s'\n", req->url);
  fq_debug(FQ_DEBUG_HTTP, ".on_url query_string -> '%s'\n", req->qs);
  return 0;
}
static int
fqd_http_message_status(http_parser *p, const char *at, size_t len) {
  struct http_req *req = p->data;
  req->status = malloc(len+1);
  strlcpy(req->status, at, len+1);
  fq_debug(FQ_DEBUG_HTTP, ".on_status -> '%s'\n", req->status);
  return 0;
}
static int
fqd_http_message_body(http_parser *p, const char *at, size_t len) {
  struct http_req *req = p->data;
  fq_debug(FQ_DEBUG_HTTP, ".on_data -> %zu\n", len);
  if(req->msg) {
    if(req->body_read + len > req->body_len) {
      req->error = strdup("excessive data received");
      return 1;
    }
    memcpy(req->msg->payload + req->body_read, at, len);
    req->body_read += len;
  }
  return 0;
}
static int
fqd_http_message_header_field(http_parser *p, const char *at, size_t len) {
  char *cp;
  struct http_req *req = p->data;
  req->fldname = malloc(len+1);
  strlcpy(req->fldname, at, len+1);
  for(cp=req->fldname;*cp;cp++) *cp = tolower(*cp);
  fq_debug(FQ_DEBUG_HTTP, ".on_header_field -> '%s'\n", req->fldname);
  return 0;
}
static const char *
fqd_http_header(struct http_req *req, const char *hdr) {
  ck_ht_entry_t entry;
  ck_ht_hash_t hv;
  int hdrlen = strlen(hdr);

  ck_ht_hash(&hv, &req->headers, hdr, hdrlen);
  ck_ht_entry_set(&entry, hv, hdr, hdrlen, NULL);
  if(ck_ht_get_spmc(&req->headers, hv, &entry)) {
    return ck_ht_entry_value(&entry);
  }
  return NULL;
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
  fq_debug(FQ_DEBUG_HTTP, ".on_header_value -> '%s'\n", val);

  ck_ht_hash(&hv, &req->headers, req->fldname, strlen(req->fldname));
  ck_ht_entry_set(&entry, hv, req->fldname, strlen(req->fldname), val);

  if(ck_ht_set_spmc(&req->headers, hv, &entry) && !ck_ht_entry_empty(&entry)) {
    char *key = ck_ht_entry_key(&entry);
    char *value = ck_ht_entry_value(&entry);
    if(key && key != req->fldname) free(key);
    if(value && value != val) free(value);
  }

  if(!strcmp(req->fldname, "expect") && !strcasecmp(val,"100-continue"))
    req->expect_continue = HTTP_EXPECT_CONTINUE;
  req->fldname = NULL;
  return 0;
}
static int
fqd_http_message_headers_complete(http_parser *p) {
#define EXPECT_CONTINUE "HTTP/1.1 100 Continue\r\n\r\n"
  const char *clen;
  static char *expect_continue = EXPECT_CONTINUE;
  static int expect_continue_len = sizeof(EXPECT_CONTINUE)-1;
  struct http_req *req = p->data;
  if(req->expect_continue == HTTP_EXPECT_CONTINUE) {
    while(write(req->client->fd, expect_continue, expect_continue_len) == -1 && errno == EINTR);
    req->expect_continue = HTTP_EXPECT_SENT;
  }
  clen = fqd_http_header(req, "content-length");
  if(!strcmp(req->url, "/submit") && clen) {
    req->body_len = atoi(clen);
    req->msg = fq_msg_alloc_BLANK(req->body_len);
  }
  return 0;
}

#define cwrite(client, str) write(client->fd, str, strlen(str))

static void
fqd_http_jsend(remote_client *client, const char *status, const char *fmt, ...)
{
  char error[1024] = {0};
  char scratch[1024] = {0};
  const char *headers = "HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n";
  va_list argp;

  va_start(argp, fmt);
  vsnprintf(error, sizeof(error), fmt, argp);
  va_end(argp);

  while(write(client->fd, headers, strlen(headers)) == -1 && errno == EINTR);
  cwrite(client, "{\n");
  cwrite(client, scratch);
  cwrite(client,  " \"status\": \"");
  cwrite(client, status);
  cwrite(client,  "\",\n");
  sprintf(scratch, " \"message\": \"%s\"\n", error);
  cwrite(client, scratch);
  cwrite(client, "}\n");
}

#define fqd_http_error_json_f(client, fmt, ...) fqd_http_jsend(client, "error", fmt, __VA_ARGS__)
#define fqd_http_success_json_f(client, fmt, ...) fqd_http_jsend(client, "success", fmt, __VA_ARGS__)
#define fqd_http_error_json(client, fmt) fqd_http_error_json_f(client, "%s", fmt)
#define fqd_http_success_json(client, fmt) fqd_http_success_json_f(client, "%s", fmt)


static int
fqd_http_message_complete(http_parser *p) {
  char file[PATH_MAX], rfile[PATH_MAX];
  struct http_req *req = p->data;

  fq_debug(FQ_DEBUG_HTTP, ".on_complete ->\n");

  /* programmatic endpoints */
  if(!strcmp(req->url, "/stats.json")) {
    fqd_config_http_stats(req->client);
    req->close = 1;
    return 0;
  }

  if(!strcmp(req->url, "/submit")) {
    fqd_http_submit_msg(req);
    return 0;
  }

  if(!strcmp(req->url, "/shutdown")) {
    const char *allowed = getenv("HTTP_SHUTDOWN");
    if(allowed && !strcmp(allowed, "1")) exit(0);
  }

  if (!strcmp(req->url, "/add_checkpoint")) {
    fqd_http_add_checkpoint(req);
    return 0;
  }

  if (!strcmp(req->url, "/remove_checkpoint")) {
    fqd_http_remove_checkpoint(req);
    return 0;
  }

  if (!strcmp(req->url, "/reset_to_checkpoint")) {
    fqd_http_reset_to_checkpoint(req);
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

static int
fqd_http_add_checkpoint(struct http_req *req) {

  fqd_config *config = fqd_config_get();

  const char *cpname = get_ht_value(&req->query_params, "cpname");
  const char *qname = get_ht_value(&req->query_params, "qname");
  const char *chkptid = get_ht_value(&req->query_params, "chkptid");

  fq_rk qn;
  fq_rk_from_str(&qn, qname);

  fqd_queue *queue = fqd_config_get_registered_queue(config, &qn);

  if (strcmp(cpname, "fq") == 0) {
    fqd_http_error_json(req->client, "'fq' is a reserved name, cannot be used for a checkpoint name");
    req->close = 1;
    return 0;
  }

  if (queue == NULL) {
    fqd_http_error_json_f(req->client, "Cannot find registered queue '%s'", qname);
    req->close = 1;
    return 0;
  }

  /* do we really want this restriction? */
  if (queue->permanent == false) {
    fqd_http_error_json(req->client, "Checkpoints on ephemeral queues not supported");
    req->close = 1;
    return 0;
  }

  /* check points only supported on disk queue */
  if (strcmp(queue->impl->name, "disk") != 0) {
    fqd_http_error_json(req->client, "Checkpoints on memory queues not supported");
    req->close = 1;
    return 0;
  }

  /* validate chkptid format */
  char ckid[48] = {0};
  strncpy(ckid, chkptid, sizeof(ckid));
  const char *log_string = ckid;
  char *sep = strchr(ckid, ':');
  if (sep == NULL) {
    fqd_http_error_json(req->client, "'chkptid' must be of format: [0-9]*:[0-9]*");
    req->close = 1;
    return 0;
  }
  sep[0] = '\0';
  const char *marker_string = sep + 1;

  uint32_t log = atoi(log_string);
  uint32_t marker = atoi(marker_string);

  fq_msgid id = {
    .id.u32.p1 = log,
    .id.u32.p2 = marker
  };

  int rv = queue->impl->add_checkpoint(queue->impl_data, cpname, &id);
  if (rv == -1) {
    fqd_http_error_json(req->client, "'chkptid' is out of range of the queue");
    req->close = 1;
    return 0;
  }

  if (rv == -2) {
    fqd_http_error_json(req->client, "Failed to set checkpoint");
    req->close = 1;
    return 0;
  }

  if (rv < 0) {
    fqd_http_error_json(req->client, "Unknown error");
    req->close = 1;
    return 0;
  }

  fqd_http_success_json(req->client, "Checkpoint added");
  req->close = 1;
  fq_debug(FQ_DEBUG_HTTP, ".on_complete -> add_checkpoint on [%s] for queue [%s] and id [%s]\n", cpname, qname, chkptid);
  return 0;
}

static int
fqd_http_remove_checkpoint(struct http_req *req)
{
  fqd_config *config = fqd_config_get();

  const char *cpname = get_ht_value(&req->query_params, "cpname");
  const char *qname = get_ht_value(&req->query_params, "qname");

  fq_rk qn;
  fq_rk_from_str(&qn, qname);

  fqd_queue *queue = fqd_config_get_registered_queue(config, &qn);

  if (strcmp(cpname, "fq") == 0) {
    fqd_http_error_json(req->client, "'fq' is a reserved name, cannot be used for a checkpoint name");
    req->close = 1;
    return 0;
  }

  if (queue == NULL) {
    fqd_http_error_json_f(req->client, "Cannot find registered queue '%s'", qname);
    req->close = 1;
    return 0;
  }

  int rv = queue->impl->remove_checkpoint(queue->impl_data, cpname);
  if (rv == -1) {
    fqd_http_error_json(req->client, "Checkpoint does not exist");
    req->close = 1;
    return 0;
  }

  if (rv < 0) {
    fqd_http_error_json(req->client, "Unknown error");
    req->close = 1;
    return 0;
  }

  fqd_http_success_json(req->client, "Checkpoint removed");
  req->close = 1;
  fq_debug(FQ_DEBUG_HTTP, ".on_complete -> remove_checkpoint on [%s] for queue [%s]\n", cpname, qname);
  return 0;
}

static int
fqd_http_reset_to_checkpoint(struct http_req *req)
{
  fqd_config *config = fqd_config_get();
  const char *cpname = get_ht_value(&req->query_params, "cpname");
  const char *qname = get_ht_value(&req->query_params, "qname");

  fq_rk qn;
  fq_rk_from_str(&qn, qname);

  fqd_queue *queue = fqd_config_get_registered_queue(config, &qn);

  if (strcmp(cpname, "fq") == 0) {
    fqd_http_error_json(req->client, "'fq' is a reserved name, cannot be used for a checkpoint name");
    req->close = 1;
    return 0;
  }

  if (queue == NULL) {
    fqd_http_error_json_f(req->client, "Cannot find registered queue '%s'", qname);
    req->close = 1;
    return 0;
  }

  int rv = queue->impl->reset_checkpoint(queue->impl_data, cpname);
  if (rv == -1) {
    fqd_http_error_json(req->client, "Checkpoint does not exist");
    req->close = 1;
    return 0;
  }

  if (rv < 0) {
    fqd_http_error_json(req->client, "Unknown error");
    req->close = 1;
    return 0;
  }

  fqd_http_success_json_f(req->client, "'%s' reset to checkpoint '%s'", qname, cpname);
  req->close = 1;
  fq_debug(FQ_DEBUG_HTTP, ".on_complete -> reset_to_checkpoint on [%s] for queue [%s]\n", cpname, qname);
  return 0;
}

static int
fqd_http_submit_msg(struct http_req *req) {
  remote_data_client tmp_data_client = {
    .refcnt = 1,
    .fd = -1,
    .pretty = "_web_data",
    .mode = FQ_PROTO_DATA_MODE
  };
  const char *hdrval;
  int len, slen;
  char http_header[1024];
  char scratch[1024];
  const char *status = "200 OK";
#define SUBERR(a) do { req->error = strdup(a); goto error; } while(0)

  if(!req->msg) SUBERR("no message");
  if(req->msg->payload_len != req->body_len) SUBERR("short message");

  hdrval = fqd_http_header(req, "x-fq-sender");
  if(!hdrval) hdrval = "_web";
  if(strlen(hdrval) > MAX_RK_LEN) SUBERR("sender too long");
  req->msg->sender.len = strlen(hdrval);
  memcpy(req->msg->sender.name, hdrval, req->msg->sender.len);

  hdrval = fqd_http_header(req, "x-fq-route");
  if(!hdrval) SUBERR("missing route");
  if(strlen(hdrval) > MAX_RK_LEN) SUBERR("route too long");
  req->msg->route.len = strlen(hdrval);
  memcpy(req->msg->route.name, hdrval, req->msg->route.len);

  hdrval = fqd_http_header(req, "x-fq-exchange");
  if(!hdrval) SUBERR("missing exchange");
  if(strlen(hdrval) > MAX_RK_LEN) SUBERR("exchange too long");
  req->msg->exchange.len = strlen(hdrval);
  memcpy(req->msg->exchange.name, hdrval, req->msg->exchange.len);

  if(req->error) goto error;
  fq_msg_id(req->msg, NULL);

  fqd_inject_message(&tmp_data_client, req->msg);
  req->msg = NULL; /* not my problem anymore */

  snprintf(scratch, sizeof(scratch),
           "{\"routed\":%u,\"dropped\":%u,"
           "\"no_route\":%u,\"no_exchange\":%u}\n",
           tmp_data_client.routed, tmp_data_client.dropped,
           tmp_data_client.no_route, tmp_data_client.no_exchange);
#define BUMP(a) ck_pr_add_32(&web_data_client.a, tmp_data_client.a)
  BUMP(msgs_in);
  BUMP(octets_in);
  BUMP(msgs_out);
  BUMP(octets_out);
  BUMP(routed);
  BUMP(dropped);
  BUMP(no_route);
  BUMP(no_exchange);
  goto out;

 error:
  status = "500 ERROR";
  snprintf(scratch, sizeof(scratch), "{ \"error\": \"%s\" }\n", req->error);

 out:
  slen = strlen(scratch);
  snprintf(http_header, sizeof(http_header), "HTTP/1.0 %s\r\nContent-Length: %lu\r\n"
           "Content-Type: application/json\r\n\r\n", status, (long int)slen);
  len = strlen(http_header);
  while(write(req->client->fd, http_header, len) == -1 && errno == EINTR);
  while(write(req->client->fd, scratch, slen) == -1 && errno == EINTR);
  return 0;
}

void
fqd_http_loop(remote_client *client, uint32_t bytes) {
  ssize_t rv, len = 4;
  char inbuff[4096 * 16];
  struct http_req req = { .client = client };
  http_parser parser;
  http_parser_settings settings;

  fq_assert(ck_ht_init(&req.headers, CK_HT_MODE_BYTESTRING, NULL, &my_alloc, 8, lrand48()));
  fq_assert(ck_ht_init(&req.query_params, CK_HT_MODE_BYTESTRING, NULL, &my_alloc, 8, lrand48()));
  http_parser_init(&parser, HTTP_REQUEST);
  http_parser_settings_init(&settings);

  parser.data = &req;
  settings.on_url = fqd_http_message_url;
  settings.on_status = fqd_http_message_status;
  settings.on_body = fqd_http_message_body;
  settings.on_header_field = fqd_http_message_header_field;
  settings.on_header_value = fqd_http_message_header_value;
  settings.on_headers_complete = fqd_http_message_headers_complete;
  settings.on_message_complete = fqd_http_message_complete;

  memcpy(inbuff, &bytes, 4);
  while((rv = http_parser_execute(&parser, &settings, inbuff, len)) == len && !req.close) {
    struct pollfd pfd;
    pfd.fd = client->fd;
    pfd.events = POLLIN|POLLHUP;
    poll(&pfd, 1, 0);
    len = recv(client->fd, inbuff, sizeof(inbuff), 0);
    fq_debug(FQ_DEBUG_HTTP, "recv() -> %d\n", (int)len);
    if(len <= 0) break;
  }

  http_req_clean(&req);
  ck_ht_destroy(&req.headers);
  ck_ht_destroy(&req.query_params);
  (void)bytes;
}
