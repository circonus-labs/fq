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

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <ck_pr.h>

#include <sqlite3.h>

#include "fq.h"
#include "fqd.h"

/* Peer connections are currently only permanent, in memory
 * bounded, public, drop-semantic queues.
 */

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

/* These are infrequent calls, big ol' lock is fine */

typedef struct {
  uint64_t gen;
  uint32_t route_id;
  fq_rk exchange;
  char *prog;
  bool  perm;
  bool  disabled;
  bool  disable_requested;
} peer_binding_info;

typedef struct peer_connection {
  fq_client client;
  char *host;
  int port;
  char *user;
  char *pass;
  bool online_and_bound;
  int n_bindings;
  peer_binding_info **bindings;
  remote_data_client *stats_holder;
  struct peer_connection *next;
} fqd_peer_connection;

static fqd_peer_connection list_head;

static int
peercmp(fqd_peer_connection *a, fqd_peer_connection *b) {
  int rv;
  if(a->host == NULL || b->host == NULL) return -1;
  if(a->user == NULL || b->user == NULL) return -1;
  if(a->pass == NULL || b->pass == NULL) return -1;
  if(0 != (rv = strcmp(a->host, b->host))) return rv;
  if(0 != (rv = strcmp(a->user, b->user))) return rv;
  if(0 != (rv = strcmp(a->pass, b->pass))) return rv;
  if(a->port == b->port) return 0;
  if(a->port <  b->port) return -1;
  return 1;
}

static void
fqd_peer_auth_hook(fq_client conn, int authed) {
  int i;
  fqd_peer_connection *peer;
  peer = fq_client_get_userdata(conn);
  fq_debug(FQ_DEBUG_PEER, "authed(%s:%d) -> %d\n",
           peer->host, peer->port, authed);
  if(authed || !peer) return;

  pthread_mutex_lock(&lock);
  for(i=0;i<peer->n_bindings;i++) {
    peer_binding_info *bi = peer->bindings[i];
    fq_bind_req *breq;
    breq = calloc(1, sizeof(*breq));
    memcpy(&breq->exchange, &bi->exchange, sizeof(bi->exchange));
    breq->flags = FQ_BIND_PEER | (bi->perm ? FQ_BIND_PERM : 0);
    breq->program = strdup(bi->prog);
    fq_client_bind(conn, breq);
  }
  peer->online_and_bound = true;
  pthread_mutex_unlock(&lock);
}
static void
fqd_peer_bind_hook(fq_client conn, fq_bind_req *breq) {
  int i;
  fqd_peer_connection *peer;
  peer = fq_client_get_userdata(conn);
  if(!peer) return;
  if(breq->out__route_id == FQ_BIND_ILLEGAL) {
    return;
  }
  pthread_mutex_lock(&lock);
  for(i=0;i<peer->n_bindings;i++) {
    peer_binding_info *bi = peer->bindings[i];
    if(!fq_rk_cmp(&bi->exchange, &breq->exchange) &&
       !strcmp(bi->prog, breq->program)) {
      bi->route_id = breq->out__route_id;
      break;
    }
  }
  pthread_mutex_unlock(&lock);
}
static void
fqd_peer_unbind_hook(fq_client conn, fq_unbind_req *breq) {
  /* We *could* find the route and unset the route_id, but
   * I see no point in doing that work.
   */
}
static void
fqd_peer_cleanup_hook(fq_client conn) {
  int i;
  fqd_peer_connection *peer;
  peer = fq_client_get_userdata(conn);
  if(peer->bindings) free(peer->bindings);
  for(i=0;i<peer->n_bindings;i++) {
    peer_binding_info *bi = peer->bindings[i];
    free(bi->prog);
  }
  if(peer->host) free(peer->host);
  if(peer->user) free(peer->user);
  if(peer->pass) free(peer->pass);
  if(peer->stats_holder) free(peer->stats_holder);
  free(peer);
}
static void
fqd_peer_disconnect_hook(fq_client conn) {
  fqd_peer_connection *peer;
  peer = fq_client_get_userdata(conn);
  if(peer) peer->online_and_bound = false;
}
static bool
fqd_peer_message_hook(fq_client conn, fq_msg *m) {
  /* route this */
  fqd_peer_connection *peer;
  peer = fq_client_get_userdata(conn);
  fq_msg_ref(m);
  fqd_inject_message(peer ? peer->stats_holder : NULL, m);
  return true;
}
static fq_hooks fqd_peer_hooks = {
  .version = FQ_HOOKS_V4,
  .auth = fqd_peer_auth_hook,
  .bind = fqd_peer_bind_hook,
  .unbind = fqd_peer_unbind_hook,
  .sync = 0,
  .message = fqd_peer_message_hook,
  .cleanup = fqd_peer_cleanup_hook,
  .disconnect = fqd_peer_disconnect_hook
};

static void
fqd_peer_start(fqd_peer_connection *peer) {
  fq_debug(FQ_DEBUG_PEER, "starting peer(%s:%d)\n", peer->host, peer->port);
  fq_client_init(&peer->client, 1, NULL);
  fq_client_set_userdata(peer->client, peer);
  fq_client_creds(peer->client, peer->host, peer->port,
                  peer->user, peer->pass);
  fq_client_hooks(peer->client, &fqd_peer_hooks);
  fq_client_connect(peer->client);
}
static void
fqd_peer_stop(fqd_peer_connection *peer) {
  fq_debug(FQ_DEBUG_PEER, "stopping peer(%s:%d)\n", peer->host, peer->port);
  fq_client_destroy(peer->client);
}
static void
fqd_peer_online_bind(fqd_peer_connection *peer, peer_binding_info *bi) {
  if(peer->online_and_bound == true) {
    fq_bind_req *breq;
    fq_debug(FQ_DEBUG_PEER, "binding peer(%s:%d) exchange:\"%.*s\"\n",
             peer->host, peer->port, bi->exchange.len, bi->exchange.name);
    breq = calloc(1, sizeof(*breq));
    memcpy(&breq->exchange, &bi->exchange, sizeof(bi->exchange));
    breq->flags = FQ_BIND_PEER | FQ_BIND_PERM;
    breq->program = strdup(bi->prog);
    fq_client_bind(peer->client, breq);
  }
}
static void
fqd_peer_online_unbind(fqd_peer_connection *peer, peer_binding_info *bi) {
  fq_unbind_req *ureq;
  if(!bi->disabled || bi->disable_requested ||
     !peer->online_and_bound || bi->route_id == FQ_BIND_ILLEGAL) return;

  fq_debug(FQ_DEBUG_PEER, "unbinding peer(%s:%d) exchange:\"%.*s\"\n",
           peer->host, peer->port, bi->exchange.len, bi->exchange.name);
  ureq = calloc(1, sizeof(*ureq));
  memcpy(&ureq->exchange, &bi->exchange, sizeof(bi->exchange));
  ureq->route_id = bi->route_id;
  fq_client_unbind(peer->client, ureq);
}

int
fqd_add_peer(uint64_t gen,
             const char *host, int port,
             const char *user, const char *pass,
             fq_rk *exchange, const char *prog,
             bool perm) {
  bool added_peer = false, added_binding = false;
  fqd_peer_connection *peer, speer;
  peer_binding_info *bi;
  int i;

  memset(&speer, 0, sizeof(speer));
  speer.host = (char *)host;
  speer.port = port;
  speer.user = (char *)user;
  speer.pass = (char *)pass;

  pthread_mutex_lock(&lock);

  /* Get a peer */
  for(peer = list_head.next; peer; peer = peer->next) {
    if(!peercmp(peer, &speer)) break;
  }
  if(!peer) {
    peer = calloc(1, sizeof(*peer));
    peer->host = strdup(speer.host);
    peer->port = speer.port;
    peer->user = strdup(speer.user);
    peer->pass = strdup(speer.pass);
    peer->next = list_head.next;
    list_head.next = peer;
    added_peer = true;
  }

  /* Get a binding */

  for(i=0; i<peer->n_bindings; i++) {
    bi = peer->bindings[i];
    if(!fq_rk_cmp(exchange, &bi->exchange) && !strcmp(prog, bi->prog)) break;
  }
  if(!bi) {
    bi = calloc(1, sizeof(*bi));
    memcpy(&bi->exchange, exchange, sizeof(*exchange));
    bi->route_id = FQ_BIND_ILLEGAL;
    bi->prog = strdup(prog);
    peer->n_bindings++;
    peer->bindings = realloc(peer->bindings, peer->n_bindings * sizeof(bi));
    peer->bindings[peer->n_bindings - 1] = bi;
    added_binding = true;
  }

  /* This will force a rebind */
  if(perm != bi->perm) added_binding = true;
  bi->perm = perm;
  bi->gen = gen;

  if(added_peer) fqd_peer_start(peer);
  else if(added_binding) fqd_peer_online_bind(peer, bi);

  pthread_mutex_unlock(&lock);

  return added_binding ? 0 : -1;
}

/* Remove all peers older than the specified generation */
int
fqd_remove_peers(uint64_t current_gen) {
  fqd_peer_connection *prev;
  int turndown = 0;

  pthread_mutex_lock(&lock);

  for(prev = &list_head; prev && prev->next; prev = prev->next) {
    fqd_peer_connection *peer = prev->next;
    bool useful = false;
    int i;

    for(i=0; i<peer->n_bindings; i++) {
      if(peer->bindings[i]->gen >= current_gen) useful = true;
      else if(!peer->bindings[i]->disabled) {
        peer->bindings[i]->disabled = true;
        turndown++;
      }
    }
    if(!useful) {
      prev->next = peer->next;
      peer->next = NULL;
      fqd_peer_stop(peer);
    }
    else {
      for(i=0; i<peer->n_bindings; i++) {
        fqd_peer_online_unbind(peer, peer->bindings[i]);
      }
    }
  }

  pthread_mutex_unlock(&lock);
  return turndown;
}
int
fqd_remove_peer(const char *host, int port,
                const char *user, const char *pass,
                fq_rk *exchange, const char *prog) {
  fqd_peer_connection *peer, speer;
  peer_binding_info *bi = NULL;
  int i;

  memset(&speer, 0, sizeof(speer));
  speer.host = (char *)host;
  speer.port = port;
  speer.user = (char *)user;
  speer.pass = (char *)pass;
  pthread_mutex_lock(&lock);

  /* Get a peer */
  for(peer = list_head.next; peer; peer = peer->next) {
    if(!peercmp(peer, &speer)) {
      for(i=0; i<peer->n_bindings; i++) {
        bi = peer->bindings[i];
        if(bi->disabled == false &&
           fq_rk_cmp(exchange, &bi->exchange) &&
           !strcmp(prog, bi->prog)) {
          bi->disabled = true;
          break;
        }
      }
      break;
    }
  }
  if(bi && peer->n_bindings == 1) {
    /* Special case, we must remove this so no one else can see it */
    fqd_peer_connection *prev = &list_head;
    for(prev = &list_head; prev->next; prev = prev->next) {
      if(!peercmp(prev->next, peer)) {
        prev->next = peer->next;
        peer->next = NULL;
        break;
      }
    }
  }

  if(bi) {
    /* We found something and it is our job to turn it down */
    if(peer->n_bindings == 1) fqd_peer_stop(peer);
    else fqd_peer_online_unbind(peer, bi);
  }

  pthread_mutex_unlock(&lock);
  return bi ? 0 : -1;
}
