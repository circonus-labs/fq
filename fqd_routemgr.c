#include <unistd.h>
#include <ck_pr.h>
#include <assert.h>
#include "fqd.h"

uint32_t global_route_id = 1;
#define RR_SET_SIZE 32

struct fqd_route_rule {
  fq_rk prefix;
  char *program;
  uint32_t route_id;
  int peermode;
  fqd_queue *queue;
  struct fqd_route_rule *next;
};

struct fqd_route_rules {
  struct fqd_route_rule *rules[RR_SET_SIZE];
};

void
fqd_inject_message(remote_client *c, fq_msg *m) {
  fqd_exchange *e;
  fqd_config *config;
  (void)c;
  config = fqd_config_get();
  e = fqd_config_get_exchange(config, &m->exchange);
  if(e) {
    int i;
    for(i=0;i<RR_SET_SIZE;i++) {
      struct fqd_route_rule *r;
      for(r=e->set->rules[i];r;r=r->next) {
        if(m->route.len >= r->prefix.len &&
           !memcmp(m->route.name, r->prefix.name, r->prefix.len)) {
          fq_debug(FQ_DEBUG_ROUTE, "M[%p] -> Q[%p]\n", (void *)m, (void *)r->queue);
          fqd_queue_enqueue(r->queue, m);
        }
      }
    }
  }
  else {
    fq_debug(FQ_DEBUG_ROUTE, "No exchange \"%.*s\"\n", m->exchange.len, m->exchange.name);
  }
  fqd_config_release(config);
  fq_msg_deref(m);
}

struct fqd_route_rule *
fqd_routemgr_compile(const char *program, int peermode, fqd_queue *q) {
  int len;
  struct fqd_route_rule *r;

  assert(q);
  len = strlen(program);
  if(len > (int)sizeof(r->prefix.name)) return NULL;
  r = calloc(1, sizeof(*r));
  r->prefix.len = len;
  r->program = strdup(program);
  memcpy(r->prefix.name, program, len);
  r->queue = q;
  fqd_queue_ref(r->queue);
  r->peermode = peermode;
  fq_debug(FQ_DEBUG_MEM, "alloc rule [%p] -> Q[%p]\n", (void *)r, (void *)r->queue);
  return r;
}
void
fqd_routemgr_rule_free(struct fqd_route_rule *rule) {
  fq_debug(FQ_DEBUG_ROUTE, "dropping rule \"%s\"\n", rule->program);
  fq_debug(FQ_DEBUG_MEM, "free rule  [%p] -> Q[%p]\n", (void *)rule, (void *)rule->queue);
  free(rule->program);
  if(rule->queue) fqd_queue_deref(rule->queue);
  free(rule);
}
struct fqd_route_rules *
fqd_routemgr_ruleset_alloc() {
  return calloc(1, sizeof(struct fqd_route_rules));
}
void
fqd_routemgr_drop_rules_by_queue(fqd_route_rules *set, fqd_queue *q) {
  int i;
  struct fqd_route_rule *r, *prev = NULL;
  fq_debug(FQ_DEBUG_ROUTE, "fqd_routemgr_drop_rules_by_queue(%p)\n", (void *)q);
  for(i=0;i<RR_SET_SIZE;i++) {
    r = set->rules[i];
    while(r) {
      if(r->queue == q) {
        struct fqd_route_rule *tofree = r;
        if(prev) r = prev->next = r->next;
        else r = set->rules[i] = r->next;
        fqd_routemgr_rule_free(tofree);
      }
      else r = r->next;
    }
  }
}
uint32_t
fqd_routemgr_ruleset_add_rule(fqd_route_rules *set, fqd_route_rule *newrule) {
  int i, idx;
  fqd_route_rule *r;
  for(i=0;i<RR_SET_SIZE;i++) {
    for(r=set->rules[i];r;r=r->next) {
      if(r->queue == newrule->queue &&
         !strcmp(r->program, newrule->program)) {
        fqd_routemgr_rule_free(newrule);
        return r->route_id;
      }
    }
  }
  newrule->route_id = ck_pr_faa_32(&global_route_id, 1);
  idx = newrule->route_id % RR_SET_SIZE;
  newrule->next = set->rules[idx];
  set->rules[idx] = newrule;
  return newrule->route_id;
}
static fqd_route_rule *
copy_rule(fqd_route_rule *in) {
  fqd_route_rule *out;
  fq_debug(FQ_DEBUG_MEM, "copy from [%p] -> Q[%p]\n", (void *)in, (void *)in->queue);
  out = calloc(1, sizeof(*out));
  memcpy(out, in, sizeof(*out));
  assert(out->queue);
  out->program = strdup(in->program);
  fqd_queue_ref(out->queue);
  out->next = NULL;
  fq_debug(FQ_DEBUG_MEM, "copy to   [%p] -> Q[%p]\n", (void *)out, (void *)out->queue);
  return out;
}
fqd_route_rules *
fqd_routemgr_ruleset_copy(fqd_route_rules *set) {
  fqd_route_rule *r, *nhead, *nr, *tmp;
  fqd_route_rules *nset;
  int i = 0;
  nset = fqd_routemgr_ruleset_alloc();
  for(i=0;i<RR_SET_SIZE;i++) {
    nhead = nr = NULL;
    for(r=set->rules[i];r;r=r->next) {
      tmp = copy_rule(r);
      if(!nhead) nhead = tmp;
      if(nr) {
        nr->next = tmp;
      }
      nr = tmp;
    }
    nset->rules[i] = nhead;
  }
  return nset;
}
void
fqd_routemgr_ruleset_free(fqd_route_rules *set) {
  int i;
  for(i=0;i<RR_SET_SIZE;i++) {
    while(set->rules[i]) {
      fqd_route_rule *r = set->rules[i]->next;
      fqd_routemgr_rule_free(set->rules[i]);
      set->rules[i] = r;
    }
  }
  free(set);
}
