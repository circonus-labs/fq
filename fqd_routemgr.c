#include <unistd.h>
#include <ck_pr.h>
#include "fqd.h"

uint32_t global_route_id;
#define RR_SET_SIZE 32

struct fqd_route_rule {
  fq_rk prefix;
  uint32_t route_id;
  fqd_queue *queue;
  struct fqd_route_rule *next;
};

struct fqd_route_rules {
  struct fqd_route_rule *rules[RR_SET_SIZE];
};

void
fqd_inject_message(remote_client *c, fq_msg *m) {
  (void)c;
  fq_msg_deref(m);
}

struct fqd_route_rules *
fqd_routemgr_ruleset_alloc() {
  return calloc(1, sizeof(struct fqd_route_rules));
}
void
fqd_routemgr_rulesset_add_rule(fqd_route_rules *set, fqd_route_rule *r) {
  int idx;
  r->route_id = ck_pr_faa_32(&global_route_id, 1);
  idx = r->route_id % RR_SET_SIZE;
  r->next = set->rules[idx];
  set->rules[idx] = r;
}
static fqd_route_rule *
copy_rule(fqd_route_rule *in) {
  fqd_route_rule *out;
  out = calloc(1, sizeof(*out));
  memcpy(out, in, sizeof(*out));
  fqd_queue_ref(out->queue);
  out->next = NULL;
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
      if(set->rules[i]->queue) fqd_queue_deref(set->rules[i]->queue);
      free(set->rules[i]);
      set->rules[i] = r;
    }
  }
  free(set);
}
