#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ck_pr.h>
#include <assert.h>
#include <arpa/nameser_compat.h>
#include "fqd.h"

uint32_t global_route_id = 1;
#define RR_SET_SIZE 32

struct fqd_route_rule {
  fq_rk prefix;
  int match_maxlen;
  char *program;
  uint32_t route_id;
  int peermode;
  fqd_queue *queue;
  struct fqd_route_rule *next;
};

struct prefix_jumptable {
  enum { JUMPTABLE, RULETABLE } tabletype;
  struct fqd_route_rule *rules;
  struct {
    uint64_t pattern;
    uint64_t checkbits;
    struct prefix_jumptable *jt;
  } *pats;
  int pat_len;
};
struct fqd_route_rules {
  struct prefix_jumptable master;
};
static void
walk_jump_table(struct prefix_jumptable *jt, fq_msg *m, int offset) {
  if(jt->tabletype == RULETABLE) {
    struct fqd_route_rule *r;
    for(r=jt->rules;r;r=r->next) {
      if(m->route.len >= r->prefix.len && m->route.len <= r->match_maxlen) {
        fq_rk *rk = (fq_rk *)r->queue;
        fq_debug(FQ_DEBUG_ROUTE, "M[%p] -> Q[%.*s]\n", (void *)m, rk->len, rk->name);
        fqd_queue_enqueue(r->queue, m);
      }
    }
  }
  else if(jt->tabletype == JUMPTABLE) {
    int i;
    uint64_t inbits;
    uint8_t *in = m->route.name + offset;
    memcpy(&inbits, in, sizeof(inbits));
    for(i=0;i<jt->pat_len;i++) {
      if(jt->pats[i].pattern == (jt->pats[i].checkbits & inbits)) {
        walk_jump_table(jt->pats[i].jt, m, offset + sizeof(inbits));
      }
    }
  }
}
void
fqd_inject_message(remote_client *c, fq_msg *m) {
  fqd_exchange *e;
  fqd_config *config;
  (void)c;
  config = fqd_config_get();
  e = fqd_config_get_exchange(config, &m->exchange);
  if(e) {
    walk_jump_table(&e->set->master, m, 0);
  }
  else {
    fq_debug(FQ_DEBUG_ROUTE, "No exchange \"%.*s\"\n", m->exchange.len, m->exchange.name);
  }
  fqd_config_release(config);
  fq_msg_deref(m);
}
#define is_hex(a) (((a) > '0' || (a) < '9') || \
                   ((a) > 'a' || (a) < 'f') || \
                   ((a) > 'A' || (a) < 'F'))
#define to_hex_c(a) (((a) > '0' || (a) < 9) ? ((a) - '0') : \
                    ((a) > 'a' || (a) < 'f') ? ((a) - 'a' + 10) : \
                    ((a) > 'A' || (a) < 'F') ? ((a) - 'A' + 10) : 0)
#define to_hex(cp) ((to_hex_c(cp[0]) << 4) || to_hex_c(cp[1]))

static inline int is_term_char(char a, const char *ts, int tslen) {
  int i;
  for(i=0;i<tslen;i++) if(a == ts[i]) return 1;
  return 0;
}
static const char *
parse_prog_string(const char *input, char *tgt, int *tgt_len) {
  const char *term = " ";
  int term_len = 2; /* includes the \0 */
  int max_len = *tgt_len, i = 0;
  if(*input == '\"') {
    input++;
    term = "\"";
    term_len = 1;
  }

  while(*input && i<max_len) {
    if(input[0] == '\\' && input[1] != '\0') {
      input++;
      if(input[0] == 'x' && is_hex(input[1]) && is_hex(input[2])) {
        input++;
        tgt[i++] = to_hex(input);
        input += 2;
      }
      else {
        tgt[i++] = input[1];
        input += 2;
      }
    }
    else {
      if(is_term_char(*input, term, term_len)) {
        if(*input) input++;
        goto out_clean;
      }
      tgt[i++] = *input++;
    }
  }
  if(is_term_char(*input, term, term_len)) goto out_clean;

  /* we failed to find a suitable terminator */
  input = NULL;

  out_clean:
  *tgt_len = i;
  return input;
}
struct fqd_route_rule *
fqd_routemgr_compile(const char *program, int peermode, fqd_queue *q) {
  int len, alen;
  const char *cp;
  struct fqd_route_rule *r;

  assert(q);
  len = strlen(program);
  if(len > (int)sizeof(r->prefix.name)) return NULL;
  if(strncmp(program, "prefix:", 7) && strncmp(program, "exact:", 6)) {
    return NULL;
  }
  cp = strchr(program, ':');
  if(!cp) return NULL;
  cp++;
  r = calloc(1, sizeof(*r));
  alen = sizeof(r->prefix.name);
  cp = parse_prog_string(cp, (char *)r->prefix.name, &alen);
  r->prefix.len = (uint8_t)alen;
  if(cp == NULL) {
    free(r);
    return NULL;
  }
  r->match_maxlen = sizeof(r->prefix.name);
  if(!strncmp(program, "exact:", 6)) r->match_maxlen = r->prefix.len;
  r->program = strdup(program);
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
static void
walk_jump_table_drop_rules_by_queue(struct prefix_jumptable *jt,
                                    fqd_queue *q) {
  if(jt->tabletype == RULETABLE) {
    struct fqd_route_rule *prev = NULL, *r = jt->rules;
    while(r) {
      if(r->queue == q) {
        struct fqd_route_rule *tofree = r;
        if(prev) r = prev->next = r->next;
        else r = jt->rules= r->next;
        fqd_routemgr_rule_free(tofree);
      }
      else r = r->next;
    }
  }
  else if(jt->tabletype == JUMPTABLE) {
    int i;
    for(i=0;i<jt->pat_len;i++)
      walk_jump_table_drop_rules_by_queue(jt->pats[i].jt, q);
  }
}
void
fqd_routemgr_drop_rules_by_queue(fqd_route_rules *set, fqd_queue *q) {
  fq_debug(FQ_DEBUG_ROUTE, "fqd_routemgr_drop_rules_by_queue(%p)\n", (void *)q);
  walk_jump_table_drop_rules_by_queue(&set->master, q);
}
static struct prefix_jumptable *
get_ruletable(struct prefix_jumptable *parent, fqd_route_rule *newrule,
              int offset) {
  uint64_t inbits;
  uint64_t incb = 0;
  int i;
  struct prefix_jumptable *child;

  if(newrule->prefix.len >= (offset+sizeof(inbits))) /* use all the bits */
    incb = ~incb;
  else if(newrule->prefix.len % sizeof(inbits) != 0) /* use partial bits */
    incb = ~incb << ((sizeof(inbits) -
                     (newrule->prefix.len % sizeof(inbits))) *
                    sizeof(inbits));
#if BYTE_ORDER != BIG_ENDIAN
  incb = (((uint64_t)ntohl(incb & 0xffffffffLLU)) << 32) |
         (ntohl((incb &0xffffffff00000000LLU) >> 32));
#endif
  memcpy(&inbits, newrule->prefix.name + offset, sizeof(inbits));

    /* We need to (possibly) insert a rule table */
  for(i=0;i<parent->pat_len;i++) {
    if(parent->pats[i].pattern == (parent->pats[i].checkbits & inbits)) {
      if(parent->pats[i].jt->tabletype == RULETABLE) {
        return parent->pats[i].jt;
      }
      else {
        return get_ruletable(parent->pats[i].jt, newrule, offset + sizeof(inbits));
      }
    }
  }
  child = calloc(1, sizeof(*child));
  if(!child) return NULL;
  child->tabletype = (~incb == 0) ? JUMPTABLE : RULETABLE;

  /* Here we use child->pats as a tmp variable to grow parent->pats */
  child->pats = malloc(sizeof(*child->pats) * (parent->pat_len + 1));
  if(!child->pats) {
    free(child);
    return NULL;
  }
  if(parent->pat_len) {
    memcpy(child->pats, parent->pats, sizeof(*child->pats) * parent->pat_len);
    free(parent->pats);
  }
  parent->pats = child->pats;
  child->pats = NULL;
  parent->pat_len++;
  parent->pats[i].pattern = (inbits & incb);
  parent->pats[i].checkbits = incb;
  parent->pats[i].jt = child;
  if(child->tabletype == RULETABLE) {
    return child;
  }
  return get_ruletable(child, newrule, offset + sizeof(inbits));
}
uint32_t
fqd_routemgr_ruleset_add_rule(fqd_route_rules *set, fqd_route_rule *newrule) {
  fqd_route_rule *r;
  struct prefix_jumptable *jt;
  jt = get_ruletable(&set->master, newrule, 0);

  for(r=jt->rules;r;r=r->next) {
    if(r->queue == newrule->queue &&
       !strcmp(r->program, newrule->program)) {
      fqd_routemgr_rule_free(newrule);
      return r->route_id;
    }
  }
  newrule->route_id = ck_pr_faa_32(&global_route_id, 1);
  newrule->next = jt->rules;
  jt->rules = newrule;
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
static void
copy_jt(struct prefix_jumptable *tgt, struct prefix_jumptable *src) {
  memcpy(tgt, src, sizeof(*src));
  if(src->tabletype == RULETABLE) {
    fqd_route_rule *r, *nhead, *nr, *tmp;
    nhead = nr = NULL;
    for(r=src->rules;r;r=r->next) {
      tmp = copy_rule(r);
      if(!nhead) nhead = tmp;
      if(nr) {
        nr->next = tmp;
      }
      nr = tmp;
    }
    tgt->rules = nhead;
  }
  else if(src->tabletype == JUMPTABLE) {
    int i;
    tgt->pats = malloc(src->pat_len * sizeof(*tgt->pats));
    if(src->pat_len) {
      memcpy(tgt->pats, src->pats, src->pat_len * sizeof(*tgt->pats));
      for(i=0; i<src->pat_len; i++) {
        tgt->pats[i].jt = malloc(sizeof(*tgt->pats[i].jt));
        if(tgt->pats[i].jt) copy_jt(tgt->pats[i].jt, src->pats[i].jt);
      }
    }
  }
}
fqd_route_rules *
fqd_routemgr_ruleset_copy(fqd_route_rules *set) {
  fqd_route_rules *nset;
  nset = fqd_routemgr_ruleset_alloc();
  copy_jt(&nset->master, &set->master);
  /* TODO: compress set */
  return nset;
}
static void
free_jt(struct prefix_jumptable *jt) {
  if(jt->tabletype == RULETABLE) {
    while(jt->rules) {
      fqd_route_rule *r = jt->rules->next;
      fqd_routemgr_rule_free(jt->rules);
      jt->rules = r;
    }
  }
  else if(jt->tabletype == JUMPTABLE) {
    int i;
    for(i=0;i<jt->pat_len;i++) {
      if(jt->pats[i].jt) {
        free_jt(jt->pats[i].jt);
        free(jt->pats[i].jt);
      }
    }
    free(jt->pats);
  }
}
void
fqd_routemgr_ruleset_free(fqd_route_rules *set) {
  free_jt(&set->master);
  free(set);
}
