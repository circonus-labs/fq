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
#include <unistd.h>
#include <string.h>
#include <ck_pr.h>
#include <assert.h>
#include <arpa/nameser_compat.h>
#include <ctype.h>
#include <dlfcn.h>
#include "fqd.h"
#include "fq_dtrace.h"

uint32_t global_route_id = 1;
#define RR_SET_SIZE 32
#define MAX_QUEUE_TARGETS 30

static void prog_free(rulenode_t *);
static void expr_free(exprnode_t *);
static rulenode_t *prog_compile(const char *program, int errlen, char *err);

struct fqd_route_rule {
  fq_rk prefix;
  int match_maxlen;
  char *program;
  rulenode_t *compiled_program;
  uint32_t route_id;
  bool permanent;
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
static bool apply_compiled_program(rulenode_t *, fq_msg *);
static bool
apply_compiled_program(rulenode_t *p, fq_msg *m) {
  bool lval = false, rval = false;
  if(p->left)  lval = apply_compiled_program(p->left, m);
  if(p->right) rval = apply_compiled_program(p->right, m);
  if(p->oper == '|') return lval || rval;
  if(p->oper == '&') return lval && rval;
  if(p->expr) {
    return p->expr->match(m, p->expr->nargs, p->expr->args);
  }
  assert("Bad program" == NULL);
  return false;
}
struct queue_target {
  fqd_queue *tgts[MAX_QUEUE_TARGETS];
  int cnt;
  int allocd;
  struct queue_target *next;
};

static void
add_queue_target(struct queue_target **d, fqd_queue *q) {
  struct queue_target *nd;
  if(!(*d) || (*d)->cnt >= MAX_QUEUE_TARGETS) {
    nd = malloc(sizeof(*nd));
    nd->next = *d;
    nd->cnt = 1;
    nd->allocd = 1;
    fqd_queue_ref(q);
    nd->tgts[0] = q;
    *d = nd;
  }
  else {
    fqd_queue_ref(q);
    (*d)->tgts[(*d)->cnt++] = q;
  }
}
static void
walk_jump_table(struct prefix_jumptable *jt, fq_msg *m, int offset, struct queue_target **d) {
  if(jt->tabletype == RULETABLE) {
    struct fqd_route_rule *r;
    for(r=jt->rules;r;r=r->next) {
      if(m->route.len >= r->prefix.len &&
         m->route.len <= r->match_maxlen) {
        bool matched = false;
        if(FQ_ROUTE_PROGRAM_ENTRY_ENABLED()) {
          fq_dtrace_msg_t dmsg;
          DTRACE_PACK_MSG(&dmsg, m);
          FQ_ROUTE_PROGRAM_ENTRY(r->program, &dmsg);
        }
        if(apply_compiled_program(r->compiled_program, m)) {
          fq_rk *rk = (fq_rk *)r->queue;
          fq_debug(FQ_DEBUG_ROUTE, "M[%p] -> Q[%.*s]\n", (void *)m, rk->len, rk->name);
          add_queue_target(d, r->queue);
          matched = true;
        }
        if(FQ_ROUTE_PROGRAM_RETURN_ENABLED()) {
          fq_dtrace_msg_t dmsg;
          DTRACE_PACK_MSG(&dmsg, m);
          FQ_ROUTE_PROGRAM_RETURN(r->program, &dmsg, matched);
        }
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
        walk_jump_table(jt->pats[i].jt, m, offset + sizeof(inbits), d);
      }
    }
  }
}
void
fqd_inject_message(remote_client *c, fq_msg *m) {
  fqd_exchange *e;
  fqd_config *config;
  struct queue_target stub, *headptr = &stub;
  (void)c;
  stub.next = NULL;
  stub.cnt = 0;
  stub.allocd = 0;
  config = fqd_config_get();
  e = fqd_config_get_exchange(config, &m->exchange);
  fqd_exchange_messages(e, 1);
  fqd_exchange_message_octets(e, m->payload_len);
  if(e) {
    walk_jump_table(&e->set->master, m, 0, &headptr);
  }
  else {
    fq_debug(FQ_DEBUG_ROUTE, "No exchange \"%.*s\"\n", m->exchange.len, m->exchange.name);
    fqd_exchange_no_exchange(NULL, 1);
    c->data->no_exchange++;
  }
  fqd_config_release(config);

  if(headptr->cnt == 0) {
    fqd_exchange_no_route(e, 1);
    c->data->no_route++;
  }
  while(headptr) {
    int i;
    struct queue_target *tofree = headptr;

    for(i=0; i<headptr->cnt; i++) {
      int dropped = 0;
      fqd_queue *q = headptr->tgts[i];

      fqd_queue_enqueue(q, m, &dropped);
      fqd_queue_deref(q);

      if(dropped) {
        fqd_exchange_dropped(e, dropped);
        c->data->dropped += dropped;
      }

      fqd_exchange_routed(e, 1);
      c->data->routed += 1;
    }
    headptr = headptr->next;
    if(tofree->allocd) free(tofree);
  }

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
  char err[128];
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
    fq_debug(FQ_DEBUG_ROUTE, "Failed to parse: %s\n", r->prefix.name);
    free(r);
    return NULL;
  }
  r->compiled_program = prog_compile(cp, sizeof(err), err);
  if(r->compiled_program == NULL) {
    fq_debug(FQ_DEBUG_ROUTE, "Failed to compile[%s]: %s\n", cp, err);
    free(r);
    return NULL;
  }
  r->match_maxlen = sizeof(r->prefix.name);
  if(!strncmp(program, "exact:", 6)) r->match_maxlen = r->prefix.len;
  r->program = strdup(program);
  r->queue = q;
  fqd_queue_ref(r->queue);
  r->peermode = peermode;
  fq_debug(FQ_DEBUG_MEM, "alloc rule [%p/%p] -> Q[%p]\n", (void *)r, (void *)r->compiled_program, (void *)r->queue);
  return r;
}
void
fqd_routemgr_rule_free(struct fqd_route_rule *rule) {
  fq_debug(FQ_DEBUG_ROUTE, "dropping rule \"%s\"\n", rule->program);
  fq_debug(FQ_DEBUG_MEM, "free rule  [%p] -> Q[%p]\n", (void *)rule, (void *)rule->queue);
  free(rule->program);
  prog_free(rule->compiled_program);
  if(rule->queue) fqd_queue_deref(rule->queue);
  free(rule);
}
struct fqd_route_rules *
fqd_routemgr_ruleset_alloc() {
  return calloc(1, sizeof(struct fqd_route_rules));
}
static int
walk_jump_table_setp_by_route_id(struct prefix_jumptable *jt,
                                 uint32_t route_id, bool nv) {
  if(jt->tabletype == RULETABLE) {
    struct fqd_route_rule *prev = NULL, *r = jt->rules;
    while(r) {
      if(r->route_id == route_id) {
        r->permanent = nv;
        return 1;
      }
      else r = r->next;
    }
  }
  else if(jt->tabletype == JUMPTABLE) {
    int i;
    for(i=0;i<jt->pat_len;i++) {
      if(walk_jump_table_setp_by_route_id(jt->pats[i].jt, route_id, nv)) {
        return 1;
      }
    }
  }
  return 0;
}
static int
walk_jump_table_drop_rules_by_route_id(struct prefix_jumptable *jt,
                                       fqd_queue *q,
                                       uint32_t route_id) {
  if(jt->tabletype == RULETABLE) {
    struct fqd_route_rule *prev = NULL, *r = jt->rules;
    while(r) {
      if(r->route_id == route_id &&
         (q == NULL || r->queue == q)) {
        struct fqd_route_rule *tofree = r;
        if(prev) r = prev->next = r->next;
        else r = jt->rules= r->next;
        fqd_routemgr_rule_free(tofree);
        return 1;
      }
      else r = r->next;
    }
  }
  else if(jt->tabletype == JUMPTABLE) {
    int i;
    for(i=0;i<jt->pat_len;i++) {
      if(walk_jump_table_drop_rules_by_route_id(jt->pats[i].jt, q, route_id)) {
        return 1;
      }
    }
  }
  return 0;
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
int
fqd_routemgr_set_permanence_by_route_id(fqd_route_rules *set,
                                        uint32_t route_id, bool nv) {
  return walk_jump_table_setp_by_route_id(&set->master, route_id, nv);
}
int
fqd_routemgr_perm_route_id(fqd_route_rules *set, uint32_t route_id) {
  return fqd_routemgr_set_permanence_by_route_id(set, route_id, true);
}
int
fqd_routemgr_trans_route_id(fqd_route_rules *set, uint32_t route_id) {
  return fqd_routemgr_set_permanence_by_route_id(set, route_id, false);
}
int
fqd_routemgr_drop_rules_by_route_id(fqd_route_rules *set, fqd_queue *q,
                                    uint32_t route_id) {
  fq_debug(FQ_DEBUG_ROUTE, "fqd_routemgr_drop_rules_by_route_id(%p, %p, %u)\n",
           (void *)set, (void *)q, route_id);
  return walk_jump_table_drop_rules_by_route_id(&set->master, q, route_id);
}
void
fqd_routemgr_drop_rules_by_queue(fqd_route_rules *set, fqd_queue *q) {
  fq_debug(FQ_DEBUG_ROUTE, "fqd_routemgr_drop_rules_by_queue(%p, %p)\n",
           (void *)set, (void *)q);
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
fqd_routemgr_ruleset_add_rule(fqd_route_rules *set, fqd_route_rule *newrule,
                              int *isnew) {
  fqd_route_rule *r;
  struct prefix_jumptable *jt;
  jt = get_ruletable(&set->master, newrule, 0);

  for(r=jt->rules;r;r=r->next) {
    if(r->queue == newrule->queue &&
       !strcmp(r->program, newrule->program)) {
      fqd_routemgr_rule_free(newrule);
      if(isnew) *isnew = 0;
      return r->route_id;
    }
  }
  do {
    newrule->route_id = ck_pr_faa_32(&global_route_id, 1);
  } while(newrule->route_id == FQ_BIND_ILLEGAL);
  newrule->next = jt->rules;
  jt->rules = newrule;
  fq_debug(FQ_DEBUG_ROUTE, "rule[%u] -> %p\n", newrule->route_id, (void *)newrule);
  if(isnew) *isnew = 1;
  return newrule->route_id;
}
static rulenode_t *
copy_compiled_program(rulenode_t *in) {
  fq_debug(FQ_DEBUG_MEM, "copy compiled program: %p\n", (void *)in);
  ck_pr_inc_uint(&in->refcnt);
  return in;
}
static fqd_route_rule *
copy_rule(fqd_route_rule *in) {
  fqd_route_rule *out;
  fq_debug(FQ_DEBUG_MEM, "copy from [%p] -> Q[%p]\n", (void *)in, (void *)in->queue);
  out = calloc(1, sizeof(*out));
  memcpy(out, in, sizeof(*out));
  assert(out->queue);
  out->program = strdup(in->program);
  out->compiled_program = copy_compiled_program(in->compiled_program);
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

static void
prog_free(rulenode_t *p) {
  bool zero;
  if(!p) return;
  ck_pr_dec_uint_zero(&p->refcnt, &zero);
  if(!zero) return;
  if(p->left) prog_free(p->left);
  if(p->right) prog_free(p->right);
  if(p->expr) expr_free(p->expr);
  free(p);
}
static void
expr_free(exprnode_t *e) {
  if(!e) return;
  if(e->args) {
    int i;
    for(i=0;i<e->nargs;i++) {
      if(e->args[i].value_type == RP_VALUE_STRING) free(e->args[i].value.s);
    }
    free(e->args);
  }
  free(e);
}

#define EAT_SPACE(p) while(*p != '\0' && isspace(*p)) (p)++
static int is_valid_term_char(char ch, bool first) {
  if((ch >= 'a' && ch <= 'z') ||
     (ch >= 'A' && ch <= 'Z') ||
     (ch == '_')) return 1;
  if(first) return 0;
  if(ch >= '0' && ch <= '9') return 1;
  return 0;
}
static int rule_getterm(const char **cp, char *term, int len) {
  int idx = 0;
  while(idx < (len-1) && is_valid_term_char((*cp)[idx], idx == 0)) {
    term[idx] = (*cp)[idx];
    idx++;
  }
  term[idx] = '\0';
  (*cp) += idx;
  fq_debug(FQ_DEBUG_ROUTE, "term[%s]\n", term);
  if(idx > 0) return 0;
  return 1;
}
static int rule_getstring(const char **cp, valnode_t *arg) {
  const char *begin;
  if(**cp != '\"') return 0;
  (*cp)++;
  begin = *cp;
  while(**cp != '\0') {
    if(**cp == '\\' && (*cp)[1] != '\0') (*cp)++;
    (*cp)++;
    if(**cp == '\"') {
      int len = (*cp) - begin;
      arg->value_type = RP_VALUE_STRING;
      arg->value.s = malloc(len + 1);
      /* TODO: unescape */
      memcpy(arg->value.s, begin, len);
      arg->value.s[len] = '\0';
      return 1;
    }
  }
  return 0;
}
static exprnode_t *
rule_compose_expression(const char *fname, int nargs, valnode_t *args,
                        int errlen, char *err) {
  int i;
  exprnode_t *expr = NULL;
  char symbol_name[256];
  char argsig[MAX_VALNODE_ARGS];
  void *symbol;

  for(i=0;i<nargs;i++) {
    switch(args[i].value_type) {
      case RP_VALUE_STRING:  argsig[i] = 's'; break;
      case RP_VALUE_BOOLEAN: argsig[i] = 'b'; break;
      case RP_VALUE_DOUBLE:  argsig[i] = 'd'; break;
    }
  }
  argsig[i] = '\0';
  snprintf(symbol_name, sizeof(symbol_name), "fqd_route_prog__%s__%s",
           fname, argsig);
#ifdef RTLD_SELF
  symbol = dlsym(RTLD_SELF, symbol_name);
#else
  symbol = dlsym(RTLD_LOCAL, symbol_name);
#endif
  if(!symbol) {
    snprintf(err, errlen, "cannot find symbol: %s\n", symbol_name);
    return NULL;
  }
  expr = calloc(1, sizeof(*expr));
  expr->match = (bool (*)(fq_msg *, int, valnode_t *)) symbol;
  if(nargs > 0) {
    expr->nargs = nargs;
    expr->args = calloc(nargs, sizeof(*expr->args));
    for(i=0; i<nargs; i++) {
      memcpy(&expr->args[i], &args[i], sizeof(*args));
      /* don't need to double the alloc */
    }
  }
  return expr;
}
rulenode_t *rule_parse(const char **cp, int errlen, char *err);
#define rule_parse_busted(fmt, ...) do { \
  snprintf(err, errlen, fmt, __VAR_ARGS__); \
  goto busted; \
} while(0)
rulenode_t *
rule_parse(const char **cp, int errlen, char *err) {
  rulenode_t *nr = NULL;
  EAT_SPACE(*cp); if(**cp == '\0') goto busted;
  fq_debug(FQ_DEBUG_ROUTE, "parse->(%s)\n", *cp);
  if(**cp == '(') {
    (*cp)++;
    EAT_SPACE(*cp); if(**cp == '\0') goto busted;
    nr = calloc(1, sizeof(*nr));
    nr->refcnt = 1;
    nr->left = rule_parse(cp, errlen, err);
    if(nr->left == NULL) goto busted;
    EAT_SPACE(*cp); if(**cp == '\0') goto busted;
    if(**cp == ')') return nr;
    if((*cp)[0] == '&' && (*cp)[1] == '&') nr->oper = '&';
    else if((*cp)[0] == '|' || (*cp)[1] == '|') nr->oper = '|';
    else goto busted;
    (*cp) += 2;
    nr->right = rule_parse(cp, errlen, err);
    if(nr->right == NULL) goto busted;
    EAT_SPACE(*cp); if(**cp == '\0') goto busted;
    if(**cp != ')') goto busted;
    (*cp)++;
    return nr;
  }
  else {
    char term[128];
    int nargs = 0;
    valnode_t args[MAX_VALNODE_ARGS];

    fq_debug(FQ_DEBUG_ROUTE, "parsing function: %s\n", *cp);
    if(rule_getterm(cp, term, sizeof(term))) goto busted;
    EAT_SPACE(*cp); if(**cp == '\0') goto busted;
    if(**cp != '(') goto busted;
    (*cp)++;
    while(**cp != '\0' && **cp != ')') {
      EAT_SPACE(*cp); if(**cp == '\0') goto busted;
      if(nargs > 0) {
        if(**cp != ',') goto busted;
        EAT_SPACE(*cp); if(**cp == '\0') goto busted;
      }
      if(**cp == '\"') {
        if(rule_getstring(cp, &args[nargs])) goto busted;
        nargs++;
      }
      else if(!strcmp(*cp, "true")) {
        args[nargs].value_type = RP_VALUE_BOOLEAN;
        args[nargs].value.b = true;
        nargs++;
        (*cp) += strlen("true");
      }
      else if(!strcmp(*cp, "false")) {
        args[nargs].value_type = RP_VALUE_BOOLEAN;
        args[nargs].value.b = false;
        nargs++;
        (*cp) += strlen("false");
      }
      else {
        char *endptr;
        /* parse a double */
        args[nargs].value_type = RP_VALUE_DOUBLE;
        args[nargs].value.d = strtod(*cp, &endptr);
        if(endptr == *cp) goto busted;
        nargs++;
        *cp = endptr;
      }
      EAT_SPACE(*cp); if(**cp == '\0') goto busted;
    }
    if(**cp != ')') goto busted;
    (*cp)++;
    nr = calloc(1, sizeof(*nr));
    nr->refcnt = 1;
    nr->expr = rule_compose_expression(term, nargs, args, errlen, err);
    if(!nr->expr) {
      int i;
      for(i=0;i<nargs;i++)
        if(args[i].value_type == RP_VALUE_STRING)
          free(args[i].value.s);
      goto busted;
    }
    return nr;
  }

busted:
  fq_debug(FQ_DEBUG_ROUTE, "parse failed at: %s\n", *cp);
  if(nr) {
    if(nr->expr) {
      if(nr->expr->nargs) {
        int i;
        for(i=0;i<nr->expr->nargs;i++)
          if(nr->expr->args[i].value_type == RP_VALUE_STRING)
            free(nr->expr->args[i].value.s);
        free(nr->expr->args);
      }
      free(nr->expr);
    }
    free(nr);
  }
  return NULL;
}
static rulenode_t *
prog_compile(const char *program, int errlen, char *err) {
  EAT_SPACE(program);
  if(*program == '\0') {
    return prog_compile("true()", errlen, err);
  }
  else {
    rulenode_t *nr;
    if(errlen>0) err[0] = '\0';
    nr = rule_parse(&program, errlen, err);
    EAT_SPACE(program);
    if(*program) {
      if(err && err[0] == '\0') snprintf(err, errlen, "trailing trash: %s", program);
      prog_free(nr);
      return NULL;
    }
    return nr;
  }
  if(err) {
    snprintf(err, errlen, "internal route program error");
  }
  return NULL;
}

