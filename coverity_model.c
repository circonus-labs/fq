typedef unsigned int uint32_t;
typedef _Bool bool;

void
ck_pr_dec_uint_zero(uint32_t *v, bool *zero) {
  *v = (*v) - 1;
  if(zero) *zero = ((*v) == 0);
}

void
ck_pr_inc_uint(uint32_t *v) {
  *v = (*v) + 1;
}

uint32_t
ck_pr_load_uint(uint32_t *v) {
  return *v;
}

