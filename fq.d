typedef struct {
  uintptr_t  route;
  uintptr_t  sender;
  uintptr_t  exchange;
  uintptr_t  payload;
  uint32_t   payload_len;
} fq_dtrace_msg_t;

typedef struct {
  string    route;
  string    exchange;
  string    sender;
  string    payload;
  uint32_t  payload_len;
} fq_msg_t;

translator fq_msg_t <fq_dtrace_msg_t *m> {
  route = copyinstr(*(uintptr_t *)copyin((uintptr_t)&m->route, sizeof(uintptr_t)));
  exchange = copyinstr(*(uintptr_t *)copyin((uintptr_t)&m->exchange, sizeof(uintptr_t)));
  sender = copyinstr(*(uintptr_t *)copyin((uintptr_t)&m->sender, sizeof(uintptr_t)));
  payload_len = *(uint32_t *)copyin((uintptr_t)&m->payload_len, sizeof(uint32_t));
  payload = copyinstr(*(uintptr_t *)copyin((uintptr_t)&m->payload, sizeof(uintptr_t)), *(uint32_t *)copyin((uintptr_t)&m->payload_len, sizeof(uint32_t)));
};

typedef struct {
  uintptr_t  name;
  int32_t    isprivate;
  int32_t    policy;
  uintptr_t  type;
} fq_dtrace_queue_t;

typedef struct {
  string     name;
  int32_t    isprivate;
  int32_t    policy;
  string     type;
} fq_queue_t;

translator fq_queue_t <fq_dtrace_queue_t *m> {
  name = copyinstr(*(uintptr_t *)copyin((uintptr_t)&m->name, sizeof(uintptr_t)));
  type = copyinstr(*(uintptr_t *)copyin((uintptr_t)&m->type, sizeof(uintptr_t)));
  isprivate = *(uint32_t *)copyin((uintptr_t)&m->isprivate, sizeof(int32_t));
  policy = *(uint32_t *)copyin((uintptr_t)&m->policy, sizeof(int32_t));
};

typedef struct {
  int32_t   fd;
  uintptr_t pretty;
} fq_dtrace_remote_anon_client_t;

typedef struct {
  int32_t  fd;
  string pretty;
} fq_remote_anon_client_t;

translator fq_remote_anon_client_t <fq_dtrace_remote_anon_client_t *c> {
  fd = *(uint32_t *)copyin((uintptr_t)&c->fd, sizeof(int32_t));
  pretty = copyinstr(*(uintptr_t *)copyin((uintptr_t)&c->pretty, sizeof(uintptr_t)));
};
