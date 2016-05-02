local ffi = require('ffi');
local fq = ffi.load("fq")

ffi.cdef[[
static const uint32_t FQ_PROTO_CMD_MODE  = 0xcc50cafe;
static const uint32_t FQ_PROTO_DATA_MODE = 0xcc50face;
static const uint32_t FQ_PROTO_PEER_MODE = 0xcc50fade;
static const uint32_t FQ_PROTO_READ_STAT = 0x47455420;
static const uint32_t FQ_PROTO_HTTP_GET  = 0x47455420;
static const uint32_t FQ_PROTO_HTTP_PUT  = 0x50555420;
static const uint32_t FQ_PROTO_HTTP_POST = 0x504f5354;
static const uint32_t FQ_PROTO_HTTP_HEAD = 0x48454144;

static const uint32_t FQ_BIND_PEER       = 0x00000001;
static const uint32_t FQ_BIND_PERM       = 0x00000110;
static const uint32_t FQ_BIND_TRANS      = 0x00000100;

static const uint32_t FQ_PROTO_ERROR     = 0xeeee;
static const uint32_t FQ_PROTO_AUTH_CMD  = 0xaaaa;
static const uint32_t FQ_PROTO_AUTH_PLAIN = 0;
static const uint32_t FQ_PROTO_AUTH_RESP = 0xaa00;
static const uint32_t FQ_PROTO_HBREQ     = 0x4848;
static const uint32_t FQ_PROTO_HB        = 0xbea7;
static const uint32_t FQ_PROTO_BINDREQ   = 0xb170;
static const uint32_t FQ_PROTO_BIND      = 0xb171;
static const uint32_t FQ_PROTO_UNBINDREQ = 0x071b;
static const uint32_t FQ_PROTO_UNBIND    = 0x171b;
static const uint32_t FQ_PROTO_STATUS    = 0x57a7;
static const uint32_t FQ_PROTO_STATUSREQ = 0xc7a7;
static const uint32_t FQ_BIND_ILLEGAL = 0xffffffff;

static const int MAX_RK_LEN = 127;
static const int MAX_HOPS = 32;
static const int FQ_HOOKS_V1 = 1;
static const int FQ_HOOKS_V2 = 2;
static const int FQ_HOOKS_V3 = 3;

typedef struct fq_rk {
  unsigned char  name[127];
  uint8_t        len;
} fq_rk;

static inline int
fq_rk_cmp(const fq_rk * const a, const fq_rk * const b) {
  if(a->len < b->len) return -1;
  if(a->len > b->len) return 1;
  return memcmp(a->name, b->name, a->len);
}

typedef struct {
  fq_rk exchange;
  uint32_t flags;
  char *program;

  uint32_t out__route_id;
} fq_bind_req;

typedef struct {
  fq_rk exchange;
  uint32_t route_id;

  uint32_t out__success;
} fq_unbind_req;

typedef struct fq_msgid {
  union {
    struct {
      uint32_t p1; /* user(sender) */
      uint32_t p2; /* user(sender) */
      uint32_t p3; /* reserved */
      uint32_t p4; /* reserved */
    } u32;
    unsigned char d[16];
  } id;
} fq_msgid;

typedef struct fq_msg {
  uint32_t       hops[32];
  fq_rk          route;
  fq_rk          sender;
  fq_rk          exchange;
  fq_msgid       sender_msgid;
  uint32_t       refcnt;
  uint32_t       payload_len;
  uint64_t       arrival_time;
  unsigned char  payload[1];  /* over allocated */
} fq_msg;

extern fq_msg *fq_msg_alloc(const void *payload,
                            size_t payload_size);
extern fq_msg *fq_msg_alloc_BLANK(size_t payload_size);
extern void    fq_msg_ref(fq_msg *);
extern void    fq_msg_deref(fq_msg *);
extern void    fq_msg_exchange(fq_msg *, const void *key, int klen);
extern void    fq_msg_route(fq_msg *, const void *key, int klen);
extern void    fq_msg_id(fq_msg *, fq_msgid *id);

typedef struct buffered_msg_reader buffered_msg_reader;

extern buffered_msg_reader *fq_buffered_msg_reader_alloc(int fd, int peermode);
extern void fq_buffered_msg_reader_free(buffered_msg_reader *f);
extern int
  fq_buffered_msg_read(buffered_msg_reader *f,
                       void (*f_msg_handler)(void *, fq_msg *),
                       void *);

/* frame */
/*
 *    1 x uint8_t<net>   hops
 * hops x uint32_t<net>  node
 *    1 x <nstring>      exchange
 *    1 x fq_rk<nstring> sender
 *    1 x fq_rk<nstring> route
 *    1 x uint32_t<net>  payload_len
 *    1 x data
 */


typedef struct fq_conn_s *fq_client;

typedef struct fq_hooks {
  int version;
  /* V1 */
  void (*auth)(fq_client, int);
  void (*bind)(fq_client, fq_bind_req *);
  /* V2 */
  void (*unbind)(fq_client, fq_unbind_req *);
  /* V3 */
  int sync;
} fq_hooks;

extern int
  fq_client_hooks(fq_client conn, fq_hooks *hooks);

extern int
  fq_client_init(fq_client *, int peermode,
                 void (*)(fq_client, const char *));

extern int
  fq_client_creds(fq_client,
                  const char *host, unsigned short port,
                  const char *source, const char *pass);

extern void
  fq_client_status(fq_client conn,
                   void (*f)(char *, uint32_t, void *), void *c);

extern void
  fq_client_heartbeat(fq_client conn, unsigned short ms);

extern void
  fq_client_bind(fq_client conn, fq_bind_req *req);

extern void
  fq_client_unbind(fq_client conn, fq_unbind_req *req);

extern void
  fq_client_set_backlog(fq_client conn, uint32_t len, uint32_t stall);

extern void
  fq_client_set_nonblock(fq_client conn, bool nonblock);

extern int
  fq_client_connect(fq_client conn);

extern int
  fq_client_publish(fq_client, fq_msg *msg);

extern fq_msg *
  fq_client_receive(fq_client conn);

extern int
  fq_client_data_backlog(fq_client conn);

extern int
  fq_rk_to_hex(char *buf, int len, fq_rk *k);

extern int
  fq_read_status(int fd, void (*f)(char *, uint32_t, void *), void *);

extern int
  fq_read_uint16(int fd, unsigned short *v);

extern int
  fq_write_uint16(int fd, unsigned short hs);

extern int
  fq_read_uint32(int fd, uint32_t *v);

extern int
  fq_write_uint32(int fd, uint32_t hs);

extern int
  fq_read_short_cmd(int fd, unsigned short buflen, void *buf);

extern int
  fq_write_short_cmd(int fd, unsigned short buflen, const void *buf);

extern int
  fq_read_long_cmd(int fd, int *len, void **buf);

/* This function returns 0 on success, -1 on failure or a positive
 * integer indicating that a partial write as happened.
 * The initial call should be made with off = 0, if a positive
 * value is returned, a subsequent call should be made with
 * off = (off + return value).
 * The caller must be able to keep track of an accumulated offset
 * in the event that several invocations are required to send the
 * message.
 */
extern int
  fq_client_write_msg(int fd, int peermode, fq_msg *m, size_t off, size_t *written);

typedef enum {
  FQ_POLICY_DROP = 0,
  FQ_POLICY_BLOCK = 1,
} queue_policy_t;

extern void usleep(int);

typedef long time_t;

typedef struct timeval {
        time_t tv_sec;
        time_t tv_usec;
} timeval;

int gettimeofday(struct timeval* t, void* tzp);
]]

local gettimeofday_struct = ffi.new("timeval")
local function gettimeofday()
  ffi.C.gettimeofday(gettimeofday_struct, nil)
  return tonumber(gettimeofday_struct.tv_sec) + tonumber(gettimeofday_struct.tv_usec) / 1000000
end

local logf = function(p,...) io.stderr:write("[fq-client] " .. string.format(p,...) .. "\n") end

local function charstar(str)
  local len = string.len(str)
  local buf = ffi.new("char[?]", len+1, 0)
  ffi.copy(buf, str, len)
  return buf
end

local function m2tab(m)
  return {
    route        = ffi.string(m.route.name, m.route.len),
    sender       = ffi.string(m.sender.name, m.sender.len),
    exchange     = ffi.string(m.exchange.name, m.exchange.len),
    arrival_time = tonumber(m.arrival_time),
    payload      = ffi.string(m.payload, m.payload_len),
  }
end

local function new(host, port, user, pass)
  local binds = {}
  local progs = {}
  local conn = ffi.new("fq_client[?]", 1);
  local object = {}
  local hooks = ffi.new("fq_hooks[?]", 1);
  hooks[0].version = ffi.C.FQ_HOOKS_V3;
  hooks[0].sync = 1
  hooks[0].unbind = nil
  hooks[0].auth = function (c, error)
    logf("called fq.auth()")
    if object.auth_cb ~= nil then return object:auth_cb(error) end
    for i,v in ipairs(binds) do
      fq.fq_client_bind(c, v[0])
    end
  end
  hooks[0].bind = function (c, breq)
    logf("called fq.bind()")
    if object.bind_cb ~= nil then object:bind_cb(breq) end
  end

  logf("fq_client_init()")
  rv = fq.fq_client_init(conn, 0, nil)
  fq.fq_client_hooks(conn[0], hooks)
  logf("calling fq.creds(%s, %d, %s, %s)", host, port, user, pass)
  fq.fq_client_creds(conn[0], host, port, user, pass)
  fq.fq_client_heartbeat(conn[0], 1000);
  fq.fq_client_set_backlog(conn[0], 10000, 100);
  fq.fq_client_set_nonblock(conn[0], false);

  object.conn = conn[0]

  object.bind = function(object, exchange, program, flags)
    logf("Listening on exchange '%s' with program '%s' and flags %o", exchange, program, flags or 0)
    local breq = ffi.new("fq_bind_req[?]", 1)
    ffi.copy(breq[0].exchange.name, exchange)
    breq[0].exchange.len = exchange:len()
    breq[0].flags = flags or fq.FQ_BIND_TRANS
    local cprog = charstar(program)
    breq[0].program = cprog
    table.insert(binds, breq)
    table.insert(progs, cprog); -- not used
  end

  object.connect = function(object)
    logf("calling connect()")
    fq.fq_client_connect(object.conn);
    logf("...connection established")
  end

  object.listen_raw = function(object, callback)
    -- poll on socket and execute callback when message is found
    local sleep_micros     = 1
    local sleep_micros_min = 2
    local sleep_micros_max = 10E3
    while true do
      jit.off()
      local m = fq.fq_client_receive(object.conn)
      if m ~= nil then
        callback(m)
        fq.fq_msg_deref(m)
        sleep_micros = 1
      elseif sleep_micros < sleep_micros_max then
        sleep_micros = sleep_micros * 2
      end
      if sleep_micros > sleep_micros_min then
        ffi.C.usleep(sleep_micros)
      end
      jit.on()
    end
  end

  object.listen = function(object, callback)
    object:listen_raw(function(m) callback(ffi.string(m.payload)) end)
  end

  object.listen_table = function(object, callback)
    object:listen_raw(function(m) callback(m2tab(m)) end)
  end

  object.send = function(object, message, exchange, route)
    local cmsg = charstar(message)
    local cexchange = charstar(exchange)
    local croute = charstar(route)
    local msg = fq.fq_msg_alloc(cmsg, string.len(message))
    fq.fq_msg_exchange(msg, cexchange, string.len(exchange))
    fq.fq_msg_route(msg, croute, string.len(route))

    -- fq is set to be blocking so fq_client_publish will block
    fq.fq_client_publish(object.conn, msg)
    fq.fq_msg_deref(msg)
  end

  return object
end

return {
  new = new,
  usleep = ffi.C.usleep,
  time = gettimeofday,
}
