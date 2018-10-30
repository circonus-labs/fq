set -o errexit   # Exit script on first error.
set -o nounset   # Treat references to unset variables as errors. 
set -o pipefail  # Use the first non-zero exit code for pipes.

AWK='
BEGIN { out=0 }
/!lua start/ { out=1; next }
/!lua stop/  { out=0; next }
/^$/ {next} # skip whitespace
/^#/ { while (/\\$/) { getline } next }
(out == 1) { print }
'

FFI_HEAD='
local ffi = require("ffi")
local fq = ffi.load("fq")
ffi.cdef [[
extern void usleep(int);

typedef long time_t;

typedef struct timeval {
        time_t tv_sec;
        time_t tv_usec;
} timeval;

int gettimeofday(struct timeval* t, void* tzp);

struct ck_stack_entry {
	struct ck_stack_entry *next;
};
typedef struct ck_stack_entry ck_stack_entry_t;

// Those are defined in fqh as macros
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
'

FFI_TAIL=']]'

printf '%s\n' "$FFI_HEAD" > fqclient.lua
cat ../fq.h | awk "$AWK" | sed 's/MAX_RK_LEN/127/' >> fqclient.lua
printf '%s\n' "$FFI_TAIL" >> fqclient.lua
cat fqclient.lua.tail >> fqclient.lua
