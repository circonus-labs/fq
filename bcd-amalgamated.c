#define BCD_AMALGAMATED
/*
 * Copyright (c) 2015 Backtrace I/O, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef BCD_H
#define BCD_H

#if !defined(__linux__)
#error "Unsupported platform."
#else
/* Needed for asprintf */
# ifndef _GNU_SOURCE
#  define _GNU_SOURCE
# endif
#endif /* __linux__ */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <sys/types.h>
#include <sys/stat.h>

/*
 * A simple self-contained library for out-of-process response of fault
 * conditions.
 */

enum bcd_target {
	BCD_TARGET_PROCESS = 0,
	BCD_TARGET_THREAD
};

struct bcd {
	int fd;
};
typedef struct bcd bcd_t;

struct bcd_error {
	const char *message;
	int errnum;
};
typedef struct bcd_error bcd_error_t;

/* Treat any trace failures as process. */
#define BCD_CF_FATAL_TR_PROCESS	(1U << 0)
#define BCD_CF_FATAL_TR_THREAD	(1U << 1)

/*
 * BCD_EVENT_TRACE indicates that a trace has failed, but this is
 * recoverable. FATAL indicates an unrecoverable error, and it is
 * recommended that the primary process exits as the environment is
 * in an unrecoverable state. The BCD slave will always attempt
 * to clean up after itself.
 */
enum bcd_event {
	BCD_EVENT_TRACE = 1,
	BCD_EVENT_METADATA,
	BCD_EVENT_FATAL,
	BCD_EVENT_OTHER
};

enum bcd_ipc {
	BCD_IPC_UNIX_SOCKET = 0
};

typedef void bcd_error_handler_t(enum bcd_event, pid_t, pid_t, const char *);

#define BCD_CONFIG_VERSION 1

/* Set a unique command name for the monitor process. */
#define BCD_CONFIG_F_SETCOMM (1UL << 0)

struct bcd_config {
	/*
	 * Version of structure, used for ABI compatibility for configuration
	 * structure breaking changes.
	 */
	unsigned int version;

	/* These are currently unused. */
	unsigned long flags;

	/* If set, then protect preforked bcd process from OOM killer. */
	unsigned int oom_adjust;

	/* Asynchronous error handler, defaults to logging to stderr. */
	bcd_error_handler_t *handler;

	/*
	 * Maximum timeout associated with I/O events and tracer. Defaults
	 * to 30 seconds.
	 */
	unsigned int timeout;

	/* Default umask for file creation. */
	mode_t umask;

	/* Ownership of any created files. */
	struct {
		const char *user;
		const char *group;
	} chown;

	/* Credentials for runtime. */
	struct {
		const char *user;
		const char *group;
	} suid;

	/*
	 * Tracer configuration. Right now this relies on command-line options
	 * but can be extended (through path) to support pipes.
	 */
	struct {
		/* Base path is /opt/backtrace/bin/ptrace. */
		const char *path;

		/*
		 * Prefix for key-value options. For example, in ptrace
		 * it is "--kv=". If this is NULL, key-value pairs will
		 * be ignored.
		 */
		const char *kp;

		/*
		 * Separator between key-value pairs. If 0, then kp is
		 * repeated for every key-value pair. Default is ','.
		 */
		char separator;

		/* Seperator between key and value. Default is ':'. */
		char ks;

		/*
		 * Prefix for thread specifier. Defaults to "--thread=". If this
		 * is NULL, then only the process identifier is passed.
		 */
		const char *tp;

		/*
		 * File for redirected stdout/stderr output. If this is NULL or
		 * blank then the tracer outputs to the same stdout/stderr as
		 * the parent process.
		 */
		const char *output_file;
	} invoke;

	/*
	 * IPC mechanism for invoker slave. The only supported mechanism
	 * at the moment is UNIX sockets.
	 */
	enum bcd_ipc ipc_mechanism;

	union {
		/* Configuration structure for UNIX socket. */
		struct {
			/*
			 * The path to the UNIX socket. If NULL, will evaluate
			 * to /tmp/bcd.<pid>.
			 */
			const char *path;
		} us;
	} ipc;

    /*
     * CPU and NUMA node affinity parameters
     */
    struct {
        /*
         * Target CPU core to migrate bcd to. If set to -1, the CPU affinity
         * is unmodified.
         */
        int target_cpu;
    } affinity;
};

/*
 * This must be called for any configuration structure that is passed to
 * bcd_init, before you overwrite the defaults.
 */
#define bcd_config_init(X, Y) \
    bcd_config_init_internal((X), BCD_CONFIG_VERSION, (Y))
int bcd_config_init_internal(struct bcd_config *, unsigned int, bcd_error_t *);

/*
 * Initializes the BCD library. This will prefork a process which will
 * initialize UNIX sockets for IPC. This must be done on a per-process
 * basis.
 */
int bcd_init(const struct bcd_config *, bcd_error_t *);

/*
 * Initialize a handle to the trace slave. Returns -1 on error and
 * sets error object, otherwise returns 0. Handle interface is necessary
 * for clean synchronous semantics, else we rely on fragile signal semantics.
 */
int bcd_attach(bcd_t *, bcd_error_t *);

/*
 * Destroy a handle to the trace slave. Returns -1 on error and
 * sets error object, otherwise returns 0.
 */
int bcd_detach(bcd_t *, bcd_error_t *);

/*
 * Synchronously generates a backtrace. This will invoke the tracer as
 * specified by the configuration and will block until the configured timeout
 * or exit of tracer. Returns -1 due to internal errors or if there was a
 * problem with the tracer.
 */
int bcd_backtrace(const bcd_t *, enum bcd_target, bcd_error_t *);

/*
 * Returns string associated with error message.
 */
const char *bcd_error_message(const bcd_error_t *);

/*
 * Returns error number of error message, this maps to errno
 * if errno is set. If the return value is 0, it should be ignored.
 */
int bcd_error_errno(const bcd_error_t *);

/*
 * Make key-value association. KV-pairs are LIFO-ordered.
 */
int bcd_kv(bcd_t *, const char *, const char *, bcd_error_t *);

/*
 * Add an argument to the command line. Arguments are presented to the tracing
 * process in order.
 */
int bcd_arg(bcd_t *, const char *, bcd_error_t *);

/*
 * Generate a backtrace for calling thread, grouped by error message. This
 * is non-fatal. It is safe to call this from signal context.
 *
 * volatile (and some internal trickery) is used to avoid some compiler
 * optimizations that require more involved debug information.
 */
void bcd_emit(const bcd_t *, volatile const char *);

/*
 * Generate a crash report, including the error message in the error report.
 * This is assumed to be fatal, the caller is required to exit immediately after
 * calling bcd_fatal and can only execute code that is guaranteed to be safe.
 * This should be used in cases where all hell has broken loose and the validity
 * of pointers cannot be trusted.
 *
 * volatile (and some internal trickery) is used to avoid some compiler
 * optimizations that require more involved debug information.
 */
void bcd_fatal(volatile const char *);

/*
 * Associate a new tid with this session. This is useful when attaching in a
 * single thread at start-up and switching to some currently unknown thread at
 * a later time (such as when it faults).
 */
int bcd_associate_tid(const bcd_t *, bcd_error_t *error, pid_t tid);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* BCD_H */
#ifndef BCD_INTERNAL_H
#define BCD_INTERNAL_H

#ifndef BCD_AMALGAMATED
#include "bcd.h"
#include "internal/cc.h"
#include "internal/cf.h"
#include "internal/io.h"
#include "internal/os.h"
#endif /* !BCD_AMALGAMATED */

#endif /* BCD_INTERNAL_H */
#ifndef BCD_INTERNAL_BCD_H
#define BCD_INTERNAL_BCD_H

#include "bcd.h"

void bcd_error_handler_default(enum bcd_event event, pid_t pid, pid_t tid,
    const char *message);
void bcd_error_set(bcd_error_t *, int, const char *);
void bcd_abort(void);

#endif /* BCD_INTERNAL_BCD_H */
#ifndef BCD_INTERNAL_CC_H
#define BCD_INTERNAL_CC_H

#define BCD_CC_SECTION(X) \
	__attribute__((section(X)))
#define BCD_CC_ALIGN(X) \
	__attribute__((aligned(X)))
#define BCD_MD_PAGESIZE	4096ULL
#define BCD_SECTION "BACKTRACE_BCD_SB"

#define BCD_CC_FORCE(M, R)	\
	__asm__ __volatile__("" : "=m" (M) : "q" (*(R)) : "memory");

#endif /* BCD_INTERNAL_CC_H */
#ifndef BCD_INTERNAL_CF_H
#define BCD_INTERNAL_CF_H

struct bcd_config_internal {
	/*
	 * Version of structure, used for ABI compatibility for configuration
	 * structure breaking changes.
	 */
	unsigned int version;

	/* These are currently unused. */
	unsigned long flags;

	/* If set, then protect preforked bcd process from OOM killer. */
	unsigned int oom_adjust;

	/* Asynchronous error handler, defaults to logging to stderr. */
	bcd_error_handler_t *handler;

	/*
	 * Maximum timeout associated with I/O events and tracer. Defaults
	 * to 30 seconds.
	 */
	unsigned int timeout;

	/* Default umask for file creation. */
	mode_t umask;

	/* Ownership of any created files. */
	struct {
		const char *user;
		const char *group;
	} chown;

	/* Credentials for runtime. */
	struct {
		const char *user;
		const char *group;
	} suid;

	/*
	 * Tracer configuration. Right now this relies on command-line options
	 * but can be extended (through path) to support pipes.
	 */
	struct {
		/* Base path is /opt/backtrace/bin/ptrace. */
		const char *path;

		/*
		 * Prefix for key-value options. For example, in ptrace
		 * it is "--kv=". If this is NULL, key-value pairs will
		 * be ignored.
		 */
		const char *kp;

		/*
		 * Separator between key-value pairs. If 0, then kp is
		 * repeated for every key-value pair. Default is ','.
		 */
		char separator;

		/* Seperator between key and value. Default is ':'. */
		char ks;

		/*
		 * Prefix for thread specifier. Defaults to "--thread=". If this
		 * is NULL, then only the process identifier is passed.
		 */
		const char *tp;

		/*
		 * File for redirected stdout/stderr output. If this is NULL or
		 * blank then the tracer outputs to the same stdout/stderr as
		 * the parent process.
		 */
		const char *output_file;
	} invoke;

	/*
	 * IPC mechanism for invoker slave. The only supported mechanism
	 * at the moment is UNIX sockets.
	 */
	enum bcd_ipc ipc_mechanism;

	union {
		/* Configuration structure for UNIX socket. */
		struct {
			/*
			 * The path to the UNIX socket. If NULL, will evaluate
			 * to /tmp/bcd.<pid>.
			 */
			const char *path;
		} us;
	} ipc;

    /*
     * CPU and NUMA node affinity parameters
     */
    struct {
        /*
         * CPU to bind ourselves to. If -1, we don't bother setting our
         * affinity.
         */
        int target_cpu;
    } affinity;
};

extern struct bcd_config_internal bcd_config;

struct bcd_config_v1 {
	/*
	 * Version of structure, used for ABI compatibility for configuration
	 * structure breaking changes.
	 */
	unsigned int version;

	/* These are currently unused. */
	unsigned long flags;

	/* If set, then protect preforked bcd process from OOM killer. */
	unsigned int oom_adjust;

	/* Asynchronous error handler, defaults to logging to stderr. */
	bcd_error_handler_t *handler;

	/*
	 * Maximum timeout associated with I/O events and tracer. Defaults
	 * to 30 seconds.
	 */
	unsigned int timeout;

	/* Default umask for file creation. */
	mode_t umask;

	/* Ownership of any created files. */
	struct {
		const char *user;
		const char *group;
	} chown;

	/* Credentials for runtime. */
	struct {
		const char *user;
		const char *group;
	} suid;

	/*
	 * Tracer configuration. Right now this relies on command-line options
	 * but can be extended (through path) to support pipes.
	 */
	struct {
		/* Base path is /opt/backtrace/bin/ptrace. */
		const char *path;

		/*
		 * Prefix for key-value options. For example, in ptrace
		 * it is "--kv=". If this is NULL, key-value pairs will
		 * be ignored.
		 */
		const char *kp;

		/*
		 * Separator between key-value pairs. If 0, then kp is
		 * repeated for every key-value pair. Default is ','.
		 */
		char separator;

		/* Seperator between key and value. Default is ':'. */
		char ks;

		/*
		 * Prefix for thread specifier. Defaults to "--thread=". If this
		 * is NULL, then only the process identifier is passed.
		 */
		const char *tp;

		/*
		 * File for redirected stdout/stderr output. If this is NULL or
		 * blank then the tracer outputs to the same stdout/stderr as
		 * the parent process.
		 */
		const char *output_file;
	} invoke;

	/*
	 * IPC mechanism for invoker slave. The only supported mechanism
	 * at the moment is UNIX sockets.
	 */
	enum bcd_ipc ipc_mechanism;

	union {
		/* Configuration structure for UNIX socket. */
		struct {
			/*
			 * The path to the UNIX socket. If NULL, will evaluate
			 * to /tmp/bcd.<pid>.
			 */
			const char *path;
		} us;
	} ipc;

    /*
     * CPU and NUMA node affinity parameters
     */
    struct {
        /*
         * Target CPU core to migrate bcd to. If set to -1, the CPU affinity
         * is unmodified.
         */
        int target_cpu;
    } affinity;
};

typedef struct bcd_config_v1 bcd_config_latest_version_t;

/*
 * Initializes a bcd_config configuration struct based on the specified version.
 */
#ifndef BCD_AMALGAMATED
int bcd_config_init_internal(struct bcd_config *,
    unsigned int, bcd_error_t *);
#endif

/*
 * Assigns a versioned configuration to our internal configuration.
 */
int bcd_config_assign(const void *, struct bcd_error *);


#endif /* BCD_INTERNAL_CF_H */
#ifndef BCD_INTERNAL_IO_H
#define BCD_INTERNAL_IO_H

#include <sys/queue.h>

#include "bcd.h"

#ifdef __linux__
#include <sys/epoll.h>

#define BCD_IO_EVENT_READ	(EPOLLIN | EPOLLET)
#define BCD_IO_EVENT_WRITE	(EPOLLOUT | EPOLLET)

#ifdef EPOLLRDHUP
#define BCD_IO_EVENT_CLOSE	(EPOLLRDHUP)
#else
#define BCD_IO_EVENT_CLOSE	(EPOLLHUP)
#endif /* !EPOLLRDHUP */

#endif /* __linux__ */

struct bcd_io_event;
typedef void bcd_io_event_handler_t(struct bcd_io_event *);

enum bcd_io_event_flags {
	BCD_IO_EVENT_IN_READY_LIST = 1
};


struct bcd_io_event {
	int fd;
	unsigned int mask;
	bcd_io_event_handler_t *handler;
	enum bcd_io_event_flags flags;
	TAILQ_ENTRY(bcd_io_event) readylink;
	char payload[];
};
typedef struct bcd_io_event bcd_io_event_t;

static inline unsigned int
bcd_io_event_mask(const struct bcd_io_event *event)
{

	return event->mask;
}

static inline void
bcd_io_event_unset(struct bcd_io_event *event, unsigned int mask)
{

	event->mask &= ~mask;
	return;
}

static inline void *
bcd_io_event_payload(struct bcd_io_event *event)
{

	return (void *)event->payload;
}

bcd_io_event_t *bcd_io_event_create(int, bcd_io_event_handler_t *, size_t,
    bcd_error_t *);
void bcd_io_event_destroy(bcd_io_event_t *);
int bcd_io_event_add(bcd_io_event_t *, unsigned int, bcd_error_t *);
int bcd_io_event_remove(bcd_io_event_t *, bcd_error_t *);
int bcd_io_event_has_error(bcd_io_event_t *);

void bcd_io_event_add_to_ready_list(struct bcd_io_event *);
void bcd_io_event_remove_from_ready_list(struct bcd_io_event *);
int bcd_io_event_ready_list_is_empty(void);
void bcd_io_event_dispatch_ready_list(void);

struct bcd_io_listener;
typedef struct bcd_io_listener bcd_io_listener_t;

bcd_io_listener_t *bcd_io_listener_unix(const char *, int, bcd_error_t *);
int bcd_io_listener_fd(const bcd_io_listener_t *);

typedef void bcd_io_listener_handler_t(bcd_io_event_t *,
    unsigned int, void *);

int bcd_io_listener_handler(bcd_io_listener_t *,
    bcd_io_listener_handler_t *,
    bcd_io_event_handler_t *,
    size_t,
    bcd_error_t *);

enum bcd_io_fd_wait {
	BCD_IO_FD_WAIT_RD = 0,
	BCD_IO_FD_WAIT_WR
};

int bcd_io_init(bcd_error_t *);
int bcd_io_enter(bcd_error_t *);
void bcd_io_fd_close(int);
int bcd_io_fd_prepare(int);
ssize_t bcd_io_fd_write(int, const void *, size_t, time_t);
ssize_t bcd_io_fd_read(int, void *, size_t, time_t);
int bcd_io_fd_wait(int, enum bcd_io_fd_wait, time_t);

#endif /* BCD_INTERNAL_IO_H */
#ifndef BCD_INTERNAL_OS_H
#define BCD_INTERNAL_OS_H

#include "bcd.h"

int bcd_os_oom_adjust(bcd_error_t *);
time_t bcd_os_time(void);
int bcd_set_cpu_affinity(int);
int bcd_setcomm(const char *);

#endif /* BCD_INTERNAL_OS_H */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#ifdef __linux__
#include <sched.h>
#include <sys/types.h>
#include <sys/syscall.h>
#endif /* __linux__ */

#ifndef BCD_AMALGAMATED
#include "internal.h"
#endif /* !BCD_AMALGAMATED */

#define BCD_MAGIC(N) \
	bcd_MAGICAL_UNICORNS_##N

/*
 * Critical communication goes over the pipe, such as total program
 * failure events and early initialization.
 */
struct bcd_pipe {
	int fd[2];
};
typedef struct bcd_pipe bcd_pipe_t;

enum bcd_op {
	/*
	 * Communicates configuration information through pipes, includes
	 * UNIX socket details.
	 */
	BCD_OP_CF = 0,

	/* Server completion of last command. */
	BCD_OP_OK,

	/* Client acknowledges thread-identifier. */
	BCD_OP_TID,

	/* Client set of key-value pair. */
	BCD_OP_KV,

	BCD_OP_TR_PROCESS,
	BCD_OP_TR_THREAD,
	BCD_OP_TR_FATAL,

	/* Client tells slave to detach. */
	BCD_OP_DETACH,

	/* Client sends argument to ptrace */
	BCD_OP_ARG,
};

struct bcd_packet {
	enum bcd_op op;
	unsigned int length;
	char payload[0];
};

#ifndef BCD_SB_PATH
#define BCD_SB_PATH 1024
#endif /* BCD_SB_PATH */

#ifndef BCD_PACKET_LIMIT
#define BCD_PACKET_LIMIT 1024
#endif /* BCD_PACKET_LIMIT */

struct bcd_kv {
	LIST_ENTRY(bcd_kv) linkage;
	const char *key;
	const char *value;
};
static LIST_HEAD(, bcd_kv) bcd_kv_list = LIST_HEAD_INITIALIZER(&bcd_kv_list);
static size_t bcd_kv_length;
static size_t bcd_kv_count;

struct bcd_arg {
	TAILQ_ENTRY(bcd_arg) linkage;
	const char *arg;
};

static TAILQ_HEAD(, bcd_arg) bcd_arg_list;
static size_t bcd_arg_length;
static size_t bcd_arg_count;

static char *bcd_target_process;

static sig_atomic_t sigalrm_fired;
static sig_atomic_t sigchld_fired;
static sig_atomic_t sigterm_fired;

typedef void bcd_signal_handler_t(int);

static int bcd_sb_read(bcd_pipe_t *, struct bcd_packet *, size_t, time_t,
    bcd_error_t *);
static ssize_t bcd_sb_write(bcd_pipe_t *, enum bcd_op, struct bcd_packet *,
    size_t, time_t);

#ifndef BCD_ARGC_LIMIT
#define BCD_ARGC_LIMIT 32
#endif /* BCD_ARGC_LIMIT */

#ifndef BCD_ARGV_LIMIT
#define BCD_ARGV_LIMIT 1024
#endif /* BCD_ARGV_LIMIT */

#ifndef BCD_KV_LIMIT
#define BCD_KV_LIMIT 1024
#endif /* BCD_KV_LIMIT */

struct bcd_sb {
	pid_t master_pid;
	pid_t slave_pid;
	bcd_pipe_t master;
	bcd_pipe_t slave;
	char path[BCD_SB_PATH];
	int output_fd;
};

static union {
	struct bcd_sb sb;
	char storage[BCD_MD_PAGESIZE];
} pcb BCD_CC_ALIGN(BCD_MD_PAGESIZE) BCD_CC_SECTION("BACKTRACE_IO_BCD");

#define BCD_PACKET_INSTANCE(L)			\
	struct {				\
		struct bcd_packet packet;	\
		char payload[L];		\
	}

#define BCD_PACKET(P)	      (&(P)->packet)
#define BCD_PACKET_PAYLOAD(P) ((void *)((P)->payload))

/*
 * BCD_PACKET_SIZE should only be called when BCD_PACKET_INSTANCE is invoked
 * with a non-zero argument. It should be used for static lengths in the same
 * context one would use sizeof (*ptr) (instead of baking the type into the
 * code).
 */
#define BCD_PACKET_SIZE(P)    (sizeof ((P)->payload))

enum bcd_session_state {
	BCD_SESSION_READING,
	BCD_SESSION_WRITING
};

struct bcd_session {
	pid_t tid;
	enum bcd_session_state state;
	int terminated;
	size_t offset;
	BCD_PACKET_INSTANCE(BCD_PACKET_LIMIT) packet;
};


static void bcd_handler_request_response(bcd_io_event_t *client);
static int bcd_read_request(int fd, struct bcd_session *);
static int bcd_perform_request(struct bcd_session *session);
static int bcd_write_ack(int fd, struct bcd_session *);

static void
handle_sigalrm(int sig)
{

	(void)sig;
	sigalrm_fired = 1;
	return;
}


static void
handle_sigchld(int sig)
{

	(void)sig;
	sigchld_fired = 1;
	return;
}

static void
handle_sigterm(int sig)
{

	(void)sig;
	sigterm_fired = 1;
	return;
}

static int
bcd_error(enum bcd_event event, const struct bcd_session *session,
    const char *string)
{
	pid_t tid = 0;

	if (session != NULL)
		tid = session->tid;

	bcd_config.handler(event, pcb.sb.master_pid, tid, string);
	return -1;
}

const char *
bcd_error_message(const struct bcd_error *const e)
{

	return e->message;
}

int
bcd_error_errno(const struct bcd_error *const e)
{

	return e->errnum;
}

static void
bcd_child_exit(int e)
{

	unlink(bcd_config.ipc.us.path);
	_exit(e);
}

#ifdef __linux__
#ifndef gettid
static pid_t
gettid(void)
{

	return syscall(__NR_gettid);
}
#endif /* !gettid */
#endif /* __linux__ */

void
bcd_error_handler_default(enum bcd_event event, pid_t pid, pid_t tid,
    const char *message)
{

	fprintf(stderr, "[%d] process(%ju)/thread(%ju): %s\n",
	    event, (uintmax_t)pid, (uintmax_t)tid, message);
	return;
}

void
bcd_error_set(struct bcd_error *e, int err, const char *m)
{

	e->errnum = err;
	e->message = m;
	return;
}

static void
bcd_pipe_ensure_readonly(struct bcd_pipe *p)
{

	while (close(p->fd[1]) == -1 && errno == EINTR);
	p->fd[1] = -1;
	return;
}

static void
bcd_pipe_ensure_writeonly(struct bcd_pipe *p)
{

	while (close(p->fd[0]) == -1 && errno == EINTR);
	p->fd[0] = -1;
	return;
}

static int
bcd_pipe_init(struct bcd_pipe *p, struct bcd_error *error)
{

	if (pipe(p->fd) == -1) {
		bcd_error_set(error, errno, "could not create create pipe");
		return -1;
	}

	if (bcd_io_fd_prepare(p->fd[0]) == -1 ||
	    bcd_io_fd_prepare(p->fd[1]) == -1) {
		bcd_error_set(error, errno,
		    "internal descriptor management error");
		goto fail;
	}

	return 0;

fail:
	bcd_io_fd_close(p->fd[0]);
	bcd_io_fd_close(p->fd[1]);
	return -1;
}

static void
bcd_pipe_deinit(struct bcd_pipe *p)
{

	bcd_io_fd_close(p->fd[0]);
	bcd_io_fd_close(p->fd[1]);
	return;
}

static ssize_t
bcd_packet_write(int fd, struct bcd_packet *packet, size_t length,
    time_t timeout_abstime)
{

	packet->length = length;
	return bcd_io_fd_write(fd, packet, sizeof(*packet) + length,
	    timeout_abstime);
}

static void
bcd_handler_accept(bcd_io_event_t *client, unsigned int mask, void *closure)
{
	struct bcd_session *session = closure;
	bcd_error_t error;

	(void)mask;

	memset(session, 0, sizeof *session);
	if (bcd_io_event_add(client,
	    BCD_IO_EVENT_READ | BCD_IO_EVENT_WRITE | BCD_IO_EVENT_CLOSE,
	    &error) == -1) {
		bcd_io_event_destroy(client);
	}

	return;
}

static int
bcd_write_ack(int fd, struct bcd_session *session)
{
	struct bcd_packet *packet = BCD_PACKET(&session->packet);
	size_t ac = session->offset;

	packet->op = BCD_OP_OK;
	packet->length = 0;

	do {
		ssize_t r = write(fd, (char *)packet + ac,
		    sizeof(*packet) - ac);

		if (r == -1) {
			if (errno == EINTR)
				continue;

			if (errno == EAGAIN) {
				session->offset = ac;
				return -1;
			}

			bcd_error(BCD_EVENT_FATAL, session,
			    "unknown communication error");
			bcd_child_exit(EXIT_FAILURE);
		}

		if (r == 0) {
			bcd_error(BCD_EVENT_FATAL, session,
			    "premature process termination");
			bcd_child_exit(EXIT_FAILURE);
		}

		ac += (size_t)r;
	} while (ac < sizeof *packet);

	session->offset = 0;

	return 0;
}

static int
bcd_channel_read_ack(int fd, time_t timeout_abstime, bcd_error_t *error)
{
	BCD_PACKET_INSTANCE(0) st;
	struct bcd_packet *packet = BCD_PACKET(&st);
	ssize_t r;
	ssize_t ac = 0;

	packet->op = BCD_OP_OK;
	packet->length = 0;

	r = bcd_io_fd_read(fd, (char *)packet + ac, sizeof(*packet),
	    timeout_abstime);
	if (r < 0) {
		if (errno == EAGAIN) {
			bcd_error_set(error, errno, "timed out");
		} else {
			bcd_error_set(error, errno, "failed to acknowledge");
		}
		return -1;
	} else if (r == 0) {
		bcd_error_set(error, 0, "premature termination");
		return -1;
	} else if ((size_t)r < sizeof(*packet)) {
		bcd_error_set(error, 0, "truncated response");
		return -1;
	}

	assert(r == sizeof(*packet));

	if (packet->op != BCD_OP_OK) {
		bcd_error_set(error, 0, "dispatch failed");
		return -1;
	}

	return 0;
}

/*
 * Requests trace and signals child that it should exit.
 */
void
bcd_fatal(volatile const char *message)
{
	BCD_PACKET_INSTANCE(0) st;
	struct bcd_packet *packet = BCD_PACKET(&st);
	bcd_pipe_t *pd = &pcb.sb.master;
	volatile const char *BCD_MAGIC(message);
	bcd_error_t error;
	time_t timeout_abstime = bcd_os_time() + bcd_config.timeout;

	BCD_MAGIC(message) = message;
	BCD_CC_FORCE(BCD_MAGIC(message), message);

	bcd_sb_write(pd, BCD_OP_TR_FATAL, packet, 0, timeout_abstime);

	/* Wait for child to exit. */
	bcd_sb_read(&pcb.sb.slave, packet, 0, timeout_abstime, &error);
	return;
}

/*
 * Construct key-value string according to latest key-value list.
 *   - output: Array of pointers to strings.
 *   - n_output: Length of array.
 *   - s: Seperator, if specified, then only the first element of output
 *     is set. Otherwise, prefix is duplicated.
 *   - ks: Key-value seperator.
 *   - prefix: The prefix for the option. For example, "--kv=" or "-k".
 */
static ssize_t
bcd_kv_get(char **output, size_t n_output,
    const char s, const char ks, const char *prefix, bcd_error_t *error)
{
	struct bcd_kv *cursor;
	size_t limit = n_output;
	size_t i = 0;

	if (bcd_kv_count == 0 ||
	    bcd_config.invoke.kp == NULL) {
		return 0;
	}

	if (n_output > bcd_kv_count)
		limit = bcd_kv_count;

	if (limit > BCD_ARGC_LIMIT)
		limit = BCD_ARGC_LIMIT;

	if (s == 0) {
		LIST_FOREACH(cursor, &bcd_kv_list, linkage) {
			int ra;

			if (i == limit)
				break;

			ra = asprintf(&output[i++], "%s%s%c%s",
			    prefix, cursor->key, ks, cursor->value);
			if (ra == -1) {
				bcd_error_set(error, 0, "failed to allocate "
				    "key-value pair");
				goto fail;
			}
		}
	} else {
		size_t p_l = strlen(prefix);

		i++;

		output[0] = malloc(p_l + bcd_kv_count +
		    bcd_kv_length + 1);
		if (output[0] == NULL) {
			bcd_error_set(error, 0, "failed to allocate single "
			    "key-value pair list");
			goto fail;
		}

		memcpy(output[0], prefix, p_l);
		LIST_FOREACH(cursor, &bcd_kv_list, linkage) {
			size_t delta = strlen(cursor->key);

			memcpy(output[0] + p_l, cursor->key, delta);
			p_l += delta;
			output[0][p_l++] = ks;

			delta = strlen(cursor->value);
			memcpy(output[0] + p_l, cursor->value, delta);
			p_l += delta;

			if (LIST_NEXT(cursor, linkage) != NULL)
				output[0][p_l++] = s;
		}
		output[0][p_l] = '\0';
	}

	return (ssize_t)i;

fail:
	while (i-- > 0)
		free(output[i]);

	return -1;
}

static int
bcd_kv_set(struct bcd_session *session, struct bcd_packet *packet)
{
	struct bcd_kv *kv, *previous;
	const char *key = packet->payload;
	const char *value;
	char *stream, *e;
	size_t k_l, v_l;

	if (*key == '\0')
		goto fail;

	value = memchr(key, '\0', packet->length);
	if (value == NULL)
		goto fail;
	k_l = value - key;

	value++;
	e = memchr(value, '\0', packet->length - k_l - 1);
	if (e == NULL)
		goto fail;
	v_l = e - value;

	if (value >= packet->payload + packet->length)
		goto fail;

	kv = malloc(sizeof(*kv) + k_l + v_l + 2);
	if (kv == NULL) {
		return bcd_error(BCD_EVENT_METADATA, session,
		    "internal memory allocation error");
	}

	if (bcd_kv_count == 0)
		LIST_INIT(&bcd_kv_list);

	LIST_FOREACH(previous, &bcd_kv_list, linkage) {
		if (strcmp(previous->key, key) == 0) {
			bcd_kv_length -= strlen(previous->key) +
			    strlen(previous->value) + 1;
			LIST_REMOVE(previous, linkage);
			free(previous);
			bcd_kv_count--;
			break;
		}
	}

	stream = (char *)&kv[1];
	memcpy(stream, key, k_l + 1);
	kv->key = stream;

	memcpy(stream + k_l + 1, value, v_l + 1);
	kv->value = stream + k_l + 1;

	LIST_INSERT_HEAD(&bcd_kv_list, kv, linkage);
	bcd_kv_count++;
	bcd_kv_length += k_l + v_l + 1;
	return 0;
fail:
	return bcd_error(BCD_EVENT_METADATA, session,
	    "malformed key-value pair");
}

static ssize_t
bcd_arg_get(char **output, size_t n_output, bcd_error_t *error)
{
	struct bcd_arg *cursor;
	size_t limit = n_output;
	size_t i = 0;

	if (bcd_arg_count == 0) {
		return 0;
	}

	if (n_output > bcd_arg_count)
		limit = bcd_arg_count;

	if (limit > BCD_ARGC_LIMIT)
		limit = BCD_ARGC_LIMIT;

	TAILQ_FOREACH(cursor, &bcd_arg_list, linkage) {
		int ra;

		if (i == limit)
			break;

		ra = asprintf(&output[i++], "%s", cursor->arg);
		if (ra == -1) {
			bcd_error_set(error, 0, "failed to allocate arg");
			goto fail;
		}
	}

	return (ssize_t)i;
fail:
	while (i-- > 0)
		free(output[i]);

	return -1;
}

static int
bcd_arg_set(struct bcd_session *session, struct bcd_packet *packet)
{
	const char *arg = packet->payload;
	struct bcd_arg *argp, *cursor;
	size_t arglen;
	char *stream;

	arglen = strlen(arg);
	if (arglen == 0)
		goto fail;

	argp = malloc(sizeof(*argp) + arglen + 1);
	if (argp == NULL) {
		return bcd_error(BCD_EVENT_METADATA, session,
		    "internal memory allocation error");
	}

	if (bcd_arg_count == 0) {
		TAILQ_INIT(&bcd_arg_list);
	} else {
		TAILQ_FOREACH(cursor, &bcd_arg_list, linkage) {
			if (strcmp(cursor->arg, arg) == 0) {
				bcd_arg_length -= strlen(cursor->arg) + 1;
				TAILQ_REMOVE(&bcd_arg_list, cursor, linkage);
				free(cursor);
				bcd_arg_count--;
				break;
			}
		}
	}

	stream = (char *)&argp[1];
	memcpy(stream, arg, arglen + 1);
	argp->arg = stream;

	TAILQ_INSERT_TAIL(&bcd_arg_list, argp, linkage);
	bcd_arg_count++;
	bcd_arg_length += arglen + 1;
	return 0;
fail:
	return bcd_error(BCD_EVENT_METADATA, session,
	    "malformed argument");
}

int
bcd_backtrace(const struct bcd *const bcd,
    enum bcd_target target, bcd_error_t *error)
{
	struct bcd_packet packet;
	ssize_t r;
	time_t timeout_abstime = bcd_os_time() + bcd_config.timeout;

	packet.op = BCD_OP_TR_PROCESS;
	if (target == BCD_TARGET_THREAD)
		packet.op = BCD_OP_TR_THREAD;

	packet.length = 0;
	r = bcd_packet_write(bcd->fd, &packet, 0, timeout_abstime);
	if (r < 0) {
		bcd_error_set(error, errno, "failed to invoke tracer");
		return -1;
	}

	return bcd_channel_read_ack(bcd->fd, timeout_abstime, error);
}

void
bcd_emit(const struct bcd *const bcd, volatile const char *message)
{
	volatile const char *BCD_MAGIC(message);
	bcd_error_t error;

	BCD_MAGIC(message) = message;
	BCD_CC_FORCE(BCD_MAGIC(message), message);

	bcd_backtrace(bcd, BCD_TARGET_THREAD, &error);
	return;
}

void
bcd_abort(void)
{

	bcd_error(BCD_EVENT_FATAL, NULL, "unrecoverable internal error");
	return;
}

static pid_t
vfork_tracer(char **argv)
{
	pid_t tracer_pid;

	tracer_pid = vfork();
	if (tracer_pid == 0) {
		if (execve(bcd_config.invoke.path, argv, NULL) == -1)
			_exit(EXIT_FAILURE);
	}

	return tracer_pid;
}

/*
 * bcd_execve is guaranteed to never mutate arguments argv[N]
 * where N < fr.
 */
static int
bcd_execve(struct bcd_session *session, char **argv, size_t fr)
{
	sigset_t blockset, interestset, origset;
	bcd_signal_handler_t *old_sigalrm_handler,
	    *old_sigchld_handler, *old_sigterm_handler;
	pid_t tracer_pid;
	int retval = 0;
	int sig, tracer_status;
	int wait_ret = 0;

	sigfillset(&blockset);
	sigemptyset(&interestset);
	sigaddset(&interestset, SIGALRM);
	sigaddset(&interestset, SIGCHLD);
	sigaddset(&interestset, SIGTERM);
	sigprocmask(0, NULL, &origset);

	sigalrm_fired = 0;
	old_sigalrm_handler = signal(SIGALRM, handle_sigalrm);
	sigchld_fired = 0;
	old_sigchld_handler = signal(SIGCHLD, handle_sigchld);
	sigterm_fired = 0;
	old_sigterm_handler = signal(SIGTERM, handle_sigterm);

	if (bcd_config.timeout != 0)
		alarm(bcd_config.timeout);

	tracer_pid = vfork_tracer(argv);
	if (tracer_pid == -1) {
		retval = bcd_error(BCD_EVENT_TRACE, session,
		    "failed to execute tracer");
		goto leave;
	}

	sigprocmask(SIG_SETMASK, &blockset, NULL);

	for (;;) {
		/*
		 * Handle the cases where SIGALRM, SIGCHLD, or SIGTERM fired
		 * after vfork() and before sigprocmask().
		 */
		if (sigterm_fired) {
			sig = SIGTERM;
			sigterm_fired = 0;
		} else if (sigchld_fired) {
			sig = SIGCHLD;
			sigchld_fired = 0;
		} else if (sigalrm_fired) {
			sig = SIGALRM;
			sigalrm_fired = 0;
		} else
			sigwait(&interestset, (int *)&sig);

		switch (sig) {
		case SIGALRM:
			kill(tracer_pid, SIGKILL);
			retval = bcd_error(BCD_EVENT_TRACE, session,
			    "tracer time out");
			goto leave;
		case SIGCHLD:
			wait_ret = waitpid(tracer_pid, (int *)&tracer_status,
			    WNOHANG);
			if (wait_ret == -1) {
				retval = bcd_error(BCD_EVENT_TRACE,
				    session, "failed to wait for tracer");
				goto leave;
			} else if (wait_ret == 0) {
				/* SIGCHLD was for another child process. */
				continue;
			}
			assert(wait_ret == tracer_pid);
			if (!WIFEXITED(tracer_status) &&
			    !WIFSIGNALED(tracer_status))
				continue;
			if (WIFEXITED(tracer_status)) {
				if (WEXITSTATUS(tracer_status) != 0) {
					retval = bcd_error(BCD_EVENT_TRACE,
					    session, "tracer exited non-zero");
					goto leave;
				}
			}
			if (WIFSIGNALED(tracer_status)) {
				retval = bcd_error(BCD_EVENT_TRACE, session,
				    "tracer killed with signal");
				goto leave;
			}
			/* The tracer exited successfully. */
			assert(WIFEXITED(tracer_status));
			assert(WEXITSTATUS(tracer_status) == 0);
			assert(retval == 0);
			goto leave;
		case SIGTERM:
			kill(tracer_pid, SIGTERM);
			_exit(128 + SIGTERM); /* Per POSIX */
		default:
			/* UNREACHABLE */
			abort();
		}
	}

leave:
	signal(SIGALRM, old_sigalrm_handler);
	signal(SIGCHLD, old_sigchld_handler);
	signal(SIGTERM, old_sigterm_handler);
	sigprocmask(SIG_SETMASK, &origset, NULL);

	while (argv[fr] != NULL)
		free(argv[fr++]);

	return retval;
}

static int
bcd_backtrace_thread(struct bcd_session *session)
{
	union {
		char *argv[BCD_ARGC_LIMIT];
		const char *cargv[BCD_ARGC_LIMIT];
	} u;
	bcd_error_t error;
	char *tp = NULL;;
	pid_t tid = session->tid;
	ssize_t r;
	size_t delta = 0;

	u.cargv[delta++] = bcd_config.invoke.path;

	r = bcd_arg_get(&(u.argv[delta]), sizeof(u.argv) / sizeof(*u.argv) - 2,
	    &error);
	if (r == -1) {
		free(tp);
		return bcd_error(BCD_EVENT_TRACE, session,
		    error.message);
	}
	delta += r;

	u.cargv[delta++] = bcd_target_process;

	if (bcd_config.invoke.tp != NULL) {
		if (asprintf(&tp, "%s%ju", bcd_config.invoke.tp,
		    (uintmax_t)tid) == -1) {
			return bcd_error(BCD_EVENT_TRACE, session,
			    "failed to construct tracer string");
		}

		u.argv[delta++] = tp;
	}

	r = bcd_kv_get(&(u.argv[delta]),
	    sizeof(u.argv) / sizeof(*u.argv) - (delta + 1),
	    bcd_config.invoke.separator,
	    bcd_config.invoke.ks,
	    bcd_config.invoke.kp, &error);
	if (r == -1) {
		free(tp);
		return bcd_error(BCD_EVENT_TRACE, session,
		    error.message);
	}

	u.argv[r + delta] = NULL;
	return bcd_execve(session, u.argv, delta - (tp != NULL));
}

static int
bcd_backtrace_process(struct bcd_session *session)
{
	union {
		char *argv[BCD_ARGC_LIMIT];
		const char *cargv[BCD_ARGC_LIMIT];
	} u;
	bcd_error_t error;
	size_t delta = 0;
	ssize_t r;

	u.cargv[delta++] = strdup(bcd_config.invoke.path);

	r = bcd_arg_get(&(u.argv[delta]), sizeof(u.argv) / sizeof(*u.argv) - 2,
	    &error);
	if (r == -1) {
		return bcd_error(BCD_EVENT_TRACE, session,
		    error.message);
	}
	delta += r;

	u.cargv[delta++] = bcd_target_process;

	r = bcd_kv_get(&(u.argv[delta]),
	    sizeof(u.argv) / sizeof(*u.argv) - (delta + 1),
	    bcd_config.invoke.separator,
	    bcd_config.invoke.ks,
	    bcd_config.invoke.kp, &error);
	if (r == -1)
		return bcd_error(BCD_EVENT_TRACE, session, error.message);

	u.argv[r + delta] = NULL;
	return bcd_execve(session, u.argv, delta);
}

static int
bcd_perform_request(struct bcd_session *session)
{
	struct bcd_packet *packet = BCD_PACKET(&session->packet);

	switch (packet->op) {
	case BCD_OP_TID:
		memcpy(&session->tid, packet->payload, sizeof session->tid);
		break;
	case BCD_OP_KV:
		return bcd_kv_set(session, packet);
	case BCD_OP_ARG:
		return bcd_arg_set(session, packet);
	case BCD_OP_TR_THREAD:
		return bcd_backtrace_thread(session);
	case BCD_OP_TR_PROCESS:
		return bcd_backtrace_process(session);
	case BCD_OP_TR_FATAL:
		bcd_backtrace_process(session);
		bcd_child_exit(EXIT_SUCCESS);
		break;
	case BCD_OP_DETACH:
		session->terminated = 1;
		break;
	default:
		break;
	}

	return 0;
}

static void
bcd_handler_request_response(bcd_io_event_t *client)
{
	bcd_error_t error;
	struct bcd_session *session = bcd_io_event_payload(client);

	int ret;

	switch (session->state) {
	case BCD_SESSION_READING:
		ret = bcd_read_request(client->fd, session);
		if (ret == -1) {
			if (errno == EAGAIN) {
				bcd_io_event_unset(client, BCD_IO_EVENT_READ);
				bcd_io_event_remove_from_ready_list(client);
				return;
			}
		}
		if (session->terminated)
			break;
		bcd_perform_request(session);
		/* FALLTHROUGH */
	case BCD_SESSION_WRITING:
		ret = bcd_write_ack(client->fd, session);
		if (ret == -1) {
			if (errno == EAGAIN) {
				bcd_io_event_unset(client, BCD_IO_EVENT_WRITE);
				bcd_io_event_remove_from_ready_list(client);
				return;
			}
		}
		break;
	default:
		/* UNREACHABLE */
		assert(session->state == BCD_SESSION_READING ||
		    session->state == BCD_SESSION_WRITING);
		abort();
	}

	if (session->terminated) {
		bcd_io_fd_close(client->fd);
		bcd_io_event_remove_from_ready_list(client);
		bcd_io_event_remove(client, &error);
		bcd_io_event_destroy(client);
	}

	return;
}

static int
bcd_read_request(int fd, struct bcd_session *session)
{
	struct bcd_packet *packet = BCD_PACKET(&session->packet);
	size_t ac = session->offset;
	size_t target = 0;

	if (ac > sizeof *packet)
		target = packet->length;

	do {
		ssize_t r = read(fd, (char *)packet + ac,
		    sizeof(*packet) + target - ac);

		if (r == -1) {
			if (errno == EINTR)
				continue;

			if (errno == EAGAIN) {
				session->offset = ac;
				return -1;
			}

			goto fail;
		}

		if (r == 0) {
			if (session->terminated) {
				/*
				 * It is expected that we may read until EOF
				 * after termination.
				 */
				return 0;
			}
			goto fail;
		}

		ac += (size_t)r;
		if (ac >= sizeof *packet) {
			target = packet->length;
			if (target > BCD_PACKET_LIMIT) {
				bcd_error(BCD_EVENT_FATAL, session,
				    "message size is too large");
				bcd_child_exit(EXIT_FAILURE);
			}
		}
	} while (ac < sizeof *packet + target);

	session->offset = 0;
	return 0;

fail:
	bcd_error(BCD_EVENT_FATAL, session, "unexpected termination of stream");
	bcd_child_exit(EXIT_FAILURE);
	return -1; /* Unreachable */
}

static ssize_t
bcd_sb_write(bcd_pipe_t *pd, enum bcd_op op, struct bcd_packet *packet,
    size_t length, time_t timeout_abstime)
{

	packet->op = op;
	packet->length = length;

	return bcd_io_fd_write(pd->fd[1], packet,
	    sizeof(*packet) + length, timeout_abstime);
}

static int
bcd_sb_read(bcd_pipe_t *pd, struct bcd_packet *packet, size_t length,
    time_t timeout_abstime, bcd_error_t *error)
{
	ssize_t r;
	int header_complete = 0;

	/* Read packet header. */
	r = bcd_io_fd_read(pd->fd[0], (char *)packet, sizeof(*packet),
	    timeout_abstime);
	if ((size_t) r != sizeof(*packet))
		goto fail;
	if (packet->length > length)
		goto fail;
	header_complete = 1;

	/* Read packet payload. */
	r += bcd_io_fd_read(pd->fd[0], (char *)&packet[1], packet->length,
	    timeout_abstime);
fail:
	if (r < 0) {
		if (errno == EAGAIN) {
			bcd_error_set(error, errno, "timed out");
		} else {
			bcd_error_set(error, errno, "failed to read response");
		}
		return -1;
	} else if (r == 0) {
		bcd_error_set(error, 0, "premature termination");
		return -1;
	} else if ((size_t)r < sizeof(*packet) +
	    (header_complete ? packet->length : 0)) {
		bcd_error_set(error, 0, "truncated response");
		return -1;
	}

	assert((size_t)r == sizeof(*packet) +
	    (header_complete ? packet->length : 0));
	return 0;
}

int
bcd_kv(struct bcd *bcd, const char *key, const char *value, bcd_error_t *e)
{
	BCD_PACKET_INSTANCE(BCD_PACKET_LIMIT) st;
	struct bcd_packet *packet = BCD_PACKET(&st);
	char *payload = packet->payload;
	int fd = bcd->fd;
	size_t k_l = strlen(key) + 1;
	size_t v_l = strlen(value) + 1;
	ssize_t r;
	time_t timeout_abstime = bcd_os_time() + bcd_config.timeout;

	if (k_l + v_l > BCD_PACKET_LIMIT) {
		bcd_error_set(e, 0, "key-value pair is too long");
		return -1;
	}

	packet->op = BCD_OP_KV;
	memcpy(payload, key, k_l);
	memcpy(payload + k_l, value, v_l);
	packet->length = k_l + v_l;

	r = bcd_packet_write(fd, packet, packet->length, timeout_abstime);
	if (r == -1) {
		bcd_error_set(e, errno, "failed to write kv-pair");
		bcd_io_fd_close(fd);
		return -1;
	}

	return bcd_channel_read_ack(fd, timeout_abstime, e);
}

int
bcd_arg(struct bcd *bcd, const char *arg, bcd_error_t *e)
{
	BCD_PACKET_INSTANCE(BCD_PACKET_LIMIT) st;
	struct bcd_packet *packet = BCD_PACKET(&st);
	char *payload = packet->payload;
	int fd = bcd->fd;
	size_t arglen = strlen(arg) + 1;
	ssize_t r;
	time_t timeout_abstime = bcd_os_time() + bcd_config.timeout;

	if (arglen > BCD_PACKET_LIMIT) {
		bcd_error_set(e, 0, "argument is too long");
		return -1;
	}

	packet->op = BCD_OP_ARG;
	memcpy(payload, arg, arglen);
	packet->length = arglen;

	r = bcd_packet_write(fd, packet, packet->length, timeout_abstime);
	if (r == -1) {
		bcd_error_set(e, errno, "failed to write argument");
		bcd_io_fd_close(fd);
		return -1;
	}

	return bcd_channel_read_ack(fd, timeout_abstime, e);
}

static void
bcd_handler_fatal(bcd_io_event_t *client)
{
	ssize_t r;
	char c;

	/*
	 * Handle the case where we start off in ready list. It is expected
	 * that the read should fail with EAGAIN.
	 */
	r = read(client->fd, &c, sizeof(c));
	if (r == -1 && errno == EAGAIN) {
		bcd_io_event_remove_from_ready_list(client);
		return;
	}

	bcd_backtrace_process(NULL);
	bcd_child_exit(EXIT_SUCCESS);
}

/*
 * Kill child in the event of any close operation.
 */
static void
bcd_handler_sb(bcd_io_event_t *client)
{
	/*
	 * Handle the case where we start off in ready list. It is expected
	 * that we will not be in an error condition unless the client
	 * thread has disconnected.
	 */
	if (!bcd_io_event_has_error(client)) {
		bcd_io_event_remove_from_ready_list(client);
		return;
	}

	bcd_child_exit(EXIT_FAILURE);
}

static int
bcd_uid_name(uid_t *uid, const char *name, bcd_error_t *error)
{
	struct passwd pw, *pwd;
	long n_buffer;
	char *buffer;
	int r;

	n_buffer = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (n_buffer == -1)
		n_buffer = 16384;

	buffer = malloc(n_buffer);
	if (buffer == NULL) {
		bcd_error_set(error, errno, "failed to allocate "
		    "internal buffer");
		return -1;
	}

	r = getpwnam_r(name,
	    &pw, buffer, n_buffer, &pwd);

	if (pwd == NULL) {
		int errnum = 0;

		if (r != 0)
			errnum = errno;

		bcd_error_set(error, errnum,
		    "failed to find user for chown");
		free(buffer);
		return -1;
	}

	*uid = pwd->pw_uid;
	free(buffer);

	return 0;
}

static int
bcd_gid_name(gid_t *gid, const char *name, bcd_error_t *error)
{
	struct group gr, *grp;
	long n_buffer;
	char *buffer;
	int r;

	n_buffer = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (n_buffer == -1)
		n_buffer = 16384;

	buffer = malloc(n_buffer);
	if (buffer == NULL) {
		bcd_error_set(error, errno, "failed to allocate "
		    "internal buffer");
		return -1;
	}

	r = getgrnam_r(name, &gr,
	    buffer, n_buffer, &grp);
	if (grp == NULL) {
		int errnum = 0;

		if (r != 0)
			errnum = errno;

		bcd_error_set(error, errnum,
		    "failed to find group");
		free(buffer);
		return -1;
	}

	*gid = grp->gr_gid;
	free(buffer);

	return 0;
}

static int
bcd_chown(const char *path, bcd_error_t *error)
{
	const char *gr;
	uid_t uid = 0;
	gid_t gid = 0;

	if (bcd_config.chown.user == NULL)
		return 0;

	if (bcd_uid_name(&uid, bcd_config.chown.user, error) == -1)
		return -1;

	gr = bcd_config.chown.group;
	if (gr == NULL) {
		gid = -1;
	} else if (bcd_gid_name(&gid, gr, error) == -1) {
		return -1;
	}

	if (chown(path, uid, gid) == -1) {
		bcd_error_set(error, errno, "failed to set permissions");
		return -1;
	}

	return 0;
}

static int
bcd_suid(bcd_error_t *error)
{
	uid_t uid = 0;
	gid_t gid = 0;

	if (bcd_config.chown.group != NULL) {
		if (bcd_gid_name(&gid, bcd_config.chown.group, error) == -1)
			return -1;

		if (getegid() != gid && setgid(gid) == -1) {
			bcd_error_set(error, errno,
			    "failed to drop group privileges");
			return -1;
		}
	}

	if (bcd_config.chown.user == NULL)
		return 0;

	if (bcd_uid_name(&uid, bcd_config.suid.user, error) == -1)
		return -1;

	if (geteuid() != uid && setuid(uid) == -1) {
		bcd_error_set(error, errno, "failed to drop user privileges");
		return -1;
	}

	return 0;
}

static void
bcd_child(void)
{
	BCD_PACKET_INSTANCE(BCD_SB_PATH) packet;
	sigset_t emptyset;
	bcd_error_t error;
	bcd_io_listener_t *listener;
	bcd_io_event_t *event;
	ssize_t r;

	bcd_set_cpu_affinity(bcd_config.affinity.target_cpu);

	if (pcb.sb.output_fd != -1) {
		int ret;

		do {
			ret = dup2(pcb.sb.output_fd, STDOUT_FILENO);
		} while (ret == -1 && errno == EINTR);

		if (ret == -1) {
			_exit(EXIT_FAILURE);
		}

		do {
			ret = dup2(pcb.sb.output_fd, STDERR_FILENO);
		} while (ret == -1 && errno == EINTR);

		if (ret == -1) {
			_exit(EXIT_FAILURE);
		}

		bcd_io_fd_close(pcb.sb.output_fd);
	}

	sigemptyset(&emptyset);
	sigprocmask(SIG_SETMASK, &emptyset, NULL);

	if (bcd_config.oom_adjust)
		bcd_os_oom_adjust(&error);

	umask(bcd_config.umask);

	if ((bcd_config.flags & BCD_CONFIG_F_SETCOMM) &&
	    bcd_setcomm("[bcd] monitor") == -1) {
		bcd_error(BCD_EVENT_FATAL, NULL,
		    "failed to respect BCD_CONFIG_F_SETCOMM");
		_exit(EXIT_FAILURE);
	}

	if (asprintf(&bcd_target_process, "%ju",
	    (uintmax_t)pcb.sb.master_pid) == -1)
		goto fail;

	bcd_io_init(&error);

	bcd_pipe_ensure_readonly(&pcb.sb.master);
	bcd_pipe_ensure_writeonly(&pcb.sb.slave);

	listener = bcd_io_listener_unix(
	    bcd_config.ipc.us.path, 128, &error);
	if (listener == NULL)
		goto fail;

	if (bcd_chown(bcd_config.ipc.us.path, &error) == -1)
		goto fail;

	if (bcd_suid(&error) == -1)
		goto fail;

	if (bcd_io_listener_handler(listener, bcd_handler_accept,
	    bcd_handler_request_response,
	    sizeof(struct bcd_session), &error) == -1)
		goto fail;
	strncpy(BCD_PACKET_PAYLOAD(&packet), bcd_config.ipc.us.path,
	    BCD_SB_PATH);

	r = bcd_sb_write(&pcb.sb.slave, BCD_OP_CF,
	    BCD_PACKET(&packet), strlen(bcd_config.ipc.us.path) + 1,
	    0 /* wait forever */);
	if (r == -1) {
		bcd_error(BCD_EVENT_FATAL, NULL,
		    "failed to write configuration information");
		bcd_child_exit(EXIT_FAILURE);
	}

	event = bcd_io_event_create(pcb.sb.slave.fd[1], bcd_handler_sb, 0,
	    &error);
	if (event == NULL) {
		bcd_error(BCD_EVENT_FATAL, NULL,
		    "failed to configure pipe watcher");
		bcd_child_exit(EXIT_FAILURE);
	}

	if (bcd_io_event_add(event, BCD_IO_EVENT_CLOSE,
	    &error) == -1) {
		bcd_io_event_destroy(event);
		bcd_error(BCD_EVENT_FATAL, NULL,
		    "failed to monitor pipe");
		bcd_child_exit(EXIT_FAILURE);
	}

	event = bcd_io_event_create(pcb.sb.master.fd[0], bcd_handler_fatal, 0,
	    &error);
	if (event == NULL) {
		bcd_error(BCD_EVENT_FATAL, NULL,
		    "failed to configure master pipe");
		bcd_child_exit(EXIT_FAILURE);
	}

	if (bcd_io_event_add(event, BCD_IO_EVENT_READ | BCD_IO_EVENT_CLOSE,
	    &error) == -1) {
		bcd_error(BCD_EVENT_FATAL, NULL,
		    "failed to watch master pipe");
		bcd_io_event_destroy(event);
		bcd_child_exit(EXIT_FAILURE);
	}

	if (bcd_io_enter(&error) == -1) {
		bcd_error(BCD_EVENT_FATAL, NULL,
		    error.message);
		bcd_child_exit(EXIT_FAILURE);
	}

	bcd_child_exit(EXIT_SUCCESS);

fail:
	bcd_error(BCD_EVENT_FATAL, NULL, "failed to create UNIX socket");
	_exit(EXIT_FAILURE);
}

static pid_t
bcd_os_fork(void)
{
	pid_t pid;
	sigset_t allmask, origmask;

	sigfillset(&allmask);
	sigprocmask(SIG_SETMASK, &allmask, &origmask);

	fflush(stdout);
	fflush(stderr);

	pid = fork();
	if (pid == 0) {
		bcd_child();
		_exit(EXIT_SUCCESS);
	}

	sigprocmask(SIG_SETMASK, &origmask, NULL);

	return pid;
}

int
bcd_associate_tid(const struct bcd *bcd, bcd_error_t *error, pid_t tid)
{
	pid_t *newtid;
	BCD_PACKET_INSTANCE(sizeof(*newtid)) packet;
	ssize_t r;
	time_t timeout_abstime = bcd_os_time() + bcd_config.timeout;

	if (bcd->fd == -1) {
		bcd_error_set(error, errno,
		    "invalid fd; did you call bcd_attach?");
		return -1;
	}

	newtid = BCD_PACKET_PAYLOAD(&packet);
	*newtid = tid;

	BCD_PACKET(&packet)->op = BCD_OP_TID;

	r = bcd_packet_write(bcd->fd, BCD_PACKET(&packet), BCD_PACKET_SIZE(&packet),
	    timeout_abstime);
	if (r == -1) {
		bcd_error_set(error, errno, "failed to set new tid");
		return -1;
	}

	if (bcd_channel_read_ack(bcd->fd, timeout_abstime, error) != 0)
		return -1;

	return 0;
}

int
bcd_attach(struct bcd *bcd, bcd_error_t *error)
{
	struct sockaddr_un un;
	const socklen_t addrlen = sizeof(un);
	pid_t *tid;
	BCD_PACKET_INSTANCE(sizeof(*tid)) packet;
	ssize_t r;
	time_t timeout_abstime = bcd_os_time() + bcd_config.timeout;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		bcd_error_set(error, errno,
		    "failed to create connection to slave");
		goto fail;
	}

	memset(&un, 0, sizeof un);
	strncpy(un.sun_path, pcb.sb.path, sizeof un.sun_path);
	un.sun_family = AF_UNIX;

	for (;;) {
		int cr = connect(fd, (struct sockaddr *)&un, addrlen);
		if (cr == -1) {
			if (errno == EAGAIN)
				continue;

			bcd_error_set(error, errno,
			    "failed to connect to slave");
			goto fail;
		}

		break;
	}

	if (bcd_io_fd_prepare(fd) == -1) {
		bcd_error_set(error, errno, "failed to create socket");
		bcd_io_fd_close(fd);
		return -1;
	}

	tid = BCD_PACKET_PAYLOAD(&packet);
	*tid = gettid();

	BCD_PACKET(&packet)->op = BCD_OP_TID;

	r = bcd_packet_write(fd, BCD_PACKET(&packet), BCD_PACKET_SIZE(&packet),
	    timeout_abstime);
	if (r == -1) {
		bcd_error_set(error, errno, "failed to initialize session");
		goto fail;
	}

	if (bcd_channel_read_ack(fd, timeout_abstime, error) != 0)
		goto fail; /* error will already be set */

	bcd->fd = fd;
	return 0;

fail:
	if (fd != -1) {
		bcd_io_fd_close(fd);
	}
	bcd->fd = -1;
	return -1;
}

int
bcd_detach(struct bcd *bcd, bcd_error_t *error)
{
	BCD_PACKET_INSTANCE(0) packet;
	ssize_t r;
	time_t timeout_abstime = bcd_os_time() + bcd_config.timeout;
	int ret, retval = 0;

	/* Succeed if we weren't attached. */
	if (bcd->fd == -1)
		return retval;

	/* Send exit operation to child. */
	BCD_PACKET(&packet)->op = BCD_OP_DETACH;

	r = bcd_packet_write(bcd->fd, BCD_PACKET(&packet), 0, timeout_abstime);
	if (r == -1) {
		bcd_error_set(error, errno,
		    "failed to cause slave to detach");
		retval = -1;
		goto fail;
	}

	/* Wait for ack from child. */
	ret = bcd_channel_read_ack(bcd->fd, timeout_abstime, error);
	if (ret != 0) {
		/* error will already be set */
		retval = -1;
	}

fail:
	if (bcd->fd != -1)
		bcd_io_fd_close(bcd->fd);

	return retval;
}

int
bcd_init(const struct bcd_config *cf, bcd_error_t *error)
{
	BCD_PACKET_INSTANCE(BCD_SB_PATH) packet;
	struct bcd_sb *sb = &pcb.sb;
	pid_t child;
	ssize_t r;
	int ret;
	time_t timeout_abstime;

	if (cf == NULL) {
		bcd_config_latest_version_t default_config;
		bcd_error_t noerror;

		ret = bcd_config_init_internal(
		    (struct bcd_config *)&default_config,
		    BCD_CONFIG_VERSION,
		    &noerror);
		assert(ret == 0);
		ret = bcd_config_assign(&default_config, &noerror);
		assert(ret == 0);
	} else {
		ret = bcd_config_assign(cf, error);
		if (ret != 0)
			return -1;
	}

	if (bcd_config.ipc.us.path == NULL) {
		char *buffer;
		int as = asprintf(&buffer, "/tmp/bcd.%ju",
		    (uintmax_t)getpid());

		if (as == -1) {
			bcd_error_set(error, 0,
			    "failed to generate UNIX socket PATH");
			return -1;
		}

		bcd_config.ipc.us.path = buffer;
	}

	sb->output_fd = -1;
	if (bcd_config.invoke.output_file != NULL &&
	    bcd_config.invoke.output_file[0] != '\0') {
		do {
			ret = open(bcd_config.invoke.output_file,
			    O_CREAT | O_WRONLY | O_TRUNC,
			    S_IRUSR | S_IWUSR);
		} while (ret == -1 && errno == EINTR);
		if (ret == -1) {
			bcd_error_set(error, errno,
			    "failed to create output file");
			return -1;
		}
		sb->output_fd = ret;
	}

	sb->master_pid = getpid();

	if (bcd_pipe_init(&sb->slave, error) == -1) {
		error->message = "failed to initialize slave pipe";
		return -1;
	}

	if (bcd_pipe_init(&sb->master, error) == -1) {
		error->message = "failed to initialize master pipe";
		bcd_pipe_deinit(&sb->slave);
		return -1;
	}

	child = bcd_os_fork();
	if (child == -1)
		goto fail;

	sb->slave_pid = child;
	bcd_pipe_ensure_readonly(&sb->slave);
	bcd_pipe_ensure_writeonly(&sb->master);

	/*
	 * After the child has spawned, wait for configuration information.
	 */
	timeout_abstime = bcd_os_time() + bcd_config.timeout;
	r = bcd_sb_read(&sb->slave, BCD_PACKET(&packet), BCD_SB_PATH,
	    timeout_abstime, error);
	if (r == -1)
		goto fail;

	switch (BCD_PACKET(&packet)->op) {
	case BCD_OP_CF:
		strncpy(sb->path, BCD_PACKET_PAYLOAD(&packet), BCD_SB_PATH);
		break;
	default:
		bcd_error_set(error, 0, "failed to initialize path");
		goto fail;
	}

	/*
	 * If all hell breaks loose, we assume we can rely on the
	 * control block section. Unfortunately, the clever person
	 * can still override protections.
	 */
#ifndef BCD_MPROTECT_OFF
	if (mprotect(sb, sizeof *sb, PROT_READ) == -1) {
		error->message = "failed to lock control page permissions";
		error->errnum = errno;
		goto fail;
	}
#endif /* !BCD_MPROTECT_OFF */

	return 0;

fail:
	bcd_pipe_deinit(&sb->slave);
	bcd_pipe_deinit(&sb->master);
	return -1;
}
#include <assert.h>
#include <string.h>

#ifndef BCD_AMALGAMATED
#include "internal.h"
#endif /* !BCD_AMALGAMATED */

struct bcd_config_internal bcd_config;

static void
bcd_config_init_v1(struct bcd_config_v1 *cf)
{

	cf->version = 1;
	cf->oom_adjust = 1;
	cf->handler = bcd_error_handler_default;
	cf->timeout = 30;
	cf->umask = 0177;
	cf->affinity.target_cpu = -1;
	memset(&cf->chown, 0, sizeof cf->chown);
	memset(&cf->suid, 0, sizeof cf->chown);

	cf->invoke.path = "/opt/backtrace/bin/ptrace";
	cf->invoke.kp = "--kv=";
	cf->invoke.separator = ',';
	cf->invoke.ks = ':';
	cf->invoke.tp = "--thread=";
	cf->invoke.output_file = NULL;

	cf->ipc_mechanism = BCD_IPC_UNIX_SOCKET;
	memset(&cf->ipc, 0, sizeof cf->ipc);
}

static int
bcd_config_assign_from_v1(const void *cfv, struct bcd_error *e)
{
	const struct bcd_config_v1 *cf = (const struct bcd_config_v1 *)cfv;

	assert(cf->version == 1);
	(void)e;

	bcd_config.version = cf->version;
	bcd_config.flags = cf->flags;
	bcd_config.oom_adjust = cf->oom_adjust;
	bcd_config.handler = cf->handler;
	bcd_config.timeout = cf->timeout;
	bcd_config.umask = cf->umask;
	bcd_config.chown.user = cf->chown.user;
	bcd_config.chown.group = cf->chown.group;
	bcd_config.suid.user = cf->suid.user;
	bcd_config.suid.group = cf->suid.group;
	bcd_config.invoke.path = cf->invoke.path;
	bcd_config.invoke.kp = cf->invoke.kp;
	bcd_config.invoke.separator = cf->invoke.separator;
	bcd_config.invoke.ks = cf->invoke.ks;
	bcd_config.invoke.tp = cf->invoke.tp;
	bcd_config.invoke.output_file = cf->invoke.output_file;
	bcd_config.ipc_mechanism = cf->ipc_mechanism;
	bcd_config.ipc.us.path = cf->ipc.us.path;
	bcd_config.affinity.target_cpu = cf->affinity.target_cpu;

	return 0;
}

int
bcd_config_init_internal(struct bcd_config *cf, unsigned int caller_version,
    bcd_error_t *e)
{

	switch (caller_version) {
	case 1:
		bcd_config_init_v1((struct bcd_config_v1 *)cf);
		return 0;
	default:
		bcd_error_set(e, 0, "unrecognized config version");
	}

	return -1;
}

int
bcd_config_assign(const void *cf, struct bcd_error *e)
{
	/* All versions of bcd_config must start with unsigned int version. */
	const struct bcd_config *bcd_cf = cf;

	switch (bcd_cf->version) {
	case 1:
		return bcd_config_assign_from_v1(cf, e);
	default:
		bcd_error_set(e, 0, "unrecognized config version");
	}

	return -1;
}

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#ifndef BCD_AMALGAMATED
#include "internal.h"
#endif /* !BCD_AMALGAMATED */

#ifndef BCD_IO_NEVENT
#define BCD_IO_NEVENT 128
#endif /* BCD_IO_NEVENT */

static TAILQ_HEAD(, bcd_io_event) readyevents =
    TAILQ_HEAD_INITIALIZER(readyevents);

struct bcd_io_listener {
	char *path;
	int fd;
};

struct bcd_io_listener_state {
	bcd_io_listener_handler_t *accept;
	bcd_io_event_handler_t *handler;
	size_t payload;
};

/*
 * Waits until an absolute timeout (timeout_abstime) for an fd to become ready.
 * Behavior for timeout_abstime values is as follows:
 *  timeout_abstime > 0 - Wait until the bcd_os_time() meets or exceeds the
 *     specified value.
 *  timeout_abstime == 0 - Wait forever.
 *  timeout_abstime < 0 - Return immediately.
 * The underlying implementation computes the relative value needed by select()
 * as close as possible to the select() call as well as bounding it to no more
 * than bcd_config.timeout to minimize risk of extended delays due to the clock
 * shifting underneath us.  However, any relative timeout syscall will always be
 * subject to such risks.
 */
int
bcd_io_fd_wait(int fd, enum bcd_io_fd_wait wt, time_t timeout_abstime)
{
	struct timeval tv;
	fd_set wfd, errfd;
	int r = 0;

	FD_ZERO(&wfd);
	FD_SET(fd, &wfd);
	FD_ZERO(&errfd);
	FD_SET(fd, &errfd);

	for (;;) {
		time_t now = bcd_os_time();

		if (now >= timeout_abstime)
			tv.tv_sec = 0;
		else if (timeout_abstime - now > bcd_config.timeout)
			tv.tv_sec = bcd_config.timeout;
		else
			tv.tv_sec = timeout_abstime - now;

		tv.tv_usec = 0;

		r = select(FD_SETSIZE, wt == BCD_IO_FD_WAIT_RD ? &wfd : NULL,
		    wt == BCD_IO_FD_WAIT_WR ? &wfd : NULL,
		    &errfd, timeout_abstime == 0 ? NULL : &tv);
		if (r == -1) {
			if (errno == EINTR)
				continue;

			return -1;
		}

		break;
	}

	return r;
}

ssize_t
bcd_io_fd_read(int fd, void *b, size_t n_read, time_t timeout_abstime)
{
	ssize_t ac = 0;
	char *buffer = b;

	for (;;) {
		ssize_t r = read(fd, buffer + ac, n_read - ac);
		if (r == 0)
			return 0;

		if (r == -1) {
			if (errno == EINTR)
				continue;

			if (errno == EAGAIN) {
				int ret = bcd_io_fd_wait(fd, BCD_IO_FD_WAIT_RD,
				    timeout_abstime);

				if (ret == 1)
					continue;

				errno = EAGAIN;
			}

			return -1;
		}

		ac += r;
		if ((size_t)ac == n_read)
			break;
	}

	return ac;
}

ssize_t
bcd_io_fd_write(int fd, const void *b, size_t n_write, time_t timeout_abstime)
{
	ssize_t ac = 0;
	const char *buffer = b;

	for (;;) {
		ssize_t r = write(fd, buffer + ac, n_write - ac);
		if (r == 0)
			return 0;

		if (r == -1) {
			if (errno == EINTR)
				continue;

			if (errno == EAGAIN) {
				int ret = bcd_io_fd_wait(fd, BCD_IO_FD_WAIT_WR,
				    timeout_abstime);

				if (ret == 1)
					continue;

				errno = EAGAIN;
			}

			return -1;
		}

		ac += r;
		if ((size_t)ac == n_write)
			break;
	}

	return ac;
}

int
bcd_io_fd_prepare(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL, NULL);
	if (flags == -1)
		return -1;

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		return -1;

	return 0;
}

void
bcd_io_fd_close(int fd)
{

	while (close(fd) == -1 && errno == EINTR);
	return;
}

void
bcd_io_event_destroy(bcd_io_event_t *event)
{

	if (event == NULL)
		return;

	free(event);
	return;
}

struct bcd_io_event *
bcd_io_event_create(int fd, bcd_io_event_handler_t *handler, size_t payload,
    bcd_error_t *error)
{
	struct bcd_io_event *event;

	event = malloc(sizeof(*event) + payload);
	if (event == NULL) {
		bcd_error_set(error, 0, "failed to allocate event");
		return NULL;
	}

	event->mask = 0;
	event->handler = handler;
	event->fd = fd;
	event->flags = 0;

	return event;
}

void
bcd_io_event_add_to_ready_list(struct bcd_io_event *event)
{

	if (!(event->flags & BCD_IO_EVENT_IN_READY_LIST)) {
		TAILQ_INSERT_TAIL(&readyevents, event, readylink);
		event->flags |= BCD_IO_EVENT_IN_READY_LIST;
	}

	return;
}

void
bcd_io_event_remove_from_ready_list(struct bcd_io_event *event)
{

	if (event->flags & BCD_IO_EVENT_IN_READY_LIST) {
		TAILQ_REMOVE(&readyevents, event, readylink);
		event->flags &= ~BCD_IO_EVENT_IN_READY_LIST;
	}

	return;
}

int
bcd_io_event_ready_list_is_empty(void)
{

	return TAILQ_EMPTY(&readyevents);
}

void
bcd_io_event_dispatch_ready_list(void)
{
	struct bcd_io_event *curr_event, *next_event;

	/*
	 * Iteration is performed safely as the readyevents list may be modified
	 * (removed from) within handlers.
	 */
	curr_event = TAILQ_FIRST(&readyevents);
	while (curr_event != NULL) {
		next_event = TAILQ_NEXT(curr_event, readylink);
		curr_event->handler(curr_event);
		curr_event = next_event;
	}

	return;
}

static int
bcd_io_accept(int fd, struct sockaddr *address, socklen_t *addrlen,
    bcd_error_t *error)
{
	int client = accept(fd, address, addrlen);

	if (client == -1)
		return -1;

	if (bcd_io_fd_prepare(client) == -1) {
		bcd_error_set(error, errno, "failed to prepare client socket");
		return -1;
	}

	return client;
}

static int
bcd_io_socket(int domain, int type, int protocol, bcd_error_t *error)
{
	int fd;

	fd = socket(domain, type, protocol);
	if (bcd_io_fd_prepare(fd) == -1) {
		bcd_error_set(error, errno, "failed to create socket");
		bcd_io_fd_close(fd);
		return -1;
	}

	return fd;
}

static void
bcd_io_listener_accept(bcd_io_event_t *event)
{
	struct bcd_io_listener_state *handler;
	struct sockaddr_un un;
	bcd_error_t error;

	handler = bcd_io_event_payload(event);

	for (;;) {
		bcd_io_event_t *client_event;
		socklen_t addrlen = sizeof(un);
		int client_fd;

		client_fd = bcd_io_accept(event->fd, (struct sockaddr *)&un,
		    &addrlen, &error);
		if (client_fd == -1) {
			if (errno == EAGAIN) {
				bcd_io_event_remove_from_ready_list(event);
				break;
			}

			break;
		}

		client_event = bcd_io_event_create(client_fd, handler->handler,
		    handler->payload, &error);

		if (client_event == NULL) {
			bcd_io_fd_close(client_fd);
			continue;
		}

		handler->accept(client_event, bcd_io_event_mask(event),
		    bcd_io_event_payload(client_event));
	}

	return;
}

int
bcd_io_listener_handler(struct bcd_io_listener *listener,
    bcd_io_listener_handler_t *ac,
    bcd_io_event_handler_t *handler,
    size_t payload,
    bcd_error_t *error)
{
	struct bcd_io_listener_state *state;
	bcd_io_event_t *event;

	event = bcd_io_event_create(listener->fd, bcd_io_listener_accept,
	    sizeof *state, error);
	if (event == NULL)
		return -1;

	state = bcd_io_event_payload(event);
	state->accept = ac;
	state->handler = handler;
	state->payload = payload;

	if (bcd_io_event_add(event, BCD_IO_EVENT_READ, error) == -1) {
		free(event);
		return -1;
	}

	return 0;
}

int
bcd_io_listener_fd(const struct bcd_io_listener *l)
{

	return l->fd;
}

struct bcd_io_listener *
bcd_io_listener_unix(const char *path, int backlog, bcd_error_t *error)
{
	struct bcd_io_listener *listener = malloc(sizeof *listener);
	struct sockaddr_un un;

	if (listener == NULL)
		return NULL;

	if (*path != '/') {
		bcd_error_set(error, 0, "listener requires full path");
		return NULL;
	}

	if (strlen(path) >= sizeof(un.sun_path)) {
		bcd_error_set(error, 0, "UNIX socket path is too long");
		return NULL;
	}

	listener->path = strdup(path);
	if (listener->path == NULL) {
		bcd_error_set(error, 0, "failed to allocate socket path");
		return NULL;
	}

	listener->fd = bcd_io_socket(AF_UNIX, SOCK_STREAM, 0, error);
	if (listener->fd == -1)
		goto error;

	if (unlink(path) == -1 && errno != ENOENT) {
		bcd_error_set(error, errno, "failed to initialize UNIX socket");
		goto error;
	}

	memset(&un, 0, sizeof un);
	strcpy(un.sun_path, path);
	un.sun_family = AF_UNIX;

	if (bind(listener->fd, (struct sockaddr *)&un, sizeof un) == -1) {
		bcd_error_set(error, errno, "failed to bind to socket");
		bcd_io_fd_close(listener->fd);
		goto error;
	}

	if (listen(listener->fd, backlog) == -1) {
		bcd_io_fd_close(listener->fd);
		goto error;
	}

	return listener;

error:
	free(listener->path);
	free(listener);
	return NULL;
}
#ifdef __linux__
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>

#ifndef BCD_AMALGAMATED
#include "internal.h"
#endif /* !BCD_AMALGAMATED */

#ifndef BCD_IO_NEVENT
#define BCD_IO_NEVENT 128
#endif /* BCD_IO_NEVENT */

static int epoll_fd;

int
bcd_io_event_add(struct bcd_io_event *event, unsigned int mask, bcd_error_t *e)
{
	struct epoll_event ev;

	ev.events = mask;
	ev.data.ptr = event;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event->fd, &ev) == -1) {
		bcd_error_set(e, errno, "failed to watch descriptor");
		return -1;
	}

	bcd_io_event_add_to_ready_list(event);

	return 0;
}

int
bcd_io_event_remove(struct bcd_io_event *event, bcd_error_t *e)
{
	struct epoll_event ev_ignored;

	bcd_io_event_remove_from_ready_list(event);

	if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, event->fd, &ev_ignored) == -1) {
		bcd_error_set(e, errno,
		    "failed to remove descriptor from watching");
		return -1;
	}

	return 0;
}

int
bcd_io_event_has_error(struct bcd_io_event *event)
{

	return !!(event->mask & EPOLLERR);
}

int
bcd_io_init(struct bcd_error *error)
{

	epoll_fd = epoll_create(BCD_IO_NEVENT);
	if (epoll_fd == -1) {
		error->errnum = errno;
		error->message ="Failed to initialize event loop";
		return -1;
	}

	return 0;
}

int
bcd_io_enter(bcd_error_t *error)
{
	struct epoll_event ev[BCD_IO_NEVENT];

	(void)error;

	for (;;) {
		int n_fd, i, timeout;

		timeout = -1;
		if (!bcd_io_event_ready_list_is_empty())
			timeout = 0;

		n_fd = epoll_wait(epoll_fd, ev, BCD_IO_NEVENT, timeout);
		if (n_fd == -1) {
			if (errno == EINTR)
				continue;

			bcd_error_set(error, errno, "internal event loop "
			    "error");
			return -1;
		}

		for (i = 0; i < n_fd; i++) {
			struct bcd_io_event *event = ev[i].data.ptr;

			event->mask |= ev[i].events;
			bcd_io_event_add_to_ready_list(event);
		}

		bcd_io_event_dispatch_ready_list();
	}

	return 0;
}
#endif /* __linux__ */
#ifdef __linux__
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sched.h>

#ifndef BCD_AMALGAMATED
#include "internal.h"
#endif /* !BCD_AMALGAMATED */

int
bcd_setcomm(const char *title)
{

	/* Linux requires comm to be <= 16 bytes, including the terminator. */
	if (title == NULL || *title == '\0' || strlen(title) > 15)
		return -1;

	return prctl(PR_SET_NAME, title);
}

int
bcd_set_cpu_affinity(int core_id)
{
	pid_t pid = getpid();
	cpu_set_t cpuset;

	if (0 > core_id) {
		return -1;
	}

	CPU_ZERO(&cpuset);
	CPU_SET(core_id, &cpuset);

	if (-1 == sched_setaffinity(pid, sizeof(cpuset), &cpuset)) {
        return -1;
	}

	return 0;
}

time_t
bcd_os_time(void)
{
#if defined(_POSIX_TIMERS) && defined(_POSIX_MONOTONIC_CLOCK)
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
		bcd_abort();

	return ts.tv_sec;
#else
#warning Crash reporting may be affected by wallclock reset.
	return time(NULL);
#endif /* !_POSIX_TIMERS || !_POSIX_MONOTONIC_CLOCK */
}

int
bcd_os_oom_adjust(bcd_error_t *error)
{
	char path[PATH_MAX];
	pid_t pid = getpid();
	const char *const score = "-17";
	size_t score_length = strlen(score);
	ssize_t ac = 0;
	int r, fd, i;

	r = snprintf(path, sizeof(path), "/proc/%ju/oom_adj",
	    (uintmax_t)pid);

	for (i = 0;; i++) {
		if (r < 0 || (size_t)r >= sizeof path) {
			bcd_error_set(error, 0, "failed to construct oom path");
			return -1;
		}

		fd = open(path, O_WRONLY);
		if (fd == -1) {
			if (errno != EEXIST || i > 1) {
				bcd_error_set(error, errno,
				    "failed to open oom path");
				return -1;
			}

			r = snprintf(path, sizeof(path),
			    "/proc/%ju/oom_score_adj", (uintmax_t)pid);
			continue;
		}

		break;
	}

	do {
		ssize_t wr = write(fd, score, score_length);

		if (wr == -1) {
			if (errno == EINTR)
				continue;

			bcd_error_set(error, errno, "failed to adjust OOM score");
			goto fail;
		}

		ac += wr;
	} while ((size_t)ac < score_length);

	bcd_io_fd_close(fd);
	return 0;

fail:
	bcd_io_fd_close(fd);
	return -1;
}
#endif /* __linux__ */
