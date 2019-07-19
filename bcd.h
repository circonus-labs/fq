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
