# ChangeLog

### Unreleased

* Upgrade jquery to 3.5.1

### v0.13.7

 * Queue drops are tracked as `dropped_to`.
 * Web UI updated to display queue drops/rate.
 * -b deprecated, -B added, and BCD is disabled by default.

### v0.13.6

 * Track drops to queues as `dropped_in` in status.

### v0.13.5

 * Force disconnect on message read/write error.
 * Reuse listener threads.

### v0.13.4

 * Various code cleanups.
 * Better bounds checking on auth handshake (allow full size).
 * Fix BCD integration.

### v0.13.3

 * Set `SO_REUSEPORT = 1` for listener.
 * Add `-b` to disable BCD/backtrace integration.

### v0.13.2

 * Name threads on Linux to aid debugging.
 * Prevent abort when queue removal fails.

### v0.13.1

 * Add libbcd support for catching faults with backtrace.

### v0.13.0

 * Place fq modules in $(LIBEXECDIR)/fq
 * Automatically load all available modules

### v0.12.1

 * Move the `valnode_t` definition into fq.h.
 * Fix hex construction macro.
 * Support var-args in loadable program functions.
 * Fix multi-argument parsing in routing grammar.

### v0.12.0

 * Omit unneeded library dependencies on Illumos.
 * Make poll() calls resume after signal interruption.

### v0.11.0

 * Use socket keep-alives for client/server connections.
 * Fix use-after-free bug in lua ffi client bindings.
 * Fix test suite.
 * Explicit registration of local function to better navigate
   changing dlsym "self" personalities.
 * ENABLE_DTRACE=1 Linux build flag.

### v0.10.14

 * Fixes to fq-client.lua on OmniOS

### v0.10.13

 * Add `fqs` tool for sending messages from stdin
 * Test suite utilizing `mtevbusted` from
   [libmtev](https://github.com/circonus-labs/libmtev/) (PR #37)

### v0.10.12

 * Fix misuse of stack for freeing messages (0.10.11 fix was bad).
 * Add Linux futex support for lower-latency idle network wake-up.
 * Ensure message ordering on per-client data connections.

### v0.10.11

 * Fix crash when shutting down client that has never seen a message.

### v0.10.10

 * Fix source management issue. 0.10.9 tag exluded commits.
 * Change message free-lists to prevent use-after-free on thread exit.

### v0.10.9

 * Fix builds on newer Mac OS X
 * Change message free-lists to prevent use-after-free on thread exit.
 * Fix bug in server->client heartbeats not beating.

### v0.10.8

 * Fix querystring parsing crash when parameters are not k=v form.
 * Resume on-disk queues at the right checkpoint location.

### v0.10.7

 * Fix bug in route binding prefix matching causing misdirected messages
   (clients could get more than they asked for).
 * Fix bug on some Linux systems regarding exposed symbols.

### v0.10.6

 * Fix crashing issue enqueueing messages due to unsafe use of spsc fifos.
 * Add dynamic loading of routing program extensions.
 * Move the "sample" function to a dynamic extension for example purposes.
