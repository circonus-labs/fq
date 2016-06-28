# fq.

fq is a *brokered* message queue using a publish subscribe model.  It is architected for performance and isn't (today) designed for large numbers of connected clients.


    +------------+
    |- exchange -|
    +------------+
    |- routemap -|
    +------------+
        |      |              +---------+
        |      +--------------|- queue -|
        |                     +---------+
    +---------+                  |
    |- queue -|                  |   +-----------+
    +---------+                  +---|- client1 -|
            |                        +-----------+
            |  +-----------+
            +--|- client2 -|
            |  +-----------+
            |
       +-----------+
       |- client3 -|
       +-----------+

## Terminology

### Broker

The `fqd` process. The daemon through which all knowledge passes.

### Peers

Peers are connected `fqd` processes.  It is important to note that peers are unidirectional.  If A peers with B, then A will act as a client to B. If you want bidirectional peering, you must specify that A peers with B and B peers with A.  The system aims to prevent cyclic delivery of messages efficiently.

Adding peers is done directly via fqd's sqlite DB store:

```
; sqlite3 /var/lib/fq/fqd.sqlite
sqlite> INSERT INTO "upstream"
              (host, port, source, password, exchange, program, permanent_binding)
        VALUES('peerB',8765,'fqd-peera//mem:drop,private,backlog=4096','none','logging','prefix:"http.access.json."','false');
```

### Client

 * [C client - libfq](https://github.com/postwait/fq/blob/master/fq.h#L164-L205)
 * [Java client - fq.jar](https://github.com/postwait/fq/blob/master/java/src/com/omniti/labs/FqClientImplInterface.java)
 * [Node.js client - fq](https://www.npmjs.com/package/fq)
 * submission-only /submit API (see below)

A client is an applications connection to fq over TCP/IP to send or receive messages. A client makes two TCP/IP connections to fq.  An application can present itself to fq as multiple clients at one time (by opening new pairs of connections). See Queues for reasons why.

### Exchanges

Exchanges are like buses on which messages may be sent.  You cannot send a message without doing so on an exchange.  Exchanges are created within fq on-demand.

### Queues

Queues are queues. If you stick something in one end, you should expect it to come out the other.  A single queue may have multiple clients subscribed.  When a client connects, it is attached to one and only one queue.  If an application wishes to attach to more than one queue, it should present as multiple clients.  Queues use a competitive consumption model meaning that if multiple clients are attached to a single queue, the messages sent to that queue will be distributed over the clients such that no two clients will see the same message.

#### Queue Types

Queues can be of type `mem` or `disk`.  The contents of memory queues will not survive restarts.

Various parameters can be set on a queue using the syntax `type:param1,param2`.

#### Sharing

Queues with the `public` parameter can have multiple clients connected to them (in which case they compete for messages).  If you want a private queue you can specify the `private` parameter.

#### Policy

Queues can either have a `block` or `drop` policy.  The drop policy means that messages that would be routed to a queue that is full will be dropped and never delivered.  The block policy will cause the publisher to wait until there is room in the queue.  The block policy makes no sense on a disk queue.

#### Backlog

The `backlog=<number>` parameter will specify how many messages may be held in the queue before the block or drop policies are applied.

#### Permanence

If you want a queue to be remembered by fqd, you can specify `permanent` as a flag.  If you'd like for fqd to forget the queue after all clients have disconnected, you can specify the `transient` flag.  If neither flag is specified, then an existing queue will retain its previous permanence setting or a new transient queue will be created.

#### Examples:

A queue called `bob` will be in memory, allowed to have multiple clients connected to it, with a drop policy and an allowable message backlog of 100000 messages: `bob/mem:public,drop,backlog=100000`

A connection client will specify username/queue.  A user "USER" connecting to the aforementioned queue would connect as `USER/bob/mem:public,drop,backlog=100000`

### Messages

Messages are, of course, a payload and metadata.

#### Message metadata

Some are set by the broker.
 
 * sender [set by the broker]
 * hops (a list of fqd via which the message passed)

Others are set by the sender. 

 * exchange (up to 127 bytes)
 * route (up to 127 bytes)
 * id (128 bits). The first 64 bits the sender shall control, the latter 64bits the broker *might* control.

### Routes and Programs

Routes and programs define how messages sent on exchanges are placed in queues:

- A receiver that connects to an fq-broker specifies a program that filters the messages on the exchange.
- A sender specifies a route for every message as part of the metadata

Programs follow the following syntax (cf. `fqd.h`):

```
PROGRAM: <prefix|exact>:string RULES*
RULE: (RULE)
RULE: (RULE && RULE)
RULE: (RULE || RULE)
RULE: EXPR
EXPR: function(args)
args: arg
args: arg, args
arg: "string"
arg: true|false
arg: [0-9][0-9]*(?:.[0-9]*)

functions are dynamically loadable with type signature
strings: s, booleans: b, integers: d
function: substr_eq(9.3,10,"tailorings",true)
C symbol: fqd_route_prog__substr_eq__ddsb(int nargs, valnode_t *args);
 ```

In particular:

- Every program starts with either `prefix:` or `exact:`
- The program `prefix:` matches all rules
- The program string is matched against the message route

The following rule functions are defined in `fq_prog.c`:

- `fqd_route_prog__sample__d()` -- subsample the stream
- `fqd_route_prog__route_contains__s()` -- check if route contains a string
- `fqd_route_prog__payload_prefix__s()` -- check if payload starts with prefix
- `fqd_route_prog__payload_contains__s()` -- check if payload contains a string
- `fqd_route_prog__true__()` -- always true

Examples:

- `prefix:` -- matches all messages
- `prefix:bla` or `prefix:"bla"` -- matches all messages with rules starting with the sting 'bla'
- `prefix: payload_prefix("M")` -- matches messages where the payload starts with 'M'
- `prefix:foo (payload_prefix("M") && route_contains("bar"))` -- matches messages where the payload starts with 'M' and route starts with "foo" and moreover contains "bar"

## Protocol

Information on command and message protocol is found in `docs/fq_protocol.md`

### HTTP superposition

The Fq protocol also acts as a non-compliant HTTP server (though compliant enough of most clients and browsers).  Fq ships with a web UI that allows inspecting real-time state and performance.

#### GET /stats.json

exposes current exchange, queue, and client information.

#### POST /submit

An endpoint allowing message submission without a full and stateful Fq connection.  It expects the following headers:

 * ```X-Fq-User```,
 * ```X-Fq-Route```, and
 * ```X-Fq-Exchange```.
 
 The HTTP client *MUST* provide a Content-Length header corresponding to the payload content (no chunked submission).  The payload is treated as the raw message box without any special encoding.

Example:

```
curl -X POST -H "X-Fq-User: user" -H 'X-Fq-Route: bla' -H 'X-Fq-Exchange: test' localhost:8765/submit --data "TEST"
```
