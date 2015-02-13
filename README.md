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

The `fqd` process. The deamon through which all knowledge passes.

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

Queues can either have a `block` or `drop` policy.  The drop policy means that messages that would be routed to a queue that is full will be dropped and never delivered.  The block policy will case the publisher to wait until there is room in the queue.  The block policy makes no sense on a disk queue.

#### Backlog

The `backlog=<number>` parameter will specify how many messages may be held in the queue before the block or drop policies are applied.

#### Permanence

If you which a queue to be remembered by fqd, you can specify `permanent` as a flag.  IF you'd like for fqd to forget the queue after all clients have disconnected, you can specify the `transient` flag.  If neither flag is specified, then an existing queue will retain it's previous permanence setting or a new transient queue will be created.

#### Examples:

A queue called `bob` will be in memory, allowed to have multiple clients connected to it, with a drop policy and an allowable message backlog of 100000 messages: `bob/mem:public,drop,backlog=100000`

### Routes

Routes define how messages sent on exchanges are placed in queues.

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


