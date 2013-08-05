# fq Protocol

## Client

Clients maintain two paired tcp connections to fq. After the connections are made, some preliminary data is sent over the command socket. A "plain auth" command is then issued, return a client key. The client key is then used in some preliminary data sent over the data socket, pairing the two sockets for the session.

### Prefixes

* Cmd Mode: `0xcc50cafe`
* Data Mode: `0xcc50face`
* Peer Mode: `0xcc50fade`

### Command Socket

    Length   | Description
    ---------+-----------------------------
    4 bytes  | Cmd Mode

### Data Socket

    Length   | Description
    ---------+-----------------------------
    4 bytes  | Data Mode
    2 bytes  | Client Key Length
    variable | Client Key

## Commands

General form `(command prefix)(command)`, big endian. All non-heartbeat related commands have in-band responses corresponding to the order in which requests they were sent to fq. Heartbeat requests are used simply to tell fq to look for and to send heartbeats at a specific interval. Heartbeats should be checked for during normal command processing and not as a response to a specific request.

### Prefixes

Commad prefixes are two bytes at the beginning of the command

* Error: `0xeeee`
* Heartbeat: `0xbea7`
* Auth CMD: `0xaaaa`
* Auth Plain: `0x0000`
* Auth Response: `0xaa00`
* Heartbeat Request: `0x4848`
* Bind: `0xb171`
* Bind Request: `0xb170`
* Unbind: `0x171b`
* Unbind Request: `0x071b`
* Status: `0x57a7`
* Status Request: `0xc7a7`

#### Plain Auth 

Plain Auth is a subset of Auth and will have both prefixs

##### Request

    Length   | Description
    ---------+-----------------------------
    2 bytes  | Auth CMD Prefix
    2 bytes  | Auth Plain Prefix
    2 bytes  | User Length
    variable | User
    2 bytes  | Queue Length
    variable | Queue
    1 byte   | 0
    variable | Queue type ("mem" or "disk")
    2 bytes  | Password Length (16 bit)
    variable | Password


##### Response

    Length   | Description
    ---------+-----------------------------
    2 bytes  | Auth Response Prefix
    2 bytes  | Client Key Length Length
    variable | Client Key (0 < length < 127 bytes)

#### Bind

##### Request
    Length   | Description
    ---------+-----------------------------
    2 bytes  | Bind Request Prefix
    2 bytes  | Peer Mode (0 or 1)
    2 bytes  | Exchange Length
    2 bytes  | Exchange
    2 bytes  | Program Length
    variable | Program

##### Response

    Length   | Description
    ---------+-----------------------------
    2 bytes  | Bind Prefix
    4 bytes  | Binding ID

#### Unbind

##### Request

    Length   | Description
    ---------+-----------------------------
    2 bytes  | Unbind Request Prefix
    4 bytes  | Binding ID
    2 bytes  | Exchange Length
    variable | Exchange

##### Response

    Length   | Description
    ---------+-----------------------------
    2 bytes  | Unbind Prefix
    4 bytes  | Binding ID

On success, the response binding id will be the same as the one sent in the request.

#### Status

##### Request

    Length   | Description
    ---------+-----------------------------
    2 bytes  | Status Request Prefix

##### Response

    Length   | Description
    ---------+-----------------------------
    2 bytes  | Status Prefix
    2 bytes  | Key Length
    variable | Key
    4 bytes  | Value
    … (repeat key length, key, value sets)
    2 bytes  | Key Length 0

The response contains serveral key-value pairs. Each key is prefixed by a length and parsing of kv pairs should continue until a key length of 0 is read.

#### Heartbeat Request

##### Request

    Length   | Description
    ---------+-----------------------------
    2 bytes  | Heartbeat Request Prefix
    2 bytes  | Heartbeat Interval (milliseconds)

##### Response

None

#### Heartbeat

##### Request

    Length   | Description
    ---------+-----------------------------
    2 bytes  | Heartbeat Prefix
    
##### Response

    Length   | Description
    ---------+-----------------------------
    2 bytes  | Heartbeat Prefix

## Messages

    Length   | Description                       | Note
    ---------+-----------------------------------+------------------------
    1 byte   | Exchange Length                   |
    variable | Exchange                          |
    1 byte   | Route Length                      |
    16 bytes | Message ID                        |
    1 byte   | Sender Length                     | Send for Peer Mode Only
    variable | Sender                            | Send for Peer Mode Only
    1 byte   | Number of Hops                    | Send for Peer Mode Only
    variable | Hops (numHops sets of 4-byte IPs) | Send for Peer Mode Only
    4 bytes  | Payload Length                    |
    variable | Payload (<= 128kb)                |

All properties will be present when receiving a message, while some propertiers are only sent when in peer mode.