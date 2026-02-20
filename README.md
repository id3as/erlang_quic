# erlang_quic

Pure Erlang QUIC implementation (RFC 9000/9001).

## Features

- TLS 1.3 handshake (RFC 8446)
- Stream multiplexing (bidirectional and unidirectional)
- Key update support (RFC 9001 Section 6)
- Connection migration with active path migration API (RFC 9000 Section 9)
- 0-RTT early data support with session resumption (RFC 9001 Section 4.6)
- DATAGRAM frame support for unreliable data (RFC 9221)
- QUIC v2 support (RFC 9369)
- Server mode with listener and pooled listeners (SO_REUSEPORT)
- QUIC-LB load balancer support with routable CIDs (RFC 9312)
- Retry packet handling for address validation (RFC 9000 Section 8.1)
- Stateless reset support (RFC 9000 Section 10.3)
- Flow control (connection and stream level)
- Congestion control (NewReno with ECN support)
- Loss detection and packet retransmission (RFC 9002)

## Requirements

- Erlang/OTP 26.0 or later
- rebar3

## Installation

Add to your `rebar.config` dependencies:

```erlang
{deps, [
    {quic, {git, "https://github.com/benoitc/erlang_quic.git", {branch, "main"}}}
]}.
```

## Quick Start

### Client

```erlang
%% Connect to a QUIC server
{ok, ConnRef} = quic:connect(<<"example.com">>, 443, #{
    alpn => [<<"h3">>],
    verify => false
}, self()),

%% Wait for connection
receive
    {quic, ConnRef, {connected, Info}} ->
        io:format("Connected: ~p~n", [Info])
end,

%% Open a bidirectional stream
{ok, StreamId} = quic:open_stream(ConnRef),

%% Send data on the stream
ok = quic:send_data(ConnRef, StreamId, <<"Hello, QUIC!">>, true),

%% Receive data
receive
    {quic, ConnRef, {stream_data, StreamId, Data, _Fin}} ->
        io:format("Received: ~p~n", [Data])
end,

%% Close connection
quic:close(ConnRef, normal).
```

### Server

```erlang
%% Load certificate and key
{ok, CertDer} = file:read_file("server.crt"),
{ok, KeyDer} = file:read_file("server.key"),

%% Start a named server (recommended)
{ok, _Pid} = quic:start_server(my_server, 4433, #{
    cert => CertDer,
    key => KeyDer,
    alpn => [<<"h3">>]
}),

%% Get the port (useful if 0 was specified for ephemeral port)
{ok, Port} = quic:get_server_port(my_server),
io:format("Listening on port ~p~n", [Port]),

%% Incoming connections are handled automatically
%% The server spawns quic_connection processes for each client

%% Stop the server when done
quic:stop_server(my_server).
```

Alternatively, use the low-level listener API directly:

```erlang
{ok, Listener} = quic_listener:start_link(4433, #{
    cert => CertDer,
    key => KeyDer,
    alpn => [<<"h3">>]
}),
Port = quic_listener:get_port(Listener).
```

## Messages

The owner process receives messages in the format `{quic, ConnRef, Event}`:

| Event | Description |
|-------|-------------|
| `{connected, Info}` | Connection established |
| `{stream_opened, StreamId}` | New stream opened by peer |
| `{stream_data, StreamId, Data, Fin}` | Data received on stream |
| `{stream_reset, StreamId, ErrorCode}` | Stream reset by peer |
| `{closed, Reason}` | Connection closed |
| `{transport_error, Code, Reason}` | Transport error |
| `{session_ticket, Ticket}` | Session ticket for 0-RTT resumption |
| `{datagram, Data}` | Datagram received (RFC 9221) |
| `{stop_sending, StreamId, ErrorCode}` | Stop sending requested by peer |
| `{send_ready, StreamId}` | Stream ready for writing |

## API Reference

### Connection

- `quic:connect/4` - Connect to a QUIC server
- `quic:close/2` - Close a connection
- `quic:peername/1` - Get remote address
- `quic:sockname/1` - Get local address
- `quic:peercert/1` - Get peer certificate (DER-encoded)
- `quic:set_owner/2` - Transfer connection ownership (like gen_tcp:controlling_process/2)
- `quic:migrate/1` - Trigger connection migration to new local address
- `quic:setopts/2` - Set connection options

### Streams

- `quic:open_stream/1` - Open bidirectional stream
- `quic:open_unidirectional_stream/1` - Open unidirectional stream
- `quic:send_data/4` - Send data on stream
- `quic:reset_stream/3` - Reset a stream

### Datagrams (RFC 9221)

- `quic:send_datagram/2` - Send unreliable datagram

### Load Balancer (RFC 9312)

- `quic_lb:new_config/1` - Create LB configuration from options map
- `quic_lb:new_cid_config/1` - Create CID generation configuration
- `quic_lb:generate_cid/1` - Generate a CID with encoded server_id
- `quic_lb:decode_server_id/2` - Extract server_id from CID
- `quic_lb:is_lb_routable/1` - Check if CID has valid LB routing bits
- `quic_lb:get_config_rotation/1` - Get config rotation bits from CID
- `quic_lb:expected_cid_len/1` - Calculate expected CID length from config

### Server

- `quic_listener:start_link/2` - Start a QUIC listener
- `quic_listener:start/2` - Start unlinked listener
- `quic_listener:stop/1` - Stop listener
- `quic_listener:get_port/1` - Get listening port
- `quic_listener:get_connections/1` - List active connections
- `quic_listener_sup:start_link/2` - Start pooled listeners (SO_REUSEPORT)
- `quic_listener_sup:get_listeners/1` - Get listener PIDs in pool

### Named Server Pools

Ranch-style named server pool management:

- `quic:start_server/3` - Start named server pool
- `quic:stop_server/1` - Stop named server
- `quic:get_server_info/1` - Get server information
- `quic:get_server_port/1` - Get server listening port
- `quic:get_server_connections/1` - Get server connection PIDs
- `quic:which_servers/0` - List all running servers

**Server Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `cert` | binary | required | DER-encoded server certificate |
| `key` | term | required | Server private key |
| `alpn` | [binary()] | `[<<"h3">>]` | ALPN protocols to advertise |
| `pool_size` | pos_integer() | 1 | Number of listener processes (uses SO_REUSEPORT) |
| `connection_handler` | fun/2 | none | Custom handler: `fun(ConnPid, ConnRef) -> {ok, HandlerPid}` |
| `lb_config` | map() | none | QUIC-LB configuration for load balancer routing (see below) |

**Server Info Map:**

`get_server_info/1` returns a map with:
- `pid` - Server supervisor PID
- `port` - Listening port number
- `opts` - Server options map
- `started_at` - Start timestamp (milliseconds since epoch)

**Example:**

```erlang
%% Start a named server with connection pooling
{ok, _} = quic:start_server(my_server, 4433, #{
    cert => CertDer,
    key => KeyTerm,
    alpn => [<<"h3">>],
    pool_size => 4  %% 4 listener processes with SO_REUSEPORT
}),

%% Query servers
quic:which_servers().             %% => [my_server]
quic:get_server_port(my_server).  %% => {ok, 4433}
quic:get_server_info(my_server).  %% => {ok, #{pid => <0.123.0>, port => 4433, ...}}
quic:get_server_connections(my_server).  %% => {ok, [<0.150.0>, <0.151.0>]}

%% Stop server
quic:stop_server(my_server).
```

### QUIC-LB Load Balancer Support (RFC 9312)

Enable load balancers to route QUIC packets to the correct server by encoding
server identity in Connection IDs.

**LB Config Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `server_id` | binary() | required | Server identifier (1-15 bytes) |
| `algorithm` | atom() | `plaintext` | `plaintext`, `stream_cipher`, or `block_cipher` |
| `config_rotation` | 0..6 | 0 | Config version for LB coordination |
| `nonce_len` | 4..18 | 4 | Random nonce length in bytes |
| `key` | binary() | none | 16-byte AES key (required for cipher algorithms) |

**Example:**

```erlang
%% Start server with QUIC-LB enabled
{ok, _} = quic:start_server(my_server, 4433, #{
    cert => CertDer,
    key => KeyTerm,
    alpn => [<<"h3">>],
    lb_config => #{
        server_id => <<1, 2, 3, 4>>,      %% Unique ID for this server
        algorithm => stream_cipher,        %% Encrypt server_id in CID
        key => crypto:strong_rand_bytes(16)  %% Shared with load balancer
    }
}),

%% The server now generates CIDs that encode the server_id
%% Load balancer can decode server_id to route packets correctly
```

**Algorithms:**

- `plaintext` - Server ID visible in CID (no encryption, simplest)
- `stream_cipher` - AES-128-CTR encryption (recommended for most deployments)
- `block_cipher` - AES-based encryption with Feistel network for variable lengths

**Direct API:**

```erlang
%% Create LB configuration
{ok, LBConfig} = quic_lb:new_config(#{
    server_id => <<1, 2, 3, 4>>,
    algorithm => stream_cipher,
    key => Key
}),

%% Generate a CID
{ok, CIDConfig} = quic_lb:new_cid_config(#{lb_config => LBConfig}),
CID = quic_lb:generate_cid(CIDConfig),

%% Decode server_id from CID (used by load balancer)
{ok, <<1, 2, 3, 4>>} = quic_lb:decode_server_id(CID, LBConfig),

%% Check if CID is LB-routable
true = quic_lb:is_lb_routable(CID).
```

## Building

```bash
rebar3 compile
```

## Testing

```bash
# Run unit tests
rebar3 eunit

# Run property-based tests
rebar3 proper

# Run all tests
rebar3 eunit && rebar3 proper
```

## Interoperability

This implementation passes all 10 [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner) test cases:

| Test Case | Status | Description |
|-----------|--------|-------------|
| handshake | ✓ | Basic QUIC handshake |
| transfer | ✓ | File download with flow control |
| retry | ✓ | Retry packet handling |
| keyupdate | ✓ | Key rotation during transfer |
| chacha20 | ✓ | ChaCha20-Poly1305 cipher |
| multiconnect | ✓ | Multiple connections |
| v2 | ✓ | QUIC v2 support |
| resumption | ✓ | Session resumption with PSK |
| zerortt | ✓ | 0-RTT early data |
| connectionmigration | ✓ | Active path migration |

See [interop/README.md](interop/README.md) for details on running interop tests.

## Documentation

Generate documentation with:

```bash
rebar3 ex_doc
```

## License

Apache License 2.0

## Author

Benoit Chesneau
