# erlang_quic Design Document

This document describes the architecture and design of the erlang_quic implementation.

## Architecture Overview

The implementation is organized into the following module groups:

### Public API Layer

| Module | Responsibility |
|--------|----------------|
| `quic` | Main public API for client connections |
| `quic_listener` | Server-side listener for accepting connections |

### Connection Layer

| Module | Responsibility |
|--------|----------------|
| `quic_connection` | Connection state machine (gen_statem) |
| `quic_stream` | Stream state management |

### Protocol Layer

| Module | Responsibility |
|--------|----------------|
| `quic_packet` | Packet encoding/decoding |
| `quic_frame` | Frame encoding/decoding |
| `quic_varint` | Variable-length integer encoding (RFC 9000 Section 16) |

### Cryptography Layer

| Module | Responsibility |
|--------|----------------|
| `quic_crypto` | Key derivation and transcript hashing |
| `quic_tls` | TLS 1.3 message building and parsing |
| `quic_keys` | Traffic key derivation |
| `quic_aead` | AEAD encryption/decryption and header protection |
| `quic_hkdf` | HKDF-based key expansion |

### Flow Control Layer

| Module | Responsibility |
|--------|----------------|
| `quic_flow` | Connection and stream flow control |
| `quic_cc` | Congestion control (NewReno) |
| `quic_loss` | Loss detection and recovery |
| `quic_ack` | ACK frame processing and generation |

### Session Layer

| Module | Responsibility |
|--------|----------------|
| `quic_ticket` | Session ticket storage and PSK derivation |

## Connection Lifecycle

```
                    ┌─────────┐
                    │  idle   │
                    └────┬────┘
                         │ send ClientHello
                         ▼
                  ┌──────────────┐
                  │ handshaking  │
                  └──────┬───────┘
                         │ receive server Finished
                         │ send client Finished
                         ▼
                  ┌──────────────┐
                  │  connected   │◄────────┐
                  └──────┬───────┘         │
                         │                 │ key update
                         │                 │ migration
                         └─────────────────┘
                         │ close/error
                         ▼
                  ┌──────────────┐
                  │   draining   │
                  └──────┬───────┘
                         │ drain timeout
                         ▼
                    ┌─────────┐
                    │ closed  │
                    └─────────┘
```

### State Descriptions

- **idle**: Initial state, preparing to connect
- **handshaking**: TLS 1.3 handshake in progress
- **connected**: Connection established, data transfer active
- **draining**: Connection closing, processing remaining packets
- **closed**: Connection terminated

## Packet Processing

### Encryption Levels

QUIC uses four encryption levels, each with its own keys:

| Level | Usage |
|-------|-------|
| Initial | ClientHello, ServerHello (derived from DCID) |
| Handshake | EncryptedExtensions through Finished |
| 0-RTT | Early data (optional, from session resumption) |
| 1-RTT | Application data after handshake |

### Packet Types

**Long Header Packets:**
- Initial (type 0x00)
- 0-RTT (type 0x01)
- Handshake (type 0x02)
- Retry (type 0x03)

**Short Header Packets:**
- 1-RTT (application data)

### Frame Processing

Frames are processed in order within a packet. Key frame types:

| Frame Type | Description |
|------------|-------------|
| PADDING (0x00) | Padding for packet size |
| PING (0x01) | Keep-alive |
| ACK (0x02-0x03) | Acknowledgment |
| CRYPTO (0x06) | TLS handshake data |
| STREAM (0x08-0x0f) | Stream data |
| MAX_DATA (0x10) | Connection flow control |
| MAX_STREAM_DATA (0x11) | Stream flow control |
| NEW_CONNECTION_ID (0x18) | Issue new CID |
| PATH_CHALLENGE (0x1a) | Path validation |
| PATH_RESPONSE (0x1b) | Path validation response |
| CONNECTION_CLOSE (0x1c-0x1d) | Close connection |

## TLS Integration

### Handshake Flow (Client)

```
Client                                  Server
  │                                       │
  │───── Initial[ClientHello] ──────────►│
  │                                       │
  │◄──── Initial[ServerHello] ───────────│
  │◄──── Handshake[EncryptedExtensions] ─│
  │◄──── Handshake[Certificate] ─────────│
  │◄──── Handshake[CertificateVerify] ───│
  │◄──── Handshake[Finished] ────────────│
  │                                       │
  │───── Handshake[Finished] ───────────►│
  │                                       │
  │◄════ 1-RTT[Application Data] ════════│
```

### Key Derivation

Keys are derived using HKDF with the following hierarchy:

```
                    PSK (or 0)
                        │
                        ▼
                 ┌─────────────┐
                 │ Early Secret│
                 └──────┬──────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             │             ▼
    client_early    binder_key    res_secret
    traffic_secret                    │
                                      │
                        ▼             │
              ┌───────────────┐       │
    (EC)DHE──►│Handshake Secret│      │
              └───────┬───────┘       │
                      │               │
        ┌─────────────┼─────────────┐ │
        ▼             │             ▼ │
   client_hs      server_hs    derived│
   traffic        traffic         │   │
   secret         secret          │   │
                                  ▼   │
                        ┌─────────────┐
                        │Master Secret│
                        └──────┬──────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                │                ▼
        client_app         server_app      resumption
        traffic            traffic         master
        secret             secret          secret
```

## Stream Management

### Stream IDs

Stream IDs encode initiator and directionality:

| Bits 1-0 | Stream Type |
|----------|-------------|
| 0x00 | Client-initiated, bidirectional |
| 0x01 | Server-initiated, bidirectional |
| 0x02 | Client-initiated, unidirectional |
| 0x03 | Server-initiated, unidirectional |

### Stream States

**Sending side:**
- Ready → Send → Data Sent → Data Recvd (terminal)
- Ready → Reset Sent → Reset Recvd (terminal)

**Receiving side:**
- Recv → Size Known → Data Recvd → Data Read (terminal)
- Recv → Reset Recvd → Reset Read (terminal)

## Flow Control

### Connection-Level

- `MAX_DATA` frame advertises connection-level receive window
- Sender tracks `data_sent` against peer's `max_data`
- Receiver sends `MAX_DATA` updates when buffer space is freed

### Stream-Level

- `MAX_STREAM_DATA` frame advertises per-stream receive window
- Similar tracking at stream granularity
- `BLOCKED` and `STREAM_BLOCKED` frames signal flow control limits

## Congestion Control

The implementation uses NewReno congestion control (RFC 9002):

### States

- **Slow Start**: Exponential growth until `ssthresh`
- **Congestion Avoidance**: Linear growth after slow start
- **Recovery**: After packet loss detection

### Key Variables

| Variable | Description |
|----------|-------------|
| `cwnd` | Congestion window (bytes) |
| `ssthresh` | Slow start threshold |
| `bytes_in_flight` | Unacknowledged bytes |

### On ACK

```
if bytes_acked > 0:
    if cwnd < ssthresh:
        cwnd += bytes_acked  # Slow start
    else:
        cwnd += (bytes_acked * max_datagram_size) / cwnd  # Congestion avoidance
```

### On Loss

```
ssthresh = max(cwnd / 2, 2 * max_datagram_size)
cwnd = ssthresh
```

## Loss Detection

### Packet Loss Detection

Two mechanisms detect packet loss:

1. **Packet Threshold**: A packet is lost if a later packet in the same number space has been acknowledged and the gap exceeds the threshold (default: 3).

2. **Time Threshold**: A packet is lost if it was sent more than `max(smoothed_rtt + max(4 * rtt_var, 1ms), 1.125 * smoothed_rtt)` before the largest acknowledged packet.

### Probe Timeout (PTO)

When no ACKs are received, PTO triggers retransmission:

```
PTO = smoothed_rtt + max(4 * rtt_var, 1ms) + max_ack_delay
```

After PTO expires:
1. Send 1-2 ack-eliciting packets
2. Double PTO for next timeout
3. After persistent congestion, reset to slow start

## Connection Migration

### Path Validation

When the peer's address changes:

1. Send `PATH_CHALLENGE` frame with random 8-byte data
2. Peer responds with `PATH_RESPONSE` containing same data
3. Path is validated upon receiving correct response

### Migration Process

1. Detect new remote address
2. Initiate path validation
3. Continue using old path until validation completes
4. Switch to new path upon successful validation
5. Reset congestion controller for new path

## Key Update

RFC 9001 Section 6 defines key update mechanism:

1. Sender increments key phase bit in packet header
2. Derives new keys from current application secrets
3. Receiver detects phase change and derives matching keys
4. Old keys retained briefly for reordered packets

```
next_app_secret = HKDF-Expand-Label(current_app_secret, "quic ku", "", hash_len)
```

## Connection ID Management

### Local CID Pool

- Generate and issue CIDs via `NEW_CONNECTION_ID` frame
- Track sequence numbers and stateless reset tokens
- Retire old CIDs via `RETIRE_CONNECTION_ID`

### Peer CID Pool

- Store CIDs received from peer
- Select appropriate CID for path
- Respect `active_connection_id_limit` transport parameter
