# Methanium Transport Protocol

MTP is a modular transport protocol built on QUIC. It provides version-negotiable type maps, a binary codec, cryptographic primitives (classical and post-quantum), and host/client connection management with mutual authentication.

## Getting Started

Add the `mtp` crate with your desired features:

```toml
[dependencies]
mtp = { path = "..", features = ["client", "crypto"] }
```

The `mtp` umbrella crate re-exports all sub-crates behind feature flags:

| Feature  | Pulls in                    | Enables                                   |
| -------- | --------------------------- | ----------------------------------------- |
| `crypto` | `mtp::crypto`               | AEAD, signatures, KEM, KDF, hashing       |
| `host`   | `mtp::host`, `mtp::codec::registry` | QUIC server, version negotiation  |
| `client` | `mtp::client`               | QUIC client connections                   |

Core crates (`codec`, `transport`, `common`, `type_map`) are always available.

```rust
use mtp::codec::{CommunicationValue, DataValue};
use mtp::type_map::{CommunicationType, DataType, TypeMap};
use mtp::transport::{Sender, Receiver};

#[cfg(feature = "crypto")]
use mtp::crypto::ChaCha20Poly1305;
```

## Sub-crates

All sub-crates are re-exported through the `mtp` facade and can be referenced as `mtp::codec`, `mtp::transport`, `mtp::common`, `mtp::type_map`, `mtp::crypto`, `mtp::host`, `mtp::client`.

### Codec

The codec crate handles binary encoding and decoding of MTP packets using Communication Types and Data Types resolved through the type-map registry.

**Data Value types:**
- Container (key-value map of typed entries)
- Encrypted Container (requires `crypto`)
- Signed Container (requires `crypto`)
- SignedEncrypted Container (requires `crypto`)
- Signed Integer (i128)
- Unsigned Integer (u128)
- Boolean
- Float (exponent + mantissa)
- String
- Array
- Bytes
- Null

Encoding and decoding use a `TypeMap` to resolve type names to wire IDs. The `CommunicationValue` struct provides the frame format (type, flags, optional id/sender/receiver, data payload, optional signature).

### Transport

The transport crate wraps QUIC using `wtransport`. It provides `Sender`/`Receiver` for bidirectional message passing over uni-directional QUIC streams. Supports two send modes: persistent stream and single-stream-per-message.

### Host

The host crate provides `MTPHost` with built-in version negotiation and optional authenticated login/registration (requires `crypto`). Accepts connections, negotiates protocol version, and returns `MTPConnection` handles.

### Client

The client crate provides `MTPClient` that connects to an MTP host. Supports `connect` (unauthenticated), `auth_connect` (login), and `auth_register` (registration) when built with `crypto`.

### Common

Common defines shared error types (`CodecError`, `CommunicationError`) used across all crates.

### Type Map

The type-map build script reads a YAML configuration to generate `CommunicationType` and `DataType` enums at compile time. The runtime crate provides `TypeMap`, `Version`, `CommunicationTypeId`, `DataTypeId`, and the multi-version `Registry` (requires `registry` feature).

### Crypto Stack

| Crate            | Audited? | Notes                                            |
| ---------------- | -------- | ------------------------------------------------ |
| ml-dsa           | No       | NIST vectors pass; regression bug fixed Jan 2026 |
| ed25519-dalek    | Yes      | Used by Signal, Diem                             |
| chacha20poly1305 | Yes      | NCC Group audit, Dec 2019                        |
| aes-gcm          | Yes      | NCC Group audit, Dec 2019                        |
| hkdf             | No       | Simple construction; well-reviewed               |
| sha2             | No       | Standard construction; widely reviewed           |
| zeroize          | No       | Simple; widely used                              |
| mlkem-tls        | No       | mlkem-rs backend unaudited                       |
