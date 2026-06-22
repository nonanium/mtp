# **M**ethanium **T**ransport **P**rotocol

**MTP** is a **m**odular **t**ransport **p**rotocol by Methanium.

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
use mtp::codec::{encode, decode, DataValue};
use mtp::type_map::TypeMap;
use mtp::transport::Sender;

#[cfg(feature = "crypto")]
use mtp::crypto::ChaCha20Poly1305;
```

## Sub-crates

All sub-crates are re-exported through the `mtp` facade and can be referenced
as `mtp::codec`, `mtp::transport`, `mtp::common`, `mtp::type_map`,
`mtp::crypto`, `mtp::host`, `mtp::client`.

### Codec

The Codec crate handles encoding and decoding of MTP packets using Communication Types and Data Types from the Registry.

**Data Values:**
- Container
- Encrypted Container (requires `crypto` feature)
- Signed Integer
- Unsigned Integer
- Boolean
- Signed Float
- String
- Array
- Binary (List of Bytes)

Encoding/decoding uses a `TypeMap` to resolve type names to wire IDs.

The Codec uses the Crypto crate to encrypt and decrypt Encrypted Containers.

---

### Transport

The Transport crate wraps QUIC using `wtransport`. It provides `Sender`/`Receiver` for bidirectional message passing over QUIC streams.

### Common

Common handles logging and error handling. Personal information reported to Common will be anonymized.

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
