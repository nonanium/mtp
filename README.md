# **M**ethanium **T**ransport **P**rotocol

**MTP** is a **m**odular **t**ransport **p**rotocol by Methanium.

## Crates
- Codec
- Transport
- Common
- Crypto
- TypeMap
- Registry
- Host
- Client

## Codec

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

## Transport

The Transport crate wraps QUIC using `wtransport`. It provides `Sender`/`Receiver` for bidirectional message passing over QUIC streams.

## Common

Common handles logging and error handling. Personal information reported to Common will be anonymized.

## Crypto Stack

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
