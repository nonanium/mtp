# **M**ethanium **T**ransport **P**rotocol

**MTP** is a **m**odular **t**ransport **p**rotocol by Methanium.

## Crates
- Common
- Crypto
- TypeMap
- Registry
- Codec
- Transport
- Host
- Client

## Registry & TypeMaps
A TypeMap maps Communication-Types to a byte, and Data-Types to 2 bytes.
A Communication- or Data-Type is a String to be used Plain in the code, while the Byte is transmitted.

The Registries map a TypeMap to a specific version of MTP.

## Codec
The Codec crate handles encoding and decoding of MTP packets using Communication Types and Data Types from the Registry.
The Codec has these Data Values:
- Container
- Encrypted Container
- Signed Integer
- Unsigned Integer
- Boolean 
- Signed Float
- String
- Array
- Binary (List of Bytes)

The Codec uses the Crypto crate to encrypt and decrypt Encrypted Containers.

## Transport
The Transport crate wraps QUIC.

## Host & Client
The host creates a quic Server that listens for incoming connections.
The host also manages the registry and versions to allow for backwards compatibility with clients.

The client connects to a quic Server and uses a registry to communicate with the host.

The Client may be Outdated while the Host is updated.

## Common
Common Handles Logging and Error Handling. Personal information reported to Common will be anonmized.

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
