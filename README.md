# Methanium Transport Protocol

MTP is a modular transport protocol built on QUIC. It provides versioned type maps, a binary codec, native and browser clients, host and WebTransport server implementations, and optional cryptographic authentication and end-to-end encryption.

Security assumptions, certificate handling, authentication, cryptographic primitives, key storage, and known limitations: [Security](./docs/SECURITY.md).

Area-specific guides:

- [Architecture](./docs/ARCHITECTURE.md)
- [Connection lifecycle](./docs/CONNECTIONS.md)
- [Native client](./docs/NATIVE-CLIENT.md)
- [WASM client](./docs/WASM-CLIENT.md)
- [Native host](./docs/NATIVE-HOST.md)
- [Web server](./docs/NATIVE-HOST-WEB-SERVER.md)
- [Connector and version negotiation](./docs/CONNECTOR.md)
- [Protocol reference](./docs/PROTOCOL-REFERENCE.md)
- [Type maps](./docs/TYPE-MAP.md)
- [Error reference](./docs/ERRORS.md)
- [Troubleshooting](./docs/TROUBLESHOOTING.md)
- [Operations](./docs/OPERATIONS.md)

`MTPWebServer` owns its UDP endpoint and must not bind to the same address and port as `MTPHost`.

## Browser SDK

The JavaScript package is `mtp`.

- `mtp` exports the SDK-first `MTPClient` API and codec helpers.
- `mtp/raw` exports generated WASM bindings for lower-level integrations.
- `mtp/vite` exports the Vite integration that builds app-specific bindings.
- `mtp/type-map` exports generated TypeScript type-name unions.

Use the [WASM client guide](./docs/WASM-CLIENT.md) for installation, type-map configuration, credentials, certificate pins, requests, subscriptions, pipes, and protocol pings. Use the SDK methods before raw bindings because the raw API does not provide the wrapper's validation, persistence, timeout, logging, or lifecycle handling.

The SDK exposes crypto helpers and frame codec helpers from the main `mtp` export. The security guide describes the available algorithms and their limitations.

## Getting Started

Add the umbrella crate with the features required by the application:

```toml
[dependencies]
mtp = { path = "..", features = ["client", "crypto"] }
```

Feature summary:

| Feature | Pulls in | Enables |
| --- | --- | --- |
| `crypto` | `mtp::crypto` | AEAD, signatures, KEM, KDF, hashing |
| `host` | `mtp::host`, codec registry | QUIC host and version negotiation |
| `client` | `mtp::client` | QUIC client connections |

The core crates are always available: `codec`, `transport`, `common`, and `type_map`. See the [native client](./docs/NATIVE-CLIENT.md) and [native host](./docs/NATIVE-HOST.md)
guides for configuration and usage. See [Security](./docs/SECURITY.md) for security boundaries.

## Sub-crates

The `mtp` facade re-exports the following modules:
`mtp::codec`, `mtp::transport`, `mtp::common`, `mtp::type_map`, `mtp::crypto`, `mtp::host`, and `mtp::client`.

### Codec

The codec encodes and decodes MTP frames using Communication Types and Data Types resolved through a version-specific type map. It supports containers, integers, booleans, floats, strings, arrays, bytes, null values, and optional signed or encrypted containers. See [Type Map](./docs/TYPE-MAP.md) for mapping configuration and [Connector](./docs/CONNECTOR.md) for negotiated codecs.

### Transport

The transport crate wraps QUIC with `wtransport`. `Sender` and `Receiver` exchange framed messages over unidirectional streams. The transport supports a persistent stream and a single-stream-per-message mode, with configurable message limits, timeouts, queues, and stream concurrency.

Certificate verification is controlled by client configuration. Use system roots or explicit certificate and SPKI pinning for production. Development self-signed and insecure modes: [Security](./docs/SECURITY.md).

### Host

The host crate provides `MTPHost`, registry-backed version negotiation, optional authentication, and `MTPConnection` handles. Authentication policies and the challenge-response protocol: [Native Host](./docs/NATIVE-HOST.md) and [Security](./docs/SECURITY.md).

### Client

The native client provides unauthenticated connections, authenticated login, and registration when the `crypto` feature is enabled. See [Native Client](./docs/NATIVE-CLIENT.md).

The browser client uses the `mtp` SDK over WebTransport. See [WASM Client](./docs/WASM-CLIENT.md).

### Common

Common defines shared errors such as `CodecError` and `CommunicationError`, as well as protocol-level types used by the other crates.

### Type Map

The type-map build script reads YAML and generates `CommunicationType` and `DataType` enums at compile time. The runtime crate provides `TypeMap`, `Version`, ID types, and the multi-version `Registry` when the registry feature is enabled. See [Type Map](./docs/TYPE-MAP.md).

### Crypto

`mtp-crypto` provides AEAD encryption, Ed25519 and ML-DSA-65 signatures, X25519 plus ML-KEM-768 hybrid KEM support, HKDF, SHA-256, keyrings, encrypted containers, and certificate generation for development. Feature flags and security boundaries: [Security](./docs/SECURITY.md).

## Examples

The [`example/`](./example/) workspace contains native client, native server, key-generation, WebTransport server, and browser client examples. The example server stores its generated development certificate and host keys locally; use the certificate pin it prints when connecting the example client.
