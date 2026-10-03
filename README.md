# Methanium Transport Protocol

MTP is a modular transport protocol built on QUIC. It provides versioned type maps, a binary codec, native and browser clients, host and WebTransport server implementations, and optional cryptographic authentication and end-to-end encryption.

Security assumptions, certificate handling, authentication, cryptographic primitives, key storage, and known limitations: [Security](./docs/SECURITY.md).

Area-specific guides:

- [Architecture](./docs/ARCHITECTURE.md)
- [Connection lifecycle](./docs/CONNECTIONS.md)
- [Native client](./docs/NATIVE-CLIENT.md)
- [Tauri integration](./docs/TAURI.md)
- [WASM client](./docs/WASM-CLIENT.md)
- [Native host](./docs/NATIVE-HOST.md)
- [Web server](./docs/NATIVE-HOST-WEB-SERVER.md)
- [Connector and version negotiation](./docs/CONNECTOR.md)
- [Protocol reference](./docs/PROTOCOL-REFERENCE.md)
- [Type maps](./docs/TYPE-MAP.md)
- [Error reference](./docs/ERRORS.md)
- [Troubleshooting](./docs/TROUBLESHOOTING.md)
- [Operations](./docs/OPERATIONS.md)

`MTPWebServer` owns TCP TLS (HTTP/1.1 and HTTP/2) plus UDP QUIC (HTTP/3 and WebTransport) on one numeric port. It must not bind its UDP address and port as `MTPHost`: their QUIC ALPN protocols remain incompatible (`h3` for the web server, native MTP for the host).

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
| `serde` | Crypto serialization support | Serde implementations for crypto key types |
| `crypto` | `mtp::crypto` | AEAD, signatures, KEM, KDF, hashing, and connection authentication support |
| `host` | `mtp::host` | Native QUIC host and version negotiation |
| `client` | `mtp::client` | Native QUIC client connections |
| `native` | `mtp::native` | Native QUIC adapter; enabled automatically by `host` and `client` |
| `pipes` | Pipe support in transport, host, client, and web server | Raw and encrypted byte streams |
| `files` | `mtp::files` | `.mk` keyrings and `.mpkb` public bundles; also enables `crypto` |
| `raw` | Raw file APIs | Legacy plaintext keyring migration APIs |
| `web-server` | `mtp::webserver` | HTTPS server with HTTP/1.1, HTTP/2, HTTP/3, and WebTransport MTP sessions |
| `full-server` | Native host and web-server surface | `host`, `web-server`, `crypto`, and `pipes` together |
| `tls` | `mtp::crypto::tls` | Development self-signed certificate generation |
| `insecure-tls` | Lower-level transport | Development-only certificate verification bypass, gated by `MTP_INSECURE_TLS=1` |

The core modules always available from the facade are `core`, `codec`, `common`, and
`type_map`. Native `client` and `host` modules re-export the connection policy
types, and the native adapter is available as `mtp::native`. See the [native client](./docs/NATIVE-CLIENT.md) and [native host](./docs/NATIVE-HOST.md)
guides for configuration and usage. See [Security](./docs/SECURITY.md) for security boundaries.

## Sub-crates

The `mtp` facade re-exports the following modules:
`mtp::core`, `mtp::codec`, `mtp::common`, `mtp::type_map`, `mtp::native`, `mtp::crypto`, `mtp::host`,
`mtp::client`, `mtp::files`, and `mtp::webserver` when their features are enabled.

### Codec

The codec encodes and decodes MTP frames using Communication Types and Data Types resolved through a version-specific type map. It supports self-delimiting containers, integers, booleans, floats, strings, arrays, bytes, null values, and composable `Signed<Value>` and `Encrypted<Value>` protection wrappers. Wrap in either order to choose whether signer metadata is public or encrypted. See [Type Map](./docs/TYPE-MAP.md) for mapping configuration and [Connector](./docs/CONNECTOR.md) for negotiated codecs.

### Core and bindings

`mtp-core` owns portable framing, retry, limit, and policy decisions. The crates under `bindings/` adapt those decisions to native wtransport, H3 WebTransport, and browser WebTransport. Native `Sender` and `Receiver` retain their connection metadata API while sharing the portable policy and framing rules.

`mtp-pipes` owns pipe negotiation, deadlines, cancellation and encrypted records.
It depends on core transport interfaces, common protocol types and codec, with
crypto enabled by its `encrypted` feature. It never depends on bindings.
Use `mtp_pipes::PipeDispatcher`, `mtp_pipes::PipeRequest` and
`mtp_pipes::EncryptedPipeWriter`, or `mtp::pipes` with umbrella features `pipes`
and `crypto`. Async byte streams may use non-`Send` browser futures.

Certificate verification is controlled by client configuration. Use system roots or explicit certificate and SPKI pinning for production. Development self-signed and insecure modes: [Security](./docs/SECURITY.md).

### Host

The host crate provides `MTPHost`, registry-backed version negotiation, optional authentication, and `MTPConnection` handles. Authentication policies and the challenge-response protocol: [Native Host](./docs/NATIVE-HOST.md) and [Security](./docs/SECURITY.md).

### Client

The native client provides unauthenticated connections, authenticated login, and registration when the `crypto` feature is enabled. See [Native Client](./docs/NATIVE-CLIENT.md).

The browser client uses the `mtp` SDK over WebTransport. See [WASM Client](./docs/WASM-CLIENT.md).

### Common

Common defines shared errors such as `CodecError` and `CommunicationError`, as well as protocol-level types used by the other crates.

## Repository layout

Protocol and application crates stay at the root. Platform code lives under `bindings/`, the published TypeScript package lives in `sdk/`, and all cross-package suites and example fixtures live in `tests/`. Cargo and pnpm each use one workspace and one lockfile.

### Type Map

The type-map build script reads YAML and generates `CommunicationType` and `DataType` enums at compile time. The runtime crate provides `TypeMap`, `Version`, ID types, and the multi-version `Registry` when the registry feature is enabled. See [Type Map](./docs/TYPE-MAP.md).

### Crypto

`mtp-crypto` provides AEAD encryption, Ed25519 and ML-DSA-65 signatures, X25519 plus ML-KEM-768 hybrid KEM support, HKDF, SHA-256, keyrings, composable protection envelopes, and certificate generation for development. Feature flags and security boundaries: [Security](./docs/SECURITY.md).

## Examples

The [`tests/fixtures/example/`](./tests/fixtures/example/) workspace contains native client, native server, key-generation, WebTransport server, and browser client examples. The example server stores its generated development certificate and host keys locally; use the certificate pin it prints when connecting the example client.
