# Connector

This file documents the Connection and Version Negotiation logic.

## Registry

The `registry` crate provides a multi-version `Registry` used by the host for version negotiation. Accessed through the `mtp` facade (requires the `host` feature):

```rust
use mtp::codec::registry::Registry;

let registry = Registry::builtin(); // loads all TypeMaps from config

// Check if a version is supported
assert!(registry.supports(&Version(1, 0)));

// Find highest mutual version for a client
let client_versions = &[Version(0, 0), Version(1, 0)];
let negotiated = registry.negotiate(client_versions);
assert_eq!(negotiated, Some(Version(1, 0)));

// Look up a version's TypeMap
let tm = registry.get(&Version(2, 0)).unwrap();
```

The `Registry::builtin()` constructor uses the `TypeMap::vX_Y()` methods generated from the config.

---

## Host

The host creates a QUIC server, manages the registry, and handles version negotiation with each connecting client.

### Initialization

```rust
use mtp::host::{MTPHost, HostConfig};

let config = HostConfig {
    ip: "::".into(),
    port: 4433,
    tls_fullchain: std::fs::read("cert.pem")?,
    tls_key: std::fs::read("key.pem")?,
};

let mut host = MTPHost::new(config).await?;
```

### Accepting Connections with Version Negotiation

```rust
while let Some(conn) = host.accept().await {
    /*
     *  conn.version is the negotiated version
     * conn.codec is a VersionedCodec scoped to that version
     * conn.sender / conn.receiver for raw CommunicationValue I/O
     */

    let msg = conn.receiver.receive().await?;
    // ...
}
```

The host's `accept()` method:
1. Accepts a QUIC connection
2. Reads the first `CommunicationValue` (always encoded with reserved type IDs)
3. Extracts the client's protocol version from `DataType::Version` (wire ID 3)
4. Calls `registry.negotiate(&[client_version])`
5. Returns `None` if the version is unsupported (caller sends `ErrorBadVersion` and disconnects)
6. Returns an `MTPConnection` with the negotiated version otherwise

### Login/Register Flow

The complete login/register handshake (see design docs) builds on top of `MTPConnection`:

1. Client sends `Identification` with version, ID, nonce, signature
2. Host verifies signature via `get_key` callback
3. Host responds with approval + nonces + signature
4. Client verifies response

New clients use the `Register` variant instead, presenting their public key for registration.

---

## Client

The client connects to a host and uses a single compiled-in protocol version.

```rust
use mtp::client::{MTPClient, ClientConfig};

let config = ClientConfig {
    url: "https://host.example.com:4433".into(),
    server_cert: None, // or Some(cert_pem_bytes)
};

// Connect (existing client)
let conn = MTPClient::connect(config, 8765).await?;

/*
 *  conn.version is the compiled-in PROTOCOL_VERSION
 *  conn.sender / conn.receiver for I/O
 */
```

The client's `PROTOCOL_VERSION` constant is set by `protocol_version` in `type-maps.yaml` and baked in at compile time. The client never imports the `registry` crate; it only uses `mtp::type_map` for enum types and `mtp::codec` for encoding.

---

## Version Negotiation Flow

```
Client (v2.0)         Host (v0.0, v1.0, v2.0)
    │                        │
    │  QUIC connect          │
    │───────────────────────→│
    │                        │
    │  CommValue{ Ident. }   │
    │    Version → "2.0"     │
    │    Id → 8765           │
    │    Nonce → ...         │
    │    Signature → ...     │
    │───────────────────────→│
    │                        │  registry.negotiate(&[Version(2,0)])
    │                        │  → Some(Version(2,0))
    │                        │
    │  Response              │
    │←───────────────────────│  (uses v2.0 TypeMap for encoding)
    │    Status, Nonces,     │
    │    Signature           │
    │                        │
    │  (subsequent messages  │
    │   use v2.0 TypeMap)    │
```

If the client sends an unsupported version (e.g. v3.0 when the host only knows up to v2.0), `negotiate` returns `None` and the host sends `ErrorBadVersion` using reserved types.
