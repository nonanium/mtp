# Connector

This file documents the connection and version negotiation logic.

## Registry

The `registry` module provides a multi-version `Registry` used by the host for version negotiation. Accessed through the `mtp` facade (requires the `host` feature):

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

The host binds to the address and port supplied in `HostConfig`:

```rust
use mtp::host::{HostConfig, MTPHost};

let config = HostConfig::new(
    "0.0.0.0".parse()?,
    4433,
    std::fs::read("cert.pem")?,
    std::fs::read("key.pem")?,
);

let mut host = MTPHost::new(config).await?;
```

### Accepting Connections with Version Negotiation

```rust
while let Some(conn) = host.accept().await? {
    // conn.version is the negotiated version
    // conn.codec is a VersionedCodec scoped to that version
    // conn.sender / conn.receiver for raw CommunicationValue I/O

    let msg = conn.receiver.receive().await?;
}
```

The host reads the reserved opening frame, extracts `DataType::Version`, calls `registry.negotiate`, and returns `AcceptError::UnsupportedVersion` when no registered version matches.

Authentication follows the version-bearing hello when the host enables it.
The sequence is defined in [Protocol Reference](PROTOCOL-REFERENCE.md).

---

## Client

The client connects to a host and uses a single compiled-in protocol version.

```rust
use mtp::client::{ClientConfig, MTPClient};

let config = ClientConfig::new("https://host.example.com:4433");
let pinned = config.clone().with_pinned_pem(cert_pem_bytes);

// Connect (unauthenticated, existing client)
let conn = MTPClient::connect(config.clone().with_client_id(8765)).await?;

// Authenticated login
let conn = MTPClient::auth_connect(pinned.with_client_id(8765), &keys, &host_pk).await?;

// Registration (new client)
let conn = MTPClient::auth_register(config, &keys, &host_pk).await?;
```

The client's `PROTOCOL_VERSION` constant is set by `protocol_version` in `type-maps.yaml` and baked in at compile time. The client uses one version and does not import the registry.

---

## Version Negotiation Flow

```
Client (v2.0)         Host (v0.0, v1.0, v2.0)
    |                        |
    |  QUIC connect          |
    |----------------------->|
    |                        |
    |  CommValue{ Ident. }   |
    |    Version -> "2.0"    |
    |    Id -> 8765          |
    |  (unsigned hello; auth |
    |   challenge follows)   |
    |----------------------->|
    |                        |  registry.negotiate(&[Version(2,0)])
    |                        |  -> Some(Version(2,0))
    |                        |
    |  Response              |  selected v2.0 TypeMap
    |<-----------------------|
    |  Status, version       |
    |                        |
    |  subsequent messages   |
    |  use v2.0 TypeMap      |
```

If the client sends an unsupported version (e.g. v3.0 when the host only knows up to v2.0), `negotiate` returns `None` and the connection is closed.

## Protocol Ping and Pong

See [Protocol Reference](PROTOCOL-REFERENCE.md#protocol-keepalive).

## Protocol Version Changes

Add a protocol version by adding its type-map entry and `protocol_version` to the YAML configuration, then rebuild both peers. The type-map build script generates a version-specific `TypeMap` and keeps the enum as the union of all configured type names.

For a backward-compatible change, keep existing communication and data IDs stable and add new types with the new version. For a breaking change, add a new version and register both versions on the host while clients migrate. A client compiles one protocol version; it can connect only when that version is present in the host registry. Remove an old version only after its clients no longer connect, because the host closes connections whose version is unsupported.
