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

The host binds to the address from the `mtp_BIND` environment variable (defaults to `::`) on the specified port:

```rust
use mtp::host::{MTPHost, HostConfig};

let config = HostConfig {
    port: 4433,
    tls_fullchain: std::fs::read("cert.pem")?,
    tls_key: std::fs::read("key.pem")?,
};

let mut host = MTPHost::new(config).await?;
```

### Accepting Connections with Version Negotiation

```rust
while let Some(conn) = host.accept().await {
    // conn.version is the negotiated version
    // conn.codec is a VersionedCodec scoped to that version
    // conn.sender / conn.receiver for raw CommunicationValue I/O

    let msg = conn.receiver.receive().await?;
}
```

The host's `accept()` method:
1. Accepts a QUIC connection
2. If authentication is required (crypto feature): performs login/register handshake
3. Reads the first `CommunicationValue` (always encoded with reserved type IDs)
4. Extracts the client's protocol version from `DataType::Version` (wire ID 3)
5. Calls `registry.negotiate(&[client_version])`
6. Returns `None` if the version is unsupported
7. Returns an `MTPConnection` with the negotiated version otherwise

### Login/Register Handshake

When `require_authentication` is set, the parties run a mutually-authenticated
**challenge-response**. The client speaks first with an *unsigned* hello:

- **Login** (`CommunicationType::Identification`, ID 15): version, client ID
- **Register** (`CommunicationType::Register`, ID 17): version, public keys

The host then issues a fresh random `server_challenge` in a signed `Challenge`
(`CommunicationType::Challenge`, ID 21, carrying `ServerNonce`). The client signs
that challenge, binding its id (login) or public keys (register), and returns a
`ChallengeResponse` (ID 22). The host verifies the proof against the challenge it
issued and sends a signed final response, which the client verifies.

Because the client's proof covers the host-issued `server_challenge` (a one-time
value held only on the accepting task's stack), a captured proof cannot be
replayed on another connection. All signed payloads are domain-separated; see
`mtp::crypto::auth`.

---

## Client

The client connects to a host and uses a single compiled-in protocol version.

```rust
use mtp::client::{MTPClient, ClientConfig};

let config = ClientConfig {
    url: "https://host.example.com:4433".into(),
    server_cert: None, // or Some(cert_pem_bytes)
};

// Connect (unauthenticated, existing client)
let conn = MTPClient::connect(config, 8765).await?;

// Authenticated login
let conn = MTPClient::auth_connect(config, 8765, keys, host_pk).await?;

// Registration (new client)
let conn = MTPClient::auth_register(config, keys, host_pk).await?;
```

The client's `PROTOCOL_VERSION` constant is set by `protocol_version` in `type-maps.yaml` and baked in at compile time. The client never imports the `registry` crate; it only uses `mtp::type_map` for enum types and `mtp::codec` for encoding.

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
    |  Response              |
    |<-----------------------|  (uses v2.0 TypeMap for encoding)
    |    Status, Nonces,     |
    |    Signature           |
    |                        |
    |  (subsequent messages  |
    |   use v2.0 TypeMap)    |
```

If the client sends an unsupported version (e.g. v3.0 when the host only knows up to v2.0), `negotiate` returns `None` and the connection is closed.
