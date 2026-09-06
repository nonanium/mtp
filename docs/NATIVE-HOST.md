# MTP Native Host

The native host is a Rust library (`mtp-host`) that runs a QUIC server, accepts MTP client connections, negotiates protocol versions, and optionally performs a mutual-authentication handshake (login/register) using Ed25519 and ML-DSA-65 signatures.

> **Note:** `MTPHost` serves native MTP clients over raw QUIC. For browser-facing HTTP/1.1, HTTP/2, HTTP/3, and WebTransport, use [`MTPWebServer`](NATIVE-HOST-WEB-SERVER.md). It accepts the same `HostConfig` but its UDP endpoint uses HTTP/3 rather than the native MTP QUIC ALPN.

## Cargo Dependency

Add the `mtp` umbrella crate with `host`. Add `crypto` for authenticated connections and `pipes` for raw streams. The feature table is in the [README](../README.md).

## HostConfig

`HostConfig::new` takes the bind address, port, PEM certificate chain, and PEM private key. Configure authentication and transport behavior with builders:

```rust
let config = HostConfig::new(ip, port, certificate, private_key)
    .with_pongs(true)
    .with_policy(Policy::default())
    .with_authentication(host_keyring, get_existing_client, complete_register)
    .with_authentication_policy(AuthenticationPolicy::ForceAuthentication);
```

| Field                  | Type                                    | Description                                    |
|------------------------|-----------------------------------------|------------------------------------------------|
| `ip`                   | `IpAddr`                                | Bind address                                   |
| `port`                 | `u16`                                   | Listen port                                    |
| `tls_fullchain`        | `Vec<u8>`                               | PEM-encoded TLS certificate chain              |
| `tls_key`              | `Vec<u8>`                               | PEM-encoded TLS private key                    |
| `send_pongs`           | `bool`                                  | Sends a Pong for each received Ping (default `true`) |
| `authentication_policy` | `AuthenticationPolicy` (crypto)       | `ForceAuthentication`, `AllowAuthentication`, or `Unauthenticated` |
| `host_keyring`         | `Keyring` (crypto)                      | Host's signing and KEM keys                    |
| `get_existing_client`  | Async callback returning `Option<PublicKeyBundle>` | Receives `(client_id, description)`. `Some` supplies the stored key bundle. `description = None` is used for guest-ID collision checks. |
| `guest_id_generator`   | Async callback returning `Option<u64>` | Custom guest ID assignment. The default generates random IDs. |
| `complete_register`    | Async callback returning `u64` | Stores the public bundle and returns its assigned client ID. |

### AuthenticationPolicy

`ForceAuthentication` requires every client to complete the login or registration handshake. `AllowAuthentication` accepts both authenticated and unauthenticated connections; unauthenticated clients receive an ID and `AuthState::Unauthenticated`. `Unauthenticated` rejects authentication attempts and is the default.
Authentication policy details are in [Security](SECURITY.md).

### TLS

`HostConfig::new` always uses the certificate and key supplied by the caller.
Certificate trust and development settings are in [Security](SECURITY.md).

### Ping-Pong

Keepalive behavior is defined in [Protocol Reference](PROTOCOL-REFERENCE.md#protocol-keepalive).

```rust
let config = HostConfig::new(ip, port, cert, key)
    .with_pongs(true);
```

Disable automatic responses only when the application needs to handle Ping frames itself:

```rust
let config = HostConfig::new(ip, port, cert, key)
    .with_pongs(false);
```

Follow the responder contract in [Protocol Reference](PROTOCOL-REFERENCE.md).

## Accepting Connections

```rust
use mtp::host::MTPHost;

let mut host = MTPHost::new(config).await?;
println!("Listening on {}", host.local_addr());

while let Some(conn) = host.accept().await? {
    // conn is an MTPConnection ready for I/O
}
```

### MTPConnection

`accept()` returns the shared connection shape in [MTP Connections](CONNECTIONS.md)
after version negotiation and authentication, when enabled. The host-specific `codec` is scoped to the negotiated version, and `client_public_key` is set for authenticated clients.
The connection's `remote_addr` is the peer `SocketAddr` observed by QUIC. It is
network metadata, not an authenticated client identity.

## Version Negotiation

`accept()` uses the version-bearing opening frame and registry flow in [Connector](CONNECTOR.md). The host registry is built from the type maps in [`tests/fixtures/example/type-maps.yaml`](../tests/fixtures/example/type-maps.yaml) by `Registry::builtin()` in this repository; downstream builds can provide their own `MTP_TYPE_MAPS` configuration.

### Registry

```rust
use mtp::codec::Version;

let registry = host.registry();
assert!(registry.supports(&Version(3, 0)));

let negotiated = registry.negotiate(&[Version(2, 0), Version(3, 0)]);
// -> Some(Version(3, 0)) for this repository's builtin map
```

## Authentication Flow

The connection lifecycle and authentication sequence are in [Protocol Reference](PROTOCOL-REFERENCE.md). Host callback contracts are documented below.

After a successful handshake, `MTPConnection` exposes `AuthState::Authenticated`, the client ID, and the client's public key bundle when one is available.

## Handling Messages

Use `conn.sender` and `conn.receive()` for bidirectional message exchange. The
connection dispatcher owns the underlying receiver, especially when `pipes` is
enabled:

```rust
while let Some(conn) = host.accept().await? {
    tokio::spawn(async move {
        loop {
            match conn.receive().await {
                Ok(msg) => {
                    let response = process_message(&msg, &conn);
                    conn.sender.send(&response).await.ok();
                }
                Err(_) => break,
            }
        }
    });
}
```

### Versioned Codec

The `conn.codec` is a `VersionedCodec` pre-configured with the negotiated version. Use it to encode/decode with version-specific type maps:

```rust
let tm = conn.codec.registry().get(&conn.version).unwrap();

// Look up type IDs for the negotiated version
let desc_id = DataTypeId(tm.data_id_enum(DataType::Description).unwrap());
let value = msg.get_data(desc_id);
```

## Pipes

The complete pipe protocol and host API are documented in [Pipes](PIPES.md).

## Host Callbacks

### get_existing_client

Called during login to retrieve a client's public key bundle for signature verification, and also during guest ID generation to check whether a random candidate collides with a registered client.  When used for collision checking the `description` argument is `None`.

Must return `Some(PublicKeyBundle)` if the client ID is known, or `None` otherwise.

```rust
// db: Arc<tokio::sync::Mutex<HashMap<u64, PublicKeyBundle>>>
let get_existing_client = |id: u64, _description: Option<String>| {
    let db = db.clone();
    Box::pin(async move { db.lock().await.get(&id).cloned() })
};
```

### guest_id_generator

Optional callback that controls how unauthenticated connections receive their client ID. When `None` (the default), the host generates a random full-width `u64` ID and checks it against `get_existing_client` to avoid collisions.

Return `Some(id)` to accept the guest with that full-width `u64` ID, or `None` to reject the connection.

```rust
use std::sync::atomic::{AtomicU64, Ordering};

// Sequential guest IDs:
let counter = AtomicU64::new(1);
let guest_id_generator = Box::new(move || {
    Box::pin(async move { Some(counter.fetch_add(1, Ordering::SeqCst)) })
});

// Reject all guests (no unauthenticated connections):
let guest_id_generator = Box::new(|| Box::pin(async { None }));

let config = HostConfig::new(ip, port, cert, key)
    .with_authentication(host_keyring, get_existing_client, complete_register)
    .with_authentication_policy(AuthenticationPolicy::AllowAuthentication)
    .with_guest_id_generator(guest_id_generator);
```

### complete_register

Called during registration to persist a new client's public key bundle and assign a client ID. The returned `u64` becomes the client's permanent identifier.

```rust
// db: Arc<tokio::sync::Mutex<HashMap<u64, PublicKeyBundle>>>
let complete_register = |bundle: PublicKeyBundle, _description: Option<String>| {
    let db = db.clone();
    let id = next_id.fetch_add(1, Ordering::SeqCst);
    Box::pin(async move {
        db.lock().await.insert(id, bundle);
        id
    })
};
```

All callbacks are called from within `accept()` and must be `Send + Sync`. They are `async` (returning `Pin<Box<dyn Future<...>>`) and are `.await`ed by the host, so they can perform I/O or other async work as needed. The `complete_register` callback returns no error value. A panic aborts the normal callback flow; validate storage and ID allocation before returning the ID.

## Host Key Generation

Generate a host keyring once and persist it:

```rust
use mtp::crypto::{Ed25519Signer, Keyring, MlDsaSigner};
use mtp::crypto::kem::HybridKem;

let (_ed_signer, sig_sk, sig_pk) = Ed25519Signer::generate();
let (_pq_signer, sig_pq_sk, sig_pq_pk) = MlDsaSigner::generate();
let (kem_sk, kem_pk) = HybridKem::generate_keypair();

let host_keyring = Keyring::new(kem_pk, kem_sk, sig_pq_pk, sig_pq_sk, sig_pk, sig_sk);

// Save to disk
let bytes = host_keyring.try_to_bytes()?;
std::fs::write("host_keys.bin", bytes)?;
```

Export the public key bundle so clients can verify the host identity:

```rust
let bundle = host_keyring.public_key_bundle();
std::fs::write("host_enc_kem_pk.bin", bundle.kem_public_key.as_bytes())?;
std::fs::write("host_sig_pk.bin", bundle.sig_cl_public_key.as_bytes())?;
std::fs::write("host_sig_pq_pk.bin", bundle.sig_pq_public_key.as_bytes())?;
```

## Policy

Customize transport limits and timeouts through `HostConfig::with_policy`:

```rust
let config = HostConfig::new(ip, port, cert, key)
    .with_policy(custom_policy);
let host = MTPHost::new(config).await?;
```

## Graceful Shutdown

Drop the `MTPHost` to stop accepting new connections. Active connections continue until their `Sender`/`Receiver` are dropped or the peer disconnects.

Run one accept loop per `MTPHost` and spawn one task per accepted connection.
Stop the accept loop before dropping the host, then close active senders and wait for application tasks to finish. Use [Operations](OPERATIONS.md) for the deployment sequence and monitoring signals.
