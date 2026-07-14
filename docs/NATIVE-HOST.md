# MTP Native Host

The native host is a Rust library (`mtp-host`) that runs a QUIC server, accepts
MTP client connections, negotiates protocol versions, and optionally performs a
mutual-authentication handshake (login/register) using Ed25519 and ML-DSA-65
signatures.

## Cargo Dependency

```toml
[dependencies]
mtp = { path = "/path/to/mtp", features = ["host"] }

# Add crypto for authenticated connections:
mtp = { path = "/path/to/mtp", features = ["host", "crypto"] }

# Add pipes for raw binary streams:
mtp = { path = "/path/to/mtp", features = ["host", "pipes"] }
```

## HostConfig

```rust
use mtp::host::HostConfig;
use std::net::{IpAddr, Ipv4Addr};

let config = HostConfig::new(
    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    4433,
    std::fs::read("cert.pem")?,
    std::fs::read("key.pem")?,
)
.with_authentication(
    /* Keyring */,
    |client_id: u64| {
        let db = CLIENT_DB.clone();
        Box::pin(async move { db.lock().unwrap().get(&client_id).cloned() })
    },
    |bundle: PublicKeyBundle| {
        let mut db = CLIENT_DB.lock().unwrap();
        let id = next_id();
        db.insert(id, bundle);
        Box::pin(async move { id })
    },
);
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
| `get_existing_user`    | `Fn(u64) -> Pin<Box<dyn Future<Output = Option<PublicKeyBundle>> + Send>> + Send + Sync` (crypto) | Async lookup callback for login |
| `complete_register`    | `Fn(PublicKeyBundle) -> Pin<Box<dyn Future<Output = u64> + Send>> + Send + Sync` (crypto) | Async registration callback, returns new client ID |

### AuthenticationPolicy

`ForceAuthentication` requires every client to complete the login/register handshake. `AllowAuthentication` accepts both authenticated and unauthenticated connections — unauthenticated clients get a random ID and `AuthState::Unauthenticated`. `Unauthenticated` rejects any client that tries to authenticate and is the default.

```rust
use mtp::host::AuthenticationPolicy;

// Force authentication (default was `require_authentication: true`):
let config = HostConfig::new(ip, port, cert, key)
    .with_authentication(host_keyring, get_user, register);

// Allow both authenticated and unauthenticated:
let config = HostConfig::new(ip, port, cert, key)
    .with_allow_authentication(host_keyring, get_user, register);

// Unauthenticated only (default):
let config = HostConfig::new(ip, port, cert, key);
```

### TLS

The host requires a TLS certificate. For development, generate a self-signed
certificate using `rcgen`. For production, use a CA-signed certificate.

### Ping-Pong

The host handles protocol Ping/Pong automatically unless you disable it with
`with_pongs(false)`. Enable the default responder explicitly when constructing
the host if you want to make the choice visible in application configuration:

```rust
let config = HostConfig::new(ip, port, cert, key)
    .with_pongs(true);
```

For every received Ping, the responder sends a Pong with the same frame id and
copies the optional `Timestamp` data entry. Ping and Pong frames handled this
way are not delivered by `conn.receiver.receive()`. This lets native clients
use `ClientConfig::with_ping_interval` and `MTPConnection::get_ping()` without
adding application-level handlers.

Disable it only when the application needs to handle Ping frames itself:

```rust
let config = HostConfig::new(ip, port, cert, key)
    .with_pongs(false);
```

With automatic responses disabled, Ping frames are delivered through the normal
receiver and the application is responsible for sending a compatible Pong (the
same frame id, and normally the Ping's `Timestamp`) if it wants clients to
continue their protocol ping loop.

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

Returned by `accept()` after version negotiation (and authentication if
enabled):

```rust
pub struct MTPConnection {
    pub version: Version,
    pub codec: VersionedCodec,
    pub sender: Sender,
    pub receiver: Receiver,
    pub description: Option<String>,
    #[cfg(feature = "crypto")]
    pub auth_state: AuthState,
    #[cfg(feature = "crypto")]
    pub client_id: u64,
    #[cfg(feature = "crypto")]
    pub client_public_key: Option<PublicKeyBundle>,
}
```

- `version` -- the negotiated protocol version
- `codec` -- a `VersionedCodec` scoped to the negotiated version (use for
  version-aware encode/decode)
- `sender` / `receiver` -- for message I/O
- `description` -- optional client-provided label (e.g. `"phone"`, `"desktop"`)
- `client_id` -- the authenticated client's ID
- `client_public_key` -- the client's public key bundle (for signature
  verification of subsequent messages)

## Version Negotiation

When a client connects, `accept()` performs the following sequence:

1. Accept the QUIC connection
2. Read the client's first `CommunicationValue` (always encoded with reserved
   type IDs)
3. Extract the protocol version from `DataType::Version` (reserved data type ID 0) as a
   `DataValue::Str("major.minor")`
4. Call `registry.negotiate(&[client_version])` to find the highest mutually
   supported version
5. Return an `AcceptError` (closing the connection) if no compatible version exists
6. Return `Ok(Some(MTPConnection))` with the negotiated version

The `Registry` is built automatically from all type maps defined in your
`type-maps.yaml` via `Registry::builtin()`.

### Registry

```rust
use mtp::codec::registry::Registry;

let registry = host.registry();
assert!(registry.supports(&Version(2, 0)));

let negotiated = registry.negotiate(&[Version(1, 0), Version(2, 0)]);
// -> Some(Version(2, 0)) if both versions are registered
```

## Authentication Flow

When `authentication_policy` is `ForceAuthentication`, `accept()` runs a mutually-authenticated
**challenge-response** handshake before returning the connection. The host issues
a fresh, random `server_challenge` that the client must sign, which is what makes
the client's proof unreplayable: a captured proof is bound to a one-time challenge
the host generates per connection and will never reissue. The challenge lives only
on the accepting task's stack; there is no replay database or shared state.

All signed payloads begin with a one-byte domain-separation tag (see
`mtp::crypto::auth`) so a signature for one step can never be reused as another.

### Login

```
Client                                    Host
  |                                         |
  |  QUIC connect                           |
  |---------------------------------------->|
  |                                         |
  |  Identification { Version, Id }         |  (unsigned hello)
  |---------------------------------------->|
  |                                         |  lookup get_existing_user(id)
  |                                         |  generate random server_challenge
  |  Challenge {                            |
  |    ServerNonce(server_challenge),       |
  |    Signature, [PqSignature]             |  host signs the challenge
  |  }                                      |
  |<----------------------------------------|
  |  ChallengeResponse {                    |
  |    ClientNonce, Signature, [PqSignature]|  client signs the challenge
  |  }                                      |
  |---------------------------------------->|
  |                                         |  verify proof over server_challenge
  |  IdentificationResponse {              |
  |    Connected=true, Id,                  |
  |    ClientNonce(echoed),                 |
  |    Signature, [PqSignature]             |
  |  }                                      |
  |<----------------------------------------|
```

Payloads (`||` is concatenation, integers big-endian; `DS_*` are domain tags):

- Host challenge: `DS_CHALLENGE || id (8) || server_challenge (16)`
- Client proof:   `DS_LOGIN_PROOF || version_string || id (8) || server_challenge (16) || client_nonce (16)`
- Host final:     `DS_HOST_FINAL || assigned_id (8) || client_nonce (16) || server_challenge (16)`

### Register

```
Client                                    Host
  |                                         |
  |  QUIC connect                           |
  |---------------------------------------->|
  |                                         |
  |  Register {                             |
  |    Version,                             |  (unsigned hello)
  |    PublicKeys (serialized PublicKeyBundle)
  |  }                                      |
  |---------------------------------------->|
  |                                         |  generate random server_challenge
  |  Challenge {                            |
  |    ServerNonce(server_challenge),       |
  |    Signature, [PqSignature]             |  (challenge binds id = 0)
  |  }                                      |
  |<----------------------------------------|
  |  ChallengeResponse {                    |
  |    ClientNonce, Signature, [PqSignature]|
  |  }                                      |
  |---------------------------------------->|
  |                                         |  verify proof over server_challenge
  |                                         |  call complete_register(bundle) -> new_id
  |  RegisterResponse {                    |
  |    Connected=true, Id(new_id),          |
  |    ClientNonce(echoed),                 |
  |    Signature, [PqSignature]             |
  |  }                                      |
  |<----------------------------------------|
```

The register client proof is:
`DS_REGISTER_PROOF || version_string || server_challenge (16) || client_nonce (16) || public_key_bytes`

After a successful handshake, `accept()` returns an `MTPConnection` with
`auth_state = Authenticated`, `client_id` set, and `client_public_key`
available for verifying subsequent signed messages from the client.

### Rejection

If verification fails or the client is not found (login), the host sends a
rejection response with `Connected=false` and closes the send stream, returning
`AcceptError::AuthenticationFailed` from `accept()`.

## Handling Messages

Use `conn.sender` and `conn.receiver` for bidirectional message exchange:

```rust
while let Some(conn) = host.accept().await? {
    tokio::spawn(async move {
        loop {
            match conn.receiver.receive().await {
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

The `conn.codec` is a `VersionedCodec` pre-configured with the negotiated
version. Use it to encode/decode with version-specific type maps:

```rust
let tm = conn.codec.registry().get(&conn.version).unwrap();

// Look up type IDs for the negotiated version
let desc_id = DataTypeId(tm.data_id_enum(DataType::Description).unwrap());
let value = msg.get_data(desc_id);
```

## Pipes

With the `pipes` feature enabled, the host can accept **raw binary streams**
from clients. A Pipe is a unidirectional QUIC stream opened by the client that
carries a lightweight `PipeRequest` handshake frame, then transitions to raw
bytes with zero per-frame overhead.

### Enabling Pipes

Add the `pipes` feature to your dependency:

```toml
[dependencies]
mtp = { path = "/path/to/mtp", features = ["host", "pipes"] }
```

### Receiving Pipe Requests

When `pipes` is enabled, **do not call `conn.receiver.receive()` directly**.
Instead, use `conn.receive()` for normal messages and `conn.receive_pipe()`
for incoming pipe requests. A background dispatcher task routes events
internally so the two channels do not race.

```rust
use mtp::host::{MTPHost, PipeRequest};
use tokio::io::AsyncReadExt;

while let Some(conn) = host.accept().await? {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                Ok(msg) = conn.receive() => {
                    // handle normal CommunicationValue
                }
                Ok(req) = conn.receive_pipe() => {
                    handle_pipe(req).await;
                }
                else => break,
            }
        }
    });
}

async fn handle_pipe(req: PipeRequest) {
    println!("Pipe {} requested: {}", req.id(), req.description());
    // Accept or deny...
}
```

### PipeRequest

```rust
pub struct PipeRequest {
    // pipe_id assigned by the creator
    // description provided by the creator
}
```

| Method | Returns | Description |
|--------|---------|-------------|
| `id()` | `u32` | The pipe ID chosen by the creator |
| `description()` | `&str` | Creator-provided label (e.g. `"file-transfer"`) |
| `accept()` | `Result<PipeReader, PipeError>` | Accept the pipe; returns an `AsyncRead` stream |
| `deny()` | `Result<(), PipeError>` | Reject the pipe |

### Accepting a Pipe

```rust
use tokio::io::AsyncReadExt;

async fn handle_pipe(req: PipeRequest) {
    match req.accept().await {
        Ok(mut reader) => {
            let mut buf = Vec::new();
            if let Err(e) = reader.read_to_end(&mut buf).await {
                eprintln!("pipe read error: {e}");
            }
            println!("received {} bytes", buf.len());
        }
        Err(e) => {
            eprintln!("pipe accept failed: {e}");
        }
    }
}
```

`PipeReader` implements `tokio::io::AsyncRead`. The stream reads until the
creator calls `PipeWriter::finish()` or the connection closes.

### Rejecting a Pipe

```rust
async fn handle_pipe(req: PipeRequest) {
    if !should_allow(&req) {
        req.deny().await.ok();
        return;
    }
    // ... accept
}
```

### PipeError

```rust
pub enum PipeError {
    Rejected,          // pipe request was rejected
    HandshakeTimeout,  // pipe handshake timed out
    StreamClosed,      // pipe stream closed unexpectedly
    IoError(String),   // pipe I/O error
    ConnectionClosed,  // connection closed
}
```

`PipeError` implements `std::error::Error` and can be converted from
`CommunicationError` via `PipeError::from()`.

### Important: Do Not Use `receiver.receive()` with Pipes

When the `pipes` feature is active, `conn.receiver.receive()` will **skip**
`PipeRequest` frames and may return them as ordinary messages if called from
the wrong task. Always use the facade methods:

- `conn.receive()` -- normal `CommunicationValue` messages
- `conn.receive_pipe()` -- incoming `PipeRequest` objects

These methods are internally synchronised and safe to call from separate tasks.

## Host Callbacks

### get_existing_user

Called during login to retrieve a client's public key bundle for signature
verification. Must return `Some(PublicKeyBundle)` if the client ID is known,
or `None` to reject.

```rust
let get_existing_user = |id: u64| {
    let db = db.clone();
    Box::pin(async move { db.lock().unwrap().get(&id).cloned() })
};
```

### complete_register

Called during registration to persist a new client's public key bundle and
assign a client ID. The returned `u64` becomes the client's permanent
identifier.

```rust
let complete_register = |bundle: PublicKeyBundle| {
    let db = db.clone();
    let id = next_id.fetch_add(1, Ordering::SeqCst);
    Box::pin(async move {
        db.lock().unwrap().insert(id, bundle);
        id
    })
};
```

Both callbacks are called from within `accept()` and must be `Send + Sync`. They
are `async` (returning `Pin<Box<dyn Future<...>>`) and are `.await`ed by the
host, so they can perform I/O or other async work as needed.

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
let bytes = host_keyring.to_bytes();
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

The transport `Policy` is set to defaults internally. To customise (timeouts,
send mode, etc.), use `mtp_transport::host()` directly instead of `MTPHost`:

```rust
use mtp_transport::{host, Policy};

let transport = host(ip, port, cert, key, custom_policy).await?;
// Then build version negotiation on top:
// - accept transport.next()
// - read first frame
// - registry.negotiate()
// - return MTPConnection
```

## Graceful Shutdown

Drop the `MTPHost` to stop accepting new connections. Active connections
continue until their `Sender`/`Receiver` are dropped or the peer disconnects.
