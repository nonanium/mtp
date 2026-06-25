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
```

## HostConfig

```rust
use mtp::host::HostConfig;
use std::net::{IpAddr, Ipv4Addr};

let config = HostConfig {
    ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    port: 4433,
    tls_fullchain: std::fs::read("cert.pem")?,
    tls_key: std::fs::read("key.pem")?,

    // Crypto fields (required when feature = "crypto"):
    require_authentication: true,
    host_id: 1,
    host_keyring: /* Keyring */,
    get_existing_user: Box::new(|client_id: u64| -> Option<PublicKeyBundle> {
        CLIENT_DB.lock().unwrap().get(&client_id).cloned()
    }),
    complete_register: Box::new(|bundle: PublicKeyBundle| -> u64 {
        let id = next_id();
        CLIENT_DB.lock().unwrap().insert(id, bundle);
        id
    }),
};
```

| Field                  | Type                                    | Description                                    |
|------------------------|-----------------------------------------|------------------------------------------------|
| `ip`                   | `IpAddr`                                | Bind address                                   |
| `port`                 | `u16`                                   | Listen port                                    |
| `tls_fullchain`        | `Vec<u8>`                               | PEM-encoded TLS certificate chain              |
| `tls_key`              | `Vec<u8>`                               | PEM-encoded TLS private key                    |
| `require_authentication` | `bool` (crypto)                      | Enable login/register handshake                |
| `host_id`              | `u64` (crypto)                          | Host identifier                                |
| `host_keyring`         | `Keyring` (crypto)                      | Host's signing and KEM keys                    |
| `get_existing_user`    | `Box<dyn Fn(u64) -> Option<PublicKeyBundle> + Send>` (crypto) | Lookup callback for login |
| `complete_register`    | `Box<dyn Fn(PublicKeyBundle) -> u64 + Send>` (crypto) | Registration callback, returns new client ID |

### TLS

The host requires a TLS certificate. For development, generate a self-signed
certificate using `rcgen`. For production, use a CA-signed certificate.

## Accepting Connections

```rust
use mtp::host::MTPHost;

let mut host = MTPHost::new(config).await?;
println!("Listening on {}", host.local_addr());

while let Some(conn) = host.accept().await {
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
- `client_id` -- the authenticated client's ID
- `client_public_key` -- the client's public key bundle (for signature
  verification of subsequent messages)

## Version Negotiation

When a client connects, `accept()` performs the following sequence:

1. Accept the QUIC connection
2. Read the client's first `CommunicationValue` (always encoded with reserved
   type IDs)
3. Extract the protocol version from `DataType::Version` (wire ID 3) as a
   `DataValue::Str("major.minor")`
4. Call `registry.negotiate(&[client_version])` to find the highest mutually
   supported version
5. Return `None` (closing the connection) if no compatible version exists
6. Return an `MTPConnection` with the negotiated version

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

## Authentication Flow (crypto feature)

When `require_authentication` is `true`, `accept()` runs an authenticated
handshake before returning the connection. The flow is:

### Login (existing client)

```
Client                                    Host
  |                                         |
  |  QUIC connect                           |
  |---------------------------------------->|
  |                                         |
  |  Identification {                       |
  |    Version, Id, ClientNonce,            |
  |    Signature, [PqSignature]             |
  |  }                                      |
  |---------------------------------------->|
  |                                         |  lookup get_existing_user(client_id)
  |                                         |  verify Ed25519 (and optional ML-DSA) sig
  |  IdentificationResponse {              |
  |    Connected=true, ClientNonce(echoed), |
  |    Id, Timestamp(new_nonce),            |
  |    Signature, [PqSignature]             |
  |  }                                      |
  |<----------------------------------------|
```

The client signature payload is: `version_string || client_id (8 bytes, big-endian) || client_nonce (16 bytes, big-endian)`

The host signs: `0x01 || assigned_id (8 bytes, big-endian) || client_nonce (16 bytes) || host_new_nonce (16 bytes)`

### Register (new client)

```
Client                                    Host
  |                                         |
  |  QUIC connect                           |
  |---------------------------------------->|
  |                                         |
  |  Register {                             |
  |    Version, ClientNonce,                |
  |    PublicKeys (serialized PublicKeyBundle),
  |    Signature, [PqSignature]             |
  |  }                                      |
  |---------------------------------------->|
  |                                         |  extract PublicKeyBundle from frame
  |                                         |  verify Ed25519 (and optional ML-DSA) sig
  |                                         |  call complete_register(bundle) -> new_id
  |  RegisterResponse {                    |
  |    Connected=true, ClientNonce(echoed), |
  |    Id, Timestamp(new_nonce),            |
  |    Signature, [PqSignature]             |
  |  }                                      |
  |<----------------------------------------|
```

The client signature payload is: `version_string || client_nonce (16 bytes) || public_key_bytes`

After a successful handshake, `accept()` returns an `MTPConnection` with
`auth_state = Authenticated`, `client_id` set, and `client_public_key`
available for verifying subsequent signed messages from the client.

### Rejection

If verification fails or the client is not found (login), the host sends a
rejection response with `Connected=false` and closes the send stream, returning
`None` from `accept()`.

## Handling Messages

Use `conn.sender` and `conn.receiver` for bidirectional message exchange:

```rust
while let Some(conn) = host.accept().await {
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

## Host Callbacks

### get_existing_user

Called during login to retrieve a client's public key bundle for signature
verification. Must return `Some(PublicKeyBundle)` if the client ID is known,
or `None` to reject.

```rust
let get_existing_user = Box::new(|id: u64| -> Option<PublicKeyBundle> {
    db.lock().unwrap().get(&id).cloned()
});
```

### complete_register

Called during registration to persist a new client's public key bundle and
assign a client ID. The returned `u64` becomes the client's permanent
identifier.

```rust
let complete_register = Box::new(|bundle: PublicKeyBundle| -> u64 {
    let mut db = db.lock().unwrap();
    let id = next_id;
    next_id += 1;
    db.insert(id, bundle);
    id
});
```

Both callbacks are called from within `accept()` and must be `Send`. They are
invoked synchronously, so avoid long-running operations (or use `spawn_blocking`
if needed, though the callbacks are `Fn`, not `AsyncFn`).

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


