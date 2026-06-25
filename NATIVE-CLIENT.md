# MTP Native Client

The native client is a Rust library (`mtp-client`) for connecting to an MTP host over QUIC. It uses `wtransport` under the hood and provides both unauthenticated and authenticated (crypto handshake) connection modes.

## Cargo Dependency

Add the `mtp` umbrella crate with the `client` feature (and optionally `crypto` for authentication):

```toml
[dependencies]
mtp = { path = "/path/to/mtp", features = ["client"] }

# Add crypto for auth_connect / auth_register:
mtp = { path = "/path/to/mtp", features = ["client", "crypto"] }
```

## ClientConfig

```rust
use mtp::client::ClientConfig;

let config = ClientConfig {
    url: "https://host.example.com:4433".into(),
    server_cert: None,   // None = use system root certificates
    client_id: 0,                              // previously assigned ID or 0
};
```

| Field        | Type               | Description                                         |
|--------------|--------------------|-----------------------------------------------------|
| `url`        | `String`           | `https://host:port` address of the MTP host         |
| `server_cert`| `Option<Vec<u8>>`  | `None` to use system roots, `Some(pem_bytes)` to pin |
| `client_id`  | `u64`              | Client identifier (ignored during `auth_register`)  |

### TLS Certificate Handling

When `server_cert` is `None` (the default), the client loads the **system's
native root certificate store** via `rustls_native_certs`. This works with
publicly-trusted CAs out of the box on Linux (using `openssl-probe`), macOS
(Keychain), and Windows (Root Store).

For development or self-signed certificates, provide one or more PEM-encoded
certificates:

```rust
let pem = std::fs::read("my-server-cert.pem")?;
let config = ClientConfig {
    server_cert: Some(pem),
    // ...
};
```

When pinned, **only** the given certificate(s) are trusted for the TLS
handshake.

## Connection Methods

All methods return a `Result<MTPConnection, CommunicationError>`.

### MTPConnection

```rust
pub struct MTPConnection {
    pub version: Version,
    pub sender: Sender,
    pub receiver: Receiver,
    #[cfg(feature = "crypto")]
    pub auth_state: AuthState,
    #[cfg(feature = "crypto")]
    pub client_id: u64,
}
```

- `version` -- the negotiated protocol version
- `sender` / `receiver` -- for message I/O
- `client_id` -- the confirmed/assigned client identifier (crypto only)

### Unauthenticated Connect

```rust
use mtp::client::{MTPClient, ClientConfig};

let config = ClientConfig {
    url: "https://host.example.com:4433".into(),
    server_cert: None,
    client_id: 42,
};

let conn = MTPClient::connect(config).await?;
```

Sends an `Identification` frame with the compiled-in protocol version and
client ID. No cryptographic handshake is performed.

### Authenticated Login

```rust
use mtp::client::MTPClient;
use mtp::crypto::{Keyring, PublicKeyBundle};

let keys = Keyring::from_bytes(&saved_keyring_bytes)?;
let host_pk = PublicKeyBundle::from_bytes(&saved_host_pk_bytes)?;

let config = ClientConfig {
    client_id: 42,           // must match the keyring's identity
    // ...
};

let conn = MTPClient::auth_connect(config, &keys, &host_pk).await?;
```

Protocol:
1. Client generates a random nonce
2. Builds a signature payload: `version || client_id || client_nonce`
3. Signs with Ed25519 (and optionally ML-DSA-65)
4. Sends `Identification` frame containing version, client ID, nonce, signature(s)
5. Host responds with `IdentificationResponse` containing echoed nonce, host
   nonce, and host signature
6. Client verifies the host signature and nonce echo

### Registration

```rust
let (ed_signer, sig_sk, sig_pk) = mtp::crypto::Ed25519Signer::generate();
let (pq_signer, sig_pq_sk, sig_pq_pk) = mtp::crypto::MlDsaSigner::generate();
let (kem_sk, kem_pk) = mtp::crypto::HybridKem::generate_keypair();

let keyring = Keyring::new(kem_pk, kem_sk, sig_pq_pk, sig_pq_sk, sig_pk, sig_sk);

let conn = MTPClient::auth_register(config, &keyring, &host_pk).await?;

// Save for next session
let id = conn.client_id;
let keyring_bytes = keyring.to_bytes();
```

Protocol:
1. Client generates a random nonce
2. Builds a signature payload: `version || client_nonce || public_key_bytes`
3. Signs with Ed25519 (and optionally ML-DSA-65)
4. Sends `Register` frame containing version, nonce, public key bundle, signature(s)
5. Host assigns a new client ID, responds with `RegisterResponse` containing
   the ID, echoed nonce, host nonce, and host signature
6. Client verifies the host signature and nonce echo

## Key Material

### Keyring

A `Keyring` bundles all secret and public key material for one identity:

```rust
pub struct Keyring {
    pub kem_secret_key: KemPrivateKey,
    pub kem_public_key: KemPublicKey,
    pub sig_cl_secret_key: SignaturePrivateKey,   // Ed25519
    pub sig_cl_public_key: SignaturePublicKey,    // Ed25519
    pub sig_pq_secret_key: SignaturePqPrivateKey, // ML-DSA-65
    pub sig_pq_public_key: SignaturePqPublicKey,  // ML-DSA-65
}
```

- Serialise: `keyring.to_bytes()` -> `Vec<u8>`
- Deserialise: `Keyring::from_bytes(&bytes)` -> `Result<Keyring, CryptoError>`
- Get public half: `keyring.public_key_bundle()` -> `PublicKeyBundle`

### PublicKeyBundle

The public half of a keyring, used by the host for signature verification and
by the client for host signature verification:

```rust
pub struct PublicKeyBundle {
    pub kem_public_key: KemPublicKey,
    pub sig_cl_public_key: SignaturePublicKey,
    pub sig_pq_public_key: SignaturePqPublicKey,
}
```

Obtain the host's `PublicKeyBundle` out of band (e.g. from files exported by
the host, or from a trusted directory).

## Sending and Receiving Messages

### CommunicationValue

Messages are `CommunicationValue` frames. Construct them with the builder API:

```rust
use mtp::codec::{CommunicationValue, CommunicationType, DataType, DataValue};
use mtp::type_map::TypeMap;

let msg = CommunicationValue::new(CommunicationType::Ping)
    .with_sender(conn.client_id)
    .add_typed_default(DataType::Description, DataValue::Str("hello".into()))
    .add_typed_default(DataType::Timestamp, DataValue::UnsignedNumber(now))
    .to_bytes();
```

When the `registry` feature is enabled (via the `host` feature), you can also
use `add_typed` with a `TypeMap` to resolve data type names from your project's
type-map configuration.

### Send

```rust
conn.sender.send(&msg).await?;
```

Two send modes (configured via `mtp::transport::Policy`):
- `PersistentStream` (default) -- reuses one QUIC uni-directional stream
- `SingleStreamPerMessage` -- opens a new stream per message

### Receive

```rust
match conn.receiver.receive().await {
    Ok(msg) => { /* handle CommunicationValue */ }
    Err(e) => { /* connection closed or error */ }
}
```

Inbound frames are queued internally. The `receive()` method returns the next
available message.

### Close

```rust
conn.sender.close();
// or
conn.receiver.close();
```

Sends a close frame and signals the peer. The `Sender::close()` spawns an async
task that sends the frame, waits for `force_close_delay` (default 300ms), then
force-closes the QUIC connection if the peer has not already done so.

## Crypto Containers

With the `crypto` feature, `DataValue` supports encrypted, signed, and
signed+encrypted containers:

```rust
use mtp::crypto::{ChaCha20Poly1305, Ed25519Signer, SigAlgorithm};

let cipher = ChaCha20Poly1305::new(derive_encryption_key(...));
let signer = Ed25519Signer::new(&keyring.sig_cl_secret_key)?;

// Encrypted container
let mut enc = DataValue::Container(vec![
    (DataTypeId(1), DataValue::Str("secret".into())),
]);
enc.encrypt_container(&cipher, b"aad");

// Signed container
let mut sig = DataValue::Container(vec![
    (DataTypeId(1), DataValue::Str("signed".into())),
]);
sig.sign_container(SigAlgorithm::ED25519, &signer);

// Signed + encrypted
let mut sec = DataValue::Container(vec![
    (DataTypeId(1), DataValue::Str("both".into())),
]);
sec.sign_and_encrypt_container(SigAlgorithm::ED25519, &signer, &cipher, b"aad");
```

On the receiving side, use the corresponding `decrypt_into_container`,
`verify_into_container`, or `decrypt_signed_encrypted_container` methods.

## Policy Configuration

The `Policy` struct controls transport behaviour:

```rust
use mtp::transport::{Policy, SendMode};

let policy = Policy {
    send_mode: SendMode::PersistentStream,
    max_message_size: 1_000_000_000,
    open_stream_timeout: Duration::from_millis(2000),
    write_timeout: Duration::from_millis(2000),
    read_timeout: Duration::from_millis(30_000),
    keep_alive_interval: Some(Duration::from_secs(3)),
    max_idle_timeout: Some(Duration::from_secs(30)),
    ..Default::default()
};
```

To apply a custom policy, call `mtp_transport::connect()` directly instead of
using `MTPClient`:

```rust
use mtp_transport::{connect, Policy};

let (sender, receiver) = connect(&config.url, config.server_cert, policy).await?;
```

Then build and send the initial `Identification` frame manually to complete
version negotiation.

## Version

The client's protocol version is baked in at compile time via the
`PROTOCOL_VERSION` constant from `mtp_codec`. The version is set by the
`protocol_version` field in your `type-maps.yaml`.

The client never imports the `registry` module; it uses a single compiled-in
version and expects the host to negotiate a compatible version.

## Error Handling

`CommunicationError` covers transport errors:

| Variant                 | Meaning                                    |
|-------------------------|--------------------------------------------|
| `StreamClosed`          | Connection was closed by peer or timed out |
| `StreamError`           | Transport-level I/O error                  |
| `MessageTooLarge`       | Frame exceeds `max_message_size`           |
| `ParseCommunicationValue` | Failed to deserialize incoming frame     |
| `AuthenticationFailed`  | Nonce mismatch or invalid host signature   |
| `ConnectionError`       | QUIC connection failure                    |
| `UseAfterClosed`        | Attempted send/receive after close         |


