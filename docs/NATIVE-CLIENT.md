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
use mtp::client::{ClientConfig, ClientTlsConfig};
use std::time::Duration;

let config = ClientConfig::new("https://host.example.com:4433")
    .with_tls(ClientTlsConfig::SystemRoots)
    .with_client_id(0)
    .with_ping_interval(Duration::from_secs(5))
    .with_max_missed_pings(3)
    .with_ping_timestamp(true);
```

| Field         | Type               | Description                                         |
|---------------|--------------------|-----------------------------------------------------|
| `url`         | `String`           | `https://host:port` address of the MTP host         |
| `tls`         | `ClientTlsConfig`  | `SystemRoots` or `PinnedPem(pem_bytes)`              |
| `client_id`   | `u64`              | Client identifier (ignored during `auth_register`)  |
| `description` | `Option<String>`   | Optional label sent during handshake (e.g. `"phone"`) |
| `ping_interval` | `Duration`       | Interval between Ping frames; zero disables pings |
| `max_missed_pings` | `usize`        | Unanswered Ping frames allowed before the connection closes |
| `ping_timestamp` | `bool`          | Adds a `Timestamp` entry to each Ping frame |
| `auth_timeout` | `Duration` (crypto) | Authentication handshake timeout (default 30s)     |

### TLS Certificate Handling

When `tls` is `ClientTlsConfig::SystemRoots` (the default), the client loads the **system's
native root certificate store** via `rustls_native_certs`. This works with
publicly-trusted CAs out of the box on Linux (using `openssl-probe`), macOS
(Keychain), and Windows (Root Store).

For development or self-signed certificates, provide one or more PEM-encoded
certificates:

```rust
let pem = std::fs::read("my-server-cert.pem")?;
let config = ClientConfig::new("https://host.example.com:4433").with_pinned_pem(pem);
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
    pub description: Option<String>,
    #[cfg(feature = "crypto")]
    pub auth_state: AuthState,
    #[cfg(feature = "crypto")]
    pub client_id: u64,
}
```

- `version` -- the negotiated protocol version
- `sender` / `receiver` -- for message I/O
- `description` -- the label sent during handshake (set via `ClientConfig::with_description`)
- `client_id` -- the confirmed/assigned client identifier (crypto only)

When `ping_interval` is non-zero, MTP sends Ping frames in the background and
consumes their Pong responses before application message handling. `get_ping()`
returns the round-trip duration of the latest matched Pong, or `None` until a
Pong arrives. A connection closes when the configured unanswered Ping limit is
reached.

### Ping-Pong

Ping/Pong is part of the protocol, not just a transport keepalive. Each Ping
frame is matched against a Pong with the same frame id, and the client uses the
response to update `get_ping()`. If the host does not answer within the
configured limit, the connection closes.

Enable it in `ClientConfig`, then inspect the latest round-trip time on the
connection. Pings start after the connection has been established; `None` is
normal until the first matching Pong arrives.

```rust
use mtp::client::{ClientConfig, MTPClient};
use std::time::Duration;

let config = ClientConfig::new("https://host.example.com:4433")
    .with_client_id(42)
    .with_ping_interval(Duration::from_secs(5))
    .with_max_missed_pings(3)
    .with_ping_timestamp(true);

let conn = MTPClient::connect(config).await?;

if let Some(round_trip) = conn.get_ping() {
    println!("latest MTP round trip: {round_trip:?}");
}
```

The client consumes the Pong frames used by this loop, so they are not returned
by `conn.receiver.receive()`. Set `ping_interval` to `Duration::ZERO` (the
default) to disable protocol pings. `max_missed_pings` is the number of
outstanding Ping frames allowed before the client closes the connection; use a
host with automatic Pong responses, or provide an equivalent responder.

### Unauthenticated Connect

```rust
use mtp::client::{ClientConfig, MTPClient};

let config = ClientConfig::new("https://host.example.com:4433").with_client_id(42);

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

let config = ClientConfig::new("https://host.example.com:4433")
    .with_client_id(42); // must match the keyring's identity

let conn = MTPClient::auth_connect(config, &keys, &host_pk).await?;
```

Protocol (challenge-response, the host issues the freshness):
1. Client sends an unsigned `Identification` hello (version, client ID)
2. Host replies with a `Challenge` carrying a fresh random `server_challenge`
   and the host's signature over it; the client verifies that signature
3. Client generates a random `client_nonce` and signs
   `version || client_id || server_challenge || client_nonce` with Ed25519
   (and optionally ML-DSA-65)
4. Client sends a `ChallengeResponse` frame (nonce + signature(s))
5. Host verifies the proof against `server_challenge` and responds with
   `IdentificationResponse` (echoed nonce + host signature)
6. Client verifies the host signature and nonce echo

Because the client's signature covers the host-issued `server_challenge`, a
captured proof cannot be replayed on another connection (each connection gets a
different challenge).

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

When callers already know whether a saved client id exists, the convenience
helper chooses login or registration:

```rust
let conn = MTPClient::auth_connect_or_register(
    config,
    saved_client_id, // Option<u64>
    &keyring,
    &host_pk,
).await?;
```

Protocol (challenge-response):
1. Client sends an unsigned `Register` hello (version, public key bundle)
2. Host replies with a `Challenge` carrying a fresh random `server_challenge`
   (signed by the host); the client verifies that signature
3. Client generates a random `client_nonce` and signs
   `version || server_challenge || client_nonce || public_key_bytes` with
   Ed25519 (and optionally ML-DSA-65)
4. Client sends a `ChallengeResponse` frame (nonce + signature(s))
5. Host verifies the proof against `server_challenge`, assigns a new client ID,
   and responds with `RegisterResponse` (the ID, echoed nonce, host signature)
6. Client verifies the host signature and nonce echo

## Key Material

### Keyring

A `Keyring` bundles all secret and public key material for one identity:

```rust
pub struct Keyring {
    pub kem_public_key: KemPublicKey,
    pub kem_secret_key: KemPrivateKey,
    pub sig_pq_public_key: SignaturePqPublicKey,  // ML-DSA-65
    pub sig_pq_secret_key: SignaturePqPrivateKey,
    pub sig_cl_public_key: SignaturePublicKey,    // Ed25519
    pub sig_cl_secret_key: SignaturePrivateKey,
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

For request/response flows, `MTPConnection::request` sends one frame and waits
for a response with the same non-zero frame id. An expected response type can be
provided for validation:

```rust
let response = conn
    .request(&msg, Some(mtp::codec::CommunicationType::Pong))
    .await?;
```

Frames with other ids are consumed by this helper. Applications that need
subscriptions or broad routing should use one receive task and correlate there.

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
signed+encrypted containers. Encryption uses ML-KEM to encapsulate to a
recipient's KEM public key (from their `PublicKeyBundle`); only the holder of
the matching `Keyring` can decrypt. Signing uses the sender's Ed25519 key.

```rust
use mtp::crypto::{EncryptionType, Ed25519Signer, SigAlgorithm};

let enc_type = EncryptionType::MlKemChaCha20Poly1305;
let signer = Ed25519Signer::new(&keyring.sig_cl_secret_key)?;

// `recipient` is the PublicKeyBundle of whoever should be able to decrypt
// (e.g. the host's bundle, obtained out of band).

// Encrypted container
let mut enc = DataValue::Container(vec![
    (DataTypeId(1), DataValue::Str("secret".into())),
]);
enc.encrypt_container(enc_type, &recipient, b"aad");

// Signed container
let mut sig = DataValue::Container(vec![
    (DataTypeId(1), DataValue::Str("signed".into())),
]);
sig.sign_container(SigAlgorithm::ED25519, &signer);

// Signed + encrypted
let mut sec = DataValue::Container(vec![
    (DataTypeId(1), DataValue::Str("both".into())),
]);
sec.sign_and_encrypt_container(SigAlgorithm::ED25519, &signer, enc_type, &recipient, b"aad");
```

On the receiving side, the recipient decrypts with its own `Keyring` (each blob
is self-describing: its leading byte selects the algorithm and the matching KEM
key from the keyring):

```rust
enc.decrypt_into_container(&keyring, b"aad");                // -> Container
sig.verify_into_container(&verifier);                        // verifier: impl SignatureScheme
sec.decrypt_signed_encrypted_container(&keyring, b"aad");    // -> SignedContainer, then verify_into_container
```

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

let server_cert = match &config.tls {
    ClientTlsConfig::SystemRoots => None,
    ClientTlsConfig::PinnedPem(pem) => Some(pem.clone()),
};
let (sender, receiver) = connect(&config.url, server_cert, policy).await?;
```

Then build and send the initial `Identification` frame manually to complete
version negotiation.

## Version

The client's protocol version is baked in at compile time via the
`PROTOCOL_VERSION` constant from `mtp::codec`. The version is set by the
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
