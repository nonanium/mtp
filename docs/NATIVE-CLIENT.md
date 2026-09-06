# MTP Native Client

The native client is a Rust library (`mtp-client`) for connecting to an MTP host over QUIC. It uses `wtransport` under the hood and provides both unauthenticated and authenticated (crypto handshake) connection modes.

## Prerequisites

Add the `mtp` umbrella crate with `client`. Add `crypto` for authenticated connections, `pipes` for raw streams, and `tls` for development certificate generation. The `insecure-tls` feature applies only to the lower-level transport API. The feature table is in the [README](../README.md).

## Quick Start

```rust
use mtp::client::{ClientConfig, MTPClient};
use mtp::codec::{CommunicationType, CommunicationValue};

let conn = MTPClient::connect(
    ClientConfig::new("https://host.example.com:4433").with_client_id(42),
).await?;
let request = CommunicationValue::new(CommunicationType::Ping).with_id(1);
conn.sender.send(&request).await?;
let response = conn.receive().await?;
println!("received {:?}", response.id());
conn.sender.close().await;
```

## Configuration

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

| Field                   | Type               | Default          | Description                                 |
|-------------------------|--------------------|------------------|---------------------------------------------|
| `url`                   | `String`           | required         | Host URL (`https://host:port`)              |
| `tls`                   | `ClientTlsConfig`  | `SystemRoots`    | `SystemRoots` or `PinnedPem(Vec<u8>)`       |
| `client_id`             | `u64`              | `0`              | Client identifier (for login)               |
| `description`           | `Option<String>`   | `None`           | Optional label sent to host                 |
| `policy`                | `Policy`           | default          | Transport policy (timeouts, send mode)      |
| `ping_interval`         | `Duration`         | `Duration::ZERO` | Interval between protocol Ping frames       |
| `ping_jitter`           | `Option<Duration>` | `None`           | Random jitter added to each interval        |
| `max_missed_pings`      | `usize`            | `3`              | Disconnect after this many unanswered Pings |
| `ping_timestamp`        | `bool`             | `true`           | Include a `Timestamp` data entry in Ping    |
| `request_timeout`       | `Duration`         | `30s`            | Max time for `MTPConnection::request`      |
| `auth_timeout` (crypto) | `Duration`         | `30s`            | Max time for auth handshake                 |
| `require_pq` (crypto)   | `bool`             | `true`           | Require ML-DSA-65 during authentication    |

### TLS Certificate Handling

`ClientTlsConfig::SystemRoots` is the default. Use `ClientTlsConfig::PinnedPem` or `ClientConfig::with_pinned_pem` for a supplied certificate chain. SPKI pinning and development or insecure transport configuration are available through lower-level transport APIs. See [Security](SECURITY.md) for trust models, certificate generation, rotation, and the insecure-mode gates.

## Connecting

All methods return a `Result<MTPConnection, CommunicationError>`.

### MTPConnection

Shared fields and lifecycle: [MTP Connections](CONNECTIONS.md).

Keepalive behavior is defined in [Protocol Reference](PROTOCOL-REFERENCE.md#protocol-keepalive).

### Requests

`MTPConnection::request` sends a `CommunicationValue` and waits for a response with the same frame ID. It uses `ClientConfig::request_timeout`; timeout and connection errors reject the request.

The request must have a non-zero ID. The response is removed from the pending request table and is not returned by a later `conn.receive()` call. A timeout removes the pending request and returns `CommunicationError`; a response with the wrong expected type also returns an error. Frames with other IDs remain available through `conn.receive()`.

```rust
let response = conn
    .request(&request_value, Some(CommunicationType::Pong))
    .await?;
```

### Protocol keepalive

Enable it with `ClientConfig` and inspect the latest matched round-trip time with `get_ping()`. See [Protocol Reference](PROTOCOL-REFERENCE.md).

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

Pong dispatch and missed-Ping behavior are defined in [Protocol Reference](PROTOCOL-REFERENCE.md#protocol-keepalive). Set `ping_interval` to `Duration::ZERO` (the default) to disable protocol pings.

### Unauthenticated Connect

```rust
use mtp::client::{ClientConfig, MTPClient};

let config = ClientConfig::new("https://host.example.com:4433").with_client_id(42);

let conn = MTPClient::connect(config).await?;
```

Sends an `Identification` frame with the compiled-in protocol version and client ID. No cryptographic handshake is performed.

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

Authentication uses the signed challenge flow in [Protocol Reference](PROTOCOL-REFERENCE.md#authentication-flow). Cryptographic fields and domain separation are defined in [Security](SECURITY.md).

### Registration

```rust
let (ed_signer, sig_sk, sig_pk) = mtp::crypto::Ed25519Signer::generate();
let (pq_signer, sig_pq_sk, sig_pq_pk) = mtp::crypto::MlDsaSigner::generate();
let (kem_sk, kem_pk) = mtp::crypto::HybridKem::generate_keypair();

let keyring = Keyring::new(kem_pk, kem_sk, sig_pq_pk, sig_pq_sk, sig_pk, sig_sk);

let conn = MTPClient::auth_register(config, &keyring, &host_pk).await?;

// Save for next session
let id = conn.client_id;
let keyring_bytes = keyring.try_to_bytes()?;
```

When callers already know whether a saved client ID exists, the convenience helper uses `Some(id)` for login and `None` for registration:

```rust
let conn = MTPClient::auth_connect_or_register(
    config,
    saved_client_id, // Option<u64>
    &keyring,
    &host_pk,
).await?;
```

Registration uses the authentication flow in [Protocol Reference](PROTOCOL-REFERENCE.md#authentication-flow).

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

- Serialise: `keyring.try_to_bytes()` -> `Result<Zeroizing<Vec<u8>>, CryptoError>`
- Deserialise: `Keyring::from_bytes(&bytes)` -> `Result<Keyring, CryptoError>`
- Get public half: `keyring.public_key_bundle()` -> `PublicKeyBundle`

### PublicKeyBundle

The public half of a keyring, used by the host for signature verification and by the client for host signature verification:

```rust
pub struct PublicKeyBundle {
    pub kem_public_key: KemPublicKey,
    pub sig_cl_public_key: SignaturePublicKey,
    pub sig_pq_public_key: SignaturePqPublicKey,
}
```

Obtain the host's `PublicKeyBundle` out of band (e.g. from files exported by the host, or from a trusted directory).

## Communicate

### Sending and Receiving Messages

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

When the `registry` feature is enabled (via the `host` feature), you can also use `add_typed` with a `TypeMap` to resolve data type names from your project's type-map configuration.

### Send

```rust
conn.sender.send(&msg).await?;
```

For request/response flows, `MTPConnection::request` sends one frame and waits for a response with the same non-zero frame id. An expected response type can be provided for validation:

```rust
let response = conn
    .request(&msg, Some(mtp::codec::CommunicationType::Pong))
    .await?;
```

Requests are routed by id through the connection's receive dispatcher. Frames with other ids remain available through `conn.receive()`.

Two send modes (configured via `mtp::client::Policy`):
- `PersistentStream` (default): reuses one QUIC unidirectional stream
- `SingleStreamPerMessage`: opens a new stream per message. Parallel sends are
  enabled by default; messages sent concurrently may be received out of order.
  Call `Policy::with_parallel_multi_stream_sends(false)` to serialize them.

### Receive

```rust
match conn.receive().await {
    Ok(msg) => { /* handle CommunicationValue */ }
    Err(e) => { /* connection closed or error */ }
}
```

Inbound frames are queued internally. The `receive()` method returns the next available message. Do not read from `conn.receiver` directly because the connection dispatcher owns the shared transport receive loop.

### Close

```rust
conn.sender.close().await;
// or
conn.receiver.close();
```

`Sender::close().await` gracefully finishes the active send stream, sends the
MTP close frame, and waits for `force_close_delay` (default 300ms) before
force-closing the QUIC connection if necessary. `Sender::close_immediate()` is
the fire-and-forget variant. `Receiver::close()` closes the local receive
handle without performing the sender's graceful close sequence.

### Pipes

The complete pipe protocol, native API, browser API, lifecycle, and errors are documented in [Pipes](PIPES.md). Use the connection facade described there when the `pipes` feature is enabled.

## Appendix: Composable Data Protection

With the `crypto` feature, any `DataValue` can be signed or encrypted. The operations return typed errors and compose by operation order. `Encrypted(Signed(Value))` keeps the signer identity inside the encrypted plaintext; `Signed(Encrypted(Value))` leaves it visible. The example uses different keyrings for the signer and recipient to make the ownership explicit.

```rust
use mtp::codec::{ProtectionPurpose, DataTypeId, DataValue};
use mtp::crypto::{Ed25519Signer, Keyring};

let sender_keyring = Keyring::generate();
let recipient_keyring = Keyring::generate();
let signer = Ed25519Signer::new(&sender_keyring.sig_cl_secret_key)?;
let recipient = recipient_keyring.public_key_bundle();
let sender_public_keys = sender_keyring.public_key_bundle();
let value = DataValue::Container(vec![
    (DataTypeId(32), DataValue::Str("secret".into())),
]);

// The outer encrypted wrapper hides the signer metadata.
let private_signer = value.clone().sign(7, ProtectionPurpose::from(1), &signer)?;
let sealed = private_signer.encrypt_for(
    std::slice::from_ref(&recipient),
    ProtectionPurpose::from(2),
)?;
```

Reverse the calls when the signer identity should remain visible to the recipient before opening the encrypted value:

```rust
let encrypted = value.encrypt_for(
    std::slice::from_ref(&recipient),
    ProtectionPurpose::from(2),
)?;
let public_signer = encrypted.sign(7, ProtectionPurpose::from(1), &signer)?;
```

Opening and verification are explicit and return the inner value without mutating the wrapper:

```rust
let signed = sealed.decrypt(&recipient_keyring, ProtectionPurpose::from(2))?;
signed.verify(7, &sender_public_keys, ProtectionPurpose::from(1))?;
let plain = signed.into_verified(7, &sender_public_keys, ProtectionPurpose::from(1))?;
```

For `public_signer`, call `verify` and `into_verified` before calling `decrypt`; its outer signature is available before the encrypted value is opened.

### Policy Configuration

The `Policy` struct controls transport behaviour:

```rust
use mtp::client::{Policy, SendMode};

let policy = Policy {
    send_mode: SendMode::PersistentStream,
    max_message_size: 16 * 1024 * 1024,
    handshake_max_message_size: 64 * 1024,
    open_stream_timeout: Duration::from_millis(2000),
    write_timeout: Duration::from_millis(2000),
    read_timeout: Duration::from_millis(30_000),
    keep_alive_interval: Some(Duration::from_secs(3)),
    max_idle_timeout: Some(Duration::from_secs(30)),
    ..Default::default()
};
```

Apply a custom policy with `ClientConfig::with_policy`:

```rust
let config = config.with_policy(policy);
let conn = MTPClient::connect(config).await?;
```

### Version

The client's protocol version is baked in at compile time via the `PROTOCOL_VERSION` constant from `mtp::codec`. The version is set by the `protocol_version` field in your `type-maps.yaml`.

The client never imports the `registry` module; it uses a single compiled-in version and expects the host to negotiate a compatible version.

### Error Handling

`CommunicationError` is summarized in the [Error Reference](ERRORS.md).
Native builds can expose additional variants that wrap QUIC and WebTransport errors.
