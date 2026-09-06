# Security

This document describes the security controls implemented by MTP, the crypto APIs exposed by `mtp-crypto`, and the limits that operators and application developers must account for.

## Reporting Vulnerabilities

Report suspected vulnerabilities privately to the project maintainers. Include the affected crate, feature flags, protocol path, reproducible input, and the commit or release being tested. Do not include private keys or credentials in the report.

## Security Boundaries

MTP runs over QUIC and relies on TLS for transport confidentiality and peer authentication. The native transport uses `wtransport`; the browser client uses WebTransport. MTP authentication adds application-level signatures and does not replace TLS certificate verification.

MTP does not provide anonymity. Client identifiers and connection metadata are visible to the host. It also cannot protect data after a client or host endpoint has been compromised.

## TLS Certificate Verification

The native client uses the system root store by default. It also supports a pinned PEM certificate or an SPKI SHA-256 pin. Browser clients use the browser root store unless `serverCertificateHashes` is configured for WebTransport.

| Configuration | Trusts | Intended use |
| --- | --- | --- |
| System roots | Certificates trusted by the operating system or browser | Publicly trusted production certificates |
| Pinned PEM | The supplied PEM certificate chain | Private CA deployments and controlled environments |
| SPKI hash | The public key represented by the supplied certificate | A fixed server key, with planned rotation |
| Insecure verification | Any certificate | Local development only |

For rotation, publish the replacement certificate or key before changing the server, update clients to trust both values where the client API permits it, then remove the old value after all clients have migrated. A pin is a key constraint, not a substitute for a certificate rotation plan.

### Development Certificates

The `tls` feature exposes `mtp_crypto::tls::generate_self_signed_cert`. It creates an ECDSA P-256 server certificate for the requested domain, `127.0.0.1`, and `::1`; the certificate is valid for 13 days. The lower-level `mtp_native::HostConfig::self_signed` provides a transport-level self-signed setup without the crypto certificate helper.

Self-signed certificates are for development. Production deployments should use a certificate trusted by the client or an explicitly pinned certificate.

### Insecure Verification

Native insecure verification has two gates:

1. Compile with the `insecure-tls` feature.
2. Set `MTP_INSECURE_TLS=1` at runtime.

Without the runtime variable, the connection fails rather than silently disabling verification. Do not use this mode on an untrusted network.

## Authentication Policies

Hosts choose one of three policies:

- `ForceAuthentication` requires login or registration.
- `AllowAuthentication` accepts authenticated and unauthenticated clients.
- `Unauthenticated` rejects authentication attempts and is the default.

An unauthenticated connection receives `AuthState::Unauthenticated`. Use `ForceAuthentication` when every client must have a registered identity.

The native host exposes four authentication states:

| State | Meaning |
| --- | --- |
| `Unauthenticated` | The connection completed without application authentication. |
| `Pending` | The authentication handshake is in progress. |
| `Authenticated` | The host verified the client proof and assigned or confirmed its identity. |
| `Failed` | Authentication started but validation failed or the handshake timed out. |

Authorize requests only after `Authenticated`. A failed handshake is reported through `AcceptError::AuthenticationFailed` or `AcceptError::AuthenticationTimedOut` on the host.

### Hybrid Signatures

Authenticated handshakes support Ed25519 and ML-DSA-65 dual signatures. The host and clients default to `require_pq = true`, so both signatures are required. Calling `with_require_pq(false)` permits Ed25519-only authentication and should be treated as an explicit compatibility decision.

The `ml-dsa` dependency is enabled by default in `mtp-crypto`. The project has not recorded an independent audit for `ml-dsa`; see [Cryptographic review status](#cryptographic-review-status).

### Challenge-Response Flow

The complete sequence is in [Protocol Reference](PROTOCOL-REFERENCE.md#authentication-flow). This section defines the signed fields and domain-separation tags used by that sequence.

### Domain Separation

Every signed handshake payload begins with a distinct byte:

| Tag | Payload |
| --- | --- |
| `0x10` | Host challenge |
| `0x11` | Client login proof |
| `0x12` | Client registration proof |
| `0x13` | Host final confirmation |

The tags prevent a valid signature for one handshake step from being accepted as a signature for another step.

## Cryptographic Primitives

`mtp-crypto` exposes the following building blocks:

| Area | Implementation | Availability |
| --- | --- | --- |
| AEAD | XChaCha20-Poly1305 | Default |
| AEAD | AES-256-GCM | `full` feature |
| Classical signatures | Ed25519 | Default |
| Post-quantum signatures | ML-DSA-65 | Default |
| KDF and hashing | HKDF-SHA-256, SHA-256 | Default |
| Password KDF for `.mk` files | Argon2id | `files` feature |
| Hybrid KEM | X25519 plus ML-KEM-768 | `pqc` feature |

AEAD output stores the nonce before the authenticated ciphertext. `DataValue::Encrypted` uses one canonical multi-recipient envelope and derives a content key through authenticated KEM key wrapping. `DataValue::Signed` authenticates a domain-separated purpose, signer ID, and exact serialized inner value. MTP does not accept caller-supplied AAD as a replacement for this context.

| Protection | Authenticated fields |
| --- | --- |
| `Signed<Value>` | `MTP-DATA-SIGN-1`, signature algorithm, purpose, signer ID, and the exact serialized inner value. |
| `Encrypted<Value>` | `MTP-DATA-ENC-1`, encryption suite, purpose, recipient count, recipient table, and the ciphertext. Each wrapped content key also authenticates `MTP-DATA-WRAP-1`, suite, purpose, and its KEM ciphertext. |

The communication header is routing metadata, not automatically part of either
generic value wrapper's authenticated data. The high-level direct protected API
adds an MTP-owned signed envelope that binds its application type, final
recipient, message ID, creation time, and content to the outer route. Callers
using the generic protection primitives must bind any routing or message
metadata they require in their own signed value.

Protection composition is significant: `Encrypted(Signed(Value))` hides signer metadata until decryption and is the construction used for sealed-sender payloads; `Signed(Encrypted(Value))` exposes the signer metadata while protecting the contents. A sealed-sender frame simply omits the outer communication sender, routes with its receiver field, and carries an `Encrypted(Signed(Value))` payload. There is no sealed-sender frame flag or wire type.

### Protected Frame Visibility

Before opening an `Encrypted(Signed(Value))` payload, a component with access to the MTP frame can read the frame length, communication type, presence flags, transport correlation ID, and next-hop receiver. Relayable application messages use the generic reserved `Relay` communication type; operation-specific names are inside the ciphertext. The outer encrypted value also reveals its encryption suite, generic relay protection purpose, recipient count, unlabeled KEM ciphertext and wrapped-key entries, and ciphertext length. Recipient entries contain no recipient IDs, although recipient count and the cryptographic entry material remain visible.

The signer algorithm, signature purpose, signer ID, signature, and application-defined inner value are encrypted. They become available only after a recipient opens the encrypted value. The recipient must still verify the inner signature before trusting its signer ID or contents.

Sealed sender is therefore a construction rule, not an anonymity guarantee or a separate protocol type. The frame sender is absent, the next-hop receiver remains visible for routing, and MTP does not inspect application containers to infer identities or protection flags.

Connection authentication and protected identity are separate. For a sealed
relay sent over an authenticated connection, the host knows the connection's
registered MTP identity even though the outer relay sender is absent. The
protected signer remains hidden until a metadata recipient decrypts and
verifies the relay metadata.

For a sealed relay sent over an unauthenticated connection, the host receives
no registered MTP identity from connection authentication. The outer relay
sender is still absent, and the protected signer is still hidden until metadata
decryption and verification. The network connection nevertheless has observable
metadata such as peer addressing, timing, sizes, and the visible frame fields
described above. Neither case provides network anonymity.

### Relay access model and replay protection

Relay messages separate metadata recipients from content recipients. A relay
service can receive the metadata key, verify the authenticated signer and
message identifiers, index the opaque encrypted-content value, and forward the
frame without receiving a content key. Only a content recipient can open the
content. The final recipient and application message type remain inside the
protected metadata/content structure; the outer frame exposes only the chosen
next hop.

The receiver must consume the authenticated `(signer ID, MessageId)` pair with
a replay guard. `CreatedAt` is authenticated metadata that the guard receives
for retention or observability, but it is not part of the replay identity and
must not be used as the replay defense. The native codec exposes `ReplayGuard`
and the browser SDK exposes the matching `MTPReplayGuard` contract. Both
high-level APIs use bounded process-local guards by default for direct and
relay subscriptions. Those defaults are duplicate suppression only while an
entry remains in the fixed cache: eviction, reloads, or multiple receiver
processes can permit a previously accepted message again. Low-level relay
metadata opening remains replay-optional for callers reopening stored frames.
Use a durable guard when replay state must survive cache eviction, reloads, or
process boundaries. A guard should atomically record a new ID before
dispatching application content. Transport frame IDs must not be used for
this purpose.

Native message-processing boundaries require a replay guard through the
checked opening APIs. Reopening stored or forensic frames without a guard is
available only through an explicitly named `without_replay` API. The reference
in-memory guard is bounded and FIFO-evicts old entries, so it is a duplicate
suppression cache rather than durable replay protection. A durable deployment
must use an atomic insert-if-absent operation keyed by `(signer ID, MessageId)`;
a separate read followed by insert is race-prone.

`VerifiedRelayMetadata` is an authenticated capability rather than a caller
constructed data transfer object. Rust fields are private and the browser
implementation keeps authenticated state behind a branded class. Content
opening consumes that authenticated state, so changing a message ID or
recipient in a normal object cannot make unrelated encrypted content inherit
those fields. Browser callers can call `dispose()` or `free()` on the metadata
capability for deterministic native-handle release; finalization remains a
fallback.

### Signature policy

Verification takes a receiver-side `SignaturePolicy`/`ProtectionPolicy`.
`AnySupported` is useful for compatibility at the low-level codec boundary,
but protocol receivers should select `Ed25519` or `Dual`. The browser SDK uses
an explicit `ed25519` default and permits an operation or client override. Its
`MTPSecurityProfile` resolves protected-message sender/receiver suites,
encrypted-pipe suites, and the authentication PQ requirement together;
`any-supported` remains an explicit compatibility value. It never derives
receive policy from the recipient keyring. Signature policy must be applied
independently to relay metadata, relay content, and pipe session establishment.

### Key history and rotation

Recipient KEM key history is tried locally without adding a stable recipient
key identifier to the visible encrypted-recipient table. Signing-key resolvers
receive a claimed, unverified signer ID only as a trusted-key lookup key; the
relay helpers authenticate that ID when they verify against the returned
history. Deployments should retain old
verification keys for at least as long as stored signed messages remain
accepted, and should make key-history lookup an authorization decision rather
than accepting any key supplied with a message.

[mtp-crypto API](../crypto/), [native client](NATIVE-CLIENT.md), and [native host](NATIVE-HOST.md).

The crate's feature groups are:

| Feature | Adds |
| --- | --- |
| Default | XChaCha20-Poly1305, Ed25519, ML-DSA-65, HKDF, and SHA-256 |
| `full` | AES-256-GCM in addition to the default features |
| `pqc` | Hybrid X25519 and ML-KEM-768 support |
| `serde` | Serialization support for key types |
| `wasm` | `getrandom` support for WebAssembly |
| `tls` | Development certificate generation |
| `password-kdf` | Argon2id password derivation for protected keyring files |

The main types are `Keyring`, `PublicKeyBundle`, `EncryptionType`, `HybridKem`, `XChaCha20Poly1305` (with the legacy `ChaCha20Poly1305` alias), `Aes256Gcm`, `Ed25519Signer`, and `MlDsaSigner`. Hashing and KDF helpers include `sha256`, `sha256_double`, `hkdf_extract`, `hkdf_expand`, and `derive_encryption_key`. Handshake payload builders are in `mtp_crypto::auth`.

## Cryptographic Review Status

The project records the following status for its cryptographic dependencies:

| Crate | Audited? | Notes |
| --- | --- | --- |
| `ed25519-dalek` | Yes | Used by Signal and Diem |
| `chacha20poly1305` | Yes | NCC Group audit, December 2019 |
| `aes-gcm` | Yes | NCC Group audit, December 2019 |
| `ml-dsa` | No | NIST vectors pass in project tests |
| `mlkem-tls` | No | Uses an unaudited `mlkem-rs` backend |
| `hkdf` | No | Standard construction |
| `sha2` | No | Standard construction |
| `zeroize` | No | Used for secret-key containers |

The audit entries describe the dependency projects. MTP's crypto tests cover round trips, wrong-key failures, wrong-AAD failures, and signature failures;
they do not replace a review of protocol composition or deployment.

## Browser End-to-End Encryption

The browser SDK's optional E2EE session uses XChaCha20-Poly1305 with message keys derived from a one-way HKDF chain. Each send and receive operation advances its chain and authenticates the message header as AAD. Initial messages can carry a hybrid KEM ciphertext for session setup.

This is a single-chain ratchet. It has no Diffie-Hellman ratchet step and does not provide post-compromise security. Out-of-order messages can create skipped keys; the SDK accepts a receive gap of at most 100 messages and retains at most 100 skipped keys. Consumed or evicted keys are zeroed in the SDK state where the implementation owns the buffer.

The session root key comes from the authenticated handshake's KEM shared secret. The initiator and responder derive separate send and receive chains.
Each message consumes one chain key, derives one message key with HKDF, and increments its counter. `sessionStorage` stores browser session state for the current origin. `encryptedSecretProvider` is an independent caller-managed encrypted-secret facility; it is not automatically used by `MTPSessionStorage` or `MTPSessionManager`. Applications that need encrypted session persistence must coordinate those stores explicitly. The provider must protect its wrapping secret outside the SDK; the SDK does not recover a lost secret or skipped message keys.

Relay envelopes, browser session E2EE, and encrypted pipes are separate
protocols:

| Model | State | Intended use |
| --- | --- | --- |
| `RelayEnvelope` | Stateless `Encrypted(Signed(Value))`, multi-recipient | Store-and-forward messages and routing |
| `SessionE2EE` | Stateful symmetric ratchet in `sessionStorage` | Active browser exchanges |
| `EncryptedPipeSession` | Authenticated setup plus ordered record chain | Protected streams |

Encrypted pipes bind the pipe/session transcript, direction, purpose, sequence,
record length, and record type to each record. `FINAL` is authenticated and
unexpected EOF is reported as truncation. The ordinary signed/KEM offer is not
forward-secure; the native and browser duplex helpers use an ephemeral
authenticated KEM exchange before deriving the record chain. Group membership
changes require a new session key and recipient set.

## Key Storage

`Keyring` contains three public and three private key values. Its private key fields use `ZeroizeOnDrop`, and serialized keyring output is held in a zeroizing buffer while it is constructed. Public key bundles contain only the three public values.

Role-specific protocol boundaries should validate only the material they need:
`validate_encryption()` checks that a KEM public/private pair corresponds, while
`validate_full()` additionally requires a complete hybrid signing identity.
This keeps partial browser keyrings usable without allowing an envelope sender
to proceed with an invalid local decryption key.

Applications remain responsible for storage at rest. The `files` feature writes passphrase-protected keyrings to `.mk` files and public bundles to `.mpkb` files. Protected `.mk` files store the Argon2id identifier, parameters, salt, and AEAD ciphertext; they do not derive their key with HKDF. On Unix, keyring files are created with owner-only `0600` permissions.
Restrict those files to the owning account and protect backups. Browser applications should treat the configured credential storage as sensitive application data.

Key-material parsing is explicit in the SDK: use the hex, Base64, or byte
helpers for encoded key material. Arbitrary strings are no longer treated as
passphrases by the compatibility `secretKeyFromString` helper. Applications
migrating data written by the old implicit-HKDF behavior can use the explicitly
named, deprecated `legacySecretKeyFromStringV1` helper only for that migration;
new data must not use it. Passwords must use the explicit Argon2id passphrase
API with a stored per-record salt and versioned parameters. The SDK's
`deriveKeyFromPassphrase` uses a worker when browser workers are available;
the explicitly named `deriveKeyFromPassphraseSync` form is for workers and
command-line migrations. HKDF helpers are for high-entropy key material and
are not password-hardening functions.

## Resource Limits and Operational Controls

`Policy::default()` sets a 16 MiB application message limit and a 64 KiB handshake message limit. It also sets a 30 second read timeout, a 30 second maximum idle timeout, a receiver queue capacity of 1000, and a maximum of 128 concurrent stream tasks. Tune these values for the deployment and peer trust level.

The recursive codec applies additional defaults while parsing untrusted values:
maximum nesting depth 64, 65,536 value nodes, 16 MiB per blob or envelope,
64 encrypted recipients, and a 64 MiB cumulative decoder allocation budget.
Decrypted values are parsed with the same limits. Transport derives the blob,
allocation, and encoder output budgets from its admitted frame size rather than
serializing an unrestricted recursive value first. The default transport
allocation budget is four times the admitted frame size to cover conservative
owned-copy and crypto-buffer accounting; deployments may choose another
factor with `DecodeLimits::for_transport_message_size_with_allocation_factor`.

The host applies an authentication-attempt limiter before storage lookups,
public-key validation, challenge signing, and registration callbacks. The
default limiter is a bounded in-memory sliding window; configure a durable or
distributed limiter when limits must coordinate across host instances. Unknown
client IDs are sent through a fixed dummy challenge/proof path by default, so
they receive a generic authentication failure instead of an enumeration hint.
Deployments that intentionally publish client IDs can disable this concealment.

Keepalive Pong observation is bounded and accepts only the currently pending
ping ID. Unsolicited Pongs are dropped before they can consume application
receiver capacity.

## Security Limitations

- The first version-negotiation frame is sent before authentication and is not signed.
- `AllowAuthentication` intentionally permits unauthenticated clients; it is not an authenticated-only mode.
- Browser-side Rust panics cannot be recovered by JavaScript. The WASM client contains panic paths from internal `expect` calls.
- The browser E2EE ratchet does not provide post-compromise security.
- The ordinary encrypted-pipe offer does not provide forward secrecy; use the
  duplex handshake when recorded-call confidentiality after long-term KEM
  compromise is required.
- Replay state is process-local by default for high-level subscriptions. Use a
  durable replay guard when protection must survive reloads or coordinate
  multiple receiver processes.
