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

The `tls` feature exposes `mtp_crypto::tls::generate_self_signed_cert`. It creates an ECDSA P-256 server certificate for the requested domain, `127.0.0.1`, and `::1`; the certificate is valid for 13 days. `HostConfig::self_signed` provides a transport-level self-signed setup without the crypto certificate helper.

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
| Hybrid KEM | X25519 plus ML-KEM-768 | `pqc` feature |

AEAD output stores the nonce before the authenticated ciphertext. Encrypted containers select their algorithm with a leading marking byte, derive an AEAD key from the KEM shared secret with HKDF, and authenticate caller-supplied AAD. Multi-recipient encryption wraps one content-encryption key separately for each recipient.

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

The main types are `Keyring`, `PublicKeyBundle`, `EncryptionType`, `HybridKem`, `ChaCha20Poly1305`, `Aes256Gcm`, `Ed25519Signer`, and `MlDsaSigner`. Hashing and KDF helpers include `sha256`, `sha256_double`, `hkdf_extract`, `hkdf_expand`, and `derive_encryption_key`. Handshake payload builders are in `mtp_crypto::auth`.

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
Each message consumes one chain key, derives one message key with HKDF, and increments its counter. `sessionStorage` stores browser session state for the current origin. `encryptedDeviceSecretProvider` supplies encrypted device secret storage when sessions must survive page reloads. The provider must protect its wrapping secret outside the SDK; the SDK does not recover a lost device secret or skipped message keys.

## Key Storage

`Keyring` contains three public and three private key values. Its private key fields use `ZeroizeOnDrop`, and serialized keyring output is held in a zeroizing buffer while it is constructed. Public key bundles contain only the three public values.

Applications remain responsible for storage at rest. The `files` feature writes passphrase-protected keyrings to `.mk` files and public bundles to `.mpkb` files. On Unix, keyring files are created with owner-only `0600` permissions.
Restrict those files to the owning account and protect backups. Browser applications should treat the configured credential storage as sensitive application data.

## Resource Limits and Operational Controls

`Policy::default()` sets a 16 MiB application message limit and a 64 KiB handshake message limit. It also sets a 30 second read timeout, a 30 second maximum idle timeout, a receiver queue capacity of 1000, and a maximum of 128 concurrent stream tasks. Tune these values for the deployment and peer trust level.

The host does not provide a general authentication-attempt rate limiter.
Deploy authentication endpoints behind a rate-limiting proxy or add admission control through the host callbacks, including `GuestIdGenerator` where guest connections are permitted.

## Security Limitations

- The first version-negotiation frame is sent before authentication and is not signed.
- `AllowAuthentication` intentionally permits unauthenticated clients; it is not an authenticated-only mode.
- Browser-side Rust panics cannot be recovered by JavaScript. The WASM client contains panic paths from internal `expect` calls.
- The browser E2EE ratchet does not provide post-compromise security.
