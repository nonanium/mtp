# mtp-crypto

Cryptographic primitives for the MTP protocol. Classical and post-quantum.

## Features

| Feature | Primitives |
|---------|-----------|
| `default` | XChaCha20-Poly1305, Ed25519, ML-DSA-65, HKDF-SHA-256, SHA-256 |
| `full` | default + AES-256-GCM |
| `pqc` | ML-KEM-768+X25519 hybrid KEM |

ML-DSA-65 is enabled by default so dual-signature support is always available
without a separate PQC feature flag in protocol crates.

## AEAD

XChaCha20-Poly1305 (default) and AES-256-GCM (`full` feature). Nonce is prepended to ciphertext.

```rust
use mtp_crypto::{ChaCha20Poly1305, AeadEncrypt, AeadDecrypt};

let cipher = ChaCha20Poly1305::new([0u8; 32]);
let ct = cipher.encrypt(b"hello", b"aad")?;
let pt = cipher.decrypt(&ct, b"aad")?;
```

## Signatures

### Ed25519

```rust
use mtp_crypto::{Ed25519Signer, SignatureScheme};

let (signer, sk, pk) = Ed25519Signer::generate();
let sig = signer.sign(b"message")?;
signer.verify(b"message", &sig)?;
```

### ML-DSA-65

```rust
use mtp_crypto::{MlDsaSigner, SignatureScheme};

let (signer, sk, pk) = MlDsaSigner::generate();
let sig = signer.sign(b"message")?;
signer.verify(b"message", &sig)?;

// Load from stored bytes
let signer = MlDsaSigner::new(&sk, &pk)?;
```

### Dual signatures

```rust
use mtp_crypto::{sign_dual, DualSignature, Ed25519Signer, MlDsaSigner};

let (ed_signer, _, _) = Ed25519Signer::generate();
let (ml_signer, _, _) = MlDsaSigner::generate();
let dual = sign_dual(ed_signer.signing_key(), ml_signer.signing_key(), b"msg");
dual.verify(ed_signer.verifying_key(), ml_signer.verifying_key(), b"msg")?;
```

## Hybrid KEM

X25519 + ML-KEM-768. 64-byte shared secret. Feed into HKDF before use.

```rust
use mtp_crypto::HybridKem;

let (sk, pk) = HybridKem::generate_keypair();
let enc = HybridKem::encapsulate(&pk)?;
let ss = HybridKem::decapsulate(&sk, &enc.ciphertext)?;
assert_eq!(enc.shared_secret, ss);
```

## Encrypted containers

Self-describing encrypted blobs with algorithm selection via `EncryptionType`.
Each blob begins with a marking byte so recipients can decrypt without
out-of-band agreement.

```rust
use mtp_crypto::{EncryptionType, Keyring, encrypt_for, decrypt_with};

let kr = Keyring::generate();
let blob = encrypt_for(EncryptionType::MlKemChaCha20Poly1305, &kr.public_key_bundle(), b"data", b"aad")?;
let pt = decrypt_with(&blob, &kr, b"aad")?;
```

## Multi-recipient encryption

Encrypt a payload for multiple recipients using a content-encryption key wrapped
per-recipient via Hybrid KEM.

```rust
use mtp_crypto::{Keyring, encrypt_multi, decrypt_multi};

let alice = Keyring::generate();
let bob = Keyring::generate();
let msg = encrypt_multi(b"secret", b"aad", &[alice.public_key_bundle(), bob.public_key_bundle()])?;
let pt = decrypt_multi(&msg, b"aad", &alice)?;
```

## Authentication handshake

Canonical domain-separated payloads for the challenge-response handshake.

```rust
use mtp_crypto::auth::{challenge_payload, login_proof_payload, register_proof_payload, host_final_payload};
```

Each payload type uses a distinct domain tag to prevent replay across protocol steps.

## KDF

```rust
use mtp_crypto::{hkdf_expand, hkdf_extract, derive_encryption_key};

let key = derive_encryption_key(b"ikm", b"salt", b"context")?;
let prk = hkdf_extract(b"ikm", b"salt");
```

## Hashing

```rust
use mtp_crypto::{sha256, sha256_double, Sha256Hasher};

let h = sha256(b"data");
let h2 = sha256_double(b"data");

let mut hasher = Sha256Hasher::new();
hasher.update(b"da");
hasher.update(b"ta");
let h3 = hasher.finalize();
```

## Key types

| Type | Secret | Zeroized |
|------|--------|----------|
| `EncryptionPrivateKey` | KEM/ECDH secret | Yes |
| `EncryptionPublicKey` | KEM/ECDH public | No |
| `SignaturePrivateKey` | Classical signing key | Yes |
| `SignaturePublicKey` | Classical verifying key | No |
| `KemPrivateKey` | Hybrid KEM secret | Yes |
| `KemPublicKey` | Hybrid KEM public | No |
| `SignaturePqPrivateKey` | PQC signing key | Yes |
| `SignaturePqPublicKey` | PQC verifying key | No |

`Keyring` holds all six keys (hybrid KEM + PQ sig + classical sig) plus
`generate()`, `to_bytes()`, and `from_bytes()` for serialization.
`PublicKeyBundle` holds the three public keys for distribution.

## Feature flags

```toml
[dependencies]
mtp-crypto = { path = "../crypto" }                          # classical + ML-DSA
mtp-crypto = { path = "../crypto", features = ["pqc"] }       # adds hybrid KEM
mtp-crypto = { path = "../crypto", features = ["full", "pqc"] } # adds AES-256-GCM + hybrid KEM
mtp-crypto = { path = "../crypto", features = ["serde"] }      # serde support
mtp-crypto = { path = "../crypto", features = ["wasm"] }       # WASM compat
```
