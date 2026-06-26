# mtp-crypto

Cryptographic primitives for the MTP protocol. Classical and post-quantum.

## Features

| Feature | Primitives | Status |
|---------|-----------|--------|
| `default` | XChaCha20-Poly1305, Ed25519, HKDF-SHA-256, SHA-256 | Classical |
| `full` | default + AES-256-GCM | Classical |
| `pqc` | ML-KEM-768+X25519 hybrid KEM, ML-DSA-65 | Post-quantum |

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

## KDF

```rust
use mtp_crypto::{hkdf_expand, derive_encryption_key};

let key = derive_encryption_key(b"ikm", b"salt", b"context")?;
```

## Hashing

```rust
use mtp_crypto::{sha256, sha256_double};

let h = sha256(b"data");
let h2 = sha256_double(b"data");
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

`KeyGroup` holds classical keys; `Keyring` holds all six (hybrid KEM + PQ sig + classical sig).

## Feature flags

```toml
[dependencies]
mtp-crypto = { path = "../crypto" }                          # classical
mtp-crypto = { path = "../crypto", features = ["pqc"] }       # post-quantum
mtp-crypto = { path = "../crypto", features = ["full", "pqc"] } # all
```
