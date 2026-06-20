pub mod aead;
pub mod error;
pub mod keypair;

#[cfg(feature = "sha2")]
pub mod hash;

#[cfg(feature = "hkdf")]
pub mod kdf;

#[cfg(any(feature = "ed25519-dalek", feature = "ml-dsa"))]
pub mod sign;

#[cfg(feature = "mlkem-tls")]
pub mod kem;

pub use aead::{AeadCipher, AeadDecrypt, AeadEncrypt};
pub use error::CryptoError;
pub use keypair::{
    EncryptionPrivateKey, EncryptionPublicKey, KemPrivateKey, KemPublicKey, KeyGroup, Keyring,
    SignaturePqPrivateKey, SignaturePqPublicKey, SignaturePrivateKey, SignaturePublicKey,
};

#[cfg(feature = "chacha20poly1305")]
pub use aead::ChaCha20Poly1305;

#[cfg(feature = "aes-gcm")]
pub use aead::Aes256Gcm;

#[cfg(feature = "ed25519-dalek")]
pub use sign::{verify_ed25519, Ed25519Signer, SignatureScheme};

#[cfg(feature = "ml-dsa")]
pub use sign::{verify_ml_dsa, MlDsaSigner};

#[cfg(all(feature = "ed25519-dalek", feature = "ml-dsa"))]
pub use sign::{sign_dual, DualSignature};

#[cfg(feature = "sha2")]
pub use hash::{sha256, sha256_double, Sha256Hasher};

#[cfg(feature = "hkdf")]
pub use kdf::{derive_encryption_key, hkdf_expand, hkdf_extract};

#[cfg(feature = "mlkem-tls")]
pub use kem::HybridKem;
