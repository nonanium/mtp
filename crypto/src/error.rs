use std::fmt;

#[derive(Debug, Clone)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidSignature,
    SigningFailed,
    VerificationFailed,
    KeyGenerationFailed,
    KdfError,
    KemEncapsulationFailed,
    KemDecapsulationFailed,
    UnknownAlgorithm,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::EncryptionFailed => write!(f, "encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "decryption failed"),
            CryptoError::InvalidKeyLength => write!(f, "invalid key length"),
            CryptoError::InvalidNonceLength => write!(f, "invalid nonce length"),
            CryptoError::InvalidSignature => write!(f, "invalid signature"),
            CryptoError::SigningFailed => write!(f, "signing failed"),
            CryptoError::VerificationFailed => write!(f, "verification failed"),
            CryptoError::KeyGenerationFailed => write!(f, "key generation failed"),
            CryptoError::KdfError => write!(f, "KDF error"),
            CryptoError::KemEncapsulationFailed => write!(f, "KEM encapsulation failed"),
            CryptoError::KemDecapsulationFailed => write!(f, "KEM decapsulation failed"),
            CryptoError::UnknownAlgorithm => write!(f, "unknown algorithm"),
        }
    }
}

impl std::error::Error for CryptoError {}
