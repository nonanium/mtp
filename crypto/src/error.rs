use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum CryptoError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("decryption output exceeds the caller's allocation limit")]
    AllocationLimit,
    #[error("malformed encryption envelope")]
    MalformedEnvelope,
    #[error("no encryption recipients")]
    NoRecipients,
    #[error("no matching encryption recipient")]
    NoMatchingRecipient,
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("public and private key material do not match")]
    InvalidKeyMaterial,
    #[error("invalid nonce length")]
    InvalidNonceLength,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("signing failed")]
    SigningFailed,
    #[error("verification failed")]
    VerificationFailed,
    #[error("key generation failed")]
    KeyGenerationFailed,
    #[error("KDF error")]
    KdfError,
    #[error("KEM encapsulation failed")]
    KemEncapsulationFailed,
    #[error("KEM decapsulation failed")]
    KemDecapsulationFailed,
    #[error("unknown algorithm")]
    UnknownAlgorithm,
    #[error("invalid hex encoding")]
    InvalidHex,
    #[error("invalid base64 encoding")]
    InvalidBase64,
    #[error("TLS error: {0}")]
    Tls(String),
}
