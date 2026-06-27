use crate::error::CryptoError;

#[cfg(any(feature = "chacha20poly1305", feature = "aes-gcm"))]
use rand_core::OsRng;

#[cfg(any(feature = "chacha20poly1305", feature = "aes-gcm"))]
use rand_core::RngCore;

pub trait AeadEncrypt {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

pub trait AeadDecrypt {
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

pub trait AeadCipher: AeadEncrypt + AeadDecrypt {
    fn key_size() -> usize;
}

#[cfg(any(feature = "chacha20poly1305", feature = "aes-gcm"))]
fn prepend_nonce(nonce: &[u8], ciphertext: &mut Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
    out.extend_from_slice(nonce);
    out.append(ciphertext);
    out
}

#[cfg(feature = "chacha20poly1305")]
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

#[cfg(feature = "chacha20poly1305")]
impl ChaCha20Poly1305 {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
}

#[cfg(feature = "chacha20poly1305")]
impl AeadEncrypt for ChaCha20Poly1305 {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use chacha20poly1305::XChaCha20Poly1305;
        use chacha20poly1305::XNonce;
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};

        let key = chacha20poly1305::Key::from_slice(&self.key);
        let cipher = XChaCha20Poly1305::new(key);

        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let nonce_ref = XNonce::from_slice(&nonce);

        let payload = Payload {
            msg: plaintext,
            aad,
        };

        let mut ciphertext = cipher
            .encrypt(nonce_ref, payload)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(prepend_nonce(&nonce, &mut ciphertext))
    }
}

#[cfg(feature = "chacha20poly1305")]
impl AeadDecrypt for ChaCha20Poly1305 {
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use chacha20poly1305::XChaCha20Poly1305;
        use chacha20poly1305::XNonce;
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};

        if ciphertext.len() < 24 {
            return Err(CryptoError::InvalidNonceLength);
        }

        let (nonce, ct) = ciphertext.split_at(24);
        let key = chacha20poly1305::Key::from_slice(&self.key);
        let cipher = XChaCha20Poly1305::new(key);
        let nonce_ref = XNonce::from_slice(nonce);

        let payload = Payload { msg: ct, aad };

        cipher
            .decrypt(nonce_ref, payload)
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

#[cfg(feature = "chacha20poly1305")]
impl AeadCipher for ChaCha20Poly1305 {
    fn key_size() -> usize {
        32
    }
}

#[cfg(feature = "aes-gcm")]
pub struct Aes256Gcm {
    key: [u8; 32],
}

#[cfg(feature = "aes-gcm")]
impl Aes256Gcm {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
}

#[cfg(feature = "aes-gcm")]
impl AeadEncrypt for Aes256Gcm {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use aes_gcm::Aes256Gcm as AesGcmInner;
        use aes_gcm::Nonce;
        use aes_gcm::aead::{Aead, KeyInit, Payload};

        let key = aes_gcm::Key::<AesGcmInner>::from_slice(&self.key);
        let cipher = AesGcmInner::new(key);

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let nonce_ref = Nonce::from_slice(&nonce);

        let payload = Payload {
            msg: plaintext,
            aad,
        };

        let mut ciphertext = cipher
            .encrypt(nonce_ref, payload)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(prepend_nonce(&nonce, &mut ciphertext))
    }
}

#[cfg(feature = "aes-gcm")]
impl AeadDecrypt for Aes256Gcm {
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use aes_gcm::Aes256Gcm as AesGcmInner;
        use aes_gcm::Nonce;
        use aes_gcm::aead::{Aead, KeyInit, Payload};

        if ciphertext.len() < 12 {
            return Err(CryptoError::InvalidNonceLength);
        }

        let (nonce, ct) = ciphertext.split_at(12);
        let key = aes_gcm::Key::<AesGcmInner>::from_slice(&self.key);
        let cipher = AesGcmInner::new(key);
        let nonce_ref = Nonce::from_slice(nonce);

        let payload = Payload { msg: ct, aad };

        cipher
            .decrypt(nonce_ref, payload)
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

#[cfg(feature = "aes-gcm")]
impl AeadCipher for Aes256Gcm {
    fn key_size() -> usize {
        32
    }
}
