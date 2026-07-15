#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
use crate::error::CryptoError;

#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
use crate::kdf::derive_encryption_key;
#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
use crate::kem::HybridKem;
#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
use crate::keypair::{Keyring, PublicKeyBundle};

/*
 * Algorithm selector for encrypted containers.
 *
 * Mirrors `SigAlgorithm` for signatures: a single marking byte identifies the
 * key-encapsulation mechanism and the AEAD used to seal a container. The byte
 * is stored as the first byte of every encrypted blob so the decryptor can pick
 * the matching algorithm (and the matching keypair from a `Keyring`) without
 * any out-of-band agreement.
 *
 * All variants currently use ML-KEM (X25519MlKem768) for key encapsulation and
 * differ only in the AEAD. AES-256-GCM variants require the `aes-gcm` feature
 * (enabled via the crate's `full` feature); sealing/opening with a variant whose
 * AEAD feature is not compiled in returns an error.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionType {
    /// ML-KEM (X25519MlKem768) key encapsulation with XChaCha20-Poly1305 AEAD.
    MlKemChaCha20Poly1305,
    /// ML-KEM (X25519MlKem768) key encapsulation with AES-256-GCM AEAD.
    MlKemAes256Gcm,
}

impl EncryptionType {
    pub const ML_KEM_CHACHA20POLY1305: u8 = 0x01;
    pub const ML_KEM_AES256_GCM: u8 = 0x02;

    /// The marking byte written at the front of an encrypted blob.
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::MlKemChaCha20Poly1305 => Self::ML_KEM_CHACHA20POLY1305,
            Self::MlKemAes256Gcm => Self::ML_KEM_AES256_GCM,
        }
    }

    /// Recover an `EncryptionType` from its marking byte, or `None` if unknown.
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            Self::ML_KEM_CHACHA20POLY1305 => Some(Self::MlKemChaCha20Poly1305),
            Self::ML_KEM_AES256_GCM => Some(Self::MlKemAes256Gcm),
            _ => None,
        }
    }
}

/*
 * Seal `plaintext` with a 32-byte AEAD key chosen by `enc_type`.
 *
 * Returns `EncryptionFailed` when the selected AEAD's feature is not compiled in.
 */
#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
#[allow(unused_variables)]
fn aead_seal(
    enc_type: EncryptionType,
    key: [u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    #[allow(unused_imports)]
    use crate::aead::AeadEncrypt;
    match enc_type {
        #[cfg(feature = "chacha20poly1305")]
        EncryptionType::MlKemChaCha20Poly1305 => {
            crate::aead::ChaCha20Poly1305::new(key).encrypt(plaintext, aad)
        }
        #[cfg(feature = "aes-gcm")]
        EncryptionType::MlKemAes256Gcm => crate::aead::Aes256Gcm::new(key).encrypt(plaintext, aad),
        #[allow(unreachable_patterns)]
        _ => Err(CryptoError::EncryptionFailed),
    }
}

/*
 * Open `ciphertext` with a 32-byte AEAD key chosen by `enc_type`.
 *
 * Returns `DecryptionFailed` when the selected AEAD's feature is not compiled in.
 */
#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
#[allow(unused_variables)]
fn aead_open(
    enc_type: EncryptionType,
    key: [u8; 32],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    #[allow(unused_imports)]
    use crate::aead::AeadDecrypt;
    match enc_type {
        #[cfg(feature = "chacha20poly1305")]
        EncryptionType::MlKemChaCha20Poly1305 => {
            crate::aead::ChaCha20Poly1305::new(key).decrypt(ciphertext, aad)
        }
        #[cfg(feature = "aes-gcm")]
        EncryptionType::MlKemAes256Gcm => crate::aead::Aes256Gcm::new(key).decrypt(ciphertext, aad),
        #[allow(unreachable_patterns)]
        _ => Err(CryptoError::DecryptionFailed),
    }
}

#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
const ENC_KDF_SALT: &[u8] = b"mtp-container-enc";
#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
const ENC_KDF_CONTEXT: &[u8] = b"single-recipient";

/*
 * Encrypt `plaintext` for a single recipient, selecting the algorithm with
 * `enc_type` and the recipient's KEM public key from `recipient`.
 *
 * The returned, self-describing blob is laid out as:
 *   [1 byte EncryptionType] [2 bytes u16 kem_ct_len] [kem_ciphertext] [aead_payload]
 * where `aead_payload` is the AEAD output (nonce + ciphertext + tag). The AEAD
 * key is derived from the KEM shared secret via HKDF, so no separate content key
 * is transmitted.
 *
 * Requires the `mlkem-tls` and `hkdf` features, plus the AEAD feature backing
 * `enc_type`.
 */
#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
pub fn encrypt_for(
    enc_type: EncryptionType,
    recipient: &PublicKeyBundle,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let enc = HybridKem::encapsulate(&recipient.kem_public_key)?;
    let key = derive_encryption_key(&enc.shared_secret, ENC_KDF_SALT, ENC_KDF_CONTEXT)?;
    let aead_payload = aead_seal(enc_type, key, plaintext, aad)?;

    let kem_ct = enc.ciphertext;
    let mut out = Vec::with_capacity(1 + 2 + kem_ct.len() + aead_payload.len());
    out.push(enc_type.to_byte());
    out.extend_from_slice(&(kem_ct.len() as u16).to_be_bytes());
    out.extend_from_slice(&kem_ct);
    out.extend_from_slice(&aead_payload);
    Ok(out)
}

/*
 * Decrypt a blob produced by [`encrypt_for`] using `keyring`.
 *
 * The leading byte selects the `EncryptionType` (and thus which keypair to use
 * from the keyring); for the current ML-KEM variants that is `kem_secret_key`.
 * Returns `DecryptionFailed` on any malformed input or authentication failure.
 *
 * Requires the `mlkem-tls` and `hkdf` features, plus the AEAD feature backing
 * the blob's algorithm.
 */
#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
pub fn decrypt_with(blob: &[u8], keyring: &Keyring, aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < 3 {
        return Err(CryptoError::DecryptionFailed);
    }
    let enc_type = EncryptionType::from_byte(blob[0]).ok_or(CryptoError::DecryptionFailed)?;
    let kem_ct_len = u16::from_be_bytes([blob[1], blob[2]]) as usize;
    let kem_end = 3usize
        .checked_add(kem_ct_len)
        .ok_or(CryptoError::DecryptionFailed)?;
    let kem_ct = blob.get(3..kem_end).ok_or(CryptoError::DecryptionFailed)?;
    let aead_payload = blob.get(kem_end..).ok_or(CryptoError::DecryptionFailed)?;

    let shared_secret = HybridKem::decapsulate(&keyring.kem_secret_key, kem_ct)?;
    let key = derive_encryption_key(&shared_secret, ENC_KDF_SALT, ENC_KDF_CONTEXT)?;
    aead_open(enc_type, key, aead_payload, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_type_byte_roundtrip() {
        for t in [
            EncryptionType::MlKemChaCha20Poly1305,
            EncryptionType::MlKemAes256Gcm,
        ] {
            assert_eq!(EncryptionType::from_byte(t.to_byte()), Some(t));
        }
        assert_eq!(EncryptionType::from_byte(0x00), None);
        assert_eq!(EncryptionType::from_byte(0xFF), None);
    }

    #[cfg(all(feature = "mlkem-tls", feature = "hkdf", feature = "chacha20poly1305"))]
    #[test]
    fn encrypt_for_roundtrip() -> Result<(), CryptoError> {
        let kr = Keyring::generate();
        let blob = encrypt_for(
            EncryptionType::MlKemChaCha20Poly1305,
            &kr.public_key_bundle(),
            b"secret payload",
            b"aad",
        )?;
        assert_eq!(blob[0], EncryptionType::ML_KEM_CHACHA20POLY1305);

        let pt = decrypt_with(&blob, &kr, b"aad")?;
        assert_eq!(pt, b"secret payload");
        Ok(())
    }

    #[cfg(all(feature = "mlkem-tls", feature = "hkdf", feature = "chacha20poly1305"))]
    #[test]
    fn decrypt_with_wrong_keyring_fails() -> Result<(), CryptoError> {
        let kr = Keyring::generate();
        let other = Keyring::generate();
        let blob = encrypt_for(
            EncryptionType::MlKemChaCha20Poly1305,
            &kr.public_key_bundle(),
            b"secret",
            b"aad",
        )?;
        assert!(decrypt_with(&blob, &other, b"aad").is_err());
        Ok(())
    }

    #[cfg(all(feature = "mlkem-tls", feature = "hkdf", feature = "chacha20poly1305"))]
    #[test]
    fn decrypt_with_wrong_aad_fails() -> Result<(), CryptoError> {
        let kr = Keyring::generate();
        let blob = encrypt_for(
            EncryptionType::MlKemChaCha20Poly1305,
            &kr.public_key_bundle(),
            b"secret",
            b"right",
        )?;
        assert!(decrypt_with(&blob, &kr, b"wrong").is_err());
        Ok(())
    }

    #[cfg(all(feature = "mlkem-tls", feature = "hkdf", feature = "chacha20poly1305"))]
    #[test]
    fn decrypt_with_malformed_fails() {
        let kr = Keyring::generate();
        assert!(decrypt_with(b"", &kr, b"").is_err());
        assert!(decrypt_with(&[0x01, 0x00], &kr, b"").is_err());
        // Unknown algorithm byte.
        assert!(decrypt_with(&[0x7F, 0x00, 0x00], &kr, b"").is_err());
    }
}
