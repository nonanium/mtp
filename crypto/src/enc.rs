#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
use crate::error::CryptoError;

#[cfg(feature = "mlkem-tls")]
use crate::kem::HybridKem;

/*
 * Algorithm selector for encrypted values.
 *
 * Mirrors `SigAlgorithm` for signatures: a single marking byte identifies the
 * key-encapsulation mechanism and the AEAD used to seal a container. The byte
 * is stored as the first byte of every encrypted envelope so the decryptor can pick
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

    /// The marking byte written at the front of an encrypted envelope.
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

    /// Size of the content-encryption key wrapped for each recipient.
    pub const CONTENT_ENCRYPTION_KEY_LEN: usize = 32;

    /// The fixed-size ciphertext emitted by the KEM selected by this suite.
    pub const fn kem_ciphertext_len(self) -> usize {
        match self {
            Self::MlKemChaCha20Poly1305 | Self::MlKemAes256Gcm => {
                #[cfg(feature = "mlkem-tls")]
                {
                    HybridKem::ciphertext_len()
                }
                #[cfg(not(feature = "mlkem-tls"))]
                {
                    0
                }
            }
        }
    }

    /// Bytes the selected AEAD prepends/appends to an encrypted payload.
    pub const fn aead_overhead(self) -> usize {
        match self {
            Self::MlKemChaCha20Poly1305 => {
                crate::aead::XCHACHA20POLY1305_NONCE_LEN + crate::aead::AUTH_TAG_LEN
            }
            Self::MlKemAes256Gcm => crate::aead::AES256GCM_NONCE_LEN + crate::aead::AUTH_TAG_LEN,
        }
    }

    /// Total output length for an encrypted plaintext of `plaintext_len` bytes.
    pub const fn encrypted_len(self, plaintext_len: usize) -> usize {
        plaintext_len.saturating_add(self.aead_overhead())
    }

    /// Minimum valid AEAD output length for this suite.
    pub const fn minimum_ciphertext_len(self) -> usize {
        self.encrypted_len(0)
    }

    /// The size of a wrapped 32-byte content key for this suite.
    pub const fn wrapped_key_len(self) -> usize {
        self.encrypted_len(Self::CONTENT_ENCRYPTION_KEY_LEN)
    }
}

/*
 * Seal `plaintext` with a 32-byte AEAD key chosen by `enc_type`.
 *
 * Returns `EncryptionFailed` when the selected AEAD's feature is not compiled in.
 */
#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
#[allow(unused_variables)]
pub fn seal_with_key(
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
            crate::aead::XChaCha20Poly1305::new(key).encrypt(plaintext, aad)
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
pub fn open_with_key(
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
            crate::aead::XChaCha20Poly1305::new(key).decrypt(ciphertext, aad)
        }
        #[cfg(feature = "aes-gcm")]
        EncryptionType::MlKemAes256Gcm => crate::aead::Aes256Gcm::new(key).decrypt(ciphertext, aad),
        #[allow(unreachable_patterns)]
        _ => Err(CryptoError::DecryptionFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "mlkem-tls")]
    #[test]
    fn envelope_parser_uses_suite_dependent_fixed_widths() {
        use crate::helper::{MultiEncryptedMessage, RecipientEntry};

        let suites = [
            EncryptionType::MlKemChaCha20Poly1305,
            EncryptionType::MlKemAes256Gcm,
        ];
        assert_ne!(suites[0].wrapped_key_len(), suites[1].wrapped_key_len());

        for (index, suite) in suites.into_iter().enumerate() {
            let marker = u8::try_from(index).unwrap();
            let message = MultiEncryptedMessage {
                encryption_type: suite,
                purpose: 0xA5,
                recipients: vec![RecipientEntry {
                    kem_ciphertext: vec![0x10 + marker; suite.kem_ciphertext_len()],
                    encrypted_key: vec![0x20 + marker; suite.wrapped_key_len()],
                }],
                ciphertext: vec![0x30 + marker; suite.minimum_ciphertext_len() + 3],
            };
            let encoded = message.to_bytes().expect("synthetic envelope is valid");
            let kem_end = 4 + suite.kem_ciphertext_len();
            let wrapped_end = kem_end + suite.wrapped_key_len();

            assert_eq!(&encoded[..4], &[suite.to_byte(), 0xA5, 0, 1]);
            assert_eq!(&encoded[4..kem_end], message.recipients[0].kem_ciphertext);
            assert_eq!(
                &encoded[kem_end..wrapped_end],
                message.recipients[0].encrypted_key
            );
            assert_eq!(&encoded[wrapped_end..], message.ciphertext);
            assert_eq!(
                MultiEncryptedMessage::from_bytes(&encoded)
                    .expect("suite-specific envelope should parse"),
                message
            );
        }
    }

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

    #[test]
    fn suite_lengths_are_derived_from_the_selected_primitives() {
        assert_eq!(
            EncryptionType::MlKemChaCha20Poly1305.wrapped_key_len(),
            EncryptionType::CONTENT_ENCRYPTION_KEY_LEN
                + crate::aead::XCHACHA20POLY1305_NONCE_LEN
                + crate::aead::AUTH_TAG_LEN
        );
        assert_eq!(
            EncryptionType::MlKemAes256Gcm.wrapped_key_len(),
            EncryptionType::CONTENT_ENCRYPTION_KEY_LEN
                + crate::aead::AES256GCM_NONCE_LEN
                + crate::aead::AUTH_TAG_LEN
        );
    }
}
