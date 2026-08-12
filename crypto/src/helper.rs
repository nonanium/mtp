// Canonical multi-recipient encryption envelopes.

use crate::enc::EncryptionType;
use crate::error::CryptoError;

#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
use crate::enc::{open_with_key, seal_with_key};
#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
use crate::kdf::derive_encryption_key;
#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
use crate::kem::HybridKem;
#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
use crate::keypair::{Keyring, PublicKeyBundle};
#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
use rand::Rng;
#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
use zeroize::Zeroizing;

pub const ENCRYPT_DOMAIN: &[u8] = b"MTP-DATA-ENC-1";
pub const KEY_WRAP_DOMAIN: &[u8] = b"MTP-DATA-WRAP-1";
/// Operational cap for recipient entries accepted in one envelope.
///
/// The wire count remains a `u16` for format stability, but decapsulation is
/// intentionally bounded because each entry can require a KEM operation.
pub const MAX_RECIPIENTS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientEntry {
    pub kem_ciphertext: Vec<u8>,
    pub encrypted_key: Vec<u8>,
}

/// The envelope body used by `DataValue::Encrypted`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiEncryptedMessage {
    pub encryption_type: EncryptionType,
    pub purpose: u8,
    pub recipients: Vec<RecipientEntry>,
    /// The AEAD output, including its nonce as defined by the selected suite.
    pub ciphertext: Vec<u8>,
}

impl MultiEncryptedMessage {
    /// Serialize the envelope body without redundant per-recipient lengths.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let kem_len = self.encryption_type.kem_ciphertext_len();
        let wrapped_len = self.encryption_type.wrapped_key_len();
        let count =
            u16::try_from(self.recipients.len()).map_err(|_| CryptoError::EncryptionFailed)?;
        if self.recipients.is_empty()
            || self.recipients.len() > MAX_RECIPIENTS
            || self.ciphertext.len() < self.encryption_type.minimum_ciphertext_len()
            || self
                .recipients
                .iter()
                .any(|r| r.kem_ciphertext.len() != kem_len || r.encrypted_key.len() != wrapped_len)
        {
            return Err(CryptoError::MalformedEnvelope);
        }

        let mut out = Vec::new();
        out.push(self.encryption_type.to_byte());
        out.push(self.purpose);
        out.extend_from_slice(&count.to_be_bytes());
        for recipient in &self.recipients {
            out.extend_from_slice(&recipient.kem_ciphertext);
            out.extend_from_slice(&recipient.encrypted_key);
        }
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    /// Parse the canonical envelope body.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 4 {
            return Err(CryptoError::MalformedEnvelope);
        }
        let encryption_type =
            EncryptionType::from_byte(bytes[0]).ok_or(CryptoError::UnknownAlgorithm)?;
        let purpose = bytes[1];
        let count = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if count == 0 || count > MAX_RECIPIENTS {
            return Err(CryptoError::MalformedEnvelope);
        }
        let entry_len = encryption_type.kem_ciphertext_len() + encryption_type.wrapped_key_len();
        let entries_len = count
            .checked_mul(entry_len)
            .ok_or(CryptoError::MalformedEnvelope)?;
        let start = 4usize;
        let end = start
            .checked_add(entries_len)
            .ok_or(CryptoError::MalformedEnvelope)?;
        let ciphertext_len = bytes
            .len()
            .checked_sub(end)
            .ok_or(CryptoError::MalformedEnvelope)?;
        if ciphertext_len < encryption_type.minimum_ciphertext_len() {
            return Err(CryptoError::MalformedEnvelope);
        }

        let mut offset = start;
        let mut recipients = Vec::with_capacity(count);
        for _ in 0..count {
            let kem_end = offset + encryption_type.kem_ciphertext_len();
            let wrapped_end = kem_end + encryption_type.wrapped_key_len();
            recipients.push(RecipientEntry {
                kem_ciphertext: bytes[offset..kem_end].to_vec(),
                encrypted_key: bytes[kem_end..wrapped_end].to_vec(),
            });
            offset = wrapped_end;
        }

        Ok(Self {
            encryption_type,
            purpose,
            recipients,
            ciphertext: bytes[offset..].to_vec(),
        })
    }
}

#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
fn wrap_aad(encryption_type: EncryptionType, purpose: u8, kem_ciphertext: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(KEY_WRAP_DOMAIN.len() + 2 + kem_ciphertext.len());
    aad.extend_from_slice(KEY_WRAP_DOMAIN);
    aad.push(encryption_type.to_byte());
    aad.push(purpose);
    aad.extend_from_slice(kem_ciphertext);
    aad
}

#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
fn payload_aad(message: &MultiEncryptedMessage) -> Result<Vec<u8>, CryptoError> {
    let count =
        u16::try_from(message.recipients.len()).map_err(|_| CryptoError::MalformedEnvelope)?;
    let mut aad = Vec::new();
    aad.extend_from_slice(ENCRYPT_DOMAIN);
    aad.push(message.encryption_type.to_byte());
    aad.push(message.purpose);
    aad.extend_from_slice(&count.to_be_bytes());
    for recipient in &message.recipients {
        aad.extend_from_slice(&recipient.kem_ciphertext);
        aad.extend_from_slice(&recipient.encrypted_key);
    }
    Ok(aad)
}

/// Encrypt a value for one or more recipients using the canonical envelope.
#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
pub fn encrypt_multi_for(
    encryption_type: EncryptionType,
    purpose: u8,
    plaintext: &[u8],
    entities: &[PublicKeyBundle],
) -> Result<MultiEncryptedMessage, CryptoError> {
    if entities.is_empty() {
        return Err(CryptoError::NoRecipients);
    }
    if entities.len() > MAX_RECIPIENTS {
        return Err(CryptoError::EncryptionFailed);
    }

    let mut cek = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(cek.as_mut());

    let mut recipients = Vec::with_capacity(entities.len());
    for entity in entities {
        let enc = HybridKem::encapsulate(&entity.kem_public_key)?;
        let wrap_key = Zeroizing::new(derive_encryption_key(
            &enc.shared_secret,
            KEY_WRAP_DOMAIN,
            &[encryption_type.to_byte(), purpose],
        )?);
        let aad = wrap_aad(encryption_type, purpose, &enc.ciphertext);
        let encrypted_key = seal_with_key(encryption_type, *wrap_key, cek.as_ref(), &aad)?;
        recipients.push(RecipientEntry {
            kem_ciphertext: enc.ciphertext,
            encrypted_key,
        });
    }

    let mut message = MultiEncryptedMessage {
        encryption_type,
        purpose,
        recipients,
        ciphertext: Vec::new(),
    };
    let aad = payload_aad(&message)?;
    message.ciphertext = seal_with_key(encryption_type, *cek, plaintext, &aad)?;
    Ok(message)
}

/// Decrypt a canonical envelope for a recipient in `keyring`.
#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
pub fn decrypt_multi_for(
    message: &MultiEncryptedMessage,
    purpose: u8,
    keyring: &Keyring,
) -> Result<Vec<u8>, CryptoError> {
    if message.recipients.is_empty()
        || message.recipients.len() > MAX_RECIPIENTS
        || message.purpose != purpose
        || message.ciphertext.len() < message.encryption_type.minimum_ciphertext_len()
        || message.recipients.iter().any(|recipient| {
            recipient.kem_ciphertext.len() != message.encryption_type.kem_ciphertext_len()
                || recipient.encrypted_key.len() != message.encryption_type.wrapped_key_len()
        })
    {
        return Err(CryptoError::MalformedEnvelope);
    }

    let payload_aad = payload_aad(message)?;
    for entry in &message.recipients {
        let shared_secret =
            match HybridKem::decapsulate(&keyring.kem_secret_key, &entry.kem_ciphertext) {
                Ok(secret) => secret,
                Err(_) => continue,
            };
        let wrap_key = Zeroizing::new(derive_encryption_key(
            &shared_secret,
            KEY_WRAP_DOMAIN,
            &[message.encryption_type.to_byte(), purpose],
        )?);
        let aad = wrap_aad(message.encryption_type, purpose, &entry.kem_ciphertext);
        let cek = match open_with_key(
            message.encryption_type,
            *wrap_key,
            &entry.encrypted_key,
            &aad,
        ) {
            Ok(key) => key,
            Err(_) => continue,
        };
        let cek: [u8; 32] = cek.try_into().map_err(|_| CryptoError::DecryptionFailed)?;
        return open_with_key(
            message.encryption_type,
            cek,
            &message.ciphertext,
            &payload_aad,
        );
    }

    Err(CryptoError::NoMatchingRecipient)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_count_is_operationally_bounded() {
        assert!(matches!(
            MultiEncryptedMessage::from_bytes(&[EncryptionType::ML_KEM_CHACHA20POLY1305, 0, 0, 65]),
            Err(CryptoError::MalformedEnvelope)
        ));
    }

    #[cfg(all(feature = "mlkem-tls", feature = "hkdf", feature = "chacha20poly1305"))]
    #[test]
    fn authenticated_envelope_fields_reject_tampering() -> Result<(), CryptoError> {
        let recipient_a = Keyring::generate();
        let recipient_b = Keyring::generate();
        let message = encrypt_multi_for(
            EncryptionType::MlKemChaCha20Poly1305,
            7,
            b"authenticated payload",
            &[
                recipient_a.public_key_bundle(),
                recipient_b.public_key_bundle(),
            ],
        )?;
        assert_eq!(
            decrypt_multi_for(&message, message.purpose, &recipient_a)?,
            b"authenticated payload"
        );

        let mut wrong_purpose = message.clone();
        wrong_purpose.purpose ^= 1;
        assert!(
            decrypt_multi_for(&wrong_purpose, wrong_purpose.purpose, &recipient_a).is_err(),
            "mutating the encryption purpose must invalidate the envelope"
        );

        let mut wrong_recipient_table = message.clone();
        wrong_recipient_table.recipients[1].encrypted_key[0] ^= 1;
        assert!(
            decrypt_multi_for(&wrong_recipient_table, message.purpose, &recipient_a).is_err(),
            "mutating another recipient's table entry must invalidate the payload"
        );

        let mut wrong_ciphertext = message;
        let last = wrong_ciphertext.ciphertext.len() - 1;
        wrong_ciphertext.ciphertext[last] ^= 1;
        assert!(
            decrypt_multi_for(&wrong_ciphertext, wrong_ciphertext.purpose, &recipient_a).is_err(),
            "mutating the ciphertext must invalidate the envelope"
        );
        Ok(())
    }

    #[cfg(feature = "mlkem-tls")]
    #[test]
    fn rejects_envelopes_without_a_complete_aead_payload() {
        let encryption_type = EncryptionType::MlKemChaCha20Poly1305;
        let message = MultiEncryptedMessage {
            encryption_type,
            purpose: 1,
            recipients: vec![RecipientEntry {
                kem_ciphertext: vec![0; encryption_type.kem_ciphertext_len()],
                encrypted_key: vec![0; encryption_type.wrapped_key_len()],
            }],
            ciphertext: vec![0; encryption_type.minimum_ciphertext_len() - 1],
        };
        assert!(matches!(
            message.to_bytes(),
            Err(CryptoError::MalformedEnvelope)
        ));

        let mut encoded = vec![encryption_type.to_byte(), 1, 0, 1];
        encoded.extend_from_slice(&vec![0; encryption_type.kem_ciphertext_len()]);
        encoded.extend_from_slice(&vec![0; encryption_type.wrapped_key_len()]);
        encoded.extend_from_slice(&vec![0; encryption_type.minimum_ciphertext_len() - 1]);
        assert!(matches!(
            MultiEncryptedMessage::from_bytes(&encoded),
            Err(CryptoError::MalformedEnvelope)
        ));
    }
}
