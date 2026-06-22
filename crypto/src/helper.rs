use crate::error::CryptoError;

#[cfg(all(feature = "mlkem-tls", feature = "chacha20poly1305", feature = "hkdf"))]
use crate::aead::{AeadDecrypt, AeadEncrypt, ChaCha20Poly1305};
#[cfg(all(feature = "mlkem-tls", feature = "chacha20poly1305", feature = "hkdf"))]
use crate::kdf::derive_encryption_key;
#[cfg(all(feature = "mlkem-tls", feature = "chacha20poly1305", feature = "hkdf"))]
use crate::kem::HybridKem;
#[cfg(all(feature = "mlkem-tls", feature = "chacha20poly1305", feature = "hkdf"))]
use crate::keypair::{Keyring, PublicKeyBundle};
#[cfg(all(feature = "mlkem-tls", feature = "chacha20poly1305", feature = "hkdf"))]
use rand_core::RngCore;

pub struct RecipientEntry {
    pub kem_ciphertext: Vec<u8>,
    pub encrypted_key: Vec<u8>,
}

/*
 * A payload encrypted for multiple recipients.
 *
 * Any recipient who possesses the corresponding `KemPrivateKey` can decrypt the message.
 */
pub struct MultiEncryptedMessage {
    pub recipients: Vec<RecipientEntry>,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl MultiEncryptedMessage {
    /*
     * Serialize into a compact byte vector.
     *
     * Format:
     * - `num_recipients: u16`
     * - for each recipient:
     *   - `kem_ct_len: u16` | `kem_ciphertext`
     *   - `ek_len: u16`     | `encrypted_key`
     * - `nonce: 24 bytes`
     * - `ciphertext` (remaining)
     */
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.recipients.len() as u16).to_be_bytes());
        for r in &self.recipients {
            out.extend_from_slice(&(r.kem_ciphertext.len() as u16).to_be_bytes());
            out.extend_from_slice(&r.kem_ciphertext);
            out.extend_from_slice(&(r.encrypted_key.len() as u16).to_be_bytes());
            out.extend_from_slice(&r.encrypted_key);
        }
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Deserialize from bytes produced by `to_bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut offset = 0;
        let read_u16 = |off: &mut usize| -> Result<u16, CryptoError> {
            let slice = bytes
                .get(*off..*off + 2)
                .ok_or(CryptoError::DecryptionFailed)?;
            let arr: [u8; 2] = slice
                .try_into()
                .map_err(|_| CryptoError::DecryptionFailed)?;
            *off += 2;
            Ok(u16::from_be_bytes(arr))
        };

        let num = read_u16(&mut offset)? as usize;
        let mut recipients = Vec::with_capacity(num);
        for _ in 0..num {
            let klen = read_u16(&mut offset)? as usize;
            let kem_ct = bytes
                .get(offset..offset + klen)
                .ok_or(CryptoError::DecryptionFailed)?
                .to_vec();
            offset += klen;

            let elen = read_u16(&mut offset)? as usize;
            let enc_key = bytes
                .get(offset..offset + elen)
                .ok_or(CryptoError::DecryptionFailed)?
                .to_vec();
            offset += elen;

            recipients.push(RecipientEntry {
                kem_ciphertext: kem_ct,
                encrypted_key: enc_key,
            });
        }

        let nonce: [u8; 24] = bytes
            .get(offset..offset + 24)
            .ok_or(CryptoError::DecryptionFailed)?
            .try_into()
            .map_err(|_| CryptoError::DecryptionFailed)?;
        offset += 24;

        let ciphertext = bytes
            .get(offset..)
            .ok_or(CryptoError::DecryptionFailed)?
            .to_vec();

        Ok(Self {
            recipients,
            nonce,
            ciphertext,
        })
    }
}

/*
 * Encrypt `plaintext` for every recipient in `entities`.
 *
 * Internally generates a fresh content-encryption key, encrypts the payload
 * with ChaCha20-Poly1305, then KEM-encapsulates and wraps the key for each
 * recipient. The returned `MultiEncryptedMessage` can be decrypted by any
 * entity whose keyring contains the corresponding private KEM key.
 *
 * Requires the `pqc` and `chacha20poly1305` features.
 */
#[cfg(all(feature = "mlkem-tls", feature = "chacha20poly1305", feature = "hkdf"))]
pub fn encrypt_multi(
    plaintext: &[u8],
    aad: &[u8],
    entities: &[PublicKeyBundle],
) -> Result<MultiEncryptedMessage, CryptoError> {
    let mut cek = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut cek);

    let cipher = ChaCha20Poly1305::new(cek);
    let encrypted_payload = cipher.encrypt(plaintext, aad)?;

    let nonce: [u8; 24] = encrypted_payload[..24]
        .try_into()
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let ciphertext = encrypted_payload[24..].to_vec();

    let mut recipients = Vec::with_capacity(entities.len());
    for entity in entities {
        let enc = HybridKem::encapsulate(&entity.kem_public_key)?;
        let wrap_key = derive_encryption_key(
            &enc.shared_secret,
            b"mtp-multi-key-wrap",
            b"multi-recipient",
        )?;

        let wrap_cipher = ChaCha20Poly1305::new(wrap_key);
        let encrypted_key = wrap_cipher.encrypt(&cek, b"")?;

        recipients.push(RecipientEntry {
            kem_ciphertext: enc.ciphertext,
            encrypted_key,
        });
    }

    Ok(MultiEncryptedMessage {
        recipients,
        nonce,
        ciphertext,
    })
}

/*
 * Decrypt a `MultiEncryptedMessage` using the recipient's `Keyring`.
 *
 * Tries each `RecipientEntry` until one succeeds with the given keyring's
 * KEM secret key. Returns the original plaintext.
 */
#[cfg(all(feature = "mlkem-tls", feature = "chacha20poly1305", feature = "hkdf"))]
pub fn decrypt_multi(
    msg: &MultiEncryptedMessage,
    aad: &[u8],
    keyring: &Keyring,
) -> Result<Vec<u8>, CryptoError> {
    for entry in &msg.recipients {
        let ss = match HybridKem::decapsulate(&keyring.kem_secret_key, &entry.kem_ciphertext) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let wrap_key = derive_encryption_key(&ss, b"mtp-multi-key-wrap", b"multi-recipient")?;
        let wrap_cipher = ChaCha20Poly1305::new(wrap_key);
        let cek = match wrap_cipher.decrypt(&entry.encrypted_key, b"") {
            Ok(k) => k,
            Err(_) => continue,
        };
        let cek_arr: [u8; 32] = cek.try_into().map_err(|_| CryptoError::DecryptionFailed)?;

        let mut full_ct = Vec::with_capacity(24 + msg.ciphertext.len());
        full_ct.extend_from_slice(&msg.nonce);
        full_ct.extend_from_slice(&msg.ciphertext);

        let data_cipher = ChaCha20Poly1305::new(cek_arr);
        return data_cipher.decrypt(&full_ct, aad);
    }
    Err(CryptoError::DecryptionFailed)
}


