pub mod aead;
pub mod auth;
pub mod error;
pub mod keypair;

#[cfg(not(target_arch = "wasm32"))]
use std::sync::Once;

#[cfg(not(target_arch = "wasm32"))]
static CRYPTO_INIT: Once = Once::new();

#[cfg(feature = "sha2")]
pub mod hash;

#[cfg(feature = "hkdf")]
pub mod kdf;

#[cfg(any(feature = "ed25519-dalek", feature = "ml-dsa"))]
pub mod sign;

#[cfg(all(feature = "ed25519-dalek", feature = "ml-dsa", feature = "parallel"))]
pub mod sign_parallel;

#[cfg(any(feature = "ed25519-dalek", feature = "ml-dsa"))]
pub use sign::SigAlgorithm;

#[cfg(feature = "mlkem-tls")]
pub mod kem;

pub mod enc;

pub mod helper;

#[cfg(feature = "tls")]
pub mod tls;

pub use aead::{AeadCipher, AeadDecrypt, AeadEncrypt};
pub use error::CryptoError;
pub use keypair::{
    EncryptionPrivateKey, EncryptionPublicKey, KemPrivateKey, KemPublicKey, Keyring,
    PublicKeyBundle, SignaturePqPrivateKey, SignaturePqPublicKey, SignaturePrivateKey,
    SignaturePublicKey,
};

#[cfg(feature = "chacha20poly1305")]
pub use aead::{ChaCha20Poly1305, XChaCha20Poly1305};

#[cfg(feature = "aes-gcm")]
pub use aead::Aes256Gcm;

#[cfg(feature = "ed25519-dalek")]
pub use sign::{Ed25519Signer, SignatureScheme, verify_ed25519};

#[cfg(feature = "ml-dsa")]
pub use sign::{MlDsaSigner, verify_ml_dsa};

#[cfg(all(feature = "ed25519-dalek", feature = "ml-dsa"))]
pub use sign::{DualSignature, DualSigner, sign_dual};

#[cfg(feature = "sha2")]
pub use hash::{Sha256Hasher, sha256, sha256_double};

#[cfg(feature = "hkdf")]
pub use kdf::{derive_encryption_key, hkdf_expand, hkdf_extract};

#[cfg(feature = "mlkem-tls")]
pub use kem::{Encapsulated, HybridKem};

pub use enc::EncryptionType;

/// Install Rustls' AWS-LC provider once for the entire process.
///
/// Rustls only accepts one process-wide default provider. Calling this helper
/// from every TLS entry point makes that initialization idempotent.
#[cfg(not(target_arch = "wasm32"))]
pub fn ensure_crypto_provider() {
    CRYPTO_INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

pub use helper::{ENCRYPT_DOMAIN, KEY_WRAP_DOMAIN};

#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
pub use helper::{
    MAX_RECIPIENTS, MultiEncryptedMessage, RecipientEntry, decrypt_multi_for, encrypt_multi_for,
};

/* ================================ TESTS ================================ */
#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "chacha20poly1305")]
    #[test]
    fn aead_encrypt_decrypt() -> Result<(), CryptoError> {
        use crate::aead::{AeadDecrypt, AeadEncrypt, ChaCha20Poly1305};
        let key = [0xAB; 32];
        let cipher = ChaCha20Poly1305::new(key);
        let ct = cipher.encrypt(b"hello world", b"aad")?;
        let pt = cipher.decrypt(&ct, b"aad")?;
        assert_eq!(pt, b"hello world");
        Ok(())
    }

    #[cfg(feature = "chacha20poly1305")]
    #[test]
    fn aead_wrong_key_fails() {
        use crate::aead::{AeadDecrypt, AeadEncrypt, ChaCha20Poly1305};
        let cipher_a = ChaCha20Poly1305::new([0xAB; 32]);
        let cipher_b = ChaCha20Poly1305::new([0xCD; 32]);
        let ct = cipher_a
            .encrypt(b"hello", b"")
            .expect("encryption should succeed");
        assert!(cipher_b.decrypt(&ct, b"").is_err());
    }

    #[cfg(feature = "chacha20poly1305")]
    #[test]
    fn aead_wrong_aad_fails() {
        use crate::aead::{AeadDecrypt, AeadEncrypt, ChaCha20Poly1305};
        let cipher = ChaCha20Poly1305::new([0xAB; 32]);
        let ct = cipher
            .encrypt(b"hello", b"correct-aad")
            .expect("encryption should succeed");
        assert!(cipher.decrypt(&ct, b"wrong-aad").is_err());
    }

    #[cfg(feature = "ed25519-dalek")]
    #[test]
    fn ed25519_sign_verify() {
        let (signer, sk, pk) = Ed25519Signer::generate();
        let msg = b"test message";
        let sig = signer.sign(msg).expect("signing should succeed");
        signer
            .verify(msg, &sig)
            .expect("verification should succeed");
        verify_ed25519(&pk, msg, &sig).expect("verification should succeed");

        let loaded = Ed25519Signer::new(&sk).expect("signer loading should succeed");
        loaded
            .verify(msg, &sig)
            .expect("verification should succeed");
    }

    #[cfg(feature = "ed25519-dalek")]
    #[test]
    fn ed25519_wrong_sig_fails() {
        let (signer, _, pk) = Ed25519Signer::generate();
        let msg = b"test message";
        let sig = signer.sign(msg).expect("signing should succeed");
        assert!(verify_ed25519(&pk, b"wrong message", &sig).is_err());
    }

    #[cfg(feature = "ml-dsa")]
    #[test]
    fn mldsa_sign_verify() {
        let (signer, sk, pk) = MlDsaSigner::generate();
        let msg = b"test message";
        let sig = signer.sign(msg).expect("signing should succeed");
        signer
            .verify(msg, &sig)
            .expect("verification should succeed");
        verify_ml_dsa(&pk, msg, &sig).expect("verification should succeed");

        let loaded = MlDsaSigner::new(&sk, &pk).expect("signer loading should succeed");
        loaded
            .verify(msg, &sig)
            .expect("verification should succeed");
    }

    #[cfg(feature = "ml-dsa")]
    #[test]
    fn mldsa_wrong_sig_fails() {
        let (signer, _, pk) = MlDsaSigner::generate();
        let msg = b"test message";
        let sig = signer.sign(msg).expect("signing should succeed");
        assert!(verify_ml_dsa(&pk, b"wrong message", &sig).is_err());
    }

    #[cfg(all(feature = "ed25519-dalek", feature = "ml-dsa"))]
    #[test]
    fn dual_sign_verify() {
        use crate::sign::sign_dual;

        let (ed_signer, _, _) = Ed25519Signer::generate();
        let (ml_signer, _, _) = MlDsaSigner::generate();
        let dual = sign_dual(ed_signer.signing_key(), ml_signer.signing_key(), b"msg")
            .expect("dual signing should succeed");
        dual.verify(ed_signer.verifying_key(), ml_signer.verifying_key(), b"msg")
            .expect("dual verification should succeed");
    }

    #[cfg(all(feature = "ed25519-dalek", feature = "ml-dsa"))]
    #[test]
    fn dual_wrong_message_fails() {
        use crate::sign::sign_dual;

        let (ed_signer, _, _) = Ed25519Signer::generate();
        let (ml_signer, _, _) = MlDsaSigner::generate();
        let dual = sign_dual(ed_signer.signing_key(), ml_signer.signing_key(), b"msg")
            .expect("dual signing should succeed");
        assert!(
            dual.verify(
                ed_signer.verifying_key(),
                ml_signer.verifying_key(),
                b"wrong"
            )
            .is_err()
        );
    }

    #[cfg(all(feature = "ed25519-dalek", feature = "ml-dsa"))]
    #[test]
    fn dual_scheme_implements_signature_trait() {
        use crate::sign::SignatureScheme;

        let (signer, _, _, _, _) = DualSigner::generate();
        let signature = signer.sign(b"msg").expect("dual signing should succeed");
        assert_eq!(signer.algorithm(), SigAlgorithm::DUAL);
        signer
            .verify(b"msg", &signature)
            .expect("dual verification should succeed");
        assert!(signer.verify(b"wrong", &signature).is_err());
    }

    #[cfg(feature = "hkdf")]
    #[test]
    fn hkdf_expand_produces_key() {
        let key = derive_encryption_key(b"ikm", b"salt", b"context")
            .expect("key derivation should succeed");
        assert_eq!(key.len(), 32);

        let expanded =
            hkdf_expand(b"ikm", b"salt", b"info", 64).expect("HKDF expansion should succeed");
        assert_eq!(expanded.len(), 64);
    }

    #[cfg(feature = "hkdf")]
    #[test]
    fn hkdf_different_info_different_key() {
        let a = derive_encryption_key(b"ikm", b"salt", b"info-a")
            .expect("key derivation should succeed");
        let b = derive_encryption_key(b"ikm", b"salt", b"info-b")
            .expect("key derivation should succeed");
        assert_ne!(a, b);
    }

    #[cfg(feature = "sha2")]
    #[test]
    fn sha256_hashes() {
        let h = sha256(b"hello");
        assert_eq!(h.len(), 32);

        let h2 = sha256_double(b"hello");
        assert_eq!(h2.len(), 32);
        assert_ne!(h, h2);
    }

    #[cfg(feature = "sha2")]
    #[test]
    fn sha256_deterministic() {
        assert_eq!(sha256(b"hello"), sha256(b"hello"));
    }

    #[cfg(feature = "sha2")]
    #[test]
    fn sha256_hasher_incremental() {
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"hel");
        hasher.update(b"lo");
        let h = hasher.finalize();
        assert_eq!(h, sha256(b"hello"));
    }

    #[test]
    fn key_types_roundtrip() {
        let data = vec![1u8, 2, 3, 4];
        let enc_pk = EncryptionPublicKey::new(data.clone());
        assert_eq!(enc_pk.as_bytes(), &data);
        let enc_sk = EncryptionPrivateKey::new(data.clone());
        assert_eq!(enc_sk.as_bytes(), &data);

        let sig_pk = SignaturePublicKey::new(data.clone());
        assert_eq!(sig_pk.as_bytes(), &data);
        let sig_sk = SignaturePrivateKey::new(data.clone());
        assert_eq!(sig_sk.as_bytes(), &data);

        let kem_pk = KemPublicKey::new(data.clone());
        assert_eq!(kem_pk.as_bytes(), &data);
        let kem_sk = KemPrivateKey::new(data.clone());
        assert_eq!(kem_sk.as_bytes(), &data);

        let sig_pq_pk = SignaturePqPublicKey::new(data.clone());
        assert_eq!(sig_pq_pk.as_bytes(), &data);
        let sig_pq_sk = SignaturePqPrivateKey::new(data.clone());
        assert_eq!(sig_pq_sk.as_bytes(), &data);
    }

    #[cfg(all(feature = "mlkem-tls", feature = "ml-dsa", feature = "ed25519-dalek"))]
    #[test]
    fn keyring_generate_and_bundle() {
        let kr = Keyring::generate();
        let bundle = kr.public_key_bundle();
        assert!(!bundle.kem_public_key.as_bytes().is_empty());
        assert!(!bundle.sig_pq_public_key.as_bytes().is_empty());
        assert!(!bundle.sig_cl_public_key.as_bytes().is_empty());
    }

    #[cfg(all(feature = "mlkem-tls", feature = "ml-dsa", feature = "ed25519-dalek"))]
    #[test]
    fn keyring_serialize_roundtrip() {
        let kr = Keyring::generate();
        let bytes = kr.to_bytes();
        let loaded = Keyring::from_bytes(&bytes).expect("keyring roundtrip should succeed");
        assert_eq!(
            kr.kem_public_key.as_bytes(),
            loaded.kem_public_key.as_bytes()
        );
        assert_eq!(
            kr.sig_pq_public_key.as_bytes(),
            loaded.sig_pq_public_key.as_bytes()
        );
        assert_eq!(
            kr.sig_cl_public_key.as_bytes(),
            loaded.sig_cl_public_key.as_bytes()
        );
    }

    #[cfg(all(feature = "mlkem-tls", feature = "ml-dsa", feature = "ed25519-dalek"))]
    #[test]
    fn public_key_bundle_serialize_roundtrip() {
        let kr = Keyring::generate();
        let bundle = kr.public_key_bundle();
        let bytes = bundle.as_bytes();
        let loaded = PublicKeyBundle::from_bytes(&bytes).expect("bundle roundtrip should succeed");
        assert_eq!(
            bundle.kem_public_key.as_bytes(),
            loaded.kem_public_key.as_bytes()
        );
        assert_eq!(
            bundle.sig_pq_public_key.as_bytes(),
            loaded.sig_pq_public_key.as_bytes()
        );
        assert_eq!(
            bundle.sig_cl_public_key.as_bytes(),
            loaded.sig_cl_public_key.as_bytes()
        );
    }

    #[cfg(feature = "mlkem-tls")]
    #[test]
    fn hybrid_kem_roundtrip() {
        let (sk, pk) = HybridKem::generate_keypair();
        let enc = HybridKem::encapsulate(&pk).expect("encapsulation should succeed");
        let ss =
            HybridKem::decapsulate(&sk, &enc.ciphertext).expect("decapsulation should succeed");
        assert_eq!(enc.shared_secret, ss);
    }

    #[cfg(all(
        feature = "mlkem-tls",
        feature = "hkdf",
        feature = "ml-dsa",
        feature = "ed25519-dalek"
    ))]
    fn multi_envelope_roundtrip(encryption_type: EncryptionType) {
        use crate::helper::{decrypt_multi_for, encrypt_multi_for};
        use crate::keypair::Keyring;

        let kr = Keyring::generate();
        let entities = vec![kr.public_key_bundle()];
        let msg = b"secret data";
        let ct = encrypt_multi_for(encryption_type, 7, msg, &entities)
            .expect("multi encrypt should succeed");
        let pt = decrypt_multi_for(&ct, 7, &kr).expect("multi decrypt should succeed");
        assert_eq!(pt, msg);
    }

    #[cfg(all(
        feature = "mlkem-tls",
        feature = "hkdf",
        feature = "ml-dsa",
        feature = "ed25519-dalek",
        feature = "chacha20poly1305"
    ))]
    #[test]
    fn chacha20_multi_envelope_roundtrip() {
        multi_envelope_roundtrip(EncryptionType::MlKemChaCha20Poly1305);
    }

    #[cfg(all(
        feature = "mlkem-tls",
        feature = "hkdf",
        feature = "ml-dsa",
        feature = "ed25519-dalek",
        feature = "aes-gcm"
    ))]
    #[test]
    fn aes_gcm_multi_envelope_roundtrip() {
        multi_envelope_roundtrip(EncryptionType::MlKemAes256Gcm);
    }
}
