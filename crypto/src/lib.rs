pub mod aead;
pub mod error;
pub mod keypair;

#[cfg(feature = "sha2")]
pub mod hash;

#[cfg(feature = "hkdf")]
pub mod kdf;

#[cfg(any(feature = "ed25519-dalek", feature = "ml-dsa"))]
pub mod sign;

#[cfg(any(feature = "ed25519-dalek", feature = "ml-dsa"))]
pub use sign::SigAlgorithm;

#[cfg(feature = "mlkem-tls")]
pub mod kem;

pub mod enc;

pub mod helper;

pub use aead::{AeadCipher, AeadDecrypt, AeadEncrypt};
pub use error::CryptoError;
pub use keypair::{
    EncryptionPrivateKey, EncryptionPublicKey, KemPrivateKey, KemPublicKey, Keyring,
    PublicKeyBundle, SignaturePqPrivateKey, SignaturePqPublicKey, SignaturePrivateKey,
    SignaturePublicKey,
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
pub use kem::{Encapsulated, HybridKem};

pub use enc::EncryptionType;

#[cfg(all(feature = "mlkem-tls", feature = "hkdf"))]
pub use enc::{decrypt_with, encrypt_for};

#[cfg(all(feature = "mlkem-tls", feature = "chacha20poly1305", feature = "hkdf"))]
pub use helper::{decrypt_multi, encrypt_multi, MultiEncryptedMessage, RecipientEntry};

/* ================================ TESTS ================================ */
#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "chacha20poly1305")]
    #[test]
    fn aead_encrypt_decrypt() {
        use crate::aead::{AeadDecrypt, AeadEncrypt, ChaCha20Poly1305};
        let key = [0xAB; 32];
        let cipher = ChaCha20Poly1305::new(key);
        let ct = cipher.encrypt(b"hello world", b"aad").unwrap();
        let pt = cipher.decrypt(&ct, b"aad").unwrap();
        assert_eq!(pt, b"hello world");
    }

    #[cfg(feature = "chacha20poly1305")]
    #[test]
    fn aead_wrong_key_fails() {
        use crate::aead::{AeadDecrypt, AeadEncrypt, ChaCha20Poly1305};
        let cipher_a = ChaCha20Poly1305::new([0xAB; 32]);
        let cipher_b = ChaCha20Poly1305::new([0xCD; 32]);
        let ct = cipher_a.encrypt(b"hello", b"").unwrap();
        assert!(cipher_b.decrypt(&ct, b"").is_err());
    }

    #[cfg(feature = "chacha20poly1305")]
    #[test]
    fn aead_wrong_aad_fails() {
        use crate::aead::{AeadDecrypt, AeadEncrypt, ChaCha20Poly1305};
        let cipher = ChaCha20Poly1305::new([0xAB; 32]);
        let ct = cipher.encrypt(b"hello", b"correct-aad").unwrap();
        assert!(cipher.decrypt(&ct, b"wrong-aad").is_err());
    }

    #[cfg(feature = "ed25519-dalek")]
    #[test]
    fn ed25519_sign_verify() {
        let (signer, sk, pk) = Ed25519Signer::generate();
        let msg = b"test message";
        let sig = signer.sign(msg).unwrap();
        signer.verify(msg, &sig).unwrap();
        verify_ed25519(&pk, msg, &sig).unwrap();

        let loaded = Ed25519Signer::new(&sk).unwrap();
        loaded.verify(msg, &sig).unwrap();
    }

    #[cfg(feature = "ed25519-dalek")]
    #[test]
    fn ed25519_wrong_sig_fails() {
        let (signer, _, pk) = Ed25519Signer::generate();
        let msg = b"test message";
        let sig = signer.sign(msg).unwrap();
        assert!(verify_ed25519(&pk, b"wrong message", &sig).is_err());
    }

    #[cfg(feature = "ml-dsa")]
    #[test]
    fn mldsa_sign_verify() {
        let (signer, sk, pk) = MlDsaSigner::generate();
        let msg = b"test message";
        let sig = signer.sign(msg).unwrap();
        signer.verify(msg, &sig).unwrap();
        verify_ml_dsa(&pk, msg, &sig).unwrap();

        let loaded = MlDsaSigner::new(&sk, &pk).unwrap();
        loaded.verify(msg, &sig).unwrap();
    }

    #[cfg(feature = "ml-dsa")]
    #[test]
    fn mldsa_wrong_sig_fails() {
        let (signer, _, pk) = MlDsaSigner::generate();
        let msg = b"test message";
        let sig = signer.sign(msg).unwrap();
        assert!(verify_ml_dsa(&pk, b"wrong message", &sig).is_err());
    }

    #[cfg(all(feature = "ed25519-dalek", feature = "ml-dsa"))]
    #[test]
    fn dual_sign_verify() {
        use crate::sign::sign_dual;

        let (ed_signer, _, _) = Ed25519Signer::generate();
        let (ml_signer, _, _) = MlDsaSigner::generate();
        let dual = sign_dual(ed_signer.signing_key(), ml_signer.signing_key(), b"msg").unwrap();
        dual
            .verify(
                ed_signer.verifying_key(),
                ml_signer.verifying_key(),
                b"msg",
            )
            .unwrap();
    }

    #[cfg(all(feature = "ed25519-dalek", feature = "ml-dsa"))]
    #[test]
    fn dual_wrong_message_fails() {
        use crate::sign::sign_dual;

        let (ed_signer, _, _) = Ed25519Signer::generate();
        let (ml_signer, _, _) = MlDsaSigner::generate();
        let dual = sign_dual(ed_signer.signing_key(), ml_signer.signing_key(), b"msg").unwrap();
        assert!(dual
            .verify(ed_signer.verifying_key(), ml_signer.verifying_key(), b"wrong")
            .is_err());
    }

    #[cfg(feature = "hkdf")]
    #[test]
    fn hkdf_expand_produces_key() {
        let key = derive_encryption_key(b"ikm", b"salt", b"context").unwrap();
        assert_eq!(key.len(), 32);

        let expanded = hkdf_expand(b"ikm", b"salt", b"info", 64).unwrap();
        assert_eq!(expanded.len(), 64);
    }

    #[cfg(feature = "hkdf")]
    #[test]
    fn hkdf_different_info_different_key() {
        let a = derive_encryption_key(b"ikm", b"salt", b"info-a").unwrap();
        let b = derive_encryption_key(b"ikm", b"salt", b"info-b").unwrap();
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
        let loaded = Keyring::from_bytes(&bytes).unwrap();
        assert_eq!(kr.kem_public_key.as_bytes(), loaded.kem_public_key.as_bytes());
        assert_eq!(kr.sig_pq_public_key.as_bytes(), loaded.sig_pq_public_key.as_bytes());
        assert_eq!(kr.sig_cl_public_key.as_bytes(), loaded.sig_cl_public_key.as_bytes());
    }

    #[cfg(all(feature = "mlkem-tls", feature = "ml-dsa", feature = "ed25519-dalek"))]
    #[test]
    fn public_key_bundle_serialize_roundtrip() {
        let kr = Keyring::generate();
        let bundle = kr.public_key_bundle();
        let bytes = bundle.as_bytes();
        let loaded = PublicKeyBundle::from_bytes(&bytes).unwrap();
        assert_eq!(bundle.kem_public_key.as_bytes(), loaded.kem_public_key.as_bytes());
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
        let enc = HybridKem::encapsulate(&pk).unwrap();
        let ss = HybridKem::decapsulate(&sk, &enc.ciphertext).unwrap();
        assert_eq!(enc.shared_secret, ss);
    }

    #[cfg(all(feature = "mlkem-tls", feature = "chacha20poly1305", feature = "hkdf"))]
    #[test]
    fn encrypt_multi_roundtrip() {
        use crate::keypair::Keyring;
        use crate::helper::{encrypt_multi, decrypt_multi};

        let kr = Keyring::generate();
        let entities = vec![kr.public_key_bundle()];
        let msg = b"secret data";
        let ct = encrypt_multi(msg, b"aad", &entities).unwrap();
        let pt = decrypt_multi(&ct, b"aad", &kr).unwrap();
        assert_eq!(pt, msg);
    }
}
