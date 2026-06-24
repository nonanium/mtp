use wasm_bindgen::prelude::*;

use mtp_crypto::{
    AeadDecrypt, AeadEncrypt, Ed25519Signer, KemPrivateKey, KemPublicKey, Keyring,
    PublicKeyBundle, SignaturePqPrivateKey, SignaturePqPublicKey, SignaturePrivateKey,
    SignaturePublicKey, SignatureScheme, ChaCha20Poly1305, sha256, sha256_double,
};

use crate::error::js_error;

// ===========================================================================
// Keyring
// ===========================================================================

#[wasm_bindgen]
pub struct WasmKeyring {
    inner: Keyring,
}

#[wasm_bindgen]
impl WasmKeyring {
    /// Serialise the keyring to bytes.
    #[wasm_bindgen]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    /// Deserialise a keyring from bytes.
    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmKeyring, JsValue> {
        let inner =
            Keyring::from_bytes(bytes).map_err(|e| js_error(&format!("Keyring::from_bytes: {}", e)))?;
        Ok(Self { inner })
    }

    /// Return the public half of this keyring as a bundle.
    #[wasm_bindgen]
    pub fn public_key_bundle(&self) -> WasmPublicKeyBundle {
        WasmPublicKeyBundle {
            inner: self.inner.public_key_bundle(),
        }
    }
}

/// Build a [`Keyring`] containing only an Ed25519 keypair (no KEM, no ML-DSA).
///
/// Takes the Ed25519 secret key and public key, each 32 bytes.
/// Returns the serialised keyring bytes, suitable for passing to `WasmClient.auth_register`.
#[wasm_bindgen]
pub fn keyring_from_ed25519(secret_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    if secret_key.len() != 32 {
        return Err(js_error("ed25519 secret key must be 32 bytes"));
    }
    if public_key.len() != 32 {
        return Err(js_error("ed25519 public key must be 32 bytes"));
    }
    let keyring = Keyring::new(
        KemPublicKey::new(vec![]),
        KemPrivateKey::new(vec![]),
        SignaturePqPublicKey::new(vec![]),
        SignaturePqPrivateKey::new(vec![]),
        SignaturePublicKey::new(public_key.to_vec()),
        SignaturePrivateKey::new(secret_key.to_vec()),
    );
    Ok(keyring.to_bytes())
}

// ===========================================================================
// PublicKeyBundle
// ===========================================================================

#[wasm_bindgen]
pub struct WasmPublicKeyBundle {
    inner: PublicKeyBundle,
}

#[wasm_bindgen]
impl WasmPublicKeyBundle {
    #[wasm_bindgen(getter)]
    pub fn kem_public_key(&self) -> Vec<u8> {
        self.inner.kem_public_key.as_bytes().to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn sig_cl_public_key(&self) -> Vec<u8> {
        self.inner.sig_cl_public_key.as_bytes().to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn sig_pq_public_key(&self) -> Vec<u8> {
        self.inner.sig_pq_public_key.as_bytes().to_vec()
    }

    #[wasm_bindgen]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes()
    }

    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmPublicKeyBundle, JsValue> {
        let inner = PublicKeyBundle::from_bytes(bytes)
            .map_err(|e| js_error(&format!("PublicKeyBundle::from_bytes: {}", e)))?;
        Ok(Self { inner })
    }
}

// ===========================================================================
// ChaCha20-Poly1305 AEAD
// ===========================================================================

#[wasm_bindgen]
pub struct WasmChaCha20Poly1305 {
    inner: ChaCha20Poly1305,
}

#[wasm_bindgen]
impl WasmChaCha20Poly1305 {
    /// Create a new cipher with a 32-byte key.
    #[wasm_bindgen(constructor)]
    pub fn new(key: Vec<u8>) -> Result<WasmChaCha20Poly1305, JsValue> {
        if key.len() != 32 {
            return Err(js_error("ChaCha20Poly1305 key must be 32 bytes"));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&key);
        Ok(Self {
            inner: ChaCha20Poly1305::new(k),
        })
    }

    /// Encrypt `plaintext` with `aad`.
    /// Returns `nonce || ciphertext`.
    #[wasm_bindgen]
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner
            .encrypt(plaintext, aad)
            .map_err(|e| js_error(&format!("encrypt failed: {}", e)))
    }

    /// Decrypt `nonce || ciphertext` with `aad`.
    #[wasm_bindgen]
    pub fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner
            .decrypt(ciphertext, aad)
            .map_err(|e| js_error(&format!("decrypt failed: {}", e)))
    }
}

// ===========================================================================
// Ed25519 signatures
// ===========================================================================

#[wasm_bindgen]
pub struct WasmEd25519Signer {
    inner: Ed25519Signer,
}

#[wasm_bindgen]
impl WasmEd25519Signer {
    /// Load a signer from its 32-byte secret key.
    #[wasm_bindgen(constructor)]
    pub fn new(secret_key: Vec<u8>) -> Result<WasmEd25519Signer, JsValue> {
        let sk = SignaturePrivateKey::new(secret_key);
        let inner =
            Ed25519Signer::new(&sk).map_err(|e| js_error(&format!("Ed25519Signer::new: {}", e)))?;
        Ok(Self { inner })
    }

    /// Sign `message` and return the signature bytes.
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner
            .sign(message)
            .map_err(|e| js_error(&format!("sign failed: {}", e)))
    }

    /// Verify `signature` against `message`.
    #[wasm_bindgen]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JsValue> {
        self.inner
            .verify(message, signature)
            .map_err(|e| js_error(&format!("verify failed: {}", e)))
    }
}

// ===========================================================================
// Ed25519 key generation helper
// ===========================================================================

/// Generate a fresh Ed25519 keypair.
///
/// Returns `{ signer: WasmEd25519Signer, secretKey: Uint8Array, publicKey: Uint8Array }`.
#[wasm_bindgen]
pub fn ed25519_generate() -> Result<JsValue, JsValue> {
    let (_signer, sk, pk) = Ed25519Signer::generate();
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("signer"),
        &WasmEd25519Signer::new(sk.as_bytes().to_vec())?.into(),
    )
    .map_err(|_| js_error("failed to set signer"))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("secretKey"),
        &js_sys::Uint8Array::from(sk.as_bytes()),
    )
    .map_err(|_| js_error("failed to set secretKey"))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("publicKey"),
        &js_sys::Uint8Array::from(pk.as_bytes()),
    )
    .map_err(|_| js_error("failed to set publicKey"))?;
    Ok(obj.into())
}

/// Standalone Ed25519 signature verification.
#[wasm_bindgen]
pub fn ed25519_verify(public_key: Vec<u8>, message: &[u8], signature: &[u8]) -> Result<(), JsValue> {
    let pk = SignaturePublicKey::new(public_key);
    mtp_crypto::verify_ed25519(&pk, message, signature)
        .map_err(|e| js_error(&format!("verify_ed25519 failed: {}", e)))
}

// ===========================================================================
// Hashing
// ===========================================================================

/// SHA-256 digest.
#[wasm_bindgen]
pub fn wasm_sha256(data: &[u8]) -> Vec<u8> {
    sha256(data).to_vec()
}

/// Double SHA-256 (SHA-256 applied twice).
#[wasm_bindgen]
pub fn wasm_sha256_double(data: &[u8]) -> Vec<u8> {
    sha256_double(data).to_vec()
}

// ===========================================================================
// KDF
// ===========================================================================

/// HKDF-expand: derive `len` bytes from `ikm` with `salt` and `info`.
#[wasm_bindgen]
pub fn wasm_hkdf_expand(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, JsValue> {
    mtp_crypto::hkdf_expand(ikm, salt, info, len)
        .map_err(|e| js_error(&format!("hkdf_expand failed: {}", e)))
}

/// Derive a 32-byte encryption key from `ikm` with `salt` and `context`.
#[wasm_bindgen]
pub fn wasm_derive_encryption_key(
    ikm: &[u8],
    salt: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, JsValue> {
    mtp_crypto::derive_encryption_key(ikm, salt, context)
        .map(|key| key.to_vec())
        .map_err(|e| js_error(&format!("derive_encryption_key failed: {}", e)))
}

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    // ------------------------------------------------------------------
    // Keyring
    // ------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn keyring_from_ed25519_roundtrip() {
        let sk = vec![0xabu8; 32];
        let pk = vec![0x42u8; 32];
        let bytes = keyring_from_ed25519(&sk, &pk).expect("keyring_from_ed25519 failed");

        let restored = WasmKeyring::from_bytes(&bytes).expect("from_bytes failed");
        let bundle = restored.public_key_bundle();
        assert_eq!(bundle.sig_cl_public_key(), pk);
    }

    #[wasm_bindgen_test]
    fn keyring_from_ed25519_wrong_key_length() {
        let short = vec![0u8; 16];
        let ok = vec![0u8; 32];
        assert!(keyring_from_ed25519(&short, &ok).is_err());
        assert!(keyring_from_ed25519(&ok, &short).is_err());
    }

    // ------------------------------------------------------------------
    // PublicKeyBundle
    // ------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn public_key_bundle_roundtrip() {
        let pk = vec![0x99u8; 32];
        let bundle = WasmPublicKeyBundle {
            inner: PublicKeyBundle {
                kem_public_key: KemPublicKey::new(vec![1, 2, 3]),
                sig_cl_public_key: SignaturePublicKey::new(pk.clone()),
                sig_pq_public_key: SignaturePqPublicKey::new(vec![4, 5, 6]),
            },
        };

        let bytes = bundle.to_bytes();
        let restored = WasmPublicKeyBundle::from_bytes(&bytes).expect("from_bytes failed");
        assert_eq!(restored.sig_cl_public_key(), pk);
    }

    // ------------------------------------------------------------------
    // ChaCha20-Poly1305
    // ------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn chacha20_encrypt_decrypt_roundtrip() {
        let key = vec![0x42u8; 32];
        let cipher = WasmChaCha20Poly1305::new(key).expect("new failed");

        let plaintext = b"hello wasm crypto";
        let aad = b"test-aad";

        let encrypted = cipher.encrypt(plaintext, aad).expect("encrypt failed");
        let decrypted = cipher.decrypt(&encrypted, aad).expect("decrypt failed");

        assert_eq!(decrypted, plaintext);
    }

    #[wasm_bindgen_test]
    fn chacha20_wrong_key_length() {
        assert!(WasmChaCha20Poly1305::new(vec![0u8; 16]).is_err());
        assert!(WasmChaCha20Poly1305::new(vec![0u8; 31]).is_err());
        assert!(WasmChaCha20Poly1305::new(vec![0u8; 33]).is_err());
    }

    #[wasm_bindgen_test]
    fn chacha20_decrypt_wrong_key_fails() {
        let key1 = vec![0x42u8; 32];
        let key2 = vec![0x43u8; 32];
        let cipher1 = WasmChaCha20Poly1305::new(key1).expect("new failed");
        let cipher2 = WasmChaCha20Poly1305::new(key2).expect("new failed");

        let encrypted = cipher1.encrypt(b"secret", b"aad").expect("encrypt failed");
        let result = cipher2.decrypt(&encrypted, b"aad");
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------
    // Ed25519
    // ------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn ed25519_sign_verify() {
        let (_signer, sk, _pk) = Ed25519Signer::generate();

        let signer = WasmEd25519Signer::new(sk.as_bytes().to_vec()).expect("new failed");
        let message = b"test message for ed25519";

        let signature = signer.sign(message).expect("sign failed");
        assert!(!signature.is_empty());

        signer.verify(message, &signature).expect("verify failed");
    }

    #[wasm_bindgen_test]
    fn ed25519_sign_wrong_message_fails_verify() {
        let (_signer, sk, _pk) = Ed25519Signer::generate();

        let signer = WasmEd25519Signer::new(sk.as_bytes().to_vec()).expect("new failed");
        let signature = signer.sign(b"message A").expect("sign failed");

        let result = signer.verify(b"message B", &signature);
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn ed25519_generate_returns_valid() {
        let result = ed25519_generate().expect("generate failed");

        let has_signer = js_sys::Reflect::has(&result, &"signer".into()).unwrap_or(false);
        let has_sk = js_sys::Reflect::has(&result, &"secretKey".into()).unwrap_or(false);
        let has_pk = js_sys::Reflect::has(&result, &"publicKey".into()).unwrap_or(false);

        assert!(has_signer);
        assert!(has_sk);
        assert!(has_pk);
    }

    #[wasm_bindgen_test]
    fn ed25519_verify_standalone() {
        let (_signer, sk, pk) = Ed25519Signer::generate();
        let signer = WasmEd25519Signer::new(sk.as_bytes().to_vec()).expect("new failed");
        let msg = b"standalone verify test";
        let sig = signer.sign(msg).expect("sign failed");

        ed25519_verify(pk.as_bytes().to_vec(), msg, &sig).expect("verify failed");
    }

    #[wasm_bindgen_test]
    fn ed25519_verify_bad_signature_fails() {
        let pk = vec![0x42u8; 32];
        let msg = b"test";
        let bad_sig = vec![0x00u8; 64];
        let result = ed25519_verify(pk, msg, &bad_sig);
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------
    // Hashing
    // ------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn sha256_empty() {
        let result = wasm_sha256(b"");
        // SHA-256 of empty string
        let expected = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .expect("hex decode");
        assert_eq!(result, expected);
    }

    #[wasm_bindgen_test]
    fn sha256_hello() {
        let result = wasm_sha256(b"hello");
        let expected = hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
            .expect("hex decode");
        assert_eq!(result, expected);
    }

    #[wasm_bindgen_test]
    fn sha256_double() {
        let single = wasm_sha256(b"test");
        let double = wasm_sha256_double(b"test");
        let expected = wasm_sha256(&single);
        assert_eq!(double, expected);
    }

    // ------------------------------------------------------------------
    // HKDF / KDF
    // ------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn hkdf_expand_produces_correct_length() {
        let result = wasm_hkdf_expand(b"ikm", b"salt", b"info", 32)
            .expect("hkdf_expand failed");
        assert_eq!(result.len(), 32);
    }

    #[wasm_bindgen_test]
    fn hkdf_expand_different_info() {
        let r1 = wasm_hkdf_expand(b"ikm", b"salt", b"info1", 16).expect("hkdf failed");
        let r2 = wasm_hkdf_expand(b"ikm", b"salt", b"info2", 16).expect("hkdf failed");
        assert_ne!(r1, r2);
    }

    #[wasm_bindgen_test]
    fn derive_encryption_key_roundtrip() {
        let key = wasm_derive_encryption_key(b"password", b"salt", b"context")
            .expect("derive failed");
        assert_eq!(key.len(), 32);

        // Deterministic: same inputs = same key
        let key2 = wasm_derive_encryption_key(b"password", b"salt", b"context")
            .expect("derive failed");
        assert_eq!(key, key2);
    }

    #[wasm_bindgen_test]
    fn derive_encryption_key_different_inputs_different_key() {
        let key = wasm_derive_encryption_key(b"pass1", b"salt", b"context")
            .expect("derive failed");
        let key2 = wasm_derive_encryption_key(b"pass2", b"salt", b"context")
            .expect("derive failed");
        assert_ne!(key, key2);
    }
}
