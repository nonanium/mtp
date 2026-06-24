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
