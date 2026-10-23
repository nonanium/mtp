mod protection;
pub use protection::{
    decrypt_data_value, decrypt_data_value_with_keyrings, encrypt_data_value,
    encrypt_data_value_for_recipients, sign_data_value_with_keyring, verify_data_value_with_policy,
};
pub(crate) use protection::{
    keyrings_from_js, protection_policy_from_suite, relay_signer_from_keyring,
};
mod relay;
pub use relay::{
    build_encrypted_relay_frame_with_keyring, build_encrypted_relay_frame_with_keyring_with_limits,
    forward_encrypted_relay_frame, mtp_pipe_session_encryption_purpose,
    mtp_pipe_session_signature_purpose, mtp_protection_signature_suite_any_supported,
    mtp_protection_signature_suite_dual, mtp_protection_signature_suite_ed25519,
    mtp_relay_content_encryption_purpose, mtp_relay_content_signature_purpose,
    mtp_relay_metadata_encryption_purpose, mtp_relay_metadata_signature_purpose,
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use mtp_codec::{
    CommunicationType, DataValue, DecodeLimits, EncodeLimits, MtpProtectionPurpose,
    PROTOCOL_VERSION, ProtectionPolicy, ProtectionPurpose, SealedRelayBuilder, SignaturePolicy,
    TypeMap,
};
use mtp_crypto::{
    AeadDecrypt, AeadEncrypt, DualSigner, Ed25519Signer, HybridKem, KemPrivateKey, KemPublicKey,
    Keyring, PublicKeyBundle, SignaturePqPrivateKey, SignaturePqPublicKey, SignaturePrivateKey,
    SignaturePublicKey, SignatureScheme, XChaCha20Poly1305, sha256, sha256_double,
};

use crate::error::{from_protection_error, js_error};
use crate::relay::{decode_error, decode_frame, relay_error, structured_error};

fn decode_data_value(value: &[u8]) -> Result<DataValue, JsValue> {
    DataValue::try_from_bytes_with_limits(value, DecodeLimits::default()).map_err(|error| {
        let value = decode_error(error, "DataValue decoding failed");
        let _ = js_sys::Reflect::set(
            &value,
            &JsValue::from_str("code"),
            &JsValue::from_str("invalid-data-value"),
        );
        value
    })
}

fn decode_public_key_bundle(
    bytes: &[u8],
    index: Option<usize>,
) -> Result<PublicKeyBundle, JsValue> {
    PublicKeyBundle::from_bytes(bytes).map_err(|e| {
        let prefix = index
            .map(|index| format!("recipient {index}: "))
            .unwrap_or_default();
        js_error(format!("{prefix}public bundle initialization failed: {e}"))
    })
}

pub(crate) fn public_key_bundles_from_js(value: &JsValue) -> Result<Vec<PublicKeyBundle>, JsValue> {
    if js_sys::Uint8Array::instanceof(value) {
        return Ok(vec![decode_public_key_bundle(
            &js_sys::Uint8Array::new(value).to_vec(),
            None,
        )?]);
    }

    if !js_sys::Array::is_array(value) {
        return Err(js_error(
            "recipient public key bundles must be a Uint8Array or an array of Uint8Arrays",
        ));
    }

    let array = js_sys::Array::from(value);
    if array.length() == 0 {
        return Err(js_error(
            "at least one recipient public key bundle is required",
        ));
    }

    array
        .iter()
        .enumerate()
        .map(|(index, value)| {
            if !js_sys::Uint8Array::instanceof(&value) {
                return Err(js_error(format!("recipient {index} must be a Uint8Array")));
            }
            decode_public_key_bundle(&js_sys::Uint8Array::new(&value).to_vec(), Some(index))
        })
        .collect()
}

// ===========================================================================
// Keyring
// ===========================================================================

#[wasm_bindgen]
pub struct WasmKeyring {
    inner: Keyring,
}

#[wasm_bindgen]
impl WasmKeyring {
    /// Serialise the keyring to bytes and report malformed caller-owned
    /// material as a JavaScript exception.
    #[wasm_bindgen]
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsValue> {
        self.try_to_bytes()
    }

    #[wasm_bindgen]
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, JsValue> {
        self.inner
            .try_to_bytes()
            .map(|bytes| bytes.to_vec())
            .map_err(|error| js_error(format!("Keyring serialization failed: {error}")))
    }

    /// Deserialise a keyring from bytes.
    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmKeyring, JsValue> {
        let inner = Keyring::from_bytes(bytes)
            .map_err(|e| js_error(format!("Keyring::from_bytes: {}", e)))?;
        Ok(Self { inner })
    }

    /// Return the public half of this keyring as a bundle.
    #[wasm_bindgen]
    pub fn public_key_bundle(&self) -> WasmPublicKeyBundle {
        WasmPublicKeyBundle {
            inner: self.inner.public_key_bundle(),
        }
    }

    /// Validate that all full-suite public/private components correspond.
    /// Role-specific browser keyrings may intentionally fail this check.
    #[wasm_bindgen]
    pub fn validate_full(&self) -> Result<(), JsValue> {
        self.inner
            .validate_full()
            .map_err(|e| js_error(format!("Keyring::validate_full: {e}")))
    }

    /// Validate the KEM public/private pair without requiring PQ signing
    /// material. This is the invariant needed by envelope recipients and
    /// sealed-relay clients that explicitly choose Ed25519 signatures.
    #[wasm_bindgen]
    pub fn validate_encryption(&self) -> Result<(), JsValue> {
        self.inner
            .validate_encryption()
            .map_err(|e| js_error(format!("Keyring::validate_encryption: {e}")))
    }
}

/// Generate a full keyring with KEM, ML-DSA, and Ed25519 keys.
#[wasm_bindgen]
pub fn keyring_generate() -> Result<Vec<u8>, JsValue> {
    keyring_generate_checked()
}

/// Generate a full keyring and report serialization failures to JavaScript.
#[wasm_bindgen]
pub fn keyring_generate_checked() -> Result<Vec<u8>, JsValue> {
    Keyring::generate()
        .try_to_bytes()
        .map(|bytes| bytes.to_vec())
        .map_err(|error| js_error(format!("generated keyring serialization failed: {error}")))
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
    keyring
        .try_to_bytes()
        .map(|bytes| bytes.to_vec())
        .map_err(|error| js_error(format!("Keyring serialization failed: {error}")))
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
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsValue> {
        self.try_to_bytes()
    }

    #[wasm_bindgen]
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, JsValue> {
        self.inner
            .try_as_bytes()
            .map_err(|error| js_error(format!("public key bundle serialization failed: {error}")))
    }

    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmPublicKeyBundle, JsValue> {
        let inner = PublicKeyBundle::from_bytes(bytes)
            .map_err(|e| js_error(format!("PublicKeyBundle::from_bytes: {}", e)))?;
        Ok(Self { inner })
    }

    /// Deserialise an explicitly partial bundle for development-only key
    /// material. Protocol encryption and signature verification use the
    /// strict `from_bytes` parser above.
    #[wasm_bindgen]
    pub fn from_bytes_unvalidated(bytes: &[u8]) -> Result<WasmPublicKeyBundle, JsValue> {
        let inner = PublicKeyBundle::from_bytes_unvalidated(bytes)
            .map_err(|e| js_error(format!("PublicKeyBundle::from_bytes_unvalidated: {}", e)))?;
        Ok(Self { inner })
    }
}

// ===========================================================================
// Hybrid KEM (X25519 + ML-KEM-768)
// ===========================================================================

/// KEM encapsulation result returned to JavaScript.
///
/// `shared_secret` is the symmetric key both parties will derive; `ciphertext`
/// is the KEM ciphertext that must be sent to the recipient so they can
/// decapsulate and recover the same shared secret.
#[wasm_bindgen]
pub struct WasmEncapsulated {
    inner_shared_secret: Zeroizing<Vec<u8>>,
    inner_ciphertext: Vec<u8>,
}

/// A short-lived ephemeral hybrid-KEM keypair for the forward-secure pipe
/// handshake. The secret is zeroized when the object is freed.
#[wasm_bindgen]
pub struct WasmKemKeypair {
    secret: Zeroizing<Vec<u8>>,
    public: Vec<u8>,
}

#[wasm_bindgen]
impl WasmKemKeypair {
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.secret.to_vec()
    }
}

#[wasm_bindgen]
pub fn wasm_kem_generate_keypair() -> WasmKemKeypair {
    let (secret, public) = HybridKem::generate_keypair();
    WasmKemKeypair {
        secret: Zeroizing::new(secret.as_bytes().to_vec()),
        public: public.as_bytes().to_vec(),
    }
}

#[wasm_bindgen]
impl WasmEncapsulated {
    /// Symmetric secret derived during encapsulation.
    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.inner_shared_secret.to_vec()
    }

    /// KEM ciphertext to transmit to the recipient.
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.inner_ciphertext.clone()
    }
}

/// Encapsulate a fresh shared secret for `recipient_public_key`.
///
/// Returns a [`WasmEncapsulated`] containing the shared secret and the KEM
/// ciphertext that the recipient needs to recover it via
/// [`wasm_kem_decapsulate`].
#[wasm_bindgen]
pub fn wasm_kem_encapsulate(recipient_public_key: &[u8]) -> Result<WasmEncapsulated, JsValue> {
    let pk = KemPublicKey::new(recipient_public_key.to_vec());
    let enc = HybridKem::encapsulate(&pk)
        .map_err(|e| js_error(format!("kem_encapsulate failed: {}", e)))?;
    Ok(WasmEncapsulated {
        inner_shared_secret: enc.shared_secret,
        inner_ciphertext: enc.ciphertext,
    })
}

/// Decapsulate a KEM `ciphertext` with the recipient's `private_key`.
///
/// Returns the same shared secret the initiator obtained from
/// [`wasm_kem_encapsulate`].
#[wasm_bindgen]
pub fn wasm_kem_decapsulate(
    recipient_private_key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let sk = KemPrivateKey::new(recipient_private_key.to_vec());
    HybridKem::decapsulate(&sk, ciphertext)
        .map(|secret| secret.to_vec())
        .map_err(|e| js_error(format!("kem_decapsulate failed: {}", e)))
}

// ===========================================================================
// ChaCha20-Poly1305 AEAD
// ===========================================================================

#[wasm_bindgen]
pub struct WasmChaCha20Poly1305 {
    inner: XChaCha20Poly1305,
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
            inner: XChaCha20Poly1305::new(k),
        })
    }

    /// Encrypt `plaintext` with `aad`.
    /// Returns `nonce || ciphertext`.
    #[wasm_bindgen]
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner
            .encrypt(plaintext, aad)
            .map_err(|e| js_error(format!("encrypt failed: {}", e)))
    }

    /// Decrypt `nonce || ciphertext` with `aad`.
    #[wasm_bindgen]
    pub fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner
            .decrypt(ciphertext, aad)
            .map_err(|e| js_error(format!("decrypt failed: {}", e)))
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
            Ed25519Signer::new(&sk).map_err(|e| js_error(format!("Ed25519Signer::new: {}", e)))?;
        Ok(Self { inner })
    }

    /// Sign `message` and return the signature bytes.
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner
            .sign(message)
            .map_err(|e| js_error(format!("sign failed: {}", e)))
    }

    /// Verify `signature` against `message`.
    #[wasm_bindgen]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JsValue> {
        self.inner
            .verify(message, signature)
            .map_err(|e| js_error(format!("verify failed: {}", e)))
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
pub fn ed25519_verify(
    public_key: Vec<u8>,
    message: &[u8],
    signature: &[u8],
) -> Result<(), JsValue> {
    let pk = SignaturePublicKey::new(public_key);
    mtp_crypto::verify_ed25519(&pk, message, signature)
        .map_err(|e| js_error(format!("verify_ed25519 failed: {}", e)))
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

/// Length, in bytes, of symmetric keys produced by the MTP key-derivation
/// bindings. SDKs should query this instead of duplicating the crypto
/// primitive's output size.
#[wasm_bindgen]
pub fn mtp_symmetric_key_length() -> u32 {
    32
}

/// HKDF-expand: derive `len` bytes from `ikm` with `salt` and `info`.
#[wasm_bindgen]
pub fn wasm_hkdf_expand(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, JsValue> {
    mtp_crypto::hkdf_expand(ikm, salt, info, len)
        .map_err(|e| js_error(format!("hkdf_expand failed: {}", e)))
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
        .map_err(|e| js_error(format!("derive_encryption_key failed: {}", e)))
}

/// Derive a 32-byte key from a passphrase using explicit Argon2id parameters.
/// The salt and parameters are part of the caller's protected-data format.
#[wasm_bindgen]
pub fn wasm_argon2id(
    passphrase: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
) -> Result<Vec<u8>, JsValue> {
    mtp_crypto::derive_password_key(passphrase, salt, memory_kib, iterations, lanes)
        .map(|key| key.to_vec())
        .map_err(|e| js_error(format!("argon2id password derivation failed: {e}")))
}

/// Signature suites accepted by high-level protected-value APIs.
pub const PROTECTION_SIGNATURE_SUITE_ED25519: u8 = 0x01;
pub const PROTECTION_SIGNATURE_SUITE_DUAL: u8 = 0x03;

pub(crate) enum RelaySigner {
    Ed25519(Ed25519Signer),
    Dual(DualSigner),
}

/// Protection purposes used by the generic browser relay envelope.
///
/// The outer encryption purpose is intentionally generic: the actual
/// application operation is inside the encrypted metadata container.
pub const RELAY_METADATA_ENCRYPTION_PURPOSE: u8 =
    MtpProtectionPurpose::RelayMetadataEncryption.value();
pub const RELAY_CONTENT_SIGNATURE_PURPOSE: u8 = MtpProtectionPurpose::RelayContentSignature.value();
pub const RELAY_CONTENT_ENCRYPTION_PURPOSE: u8 =
    MtpProtectionPurpose::RelayContentEncryption.value();
pub const RELAY_METADATA_SIGNATURE_PURPOSE: u8 =
    MtpProtectionPurpose::RelayMetadataSignature.value();

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
mod tests;
