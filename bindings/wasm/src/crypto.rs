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

pub(crate) fn protection_policy_from_suite(suite: u8) -> Result<ProtectionPolicy, JsValue> {
    let signature = match suite {
        0 => SignaturePolicy::AnySupported,
        PROTECTION_SIGNATURE_SUITE_ED25519 => SignaturePolicy::Ed25519,
        PROTECTION_SIGNATURE_SUITE_DUAL => SignaturePolicy::Dual,
        _ => {
            return Err(js_error(format!(
                "unknown protection signature suite: {suite}"
            )));
        }
    };
    Ok(ProtectionPolicy { signature })
}

pub(crate) enum RelaySigner {
    Ed25519(Ed25519Signer),
    Dual(DualSigner),
}

impl SignatureScheme for RelaySigner {
    fn algorithm(&self) -> u8 {
        match self {
            Self::Ed25519(signer) => signer.algorithm(),
            Self::Dual(signer) => signer.algorithm(),
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, mtp_crypto::CryptoError> {
        match self {
            Self::Ed25519(signer) => signer.sign(message),
            Self::Dual(signer) => signer.sign(message),
        }
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), mtp_crypto::CryptoError> {
        match self {
            Self::Ed25519(signer) => signer.verify(message, signature),
            Self::Dual(signer) => signer.verify(message, signature),
        }
    }
}

pub(crate) fn relay_signer_from_keyring(
    keyring: &Keyring,
    suite: u8,
) -> Result<RelaySigner, JsValue> {
    match suite {
        PROTECTION_SIGNATURE_SUITE_ED25519 => {
            keyring
                .validate_ed25519_signing()
                .map_err(|e| js_error(format!("signing key validation failed: {e}")))?;
            Ed25519Signer::new(&keyring.sig_cl_secret_key)
                .map(RelaySigner::Ed25519)
                .map_err(|e| js_error(format!("signer initialization failed: {e}")))
        }
        PROTECTION_SIGNATURE_SUITE_DUAL => {
            keyring
                .validate_dual_signing()
                .map_err(|e| js_error(format!("dual signing key validation failed: {e}")))?;
            DualSigner::new(
                &keyring.sig_cl_secret_key,
                &keyring.sig_pq_secret_key,
                &keyring.sig_pq_public_key,
            )
            .map(RelaySigner::Dual)
            .map_err(|e| js_error(format!("dual signer initialization failed: {e}")))
        }
        _ => Err(js_error(format!(
            "unknown protection signature suite: {suite}"
        ))),
    }
}

/// Sign a serialized `DataValue` using the selected suite from a serialized
/// keyring.
#[wasm_bindgen]
pub fn sign_data_value_with_keyring(
    value: &[u8],
    signer_id: u64,
    purpose: u8,
    keyring: &[u8],
    signature_suite: u8,
) -> Result<Vec<u8>, JsValue> {
    let value = decode_data_value(value)?;
    let keyring = Keyring::from_bytes(keyring)
        .map_err(|e| js_error(format!("keyring initialization failed: {e}")))?;
    let signer = relay_signer_from_keyring(&keyring, signature_suite)?;
    value
        .sign(signer_id, ProtectionPurpose::from(purpose), &signer)
        .map_err(from_protection_error)?
        .to_bytes()
        .map_err(|e| js_error(format!("sign failed: {e}")))
}

/// Verify a serialized `Signed<Value>` wrapper while enforcing the receiver's
/// required signature suite. `0` retains the legacy any-supported behavior;
/// new protocol callers should pass one of the exported suite constants.
#[wasm_bindgen]
pub fn verify_data_value_with_policy(
    value: &[u8],
    public_key_bundle: &[u8],
    expected_signer_id: u64,
    expected_purpose: u8,
    signature_suite: u8,
) -> Result<(), JsValue> {
    let value = decode_data_value(value)?;
    let bundle = decode_public_key_bundle(public_key_bundle, None)?;
    let result = if signature_suite == 0 {
        value.verify_with_policy(
            expected_signer_id,
            &bundle,
            ProtectionPurpose::from(expected_purpose),
            ProtectionPolicy::any_supported(),
        )
    } else {
        value.verify_with_policy(
            expected_signer_id,
            &bundle,
            ProtectionPurpose::from(expected_purpose),
            protection_policy_from_suite(signature_suite)?,
        )
    };
    result.map_err(from_protection_error)
}

/// Encrypt a serialized `DataValue` for one recipient using the canonical
/// multi-recipient envelope.
#[wasm_bindgen]
pub fn encrypt_data_value(
    value: &[u8],
    recipient_public_key_bundle: &[u8],
    purpose: u8,
) -> Result<Vec<u8>, JsValue> {
    let value = decode_data_value(value)?;
    let recipient = decode_public_key_bundle(recipient_public_key_bundle, None)?;
    let encrypted = value
        .encrypt_for(&[recipient], ProtectionPurpose::from(purpose))
        .map_err(from_protection_error)?;
    encrypted
        .to_bytes()
        .map_err(|e| js_error(format!("encryption failed: {e}")))
}

/// Encrypt a serialized `DataValue` for one or more recipients.
///
/// `recipient_public_key_bundles` may be a single `Uint8Array` for the common
/// case or an array of serialized public-key bundles. The array form uses the
/// same canonical envelope as native multi-recipient encryption.
#[wasm_bindgen]
pub fn encrypt_data_value_for_recipients(
    value: &[u8],
    recipient_public_key_bundles: JsValue,
    purpose: u8,
) -> Result<Vec<u8>, JsValue> {
    let value = decode_data_value(value)?;
    let recipients = public_key_bundles_from_js(&recipient_public_key_bundles)?;
    value
        .encrypt_for(&recipients, ProtectionPurpose::from(purpose))
        .map_err(from_protection_error)?
        .to_bytes()
        .map_err(|e| js_error(format!("encryption failed: {e}")))
}

/// Decrypt a serialized `Encrypted<Value>` wrapper with a serialized keyring.
/// The expected purpose is supplied by the protocol caller, not taken from
/// the untrusted encrypted wrapper.
#[wasm_bindgen]
pub fn decrypt_data_value(
    value: &[u8],
    keyring: &[u8],
    expected_purpose: u8,
) -> Result<Vec<u8>, JsValue> {
    let value = decode_data_value(value)?;
    let keyring = Keyring::from_bytes(keyring)
        .map_err(|e| js_error(format!("keyring initialization failed: {e}")))?;
    let opened = value
        .decrypt(&keyring, ProtectionPurpose::from(expected_purpose))
        .map_err(from_protection_error)?;
    opened
        .to_bytes()
        .map_err(|e| js_error(format!("decryption failed: {e}")))
}

/// Decrypt using a caller-supplied local key history. Recipient key
/// identifiers remain absent from the serialized envelope.
#[wasm_bindgen]
pub fn decrypt_data_value_with_keyrings(
    value: &[u8],
    keyrings: JsValue,
    expected_purpose: u8,
) -> Result<Vec<u8>, JsValue> {
    let value = decode_data_value(value)?;
    let keyrings = keyrings_from_js(&keyrings)?;
    let references: Vec<&Keyring> = keyrings.iter().collect();
    value
        .decrypt_with_keyrings_and_limits(
            &references,
            ProtectionPurpose::from(expected_purpose),
            DecodeLimits::default(),
        )
        .map_err(from_protection_error)?
        .to_bytes()
        .map_err(|e| js_error(format!("decryption failed: {e}")))
}

pub(crate) fn keyrings_from_js(value: &JsValue) -> Result<Vec<Keyring>, JsValue> {
    let keyring_bytes: Vec<Vec<u8>> = if js_sys::Uint8Array::instanceof(value) {
        vec![js_sys::Uint8Array::new(value).to_vec()]
    } else if js_sys::Array::is_array(value) {
        let array = js_sys::Array::from(value);
        array
            .iter()
            .enumerate()
            .map(|(index, value)| {
                if !js_sys::Uint8Array::instanceof(&value) {
                    return Err(js_error(format!("keyring {index} must be a Uint8Array")));
                }
                Ok(js_sys::Uint8Array::new(&value).to_vec())
            })
            .collect::<Result<_, _>>()?
    } else {
        return Err(js_error(
            "keyrings must be a Uint8Array or an array of Uint8Arrays",
        ));
    };
    if keyring_bytes.is_empty() {
        return Err(js_error("at least one keyring is required"));
    }
    keyring_bytes
        .iter()
        .map(|bytes| {
            Keyring::from_bytes(bytes)
                .map_err(|e| js_error(format!("keyring initialization failed: {e}")))
        })
        .collect()
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

/// Return the canonical MTP relay metadata-encryption purpose.
#[wasm_bindgen]
pub fn mtp_relay_metadata_encryption_purpose() -> u8 {
    MtpProtectionPurpose::RelayMetadataEncryption.value()
}

/// Return the canonical MTP relay content-signature purpose.
#[wasm_bindgen]
pub fn mtp_relay_content_signature_purpose() -> u8 {
    MtpProtectionPurpose::RelayContentSignature.value()
}

/// Return the canonical MTP relay content-encryption purpose.
#[wasm_bindgen]
pub fn mtp_relay_content_encryption_purpose() -> u8 {
    MtpProtectionPurpose::RelayContentEncryption.value()
}

/// Return the canonical MTP relay metadata-signature purpose.
#[wasm_bindgen]
pub fn mtp_relay_metadata_signature_purpose() -> u8 {
    MtpProtectionPurpose::RelayMetadataSignature.value()
}

/// Return the canonical MTP pipe-session signature purpose.
#[wasm_bindgen]
pub fn mtp_pipe_session_signature_purpose() -> u8 {
    MtpProtectionPurpose::PipeSessionSignature.value()
}

/// Return the canonical MTP pipe-session encryption purpose.
#[wasm_bindgen]
pub fn mtp_pipe_session_encryption_purpose() -> u8 {
    MtpProtectionPurpose::PipeSessionEncryption.value()
}

#[wasm_bindgen]
pub fn mtp_protection_signature_suite_ed25519() -> u8 {
    PROTECTION_SIGNATURE_SUITE_ED25519
}

#[wasm_bindgen]
pub fn mtp_protection_signature_suite_dual() -> u8 {
    PROTECTION_SIGNATURE_SUITE_DUAL
}

/// Explicit compatibility policy value accepting any signature suite
/// supported by this WASM build. New callers should prefer a fixed suite.
#[wasm_bindgen]
pub fn mtp_protection_signature_suite_any_supported() -> u8 {
    0
}

/// Forward a sealed relay frame to another clear next hop without opening or
/// re-encoding its authenticated encrypted payload.
#[wasm_bindgen]
pub fn forward_encrypted_relay_frame(
    frame: &[u8],
    next_hop_receiver_id: u64,
) -> Result<Vec<u8>, JsValue> {
    let frame = decode_frame(frame)?;
    mtp_codec::forward_relay_frame(&frame, next_hop_receiver_id)
        .map_err(relay_error)?
        .to_bytes()
        .map_err(|e| structured_error("invalid-frame", format!("relay frame encoding failed: {e}")))
}

/// Convert browser values and build a sealed relay frame through the native
/// codec builder. The builder owns the protected relay layout so native and
/// browser callers cannot silently diverge.
#[allow(clippy::too_many_arguments)]
fn build_encrypted_relay_frame_impl(
    message_type: &str,
    data: JsValue,
    signer_id: u64,
    final_recipient_id: u64,
    next_hop_id: u64,
    message_id: u128,
    created_at: u64,
    encoded_metadata: Option<Vec<u8>>,
    signer: &dyn SignatureScheme,
    metadata_recipient_public_key_bundles: JsValue,
    content_recipient_public_key_bundles: JsValue,
    limits: JsValue,
) -> Result<Vec<u8>, JsValue> {
    let tm = TypeMap::new(PROTOCOL_VERSION);
    let encode_limits = if limits.is_null() || limits.is_undefined() {
        EncodeLimits::default()
    } else {
        crate::client::encode_limits_from_js(&limits)?
    };
    let relay_options =
        crate::relay::relay_open_options(ProtectionPolicy::any_supported(), &limits)?;
    let application_content =
        crate::frame::js_to_data_value_with_limits(&data, &tm, encode_limits)?;
    let application_metadata = encoded_metadata
        .as_deref()
        .map(|bytes| {
            DataValue::try_from_bytes_with_limits(
                bytes,
                DecodeLimits::for_transport_message_size(encode_limits.max_output_size as u64),
            )
            .map_err(|error| crate::relay::decode_error(error, "metadata decoding failed"))
        })
        .transpose()?;
    let content_recipients = public_key_bundles_from_js(&content_recipient_public_key_bundles)?;
    let metadata_recipients = public_key_bundles_from_js(&metadata_recipient_public_key_bundles)?;

    let builder = SealedRelayBuilder::new(
        CommunicationType::from_name(&message_type).ok_or_else(|| {
            structured_error("invalid-message-type", "unknown communication type")
        })?,
        application_content,
        signer_id,
        final_recipient_id,
        next_hop_id,
        signer,
    )
    .message_id(message_id)
    .created_at(created_at)
    .metadata_recipients(metadata_recipients)
    .content_recipients(content_recipients)
    .encode_limits(encode_limits)
    .protected_limits(relay_options.protected_limits)
    .type_map(&tm);
    let builder = match application_metadata {
        Some(metadata) => builder.metadata(metadata),
        None => builder,
    };

    builder
        .build()
        .map_err(relay_error)?
        .to_bytes_with_limits(encode_limits)
        .map_err(|e| js_error(format!("relay frame encoding failed: {e}")))
}

/// Build a relay frame using an explicit Ed25519 or dual-signature policy.
/// `created_at` is Unix epoch milliseconds.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn build_encrypted_relay_frame_with_keyring(
    message_type: &str,
    data: JsValue,
    signer_id: u64,
    final_recipient_id: u64,
    next_hop_id: u64,
    message_id: u128,
    created_at: u64,
    encoded_metadata: Option<Vec<u8>>,
    keyring_bytes: &[u8],
    signature_suite: u8,
    metadata_recipient_public_key_bundles: JsValue,
    content_recipient_public_key_bundles: JsValue,
) -> Result<Vec<u8>, JsValue> {
    let keyring = Keyring::from_bytes(keyring_bytes)
        .map_err(|e| js_error(format!("keyring initialization failed: {e}")))?;
    let signer = relay_signer_from_keyring(&keyring, signature_suite)?;
    build_encrypted_relay_frame_impl(
        message_type,
        data,
        signer_id,
        final_recipient_id,
        next_hop_id,
        message_id,
        created_at,
        encoded_metadata,
        &signer,
        metadata_recipient_public_key_bundles,
        content_recipient_public_key_bundles,
        JsValue::UNDEFINED,
    )
}

/// Build a sealed relay frame with explicit encoder and semantic field
/// limits. The same limits are applied by the native relay builder.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn build_encrypted_relay_frame_with_keyring_with_limits(
    message_type: &str,
    data: JsValue,
    signer_id: u64,
    final_recipient_id: u64,
    next_hop_id: u64,
    message_id: u128,
    created_at: u64,
    encoded_metadata: Option<Vec<u8>>,
    keyring_bytes: &[u8],
    signature_suite: u8,
    metadata_recipient_public_key_bundles: JsValue,
    content_recipient_public_key_bundles: JsValue,
    limits: JsValue,
) -> Result<Vec<u8>, JsValue> {
    let keyring = Keyring::from_bytes(keyring_bytes)
        .map_err(|e| js_error(format!("keyring initialization failed: {e}")))?;
    let signer = relay_signer_from_keyring(&keyring, signature_suite)?;
    build_encrypted_relay_frame_impl(
        message_type,
        data,
        signer_id,
        final_recipient_id,
        next_hop_id,
        message_id,
        created_at,
        encoded_metadata,
        &signer,
        metadata_recipient_public_key_bundles,
        content_recipient_public_key_bundles,
        limits,
    )
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

        let bytes = bundle.try_to_bytes().expect("bundle serialization");
        let restored = WasmPublicKeyBundle::from_bytes_unvalidated(&bytes)
            .expect("from_bytes_unvalidated failed");
        assert_eq!(restored.sig_cl_public_key(), pk);
    }

    // ------------------------------------------------------------------
    // KEM encapsulate / decapsulate
    // ------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn kem_encapsulate_decapsulate_roundtrip() {
        let (sk, pk) = HybridKem::generate_keypair();
        let enc = wasm_kem_encapsulate(pk.as_bytes()).expect("encapsulate failed");
        let ss =
            wasm_kem_decapsulate(sk.as_bytes(), &enc.ciphertext()).expect("decapsulate failed");
        assert_eq!(enc.shared_secret(), ss);
    }

    #[wasm_bindgen_test]
    fn kem_encapsulate_invalid_public_key_fails() {
        let bad = vec![0u8; 16];
        assert!(wasm_kem_encapsulate(&bad).is_err());
    }

    #[wasm_bindgen_test]
    fn kem_decapsulate_invalid_ciphertext_fails() {
        let (sk, _pk) = HybridKem::generate_keypair();
        let bad = vec![0u8; 32];
        assert!(wasm_kem_decapsulate(sk.as_bytes(), &bad).is_err());
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
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .expect("hex decode");
        assert_eq!(result, expected);
    }

    #[wasm_bindgen_test]
    fn sha256_hello() {
        let result = wasm_sha256(b"hello");
        let expected =
            hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
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
        let result = wasm_hkdf_expand(b"ikm", b"salt", b"info", 32).expect("hkdf_expand failed");
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
        let key =
            wasm_derive_encryption_key(b"password", b"salt", b"context").expect("derive failed");
        assert_eq!(key.len(), 32);

        // Deterministic: same inputs = same key
        let key2 =
            wasm_derive_encryption_key(b"password", b"salt", b"context").expect("derive failed");
        assert_eq!(key, key2);
    }

    #[wasm_bindgen_test]
    fn derive_encryption_key_different_inputs_different_key() {
        let key = wasm_derive_encryption_key(b"pass1", b"salt", b"context").expect("derive failed");
        let key2 =
            wasm_derive_encryption_key(b"pass2", b"salt", b"context").expect("derive failed");
        assert_ne!(key, key2);
    }

    // ------------------------------------------------------------------
    // DataValue protection
    // ------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn signed_data_value_can_be_verified_through_wasm() {
        let keyring = Keyring::generate();
        let value = DataValue::Str("signed through wasm".into())
            .to_bytes()
            .expect("value encoding failed");
        let keyring_bytes = keyring.try_to_bytes().expect("keyring serialization");
        let signed = sign_data_value_with_keyring(
            &value,
            0xfeed_beef,
            7,
            &keyring_bytes,
            PROTECTION_SIGNATURE_SUITE_ED25519,
        )
        .expect("sign_data_value_with_keyring failed");
        let bundle = keyring.public_key_bundle();

        verify_data_value_with_policy(
            &signed,
            &bundle.try_as_bytes().expect("bundle serialization"),
            0xfeed_beef,
            7,
            PROTECTION_SIGNATURE_SUITE_ED25519,
        )
        .expect("verify_data_value_with_policy failed");
        let wrong_bundle = Keyring::generate().public_key_bundle();
        assert!(
            verify_data_value_with_policy(
                &signed,
                &wrong_bundle.try_as_bytes().expect("bundle serialization"),
                0xfeed_beef,
                7,
                PROTECTION_SIGNATURE_SUITE_ED25519,
            )
            .is_err()
        );
    }

    #[wasm_bindgen_test]
    fn encrypted_data_value_can_be_opened_through_wasm() {
        let keyring = Keyring::generate();
        let recipient = keyring.public_key_bundle();
        let value = DataValue::Array(vec![DataValue::BoolTrue, DataValue::UnsignedNumber(42)])
            .to_bytes()
            .expect("value encoding failed");
        let recipient_bytes = recipient.try_as_bytes().expect("recipient serialization");
        let encrypted =
            encrypt_data_value(&value, &recipient_bytes, 9).expect("encrypt_data_value failed");
        let keyring_bytes = keyring.try_to_bytes().expect("keyring serialization");
        let decrypted =
            decrypt_data_value(&encrypted, &keyring_bytes, 9).expect("decrypt_data_value failed");

        assert_eq!(decrypted, value);

        let second_keyring = Keyring::generate();
        let second_recipient = second_keyring.public_key_bundle();
        let recipients = js_sys::Array::new();
        let second_recipient_bytes = second_recipient
            .try_as_bytes()
            .expect("second recipient serialization");
        recipients.push(&js_sys::Uint8Array::from(&recipient_bytes[..]));
        recipients.push(&js_sys::Uint8Array::from(&second_recipient_bytes[..]));
        let multi = encrypt_data_value_for_recipients(&value, recipients.into(), 9)
            .expect("multi-recipient encryption failed");
        let second_keyring_bytes = second_keyring
            .try_to_bytes()
            .expect("second keyring serialization");
        let opened_by_second = decrypt_data_value(&multi, &second_keyring_bytes, 9)
            .expect("second recipient could not decrypt");
        assert_eq!(opened_by_second, value);
    }
}
