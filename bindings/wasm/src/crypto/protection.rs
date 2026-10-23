use super::*;

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
