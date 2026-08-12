use wasm_bindgen::prelude::*;

use mtp_codec::{
    CommunicationValue, DataValue, ProtectionError, RelayError, VerifiedRelayContent,
    VerifiedRelayMetadata,
};

use crate::crypto::{keyrings_from_js, protection_policy_from_suite, public_key_bundles_from_js};

const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

pub(crate) fn structured_error(code: &str, message: impl Into<String>) -> JsValue {
    let error = js_sys::Error::new(&message.into());
    let value: JsValue = error.into();
    let _ = js_sys::Reflect::set(&value, &JsValue::from_str("code"), &JsValue::from_str(code));
    value
}

fn wrapped_input_error(code: &str, error: JsValue) -> JsValue {
    let message = error
        .as_string()
        .unwrap_or_else(|| "invalid relay operation input".to_owned());
    structured_error(code, message)
}

pub(crate) fn relay_error(error: mtp_codec::RelayError) -> JsValue {
    let code = relay_error_code(&error);
    let message = format!("relay opening failed: {error}");
    let value = structured_error(code, message);
    if let RelayError::UnsupportedRelayVersion(version) = &error {
        let _ = js_sys::Reflect::set(
            &value,
            &JsValue::from_str("relayVersion"),
            &JsValue::bigint_from_str(&version.to_string()),
        );
    }
    if let RelayError::ReservedApplicationType(application_type) = &error {
        let _ = js_sys::Reflect::set(
            &value,
            &JsValue::from_str("applicationType"),
            &JsValue::from_str(application_type),
        );
    }
    value
}

fn relay_error_code(error: &RelayError) -> &'static str {
    match error {
        RelayError::NotRelay => "not-relay",
        RelayError::OuterSenderPresent => "outer-sender-present",
        RelayError::MissingNextHop => "missing-next-hop",
        RelayError::InvalidLayout(_) => "invalid-layout",
        RelayError::MissingRelayVersion => "missing-relay-version",
        RelayError::UnsupportedRelayVersion(_) => "unsupported-relay-version",
        RelayError::NotFinalRecipient => "not-final-recipient",
        RelayError::Replay => "replay",
        RelayError::ReservedApplicationType(_) => "reserved-application-type",
        RelayError::ReplayGuard(_) => "replay-guard-error",
        RelayError::Protection(error) => match error {
            ProtectionError::NoMatchingRecipient => "no-matching-recipient",
            ProtectionError::InvalidSignature => "invalid-signature",
            ProtectionError::SignaturePolicyMismatch { .. } => "signature-policy-mismatch",
            ProtectionError::PurposeMismatch { .. } => "purpose-mismatch",
            ProtectionError::SignerIdMismatch { .. } => "signer-id-mismatch",
            ProtectionError::SignerKeyNotFound(_) => "signer-key-not-found",
            ProtectionError::Crypto(mtp_crypto::CryptoError::InvalidSignature)
            | ProtectionError::Crypto(mtp_crypto::CryptoError::VerificationFailed) => {
                "invalid-signature"
            }
            _ => "protection-error",
        },
    }
}

pub(crate) fn decode_frame(frame: &[u8]) -> Result<CommunicationValue, JsValue> {
    CommunicationValue::from_bytes(frame).map_err(|error| {
        structured_error(
            "invalid-frame",
            format!("relay frame decoding failed: {error}"),
        )
    })
}

fn optional_u64(value: &JsValue, name: &str) -> Result<Option<u64>, JsValue> {
    if value.is_null() || value.is_undefined() {
        return Ok(None);
    }
    if let Some(number) = value.as_f64() {
        if !number.is_finite()
            || number.fract() != 0.0
            || !(0.0..=MAX_SAFE_INTEGER).contains(&number)
        {
            return Err(structured_error(
                "invalid-option",
                format!("{name} must be an exact non-negative integer"),
            ));
        }
        return Ok(Some(number as u64));
    }
    if value.js_typeof().as_string().as_deref() == Some("bigint") {
        let bigint = value.clone().unchecked_into::<js_sys::BigInt>();
        let text = bigint.to_string(10)?.as_string().ok_or_else(|| {
            structured_error("invalid-option", format!("failed to stringify {name}"))
        })?;
        return text
            .parse::<u64>()
            .map(Some)
            .map_err(|_| structured_error("invalid-option", format!("{name} is out of range")));
    }
    Err(structured_error(
        "invalid-option",
        format!("{name} must be a number or bigint"),
    ))
}

fn serialize_data_value(value: &DataValue) -> Result<Vec<u8>, JsValue> {
    value.to_bytes().map_err(|error| {
        structured_error(
            "invalid-data-value",
            format!("relay value encoding failed: {error}"),
        )
    })
}

#[wasm_bindgen]
pub struct WasmVerifiedRelayMetadata {
    inner: VerifiedRelayMetadata,
}

#[wasm_bindgen]
impl WasmVerifiedRelayMetadata {
    pub fn relay_version(&self) -> u64 {
        self.inner.relay_version()
    }

    pub fn signer_id(&self) -> u64 {
        self.inner.signer_id()
    }

    pub fn final_recipient_id(&self) -> u64 {
        self.inner.final_recipient_id()
    }

    pub fn message_id(&self) -> String {
        self.inner.message_id().to_owned()
    }

    pub fn created_at(&self) -> u64 {
        self.inner.created_at()
    }

    pub fn metadata(&self) -> Result<JsValue, JsValue> {
        match self.inner.metadata() {
            Some(value) => {
                let bytes = serialize_data_value(value)?;
                Ok(js_sys::Uint8Array::from(&bytes[..]).into())
            }
            None => Ok(JsValue::NULL),
        }
    }

    pub fn encrypted_content(&self) -> Result<Vec<u8>, JsValue> {
        serialize_data_value(self.inner.encrypted_content())
    }

    pub fn matched_signer_key_index(&self) -> usize {
        self.inner.matched_signer_key_index()
    }
}

#[wasm_bindgen]
pub struct WasmVerifiedRelayContent {
    inner: VerifiedRelayContent,
}

#[wasm_bindgen]
impl WasmVerifiedRelayContent {
    pub fn signer_id(&self) -> u64 {
        self.inner.signer_id
    }

    pub fn final_recipient_id(&self) -> u64 {
        self.inner.final_recipient_id
    }

    pub fn message_type(&self) -> String {
        self.inner.message_type.clone()
    }

    pub fn content(&self) -> Result<Vec<u8>, JsValue> {
        serialize_data_value(&self.inner.content)
    }
}

/// Read the claimed, unverified signer ID from a relay without duplicating the
/// versioned relay metadata parser in the JavaScript SDK. The caller must bind
/// this value as the expected signer during the subsequent verification call.
#[wasm_bindgen]
pub fn relay_metadata_claimed_signer_id(frame: &[u8], keyrings: JsValue) -> Result<u64, JsValue> {
    let frame = decode_frame(frame)?;
    let keyrings = keyrings_from_js(&keyrings)
        .map_err(|error| wrapped_input_error("invalid-recipient-keyrings", error))?;
    let references: Vec<&mtp_crypto::Keyring> = keyrings.iter().collect();
    mtp_codec::relay_metadata_claimed_signer_id(&frame, &references).map_err(relay_error)
}

/// Open and verify relay metadata in the native codec. JavaScript resolves
/// the trusted signing-key history before calling this function, while the
/// codec owns all relay layout and version interpretation.
#[wasm_bindgen]
pub fn open_relay_metadata_with_keyrings(
    frame: &[u8],
    keyrings: JsValue,
    expected_signer_id: JsValue,
    signer_public_key_bundles: JsValue,
    signature_suite: u8,
) -> Result<WasmVerifiedRelayMetadata, JsValue> {
    let frame = decode_frame(frame)?;
    let keyrings = keyrings_from_js(&keyrings)
        .map_err(|error| wrapped_input_error("invalid-recipient-keyrings", error))?;
    let references: Vec<&mtp_crypto::Keyring> = keyrings.iter().collect();
    let signer_public_keys = public_key_bundles_from_js(&signer_public_key_bundles)
        .map_err(|error| wrapped_input_error("invalid-signer-keys", error))?;
    let expected_signer_id = optional_u64(&expected_signer_id, "expectedSignerId")?
        .ok_or_else(|| structured_error("invalid-option", "expectedSignerId is required"))?;
    let policy = protection_policy_from_suite(signature_suite)
        .map_err(|error| wrapped_input_error("unsupported-signature-suite", error))?;
    let metadata = mtp_codec::open_relay_metadata_with_keys(
        &frame,
        &references,
        expected_signer_id,
        &signer_public_keys,
        policy,
    )
    .map_err(relay_error)?;
    Ok(WasmVerifiedRelayMetadata { inner: metadata })
}

/// Open and verify relay content in the native codec using recipient and
/// signer key histories supplied by the SDK.
#[wasm_bindgen]
pub fn open_relay_content_with_keyrings(
    metadata: &WasmVerifiedRelayMetadata,
    keyrings: JsValue,
    signer_public_key_bundles: JsValue,
    expected_final_recipient_id: JsValue,
    signature_suite: u8,
) -> Result<WasmVerifiedRelayContent, JsValue> {
    let keyrings = keyrings_from_js(&keyrings)
        .map_err(|error| wrapped_input_error("invalid-recipient-keyrings", error))?;
    let references: Vec<&mtp_crypto::Keyring> = keyrings.iter().collect();
    let signer_public_keys = public_key_bundles_from_js(&signer_public_key_bundles)
        .map_err(|error| wrapped_input_error("invalid-signer-keys", error))?;
    let expected_final_recipient_id =
        optional_u64(&expected_final_recipient_id, "expectedFinalRecipientId")?;
    let policy = protection_policy_from_suite(signature_suite)
        .map_err(|error| wrapped_input_error("unsupported-signature-suite", error))?;
    let content = mtp_codec::open_relay_content_with_keyrings(
        &metadata.inner,
        &references,
        &signer_public_keys,
        expected_final_recipient_id,
        policy,
    )
    .map_err(relay_error)?;
    Ok(WasmVerifiedRelayContent { inner: content })
}
