use wasm_bindgen::prelude::*;

use mtp_codec::{
    CommunicationValue, DataValue, DecodeLimits, EncodeLimits, ProtectedLimits, ProtectionError,
    ProtectionPolicy, RelayError, RelayOpenOptions, VerifiedRelayContent, VerifiedRelayMetadata,
};

use crate::crypto::{keyrings_from_js, protection_policy_from_suite, public_key_bundles_from_js};

const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

pub(crate) fn structured_error(code: &str, message: impl Into<String>) -> JsValue {
    let error = js_sys::Error::new(&message.into());
    let value: JsValue = error.into();
    let _ = js_sys::Reflect::set(&value, &JsValue::from_str("code"), &JsValue::from_str(code));
    value
}

pub(crate) fn decode_error(error: mtp_codec::DecodeError, context: &str) -> JsValue {
    let value = structured_error("invalid-frame", format!("{context}: {error}"));
    let _ = js_sys::Reflect::set(
        &value,
        &JsValue::from_str("decodeCode"),
        &JsValue::from_str(decode_error_code(&error)),
    );
    value
}

pub(crate) fn decode_error_code(error: &mtp_codec::DecodeError) -> &'static str {
    match error {
        mtp_codec::DecodeError::MalformedEncoding => "malformed-encoding",
        mtp_codec::DecodeError::DepthLimit => "depth-limit",
        mtp_codec::DecodeError::ValueCountLimit => "value-count-limit",
        mtp_codec::DecodeError::BlobLimit => "blob-limit",
        mtp_codec::DecodeError::AllocationLimit => "allocation-limit",
        mtp_codec::DecodeError::RecipientLimit => "recipient-limit",
        mtp_codec::DecodeError::DuplicateField => "duplicate-field",
    }
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
        RelayError::ResourceLimit(_) => "resource-limit",
        RelayError::ReservedApplicationType(_) => "reserved-application-type",
        RelayError::ReplayGuard(_) => "replay-guard-error",
        RelayError::Protection(error) => match error {
            ProtectionError::NoMatchingRecipient => "no-matching-recipient",
            ProtectionError::InvalidSignature => "invalid-signature",
            ProtectionError::SignaturePolicyMismatch { .. } => "signature-policy-mismatch",
            ProtectionError::PurposeMismatch { .. } => "purpose-mismatch",
            ProtectionError::SignerIdMismatch { .. } => "signer-id-mismatch",
            ProtectionError::SignerKeyNotFound(_) => "signer-key-not-found",
            ProtectionError::ResourceLimit(_) => "resource-limit",
            ProtectionError::Crypto(mtp_crypto::CryptoError::InvalidSignature)
            | ProtectionError::Crypto(mtp_crypto::CryptoError::VerificationFailed) => {
                "invalid-signature"
            }
            _ => "protection-error",
        },
    }
}

pub(crate) fn decode_frame(frame: &[u8]) -> Result<CommunicationValue, JsValue> {
    decode_frame_with_limits(frame, DecodeLimits::default())
}

pub(crate) fn decode_frame_with_limits(
    frame: &[u8],
    limits: DecodeLimits,
) -> Result<CommunicationValue, JsValue> {
    CommunicationValue::try_from_bytes_with_limits(frame, limits)
        .map_err(|error| decode_error(error, "relay frame decoding failed"))
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

fn limit_usize(options: &JsValue, key: &str, default: usize) -> Result<usize, JsValue> {
    if options.is_null() || options.is_undefined() {
        return Ok(default);
    }
    let value = js_sys::Reflect::get(options, &JsValue::from_str(key))?;
    if value.is_null() || value.is_undefined() {
        return Ok(default);
    }
    let Some(number) = value.as_f64() else {
        return Err(structured_error(
            "invalid-limit",
            format!("{key} must be a number"),
        ));
    };
    if !number.is_finite() || number.fract() != 0.0 || number < 0.0 {
        return Err(structured_error(
            "invalid-limit",
            format!("{key} must be a non-negative integer"),
        ));
    }
    usize::try_from(number as u64)
        .map_err(|_| structured_error("invalid-limit", format!("{key} is out of range")))
}

pub(crate) fn relay_open_options(
    policy: mtp_codec::ProtectionPolicy,
    limits: &JsValue,
) -> Result<RelayOpenOptions, JsValue> {
    let decode_defaults = DecodeLimits::default();
    let encode_defaults = EncodeLimits::default();
    let protected_defaults = ProtectedLimits::default();
    let options = RelayOpenOptions::new(policy).with_limits(
        DecodeLimits {
            max_depth: limit_usize(limits, "maxDepth", decode_defaults.max_depth)?,
            max_values: limit_usize(limits, "maxValues", decode_defaults.max_values)?,
            max_blob_size: limit_usize(limits, "maxBlobSize", decode_defaults.max_blob_size)?,
            max_recipients: limit_usize(limits, "maxRecipients", decode_defaults.max_recipients)?,
            max_allocated_bytes: limit_usize(
                limits,
                "maxAllocatedBytes",
                decode_defaults.max_allocated_bytes,
            )?,
        },
        ProtectedLimits {
            max_metadata_encoded_bytes: limit_usize(
                limits,
                "maxMetadataEncodedBytes",
                protected_defaults.max_metadata_encoded_bytes,
            )?,
            max_signer_key_history: limit_usize(
                limits,
                "maxSignerKeyHistory",
                protected_defaults.max_signer_key_history,
            )?,
            max_decryption_key_history: limit_usize(
                limits,
                "maxDecryptionKeyHistory",
                protected_defaults.max_decryption_key_history,
            )?,
        },
    );
    Ok(options.with_encode_limits(EncodeLimits {
        max_depth: limit_usize(limits, "maxDepth", encode_defaults.max_depth)?,
        max_values: limit_usize(limits, "maxValues", encode_defaults.max_values)?,
        max_output_size: limit_usize(limits, "maxOutputSize", encode_defaults.max_output_size)?,
    }))
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

    pub fn message_id(&self) -> u128 {
        self.inner.message_id().get()
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
        self.inner.message_type.name().to_owned()
    }

    pub fn content(&self) -> Result<Vec<u8>, JsValue> {
        serialize_data_value(&self.inner.content)
    }
}

/// Read the claimed, unverified signer ID from a relay without duplicating the
/// versioned relay metadata parser in the JavaScript SDK. The caller must bind
/// this value as the expected signer during the subsequent verification call.
#[wasm_bindgen]
#[allow(deprecated)]
#[deprecated(note = "use relay_metadata_claimed_signer_id_with_limits")]
pub fn relay_metadata_claimed_signer_id(frame: &[u8], keyrings: JsValue) -> Result<u64, JsValue> {
    relay_metadata_claimed_signer_id_impl(frame, keyrings, JsValue::UNDEFINED)
}

fn relay_metadata_claimed_signer_id_impl(
    frame: &[u8],
    keyrings: JsValue,
    limits: JsValue,
) -> Result<u64, JsValue> {
    let options = relay_open_options(ProtectionPolicy::any_supported(), &limits)?;
    let frame = decode_frame_with_limits(frame, options.decode_limits)?;
    let keyrings = keyrings_from_js(&keyrings)
        .map_err(|error| wrapped_input_error("invalid-recipient-keyrings", error))?;
    if keyrings.len() > options.protected_limits.max_decryption_key_history {
        return Err(relay_error(RelayError::ResourceLimit(
            "decryption key history",
        )));
    }
    let references: Vec<&mtp_crypto::Keyring> = keyrings.iter().collect();
    mtp_codec::relay_metadata_claimed_signer_id_with_options(
        &frame,
        &references,
        options.decode_limits,
        options.protected_limits,
    )
    .map_err(relay_error)
}

#[wasm_bindgen]
pub fn relay_metadata_claimed_signer_id_with_limits(
    frame: &[u8],
    keyrings: JsValue,
    limits: JsValue,
) -> Result<u64, JsValue> {
    relay_metadata_claimed_signer_id_impl(frame, keyrings, limits)
}

/// Open relay metadata without replay protection. This raw entry point is for
/// stored/forwarded messages; message-processing paths should add a guard in
/// the SDK or use the checked native API.
#[wasm_bindgen]
pub fn open_relay_metadata_with_keyrings_without_replay(
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
    let metadata = mtp_codec::open_relay_metadata_with_limits_without_replay(
        &frame,
        &references,
        Some(expected_signer_id),
        move |_| Some(signer_public_keys),
        RelayOpenOptions::new(policy),
    )
    .map_err(relay_error)?;
    Ok(WasmVerifiedRelayMetadata { inner: metadata })
}

/// Open bounded relay metadata without replay protection. Use the SDK's
/// message-processing guard or a native checked API for live traffic.
#[wasm_bindgen]
pub fn open_relay_metadata_with_keyrings_with_limits_without_replay(
    frame: &[u8],
    keyrings: JsValue,
    expected_signer_id: JsValue,
    signer_public_key_bundles: JsValue,
    signature_suite: u8,
    limits: JsValue,
) -> Result<WasmVerifiedRelayMetadata, JsValue> {
    let keyrings = keyrings_from_js(&keyrings)
        .map_err(|error| wrapped_input_error("invalid-recipient-keyrings", error))?;
    let references: Vec<&mtp_crypto::Keyring> = keyrings.iter().collect();
    let signer_public_keys = public_key_bundles_from_js(&signer_public_key_bundles)
        .map_err(|error| wrapped_input_error("invalid-signer-keys", error))?;
    let expected_signer_id = optional_u64(&expected_signer_id, "expectedSignerId")?
        .ok_or_else(|| structured_error("invalid-option", "expectedSignerId is required"))?;
    let policy = protection_policy_from_suite(signature_suite)
        .map_err(|error| wrapped_input_error("unsupported-signature-suite", error))?;
    let options = relay_open_options(policy, &limits)?;
    let frame = decode_frame_with_limits(frame, options.decode_limits)?;
    let metadata = mtp_codec::open_relay_metadata_with_limits_without_replay(
        &frame,
        &references,
        Some(expected_signer_id),
        move |_| Some(signer_public_keys),
        options,
    )
    .map_err(relay_error)?;
    Ok(WasmVerifiedRelayMetadata { inner: metadata })
}

/// Open relay content without making a second replay decision. Replay is
/// consumed when live message processing accepts the authenticated metadata.
#[wasm_bindgen]
pub fn open_relay_content_with_keyrings_without_replay(
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
    let content = mtp_codec::open_relay_content_with_limits_without_replay(
        &metadata.inner,
        &references,
        &signer_public_keys,
        expected_final_recipient_id,
        RelayOpenOptions {
            policy,
            decode_limits: metadata.inner.decode_limits(),
            encode_limits: metadata.inner.encode_limits(),
            protected_limits: metadata.inner.protected_limits(),
        },
    )
    .map_err(relay_error)?;
    Ok(WasmVerifiedRelayContent { inner: content })
}

/// Open bounded relay content without replay protection. Replay is consumed
/// when metadata is accepted by the live SDK/native processing boundary.
#[wasm_bindgen]
pub fn open_relay_content_with_keyrings_with_limits_without_replay(
    metadata: &WasmVerifiedRelayMetadata,
    keyrings: JsValue,
    signer_public_key_bundles: JsValue,
    expected_final_recipient_id: JsValue,
    signature_suite: u8,
    limits: JsValue,
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
    let options = relay_open_options(policy, &limits)?;
    let content = mtp_codec::open_relay_content_with_limits_without_replay(
        &metadata.inner,
        &references,
        &signer_public_keys,
        expected_final_recipient_id,
        options,
    )
    .map_err(relay_error)?;
    Ok(WasmVerifiedRelayContent { inner: content })
}
