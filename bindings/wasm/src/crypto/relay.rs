use super::*;

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
pub(super) fn build_encrypted_relay_frame_impl(
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
        CommunicationType::from_name(message_type).ok_or_else(|| {
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
