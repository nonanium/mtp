use super::*;

/// Open and verify content after metadata has been authenticated.
#[deprecated(note = "use open_relay_content_with_limits_without_replay")]
pub fn open_relay_content(
    metadata: &VerifiedRelayMetadata,
    keyring: &Keyring,
    signer_public_key: &PublicKeyBundle,
    expected_recipient_id: u64,
    policy: ProtectionPolicy,
) -> Result<VerifiedRelayContent, RelayError> {
    open_relay_content_with_limits_without_replay(
        metadata,
        std::slice::from_ref(&keyring),
        std::slice::from_ref(signer_public_key),
        Some(expected_recipient_id),
        RelayOpenOptions {
            policy,
            decode_limits: metadata.decode_limits,
            encode_limits: metadata.encode_limits,
            protected_limits: metadata.protected_limits,
        },
    )
}

/// Open relay content against trusted signing-key history for the metadata's
/// authenticated signer ID.
#[deprecated(note = "use open_relay_content_with_limits_without_replay")]
pub fn open_relay_content_with_keys(
    metadata: &VerifiedRelayMetadata,
    keyring: &Keyring,
    signer_public_keys: &[PublicKeyBundle],
    expected_recipient_id: u64,
    policy: ProtectionPolicy,
) -> Result<VerifiedRelayContent, RelayError> {
    open_relay_content_with_limits_without_replay(
        metadata,
        std::slice::from_ref(&keyring),
        signer_public_keys,
        Some(expected_recipient_id),
        RelayOpenOptions {
            policy,
            decode_limits: metadata.decode_limits,
            encode_limits: metadata.encode_limits,
            protected_limits: metadata.protected_limits,
        },
    )
}

/// Open relay content against recipient-key history and trusted signing-key
/// history. The expected final recipient is optional for callers that only
/// have decryption material and do not have a local identity ID.
#[deprecated(note = "use open_relay_content_with_limits_without_replay")]
pub fn open_relay_content_with_keyrings(
    metadata: &VerifiedRelayMetadata,
    keyrings: &[&Keyring],
    signer_public_keys: &[PublicKeyBundle],
    expected_recipient_id: Option<u64>,
    policy: ProtectionPolicy,
) -> Result<VerifiedRelayContent, RelayError> {
    // Migrate to `open_relay_content_with_limits_without_replay` to keep the decode policy
    // explicit across metadata and content opening.
    open_relay_content_with_limits_without_replay(
        metadata,
        keyrings,
        signer_public_keys,
        expected_recipient_id,
        RelayOpenOptions {
            policy,
            decode_limits: metadata.decode_limits,
            encode_limits: metadata.encode_limits,
            protected_limits: metadata.protected_limits,
        },
    )
}

#[deprecated(note = "use open_relay_content_with_limits_without_replay")]
pub fn open_relay_content_with_keyrings_and_limits(
    metadata: &VerifiedRelayMetadata,
    keyrings: &[&Keyring],
    signer_public_keys: &[PublicKeyBundle],
    expected_recipient_id: Option<u64>,
    options: RelayOpenOptions,
) -> Result<VerifiedRelayContent, RelayError> {
    open_relay_content_with_limits_without_replay(
        metadata,
        keyrings,
        signer_public_keys,
        expected_recipient_id,
        options,
    )
}

/// Compatibility alias for callers that already hold authenticated relay
/// metadata. New code should use the explicit `_without_replay` name.
#[deprecated(note = "use open_relay_content_with_limits_without_replay")]
pub fn open_relay_content_with_limits(
    metadata: &VerifiedRelayMetadata,
    keyrings: &[&Keyring],
    signer_public_keys: &[PublicKeyBundle],
    expected_recipient_id: Option<u64>,
    options: RelayOpenOptions,
) -> Result<VerifiedRelayContent, RelayError> {
    open_relay_content_with_limits_without_replay(
        metadata,
        keyrings,
        signer_public_keys,
        expected_recipient_id,
        options,
    )
}

/// Open relay content after the authenticated metadata operation without
/// making a second replay decision. Replay is consumed by the metadata
/// processing boundary; this explicit name prevents callers from mistaking
/// content opening for an independent replay check.
pub fn open_relay_content_with_limits_without_replay(
    metadata: &VerifiedRelayMetadata,
    keyrings: &[&Keyring],
    signer_public_keys: &[PublicKeyBundle],
    expected_recipient_id: Option<u64>,
    options: RelayOpenOptions,
) -> Result<VerifiedRelayContent, RelayError> {
    let options = RelayOpenOptions {
        policy: options.policy,
        decode_limits: options.decode_limits.intersection(metadata.decode_limits),
        encode_limits: options.encode_limits.intersection(metadata.encode_limits),
        protected_limits: restrict_protected_limits(
            options.protected_limits,
            metadata.protected_limits,
        ),
    };
    if expected_recipient_id.is_some_and(|id| metadata.final_recipient_id != id) {
        return Err(RelayError::NotFinalRecipient);
    }
    if keyrings.len() > options.protected_limits.max_decryption_key_history {
        return Err(RelayError::ResourceLimit("decryption key history"));
    }
    if signer_public_keys.len() > options.protected_limits.max_signer_key_history {
        return Err(RelayError::ResourceLimit("signer key history"));
    }

    let type_map = &metadata.type_map;
    let decrypted = metadata
        .encrypted_content
        .decrypt_with_keyrings_and_limits(
            keyrings,
            MtpProtectionPurpose::RelayContentEncryption.into(),
            options.decode_limits,
        )?;
    let signed = decrypted
        .as_signed()
        .ok_or(RelayError::InvalidLayout("content is not signed"))?;
    if signed.signer_id != metadata.signer_id {
        return Err(RelayError::InvalidLayout(
            "metadata and content signer IDs differ",
        ));
    }
    // Content is a separately signed value and must not inherit a weaker
    // metadata policy.
    signed.verify_with_key_history_and_limits(
        metadata.signer_id,
        signer_public_keys,
        MtpProtectionPurpose::RelayContentSignature.into(),
        options.policy,
        options.encode_limits,
    )?;
    let content = signed
        .value
        .container_entries()
        .ok_or(RelayError::InvalidLayout("content is not a container"))?;
    let message_type =
        CommunicationType::from_name(&string_field(content, DataType::MessageType, type_map)?)
            .ok_or(RelayError::InvalidLayout("relay message type is unknown"))?;
    let expected = type_map
        .fingerprint()
        .ok_or(RelayError::InvalidLayout("unknown dictionary"))?;
    if field(content, DataType::DictionaryFingerprint, type_map)?.as_bytes_slice()
        != Some(expected.as_slice())
    {
        return Err(RelayError::InvalidLayout("dictionary fingerprint mismatch"));
    }
    validate_application_message_type(message_type, type_map)?;
    Ok(VerifiedRelayContent {
        signer_id: signed.signer_id,
        final_recipient_id: metadata.final_recipient_id,
        message_type,
        content: field(content, DataType::Content, type_map)?.clone(),
    })
}

pub(super) fn restrict_protected_limits(
    left: ProtectedLimits,
    right: ProtectedLimits,
) -> ProtectedLimits {
    ProtectedLimits {
        max_metadata_encoded_bytes: left
            .max_metadata_encoded_bytes
            .min(right.max_metadata_encoded_bytes),
        max_signer_key_history: left
            .max_signer_key_history
            .min(right.max_signer_key_history),
        max_decryption_key_history: left
            .max_decryption_key_history
            .min(right.max_decryption_key_history),
    }
}
