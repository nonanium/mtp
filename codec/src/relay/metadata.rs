use super::*;

pub(super) fn relay_field(
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<mtp_type_map::DataTypeId, RelayError> {
    data_type
        .try_to_id(type_map)
        .ok_or(RelayError::InvalidLayout(
            "reserved relay type is unavailable",
        ))
}

pub(super) fn validate_application_message_type(
    message_type: CommunicationType,
    type_map: &TypeMap,
) -> Result<(), RelayError> {
    let communication_id = message_type
        .try_to_id(type_map)
        .ok_or(RelayError::InvalidLayout(
            "relay message type is unavailable",
        ))?;
    if communication_id.is_reserved() {
        return Err(RelayError::ReservedApplicationType(
            message_type.name().to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_metadata_size(
    metadata: &DataValue,
    limits: &ProtectedLimits,
) -> Result<(), RelayError> {
    let encoded = metadata
        .to_bytes_with_limits(EncodeLimits {
            max_output_size: limits.max_metadata_encoded_bytes,
            ..EncodeLimits::default()
        })
        .map_err(|error| match error {
            mtp_common::CodecError::TooManyEntries => RelayError::ResourceLimit("metadata"),
            _ => RelayError::InvalidLayout("metadata cannot be encoded"),
        })?;
    if encoded.len() > limits.max_metadata_encoded_bytes {
        return Err(RelayError::ResourceLimit("metadata"));
    }
    Ok(())
}

pub(super) fn field<'a>(
    entries: &'a [(DataTypeId, DataValue)],
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<&'a DataValue, RelayError> {
    let field_id = relay_field(data_type, type_map)?;
    entries
        .iter()
        .find(|(id, _)| *id == field_id)
        .map(|(_, value)| value)
        .ok_or(RelayError::InvalidLayout("required relay field is missing"))
}

pub(super) fn string_field(
    entries: &[(DataTypeId, DataValue)],
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<String, RelayError> {
    field(entries, data_type, type_map)?
        .as_string()
        .filter(|value| !value.is_empty())
        .ok_or(RelayError::InvalidLayout(
            "relay field is not a non-empty string",
        ))
}

pub(super) fn message_id_field(
    entries: &[(DataTypeId, DataValue)],
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<MessageId, RelayError> {
    field(entries, data_type, type_map)?
        .as_unsigned_number()
        .map(MessageId::new)
        .ok_or(RelayError::InvalidLayout(
            "relay message ID is not unsigned",
        ))
}

pub(super) fn optional_metadata_field<'a>(
    entries: &'a [(DataTypeId, DataValue)],
    type_map: &TypeMap,
) -> Result<Option<&'a DataValue>, RelayError> {
    let field_id = relay_field(DataType::Metadata, type_map)?;
    Ok(entries
        .iter()
        .find(|(id, _)| *id == field_id)
        .map(|(_, value)| value))
}

pub(super) fn unsigned_field(
    entries: &[(DataTypeId, DataValue)],
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<u128, RelayError> {
    field(entries, data_type, type_map)?
        .as_unsigned_number()
        .ok_or(RelayError::InvalidLayout("relay field is not unsigned"))
}

pub(super) fn relay_version(
    entries: &[(DataTypeId, DataValue)],
    type_map: &TypeMap,
) -> Result<u64, RelayError> {
    let version_id = relay_field(DataType::RelayVersion, type_map)?;
    let version = entries
        .iter()
        .find(|(id, _)| *id == version_id)
        .map(|(_, value)| value)
        .ok_or(RelayError::MissingRelayVersion)?
        .as_unsigned_number()
        .ok_or(RelayError::InvalidLayout("relay version is not unsigned"))?;
    u64::try_from(version).map_err(|_| RelayError::InvalidLayout("relay version is out of range"))
}

pub(super) fn parse_relay_v1(
    entries: &[(DataTypeId, DataValue)],
    type_map: &TypeMap,
    limits: &ProtectedLimits,
) -> Result<RelayMetadataV1, RelayError> {
    let final_recipient_id = u64::try_from(unsigned_field(
        entries,
        DataType::FinalRecipientId,
        type_map,
    )?)
    .map_err(|_| RelayError::InvalidLayout("final recipient ID is out of range"))?;
    let created_at = u64::try_from(unsigned_field(entries, DataType::CreatedAt, type_map)?)
        .map_err(|_| RelayError::InvalidLayout("created-at value is out of range"))?;
    let encrypted_content = field(entries, DataType::Content, type_map)?.clone();
    if encrypted_content.as_encrypted().is_none() {
        return Err(RelayError::InvalidLayout("content is not encrypted"));
    }
    let message_id = message_id_field(entries, DataType::MessageId, type_map)?;
    let metadata = optional_metadata_field(entries, type_map)?;
    if let Some(metadata) = metadata {
        validate_metadata_size(metadata, limits)?;
    }
    Ok(RelayMetadataV1 {
        final_recipient_id,
        message_id,
        created_at,
        metadata: metadata.cloned(),
        encrypted_content,
    })
}

pub fn open_relay_metadata_checked(
    frame: &CommunicationValue,
    keyring: &Keyring,
    expected_signer_id: u64,
    signer_public_key: &PublicKeyBundle,
    options: RelayOpenOptions,
    replay_guard: &mut dyn ReplayGuard,
) -> Result<VerifiedRelayMetadata, RelayError> {
    open_relay_metadata_with_limits_checked(
        frame,
        std::slice::from_ref(&keyring),
        Some(expected_signer_id),
        |_| Some(vec![signer_public_key.clone()]),
        options,
        replay_guard,
    )
}

pub fn open_relay_metadata_without_replay(
    frame: &CommunicationValue,
    keyring: &Keyring,
    expected_signer_id: u64,
    signer_public_key: &PublicKeyBundle,
    options: RelayOpenOptions,
) -> Result<VerifiedRelayMetadata, RelayError> {
    open_relay_metadata_with_limits_without_replay(
        frame,
        std::slice::from_ref(&keyring),
        Some(expected_signer_id),
        |_| Some(vec![signer_public_key.clone()]),
        options,
    )
}

pub(super) fn validate_relay_frame(frame: &CommunicationValue) -> Result<(), RelayError> {
    if !frame.is_type(CommunicationType::Relay) {
        return Err(RelayError::NotRelay);
    }
    if frame.sender().is_some() {
        return Err(RelayError::OuterSenderPresent);
    }
    if frame.receiver().is_none() {
        return Err(RelayError::MissingNextHop);
    }
    Ok(())
}

/// Return the claimed signer ID from relay metadata without verifying its
/// signature or interpreting the versioned relay schema. The result is
/// untrusted and may only select the key history that is then bound to the
/// same signer ID during [`open_relay_metadata_with_keys`].
#[deprecated(note = "use relay_metadata_claimed_signer_id_with_limits")]
pub fn relay_metadata_claimed_signer_id(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
) -> Result<u64, RelayError> {
    // Migrate to `relay_metadata_claimed_signer_id_with_limits` at receive boundaries.
    relay_metadata_claimed_signer_id_with_limits(frame, keyrings, DecodeLimits::default())
}

pub fn relay_metadata_claimed_signer_id_with_limits(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    decode_limits: DecodeLimits,
) -> Result<u64, RelayError> {
    relay_metadata_claimed_signer_id_with_options(
        frame,
        keyrings,
        decode_limits,
        ProtectedLimits::default(),
    )
}

/// Return the claimed relay signer ID while applying the complete receive
/// policy, including the caller's decryption-key history bound.
pub fn relay_metadata_claimed_signer_id_with_options(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    decode_limits: DecodeLimits,
    protected_limits: ProtectedLimits,
) -> Result<u64, RelayError> {
    validate_relay_frame(frame)?;
    if keyrings.len() > protected_limits.max_decryption_key_history {
        return Err(RelayError::ResourceLimit("decryption key history"));
    }

    let decrypted = frame.payload().decrypt_with_keyrings_and_limits(
        keyrings,
        MtpProtectionPurpose::RelayMetadataEncryption.into(),
        decode_limits,
    )?;
    let signed = decrypted
        .as_signed()
        .ok_or(RelayError::InvalidLayout("metadata is not signed"))?;
    Ok(signed.signer_id)
}

/// Decrypt and verify relay metadata using recipient-key history and a
/// signer-key resolver. The resolver receives a claimed, unverified signer
/// ID used only as a trusted-key lookup key. The ID becomes authenticated
/// only after signature verification. This is the native counterpart of the
/// browser relay API and supports sealed sender plus signing-key rotation.
pub fn open_relay_metadata_with_checked<F>(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    expected_signer_id: Option<u64>,
    resolve_signer_keys: F,
    options: RelayOpenOptions,
    replay_guard: &mut dyn ReplayGuard,
) -> Result<VerifiedRelayMetadata, RelayError>
where
    F: FnOnce(u64) -> Option<Vec<PublicKeyBundle>>,
{
    open_relay_metadata_with_limits_checked(
        frame,
        keyrings,
        expected_signer_id,
        resolve_signer_keys,
        options,
        replay_guard,
    )
}

/// Open relay metadata for message processing with replay protection required
/// by the type system.
pub fn open_relay_metadata_with_limits_checked<F>(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    expected_signer_id: Option<u64>,
    resolve_signer_keys: F,
    options: RelayOpenOptions,
    replay_guard: &mut dyn ReplayGuard,
) -> Result<VerifiedRelayMetadata, RelayError>
where
    F: FnOnce(u64) -> Option<Vec<PublicKeyBundle>>,
{
    open_relay_metadata_impl(
        frame,
        keyrings,
        expected_signer_id,
        resolve_signer_keys,
        options,
        Some(replay_guard),
    )
}

pub fn open_relay_metadata_with_without_replay<F>(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    expected_signer_id: Option<u64>,
    resolve_signer_keys: F,
    options: RelayOpenOptions,
) -> Result<VerifiedRelayMetadata, RelayError>
where
    F: FnOnce(u64) -> Option<Vec<PublicKeyBundle>>,
{
    open_relay_metadata_with_limits_without_replay(
        frame,
        keyrings,
        expected_signer_id,
        resolve_signer_keys,
        options,
    )
}

/// Open relay metadata for stored/forensic use without replay protection.
/// The name makes the security trade-off explicit at the call site.
pub fn open_relay_metadata_with_limits_without_replay<F>(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    expected_signer_id: Option<u64>,
    resolve_signer_keys: F,
    options: RelayOpenOptions,
) -> Result<VerifiedRelayMetadata, RelayError>
where
    F: FnOnce(u64) -> Option<Vec<PublicKeyBundle>>,
{
    open_relay_metadata_impl(
        frame,
        keyrings,
        expected_signer_id,
        resolve_signer_keys,
        options,
        None,
    )
}

pub(super) fn open_relay_metadata_impl<F>(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    expected_signer_id: Option<u64>,
    resolve_signer_keys: F,
    options: RelayOpenOptions,
    mut replay_guard: Option<&mut dyn ReplayGuard>,
) -> Result<VerifiedRelayMetadata, RelayError>
where
    F: FnOnce(u64) -> Option<Vec<PublicKeyBundle>>,
{
    validate_relay_frame(frame)?;

    if keyrings.len() > options.protected_limits.max_decryption_key_history {
        return Err(RelayError::ResourceLimit("decryption key history"));
    }

    let type_map = frame
        .type_map()
        .cloned()
        .ok_or(RelayError::InvalidLayout("missing negotiated dictionary"))?;
    let decrypted = frame.payload().decrypt_with_keyrings_and_limits(
        keyrings,
        MtpProtectionPurpose::RelayMetadataEncryption.into(),
        options.decode_limits,
    )?;
    let signed = decrypted
        .as_signed()
        .ok_or(RelayError::InvalidLayout("metadata is not signed"))?;
    if let Some(expected_signer_id) = expected_signer_id
        && signed.signer_id != expected_signer_id
    {
        return Err(ProtectionError::SignerIdMismatch {
            expected: expected_signer_id,
            actual: signed.signer_id,
        }
        .into());
    }
    let signer_keys = resolve_signer_keys(signed.signer_id)
        .ok_or(ProtectionError::SignerKeyNotFound(signed.signer_id))?;
    if signer_keys.len() > options.protected_limits.max_signer_key_history {
        return Err(RelayError::ResourceLimit("signer key history"));
    }
    let matched_signer_key_index = signed.verify_with_key_history_index_and_limits(
        signed.signer_id,
        &signer_keys,
        MtpProtectionPurpose::RelayMetadataSignature.into(),
        options.policy,
        options.encode_limits,
    )?;
    /* Verification leaves the signed envelope owned by `decrypted`; inspect
    its entries in place to avoid a second attacker-controlled clone. */
    let metadata = signed
        .value
        .container_entries()
        .ok_or(RelayError::InvalidLayout("metadata is not a container"))?;
    let relay_version = relay_version(metadata, &type_map)?;
    if relay_version != CURRENT_RELAY_VERSION {
        return Err(RelayError::UnsupportedRelayVersion(relay_version));
    }
    let expected = type_map
        .fingerprint()
        .ok_or(RelayError::InvalidLayout("unknown dictionary"))?;
    if field(metadata, DataType::DictionaryFingerprint, &type_map)?.as_bytes_slice()
        != Some(expected.as_slice())
    {
        return Err(RelayError::InvalidLayout("dictionary fingerprint mismatch"));
    }
    let parsed = match relay_version {
        1 => parse_relay_v1(metadata, &type_map, &options.protected_limits)?,
        other => return Err(RelayError::UnsupportedRelayVersion(other)),
    };
    let result = VerifiedRelayMetadata {
        relay_version,
        signer_id: signed.signer_id,
        final_recipient_id: parsed.final_recipient_id,
        message_id: parsed.message_id,
        created_at: parsed.created_at,
        metadata: parsed.metadata,
        encrypted_content: parsed.encrypted_content,
        type_map,
        matched_signer_key_index,
        decode_limits: options.decode_limits,
        encode_limits: options.encode_limits,
        protected_limits: options.protected_limits,
        _verified: VerifiedMarker,
    };
    if let Some(guard) = replay_guard.as_mut()
        && !guard.accept(result.signer_id, result.message_id, result.created_at)?
    {
        return Err(RelayError::Replay);
    }
    Ok(result)
}
