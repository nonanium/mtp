use super::*;

pub(super) fn protected_field_id(
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<mtp_type_map::DataTypeId, ProtectedError> {
    data_type
        .try_to_id(type_map)
        .ok_or(ProtectedError::InvalidLayout(
            "reserved protected type is unavailable",
        ))
}

pub(super) fn validate_application_message_type(
    message_type: CommunicationType,
    type_map: &TypeMap,
) -> Result<CommunicationType, ProtectedError> {
    let communication_id =
        message_type
            .try_to_id(type_map)
            .ok_or(ProtectedError::InvalidLayout(
                "protected message type is unavailable",
            ))?;
    if communication_id.is_reserved() {
        return Err(ProtectedError::ReservedApplicationType(
            message_type.name().to_owned(),
        ));
    }
    Ok(message_type)
}

pub(super) fn validate_protected_frame(
    frame: &CommunicationValue,
) -> Result<TypeMap, ProtectedError> {
    let type_map = frame
        .type_map()
        .cloned()
        .ok_or(ProtectedError::InvalidLayout(
            "missing negotiated dictionary",
        ))?;
    let Some(communication_type) = frame.get_comm_type_enum() else {
        return Err(ProtectedError::NotApplicationFrame);
    };
    let communication_id = communication_type
        .try_to_id(&type_map)
        .ok_or(ProtectedError::NotApplicationFrame)?;
    if communication_id.is_reserved() {
        return Err(ProtectedError::ReservedApplicationType(
            communication_type.name().to_owned(),
        ));
    }
    if frame.receiver().is_none() {
        return Err(ProtectedError::MissingReceiver);
    }
    Ok(type_map)
}

pub(super) fn field<'a>(
    entries: &'a [(DataTypeId, DataValue)],
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<&'a DataValue, ProtectedError> {
    let field_id = protected_field_id(data_type, type_map)?;
    entries
        .iter()
        .find(|(id, _)| *id == field_id)
        .map(|(_, value)| value)
        .ok_or(ProtectedError::InvalidLayout(
            "required protected field is missing",
        ))
}

pub(super) fn take_field(
    entries: &mut Vec<(DataTypeId, DataValue)>,
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<DataValue, ProtectedError> {
    let field_id = protected_field_id(data_type, type_map)?;
    let index =
        entries
            .iter()
            .position(|(id, _)| *id == field_id)
            .ok_or(ProtectedError::InvalidLayout(
                "required protected field is missing",
            ))?;
    Ok(entries.remove(index).1)
}

pub(super) fn unsigned_field(
    entries: &[(DataTypeId, DataValue)],
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<u128, ProtectedError> {
    field(entries, data_type, type_map)?
        .as_unsigned_number()
        .ok_or(ProtectedError::InvalidLayout(
            "protected field is not unsigned",
        ))
}

pub(super) fn string_field(
    entries: &[(DataTypeId, DataValue)],
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<String, ProtectedError> {
    field(entries, data_type, type_map)?
        .as_string()
        .filter(|value| !value.is_empty())
        .ok_or(ProtectedError::InvalidLayout(
            "protected field is not a non-empty string",
        ))
}

pub(super) fn communication_type_field(
    entries: &[(DataTypeId, DataValue)],
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<CommunicationType, ProtectedError> {
    let value = string_field(entries, data_type, type_map)?;
    CommunicationType::from_name(&value).ok_or(ProtectedError::InvalidLayout(
        "protected message type is unknown",
    ))
}

pub(super) fn message_id_field(
    entries: &[(DataTypeId, DataValue)],
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<MessageId, ProtectedError> {
    field(entries, data_type, type_map)?
        .as_unsigned_number()
        .map(MessageId::new)
        .ok_or(ProtectedError::InvalidLayout(
            "protected message ID is not unsigned",
        ))
}

pub(super) fn protected_version(
    entries: &[(DataTypeId, DataValue)],
    type_map: &TypeMap,
) -> Result<u64, ProtectedError> {
    let version_id = protected_field_id(DataType::ProtectedVersion, type_map)?;
    let version = entries
        .iter()
        .find(|(id, _)| *id == version_id)
        .map(|(_, value)| value)
        .ok_or(ProtectedError::MissingProtectedVersion)?
        .as_unsigned_number()
        .ok_or(ProtectedError::InvalidLayout(
            "protected version is not unsigned",
        ))?;
    u64::try_from(version)
        .map_err(|_| ProtectedError::InvalidLayout("protected version is out of range"))
}

pub(super) fn decrypt_protected_payload(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    encryption_purpose: ProtectionPurpose,
    decode_limits: DecodeLimits,
    max_decryption_key_history: usize,
) -> Result<DataValue, ProtectedError> {
    if keyrings.len() > max_decryption_key_history {
        return Err(ProtectedError::ResourceLimit("decryption key history"));
    }
    frame
        .payload()
        .decrypt_with_keyrings_and_limits(keyrings, encryption_purpose, decode_limits)
        .map_err(|error| match error {
            ProtectionError::NotEncrypted => ProtectedError::PayloadNotEncrypted,
            other => ProtectedError::Protection(other),
        })
}

/// Return the claimed signer ID after decryption, without verifying its
/// signature. The value is untrusted and may only select the key history that
/// is then bound to the same signer ID during the subsequent open.
#[deprecated(note = "use protected_claimed_signer_id_with_limits; pass the receive DecodeLimits")]
pub fn protected_claimed_signer_id(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    encryption_purpose: ProtectionPurpose,
) -> Result<u64, ProtectedError> {
    // Migrate to `protected_claimed_signer_id_with_limits` at receive boundaries.
    protected_claimed_signer_id_with_limits(
        frame,
        keyrings,
        encryption_purpose,
        DecodeLimits::default(),
    )
}

pub fn protected_claimed_signer_id_with_limits(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    encryption_purpose: ProtectionPurpose,
    decode_limits: DecodeLimits,
) -> Result<u64, ProtectedError> {
    protected_claimed_signer_id_with_options(
        frame,
        keyrings,
        encryption_purpose,
        decode_limits,
        ProtectedLimits::default(),
    )
}

/// Return the claimed signer ID while applying the complete receive policy.
///
/// This is deliberately separate from the compatibility decoder above: the
/// claimed ID is used to select a signer-key history, so the decryption-key
/// history bound must be the same bound used by the eventual open operation.
pub fn protected_claimed_signer_id_with_options(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    encryption_purpose: ProtectionPurpose,
    decode_limits: DecodeLimits,
    protected_limits: ProtectedLimits,
) -> Result<u64, ProtectedError> {
    validate_protected_frame(frame)?;
    let decrypted = decrypt_protected_payload(
        frame,
        keyrings,
        encryption_purpose,
        decode_limits,
        protected_limits.max_decryption_key_history,
    )?;
    let signed = decrypted
        .as_signed()
        .ok_or(ProtectedError::PayloadNotSigned)?;
    Ok(signed.signer_id)
}

pub(super) fn open_protected_with_impl<F>(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    expected_signer_id: Option<u64>,
    resolve_signer_keys: F,
    options: ProtectedOpenOptions,
    replay_guard: Option<&mut dyn ReplayGuard>,
) -> Result<VerifiedProtectedMessage, ProtectedError>
where
    F: FnOnce(u64) -> Option<Vec<PublicKeyBundle>>,
{
    validate_protected_frame(frame)?;
    let type_map = frame.type_map().cloned().unwrap_or_else(TypeMap::latest);
    let mut decrypted = decrypt_protected_payload(
        frame,
        keyrings,
        options.encryption_purpose,
        options.decode_limits,
        options.protected_limits.max_decryption_key_history,
    )?;
    let signer_id = decrypted
        .as_signed()
        .ok_or(ProtectedError::PayloadNotSigned)?;
    let signer_id = signer_id.signer_id;
    if let Some(expected_signer_id) = expected_signer_id
        && signer_id != expected_signer_id
    {
        return Err(ProtectionError::SignerIdMismatch {
            expected: expected_signer_id,
            actual: signer_id,
        }
        .into());
    }
    let signer_keys =
        resolve_signer_keys(signer_id).ok_or(ProtectionError::SignerKeyNotFound(signer_id))?;
    if signer_keys.len() > options.protected_limits.max_signer_key_history {
        return Err(ProtectedError::ResourceLimit("signer key history"));
    }
    let signed = decrypted
        .as_signed_mut()
        .ok_or(ProtectedError::PayloadNotSigned)?;
    open_decrypted_protected(frame, type_map, signed, &signer_keys, options, replay_guard)
}

pub fn open_protected_with_checked<F>(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    expected_signer_id: Option<u64>,
    resolve_signer_keys: F,
    options: ProtectedOpenOptions,
    replay_guard: &mut dyn ReplayGuard,
) -> Result<VerifiedProtectedMessage, ProtectedError>
where
    F: FnOnce(u64) -> Option<Vec<PublicKeyBundle>>,
{
    open_protected_with_impl(
        frame,
        keyrings,
        expected_signer_id,
        resolve_signer_keys,
        options,
        Some(replay_guard),
    )
}

pub fn open_protected_with_without_replay<F>(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    expected_signer_id: Option<u64>,
    resolve_signer_keys: F,
    options: ProtectedOpenOptions,
) -> Result<VerifiedProtectedMessage, ProtectedError>
where
    F: FnOnce(u64) -> Option<Vec<PublicKeyBundle>>,
{
    open_protected_with_impl(
        frame,
        keyrings,
        expected_signer_id,
        resolve_signer_keys,
        options,
        None,
    )
}

pub(super) fn open_protected_with_keys_impl(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    expected_signer_id: u64,
    signer_public_keys: &[PublicKeyBundle],
    options: ProtectedOpenOptions,
    replay_guard: Option<&mut dyn ReplayGuard>,
) -> Result<VerifiedProtectedMessage, ProtectedError> {
    let type_map = validate_protected_frame(frame)?;
    let mut decrypted = decrypt_protected_payload(
        frame,
        keyrings,
        options.encryption_purpose,
        options.decode_limits,
        options.protected_limits.max_decryption_key_history,
    )?;
    let signer_id = decrypted
        .as_signed()
        .ok_or(ProtectedError::PayloadNotSigned)?;
    let signer_id = signer_id.signer_id;
    if signer_id != expected_signer_id {
        return Err(ProtectionError::SignerIdMismatch {
            expected: expected_signer_id,
            actual: signer_id,
        }
        .into());
    }
    let signed = decrypted
        .as_signed_mut()
        .ok_or(ProtectedError::PayloadNotSigned)?;
    open_decrypted_protected(
        frame,
        type_map,
        signed,
        signer_public_keys,
        options,
        replay_guard,
    )
}

pub fn open_protected_with_keys_checked(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    expected_signer_id: u64,
    signer_public_keys: &[PublicKeyBundle],
    options: ProtectedOpenOptions,
    replay_guard: &mut dyn ReplayGuard,
) -> Result<VerifiedProtectedMessage, ProtectedError> {
    open_protected_with_keys_impl(
        frame,
        keyrings,
        expected_signer_id,
        signer_public_keys,
        options,
        Some(replay_guard),
    )
}

pub fn open_protected_with_keys_without_replay(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    expected_signer_id: u64,
    signer_public_keys: &[PublicKeyBundle],
    options: ProtectedOpenOptions,
) -> Result<VerifiedProtectedMessage, ProtectedError> {
    open_protected_with_keys_impl(
        frame,
        keyrings,
        expected_signer_id,
        signer_public_keys,
        options,
        None,
    )
}

pub fn open_protected_checked(
    frame: &CommunicationValue,
    keyring: &Keyring,
    expected_signer_id: u64,
    signer_public_key: &PublicKeyBundle,
    options: ProtectedOpenOptions,
    replay_guard: &mut dyn ReplayGuard,
) -> Result<VerifiedProtectedMessage, ProtectedError> {
    open_protected_with_keys_impl(
        frame,
        std::slice::from_ref(&keyring),
        expected_signer_id,
        std::slice::from_ref(signer_public_key),
        options,
        Some(replay_guard),
    )
}

pub fn open_protected_without_replay(
    frame: &CommunicationValue,
    keyring: &Keyring,
    expected_signer_id: u64,
    signer_public_key: &PublicKeyBundle,
    options: ProtectedOpenOptions,
) -> Result<VerifiedProtectedMessage, ProtectedError> {
    open_protected_with_keys_impl(
        frame,
        std::slice::from_ref(&keyring),
        expected_signer_id,
        std::slice::from_ref(signer_public_key),
        options,
        None,
    )
}

pub(super) fn open_decrypted_protected(
    frame: &CommunicationValue,
    type_map: TypeMap,
    signed: &mut crate::SignedValue,
    signer_public_keys: &[PublicKeyBundle],
    options: ProtectedOpenOptions,
    mut replay_guard: Option<&mut dyn ReplayGuard>,
) -> Result<VerifiedProtectedMessage, ProtectedError> {
    if signer_public_keys.len() > options.protected_limits.max_signer_key_history {
        return Err(ProtectedError::ResourceLimit("signer key history"));
    }
    let matched_signer_key_index = signed.verify_with_key_history_index_and_limits(
        signed.signer_id,
        signer_public_keys,
        options.signature_purpose,
        options.policy,
        options.encode_limits,
    )?;
    let receiver_id = frame.receiver().ok_or(ProtectedError::MissingReceiver)?;
    if options
        .expected_receiver_id
        .is_some_and(|expected| expected != receiver_id)
    {
        return Err(ProtectedError::ExpectedReceiverMismatch);
    }
    if frame
        .sender()
        .is_some_and(|sender| sender != signed.signer_id)
    {
        return Err(ProtectedError::SenderMismatch);
    }
    /* The authenticated value is already owned by the decoder. Keep this
    inspection borrowed so opening a large envelope does not clone it. */
    let envelope = signed
        .value
        .container_entries_mut()
        .ok_or(ProtectedError::MissingEnvelope)?;
    let version = protected_version(envelope, &type_map)?;
    if version != CURRENT_PROTECTED_VERSION {
        return Err(ProtectedError::UnsupportedProtectedVersion(version));
    }
    let expected = type_map
        .fingerprint()
        .ok_or(ProtectedError::InvalidLayout("unknown dictionary"))?;
    if envelope.len() != 7
        || field(envelope, DataType::DictionaryFingerprint, &type_map)?.as_bytes_slice()
            != Some(expected.as_slice())
    {
        return Err(ProtectedError::InvalidLayout(
            "dictionary fingerprint mismatch",
        ));
    }
    let message_type = communication_type_field(envelope, DataType::MessageType, &type_map)?;
    let application_type = validate_application_message_type(message_type, &type_map)?;
    if frame.get_comm_type_enum() != Some(application_type) {
        return Err(ProtectedError::MessageTypeMismatch);
    }
    let final_recipient_id = u64::try_from(unsigned_field(
        envelope,
        DataType::FinalRecipientId,
        &type_map,
    )?)
    .map_err(|_| ProtectedError::InvalidLayout("final recipient ID is out of range"))?;
    if final_recipient_id != receiver_id {
        return Err(ProtectedError::FinalRecipientMismatch);
    }
    let message_id = message_id_field(envelope, DataType::MessageId, &type_map)?;
    let created_at = u64::try_from(unsigned_field(envelope, DataType::CreatedAt, &type_map)?)
        .map_err(|_| ProtectedError::InvalidLayout("created-at value is out of range"))?;
    let content = take_field(envelope, DataType::Content, &type_map)?;

    if let Some(guard) = replay_guard.as_mut()
        && !guard.accept(signed.signer_id, message_id, created_at)?
    {
        return Err(ProtectedError::Replay);
    }

    Ok(VerifiedProtectedMessage {
        protected_version: version,
        signer_id: signed.signer_id,
        final_recipient_id,
        message_id,
        created_at,
        message_type: application_type,
        content,
        matched_signer_key_index,
    })
}
