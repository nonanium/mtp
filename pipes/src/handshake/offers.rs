use super::*;

pub(super) fn session_offer_value(params: &PipeSessionParameters, key: [u8; 32]) -> DataValue {
    DataValue::Array(vec![
        DataValue::Str(PIPE_SESSION_OFFER_DOMAIN.to_owned()),
        DataValue::Bytes(params.session_id.clone()),
        DataValue::UnsignedNumber(params.pipe_id.get() as u128),
        DataValue::UnsignedNumber(params.sender_id as u128),
        DataValue::UnsignedNumber(params.recipient_id as u128),
        DataValue::UnsignedNumber(params.purpose as u128),
        DataValue::UnsignedNumber(params.direction as u128),
        DataValue::Bytes(key.to_vec()),
    ])
}

pub(super) fn build_session_offer(
    params: &PipeSessionParameters,
    sender_keyring: &Keyring,
    recipient_public_keys: &[PublicKeyBundle],
    key: [u8; 32],
) -> Result<Vec<u8>, PipeSessionError> {
    if recipient_public_keys.is_empty() {
        return Err(PipeSessionError::InvalidParameters(
            "at least one pipe-session recipient is required",
        ));
    }
    for recipient_public_key in recipient_public_keys {
        recipient_public_key.validate()?;
    }
    let signer = pipe_signer_for_keyring(sender_keyring)?;
    let signed = session_offer_value(params, key).sign(
        params.sender_id,
        ProtectionPurpose::from(PIPE_SESSION_SIGNATURE_PURPOSE),
        &signer,
    )?;
    let encrypted = signed.encrypt_for(
        recipient_public_keys,
        ProtectionPurpose::from(PIPE_SESSION_ENCRYPTION_PURPOSE),
    )?;
    let offer = encrypted.to_bytes()?;
    if offer.len() > MAX_PIPE_SESSION_OFFER {
        return Err(PipeSessionError::OfferTooLarge(offer.len()));
    }
    Ok(offer)
}

pub(super) async fn write_session_offer<S: AsyncWrite + Unpin>(
    stream: &mut S,
    offer: &[u8],
) -> Result<(), PipeSessionError> {
    let length =
        u32::try_from(offer.len()).map_err(|_| PipeSessionError::OfferTooLarge(offer.len()))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(offer).await?;
    stream.flush().await?;
    Ok(())
}

pub(super) async fn read_session_offer<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<Vec<u8>, PipeSessionError> {
    let mut length_bytes = [0u8; 4];
    stream
        .read_exact(&mut length_bytes)
        .await
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                PipeSessionError::UnexpectedEof
            } else {
                PipeSessionError::Io(error)
            }
        })?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > MAX_PIPE_SESSION_OFFER {
        return Err(PipeSessionError::OfferTooLarge(length));
    }
    let mut offer = vec![0u8; length];
    stream.read_exact(&mut offer).await.map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            PipeSessionError::UnexpectedEof
        } else {
            PipeSessionError::Io(error)
        }
    })?;
    Ok(offer)
}

pub(super) fn offer_field(
    fields: &[DataValue],
    index: usize,
) -> Result<&DataValue, PipeSessionError> {
    fields.get(index).ok_or(PipeSessionError::InvalidOffer)
}

pub(super) fn unsigned_field(fields: &[DataValue], index: usize) -> Result<u128, PipeSessionError> {
    offer_field(fields, index)?
        .as_unsigned_number()
        .ok_or(PipeSessionError::InvalidOffer)
}

pub(super) fn validate_session_offer(
    decrypted: DataValue,
    expected: &PipeSessionParameters,
    sender_public_key: &PublicKeyBundle,
    policy: ProtectionPolicy,
) -> Result<[u8; 32], PipeSessionError> {
    validate_session_offer_with_keys(
        decrypted,
        expected,
        std::slice::from_ref(sender_public_key),
        policy,
    )
}

pub(super) fn validate_session_offer_with_keys(
    decrypted: DataValue,
    expected: &PipeSessionParameters,
    sender_public_keys: &[PublicKeyBundle],
    policy: ProtectionPolicy,
) -> Result<[u8; 32], PipeSessionError> {
    let signed = decrypted
        .as_signed()
        .ok_or(PipeSessionError::InvalidOffer)?;
    if signed.signer_id != expected.sender_id {
        return Err(PipeSessionError::Protection(
            ProtectionError::SignerIdMismatch {
                expected: expected.sender_id,
                actual: signed.signer_id,
            },
        ));
    }
    for sender_public_key in sender_public_keys {
        sender_public_key.validate()?;
    }
    signed.verify_with_key_history(
        expected.sender_id,
        sender_public_keys,
        ProtectionPurpose::from(PIPE_SESSION_SIGNATURE_PURPOSE),
        policy,
    )?;

    let fields = signed
        .value
        .as_array_slice()
        .ok_or(PipeSessionError::InvalidOffer)?;
    if fields.len() != 8
        || offer_field(fields, 0)?.as_str() != Some(PIPE_SESSION_OFFER_DOMAIN)
        || offer_field(fields, 1)?.as_bytes_slice() != Some(expected.session_id())
        || u32::try_from(unsigned_field(fields, 2)?).ok() != Some(expected.pipe_id.get())
        || u64::try_from(unsigned_field(fields, 3)?).ok() != Some(expected.sender_id)
        || u64::try_from(unsigned_field(fields, 4)?).ok() != Some(expected.recipient_id)
        || u8::try_from(unsigned_field(fields, 5)?).ok() != Some(expected.purpose)
        || u8::try_from(unsigned_field(fields, 6)?).ok() != Some(expected.direction)
    {
        return Err(PipeSessionError::InvalidOffer);
    }
    let key = offer_field(fields, 7)?
        .as_bytes_slice()
        .ok_or(PipeSessionError::InvalidOffer)?;
    key.try_into().map_err(|_| PipeSessionError::InvalidOffer)
}

/// Establish an encrypted writer by sending a signed, recipient-encrypted
/// session-key offer over the raw pipe, then return the authenticated record
/// layer for subsequent bytes.
pub async fn initiate_pipe_session<S: AsyncWrite + Unpin>(
    stream: S,
    params: PipeSessionParameters,
    sender_keyring: &Keyring,
    recipient_public_key: &PublicKeyBundle,
) -> Result<EncryptedPipeWriter<S>, PipeSessionError> {
    let recipients = [recipient_public_key.clone()];
    initiate_group_pipe_session(stream, params, sender_keyring, &recipients).await
}

/// Establish a pipe session for a group by encrypting one fresh session key
/// to every current member. Membership changes must create a fresh session
/// offer with the new recipient set; do not reuse the old record key for a
/// newly added member or continue sending it to a removed member.
pub async fn initiate_group_pipe_session<S: AsyncWrite + Unpin>(
    mut stream: S,
    params: PipeSessionParameters,
    sender_keyring: &Keyring,
    recipient_public_keys: &[PublicKeyBundle],
) -> Result<EncryptedPipeWriter<S>, PipeSessionError> {
    let mut key = [0u8; 32];
    rand::rng().fill(&mut key);
    let offer = build_session_offer(&params, sender_keyring, recipient_public_keys, key)?;
    write_session_offer(&mut stream, &offer).await?;
    Ok(EncryptedPipeWriter::new(stream, key, params.context()))
}

pub async fn initiate_group_pipe_session_with_suite<S: AsyncWrite + Unpin>(
    mut stream: S,
    params: PipeSessionParameters,
    keys: &Keyring,
    recipients: &[PublicKeyBundle],
    dual: bool,
) -> Result<EncryptedPipeWriter<S>, PipeSessionError> {
    if recipients.is_empty() {
        return Err(PipeSessionError::InvalidParameters(
            "at least one recipient required",
        ));
    }
    for recipient in recipients {
        recipient.validate()?;
    }
    let signer: Box<dyn SignatureScheme + Send> = if dual {
        Box::new(DualSigner::new(
            &keys.sig_cl_secret_key,
            &keys.sig_pq_secret_key,
            &keys.sig_pq_public_key,
        )?)
    } else {
        Box::new(Ed25519Signer::new(&keys.sig_cl_secret_key)?)
    };
    let mut key = Zeroizing::new([0u8; 32]);
    rand::rng().fill(&mut *key);
    let offer = session_offer_value(&params, *key)
        .sign(
            params.sender_id,
            ProtectionPurpose::from(PIPE_SESSION_SIGNATURE_PURPOSE),
            signer.as_ref(),
        )?
        .encrypt_for(
            recipients,
            ProtectionPurpose::from(PIPE_SESSION_ENCRYPTION_PURPOSE),
        )?
        .to_bytes()?;
    if offer.len() > MAX_PIPE_SESSION_OFFER {
        return Err(PipeSessionError::OfferTooLarge(offer.len()));
    }
    write_session_offer(&mut stream, &offer).await?;
    Ok(EncryptedPipeWriter::new(stream, *key, params.context()))
}

/// Accept and authenticate a signed, recipient-encrypted session-key offer,
/// then return the record layer for subsequent bytes.
pub async fn accept_pipe_session<R: AsyncRead + Unpin>(
    stream: R,
    expected: &PipeSessionParameters,
    recipient_keyring: &Keyring,
    sender_public_key: &PublicKeyBundle,
) -> Result<EncryptedPipeReader<R>, PipeSessionError> {
    let policy = pipe_signature_policy(recipient_keyring)?;
    accept_pipe_session_with_policy(
        stream,
        expected,
        recipient_keyring,
        sender_public_key,
        policy,
    )
    .await
}

/// Policy-aware counterpart to [`accept_pipe_session`].
pub async fn accept_pipe_session_with_policy<R: AsyncRead + Unpin>(
    mut stream: R,
    expected: &PipeSessionParameters,
    recipient_keyring: &Keyring,
    sender_public_key: &PublicKeyBundle,
    policy: ProtectionPolicy,
) -> Result<EncryptedPipeReader<R>, PipeSessionError> {
    let offer = read_session_offer(&mut stream).await?;
    let encrypted = DataValue::from_bytes_with_limits(
        &offer,
        DecodeLimits {
            max_blob_size: MAX_PIPE_SESSION_OFFER,
            ..DecodeLimits::default()
        },
    )
    .ok_or(PipeSessionError::InvalidOffer)?;
    let signed = encrypted.decrypt(
        recipient_keyring,
        ProtectionPurpose::from(PIPE_SESSION_ENCRYPTION_PURPOSE),
    )?;
    let key = validate_session_offer(signed, expected, sender_public_key, policy)?;
    Ok(EncryptedPipeReader::new(stream, key, expected.context()))
}

/// Accept a pipe session against a trusted signing-key history. Historical
/// keys are local resolver state and never become visible in the offer.
pub async fn accept_pipe_session_with_key_history<R: AsyncRead + Unpin>(
    mut stream: R,
    expected: &PipeSessionParameters,
    recipient_keyring: &Keyring,
    sender_public_keys: &[PublicKeyBundle],
    policy: ProtectionPolicy,
) -> Result<EncryptedPipeReader<R>, PipeSessionError> {
    if sender_public_keys.is_empty() {
        return Err(PipeSessionError::InvalidParameters(
            "at least one sender verification key is required",
        ));
    }
    let offer = read_session_offer(&mut stream).await?;
    let encrypted = DataValue::from_bytes_with_limits(
        &offer,
        DecodeLimits {
            max_blob_size: MAX_PIPE_SESSION_OFFER,
            ..DecodeLimits::default()
        },
    )
    .ok_or(PipeSessionError::InvalidOffer)?;
    let signed = encrypted.decrypt(
        recipient_keyring,
        ProtectionPurpose::from(PIPE_SESSION_ENCRYPTION_PURPOSE),
    )?;
    let key = validate_session_offer_with_keys(signed, expected, sender_public_keys, policy)?;
    Ok(EncryptedPipeReader::new(stream, key, expected.context()))
}

/// Accept a legacy/group offer whose fresh session ID is selected by the
/// sender. The ID is only trusted after the complete signed transcript passes.
#[allow(clippy::too_many_arguments)]
pub async fn accept_pipe_session_auto<R: AsyncRead + Unpin>(
    mut stream: R,
    pipe_id: PipeId,
    sender_id: u64,
    recipient_id: u64,
    purpose: u8,
    direction: u8,
    recipient_keyring: &Keyring,
    sender_public_keys: &[PublicKeyBundle],
    policy: ProtectionPolicy,
) -> Result<EncryptedPipeReader<R>, PipeSessionError> {
    let offer = read_session_offer(&mut stream).await?;
    let encrypted = DataValue::from_bytes_with_limits(
        &offer,
        DecodeLimits {
            max_blob_size: MAX_PIPE_SESSION_OFFER,
            ..DecodeLimits::default()
        },
    )
    .ok_or(PipeSessionError::InvalidOffer)?;
    let signed = encrypted.decrypt(
        recipient_keyring,
        ProtectionPurpose::from(PIPE_SESSION_ENCRYPTION_PURPOSE),
    )?;
    let fields = signed
        .as_signed()
        .ok_or(PipeSessionError::InvalidOffer)?
        .value
        .as_array_slice()
        .ok_or(PipeSessionError::InvalidOffer)?;
    let session_id = fields
        .get(1)
        .and_then(DataValue::as_bytes_slice)
        .ok_or(PipeSessionError::InvalidOffer)?;
    let expected = PipeSessionParameters::new_id(
        session_id,
        pipe_id,
        sender_id,
        recipient_id,
        purpose,
        direction,
    )?;
    let key = validate_session_offer_with_keys(signed, &expected, sender_public_keys, policy)?;
    Ok(EncryptedPipeReader::new(stream, key, expected.context()))
}
