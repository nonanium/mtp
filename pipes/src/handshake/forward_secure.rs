use super::*;

pub(super) fn fs_common_fields(params: &PipeSessionParameters) -> Vec<DataValue> {
    vec![
        DataValue::Bytes(params.session_id.clone()),
        DataValue::UnsignedNumber(params.pipe_id.get() as u128),
        DataValue::UnsignedNumber(params.sender_id as u128),
        DataValue::UnsignedNumber(params.recipient_id as u128),
        DataValue::UnsignedNumber(params.purpose as u128),
        DataValue::UnsignedNumber(params.direction as u128),
    ]
}

pub(super) fn fs_init_value(params: &PipeSessionParameters, nonce: [u8; 32]) -> DataValue {
    let mut fields = vec![DataValue::Str(FS_INIT_DOMAIN.to_owned())];
    fields.extend(fs_common_fields(params));
    fields.push(DataValue::Bytes(nonce.to_vec()));
    DataValue::Array(fields)
}

pub(super) fn fs_response_value(
    params: &PipeSessionParameters,
    init_hash: [u8; 32],
    ephemeral_public_key: &[u8],
) -> DataValue {
    let mut fields = vec![DataValue::Str(FS_RESPONSE_DOMAIN.to_owned())];
    fields.extend(fs_common_fields(params));
    fields.push(DataValue::Bytes(init_hash.to_vec()));
    fields.push(DataValue::Bytes(ephemeral_public_key.to_vec()));
    DataValue::Array(fields)
}

pub(super) fn fs_finish_value(
    params: &PipeSessionParameters,
    response_hash: [u8; 32],
    ciphertext: &[u8],
) -> DataValue {
    let mut fields = vec![DataValue::Str(FS_FINISH_DOMAIN.to_owned())];
    fields.extend(fs_common_fields(params));
    fields.push(DataValue::Bytes(response_hash.to_vec()));
    fields.push(DataValue::Bytes(ciphertext.to_vec()));
    DataValue::Array(fields)
}

pub(super) fn validate_fs_common(
    fields: &[DataValue],
    expected: &PipeSessionParameters,
    expected_domain: &str,
    expected_len: usize,
) -> Result<(), PipeSessionError> {
    if fields.len() != expected_len
        || fields.first().and_then(DataValue::as_str) != Some(expected_domain)
        || offer_field(fields, 1)?.as_bytes_slice() != Some(expected.session_id())
        || u32::try_from(unsigned_field(fields, 2)?).ok() != Some(expected.pipe_id.get())
        || u64::try_from(unsigned_field(fields, 3)?).ok() != Some(expected.sender_id)
        || u64::try_from(unsigned_field(fields, 4)?).ok() != Some(expected.recipient_id)
        || u8::try_from(unsigned_field(fields, 5)?).ok() != Some(expected.purpose)
        || u8::try_from(unsigned_field(fields, 6)?).ok() != Some(expected.direction)
    {
        return Err(PipeSessionError::InvalidOffer);
    }
    Ok(())
}

pub(super) fn derive_forward_secure_chain_key(
    shared_secret: &[u8],
    handshake_transcript: &[u8; 32],
) -> Result<[u8; 32], PipeSessionError> {
    let key = mtp_crypto::hkdf_expand(shared_secret, handshake_transcript, FS_ROOT_INFO, 32)?;
    key.try_into().map_err(|_| PipeSessionError::InvalidOffer)
}

pub(super) fn forward_secure_context(
    params: &PipeSessionParameters,
    handshake_transcript: &[u8; 32],
) -> PipeProtectionContext {
    let mut transcript = Vec::with_capacity(PIPE_TRANSCRIPT_DOMAIN.len() + 64);
    transcript.extend_from_slice(PIPE_TRANSCRIPT_DOMAIN);
    transcript.extend_from_slice(&params.transcript_hash());
    transcript.extend_from_slice(handshake_transcript);
    let hash: [u8; 32] = mtp_crypto::sha256(&transcript);
    PipeProtectionContext {
        session_id: params.session_id.clone(),
        purpose: params.purpose,
        direction: params.direction,
        transcript_hash: hash,
    }
}

pub(super) fn sign_forward_secure_value(
    value: DataValue,
    signer_id: u64,
    keyring: &Keyring,
) -> Result<Vec<u8>, PipeSessionError> {
    let signer = pipe_signer_for_keyring(keyring)?;
    value
        .sign(
            signer_id,
            ProtectionPurpose::from(PIPE_SESSION_SIGNATURE_PURPOSE),
            &signer,
        )?
        .to_bytes()
        .map_err(PipeSessionError::Codec)
}

pub(super) fn verify_forward_secure_value(
    bytes: &[u8],
    expected_signer_id: u64,
    signer_public_key: &PublicKeyBundle,
    policy: ProtectionPolicy,
) -> Result<DataValue, PipeSessionError> {
    verify_forward_secure_value_with_keys(
        bytes,
        expected_signer_id,
        std::slice::from_ref(signer_public_key),
        policy,
    )
}

pub(super) fn verify_forward_secure_value_with_keys(
    bytes: &[u8],
    expected_signer_id: u64,
    signer_public_keys: &[PublicKeyBundle],
    policy: ProtectionPolicy,
) -> Result<DataValue, PipeSessionError> {
    if signer_public_keys.is_empty() {
        return Err(PipeSessionError::InvalidParameters(
            "at least one sender verification key is required",
        ));
    }
    let value = DataValue::from_bytes_with_limits(
        bytes,
        DecodeLimits {
            max_blob_size: MAX_PIPE_SESSION_OFFER,
            ..DecodeLimits::default()
        },
    )
    .ok_or(PipeSessionError::InvalidOffer)?;
    for signer_public_key in signer_public_keys {
        signer_public_key.validate()?;
    }
    let signed = value.as_signed().ok_or(PipeSessionError::InvalidOffer)?;
    signed.verify_with_key_history(
        expected_signer_id,
        signer_public_keys,
        ProtectionPurpose::from(PIPE_SESSION_SIGNATURE_PURPOSE),
        policy,
    )?;
    Ok((*signed.value).clone())
}

pub(super) fn handshake_hash(parts: &[&[u8]]) -> [u8; 32] {
    let total = parts.iter().map(|part| part.len()).sum();
    let mut transcript = Vec::with_capacity(total);
    for part in parts {
        append_transcript_field(&mut transcript, part);
    }
    mtp_crypto::sha256(&transcript)
}

/// Forward-secret duplex handshake.
///
/// Unlike the one-way session offer, this API requires a bidirectional stream:
/// the responder contributes an ephemeral KEM key, the initiator encapsulates
/// to it, and both sides derive record keys from the authenticated transcript.
/// Long-term KEM keys are not used, so later compromise of those keys cannot
/// recover recorded sessions. Long-term signing keys still authenticate the
/// exchange.
pub async fn initiate_forward_secure_pipe_session<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    params: PipeSessionParameters,
    sender_keyring: &Keyring,
    recipient_public_key: &PublicKeyBundle,
    policy: ProtectionPolicy,
) -> Result<EncryptedPipeWriter<S>, PipeSessionError> {
    recipient_public_key.validate()?;
    let mut nonce = [0u8; 32];
    rand::rng().fill(&mut nonce);
    let init_bytes = sign_forward_secure_value(
        fs_init_value(&params, nonce),
        params.sender_id,
        sender_keyring,
    )?;
    write_session_offer(&mut stream, &init_bytes).await?;

    let response_bytes = read_session_offer(&mut stream).await?;
    let response = verify_forward_secure_value(
        &response_bytes,
        params.recipient_id,
        recipient_public_key,
        policy,
    )?;
    let response_fields = response
        .as_array_slice()
        .ok_or(PipeSessionError::InvalidOffer)?;
    validate_fs_common(response_fields, &params, FS_RESPONSE_DOMAIN, 9)?;
    let init_hash = handshake_hash(&[&init_bytes]);
    if response_fields[7].as_bytes_slice() != Some(init_hash.as_slice()) {
        return Err(PipeSessionError::InvalidOffer);
    }
    let ephemeral_public = response_fields[8]
        .as_bytes_slice()
        .ok_or(PipeSessionError::InvalidOffer)?;
    let encapsulated =
        mtp_crypto::HybridKem::encapsulate(&KemPublicKey::new(ephemeral_public.to_vec()))?;
    let finish_bytes = sign_forward_secure_value(
        fs_finish_value(
            &params,
            handshake_hash(&[&response_bytes]),
            &encapsulated.ciphertext,
        ),
        params.sender_id,
        sender_keyring,
    )?;
    write_session_offer(&mut stream, &finish_bytes).await?;

    let transcript = handshake_hash(&[&init_bytes, &response_bytes, &finish_bytes]);
    let chain_key = derive_forward_secure_chain_key(&encapsulated.shared_secret, &transcript)?;
    Ok(EncryptedPipeWriter::new(
        stream,
        chain_key,
        forward_secure_context(&params, &transcript),
    ))
}

/// Responder side of [`initiate_forward_secure_pipe_session`].
pub async fn accept_forward_secure_pipe_session<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    expected: &PipeSessionParameters,
    recipient_keyring: &Keyring,
    sender_public_key: &PublicKeyBundle,
    policy: ProtectionPolicy,
) -> Result<EncryptedPipeReader<S>, PipeSessionError> {
    accept_forward_secure_pipe_session_with_key_history(
        stream,
        expected,
        recipient_keyring,
        std::slice::from_ref(sender_public_key),
        policy,
    )
    .await
}

/// Responder side of the forward-secure handshake with a local signing-key
/// history. Historical public keys remain local resolver state and are never
/// included in the handshake.
pub async fn accept_forward_secure_pipe_session_with_key_history<
    S: AsyncRead + AsyncWrite + Unpin,
>(
    mut stream: S,
    expected: &PipeSessionParameters,
    recipient_keyring: &Keyring,
    sender_public_keys: &[PublicKeyBundle],
    policy: ProtectionPolicy,
) -> Result<EncryptedPipeReader<S>, PipeSessionError> {
    let init_bytes = read_session_offer(&mut stream).await?;
    accept_forward_secure_pipe_session_after_init(
        stream,
        init_bytes,
        expected,
        recipient_keyring,
        sender_public_keys,
        policy,
    )
    .await
}

/// Learn the sender's session ID only after authenticating the init message.
#[allow(clippy::too_many_arguments)]
pub async fn accept_forward_secure_pipe_session_auto<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    pipe_id: PipeId,
    sender_id: u64,
    recipient_id: u64,
    purpose: u8,
    direction: u8,
    recipient_keyring: &Keyring,
    sender_public_keys: &[PublicKeyBundle],
    policy: ProtectionPolicy,
) -> Result<EncryptedPipeReader<S>, PipeSessionError> {
    let init_bytes = read_session_offer(&mut stream).await?;
    let init =
        verify_forward_secure_value_with_keys(&init_bytes, sender_id, sender_public_keys, policy)?;
    let fields = init
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
    accept_forward_secure_pipe_session_after_init(
        stream,
        init_bytes,
        &expected,
        recipient_keyring,
        sender_public_keys,
        policy,
    )
    .await
}

pub(super) async fn accept_forward_secure_pipe_session_after_init<
    S: AsyncRead + AsyncWrite + Unpin,
>(
    mut stream: S,
    init_bytes: Vec<u8>,
    expected: &PipeSessionParameters,
    recipient_keyring: &Keyring,
    sender_public_keys: &[PublicKeyBundle],
    policy: ProtectionPolicy,
) -> Result<EncryptedPipeReader<S>, PipeSessionError> {
    let init = verify_forward_secure_value_with_keys(
        &init_bytes,
        expected.sender_id,
        sender_public_keys,
        policy,
    )?;
    let init_fields = init
        .as_array_slice()
        .ok_or(PipeSessionError::InvalidOffer)?;
    validate_fs_common(init_fields, expected, FS_INIT_DOMAIN, 8)?;
    let nonce = init_fields[7]
        .as_bytes_slice()
        .ok_or(PipeSessionError::InvalidOffer)?;
    if nonce.len() != 32 {
        return Err(PipeSessionError::InvalidOffer);
    }

    let (ephemeral_secret, ephemeral_public) = mtp_crypto::HybridKem::generate_keypair();
    let response_bytes = sign_forward_secure_value(
        fs_response_value(
            expected,
            handshake_hash(&[&init_bytes]),
            ephemeral_public.as_bytes(),
        ),
        expected.recipient_id,
        recipient_keyring,
    )?;
    write_session_offer(&mut stream, &response_bytes).await?;

    let finish_bytes = read_session_offer(&mut stream).await?;
    let finish = verify_forward_secure_value_with_keys(
        &finish_bytes,
        expected.sender_id,
        sender_public_keys,
        policy,
    )?;
    let finish_fields = finish
        .as_array_slice()
        .ok_or(PipeSessionError::InvalidOffer)?;
    validate_fs_common(finish_fields, expected, FS_FINISH_DOMAIN, 9)?;
    let response_hash = handshake_hash(&[&response_bytes]);
    if finish_fields[7].as_bytes_slice() != Some(response_hash.as_slice()) {
        return Err(PipeSessionError::InvalidOffer);
    }
    let ciphertext = finish_fields[8]
        .as_bytes_slice()
        .ok_or(PipeSessionError::InvalidOffer)?;
    let shared_secret = mtp_crypto::HybridKem::decapsulate(&ephemeral_secret, ciphertext)?;
    let transcript = handshake_hash(&[&init_bytes, &response_bytes, &finish_bytes]);
    let chain_key = derive_forward_secure_chain_key(&shared_secret, &transcript)?;
    Ok(EncryptedPipeReader::new(
        stream,
        chain_key,
        forward_secure_context(expected, &transcript),
    ))
}
