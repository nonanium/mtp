//! Authenticated session offers and forward-secure pipe handshakes.
//!
//! Pipe negotiation and QUIC/WebTransport remain transport primitives. This
//! module adds the application-facing record layer that callers can place on
//! top of any async byte stream, plus an explicit
//! signed/KEM session-offer helper. The raw stream adapter does not infer
//! application identities or derive keys from clear pipe metadata.

use crate::policy::{pipe_signature_policy, pipe_signer_for_keyring};
use crate::{EncryptedPipeError, EncryptedPipeReader, EncryptedPipeWriter};
use mtp_codec::{
    DataValue, DecodeLimits, MtpProtectionPurpose, ProtectionError, ProtectionPolicy,
    ProtectionPurpose,
};
use mtp_common::PipeId;
use mtp_crypto::{
    DualSigner, Ed25519Signer, KemPublicKey, Keyring, PublicKeyBundle, SignatureScheme,
};
use rand::RngExt;
use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

const PIPE_TRANSCRIPT_DOMAIN: &[u8] = b"MTP-PIPE-TRANSCRIPT-1";
const SESSION_ID_MAX_LEN: usize = 1024;

/// Purpose authenticated by the signed session-key offer.
pub const PIPE_SESSION_SIGNATURE_PURPOSE: u8 = MtpProtectionPurpose::PipeSessionSignature.value();
/// Generic purpose authenticated by the encrypted session-key offer.
pub const PIPE_SESSION_ENCRYPTION_PURPOSE: u8 = MtpProtectionPurpose::PipeSessionEncryption.value();
/// Maximum serialized size of a session-key offer.
pub const MAX_PIPE_SESSION_OFFER: usize = 64 * 1024;
const PIPE_SESSION_OFFER_DOMAIN: &str = "MTP-PIPE-SESSION-1";
const FS_INIT_DOMAIN: &str = "MTP-PIPE-FS-INIT-1";
const FS_RESPONSE_DOMAIN: &str = "MTP-PIPE-FS-RESPONSE-1";
const FS_FINISH_DOMAIN: &str = "MTP-PIPE-FS-FINISH-1";
const FS_ROOT_INFO: &[u8] = b"MTP-PIPE-FS-ROOT-1";

/// The context authenticated by every encrypted pipe record.
#[derive(Clone, PartialEq, Eq)]
pub struct PipeProtectionContext {
    session_id: Vec<u8>,
    purpose: u8,
    direction: u8,
    transcript_hash: [u8; 32],
}

impl fmt::Debug for PipeProtectionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PipeProtectionContext")
            .field("session_id_len", &self.session_id.len())
            .field("purpose", &self.purpose)
            .field("direction", &self.direction)
            .field("transcript_hash", &"[REDACTED]")
            .finish()
    }
}

impl PipeProtectionContext {
    /// Create a context shared by both endpoints of one logical pipe stream.
    ///
    /// `session_id` must identify the authenticated pipe/session and should
    /// include both endpoint identities and the pipe identity. `direction`
    /// is a protocol-defined value that must be identical at both endpoints;
    /// use different values for the two directions of a bidirectional design.
    pub fn new(
        session_id: impl AsRef<[u8]>,
        purpose: u8,
        direction: u8,
    ) -> Result<Self, EncryptedPipeError> {
        let session_id = session_id.as_ref();
        if session_id.is_empty() || session_id.len() > SESSION_ID_MAX_LEN {
            return Err(EncryptedPipeError::InvalidContext);
        }
        if MtpProtectionPurpose::is_reserved(purpose) {
            return Err(EncryptedPipeError::InvalidContext);
        }
        Ok(Self {
            session_id: session_id.to_vec(),
            purpose,
            direction,
            transcript_hash: base_transcript_hash(session_id, purpose, direction),
        })
    }

    fn from_parameters(parameters: &PipeSessionParameters) -> Self {
        Self {
            session_id: parameters.session_id.clone(),
            purpose: parameters.purpose,
            direction: parameters.direction,
            transcript_hash: parameters.transcript_hash(),
        }
    }

    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    pub fn purpose(&self) -> u8 {
        self.purpose
    }

    pub fn direction(&self) -> u8 {
        self.direction
    }

    pub fn transcript_hash(&self) -> &[u8; 32] {
        &self.transcript_hash
    }

    pub fn with_transcript_hash(mut self, transcript_hash: [u8; 32]) -> Self {
        self.transcript_hash = transcript_hash;
        self
    }
}

/// Endpoint and stream metadata that a pipe-session key must bind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipeSessionParameters {
    session_id: Vec<u8>,
    pipe_id: PipeId,
    sender_id: u64,
    recipient_id: u64,
    purpose: u8,
    direction: u8,
}

impl PipeSessionParameters {
    pub fn new_id(
        session_id: impl AsRef<[u8]>,
        pipe_id: PipeId,
        sender_id: u64,
        recipient_id: u64,
        purpose: u8,
        direction: u8,
    ) -> Result<Self, PipeSessionError> {
        let session_id = session_id.as_ref().to_vec();
        PipeProtectionContext::new(&session_id, purpose, direction)
            .map_err(|_| PipeSessionError::InvalidParameters("invalid session id"))?;
        Ok(Self {
            session_id,
            pipe_id,
            sender_id,
            recipient_id,
            purpose,
            direction,
        })
    }

    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    pub fn pipe_id_value(&self) -> PipeId {
        self.pipe_id
    }

    pub fn sender_id(&self) -> u64 {
        self.sender_id
    }

    pub fn recipient_id(&self) -> u64 {
        self.recipient_id
    }

    pub fn purpose(&self) -> u8 {
        self.purpose
    }

    pub fn direction(&self) -> u8 {
        self.direction
    }

    fn context(&self) -> PipeProtectionContext {
        PipeProtectionContext::from_parameters(self)
    }

    fn transcript_hash(&self) -> [u8; 32] {
        let mut transcript = Vec::with_capacity(64 + self.session_id.len());
        transcript.extend_from_slice(PIPE_TRANSCRIPT_DOMAIN);
        append_transcript_field(&mut transcript, &self.session_id);
        transcript.extend_from_slice(&self.pipe_id.get().to_be_bytes());
        transcript.extend_from_slice(&self.sender_id.to_be_bytes());
        transcript.extend_from_slice(&self.recipient_id.to_be_bytes());
        transcript.push(self.purpose);
        transcript.push(self.direction);
        mtp_crypto::sha256(&transcript)
    }
}

fn append_transcript_field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn base_transcript_hash(session_id: &[u8], purpose: u8, direction: u8) -> [u8; 32] {
    let mut transcript = Vec::with_capacity(32 + session_id.len());
    transcript.extend_from_slice(PIPE_TRANSCRIPT_DOMAIN);
    append_transcript_field(&mut transcript, session_id);
    transcript.push(purpose);
    transcript.push(direction);
    mtp_crypto::sha256(&transcript)
}

/// Errors returned while establishing an encrypted pipe session.
#[derive(Debug)]
pub enum PipeSessionError {
    InvalidParameters(&'static str),
    InvalidOffer,
    OfferTooLarge(usize),
    UnexpectedEof,
    Io(std::io::Error),
    Codec(mtp_common::CodecError),
    Protection(ProtectionError),
    Crypto(mtp_crypto::CryptoError),
}

impl fmt::Display for PipeSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameters(message) => {
                write!(f, "invalid pipe session parameters: {message}")
            }
            Self::InvalidOffer => f.write_str("invalid pipe session offer"),
            Self::OfferTooLarge(length) => {
                write!(f, "pipe session offer is too large: {length} bytes")
            }
            Self::UnexpectedEof => f.write_str("truncated pipe session offer"),
            Self::Io(error) => write!(f, "pipe session I/O error: {error}"),
            Self::Codec(error) => write!(f, "pipe session codec error: {error}"),
            Self::Protection(error) => write!(f, "pipe session protection error: {error}"),
            Self::Crypto(error) => write!(f, "pipe session crypto error: {error}"),
        }
    }
}

impl std::error::Error for PipeSessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Codec(error) => Some(error),
            Self::Protection(error) => Some(error),
            Self::Crypto(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for PipeSessionError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<mtp_common::CodecError> for PipeSessionError {
    fn from(error: mtp_common::CodecError) -> Self {
        Self::Codec(error)
    }
}

impl From<ProtectionError> for PipeSessionError {
    fn from(error: ProtectionError) -> Self {
        Self::Protection(error)
    }
}

impl From<mtp_crypto::CryptoError> for PipeSessionError {
    fn from(error: mtp_crypto::CryptoError) -> Self {
        Self::Crypto(error)
    }
}

fn session_offer_value(params: &PipeSessionParameters, key: [u8; 32]) -> DataValue {
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

fn fs_common_fields(params: &PipeSessionParameters) -> Vec<DataValue> {
    vec![
        DataValue::Bytes(params.session_id.clone()),
        DataValue::UnsignedNumber(params.pipe_id.get() as u128),
        DataValue::UnsignedNumber(params.sender_id as u128),
        DataValue::UnsignedNumber(params.recipient_id as u128),
        DataValue::UnsignedNumber(params.purpose as u128),
        DataValue::UnsignedNumber(params.direction as u128),
    ]
}

fn fs_init_value(params: &PipeSessionParameters, nonce: [u8; 32]) -> DataValue {
    let mut fields = vec![DataValue::Str(FS_INIT_DOMAIN.to_owned())];
    fields.extend(fs_common_fields(params));
    fields.push(DataValue::Bytes(nonce.to_vec()));
    DataValue::Array(fields)
}

fn fs_response_value(
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

fn fs_finish_value(
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

fn validate_fs_common(
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

fn derive_forward_secure_chain_key(
    shared_secret: &[u8],
    handshake_transcript: &[u8; 32],
) -> Result<[u8; 32], PipeSessionError> {
    let key = mtp_crypto::hkdf_expand(shared_secret, handshake_transcript, FS_ROOT_INFO, 32)?;
    key.try_into().map_err(|_| PipeSessionError::InvalidOffer)
}

fn forward_secure_context(
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

fn build_session_offer(
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

async fn write_session_offer<S: AsyncWrite + Unpin>(
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

async fn read_session_offer<R: AsyncRead + Unpin>(
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

fn offer_field(fields: &[DataValue], index: usize) -> Result<&DataValue, PipeSessionError> {
    fields.get(index).ok_or(PipeSessionError::InvalidOffer)
}

fn unsigned_field(fields: &[DataValue], index: usize) -> Result<u128, PipeSessionError> {
    offer_field(fields, index)?
        .as_unsigned_number()
        .ok_or(PipeSessionError::InvalidOffer)
}

fn validate_session_offer(
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

fn validate_session_offer_with_keys(
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

fn sign_forward_secure_value(
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

fn verify_forward_secure_value(
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

fn verify_forward_secure_value_with_keys(
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

fn handshake_hash(parts: &[&[u8]]) -> [u8; 32] {
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

async fn accept_forward_secure_pipe_session_after_init<S: AsyncRead + AsyncWrite + Unpin>(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::derive_record_keys;
    use tokio::io::duplex;

    #[tokio::test]
    async fn cancelled_record_io_cannot_reuse_a_partial_stream() {
        let context = PipeProtectionContext::new(b"cancelled", 0x40, 0).expect("context");
        let (left, right) = duplex(1);
        let mut writer = EncryptedPipeWriter::new(left, [7; 32], context.clone());
        let mut write = Box::pin(writer.write_record(b"partial record"));
        assert!(
            std::future::poll_fn(|cx| {
                std::task::Poll::Ready(write.as_mut().poll(cx).is_pending())
            })
            .await
        );
        drop(write);
        assert!(matches!(
            writer.write_record(b"retry").await,
            Err(EncryptedPipeError::InvalidState)
        ));
        assert!(matches!(
            writer.try_into_inner(),
            Err(EncryptedPipeError::InvalidState)
        ));

        let (mut left, empty) = duplex(16);
        left.write_all(&[0]).await.expect("partial prefix");
        let mut reader = EncryptedPipeReader::new(empty, [7; 32], context);
        let mut read = Box::pin(reader.read_record());
        assert!(
            std::future::poll_fn(|cx| {
                std::task::Poll::Ready(read.as_mut().poll(cx).is_pending())
            })
            .await
        );
        drop(read);
        assert!(matches!(
            reader.read_record().await,
            Err(EncryptedPipeError::InvalidState)
        ));
        assert!(matches!(
            reader.try_into_inner(),
            Err(EncryptedPipeError::InvalidState)
        ));
        drop(right);
    }

    #[test]
    fn application_pipe_context_rejects_mtp_purposes() {
        assert!(matches!(
            PipeProtectionContext::new(b"application", PIPE_SESSION_SIGNATURE_PURPOSE, 0),
            Err(EncryptedPipeError::InvalidContext)
        ));
    }

    #[tokio::test]
    async fn records_roundtrip_and_bind_context() {
        let (left, right) = duplex(4096);
        let context =
            PipeProtectionContext::new(b"pipe-session/client/peer", 0x41, 0).expect("context");
        let writer_context = context.clone();
        let reader_context = context.clone();
        let writer = tokio::spawn(async move {
            let mut writer = EncryptedPipeWriter::new(left, [7u8; 32], writer_context);
            writer.write_record(b"first").await.expect("first record");
            writer.write_record(b"second").await.expect("second record");
            writer.finish().await.expect("finish");
        });

        let mut reader = EncryptedPipeReader::new(right, [7u8; 32], reader_context);
        assert_eq!(
            reader.read_record().await.expect("read").as_deref(),
            Some(b"first".as_slice())
        );
        assert_eq!(
            reader.read_record().await.expect("read").as_deref(),
            Some(b"second".as_slice())
        );
        assert!(reader.read_record().await.expect("eof").is_none());
        writer.await.expect("writer task");
    }

    #[tokio::test]
    async fn wrong_context_fails_authentication() {
        let (left, right) = duplex(4096);
        let writer_context = PipeProtectionContext::new(b"session-a", 1, 0).expect("context");
        let reader_context = PipeProtectionContext::new(b"session-b", 1, 0).expect("context");
        let writer = tokio::spawn(async move {
            let mut writer = EncryptedPipeWriter::new(left, [9u8; 32], writer_context);
            writer.write_record(b"secret").await.expect("write");
        });
        let mut reader = EncryptedPipeReader::new(right, [9u8; 32], reader_context);
        assert!(matches!(
            reader.read_record().await,
            Err(EncryptedPipeError::Crypto(_))
        ));
        assert!(matches!(
            reader.read_record().await,
            Err(EncryptedPipeError::InvalidState)
        ));
        writer.await.expect("writer task");
    }

    #[tokio::test]
    async fn transport_eof_without_final_record_is_truncation() {
        let (left, right) = duplex(4096);
        let context = PipeProtectionContext::new(b"session", 0x40, 0).expect("context");
        let mut writer = EncryptedPipeWriter::new(left, [3u8; 32], context.clone());
        writer.write_record(b"not finished").await.expect("record");
        let stream = writer.try_into_inner().expect("aligned stream");
        drop(stream);

        let mut reader = EncryptedPipeReader::new(right, [3u8; 32], context);
        assert_eq!(
            reader.read_record().await.expect("record").as_deref(),
            Some(b"not finished".as_slice())
        );
        assert!(matches!(
            reader.read_record().await,
            Err(EncryptedPipeError::FinalRecordRequired)
        ));
        assert!(matches!(
            reader.read_record().await,
            Err(EncryptedPipeError::InvalidState)
        ));
    }

    #[test]
    fn record_key_schedule_is_context_and_chain_bound() {
        let context = PipeProtectionContext::new(b"session-a", 1, 0).expect("context");
        let first = derive_record_keys(&[7u8; 32], &context, 0).expect("first keys");
        let second = derive_record_keys(&first.1, &context, 1).expect("second keys");
        let repeated = derive_record_keys(&[7u8; 32], &context, 1).expect("repeated keys");
        let other_context = PipeProtectionContext::new(b"session-b", 1, 0).expect("context");
        let other = derive_record_keys(&first.1, &other_context, 1).expect("other keys");

        assert_ne!(first.0, second.0);
        assert_ne!(second.0, repeated.0);
        assert_ne!(second.0, other.0);
        assert_ne!(second.1, other.1);
    }

    #[tokio::test]
    async fn signed_session_offer_establishes_the_record_layer() {
        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let sender_public = sender.public_key_bundle();
        let recipient_public = recipient.public_key_bundle();
        let params = PipeSessionParameters::new_id(
            b"session/client/peer/pipe-7",
            PipeId::new(7).unwrap(),
            41,
            99,
            0x40,
            0,
        )
        .expect("parameters");
        let writer_params = params.clone();
        let (left, right) = duplex(128 * 1024);
        let writer_task = tokio::spawn(async move {
            let mut writer = initiate_pipe_session(left, writer_params, &sender, &recipient_public)
                .await
                .expect("session offer");
            writer
                .write_record(b"authenticated pipe data")
                .await
                .expect("record");
            writer.finish().await.expect("finish");
        });

        let mut reader = accept_pipe_session(right, &params, &recipient, &sender_public)
            .await
            .expect("session accept");
        assert_eq!(
            reader.read_record().await.expect("record").as_deref(),
            Some(b"authenticated pipe data".as_slice())
        );
        assert!(reader.read_record().await.expect("eof").is_none());
        writer_task.await.expect("writer task");
    }

    #[tokio::test]
    async fn session_offer_accepts_a_trusted_historical_signing_key() {
        let historical_sender = Keyring::generate();
        let current_sender = Keyring::generate();
        let recipient = Keyring::generate();
        let recipient_public = recipient.public_key_bundle();
        let historical_public = historical_sender.public_key_bundle();
        let current_public = current_sender.public_key_bundle();
        let params = PipeSessionParameters::new_id(
            b"historical-session",
            PipeId::new(8).unwrap(),
            41,
            99,
            0x40,
            0,
        )
        .expect("parameters");
        let writer_params = params.clone();
        let (left, right) = duplex(128 * 1024);
        let writer_task = tokio::spawn(async move {
            initiate_pipe_session(left, writer_params, &historical_sender, &recipient_public).await
        });
        let reader = accept_pipe_session_with_key_history(
            right,
            &params,
            &recipient,
            &[current_public, historical_public],
            ProtectionPolicy::from(mtp_codec::SignaturePolicy::Dual),
        )
        .await
        .expect("historical session offer");
        let writer = writer_task.await.expect("writer task").expect("writer");
        drop(writer);
        // The successful setup is the assertion; no application record is
        // needed to prove that the historical signature key was selected.
        assert_eq!(reader.sequence(), 0);
    }

    #[tokio::test]
    async fn forward_secure_duplex_handshake_accepts_signing_key_history() {
        let historical_sender = Keyring::generate();
        let current_sender = Keyring::generate();
        let recipient = Keyring::generate();
        let historical_public = historical_sender.public_key_bundle();
        let current_public = current_sender.public_key_bundle();
        let recipient_public = recipient.public_key_bundle();
        let params = PipeSessionParameters::new_id(
            b"forward-secure-session",
            PipeId::new(17).unwrap(),
            41,
            99,
            0x40,
            0,
        )
        .expect("parameters");
        let responder_params = params.clone();
        let (left, right) = duplex(256 * 1024);
        let responder = tokio::spawn(async move {
            accept_forward_secure_pipe_session_with_key_history(
                right,
                &responder_params,
                &recipient,
                &[current_public, historical_public],
                ProtectionPolicy::from(mtp_codec::SignaturePolicy::Dual),
            )
            .await
        });
        let mut writer = initiate_forward_secure_pipe_session(
            left,
            params,
            &historical_sender,
            &recipient_public,
            ProtectionPolicy::from(mtp_codec::SignaturePolicy::Dual),
        )
        .await
        .expect("forward-secure initiator");
        writer
            .write_record(b"forward secret")
            .await
            .expect("record");
        writer.finish().await.expect("finish");
        let mut reader = responder.await.expect("responder task").expect("reader");
        assert_eq!(
            reader.read_record().await.expect("record").as_deref(),
            Some(b"forward secret".as_slice())
        );
        assert!(reader.read_record().await.expect("final").is_none());
    }

    #[test]
    fn group_session_offer_is_decryptable_by_each_current_member_only() {
        let sender = Keyring::generate();
        let first = Keyring::generate();
        let second = Keyring::generate();
        let outsider = Keyring::generate();
        let params = PipeSessionParameters::new_id(
            b"group-session",
            PipeId::new(11).unwrap(),
            41,
            99,
            0x40,
            0,
        )
        .expect("parameters");
        let key = [8u8; 32];
        let offer = build_session_offer(
            &params,
            &sender,
            &[first.public_key_bundle(), second.public_key_bundle()],
            key,
        )
        .expect("offer");
        let encrypted = DataValue::from_bytes(&offer).expect("encrypted offer");
        for member in [&first, &second] {
            let opened = encrypted
                .decrypt(
                    member,
                    ProtectionPurpose::from(PIPE_SESSION_ENCRYPTION_PURPOSE),
                )
                .expect("member decrypt");
            let fields = opened
                .as_signed()
                .and_then(|value| value.value.as_array_slice())
                .expect("signed fields");
            assert_eq!(fields[7].as_bytes_slice(), Some(key.as_slice()));
        }
        assert!(matches!(
            encrypted.decrypt(
                &outsider,
                ProtectionPurpose::from(PIPE_SESSION_ENCRYPTION_PURPOSE),
            ),
            Err(ProtectionError::NoMatchingRecipient)
        ));
    }
}
