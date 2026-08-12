//! Endpoint-to-endpoint authenticated encryption for MTP pipes.
//!
//! Pipe negotiation and QUIC/WebTransport remain transport primitives. This
//! module adds the application-facing record layer that callers can place on
//! top of an accepted [`PipeWriter`] or [`PipeReader`], plus an explicit
//! signed/KEM session-offer helper. The raw stream adapter does not infer
//! application identities or derive keys from clear pipe metadata.

use mtp_codec::{
    DataValue, DecodeLimits, MtpProtectionPurpose, ProtectionError, ProtectionPolicy,
    ProtectionPurpose,
};
use mtp_crypto::{
    AeadDecrypt, AeadEncrypt, DualSigner, Ed25519Signer, KemPublicKey, Keyring, PublicKeyBundle,
    SignatureScheme, XChaCha20Poly1305,
};
use rand::RngExt;
use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::{Zeroize, Zeroizing};

const PIPE_E2EE_DOMAIN: &[u8] = b"MTP-PIPE-E2EE-1";
const PIPE_RECORD_KDF_DOMAIN: &[u8] = b"MTP-PIPE-E2EE-1/KEY";
const PIPE_TRANSCRIPT_DOMAIN: &[u8] = b"MTP-PIPE-TRANSCRIPT-1";
const PIPE_RECORD_MESSAGE_LABEL: &[u8] = b"/message";
const PIPE_RECORD_NEXT_LABEL: &[u8] = b"/next";
const SESSION_ID_MAX_LEN: usize = 1024;
const RECORD_LENGTH_BYTES: usize = 4;
const RECORD_TYPE_BYTES: usize = 1;
const RECORD_TYPE_DATA: u8 = 0;
const RECORD_TYPE_FINAL: u8 = 1;
const XCHACHA_OVERHEAD: usize =
    mtp_crypto::aead::XCHACHA20POLY1305_NONCE_LEN + mtp_crypto::aead::AUTH_TAG_LEN;

/// Maximum encoded ciphertext size of one encrypted pipe record.
pub const MAX_ENCRYPTED_PIPE_RECORD: usize = 16 * 1024 * 1024;

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
}

/// Endpoint and stream metadata that a pipe-session key must bind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipeSessionParameters {
    session_id: Vec<u8>,
    pipe_id: u32,
    sender_id: u64,
    recipient_id: u64,
    purpose: u8,
    direction: u8,
}

impl PipeSessionParameters {
    pub fn new(
        session_id: impl AsRef<[u8]>,
        pipe_id: u32,
        sender_id: u64,
        recipient_id: u64,
        purpose: u8,
        direction: u8,
    ) -> Result<Self, PipeSessionError> {
        if pipe_id == 0 {
            return Err(PipeSessionError::InvalidParameters(
                "pipe id must be non-zero",
            ));
        }
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

    pub fn pipe_id(&self) -> u32 {
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
        transcript.extend_from_slice(&self.pipe_id.to_be_bytes());
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
        DataValue::UnsignedNumber(params.pipe_id as u128),
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
        DataValue::UnsignedNumber(params.pipe_id as u128),
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
        || u32::try_from(unsigned_field(fields, 2)?).ok() != Some(expected.pipe_id)
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

enum PipeSigner {
    Ed25519(Ed25519Signer),
    Dual(DualSigner),
}

impl SignatureScheme for PipeSigner {
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

fn pipe_signer_for_keyring(sender_keyring: &Keyring) -> Result<PipeSigner, PipeSessionError> {
    match (
        sender_keyring.sig_pq_secret_key.as_bytes().is_empty(),
        sender_keyring.sig_pq_public_key.as_bytes().is_empty(),
    ) {
        (true, true) => {
            sender_keyring.validate_ed25519_signing()?;
            Ok(PipeSigner::Ed25519(Ed25519Signer::new(
                &sender_keyring.sig_cl_secret_key,
            )?))
        }
        (false, false) => {
            sender_keyring.validate_dual_signing()?;
            Ok(PipeSigner::Dual(DualSigner::new(
                &sender_keyring.sig_cl_secret_key,
                &sender_keyring.sig_pq_secret_key,
                &sender_keyring.sig_pq_public_key,
            )?))
        }
        _ => Err(PipeSessionError::InvalidParameters(
            "incomplete ML-DSA key pair",
        )),
    }
}

fn pipe_signature_policy(keyring: &Keyring) -> Result<ProtectionPolicy, PipeSessionError> {
    match (
        keyring.sig_pq_secret_key.as_bytes().is_empty(),
        keyring.sig_pq_public_key.as_bytes().is_empty(),
    ) {
        (true, true) => Ok(ProtectionPolicy::from(mtp_codec::SignaturePolicy::Ed25519)),
        (false, false) => Ok(ProtectionPolicy::from(mtp_codec::SignaturePolicy::Dual)),
        _ => Err(PipeSessionError::InvalidParameters(
            "incomplete ML-DSA key pair",
        )),
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
        || u32::try_from(unsigned_field(fields, 2)?).ok() != Some(expected.pipe_id)
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

/// Errors produced by the encrypted pipe record layer.
#[derive(Debug)]
pub enum EncryptedPipeError {
    InvalidContext,
    InvalidRecordLength(usize),
    InvalidRecordType(u8),
    InvalidState,
    SequenceExhausted,
    FinalRecordRequired,
    UnexpectedEof,
    Io(std::io::Error),
    Crypto(mtp_crypto::CryptoError),
}

impl fmt::Display for EncryptedPipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContext => write!(f, "invalid encrypted pipe context"),
            Self::InvalidRecordLength(length) => {
                write!(f, "invalid encrypted pipe record length: {length}")
            }
            Self::InvalidRecordType(record_type) => {
                write!(f, "invalid encrypted pipe record type: {record_type}")
            }
            Self::InvalidState => f.write_str("encrypted pipe is no longer usable"),
            Self::SequenceExhausted => write!(f, "encrypted pipe sequence exhausted"),
            Self::FinalRecordRequired => f.write_str("encrypted pipe ended without a final record"),
            Self::UnexpectedEof => write!(f, "truncated encrypted pipe record"),
            Self::Io(error) => write!(f, "encrypted pipe I/O error: {error}"),
            Self::Crypto(error) => write!(f, "encrypted pipe authentication failed: {error}"),
        }
    }
}

impl std::error::Error for EncryptedPipeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Crypto(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for EncryptedPipeError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<mtp_crypto::CryptoError> for EncryptedPipeError {
    fn from(error: mtp_crypto::CryptoError) -> Self {
        Self::Crypto(error)
    }
}

fn checked_record_length(plaintext_len: usize) -> Result<usize, EncryptedPipeError> {
    let length = plaintext_len
        .checked_add(XCHACHA_OVERHEAD)
        .ok_or(EncryptedPipeError::InvalidRecordLength(usize::MAX))?;
    if length > MAX_ENCRYPTED_PIPE_RECORD || length > u32::MAX as usize {
        return Err(EncryptedPipeError::InvalidRecordLength(length));
    }
    Ok(length)
}

fn record_aad(
    context: &PipeProtectionContext,
    sequence: u64,
    record_len: usize,
    record_type: u8,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(PIPE_E2EE_DOMAIN.len() + 2 + 32 + 8 + 4);
    aad.extend_from_slice(PIPE_E2EE_DOMAIN);
    aad.push(context.purpose);
    aad.push(context.direction);
    aad.extend_from_slice(context.transcript_hash());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.extend_from_slice(&(record_len as u32).to_be_bytes());
    aad.push(record_type);
    aad
}

fn record_key_info(context: &PipeProtectionContext, sequence: u64, label: &[u8]) -> Vec<u8> {
    let mut info = Vec::with_capacity(PIPE_RECORD_KDF_DOMAIN.len() + 2 + 32 + 8 + label.len());
    info.extend_from_slice(PIPE_RECORD_KDF_DOMAIN);
    info.push(context.purpose);
    info.push(context.direction);
    info.extend_from_slice(context.transcript_hash());
    info.extend_from_slice(&sequence.to_be_bytes());
    info.extend_from_slice(label);
    info
}

fn derive_record_keys(
    chain_key: &[u8; 32],
    context: &PipeProtectionContext,
    sequence: u64,
) -> Result<([u8; 32], [u8; 32]), EncryptedPipeError> {
    let message_key = mtp_crypto::hkdf_expand(
        chain_key,
        context.transcript_hash(),
        &record_key_info(context, sequence, PIPE_RECORD_MESSAGE_LABEL),
        32,
    )?;
    let next_chain_key = mtp_crypto::hkdf_expand(
        chain_key,
        context.transcript_hash(),
        &record_key_info(context, sequence, PIPE_RECORD_NEXT_LABEL),
        32,
    )?;
    Ok((
        message_key
            .try_into()
            .map_err(|_| EncryptedPipeError::InvalidContext)?,
        next_chain_key
            .try_into()
            .map_err(|_| EncryptedPipeError::InvalidContext)?,
    ))
}

/// Writer for ordered, authenticated encrypted pipe records.
pub struct EncryptedPipeWriter<S> {
    stream: S,
    chain_key: Zeroizing<[u8; 32]>,
    context: PipeProtectionContext,
    sequence: u64,
    state: PipeStreamState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipeStreamState {
    Open,
    Finalized,
    Failed,
}

impl<S> EncryptedPipeWriter<S> {
    pub fn new(stream: S, key: [u8; 32], context: PipeProtectionContext) -> Self {
        Self {
            stream,
            chain_key: Zeroizing::new(key),
            context,
            sequence: 0,
            state: PipeStreamState::Open,
        }
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: AsyncWrite + Unpin> EncryptedPipeWriter<S> {
    /// Encrypt and append one record. Record boundaries are preserved by the
    /// four-byte length prefix and are authenticated as associated data.
    pub async fn write_record(&mut self, plaintext: &[u8]) -> Result<(), EncryptedPipeError> {
        if self.state != PipeStreamState::Open {
            return Err(EncryptedPipeError::InvalidState);
        }
        let result = self.write_record_inner(plaintext, RECORD_TYPE_DATA).await;
        if result.is_err() {
            self.poison();
        }
        result
    }

    async fn write_record_inner(
        &mut self,
        plaintext: &[u8],
        record_type: u8,
    ) -> Result<(), EncryptedPipeError> {
        let sequence = self.sequence;
        if sequence == u64::MAX {
            return Err(EncryptedPipeError::SequenceExhausted);
        }
        let record_len = checked_record_length(plaintext.len())?;
        let aad = record_aad(&self.context, sequence, record_len, record_type);
        let (message_key, next_chain_key) =
            derive_record_keys(&self.chain_key, &self.context, sequence)?;
        let next_chain_key = Zeroizing::new(next_chain_key);
        let cipher = XChaCha20Poly1305::new(message_key);
        let ciphertext = cipher.encrypt(plaintext, &aad)?;
        if ciphertext.len() != record_len {
            return Err(EncryptedPipeError::InvalidRecordLength(ciphertext.len()));
        }

        self.stream
            .write_all(&(record_len as u32).to_be_bytes())
            .await?;
        self.stream.write_all(&[record_type]).await?;
        self.stream.write_all(&ciphertext).await?;
        self.stream.flush().await?;
        self.chain_key = next_chain_key;
        self.sequence = sequence
            .checked_add(1)
            .ok_or(EncryptedPipeError::SequenceExhausted)?;
        Ok(())
    }

    fn poison(&mut self) {
        self.chain_key.zeroize();
        self.state = PipeStreamState::Failed;
    }

    /// Authenticate stream completion with a final empty record before
    /// closing the underlying transport.
    pub async fn finish(mut self) -> Result<(), EncryptedPipeError> {
        if self.state != PipeStreamState::Open {
            return Err(EncryptedPipeError::InvalidState);
        }
        if let Err(error) = self.write_record_inner(&[], RECORD_TYPE_FINAL).await {
            self.poison();
            return Err(error);
        }
        self.state = PipeStreamState::Finalized;
        if let Err(error) = self.stream.shutdown().await {
            self.poison();
            return Err(error.into());
        }
        Ok(())
    }
}

/// Reader for ordered, authenticated encrypted pipe records.
pub struct EncryptedPipeReader<R> {
    stream: R,
    chain_key: Zeroizing<[u8; 32]>,
    context: PipeProtectionContext,
    sequence: u64,
    state: PipeStreamState,
}

impl<R> EncryptedPipeReader<R> {
    pub fn new(stream: R, key: [u8; 32], context: PipeProtectionContext) -> Self {
        Self {
            stream,
            chain_key: Zeroizing::new(key),
            context,
            sequence: 0,
            state: PipeStreamState::Open,
        }
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn into_inner(self) -> R {
        self.stream
    }
}

impl<R: AsyncRead + Unpin> EncryptedPipeReader<R> {
    /// Read and authenticate the next record. `None` is returned only after a
    /// valid authenticated final record; transport EOF alone is truncation.
    pub async fn read_record(&mut self) -> Result<Option<Vec<u8>>, EncryptedPipeError> {
        if self.state == PipeStreamState::Finalized {
            return Ok(None);
        }
        if self.state == PipeStreamState::Failed {
            return Err(EncryptedPipeError::InvalidState);
        }
        let result = self.read_record_inner().await;
        if result.is_err() {
            self.poison();
        }
        result
    }

    async fn read_record_inner(&mut self) -> Result<Option<Vec<u8>>, EncryptedPipeError> {
        if self.sequence == u64::MAX {
            return Err(EncryptedPipeError::SequenceExhausted);
        }
        let mut prefix = [0u8; RECORD_LENGTH_BYTES];
        self.stream.read_exact(&mut prefix).await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                EncryptedPipeError::FinalRecordRequired
            } else {
                EncryptedPipeError::Io(error)
            }
        })?;

        let record_len = u32::from_be_bytes(prefix) as usize;
        if !(XCHACHA_OVERHEAD..=MAX_ENCRYPTED_PIPE_RECORD).contains(&record_len) {
            return Err(EncryptedPipeError::InvalidRecordLength(record_len));
        }
        let mut record_type = [0u8; RECORD_TYPE_BYTES];
        self.stream
            .read_exact(&mut record_type)
            .await
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    EncryptedPipeError::UnexpectedEof
                } else {
                    EncryptedPipeError::Io(error)
                }
            })?;
        if !matches!(record_type[0], RECORD_TYPE_DATA | RECORD_TYPE_FINAL) {
            return Err(EncryptedPipeError::InvalidRecordType(record_type[0]));
        }

        let mut ciphertext = vec![0u8; record_len];
        self.stream
            .read_exact(&mut ciphertext)
            .await
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    EncryptedPipeError::UnexpectedEof
                } else {
                    EncryptedPipeError::Io(error)
                }
            })?;
        let sequence = self.sequence;
        let aad = record_aad(&self.context, sequence, record_len, record_type[0]);
        let (message_key, next_chain_key) =
            derive_record_keys(&self.chain_key, &self.context, sequence)?;
        let next_chain_key = Zeroizing::new(next_chain_key);
        let cipher = XChaCha20Poly1305::new(message_key);
        let plaintext = cipher.decrypt(&ciphertext, &aad)?;
        self.chain_key = next_chain_key;
        self.sequence = sequence
            .checked_add(1)
            .ok_or(EncryptedPipeError::SequenceExhausted)?;
        if record_type[0] == RECORD_TYPE_FINAL {
            if !plaintext.is_empty() {
                return Err(EncryptedPipeError::InvalidRecordLength(plaintext.len()));
            }
            self.state = PipeStreamState::Finalized;
            return Ok(None);
        }
        Ok(Some(plaintext))
    }

    fn poison(&mut self) {
        self.chain_key.zeroize();
        self.state = PipeStreamState::Failed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

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
        let stream = writer.into_inner();
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
        let params = PipeSessionParameters::new(b"session/client/peer/pipe-7", 7, 41, 99, 0x40, 0)
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
        let params = PipeSessionParameters::new(b"historical-session", 8, 41, 99, 0x40, 0)
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
        let params = PipeSessionParameters::new(b"forward-secure-session", 17, 41, 99, 0x40, 0)
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
        let params =
            PipeSessionParameters::new(b"group-session", 11, 41, 99, 0x40, 0).expect("parameters");
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
