//! Authenticated session offers and forward-secure pipe handshakes.
//!
//! Pipe negotiation and QUIC/WebTransport remain transport primitives. This
//! module adds the application-facing record layer that callers can place on
//! top of any async byte stream, plus an explicit
//! signed/KEM session-offer helper. The raw stream adapter does not infer
//! application identities or derive keys from clear pipe metadata.

mod offers;
#[cfg(test)]
use offers::build_session_offer;
pub use offers::{
    accept_pipe_session, accept_pipe_session_auto, accept_pipe_session_with_key_history,
    accept_pipe_session_with_policy, initiate_group_pipe_session,
    initiate_group_pipe_session_with_suite, initiate_pipe_session,
};
use offers::{offer_field, read_session_offer, unsigned_field, write_session_offer};
mod forward_secure;
use crate::policy::{pipe_signature_policy, pipe_signer_for_keyring};
use crate::{EncryptedPipeError, EncryptedPipeReader, EncryptedPipeWriter};
pub use forward_secure::{
    accept_forward_secure_pipe_session, accept_forward_secure_pipe_session_auto,
    accept_forward_secure_pipe_session_with_key_history, initiate_forward_secure_pipe_session,
};
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

#[cfg(test)]
mod tests;
