//! Ordered encrypted records and cancellation-safe stream state.

use crate::PipeProtectionContext;
use mtp_crypto::{AeadDecrypt, AeadEncrypt, XChaCha20Poly1305};
use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::{Zeroize, Zeroizing};

const PIPE_E2EE_DOMAIN: &[u8] = b"MTP-PIPE-E2EE-1";
const PIPE_RECORD_KDF_DOMAIN: &[u8] = b"MTP-PIPE-E2EE-1/KEY";
const PIPE_RECORD_MESSAGE_LABEL: &[u8] = b"/message";
const PIPE_RECORD_NEXT_LABEL: &[u8] = b"/next";
const RECORD_LENGTH_BYTES: usize = 4;
const RECORD_TYPE_BYTES: usize = 1;
const RECORD_TYPE_DATA: u8 = 0;
const RECORD_TYPE_FINAL: u8 = 1;
const XCHACHA_OVERHEAD: usize =
    mtp_crypto::aead::XCHACHA20POLY1305_NONCE_LEN + mtp_crypto::aead::AUTH_TAG_LEN;

/// Maximum encoded ciphertext size of one encrypted pipe record.
pub const MAX_ENCRYPTED_PIPE_RECORD: usize = 16 * 1024 * 1024;

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
            Self::InvalidContext => write!(f, "invalid encrypted pipe context or reserved purpose"),
            Self::InvalidRecordLength(length) => {
                write!(f, "invalid encrypted pipe record length: {length}")
            }
            Self::InvalidRecordType(record_type) => {
                write!(f, "invalid encrypted pipe record type: {record_type}")
            }
            Self::InvalidState => f.write_str("encrypted pipe is in an unusable state"),
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
    aad.push(context.purpose());
    aad.push(context.direction());
    aad.extend_from_slice(context.transcript_hash());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.extend_from_slice(&(record_len as u32).to_be_bytes());
    aad.push(record_type);
    aad
}

fn record_key_info(context: &PipeProtectionContext, sequence: u64, label: &[u8]) -> Vec<u8> {
    let mut info = Vec::with_capacity(PIPE_RECORD_KDF_DOMAIN.len() + 2 + 32 + 8 + label.len());
    info.extend_from_slice(PIPE_RECORD_KDF_DOMAIN);
    info.push(context.purpose());
    info.push(context.direction());
    info.extend_from_slice(context.transcript_hash());
    info.extend_from_slice(&sequence.to_be_bytes());
    info.extend_from_slice(label);
    info
}

pub(crate) fn derive_record_keys(
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
    InProgress,
    Finalized,
    Failed,
}

impl<S> EncryptedPipeWriter<S> {
    pub fn abort(self) -> S {
        self.stream
    }
    pub fn context(&self) -> &PipeProtectionContext {
        &self.context
    }
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

    /// Recover the underlying stream only at a confirmed record boundary.
    ///
    /// An in-progress or failed writer may have emitted a partial record, so
    /// its stream is discarded rather than returned for unsafe reuse.
    pub fn try_into_inner(self) -> Result<S, EncryptedPipeError> {
        match self.state {
            PipeStreamState::Open | PipeStreamState::Finalized => Ok(self.stream),
            PipeStreamState::InProgress | PipeStreamState::Failed => {
                Err(EncryptedPipeError::InvalidState)
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> EncryptedPipeWriter<S> {
    /// Encrypt and append one record. Record boundaries are preserved by the
    /// four-byte length prefix and are authenticated as associated data.
    pub async fn write_record(&mut self, plaintext: &[u8]) -> Result<(), EncryptedPipeError> {
        match self.state {
            PipeStreamState::Open => {}
            PipeStreamState::InProgress => {
                self.poison();
                return Err(EncryptedPipeError::InvalidState);
            }
            PipeStreamState::Finalized | PipeStreamState::Failed => {
                return Err(EncryptedPipeError::InvalidState);
            }
        }

        self.state = PipeStreamState::InProgress;
        match self.write_record_inner(plaintext, RECORD_TYPE_DATA).await {
            Ok(()) => {
                self.state = PipeStreamState::Open;
                Ok(())
            }
            Err(error) => {
                self.poison();
                Err(error)
            }
        }
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
        self.state = PipeStreamState::InProgress;
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
    pub fn context(&self) -> &PipeProtectionContext {
        &self.context
    }
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

    /// Recover the underlying stream only at a confirmed record boundary.
    ///
    /// An in-progress or failed reader may have consumed part of a record, so
    /// its stream is discarded rather than returned for unsafe reuse.
    pub fn try_into_inner(self) -> Result<R, EncryptedPipeError> {
        match self.state {
            PipeStreamState::Open | PipeStreamState::Finalized => Ok(self.stream),
            PipeStreamState::InProgress | PipeStreamState::Failed => {
                Err(EncryptedPipeError::InvalidState)
            }
        }
    }
}

impl<R: AsyncRead + Unpin> EncryptedPipeReader<R> {
    /// Read and authenticate the next record. `None` is returned only after a
    /// valid authenticated final record; transport EOF alone is truncation.
    pub async fn read_record(&mut self) -> Result<Option<Vec<u8>>, EncryptedPipeError> {
        match self.state {
            PipeStreamState::Open => {}
            PipeStreamState::Finalized => return Ok(None),
            PipeStreamState::InProgress => {
                self.poison();
                return Err(EncryptedPipeError::InvalidState);
            }
            PipeStreamState::Failed => return Err(EncryptedPipeError::InvalidState),
        }

        self.state = PipeStreamState::InProgress;
        match self.read_record_inner().await {
            Ok(record) => {
                if self.state == PipeStreamState::InProgress {
                    self.state = PipeStreamState::Open;
                }
                Ok(record)
            }
            Err(error) => {
                self.poison();
                Err(error)
            }
        }
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
