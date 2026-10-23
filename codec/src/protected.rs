//! Native codec for direct protected application messages.
//!
//! The protected envelope is an MTP protocol structure. Keeping its schema,
//! version checks, and routing authentication here gives native applications
//! and language bindings one implementation to consume.

#![cfg(feature = "crypto")]

mod builder;
mod opening;
mod replay;
use mtp_common::MessageId;
use mtp_crypto::{Keyring, PublicKeyBundle, SignatureScheme};
use mtp_type_map::{CommunicationType, DataType, DataTypeId, TypeMap};
#[allow(deprecated)]
pub use opening::protected_claimed_signer_id;
pub use opening::{
    open_protected_checked, open_protected_with_checked, open_protected_with_keys_checked,
    open_protected_with_keys_without_replay, open_protected_with_without_replay,
    open_protected_without_replay, protected_claimed_signer_id_with_limits,
    protected_claimed_signer_id_with_options,
};
use opening::{protected_field_id, validate_application_message_type};
use std::collections::{HashSet, VecDeque};

use crate::{
    CommunicationValue, DataValue, DecodeLimits, EncodeLimits, ProtectionError, ProtectionPolicy,
    ProtectionPurpose,
};

/// The direct protected-message envelope schema version emitted by this
/// codec.
pub const CURRENT_PROTECTED_VERSION: u64 = 1;

/// Semantic limits for fields that are retained after a protected message is
/// opened. These are intentionally separate from generic transport blobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtectedLimits {
    pub max_metadata_encoded_bytes: usize,
    pub max_signer_key_history: usize,
    pub max_decryption_key_history: usize,
}

impl Default for ProtectedLimits {
    fn default() -> Self {
        Self {
            max_metadata_encoded_bytes: 1024 * 1024,
            max_signer_key_history: 8,
            max_decryption_key_history: 8,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtectedError {
    #[error("value is not an application communication frame")]
    NotApplicationFrame,
    #[error("protected frame must contain an explicit receiver")]
    MissingReceiver,
    #[error("protected frame payload is not encrypted")]
    PayloadNotEncrypted,
    #[error("protected frame payload is not signed")]
    PayloadNotSigned,
    #[error("protected payload does not contain an MTP envelope")]
    MissingEnvelope,
    #[error("protected frame has an invalid protected layout: {0}")]
    InvalidLayout(&'static str),
    #[error("protected message does not declare a protected version")]
    MissingProtectedVersion,
    #[error("unsupported protected message version {0}")]
    UnsupportedProtectedVersion(u64),
    #[error("protected message type does not match outer routing")]
    MessageTypeMismatch,
    #[error("protected final recipient does not match outer routing receiver")]
    FinalRecipientMismatch,
    #[error("protected frame sender does not match authenticated signer")]
    SenderMismatch,
    #[error("protected receiver does not match the expected recipient")]
    ExpectedReceiverMismatch,
    #[error("protected application communication type is reserved: {0}")]
    ReservedApplicationType(String),
    #[error("protected message was already accepted")]
    Replay,
    #[error("protected resource limit exceeded: {0}")]
    ResourceLimit(&'static str),
    #[error("protection error: {0}")]
    Protection(#[from] ProtectionError),
    #[error("replay guard error: {0}")]
    ReplayGuard(#[from] ReplayError),
}

/// A storage-backed caller hook for authenticated message deduplication.
///
/// The codec deliberately does not decide where durable state lives. An
/// application can implement this over persistent storage. The key is the
/// authenticated `(signer_id, message_id)` pair, never the transport-visible
/// communication ID. `created_at` is supplied as authenticated retention
/// metadata; implementations must not use it as the replay identity.
pub trait ReplayGuard {
    /// Return `true` when the message is new and has been recorded. Return
    /// `false` for a message that was already recorded.
    fn accept(
        &mut self,
        signer_id: u64,
        message_id: MessageId,
        created_at: u64,
    ) -> Result<bool, ReplayError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("replay store error: {0}")]
    Store(String),
}

/// Small in-memory guard useful for tests and short-lived clients. Production
/// consumers should implement [`ReplayGuard`] over persistent storage.
#[derive(Debug)]
pub struct InMemoryReplayGuard {
    accepted: HashSet<(u64, MessageId)>,
    order: VecDeque<(u64, MessageId)>,
    capacity: usize,
}

/// A direct protected-message builder shared by native applications and
/// language bindings.
pub struct ProtectedMessageBuilder<'a> {
    message_type: CommunicationType,
    content: DataValue,
    signer_id: u64,
    final_recipient_id: u64,
    message_id: Option<MessageId>,
    created_at: Option<u64>,
    signer: &'a dyn SignatureScheme,
    recipients: Vec<PublicKeyBundle>,
    signature_purpose: ProtectionPurpose,
    encryption_purpose: ProtectionPurpose,
    type_map: Option<TypeMap>,
    frame_id: Option<u32>,
    expose_sender: bool,
    limits: ProtectedLimits,
    encode_limits: EncodeLimits,
}

/// A direct protected message after the encrypted envelope and its signature
/// have been authenticated.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedProtectedMessage {
    protected_version: u64,
    signer_id: u64,
    final_recipient_id: u64,
    message_id: MessageId,
    created_at: u64,
    message_type: CommunicationType,
    content: DataValue,
    matched_signer_key_index: usize,
}

impl VerifiedProtectedMessage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protected_version: u64,
        signer_id: u64,
        final_recipient_id: u64,
        message_id: MessageId,
        created_at: u64,
        message_type: CommunicationType,
        content: DataValue,
        matched_signer_key_index: usize,
    ) -> Self {
        Self {
            protected_version,
            signer_id,
            final_recipient_id,
            message_id,
            created_at,
            message_type,
            content,
            matched_signer_key_index,
        }
    }

    pub fn protected_version(&self) -> u64 {
        self.protected_version
    }

    pub fn signer_id(&self) -> u64 {
        self.signer_id
    }

    pub fn final_recipient_id(&self) -> u64 {
        self.final_recipient_id
    }

    pub fn message_id(&self) -> MessageId {
        self.message_id
    }

    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    pub fn message_type(&self) -> CommunicationType {
        self.message_type
    }

    pub fn content(&self) -> &DataValue {
        &self.content
    }

    pub fn matched_signer_key_index(&self) -> usize {
        self.matched_signer_key_index
    }
}

/// Options that control verification of a direct protected message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtectedOpenOptions {
    /// Require the protected frame to be addressed to this receiver when set.
    pub expected_receiver_id: Option<u64>,
    /// Purpose used to verify the protected envelope signature.
    pub signature_purpose: ProtectionPurpose,
    /// Purpose used to decrypt the protected envelope.
    pub encryption_purpose: ProtectionPurpose,
    /// Signature algorithms accepted by the receiver.
    pub policy: ProtectionPolicy,
    /// Recursive and cumulative allocation policy used while opening.
    pub decode_limits: DecodeLimits,
    /// Bound used when reconstructing signed bytes for verification.
    pub encode_limits: EncodeLimits,
    /// Semantic limits for retained protected fields and key histories.
    pub protected_limits: ProtectedLimits,
}

impl ProtectedOpenOptions {
    pub const fn new(
        expected_receiver_id: Option<u64>,
        signature_purpose: ProtectionPurpose,
        encryption_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
    ) -> Self {
        Self {
            expected_receiver_id,
            signature_purpose,
            encryption_purpose,
            policy,
            decode_limits: DecodeLimits {
                max_depth: 64,
                max_values: 65_536,
                max_blob_size: 16 * 1024 * 1024,
                max_recipients: 64,
                max_allocated_bytes: 64 * 1024 * 1024,
            },
            encode_limits: EncodeLimits {
                max_depth: 64,
                max_values: 65_536,
                max_output_size: 16 * 1024 * 1024,
            },
            protected_limits: ProtectedLimits {
                max_metadata_encoded_bytes: 1024 * 1024,
                max_signer_key_history: 8,
                max_decryption_key_history: 8,
            },
        }
    }

    pub const fn with_limits(
        mut self,
        decode_limits: DecodeLimits,
        protected_limits: ProtectedLimits,
    ) -> Self {
        self.decode_limits = decode_limits;
        self.protected_limits = protected_limits;
        self
    }

    pub const fn with_encode_limits(mut self, encode_limits: EncodeLimits) -> Self {
        self.encode_limits = encode_limits;
        self
    }
}

#[cfg(test)]
mod tests;
