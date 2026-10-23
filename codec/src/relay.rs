#![cfg(feature = "crypto")]

mod builder;
mod metadata;
#[allow(deprecated)]
pub use metadata::relay_metadata_claimed_signer_id;
use metadata::{
    field, relay_field, string_field, validate_application_message_type, validate_metadata_size,
    validate_relay_frame,
};
pub use metadata::{
    open_relay_metadata_checked, open_relay_metadata_with_checked,
    open_relay_metadata_with_limits_checked, open_relay_metadata_with_limits_without_replay,
    open_relay_metadata_with_without_replay, open_relay_metadata_without_replay,
    relay_metadata_claimed_signer_id_with_limits, relay_metadata_claimed_signer_id_with_options,
};
mod content;
pub use content::open_relay_content_with_limits_without_replay;
#[allow(deprecated)]
pub use content::{
    open_relay_content, open_relay_content_with_keyrings,
    open_relay_content_with_keyrings_and_limits, open_relay_content_with_keys,
    open_relay_content_with_limits,
};
// Relay-specific opening helpers.
//
// The generic [`DataValue`] protection operations remain the primitive API.
// These helpers add the protocol boundary needed by relay participants:
// metadata can be authenticated and returned with an opaque content value,
// while content opening is a separate operation that requires the final
// recipient identity.

use mtp_common::MessageId;
use mtp_crypto::{Keyring, PublicKeyBundle, SignatureScheme};
use mtp_type_map::{CommunicationType, DataType, DataTypeId, TypeMap};

use crate::{
    CommunicationValue, DataValue, DecodeLimits, EncodeLimits, MtpProtectionPurpose,
    ProtectedLimits, ProtectionError, ProtectionPolicy, ReplayError, ReplayGuard, rand_u32,
};

/// The relay metadata schema emitted by [`SealedRelayBuilder`].
pub const CURRENT_RELAY_VERSION: u64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("value is not a Relay communication frame")]
    NotRelay,
    #[error("sealed relay frame must not expose an outer sender")]
    OuterSenderPresent,
    #[error("sealed relay frame must contain an explicit next-hop receiver")]
    MissingNextHop,
    #[error("relay frame has an invalid protected layout: {0}")]
    InvalidLayout(&'static str),
    #[error("relay frame does not declare a relay version")]
    MissingRelayVersion,
    #[error("unsupported relay version {0}")]
    UnsupportedRelayVersion(u64),
    #[error("relay content is addressed to a different final recipient")]
    NotFinalRecipient,
    #[error("relay message was already accepted")]
    Replay,
    #[error("relay resource limit exceeded: {0}")]
    ResourceLimit(&'static str),
    #[error("relay application message type is reserved: {0}")]
    ReservedApplicationType(String),
    #[error("protection error: {0}")]
    Protection(#[from] ProtectionError),
    #[error("replay guard error: {0}")]
    ReplayGuard(#[from] ReplayError),
}

/// Metadata authenticated by the signer and decryptable by metadata
/// recipients.
///
/// `encrypted_content` is intentionally kept as an opaque `DataValue` so a
/// metadata-only relay participant can store or forward it without possessing
/// a content key.
#[derive(Debug, Clone)]
pub struct VerifiedRelayMetadata {
    relay_version: u64,
    signer_id: u64,
    final_recipient_id: u64,
    message_id: MessageId,
    created_at: u64,
    metadata: Option<DataValue>,
    encrypted_content: DataValue,
    type_map: TypeMap,
    matched_signer_key_index: usize,
    decode_limits: DecodeLimits,
    encode_limits: EncodeLimits,
    protected_limits: ProtectedLimits,
    // There is intentionally no public constructor. This marker documents
    // that the fields originate from a successful authenticated open.
    _verified: VerifiedMarker,
}

#[derive(Debug, Clone, Copy)]
struct VerifiedMarker;

impl VerifiedRelayMetadata {
    /// Return the authenticated MTP relay metadata schema version.
    pub fn relay_version(&self) -> u64 {
        self.relay_version
    }

    pub fn signer_id(&self) -> u64 {
        self.signer_id
    }

    pub fn final_recipient_id(&self) -> u64 {
        self.final_recipient_id
    }

    pub fn decode_limits(&self) -> DecodeLimits {
        self.decode_limits
    }

    pub fn protected_limits(&self) -> ProtectedLimits {
        self.protected_limits
    }

    pub fn encode_limits(&self) -> EncodeLimits {
        self.encode_limits
    }

    pub fn message_id(&self) -> MessageId {
        self.message_id
    }

    /// Return the authenticated creation time as Unix epoch milliseconds.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Return the authenticated application metadata without interpreting it.
    pub fn metadata(&self) -> Option<&DataValue> {
        self.metadata.as_ref()
    }

    /// Return the authenticated content envelope for forwarding. The value
    /// remains opaque to metadata-only relay participants.
    pub fn encrypted_content(&self) -> &DataValue {
        &self.encrypted_content
    }

    /// Return the index of the trusted signing key that verified the
    /// authenticated metadata.
    pub fn matched_signer_key_index(&self) -> usize {
        self.matched_signer_key_index
    }
}

/// Content opened and authenticated for the final recipient.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedRelayContent {
    pub signer_id: u64,
    pub final_recipient_id: u64,
    pub message_type: CommunicationType,
    pub content: DataValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelayOpenOptions {
    pub policy: ProtectionPolicy,
    pub decode_limits: DecodeLimits,
    pub encode_limits: EncodeLimits,
    pub protected_limits: ProtectedLimits,
}

impl RelayOpenOptions {
    pub fn new(policy: ProtectionPolicy) -> Self {
        Self {
            policy,
            decode_limits: DecodeLimits::default(),
            encode_limits: EncodeLimits::default(),
            protected_limits: ProtectedLimits::default(),
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

/// Native sealed-relay builder shared by non-WASM applications.
///
/// The browser SDK and this builder intentionally produce the same reserved
/// metadata layout. Routing recipients are supplied separately from content
/// recipients so a metadata-only relay participant can open metadata without
/// receiving content keys.
pub struct SealedRelayBuilder<'a> {
    message_type: CommunicationType,
    content: DataValue,
    signer_id: u64,
    final_recipient_id: u64,
    next_hop_id: u64,
    message_id: Option<MessageId>,
    created_at: Option<u64>,
    metadata: Option<DataValue>,
    signer: &'a dyn SignatureScheme,
    metadata_recipients: Vec<PublicKeyBundle>,
    content_recipients: Vec<PublicKeyBundle>,
    type_map: Option<TypeMap>,
    limits: ProtectedLimits,
    encode_limits: EncodeLimits,
}

#[derive(Debug)]
struct RelayMetadataV1 {
    final_recipient_id: u64,
    message_id: MessageId,
    created_at: u64,
    metadata: Option<DataValue>,
    encrypted_content: DataValue,
}

/// Change only the clear next-hop routing field of a sealed relay frame.
/// The authenticated encrypted payload is cloned byte-for-byte, so a relay
/// cannot alter the final recipient or message metadata while forwarding.
pub fn forward_relay_frame(
    frame: &CommunicationValue,
    next_hop_receiver_id: u64,
) -> Result<CommunicationValue, RelayError> {
    validate_relay_frame(frame)?;
    Ok(frame
        .clone()
        .with_id(rand_u32())
        .with_receiver(next_hop_receiver_id))
}

#[cfg(test)]
mod tests;
