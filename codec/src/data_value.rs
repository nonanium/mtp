mod wire;
use wire::{checked_add, checked_count};
mod containers;
#[cfg(feature = "crypto")]
mod protection;
use containers::{encoded_container_len_after_value, ensure_unique_container_fields};
pub use containers::{
    merge_container_from_with, merge_container_from_with_limits, merge_container_left_biased,
    merge_containers_owned, merge_containers_owned_with_limits, validate_container,
    validate_container_entries, validate_container_with_limits,
};
mod conversions;
use base64::Engine;
use base64::engine::general_purpose;
use byteorder::{BigEndian, ReadBytesExt};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::Cursor;
use std::mem::size_of;

use mtp_common::CodecError;
use mtp_type_map::DataTypeId;

#[cfg(feature = "crypto")]
use mtp_crypto::{
    EncryptionType, Keyring, PublicKeyBundle, RecipientEntry, SigAlgorithm, SignatureScheme,
};

/// Protocol context authenticated by every signed [`DataValue`].
///
/// This is intentionally not serialized: it separates MTP data-value
/// signatures from signatures generated for every other MTP purpose.
#[cfg(feature = "crypto")]
const SIGN_DOMAIN: &[u8] = b"MTP-DATA-SIGN-1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataKind {
    Bool,
    SignedNumber,
    UnsignedNumber,
    Float,
    Str,
    Bytes,
    /// Arrays may contain heterogeneous recursive values.
    Array,
    Container,
    #[cfg(feature = "crypto")]
    Encrypted,
    #[cfg(feature = "crypto")]
    Signed,
    Null,
}

/// Resource limits applied while decoding recursive `DataValue` structures.
///
/// The wire format deliberately uses recursive values, so decoding must not
/// let attacker-controlled nesting or allocation sizes become process-wide
/// limits. These are conservative defaults for transported frames; callers
/// handling a different trust boundary can opt into stricter limits with
/// [`DataValue::from_bytes_with_limits`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DecodeLimits {
    /// Maximum number of nested `Array`, `Container`, and `Signed` wrappers.
    pub max_depth: usize,
    /// Maximum number of `DataValue` nodes in one decoded value.
    pub max_values: usize,
    /// Maximum size of one string, binary blob, signed wrapper, or encrypted
    /// envelope body.
    pub max_blob_size: usize,
    /// Maximum number of recipients in one encrypted envelope.
    pub max_recipients: usize,
    /// Maximum aggregate memory allocated for owned decoder output.
    pub max_allocated_bytes: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_values: 65_536,
            max_blob_size: 16 * 1024 * 1024,
            max_recipients: 64,
            max_allocated_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Conservative multiplier used when deriving decoder allocation capacity
/// from an admitted transport frame.  A frame can result in owned wrapper,
/// recipient, ciphertext, and value allocations, so this is intentionally
/// larger than the number of bytes on the wire.
pub const DEFAULT_TRANSPORT_ALLOCATION_FACTOR: u64 = 4;

impl DecodeLimits {
    pub fn intersection(self, other: Self) -> Self {
        Self {
            max_depth: self.max_depth.min(other.max_depth),
            max_values: self.max_values.min(other.max_values),
            max_blob_size: self.max_blob_size.min(other.max_blob_size),
            max_recipients: self.max_recipients.min(other.max_recipients),
            max_allocated_bytes: self.max_allocated_bytes.min(other.max_allocated_bytes),
        }
    }

    /// Derive codec allocation limits from the transport's admitted complete
    /// frame size. This keeps a larger explicitly configured transport policy
    /// from being rejected by an unrelated hard-coded blob bound while still
    /// preserving recursive and recipient-count limits.
    pub fn for_transport_message_size(max_message_size: u64) -> Self {
        Self::for_transport_message_size_with_allocation_factor(
            max_message_size,
            DEFAULT_TRANSPORT_ALLOCATION_FACTOR,
        )
    }

    /// Derive transport limits with an explicit allocation multiplier.
    ///
    /// The multiplier is a deployment knob for transports whose crypto or
    /// framing implementation has a different copy profile. A zero value is
    /// treated as one so the allocation budget never becomes accidentally
    /// unbounded by arithmetic underflow or unusably small by configuration.
    pub fn for_transport_message_size_with_allocation_factor(
        max_message_size: u64,
        allocation_factor: u64,
    ) -> Self {
        let max_blob_size = usize::try_from(max_message_size.saturating_sub(4))
            .unwrap_or(usize::MAX)
            .min(u32::MAX as usize);
        let allocation_factor = allocation_factor.max(1);
        let max_allocated_bytes =
            usize::try_from(max_message_size.saturating_mul(allocation_factor))
                .unwrap_or(usize::MAX);
        Self {
            max_blob_size,
            max_allocated_bytes,
            ..Self::default()
        }
    }
}

/// Resource limits applied while encoding recursive `DataValue` structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EncodeLimits {
    /// Maximum number of nested `Array`, `Container`, and `Signed` wrappers.
    pub max_depth: usize,
    /// Maximum number of `DataValue` nodes in one encoded value.
    pub max_values: usize,
    /// Maximum serialized size of the encoded value.
    pub max_output_size: usize,
}

impl Default for EncodeLimits {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_values: 65_536,
            max_output_size: 16 * 1024 * 1024,
        }
    }
}

impl EncodeLimits {
    pub fn intersection(self, other: Self) -> Self {
        Self {
            max_depth: self.max_depth.min(other.max_depth),
            max_values: self.max_values.min(other.max_values),
            max_output_size: self.max_output_size.min(other.max_output_size),
        }
    }

    /// Derive encoder limits from the transport's admitted complete frame size.
    pub fn for_transport_message_size(max_message_size: u64) -> Self {
        Self {
            max_output_size: usize::try_from(max_message_size).unwrap_or(usize::MAX),
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct DecodeContext {
    limits: DecodeLimits,
    depth: usize,
    values: usize,
    allocated_bytes: usize,
}

/// Structured failures returned by the diagnostic decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("malformed encoding")]
    MalformedEncoding,
    #[error("decoder nesting depth limit exceeded")]
    DepthLimit,
    #[error("decoder value-count limit exceeded")]
    ValueCountLimit,
    #[error("decoder blob-size limit exceeded")]
    BlobLimit,
    #[error("decoder allocation limit exceeded")]
    AllocationLimit,
    #[error("decoder recipient-count limit exceeded")]
    RecipientLimit,
    #[error("duplicate container field")]
    DuplicateField,
}

// Keep the name used by the original internal diagnostics in this module.
type DecodeFailure = DecodeError;

#[derive(Debug, Clone, Copy)]
struct EncodeContext {
    limits: EncodeLimits,
    depth: usize,
    values: usize,
}

impl fmt::Display for DataKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool => f.write_str("Bool"),
            Self::SignedNumber => f.write_str("SignedNumber"),
            Self::UnsignedNumber => f.write_str("UnsignedNumber"),
            Self::Float => f.write_str("Float"),
            Self::Str => f.write_str("Str"),
            Self::Bytes => f.write_str("Bytes"),
            Self::Array => f.write_str("Array"),
            Self::Container => f.write_str("Container"),
            #[cfg(feature = "crypto")]
            Self::Encrypted => f.write_str("Encrypted"),
            #[cfg(feature = "crypto")]
            Self::Signed => f.write_str("Signed"),
            Self::Null => f.write_str("Null"),
        }
    }
}

#[cfg(feature = "crypto")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtectionPurpose(pub u8);

#[cfg(feature = "crypto")]
impl From<u8> for ProtectionPurpose {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

#[cfg(feature = "crypto")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ApplicationProtectionPurpose(u8);

#[cfg(feature = "crypto")]
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionPurposeError {
    #[error("protection purpose 0x{0:02x} is reserved for MTP")]
    Reserved(u8),
}

/// MTP-owned protection-purpose registry.
///
/// Applications may still use [`ProtectionPurpose::from`] for their own
/// domain-separated values, but protocol code should use this enum so the
/// reserved values are defined in one place.
#[cfg(feature = "crypto")]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MtpProtectionPurpose {
    RelayMetadataEncryption = 0x30,
    RelayContentSignature = 0x31,
    RelayContentEncryption = 0x32,
    RelayMetadataSignature = 0x33,
    PipeSessionSignature = 0x50,
    PipeSessionEncryption = 0x51,
}

#[cfg(feature = "crypto")]
impl MtpProtectionPurpose {
    pub const fn value(self) -> u8 {
        self as u8
    }

    pub const fn is_reserved(value: u8) -> bool {
        value == Self::RelayMetadataEncryption as u8
            || value == Self::RelayContentSignature as u8
            || value == Self::RelayContentEncryption as u8
            || value == Self::RelayMetadataSignature as u8
            || value == Self::PipeSessionSignature as u8
            || value == Self::PipeSessionEncryption as u8
    }
}

#[cfg(feature = "crypto")]
impl ApplicationProtectionPurpose {
    pub fn new(value: u8) -> Result<Self, ProtectionPurposeError> {
        if MtpProtectionPurpose::is_reserved(value) {
            return Err(ProtectionPurposeError::Reserved(value));
        }
        Ok(Self(value))
    }

    pub const fn value(self) -> u8 {
        self.0
    }
}

#[cfg(feature = "crypto")]
impl TryFrom<u8> for ApplicationProtectionPurpose {
    type Error = ProtectionPurposeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[cfg(feature = "crypto")]
impl From<ApplicationProtectionPurpose> for ProtectionPurpose {
    fn from(value: ApplicationProtectionPurpose) -> Self {
        Self(value.value())
    }
}

#[cfg(feature = "crypto")]
impl From<MtpProtectionPurpose> for ProtectionPurpose {
    fn from(value: MtpProtectionPurpose) -> Self {
        Self(value.value())
    }
}

/// Signature algorithms a receiver is willing to accept for a protected
/// value.  The policy is deliberately supplied by the receiver; accepting
/// the algorithm selected by an untrusted wrapper is not a security policy.
#[cfg(feature = "crypto")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignaturePolicy {
    /// Accept a classical Ed25519 signature only.
    Ed25519,
    /// Require the hybrid Ed25519 + ML-DSA signature.
    Dual,
    /// Accept any signature algorithm supported by this build.
    AnySupported,
}

#[cfg(feature = "crypto")]
impl SignaturePolicy {
    pub const fn accepts(self, algorithm: u8) -> bool {
        match self {
            Self::Ed25519 => algorithm == SigAlgorithm::ED25519,
            Self::Dual => algorithm == SigAlgorithm::DUAL,
            Self::AnySupported => matches!(
                algorithm,
                SigAlgorithm::ED25519 | SigAlgorithm::ML_DSA_65 | SigAlgorithm::DUAL
            ),
        }
    }
}

/// Receiver-side protection policy.  This is a struct so additional
/// authenticated-value requirements can be added without continually
/// changing every verification function signature.
#[cfg(feature = "crypto")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtectionPolicy {
    pub signature: SignaturePolicy,
}

#[cfg(feature = "crypto")]
impl Default for ProtectionPolicy {
    fn default() -> Self {
        // Boundary verification should not silently widen when a new
        // signature suite is compiled in. Callers that intentionally need
        // the historical permissive behavior must opt into
        // `ProtectionPolicy::any_supported()` explicitly.
        Self::ed25519()
    }
}

#[cfg(feature = "crypto")]
impl ProtectionPolicy {
    pub const fn ed25519() -> Self {
        Self {
            signature: SignaturePolicy::Ed25519,
        }
    }

    pub const fn dual() -> Self {
        Self {
            signature: SignaturePolicy::Dual,
        }
    }

    /// Explicit compatibility profile for callers that must accept every
    /// signature suite compiled into the current build.
    pub const fn any_supported() -> Self {
        Self {
            signature: SignaturePolicy::AnySupported,
        }
    }
}

#[cfg(feature = "crypto")]
impl From<SignaturePolicy> for ProtectionPolicy {
    fn from(signature: SignaturePolicy) -> Self {
        Self { signature }
    }
}

#[cfg(feature = "crypto")]
#[derive(Debug, thiserror::Error)]
pub enum ProtectionError {
    #[error("value is not encrypted")]
    NotEncrypted,
    #[error("value is not signed")]
    NotSigned,
    #[error("malformed protected value")]
    Malformed,
    #[error("no matching recipient")]
    NoMatchingRecipient,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("signature algorithm {actual} does not satisfy the receiver policy {expected:?}")]
    SignaturePolicyMismatch {
        expected: SignaturePolicy,
        actual: u8,
    },
    #[error("protection purpose mismatch: expected {expected}, got {actual}")]
    PurposeMismatch { expected: u8, actual: u8 },
    #[error("signer ID mismatch: expected {expected}, got {actual}")]
    SignerIdMismatch { expected: u64, actual: u64 },
    #[error("no verification key for signer ID {0}")]
    SignerKeyNotFound(u64),
    #[error("protected resource limit exceeded: {0}")]
    ResourceLimit(&'static str),
    #[error("codec error: {0}")]
    Codec(#[from] CodecError),
    #[error("crypto error: {0}")]
    Crypto(#[from] mtp_crypto::CryptoError),
}

#[cfg(feature = "crypto")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedValue {
    pub algorithm: u8,
    pub purpose: u8,
    pub signer_id: u64,
    pub signature: Vec<u8>,
    pub value: Box<DataValue>,
}

#[cfg(feature = "crypto")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedValue {
    pub encryption_type: EncryptionType,
    pub purpose: u8,
    pub recipients: Vec<RecipientEntry>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum DataValue {
    BoolTrue,
    BoolFalse,
    Bool(bool),
    SignedNumber(i128),
    UnsignedNumber(u128),
    Float(f64),
    Str(String),
    Bytes(Vec<u8>),
    Array(Vec<DataValue>),
    Container(Vec<(DataTypeId, DataValue)>),
    #[cfg(feature = "crypto")]
    Encrypted(EncryptedValue),
    #[cfg(feature = "crypto")]
    Signed(SignedValue),
    Null,
}

/// How a container merge handles a field present in both inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MergeConflictPolicy {
    /// Preserve the destination value.
    #[default]
    KeepLeft,
    /// Replace the destination value with the source value.
    KeepRight,
    /// Preserve the value only when both values are equal.
    ///
    /// When recursive container merging is enabled, overlapping containers are
    /// merged first and overlapping descendant values must be equal.
    RequireEqual,
    /// Reject overlapping non-container values.
    ///
    /// When recursive container merging is enabled, overlapping containers are
    /// merged first and overlaps reached inside those containers are rejected.
    Reject,
}

/// Options shared by frame and standalone container merging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MergeOptions {
    pub conflicts: MergeConflictPolicy,
    /// Merge child fields when both conflicting values are containers before
    /// applying the conflict policy to non-container overlaps.
    pub recursive_containers: bool,
}

/// A field location in a container merge report or conflict error.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MergePath {
    segments: Vec<DataTypeId>,
}

impl MergePath {
    pub fn new(segments: Vec<DataTypeId>) -> Self {
        Self { segments }
    }

    pub fn as_slice(&self) -> &[DataTypeId] {
        &self.segments
    }

    pub fn into_vec(self) -> Vec<DataTypeId> {
        self.segments
    }
}

/// Fields affected by a successful ordered container merge.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MergeReport {
    pub inserted: Vec<MergePath>,
    pub preserved: Vec<MergePath>,
    pub replaced: Vec<MergePath>,
    pub matched: Vec<MergePath>,
    /// Container overlaps for which recursive merging was entered.
    pub recursed: Vec<MergePath>,
}

/// Failure returned by a standalone container merge.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContainerMergeError {
    #[error("destination container contains duplicate field {0:?}")]
    DestinationDuplicateField(DataTypeId),
    #[error("source container contains duplicate field {0:?}")]
    SourceDuplicateField(DataTypeId),
    #[error("container contains structurally invalid data: {0}")]
    InvalidStructure(CodecError),
    #[error("conflicting field at {0:?}")]
    Conflict(MergePath),
}

impl DataValue {
    const KIND_BOOL_TRUE: u8 = 0x01;
    const KIND_BOOL_FALSE: u8 = 0x02;
    const KIND_SIGNED_NUMBER: u8 = 0x03;
    const KIND_UNSIGNED_NUMBER: u8 = 0x04;
    const KIND_FLOAT: u8 = 0x05;
    const KIND_STR: u8 = 0x06;
    const KIND_BYTES: u8 = 0x07;
    const KIND_ARRAY: u8 = 0x08;
    const KIND_CONTAINER: u8 = 0x09;
    #[cfg(feature = "crypto")]
    const KIND_ENCRYPTED: u8 = 0x0A;
    #[cfg(feature = "crypto")]
    const KIND_SIGNED: u8 = 0x0B;
    const KIND_NULL: u8 = 0xFF;

    /// Validate every structural invariant without allocating an encoded byte
    /// vector. This traverses arrays, containers, and signed inner values.
    pub fn validate_structure(&self) -> Result<(), CodecError> {
        self.validate_with_limits(EncodeLimits::default())
    }

    /// Validate structure and encoding resource limits without serializing.
    pub fn validate_with_limits(&self, limits: EncodeLimits) -> Result<(), CodecError> {
        let mut context = EncodeContext::new(limits);
        let size = self.encoded_len_with_context(&mut context)?;
        context.check_output(0, size)
    }

    pub fn container_from_map(map: &BTreeMap<DataTypeId, DataValue>) -> Self {
        Self::Container(map.iter().map(|(id, value)| (*id, value.clone())).collect())
    }

    pub fn kind(&self) -> DataKind {
        match self {
            Self::BoolTrue | Self::BoolFalse | Self::Bool(_) => DataKind::Bool,
            Self::SignedNumber(_) => DataKind::SignedNumber,
            Self::UnsignedNumber(_) => DataKind::UnsignedNumber,
            Self::Float(_) => DataKind::Float,
            Self::Str(_) => DataKind::Str,
            Self::Bytes(_) => DataKind::Bytes,
            Self::Array(_) => DataKind::Array,
            Self::Container(_) => DataKind::Container,
            #[cfg(feature = "crypto")]
            Self::Encrypted(_) => DataKind::Encrypted,
            #[cfg(feature = "crypto")]
            Self::Signed(_) => DataKind::Signed,
            Self::Null => DataKind::Null,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::BoolTrue => Some(true),
            Self::BoolFalse => Some(false),
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<String> {
        self.as_str().map(str::to_owned)
    }

    pub fn as_signed_number(&self) -> Option<i128> {
        match self {
            Self::SignedNumber(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_unsigned_number(&self) -> Option<u128> {
        match self {
            Self::UnsignedNumber(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_float(&self) -> Option<f64> {
        match self {
            Self::Float(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<Vec<DataValue>> {
        match self {
            Self::Array(value) => Some(value.clone()),
            _ => None,
        }
    }

    pub fn as_array_slice(&self) -> Option<&[DataValue]> {
        match self {
            Self::Array(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Self::Bytes(value) => Some(value.clone()),
            _ => None,
        }
    }

    pub fn as_bytes_slice(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_container(&self) -> Option<Vec<(DataTypeId, DataValue)>> {
        self.container_entries().map(<[_]>::to_vec)
    }

    pub fn container_entries(&self) -> Option<&[(DataTypeId, DataValue)]> {
        match self {
            Self::Container(entries) => Some(entries),
            _ => None,
        }
    }

    pub fn container_entries_mut(&mut self) -> Option<&mut Vec<(DataTypeId, DataValue)>> {
        match self {
            Self::Container(entries) => Some(entries),
            _ => None,
        }
    }

    pub fn as_container_map(&self) -> Option<BTreeMap<DataTypeId, DataValue>> {
        self.container_entries()
            .map(|entries| entries.iter().cloned().collect())
    }

    pub fn as_number(&self) -> Option<i128> {
        match self {
            Self::SignedNumber(value) => Some(*value),
            Self::UnsignedNumber(value) => i128::try_from(*value).ok(),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    pub fn is_truthy(&self) -> bool {
        match self {
            Self::BoolTrue | Self::Bool(true) => true,
            Self::BoolFalse | Self::Bool(false) | Self::Null => false,
            Self::SignedNumber(0) | Self::UnsignedNumber(0) => false,
            _ => true,
        }
    }

    pub fn get_field(&self, key: DataTypeId) -> Option<&DataValue> {
        match self {
            Self::Container(entries) => entries.iter().find(|(id, _)| *id == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<BTreeMap<DataTypeId, DataValue>> {
        self.as_container_map()
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Self::BoolTrue | Self::BoolFalse | Self::Bool(_) => "Bool",
            Self::SignedNumber(_) => "SignedNumber",
            Self::UnsignedNumber(_) => "UnsignedNumber",
            Self::Float(_) => "Float",
            Self::Str(_) => "Str",
            Self::Bytes(_) => "Bytes",
            Self::Array(_) => "Array",
            Self::Container(_) => "Container",
            #[cfg(feature = "crypto")]
            Self::Encrypted(_) => "Encrypted",
            #[cfg(feature = "crypto")]
            Self::Signed(_) => "Signed",
            Self::Null => "Null",
        }
    }

    #[cfg(feature = "crypto")]
    pub fn as_encrypted(&self) -> Option<&EncryptedValue> {
        match self {
            Self::Encrypted(value) => Some(value),
            _ => None,
        }
    }

    #[cfg(feature = "crypto")]
    pub fn as_signed(&self) -> Option<&SignedValue> {
        match self {
            Self::Signed(value) => Some(value),
            _ => None,
        }
    }

    #[cfg(feature = "crypto")]
    pub fn as_signed_mut(&mut self) -> Option<&mut SignedValue> {
        match self {
            Self::Signed(value) => Some(value),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataValueTypeMismatch {
    pub expected: &'static str,
    pub got: &'static str,
}

#[cfg(test)]
mod tests;
