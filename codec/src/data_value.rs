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

impl DecodeContext {
    fn new(limits: DecodeLimits) -> Self {
        Self {
            limits,
            depth: 0,
            values: 0,
            allocated_bytes: 0,
        }
    }

    fn allocate(&mut self, bytes: usize) -> Result<(), DecodeFailure> {
        self.allocated_bytes = self
            .allocated_bytes
            .checked_add(bytes)
            .ok_or(DecodeFailure::AllocationLimit)?;
        if self.allocated_bytes > self.limits.max_allocated_bytes {
            return Err(DecodeFailure::AllocationLimit);
        }
        Ok(())
    }

    fn value(&mut self) -> Result<(), DecodeFailure> {
        self.values = self
            .values
            .checked_add(1)
            .ok_or(DecodeFailure::ValueCountLimit)?;
        (self.values <= self.limits.max_values)
            .then_some(())
            .ok_or(DecodeFailure::ValueCountLimit)
    }

    fn enter(&mut self) -> Result<(), DecodeFailure> {
        self.depth = self.depth.checked_add(1).ok_or(DecodeFailure::DepthLimit)?;
        (self.depth <= self.limits.max_depth)
            .then_some(())
            .ok_or(DecodeFailure::DepthLimit)
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }
}

impl EncodeContext {
    fn new(limits: EncodeLimits) -> Self {
        Self {
            limits,
            depth: 0,
            values: 0,
        }
    }

    fn value(&mut self) -> Result<(), CodecError> {
        self.values = self
            .values
            .checked_add(1)
            .ok_or(CodecError::TooManyEntries)?;
        if self.values > self.limits.max_values {
            return Err(CodecError::TooManyEntries);
        }
        Ok(())
    }

    fn enter(&mut self) -> Result<(), CodecError> {
        self.depth = self
            .depth
            .checked_add(1)
            .ok_or(CodecError::TooManyEntries)?;
        if self.depth > self.limits.max_depth {
            return Err(CodecError::TooManyEntries);
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn check_output(&self, current: usize, additional: usize) -> Result<(), CodecError> {
        let next = current
            .checked_add(additional)
            .ok_or(CodecError::TooManyEntries)?;
        if next > self.limits.max_output_size {
            return Err(CodecError::TooManyEntries);
        }
        Ok(())
    }
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
    pub fn sign(
        self,
        signer_id: u64,
        purpose: ProtectionPurpose,
        signer: &(impl SignatureScheme + ?Sized),
    ) -> Result<Self, ProtectionError> {
        self.sign_with_limits(signer_id, purpose, signer, EncodeLimits::default())
    }

    /// Sign after bounding the recursive serialization used to construct the
    /// authenticated bytes.
    #[cfg(feature = "crypto")]
    pub fn sign_with_limits(
        self,
        signer_id: u64,
        purpose: ProtectionPurpose,
        signer: &(impl SignatureScheme + ?Sized),
        limits: EncodeLimits,
    ) -> Result<Self, ProtectionError> {
        let inner = self.to_bytes_with_limits(limits)?;
        let algorithm = signer.algorithm();
        let signing_bytes = signed_message(algorithm, purpose.0, signer_id, &inner);
        let signature = signer.sign(&signing_bytes)?;
        validate_signature(algorithm, &signature)?;
        Ok(Self::Signed(SignedValue {
            algorithm,
            purpose: purpose.0,
            signer_id,
            signature,
            value: Box::new(self),
        }))
    }

    #[cfg(feature = "crypto")]
    #[deprecated(note = "migrate to verify_with_policy with an explicit ProtectionPolicy")]
    /// Verify with the compatibility policy that accepts any supported suite.
    /// Protocol boundaries should prefer [`Self::verify_with_policy`].
    pub fn verify(
        &self,
        expected_signer_id: u64,
        public_keys: &PublicKeyBundle,
        expected_purpose: ProtectionPurpose,
    ) -> Result<(), ProtectionError> {
        self.verify_with_policy(
            expected_signer_id,
            public_keys,
            expected_purpose,
            ProtectionPolicy::any_supported(),
        )
    }

    #[cfg(feature = "crypto")]
    pub fn verify_with_policy(
        &self,
        expected_signer_id: u64,
        public_keys: &PublicKeyBundle,
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
    ) -> Result<(), ProtectionError> {
        match self {
            Self::Signed(value) => {
                value.verify_with_policy(expected_signer_id, public_keys, expected_purpose, policy)
            }
            _ => Err(ProtectionError::NotSigned),
        }
    }

    #[cfg(feature = "crypto")]
    #[deprecated(note = "migrate to verify_with_resolver_policy with an explicit ProtectionPolicy")]
    pub fn verify_with<F>(
        &self,
        resolve: F,
        expected_purpose: ProtectionPurpose,
    ) -> Result<(), ProtectionError>
    where
        F: FnOnce(u64) -> Option<PublicKeyBundle>,
    {
        self.verify_with_resolver_policy(
            resolve,
            expected_purpose,
            ProtectionPolicy::any_supported(),
        )
    }

    #[cfg(feature = "crypto")]
    pub fn verify_with_resolver_policy<F>(
        &self,
        resolve: F,
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
    ) -> Result<(), ProtectionError>
    where
        F: FnOnce(u64) -> Option<PublicKeyBundle>,
    {
        let signed = match self {
            Self::Signed(value) => value,
            _ => return Err(ProtectionError::NotSigned),
        };
        let signer_id = signed.signer_id;
        let public_keys =
            resolve(signer_id).ok_or(ProtectionError::SignerKeyNotFound(signer_id))?;
        signed.verify_with_policy(signer_id, &public_keys, expected_purpose, policy)
    }

    #[cfg(feature = "crypto")]
    #[deprecated(note = "migrate to into_verified_with_policy with an explicit ProtectionPolicy")]
    /// Consume a signed value using the compatibility policy that accepts any
    /// supported suite. Protocol boundaries should prefer the policy-aware
    /// counterpart.
    pub fn into_verified(
        self,
        expected_signer_id: u64,
        public_keys: &PublicKeyBundle,
        expected_purpose: ProtectionPurpose,
    ) -> Result<Self, ProtectionError> {
        self.into_verified_with_policy(
            expected_signer_id,
            public_keys,
            expected_purpose,
            ProtectionPolicy::any_supported(),
        )
    }

    #[cfg(feature = "crypto")]
    pub fn into_verified_with_policy(
        self,
        expected_signer_id: u64,
        public_keys: &PublicKeyBundle,
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
    ) -> Result<Self, ProtectionError> {
        match self {
            Self::Signed(value) => value.into_verified_with_policy(
                expected_signer_id,
                public_keys,
                expected_purpose,
                policy,
            ),
            _ => Err(ProtectionError::NotSigned),
        }
    }

    #[cfg(feature = "crypto")]
    pub fn encrypt_for(
        self,
        recipients: &[PublicKeyBundle],
        purpose: ProtectionPurpose,
    ) -> Result<Self, ProtectionError> {
        self.encrypt_for_with_limits(recipients, purpose, EncodeLimits::default())
    }

    /// Encrypt after bounding the recursive serialization of the plaintext.
    #[cfg(feature = "crypto")]
    pub fn encrypt_for_with_limits(
        self,
        recipients: &[PublicKeyBundle],
        purpose: ProtectionPurpose,
        limits: EncodeLimits,
    ) -> Result<Self, ProtectionError> {
        let plaintext = self.to_bytes_with_limits(limits)?;
        let message = mtp_crypto::encrypt_multi_for(
            EncryptionType::MlKemChaCha20Poly1305,
            purpose.0,
            &plaintext,
            recipients,
        )?;
        Ok(Self::Encrypted(EncryptedValue {
            encryption_type: message.encryption_type,
            purpose: purpose.0,
            recipients: message.recipients,
            ciphertext: message.ciphertext,
        }))
    }

    #[cfg(feature = "crypto")]
    pub fn decrypt(
        &self,
        keyring: &Keyring,
        expected_purpose: ProtectionPurpose,
    ) -> Result<Self, ProtectionError> {
        self.decrypt_with_limits(keyring, expected_purpose, DecodeLimits::default())
    }

    // Migrate to `decrypt_with_limits` or
    // `decrypt_with_keyrings_and_limits` at a protocol boundary so the
    // receive policy is not replaced by an intermediate default.
    #[deprecated(note = "migrate to decrypt_with_keyrings_and_limits with explicit DecodeLimits")]
    #[cfg(feature = "crypto")]
    pub fn decrypt_with_keyrings(
        &self,
        keyrings: &[&Keyring],
        expected_purpose: ProtectionPurpose,
    ) -> Result<Self, ProtectionError> {
        self.decrypt_with_keyrings_and_limits(keyrings, expected_purpose, DecodeLimits::default())
    }

    /// Try a local key history without exposing recipient-key identifiers on
    /// the wire, parsing each successful plaintext with the supplied policy.
    #[cfg(feature = "crypto")]
    pub fn decrypt_with_keyrings_and_limits(
        &self,
        keyrings: &[&Keyring],
        expected_purpose: ProtectionPurpose,
        limits: DecodeLimits,
    ) -> Result<Self, ProtectionError> {
        if keyrings.is_empty() {
            return Err(ProtectionError::NoMatchingRecipient);
        }
        let ciphertext_len = match self {
            Self::Encrypted(value) => value.ciphertext.len(),
            _ => return Err(ProtectionError::NotEncrypted),
        };
        let mut remaining_allocations = limits.max_allocated_bytes;
        for keyring in keyrings {
            if ciphertext_len > remaining_allocations {
                return Err(ProtectionError::ResourceLimit("decryption attempts"));
            }
            let attempt_limits = DecodeLimits {
                max_allocated_bytes: remaining_allocations,
                ..limits
            };
            match self.decrypt_with_limits(keyring, expected_purpose, attempt_limits) {
                Ok(value) => return Ok(value),
                Err(ProtectionError::NoMatchingRecipient) => {
                    /* A failed attempt may have allocated a plaintext buffer
                    as large as the ciphertext. Reserve that upper bound
                    before trying the next historical key. */
                    remaining_allocations -= ciphertext_len;
                }
                Err(error) => return Err(error),
            }
        }
        Err(ProtectionError::NoMatchingRecipient)
    }

    /// Decrypt an envelope and parse its plaintext with caller-supplied
    /// recursive/resource limits.
    #[cfg(feature = "crypto")]
    pub fn decrypt_with_limits(
        &self,
        keyring: &Keyring,
        expected_purpose: ProtectionPurpose,
        limits: DecodeLimits,
    ) -> Result<Self, ProtectionError> {
        let value = match self {
            Self::Encrypted(value) => value,
            _ => return Err(ProtectionError::NotEncrypted),
        };
        if value.ciphertext.len() > limits.max_allocated_bytes {
            return Err(ProtectionError::ResourceLimit("decrypted plaintext"));
        }
        let plaintext = mtp_crypto::decrypt_multi_for_parts_with_limit(
            value.encryption_type,
            value.purpose,
            &value.recipients,
            &value.ciphertext,
            expected_purpose.0,
            keyring,
            limits.max_allocated_bytes,
        )
        .map_err(protection_error_from_decryption)?;
        if plaintext.len() > limits.max_allocated_bytes {
            return Err(ProtectionError::ResourceLimit("decrypted plaintext"));
        }
        let mut decode_limits = limits;
        decode_limits.max_allocated_bytes -= plaintext.len();
        Self::try_from_bytes_with_limits(&plaintext, decode_limits).map_err(|error| match error {
            DecodeError::DepthLimit => ProtectionError::ResourceLimit("decrypted value depth"),
            DecodeError::ValueCountLimit => ProtectionError::ResourceLimit("decrypted value count"),
            DecodeError::BlobLimit => ProtectionError::ResourceLimit("decrypted blob"),
            DecodeError::AllocationLimit => {
                ProtectionError::ResourceLimit("decrypted value allocation")
            }
            DecodeError::RecipientLimit => ProtectionError::ResourceLimit("decrypted recipients"),
            DecodeError::MalformedEncoding | DecodeError::DuplicateField => {
                ProtectionError::Malformed
            }
        })
    }

    /// Encode with the compatibility resource policy.
    ///
    /// New protocol boundaries should pass an explicit [`EncodeLimits`] value
    /// derived from their admission policy.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CodecError> {
        self.to_bytes_with_limits(EncodeLimits::default())
    }

    pub fn to_bytes_with_limits(&self, limits: EncodeLimits) -> Result<Vec<u8>, CodecError> {
        let mut out = Vec::new();
        self.write_to_with_limits(&mut out, limits)?;
        Ok(out)
    }

    /// Encode into an existing output buffer while enforcing depth, node, and
    /// serialized-size limits before recursive output is produced.
    pub fn write_to(&self, out: &mut Vec<u8>) -> Result<(), CodecError> {
        self.write_to_with_limits(out, EncodeLimits::default())
    }

    pub fn write_to_with_limits(
        &self,
        out: &mut Vec<u8>,
        limits: EncodeLimits,
    ) -> Result<(), CodecError> {
        let mut sizing = EncodeContext::new(limits);
        let size = self.encoded_len_with_context(&mut sizing)?;
        sizing.check_output(out.len(), size)?;

        let mut context = EncodeContext::new(limits);
        self.write_to_with_context(out, &mut context)
    }

    fn encoded_len_with_context(&self, context: &mut EncodeContext) -> Result<usize, CodecError> {
        context.value()?;
        let size = match self {
            Self::BoolTrue | Self::BoolFalse | Self::Bool(_) | Self::Null => 1,
            Self::SignedNumber(_) | Self::UnsignedNumber(_) => 1 + 16,
            Self::Float(_) => 1 + 8,
            Self::Str(value) => checked_add(1, blob_len(value.as_bytes())?)?,
            Self::Bytes(value) => checked_add(1, blob_len(value)?)?,
            Self::Array(values) => {
                context.enter()?;
                let _ = checked_count(values.len())?;
                let mut size = 1 + 2;
                for value in values {
                    size = checked_add(size, value.encoded_len_with_context(context)?)?;
                }
                context.leave();
                size
            }
            Self::Container(entries) => {
                ensure_unique_container_fields(entries)?;
                context.enter()?;
                let _ = checked_count(entries.len())?;
                let mut size = 1 + 2;
                for (_, value) in entries {
                    size = checked_add(
                        checked_add(size, 2)?,
                        value.encoded_len_with_context(context)?,
                    )?;
                }
                context.leave();
                size
            }
            #[cfg(feature = "crypto")]
            Self::Signed(value) => {
                context.enter()?;
                let signature_len =
                    SigAlgorithm::length(value.algorithm).ok_or(CodecError::InvalidEncoding)?;
                if value.signature.len() != signature_len {
                    return Err(CodecError::InvalidEncoding);
                }
                let inner_len = value.value.encoded_len_with_context(context)?;
                context.leave();
                let wrapper_len = checked_add(1 + 1 + 8 + signature_len, inner_len)?;
                checked_add(1, checked_add(4, wrapper_len)?)?
            }
            #[cfg(feature = "crypto")]
            Self::Encrypted(value) => {
                let envelope_len = encrypted_envelope_len(value)?;
                checked_add(1, checked_add(4, envelope_len)?)?
            }
        };
        Ok(size)
    }

    fn write_to_with_context(
        &self,
        out: &mut Vec<u8>,
        context: &mut EncodeContext,
    ) -> Result<(), CodecError> {
        context.value()?;
        append_bytes(out, context, &[Self::kind_marker(self)])?;
        match self {
            Self::BoolTrue | Self::BoolFalse | Self::Bool(_) | Self::Null => {}
            Self::SignedNumber(value) => append_bytes(out, context, &value.to_be_bytes())?,
            Self::UnsignedNumber(value) => append_bytes(out, context, &value.to_be_bytes())?,
            Self::Float(value) => append_bytes(out, context, &value.to_bits().to_be_bytes())?,
            Self::Str(value) => write_blob_with_context(out, context, value.as_bytes())?,
            Self::Bytes(value) => write_blob_with_context(out, context, value)?,
            Self::Array(values) => {
                context.enter()?;
                append_bytes(out, context, &checked_count(values.len())?.to_be_bytes())?;
                for value in values {
                    value.write_to_with_context(out, context)?;
                }
                context.leave();
            }
            Self::Container(entries) => {
                ensure_unique_container_fields(entries)?;
                context.enter()?;
                append_bytes(out, context, &checked_count(entries.len())?.to_be_bytes())?;
                for (id, value) in entries {
                    append_bytes(out, context, &id.0.to_be_bytes())?;
                    value.write_to_with_context(out, context)?;
                }
                context.leave();
            }
            #[cfg(feature = "crypto")]
            Self::Signed(value) => {
                context.enter()?;
                let signature_len =
                    SigAlgorithm::length(value.algorithm).ok_or(CodecError::InvalidEncoding)?;
                if value.signature.len() != signature_len {
                    return Err(CodecError::InvalidEncoding);
                }
                let inner_len = value
                    .value
                    .encoded_len_with_context(&mut EncodeContext::new(context.limits))?;
                let wrapper_len = checked_add(1 + 1 + 8 + signature_len, inner_len)?;
                let wrapper_len =
                    u32::try_from(wrapper_len).map_err(|_| CodecError::InvalidEncoding)?;
                append_bytes(out, context, &wrapper_len.to_be_bytes())?;
                append_bytes(out, context, &[value.algorithm, value.purpose])?;
                append_bytes(out, context, &value.signer_id.to_be_bytes())?;
                append_bytes(out, context, &value.signature)?;
                value.value.write_to_with_context(out, context)?;
                context.leave();
            }
            #[cfg(feature = "crypto")]
            Self::Encrypted(value) => write_encrypted_with_context(out, context, value)?,
        }
        Ok(())
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Self::from_bytes_with_limits(bytes, DecodeLimits::default())
    }

    pub fn from_bytes_with_limits(bytes: &[u8], limits: DecodeLimits) -> Option<Self> {
        Self::try_from_bytes_with_limits(bytes, limits).ok()
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::try_from_bytes_with_limits(bytes, DecodeLimits::default())
    }

    pub fn try_from_bytes_with_limits(
        bytes: &[u8],
        limits: DecodeLimits,
    ) -> Result<Self, DecodeError> {
        let mut cursor = Cursor::new(bytes);
        let value = Self::read_from_with_diagnostics(&mut cursor, limits)?;
        if cursor.position() as usize != bytes.len() {
            return Err(DecodeError::MalformedEncoding);
        }
        Ok(value)
    }

    pub fn read_from(cursor: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Self::read_from_with_limits(cursor, DecodeLimits::default())
    }

    pub fn read_from_with_limits(
        cursor: &mut Cursor<&[u8]>,
        limits: DecodeLimits,
    ) -> Result<Self, CodecError> {
        Self::read_from_with_diagnostics(cursor, limits).map_err(|_| CodecError::InvalidEncoding)
    }

    pub fn read_from_with_diagnostics(
        cursor: &mut Cursor<&[u8]>,
        limits: DecodeLimits,
    ) -> Result<Self, DecodeError> {
        let mut context = DecodeContext::new(limits);
        Self::read_value(cursor, &mut context)
    }

    pub fn to_base64(&self) -> Result<String, CodecError> {
        Ok(general_purpose::STANDARD.encode(self.to_bytes()?))
    }

    pub fn from_base64(value: &str) -> Option<Self> {
        general_purpose::STANDARD
            .decode(value)
            .ok()
            .and_then(|bytes| Self::from_bytes(&bytes))
    }

    fn kind_marker(value: &Self) -> u8 {
        match value {
            Self::BoolTrue => Self::KIND_BOOL_TRUE,
            Self::BoolFalse => Self::KIND_BOOL_FALSE,
            Self::Bool(value) => {
                if *value {
                    Self::KIND_BOOL_TRUE
                } else {
                    Self::KIND_BOOL_FALSE
                }
            }
            Self::SignedNumber(_) => Self::KIND_SIGNED_NUMBER,
            Self::UnsignedNumber(_) => Self::KIND_UNSIGNED_NUMBER,
            Self::Float(_) => Self::KIND_FLOAT,
            Self::Str(_) => Self::KIND_STR,
            Self::Bytes(_) => Self::KIND_BYTES,
            Self::Array(_) => Self::KIND_ARRAY,
            Self::Container(_) => Self::KIND_CONTAINER,
            #[cfg(feature = "crypto")]
            Self::Encrypted(_) => Self::KIND_ENCRYPTED,
            #[cfg(feature = "crypto")]
            Self::Signed(_) => Self::KIND_SIGNED,
            Self::Null => Self::KIND_NULL,
        }
    }

    fn read_value(
        cursor: &mut Cursor<&[u8]>,
        context: &mut DecodeContext,
    ) -> Result<Self, DecodeFailure> {
        context.value()?;
        match cursor
            .read_u8()
            .map_err(|_| DecodeFailure::MalformedEncoding)?
        {
            Self::KIND_BOOL_TRUE => Ok(Self::BoolTrue),
            Self::KIND_BOOL_FALSE => Ok(Self::BoolFalse),
            Self::KIND_SIGNED_NUMBER => Ok(Self::SignedNumber(
                cursor
                    .read_i128::<BigEndian>()
                    .map_err(|_| DecodeFailure::MalformedEncoding)?,
            )),
            Self::KIND_UNSIGNED_NUMBER => Ok(Self::UnsignedNumber(
                cursor
                    .read_u128::<BigEndian>()
                    .map_err(|_| DecodeFailure::MalformedEncoding)?,
            )),
            Self::KIND_FLOAT => Ok(Self::Float(
                cursor
                    .read_f64::<BigEndian>()
                    .map_err(|_| DecodeFailure::MalformedEncoding)?,
            )),
            Self::KIND_STR => {
                let bytes = read_blob_owned(cursor, context)?;
                Ok(Self::Str(
                    String::from_utf8(bytes).map_err(|_| DecodeFailure::MalformedEncoding)?,
                ))
            }
            Self::KIND_BYTES => Ok(Self::Bytes(read_blob_owned(cursor, context)?)),
            Self::KIND_ARRAY => {
                context.enter()?;
                let count = cursor
                    .read_u16::<BigEndian>()
                    .map_err(|_| DecodeFailure::MalformedEncoding)?
                    as usize;
                context.allocate(
                    count
                        .checked_mul(size_of::<DataValue>())
                        .ok_or(DecodeFailure::AllocationLimit)?,
                )?;
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    values.push(Self::read_value(cursor, context)?);
                }
                context.leave();
                Ok(Self::Array(values))
            }
            Self::KIND_CONTAINER => {
                context.enter()?;
                let count = cursor
                    .read_u16::<BigEndian>()
                    .map_err(|_| DecodeFailure::MalformedEncoding)?
                    as usize;
                context.allocate(
                    count
                        .checked_mul(size_of::<(DataTypeId, DataValue)>())
                        .ok_or(DecodeFailure::AllocationLimit)?,
                )?;
                let mut values = Vec::with_capacity(count);
                /* DataTypeId is a u16, so a fixed bitset gives duplicate
                detection a predictable allocation instead of hidden
                per-node BTreeSet allocations. */
                let seen_words = (usize::from(u16::MAX) + 1) / 64;
                context.allocate(
                    seen_words
                        .checked_mul(size_of::<u64>())
                        .ok_or(DecodeFailure::AllocationLimit)?,
                )?;
                let mut seen = vec![0_u64; seen_words];
                for _ in 0..count {
                    let id = DataTypeId(
                        cursor
                            .read_u16::<BigEndian>()
                            .map_err(|_| DecodeFailure::MalformedEncoding)?,
                    );
                    let index = usize::from(id.0);
                    let word = index / 64;
                    let bit = 1_u64 << (index % 64);
                    if seen[word] & bit != 0 {
                        return Err(DecodeFailure::DuplicateField);
                    }
                    seen[word] |= bit;
                    values.push((id, Self::read_value(cursor, context)?));
                }
                context.leave();
                Ok(Self::Container(values))
            }
            #[cfg(feature = "crypto")]
            Self::KIND_SIGNED => {
                context.enter()?;
                let wrapper = read_blob_slice(cursor, context.limits.max_blob_size)?;
                let mut inner = Cursor::new(wrapper);
                let algorithm = inner
                    .read_u8()
                    .map_err(|_| DecodeFailure::MalformedEncoding)?;
                let purpose = inner
                    .read_u8()
                    .map_err(|_| DecodeFailure::MalformedEncoding)?;
                let signer_id = inner
                    .read_u64::<BigEndian>()
                    .map_err(|_| DecodeFailure::MalformedEncoding)?;
                let signature_len =
                    SigAlgorithm::length(algorithm).ok_or(DecodeFailure::MalformedEncoding)?;
                context.allocate(signature_len)?;
                let signature = read_slice(&mut inner, signature_len)
                    .ok_or(DecodeFailure::MalformedEncoding)?
                    .to_vec();
                let value = Self::read_value(&mut inner, context)?;
                if inner.position() as usize != wrapper.len() {
                    return Err(DecodeFailure::MalformedEncoding);
                }
                context.allocate(size_of::<DataValue>())?;
                context.leave();
                Ok(Self::Signed(SignedValue {
                    algorithm,
                    purpose,
                    signer_id,
                    signature,
                    value: Box::new(value),
                }))
            }
            #[cfg(feature = "crypto")]
            Self::KIND_ENCRYPTED => {
                let envelope = read_blob_slice(cursor, context.limits.max_blob_size)?;
                let message = mtp_crypto::MultiEncryptedMessageRef::from_bytes(envelope)
                    .map_err(|_| DecodeFailure::MalformedEncoding)?;
                if message.recipient_count() > context.limits.max_recipients {
                    return Err(DecodeFailure::RecipientLimit);
                }
                let kem_len = message.encryption_type().kem_ciphertext_len();
                let wrapped_len = message.encryption_type().wrapped_key_len();
                let entry_size = size_of::<mtp_crypto::RecipientEntry>()
                    .checked_add(kem_len)
                    .and_then(|size| size.checked_add(wrapped_len))
                    .ok_or(DecodeFailure::AllocationLimit)?;
                let owned_size = message
                    .recipient_count()
                    .checked_mul(entry_size)
                    .and_then(|size| size.checked_add(message.ciphertext().len()))
                    .ok_or(DecodeFailure::AllocationLimit)?;
                context.allocate(owned_size)?;
                let mut recipients = Vec::with_capacity(message.recipient_count());
                for index in 0..message.recipient_count() {
                    let (kem_ciphertext, encrypted_key) = message
                        .recipient(index)
                        .ok_or(DecodeFailure::MalformedEncoding)?;
                    recipients.push(mtp_crypto::RecipientEntry {
                        kem_ciphertext: kem_ciphertext.to_vec(),
                        encrypted_key: encrypted_key.to_vec(),
                    });
                }
                Ok(Self::Encrypted(EncryptedValue {
                    encryption_type: message.encryption_type(),
                    purpose: message.purpose(),
                    recipients,
                    ciphertext: message.ciphertext().to_vec(),
                }))
            }
            Self::KIND_NULL => Ok(Self::Null),
            // 0x0C was the old SignedEncryptedContainer kind and is reserved.
            _ => Err(DecodeFailure::MalformedEncoding),
        }
    }
}

#[cfg(feature = "crypto")]
impl SignedValue {
    #[deprecated(note = "migrate to verify_with_policy with an explicit ProtectionPolicy")]
    pub fn verify(
        &self,
        expected_signer_id: u64,
        public_keys: &PublicKeyBundle,
        expected_purpose: ProtectionPurpose,
    ) -> Result<(), ProtectionError> {
        self.verify_with_policy(
            expected_signer_id,
            public_keys,
            expected_purpose,
            ProtectionPolicy::any_supported(),
        )
    }

    pub fn verify_with_policy(
        &self,
        expected_signer_id: u64,
        public_keys: &PublicKeyBundle,
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
    ) -> Result<(), ProtectionError> {
        self.verify_with_policy_and_limits(
            expected_signer_id,
            public_keys,
            expected_purpose,
            policy,
            EncodeLimits::default(),
        )
    }

    /// Verify a signed value while bounding the serialization used to
    /// reconstruct its authenticated bytes.
    pub fn verify_with_policy_and_limits(
        &self,
        expected_signer_id: u64,
        public_keys: &PublicKeyBundle,
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
        limits: EncodeLimits,
    ) -> Result<(), ProtectionError> {
        if self.signer_id != expected_signer_id {
            return Err(ProtectionError::SignerIdMismatch {
                expected: expected_signer_id,
                actual: self.signer_id,
            });
        }
        if self.purpose != expected_purpose.0 {
            return Err(ProtectionError::PurposeMismatch {
                expected: expected_purpose.0,
                actual: self.purpose,
            });
        }
        if !policy.signature.accepts(self.algorithm) {
            return Err(ProtectionError::SignaturePolicyMismatch {
                expected: policy.signature,
                actual: self.algorithm,
            });
        }
        validate_signature(self.algorithm, &self.signature)?;
        let inner = self.value.to_bytes_with_limits(limits).map_err(|error| {
            if matches!(error, CodecError::TooManyEntries) {
                ProtectionError::ResourceLimit("signed value encoding")
            } else {
                ProtectionError::Codec(error)
            }
        })?;
        let message = signed_message(self.algorithm, self.purpose, self.signer_id, &inner);
        let result = match self.algorithm {
            SigAlgorithm::ED25519 => mtp_crypto::verify_ed25519(
                &public_keys.sig_cl_public_key,
                &message,
                &self.signature,
            ),
            SigAlgorithm::ML_DSA_65 => {
                mtp_crypto::verify_ml_dsa(&public_keys.sig_pq_public_key, &message, &self.signature)
            }
            SigAlgorithm::DUAL => {
                let ed_len = SigAlgorithm::length(SigAlgorithm::ED25519).unwrap();
                if self.signature.len()
                    != ed_len + SigAlgorithm::length(SigAlgorithm::ML_DSA_65).unwrap()
                {
                    return Err(ProtectionError::Malformed);
                }
                mtp_crypto::verify_ed25519(
                    &public_keys.sig_cl_public_key,
                    &message,
                    &self.signature[..ed_len],
                )
                .and_then(|_| {
                    mtp_crypto::verify_ml_dsa(
                        &public_keys.sig_pq_public_key,
                        &message,
                        &self.signature[ed_len..],
                    )
                })
            }
            _ => return Err(ProtectionError::Malformed),
        };
        result.map_err(|_| ProtectionError::InvalidSignature)
    }

    #[deprecated(note = "migrate to into_verified_with_policy with an explicit ProtectionPolicy")]
    /// Verify this signed wrapper and return its inner value.
    pub fn into_verified(
        self,
        expected_signer_id: u64,
        public_keys: &PublicKeyBundle,
        expected_purpose: ProtectionPurpose,
    ) -> Result<DataValue, ProtectionError> {
        self.into_verified_with_policy(
            expected_signer_id,
            public_keys,
            expected_purpose,
            ProtectionPolicy::any_supported(),
        )
    }

    /// Verify this signed wrapper with an explicit receiver policy and return
    /// its inner value.
    pub fn into_verified_with_policy(
        self,
        expected_signer_id: u64,
        public_keys: &PublicKeyBundle,
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
    ) -> Result<DataValue, ProtectionError> {
        self.verify_with_policy(expected_signer_id, public_keys, expected_purpose, policy)?;
        Ok(*self.value)
    }

    #[deprecated(note = "migrate to verify_with_resolver_policy with an explicit ProtectionPolicy")]
    pub fn verify_with<F>(
        &self,
        resolve: F,
        expected_purpose: ProtectionPurpose,
    ) -> Result<(), ProtectionError>
    where
        F: FnOnce(u64) -> Option<PublicKeyBundle>,
    {
        self.verify_with_resolver_policy(
            resolve,
            expected_purpose,
            ProtectionPolicy::any_supported(),
        )
    }

    pub fn verify_with_resolver_policy<F>(
        &self,
        resolve: F,
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
    ) -> Result<(), ProtectionError>
    where
        F: FnOnce(u64) -> Option<PublicKeyBundle>,
    {
        let public_keys =
            resolve(self.signer_id).ok_or(ProtectionError::SignerKeyNotFound(self.signer_id))?;
        self.verify_with_policy(self.signer_id, &public_keys, expected_purpose, policy)
    }

    /// Verify against a local signing-key history without exposing a key
    /// identifier in the signed wire value.  The first trusted key that
    /// verifies is accepted.
    pub fn verify_with_key_history(
        &self,
        expected_signer_id: u64,
        public_keys: &[PublicKeyBundle],
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
    ) -> Result<(), ProtectionError> {
        self.verify_with_key_history_index_and_limits(
            expected_signer_id,
            public_keys,
            expected_purpose,
            policy,
            EncodeLimits::default(),
        )
        .map(|_| ())
    }

    /// Verify against a signing-key history with a bounded authenticated-byte
    /// reconstruction policy.
    pub fn verify_with_key_history_and_limits(
        &self,
        expected_signer_id: u64,
        public_keys: &[PublicKeyBundle],
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
        limits: EncodeLimits,
    ) -> Result<(), ProtectionError> {
        self.verify_with_key_history_index_and_limits(
            expected_signer_id,
            public_keys,
            expected_purpose,
            policy,
            limits,
        )
        .map(|_| ())
    }

    /// Verify against a local signing-key history and return the index of the
    /// trusted key that authenticated the value.
    pub fn verify_with_key_history_index(
        &self,
        expected_signer_id: u64,
        public_keys: &[PublicKeyBundle],
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
    ) -> Result<usize, ProtectionError> {
        self.verify_with_key_history_index_and_limits(
            expected_signer_id,
            public_keys,
            expected_purpose,
            policy,
            EncodeLimits::default(),
        )
    }

    /// Verify against a signing-key history and bound every authenticated
    /// value serialization attempt.
    pub fn verify_with_key_history_index_and_limits(
        &self,
        expected_signer_id: u64,
        public_keys: &[PublicKeyBundle],
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
        limits: EncodeLimits,
    ) -> Result<usize, ProtectionError> {
        let mut last_error = None;
        for (index, public_key) in public_keys.iter().enumerate() {
            match self.verify_with_policy_and_limits(
                expected_signer_id,
                public_key,
                expected_purpose,
                policy,
                limits,
            ) {
                Ok(()) => return Ok(index),
                Err(error @ ProtectionError::InvalidSignature) => last_error = Some(error),
                Err(error @ ProtectionError::Crypto(_)) => last_error = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last_error.unwrap_or(ProtectionError::SignerKeyNotFound(expected_signer_id)))
    }
}

#[cfg(feature = "crypto")]
fn signed_message(algorithm: u8, purpose: u8, signer_id: u64, inner: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGN_DOMAIN.len() + 10 + inner.len());
    message.extend_from_slice(SIGN_DOMAIN);
    message.push(algorithm);
    message.push(purpose);
    message.extend_from_slice(&signer_id.to_be_bytes());
    message.extend_from_slice(inner);
    message
}

#[cfg(feature = "crypto")]
fn validate_signature(algorithm: u8, signature: &[u8]) -> Result<(), ProtectionError> {
    let expected = SigAlgorithm::length(algorithm).ok_or(ProtectionError::Malformed)?;
    if signature.len() == expected {
        Ok(())
    } else {
        Err(ProtectionError::Malformed)
    }
}

#[cfg(feature = "crypto")]
fn protection_error_from_decryption(error: mtp_crypto::CryptoError) -> ProtectionError {
    match error {
        mtp_crypto::CryptoError::MalformedEnvelope => ProtectionError::Malformed,
        mtp_crypto::CryptoError::NoMatchingRecipient => ProtectionError::NoMatchingRecipient,
        mtp_crypto::CryptoError::AllocationLimit => {
            ProtectionError::ResourceLimit("decrypted plaintext")
        }
        other => ProtectionError::Crypto(other),
    }
}

fn checked_count(count: usize) -> Result<u16, CodecError> {
    u16::try_from(count).map_err(|_| CodecError::TooManyEntries)
}

fn checked_add(left: usize, right: usize) -> Result<usize, CodecError> {
    left.checked_add(right).ok_or(CodecError::TooManyEntries)
}

fn blob_len(bytes: &[u8]) -> Result<usize, CodecError> {
    let _ = u32::try_from(bytes.len()).map_err(|_| CodecError::InvalidEncoding)?;
    checked_add(4, bytes.len())
}

fn append_bytes(
    out: &mut Vec<u8>,
    context: &EncodeContext,
    bytes: &[u8],
) -> Result<(), CodecError> {
    context.check_output(out.len(), bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn ensure_unique_container_fields(entries: &[(DataTypeId, DataValue)]) -> Result<(), CodecError> {
    let mut seen = BTreeSet::new();
    if entries.iter().all(|(id, _)| seen.insert(*id)) {
        Ok(())
    } else {
        Err(CodecError::InvalidEncoding)
    }
}

fn write_blob_with_context(
    out: &mut Vec<u8>,
    context: &EncodeContext,
    bytes: &[u8],
) -> Result<(), CodecError> {
    let len = u32::try_from(bytes.len()).map_err(|_| CodecError::InvalidEncoding)?;
    append_bytes(out, context, &len.to_be_bytes())?;
    append_bytes(out, context, bytes)
}

#[cfg(feature = "crypto")]
fn encrypted_envelope_len(value: &EncryptedValue) -> Result<usize, CodecError> {
    let kem_len = value.encryption_type.kem_ciphertext_len();
    let wrapped_len = value.encryption_type.wrapped_key_len();
    if value.recipients.is_empty()
        || value.recipients.len() > mtp_crypto::MAX_RECIPIENTS
        || value.ciphertext.len() < value.encryption_type.minimum_ciphertext_len()
        || value.recipients.iter().any(|recipient| {
            recipient.kem_ciphertext.len() != kem_len
                || recipient.encrypted_key.len() != wrapped_len
        })
    {
        return Err(CodecError::InvalidEncoding);
    }
    let _ = checked_count(value.recipients.len())?;
    let entry_len = kem_len
        .checked_add(wrapped_len)
        .ok_or(CodecError::TooManyEntries)?;
    let entries_len = value
        .recipients
        .len()
        .checked_mul(entry_len)
        .ok_or(CodecError::TooManyEntries)?;
    checked_add(4, checked_add(entries_len, value.ciphertext.len())?)
}

#[cfg(feature = "crypto")]
fn write_encrypted_with_context(
    out: &mut Vec<u8>,
    context: &EncodeContext,
    value: &EncryptedValue,
) -> Result<(), CodecError> {
    let envelope_len = encrypted_envelope_len(value)?;
    let envelope_len = u32::try_from(envelope_len).map_err(|_| CodecError::InvalidEncoding)?;
    append_bytes(out, context, &envelope_len.to_be_bytes())?;
    append_bytes(
        out,
        context,
        &[value.encryption_type.to_byte(), value.purpose],
    )?;
    let count = checked_count(value.recipients.len())?;
    append_bytes(out, context, &count.to_be_bytes())?;
    for recipient in &value.recipients {
        append_bytes(out, context, &recipient.kem_ciphertext)?;
        append_bytes(out, context, &recipient.encrypted_key)?;
    }
    append_bytes(out, context, &value.ciphertext)
}

fn read_blob_slice<'a>(
    cursor: &mut Cursor<&'a [u8]>,
    max_size: usize,
) -> Result<&'a [u8], DecodeFailure> {
    let len = cursor
        .read_u32::<BigEndian>()
        .map_err(|_| DecodeFailure::MalformedEncoding)? as usize;
    if len > max_size {
        return Err(DecodeFailure::BlobLimit);
    }
    read_slice(cursor, len).ok_or(DecodeFailure::MalformedEncoding)
}

fn read_blob_owned(
    cursor: &mut Cursor<&[u8]>,
    context: &mut DecodeContext,
) -> Result<Vec<u8>, DecodeFailure> {
    let bytes = read_blob_slice(cursor, context.limits.max_blob_size)?;
    context.allocate(bytes.len())?;
    Ok(bytes.to_vec())
}

fn read_slice<'a>(cursor: &mut Cursor<&'a [u8]>, len: usize) -> Option<&'a [u8]> {
    let start = cursor.position() as usize;
    let end = start.checked_add(len)?;
    if end > cursor.get_ref().len() {
        return None;
    }
    cursor.set_position(end as u64);
    Some(&cursor.get_ref()[start..end])
}

impl fmt::Display for DataValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoolTrue => f.write_str("true"),
            Self::BoolFalse => f.write_str("false"),
            Self::Bool(value) => write!(f, "{value}"),
            Self::SignedNumber(value) => write!(f, "{value}"),
            Self::UnsignedNumber(value) => write!(f, "{value}"),
            Self::Float(value) => write!(f, "{value}"),
            Self::Str(value) => write!(f, "\"{value}\""),
            Self::Bytes(_) => f.write_str("(Binary)"),
            Self::Array(values) => {
                f.write_str("[")?;
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{value}")?;
                }
                f.write_str("]")
            }
            Self::Container(entries) => {
                f.write_str("{")?;
                for (index, (id, value)) in entries.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{}: {value}", id.0)?;
                }
                f.write_str("}")
            }
            #[cfg(feature = "crypto")]
            Self::Encrypted(_) => f.write_str("(Encrypted)"),
            #[cfg(feature = "crypto")]
            Self::Signed(_) => f.write_str("(Signed)"),
            Self::Null => f.write_str("null"),
        }
    }
}

impl PartialEq for DataValue {
    fn eq(&self, other: &Self) -> bool {
        use DataValue::*;
        match (self, other) {
            (BoolTrue, BoolTrue)
            | (BoolFalse, BoolFalse)
            | (BoolTrue, Bool(true))
            | (Bool(true), BoolTrue)
            | (BoolFalse, Bool(false))
            | (Bool(false), BoolFalse) => true,
            (Bool(a), Bool(b)) => a == b,
            (SignedNumber(a), SignedNumber(b)) => a == b,
            (UnsignedNumber(a), UnsignedNumber(b)) => a == b,
            (Float(a), Float(b)) => a.to_bits() == b.to_bits(),
            (Str(a), Str(b)) => a == b,
            (Bytes(a), Bytes(b)) => a == b,
            (Array(a), Array(b)) => a == b,
            (Container(a), Container(b)) => a == b,
            #[cfg(feature = "crypto")]
            (Encrypted(a), Encrypted(b)) => a == b,
            #[cfg(feature = "crypto")]
            (Signed(a), Signed(b)) => a == b,
            (Null, Null) => true,
            _ => false,
        }
    }
}

impl Eq for DataValue {}

impl Hash for DataValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Self::kind_marker(self).hash(state);
        match self {
            Self::BoolTrue | Self::BoolFalse | Self::Bool(_) | Self::Null => {}
            Self::SignedNumber(value) => value.hash(state),
            Self::UnsignedNumber(value) => value.hash(state),
            Self::Float(value) => value.to_bits().hash(state),
            Self::Str(value) => value.hash(state),
            Self::Bytes(value) => value.hash(state),
            Self::Array(value) => value.hash(state),
            Self::Container(value) => value.hash(state),
            #[cfg(feature = "crypto")]
            Self::Encrypted(value) => value.to_bytes().hash(state),
            #[cfg(feature = "crypto")]
            Self::Signed(value) => value.to_bytes().hash(state),
        }
    }
}

#[cfg(feature = "crypto")]
impl EncryptedValue {
    fn to_bytes(&self) -> Vec<u8> {
        mtp_crypto::MultiEncryptedMessage {
            encryption_type: self.encryption_type,
            purpose: self.purpose,
            recipients: self.recipients.clone(),
            ciphertext: self.ciphertext.clone(),
        }
        .to_bytes()
        .unwrap_or_default()
    }
}

#[cfg(feature = "crypto")]
impl SignedValue {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.algorithm);
        out.push(self.purpose);
        out.extend_from_slice(&self.signer_id.to_be_bytes());
        out.extend_from_slice(&self.signature);
        let _ = self.value.write_to(&mut out);
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataValueTypeMismatch {
    pub expected: &'static str,
    pub got: &'static str,
}

impl fmt::Display for DataValueTypeMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "expected {}, got {}", self.expected, self.got)
    }
}

impl std::error::Error for DataValueTypeMismatch {}

impl From<bool> for DataValue {
    fn from(value: bool) -> Self {
        if value {
            Self::BoolTrue
        } else {
            Self::BoolFalse
        }
    }
}

impl From<&str> for DataValue {
    fn from(value: &str) -> Self {
        Self::Str(value.to_owned())
    }
}

impl From<String> for DataValue {
    fn from(value: String) -> Self {
        Self::Str(value)
    }
}

impl From<i64> for DataValue {
    fn from(value: i64) -> Self {
        Self::SignedNumber(value as i128)
    }
}

impl From<i128> for DataValue {
    fn from(value: i128) -> Self {
        Self::SignedNumber(value)
    }
}

impl From<u64> for DataValue {
    fn from(value: u64) -> Self {
        Self::UnsignedNumber(value as u128)
    }
}

impl From<u128> for DataValue {
    fn from(value: u128) -> Self {
        Self::UnsignedNumber(value)
    }
}

impl From<Vec<u8>> for DataValue {
    fn from(value: Vec<u8>) -> Self {
        Self::Bytes(value)
    }
}

impl From<&[u8]> for DataValue {
    fn from(value: &[u8]) -> Self {
        Self::Bytes(value.to_vec())
    }
}

impl TryFrom<DataValue> for bool {
    type Error = DataValueTypeMismatch;
    fn try_from(value: DataValue) -> Result<Self, Self::Error> {
        value.as_bool().ok_or(DataValueTypeMismatch {
            expected: "Bool",
            got: value.type_name(),
        })
    }
}

impl TryFrom<DataValue> for String {
    type Error = DataValueTypeMismatch;
    fn try_from(value: DataValue) -> Result<Self, Self::Error> {
        match value {
            DataValue::Str(value) => Ok(value),
            other => Err(DataValueTypeMismatch {
                expected: "Str",
                got: other.type_name(),
            }),
        }
    }
}

impl TryFrom<DataValue> for i128 {
    type Error = DataValueTypeMismatch;
    fn try_from(value: DataValue) -> Result<Self, Self::Error> {
        value.as_signed_number().ok_or(DataValueTypeMismatch {
            expected: "SignedNumber",
            got: value.type_name(),
        })
    }
}

impl TryFrom<DataValue> for i64 {
    type Error = DataValueTypeMismatch;
    fn try_from(value: DataValue) -> Result<Self, Self::Error> {
        let value = i128::try_from(value)?;
        i64::try_from(value).map_err(|_| DataValueTypeMismatch {
            expected: "i64",
            got: "SignedNumber",
        })
    }
}

impl TryFrom<DataValue> for u128 {
    type Error = DataValueTypeMismatch;
    fn try_from(value: DataValue) -> Result<Self, Self::Error> {
        value.as_unsigned_number().ok_or(DataValueTypeMismatch {
            expected: "UnsignedNumber",
            got: value.type_name(),
        })
    }
}

impl TryFrom<DataValue> for u64 {
    type Error = DataValueTypeMismatch;
    fn try_from(value: DataValue) -> Result<Self, Self::Error> {
        let value = u128::try_from(value)?;
        u64::try_from(value).map_err(|_| DataValueTypeMismatch {
            expected: "u64",
            got: "UnsignedNumber",
        })
    }
}

impl TryFrom<DataValue> for Vec<u8> {
    type Error = DataValueTypeMismatch;
    fn try_from(value: DataValue) -> Result<Self, Self::Error> {
        match value {
            DataValue::Bytes(value) => Ok(value),
            other => Err(DataValueTypeMismatch {
                expected: "Bytes",
                got: other.type_name(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_data_value_vectors() {
        let vectors = [
            (DataValue::BoolTrue, vec![0x01]),
            (DataValue::BoolFalse, vec![0x02]),
            (
                DataValue::Str("Hello".into()),
                vec![0x06, 0, 0, 0, 5, b'H', b'e', b'l', b'l', b'o'],
            ),
            (DataValue::Bytes(vec![1, 2]), vec![0x07, 0, 0, 0, 2, 1, 2]),
            (
                DataValue::Array(vec![
                    DataValue::BoolTrue,
                    DataValue::Str("A".into()),
                    DataValue::Bytes(vec![0xFF]),
                ]),
                vec![
                    0x08, 0, 3,    // array kind and value count
                    0x01, // true
                    0x06, 0, 0, 0, 1, b'A', // string
                    0x07, 0, 0, 0, 1, 0xFF, // bytes
                ],
            ),
            (
                DataValue::Container(vec![
                    (DataTypeId(9), DataValue::Str("Hello".into())),
                    (DataTypeId(10), DataValue::BoolTrue),
                ]),
                vec![
                    0x09, 0, 2, // container kind and entry count
                    0, 9, // field ID
                    0x06, 0, 0, 0, 5, b'H', b'e', b'l', b'l', b'o', // string
                    0, 10,   // field ID
                    0x01, // true has no payload or entry length
                ],
            ),
        ];

        for (value, expected) in vectors {
            assert_eq!(value.to_bytes().unwrap(), expected);
            assert_eq!(DataValue::from_bytes(&expected), Some(value));
        }
    }

    #[test]
    fn decode_limits_bound_recursive_values_and_blobs() {
        let nested = DataValue::Array(vec![DataValue::Array(vec![DataValue::BoolTrue])]);
        let bytes = nested.to_bytes().expect("nested value should encode");
        let mut limits = DecodeLimits {
            max_depth: 1,
            ..DecodeLimits::default()
        };
        assert!(DataValue::from_bytes_with_limits(&bytes, limits).is_none());

        let many = DataValue::Array(vec![DataValue::BoolTrue, DataValue::BoolFalse]);
        let bytes = many.to_bytes().expect("array should encode");
        limits = DecodeLimits::default();
        limits.max_values = 2;
        assert!(DataValue::from_bytes_with_limits(&bytes, limits).is_none());

        let blob = DataValue::Bytes(vec![1, 2, 3]);
        let bytes = blob.to_bytes().expect("blob should encode");
        limits = DecodeLimits::default();
        limits.max_blob_size = 2;
        assert!(DataValue::from_bytes_with_limits(&bytes, limits).is_none());
    }

    #[test]
    fn decoder_diagnostics_distinguish_policy_rejections() {
        let nested = DataValue::Array(vec![DataValue::Array(vec![DataValue::BoolTrue])]);
        let nested_bytes = nested.to_bytes().expect("nested value should encode");
        let mut limits = DecodeLimits {
            max_depth: 1,
            ..DecodeLimits::default()
        };
        let mut cursor = Cursor::new(nested_bytes.as_slice());
        assert_eq!(
            DataValue::read_from_with_diagnostics(&mut cursor, limits),
            Err(DecodeFailure::DepthLimit)
        );

        let many = DataValue::Array(vec![DataValue::BoolTrue, DataValue::BoolFalse]);
        let many_bytes = many.to_bytes().expect("array should encode");
        limits = DecodeLimits {
            max_values: 2,
            ..DecodeLimits::default()
        };
        let mut cursor = Cursor::new(many_bytes.as_slice());
        assert_eq!(
            DataValue::read_from_with_diagnostics(&mut cursor, limits),
            Err(DecodeFailure::ValueCountLimit)
        );

        let allocation_blob = DataValue::Bytes(vec![1, 2, 3]);
        let allocation_blob_bytes = allocation_blob.to_bytes().expect("blob should encode");
        limits = DecodeLimits {
            max_blob_size: 2,
            ..DecodeLimits::default()
        };
        let mut cursor = Cursor::new(allocation_blob_bytes.as_slice());
        assert_eq!(
            DataValue::read_from_with_diagnostics(&mut cursor, limits),
            Err(DecodeFailure::BlobLimit)
        );

        let duplicate = [0x09, 0, 2, 0, 1, 0x01, 0, 1, 0x02];
        let mut cursor = Cursor::new(duplicate.as_slice());
        assert_eq!(
            DataValue::read_from_with_diagnostics(&mut cursor, DecodeLimits::default()),
            Err(DecodeFailure::DuplicateField)
        );

        let mut cursor = Cursor::new([0xFE].as_slice());
        assert_eq!(
            DataValue::read_from_with_diagnostics(&mut cursor, DecodeLimits::default()),
            Err(DecodeFailure::MalformedEncoding)
        );

        let blob = DataValue::Bytes(vec![1, 2, 3]);
        let blob_bytes = blob.to_bytes().expect("blob should encode");
        let limits = DecodeLimits {
            max_allocated_bytes: 2,
            ..DecodeLimits::default()
        };
        let mut cursor = Cursor::new(blob_bytes.as_slice());
        assert_eq!(
            DataValue::read_from_with_diagnostics(&mut cursor, limits),
            Err(DecodeFailure::AllocationLimit)
        );
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn nested_signed_values_hit_cumulative_allocation_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        use mtp_crypto::Ed25519Signer;

        let (signer, _, _) = Ed25519Signer::generate();
        let mut value = DataValue::Null;
        for _ in 0..3 {
            value = value.sign(7, ProtectionPurpose::from(1), &signer)?;
        }
        let bytes = value.to_bytes()?;
        let limits = DecodeLimits {
            max_allocated_bytes: 100,
            ..DecodeLimits::default()
        };
        let mut cursor = Cursor::new(bytes.as_slice());

        assert_eq!(
            DataValue::read_from_with_diagnostics(&mut cursor, limits),
            Err(DecodeFailure::AllocationLimit)
        );
        Ok(())
    }

    #[test]
    fn encoder_limits_bound_nodes_depth_and_output() {
        let value = DataValue::Array(vec![DataValue::BoolTrue]);

        let limits = EncodeLimits {
            max_values: 1,
            ..EncodeLimits::default()
        };
        assert_eq!(
            value.to_bytes_with_limits(limits),
            Err(CodecError::TooManyEntries)
        );

        let limits = EncodeLimits {
            max_depth: 0,
            ..EncodeLimits::default()
        };
        assert_eq!(
            value.to_bytes_with_limits(limits),
            Err(CodecError::TooManyEntries)
        );

        let limits = EncodeLimits {
            max_output_size: 1,
            ..EncodeLimits::default()
        };
        assert_eq!(
            value.to_bytes_with_limits(limits),
            Err(CodecError::TooManyEntries)
        );
    }

    #[test]
    fn transport_decode_limits_follow_admitted_frame_size() {
        let limits = DecodeLimits::for_transport_message_size(1024);
        assert_eq!(limits.max_blob_size, 1020);
        assert_eq!(
            limits.max_allocated_bytes,
            1024 * DEFAULT_TRANSPORT_ALLOCATION_FACTOR as usize
        );
        assert_eq!(limits.max_depth, DecodeLimits::default().max_depth);
        assert_eq!(
            limits.max_recipients,
            DecodeLimits::default().max_recipients
        );

        let custom = DecodeLimits::for_transport_message_size_with_allocation_factor(1024, 2);
        assert_eq!(custom.max_allocated_bytes, 2048);
    }

    #[test]
    fn decoder_allocation_budget_counts_utf8_bytes_and_capacity() {
        let value = DataValue::Str("é".into());
        let bytes = value.to_bytes().expect("string should encode");

        let mut limits = DecodeLimits {
            max_allocated_bytes: 1,
            ..DecodeLimits::default()
        };
        let mut cursor = Cursor::new(bytes.as_slice());
        assert_eq!(
            DataValue::read_from_with_diagnostics(&mut cursor, limits),
            Err(DecodeFailure::AllocationLimit)
        );

        limits.max_allocated_bytes = "é".len();
        assert_eq!(
            DataValue::try_from_bytes_with_limits(&bytes, limits),
            Ok(value)
        );

        let array = DataValue::Array(vec![DataValue::BoolTrue]);
        let array_bytes = array.to_bytes().expect("array should encode");
        limits.max_allocated_bytes = size_of::<DataValue>() - 1;
        let mut cursor = Cursor::new(array_bytes.as_slice());
        assert_eq!(
            DataValue::read_from_with_diagnostics(&mut cursor, limits),
            Err(DecodeFailure::AllocationLimit)
        );
    }

    #[test]
    fn integer_conversions_reject_narrowing_overflow() {
        assert!(i64::try_from(DataValue::SignedNumber(i64::MAX as i128 + 1)).is_err());
        assert!(i64::try_from(DataValue::SignedNumber(i64::MIN as i128 - 1)).is_err());
        assert!(u64::try_from(DataValue::UnsignedNumber(u64::MAX as u128 + 1)).is_err());
    }

    #[test]
    fn duplicate_container_fields_are_rejected() {
        let bytes = [0x09, 0, 2, 0, 1, 0x01, 0, 1, 0x02];
        assert!(DataValue::from_bytes(&bytes).is_none());

        let value = DataValue::Container(vec![
            (DataTypeId(1), DataValue::BoolTrue),
            (DataTypeId(1), DataValue::BoolFalse),
        ]);
        assert_eq!(value.to_bytes(), Err(CodecError::InvalidEncoding));
    }

    #[test]
    fn read_from_stops_at_each_self_delimiting_value() {
        let bytes = [0x01, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42];
        let mut cursor = Cursor::new(bytes.as_slice());

        assert_eq!(
            DataValue::read_from(&mut cursor).unwrap(),
            DataValue::BoolTrue
        );
        assert_eq!(
            DataValue::read_from(&mut cursor).unwrap(),
            DataValue::SignedNumber(42)
        );
        assert_eq!(cursor.position() as usize, bytes.len());
    }

    #[test]
    fn removed_signed_encrypted_container_kind_is_rejected() {
        assert_eq!(DataValue::from_bytes(&[0x0C]), None);
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn signed_values_have_canonical_layout_and_verify() -> Result<(), Box<dyn std::error::Error>> {
        use mtp_crypto::{Ed25519Signer, Keyring, SigAlgorithm};

        let (signer, _, signer_public) = Ed25519Signer::generate();
        let mut public_keys = Keyring::generate().public_key_bundle();
        public_keys.sig_cl_public_key = signer_public;

        let original = DataValue::Container(vec![
            (DataTypeId(20), DataValue::BoolTrue),
            (DataTypeId(21), DataValue::Str("signed".into())),
        ]);
        let inner = original.to_bytes()?;
        let signed = original.clone().sign(
            0x0102_0304_0506_0708,
            ProtectionPurpose::from(0xA5),
            &signer,
        )?;
        let encoded = signed.to_bytes()?;

        let wrapper_len = u32::from_be_bytes(encoded[1..5].try_into()?) as usize;
        let signature_len = SigAlgorithm::length(SigAlgorithm::ED25519).unwrap();
        assert_eq!(encoded[0], DataValue::KIND_SIGNED);
        assert_eq!(wrapper_len, encoded.len() - 5);
        assert_eq!(encoded[5], SigAlgorithm::ED25519);
        assert_eq!(encoded[6], 0xA5);
        assert_eq!(&encoded[7..15], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&encoded[15 + signature_len..], inner);

        let decoded = DataValue::from_bytes(&encoded).ok_or("signed value did not decode")?;
        decoded.verify_with_policy(
            0x0102_0304_0506_0708,
            &public_keys,
            ProtectionPurpose::from(0xA5),
            ProtectionPolicy::any_supported(),
        )?;
        assert!(matches!(
            decoded.clone().into_verified_with_policy(
                0x0102_0304_0506_0708,
                &public_keys,
                ProtectionPurpose::from(0xA5),
                ProtectionPolicy::from(SignaturePolicy::Dual),
            ),
            Err(ProtectionError::SignaturePolicyMismatch { .. })
        ));
        // Verification is non-consuming, so it can safely be repeated.
        decoded.verify_with_policy(
            0x0102_0304_0506_0708,
            &public_keys,
            ProtectionPurpose::from(0xA5),
            ProtectionPolicy::any_supported(),
        )?;
        assert_eq!(
            decoded.clone().into_verified_with_policy(
                0x0102_0304_0506_0708,
                &public_keys,
                ProtectionPurpose::from(0xA5),
                ProtectionPolicy::any_supported(),
            )?,
            original
        );

        let DataValue::Signed(wrapper) = decoded else {
            return Err("expected signed value".into());
        };
        assert_eq!(
            wrapper.into_verified_with_policy(
                0x0102_0304_0506_0708,
                &public_keys,
                ProtectionPurpose::from(0xA5),
                ProtectionPolicy::any_supported(),
            )?,
            original
        );
        Ok(())
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn reordered_containers_have_distinct_signed_bytes() -> Result<(), Box<dyn std::error::Error>> {
        use mtp_crypto::Ed25519Signer;

        let (signer, _, _) = Ed25519Signer::generate();
        let first = DataValue::Container(vec![
            (DataTypeId(1), DataValue::BoolTrue),
            (DataTypeId(2), DataValue::BoolFalse),
        ])
        .sign(1, ProtectionPurpose::from(7), &signer)?;
        let second = DataValue::Container(vec![
            (DataTypeId(2), DataValue::BoolFalse),
            (DataTypeId(1), DataValue::BoolTrue),
        ])
        .sign(1, ProtectionPurpose::from(7), &signer)?;

        assert_ne!(first.to_bytes()?, second.to_bytes()?);
        Ok(())
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn encrypted_decode_limits_bound_owned_entries() -> Result<(), Box<dyn std::error::Error>> {
        use mtp_crypto::Keyring;

        let keyring = Keyring::generate();
        let encrypted = DataValue::Bytes(vec![0xAB; 32]).encrypt_for(
            std::slice::from_ref(&keyring.public_key_bundle()),
            ProtectionPurpose::from(9),
        )?;
        let bytes = encrypted.to_bytes()?;
        let mut limits = DecodeLimits {
            max_allocated_bytes: 1,
            ..DecodeLimits::default()
        };
        let mut cursor = Cursor::new(bytes.as_slice());
        assert_eq!(
            DataValue::read_from_with_diagnostics(&mut cursor, limits),
            Err(DecodeFailure::AllocationLimit)
        );

        limits.max_allocated_bytes = usize::MAX;
        limits.max_recipients = 0;
        let mut cursor = Cursor::new(bytes.as_slice());
        assert_eq!(
            DataValue::read_from_with_diagnostics(&mut cursor, limits),
            Err(DecodeFailure::RecipientLimit)
        );
        Ok(())
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn signed_value_authenticates_its_metadata_and_inner_value()
    -> Result<(), Box<dyn std::error::Error>> {
        use mtp_crypto::{Ed25519Signer, Keyring};

        let (signer, _, signer_public) = Ed25519Signer::generate();
        let mut public_keys = Keyring::generate().public_key_bundle();
        public_keys.sig_cl_public_key = signer_public;
        let signed =
            DataValue::Str("original".into()).sign(41, ProtectionPurpose::from(7), &signer)?;

        let DataValue::Signed(mut wrong_purpose) = signed.clone() else {
            return Err("expected signed value".into());
        };
        wrong_purpose.purpose ^= 1;
        assert!(matches!(
            wrong_purpose.verify_with_policy(
                41,
                &public_keys,
                ProtectionPurpose::from(7),
                ProtectionPolicy::any_supported(),
            ),
            Err(ProtectionError::PurposeMismatch { .. })
        ));

        let DataValue::Signed(mut wrong_signer_id) = signed.clone() else {
            return Err("expected signed value".into());
        };
        wrong_signer_id.signer_id ^= 1;
        assert!(matches!(
            wrong_signer_id.verify_with_policy(
                41,
                &public_keys,
                ProtectionPurpose::from(7),
                ProtectionPolicy::any_supported(),
            ),
            Err(ProtectionError::SignerIdMismatch { .. })
        ));

        let DataValue::Signed(mut wrong_signature) = signed.clone() else {
            return Err("expected signed value".into());
        };
        wrong_signature.signature[0] ^= 1;
        assert!(matches!(
            wrong_signature.verify_with_policy(
                41,
                &public_keys,
                ProtectionPurpose::from(7),
                ProtectionPolicy::any_supported(),
            ),
            Err(ProtectionError::InvalidSignature)
        ));

        let DataValue::Signed(mut wrong_value) = signed else {
            return Err("expected signed value".into());
        };
        *wrong_value.value = DataValue::Str("replacement".into());
        assert!(matches!(
            wrong_value.verify_with_policy(
                41,
                &public_keys,
                ProtectionPurpose::from(7),
                ProtectionPolicy::any_supported(),
            ),
            Err(ProtectionError::InvalidSignature)
        ));
        Ok(())
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn signing_rejects_an_unknown_algorithm_or_wrong_signature_size() {
        use mtp_crypto::{CryptoError, SigAlgorithm, SignatureScheme};

        struct InvalidSigner(u8);

        impl SignatureScheme for InvalidSigner {
            fn algorithm(&self) -> u8 {
                self.0
            }

            fn sign(&self, _: &[u8]) -> Result<Vec<u8>, CryptoError> {
                Ok(vec![0; 63])
            }

            fn verify(&self, _: &[u8], _: &[u8]) -> Result<(), CryptoError> {
                Ok(())
            }
        }

        assert!(matches!(
            DataValue::Null.sign(
                1,
                ProtectionPurpose::from(1),
                &InvalidSigner(SigAlgorithm::ED25519)
            ),
            Err(ProtectionError::Malformed)
        ));
        assert!(matches!(
            DataValue::Null.sign(1, ProtectionPurpose::from(1), &InvalidSigner(0xFE)),
            Err(ProtectionError::Malformed)
        ));
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn signed_then_encrypted_composition_roundtrips() -> Result<(), Box<dyn std::error::Error>> {
        use mtp_crypto::{Ed25519Signer, Keyring};

        let (signer, _, signer_public) = Ed25519Signer::generate();
        let keyring = Keyring::generate();
        let value = DataValue::Container(vec![(DataTypeId(32), DataValue::Str("secret".into()))]);
        let protected = value
            .clone()
            .sign(7, ProtectionPurpose::from(1), &signer)?
            .encrypt_for(
                std::slice::from_ref(&keyring.public_key_bundle()),
                ProtectionPurpose::from(2),
            )?;

        let encoded = protected.to_bytes()?;
        assert_eq!(encoded[0], DataValue::KIND_ENCRYPTED);
        let decoded = DataValue::from_bytes(&encoded).ok_or("protected value did not decode")?;
        let opened = decoded.decrypt(&keyring, ProtectionPurpose::from(2))?;
        let mut public_keys = keyring.public_key_bundle();
        public_keys.sig_cl_public_key = signer_public;
        opened.verify_with_policy(
            7,
            &public_keys,
            ProtectionPurpose::from(1),
            ProtectionPolicy::any_supported(),
        )?;
        assert_eq!(
            opened.into_verified_with_policy(
                7,
                &public_keys,
                ProtectionPurpose::from(1),
                ProtectionPolicy::any_supported(),
            )?,
            value
        );
        Ok(())
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn encrypted_then_signed_composition_roundtrips_and_exposes_signer()
    -> Result<(), Box<dyn std::error::Error>> {
        use mtp_crypto::{Ed25519Signer, Keyring};

        let (signer, _, signer_public) = Ed25519Signer::generate();
        let keyring = Keyring::generate();
        let value = DataValue::Container(vec![(DataTypeId(32), DataValue::Str("secret".into()))]);
        let protected = value
            .clone()
            .encrypt_for(
                std::slice::from_ref(&keyring.public_key_bundle()),
                ProtectionPurpose::from(2),
            )?
            .sign(7, ProtectionPurpose::from(1), &signer)?;

        let encoded = protected.to_bytes()?;
        assert_eq!(encoded[0], DataValue::KIND_SIGNED);
        let decoded = DataValue::from_bytes(&encoded).ok_or("protected value did not decode")?;
        let mut public_keys = keyring.public_key_bundle();
        public_keys.sig_cl_public_key = signer_public;

        // The signer metadata is available before opening the encrypted value.
        let DataValue::Signed(signed) = decoded else {
            return Err("expected signed outer wrapper".into());
        };
        assert_eq!(signed.signer_id, 7);
        signed.verify_with_policy(
            7,
            &public_keys,
            ProtectionPurpose::from(1),
            ProtectionPolicy::any_supported(),
        )?;
        let encrypted = signed.into_verified_with_policy(
            7,
            &public_keys,
            ProtectionPurpose::from(1),
            ProtectionPolicy::any_supported(),
        )?;
        assert!(matches!(encrypted, DataValue::Encrypted(_)));
        assert_eq!(
            encrypted.decrypt(&keyring, ProtectionPurpose::from(2))?,
            value
        );
        Ok(())
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn deeply_nested_protection_composition_roundtrips() -> Result<(), Box<dyn std::error::Error>> {
        use mtp_crypto::{Ed25519Signer, Keyring};

        const OUTER_SIGNER_ID: u64 = 0x0102_0304_0506_0708;
        const INNER_SIGNER_ID: u64 = 0x1112_1314_1516_1718;

        let (signer, _, signer_public) = Ed25519Signer::generate();
        let outer_recipient = Keyring::generate();
        let inner_recipient = Keyring::generate();
        let leaf =
            DataValue::Container(vec![(DataTypeId(60), DataValue::Str("deep secret".into()))]);
        let nested = leaf
            .clone()
            .sign(INNER_SIGNER_ID, ProtectionPurpose::from(3), &signer)?
            .encrypt_for(
                std::slice::from_ref(&inner_recipient.public_key_bundle()),
                ProtectionPurpose::from(4),
            )?;
        let middle = DataValue::Container(vec![(DataTypeId(50), nested)]);
        let protected = middle
            .clone()
            .sign(OUTER_SIGNER_ID, ProtectionPurpose::from(1), &signer)?
            .encrypt_for(
                std::slice::from_ref(&outer_recipient.public_key_bundle()),
                ProtectionPurpose::from(2),
            )?;

        let encoded = protected.to_bytes()?;
        let decoded = DataValue::from_bytes(&encoded).ok_or("nested value did not decode")?;
        assert!(matches!(decoded, DataValue::Encrypted(_)));

        let outer_signed = decoded.decrypt(&outer_recipient, ProtectionPurpose::from(2))?;
        let DataValue::Signed(outer_wrapper) = &outer_signed else {
            return Err("expected signed value inside outer encryption".into());
        };
        assert_eq!(outer_wrapper.signer_id, OUTER_SIGNER_ID);

        let mut signer_keys = outer_recipient.public_key_bundle();
        signer_keys.sig_cl_public_key = signer_public;
        let middle = outer_signed.into_verified_with_policy(
            OUTER_SIGNER_ID,
            &signer_keys,
            ProtectionPurpose::from(1),
            ProtectionPolicy::any_supported(),
        )?;
        let DataValue::Container(entries) = middle else {
            return Err("expected container inside outer signature".into());
        };
        let nested = entries
            .into_iter()
            .find_map(|(id, value)| (id == DataTypeId(50)).then_some(value))
            .ok_or("nested field missing")?;
        assert!(matches!(nested, DataValue::Encrypted(_)));

        let inner_signed = nested.decrypt(&inner_recipient, ProtectionPurpose::from(4))?;
        let DataValue::Signed(inner_wrapper) = &inner_signed else {
            return Err("expected signed value inside nested encryption".into());
        };
        assert_eq!(inner_wrapper.signer_id, INNER_SIGNER_ID);
        assert_eq!(
            inner_signed.into_verified_with_policy(
                INNER_SIGNER_ID,
                &signer_keys,
                ProtectionPurpose::from(3),
                ProtectionPolicy::any_supported(),
            )?,
            leaf
        );
        Ok(())
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn encrypted_authenticated_purpose_cannot_be_changed() -> Result<(), Box<dyn std::error::Error>>
    {
        use mtp_crypto::Keyring;

        let keyring = Keyring::generate();
        let value = DataValue::Bytes(vec![1, 2, 3]).encrypt_for(
            std::slice::from_ref(&keyring.public_key_bundle()),
            ProtectionPurpose::from(9),
        )?;
        let DataValue::Encrypted(mut encrypted) = value else {
            return Err("expected encrypted value".into());
        };
        encrypted.purpose ^= 1;
        assert!(
            DataValue::Encrypted(encrypted)
                .decrypt(&keyring, ProtectionPurpose::from(9))
                .is_err()
        );
        Ok(())
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn encrypted_values_use_one_authenticated_envelope_for_all_recipients()
    -> Result<(), Box<dyn std::error::Error>> {
        use mtp_crypto::Keyring;

        let recipient_a = Keyring::generate();
        let recipient_b = Keyring::generate();
        let recipient_c = Keyring::generate();
        let original = DataValue::Container(vec![
            (DataTypeId(40), DataValue::Str("shared secret".into())),
            (DataTypeId(41), DataValue::UnsignedNumber(42)),
        ]);
        let inner = original.to_bytes()?;
        let purpose = ProtectionPurpose::from(0xA5);
        let encrypted = original.clone().encrypt_for(
            &[
                recipient_a.public_key_bundle(),
                recipient_b.public_key_bundle(),
                recipient_c.public_key_bundle(),
            ],
            purpose,
        )?;

        let DataValue::Encrypted(value) = &encrypted else {
            return Err("expected encrypted value".into());
        };
        let suite = value.encryption_type;
        assert_eq!(value.recipients.len(), 3);
        assert!(
            value
                .recipients
                .iter()
                .all(
                    |entry| entry.kem_ciphertext.len() == suite.kem_ciphertext_len()
                        && entry.encrypted_key.len() == suite.wrapped_key_len()
                )
        );

        let encoded = encrypted.to_bytes()?;
        let envelope_len = u32::from_be_bytes(encoded[1..5].try_into()?) as usize;
        assert_eq!(encoded[0], DataValue::KIND_ENCRYPTED);
        assert_eq!(envelope_len, encoded.len() - 5);
        assert_eq!(encoded[5], suite.to_byte());
        assert_eq!(encoded[6], purpose.0);
        assert_eq!(u16::from_be_bytes(encoded[7..9].try_into()?), 3);
        assert_eq!(
            envelope_len,
            4 + 3 * (suite.kem_ciphertext_len() + suite.wrapped_key_len())
                + suite.encrypted_len(inner.len())
        );

        for keyring in [&recipient_a, &recipient_b, &recipient_c] {
            assert_eq!(encrypted.decrypt(keyring, purpose)?, original);
        }
        assert!(matches!(
            encrypted.decrypt(&Keyring::generate(), purpose),
            Err(ProtectionError::NoMatchingRecipient)
        ));
        Ok(())
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn encrypted_recipient_table_is_authenticated() -> Result<(), Box<dyn std::error::Error>> {
        use mtp_crypto::{CryptoError, Keyring};

        let recipient_a = Keyring::generate();
        let recipient_b = Keyring::generate();
        let encrypted = DataValue::Str("secret".into()).encrypt_for(
            &[
                recipient_a.public_key_bundle(),
                recipient_b.public_key_bundle(),
            ],
            ProtectionPurpose::from(1),
        )?;
        let DataValue::Encrypted(mut value) = encrypted else {
            return Err("expected encrypted value".into());
        };

        // Keep recipient A's wrapped CEK valid. Altering B's table entry must
        // still invalidate the payload because that complete table is AAD.
        value.recipients[1].encrypted_key[0] ^= 1;
        assert!(matches!(
            DataValue::Encrypted(value).decrypt(&recipient_a, ProtectionPurpose::from(1)),
            Err(ProtectionError::Crypto(CryptoError::DecryptionFailed))
        ));
        Ok(())
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn decryption_rejects_a_trailing_inner_value() -> Result<(), Box<dyn std::error::Error>> {
        use mtp_crypto::{EncryptionType, Keyring};

        let recipient = Keyring::generate();
        let original = DataValue::BoolTrue;
        let mut plaintext = original.to_bytes()?;
        plaintext.push(DataValue::KIND_NULL);
        let message = mtp_crypto::encrypt_multi_for(
            EncryptionType::MlKemChaCha20Poly1305,
            3,
            &plaintext,
            std::slice::from_ref(&recipient.public_key_bundle()),
        )?;
        let encrypted = DataValue::Encrypted(EncryptedValue {
            encryption_type: message.encryption_type,
            purpose: message.purpose,
            recipients: message.recipients,
            ciphertext: message.ciphertext,
        });

        assert!(matches!(
            encrypted.decrypt(&recipient, ProtectionPurpose::from(3)),
            Err(ProtectionError::Malformed)
        ));
        Ok(())
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn protection_operations_preserve_failure_reasons() -> Result<(), Box<dyn std::error::Error>> {
        use mtp_crypto::{EncryptionType, Keyring};

        let keyring = Keyring::generate();
        let public_keys = keyring.public_key_bundle();

        assert!(matches!(
            DataValue::Null.verify_with_policy(
                1,
                &public_keys,
                ProtectionPurpose::from(1),
                ProtectionPolicy::any_supported(),
            ),
            Err(ProtectionError::NotSigned)
        ));
        assert!(matches!(
            DataValue::Null.into_verified_with_policy(
                1,
                &public_keys,
                ProtectionPurpose::from(1),
                ProtectionPolicy::any_supported(),
            ),
            Err(ProtectionError::NotSigned)
        ));
        assert!(matches!(
            DataValue::Null.decrypt(&keyring, ProtectionPurpose::from(1)),
            Err(ProtectionError::NotEncrypted)
        ));
        assert!(matches!(
            DataValue::Null.encrypt_for(&[], ProtectionPurpose::from(1)),
            Err(ProtectionError::Crypto(
                mtp_crypto::CryptoError::NoRecipients
            ))
        ));

        let malformed_encrypted = DataValue::Encrypted(EncryptedValue {
            encryption_type: EncryptionType::MlKemChaCha20Poly1305,
            purpose: 1,
            recipients: Vec::new(),
            ciphertext: Vec::new(),
        });
        assert!(matches!(
            malformed_encrypted.decrypt(&keyring, ProtectionPurpose::from(1)),
            Err(ProtectionError::Malformed)
        ));

        let (signer, _, signer_public) = mtp_crypto::Ed25519Signer::generate();
        let mut signing_keys = keyring.public_key_bundle();
        signing_keys.sig_cl_public_key = signer_public;

        let duplicate_fields = DataValue::Container(vec![
            (DataTypeId(1), DataValue::Null),
            (DataTypeId(1), DataValue::Null),
        ]);
        assert!(matches!(
            duplicate_fields.sign(1, ProtectionPurpose::from(1), &signer),
            Err(ProtectionError::Codec(CodecError::InvalidEncoding))
        ));

        let signed = DataValue::Null.sign(1, ProtectionPurpose::from(1), &signer)?;
        let DataValue::Signed(mut signed) = signed else {
            return Err("expected signed value".into());
        };
        signed.signature[0] ^= 1;
        assert!(matches!(
            DataValue::Signed(signed).verify_with_policy(
                1,
                &signing_keys,
                ProtectionPurpose::from(1),
                ProtectionPolicy::any_supported(),
            ),
            Err(ProtectionError::InvalidSignature)
        ));

        Ok(())
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn application_purposes_cannot_collide_with_mtp_registry() {
        assert!(
            ApplicationProtectionPurpose::new(
                MtpProtectionPurpose::RelayMetadataEncryption.value()
            )
            .is_err()
        );
        let application = ApplicationProtectionPurpose::new(0x40).expect("application purpose");
        assert_eq!(ProtectionPurpose::from(application).0, 0x40);
    }
}
