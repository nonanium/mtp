// Relay-specific opening helpers.
//
// The generic [`DataValue`] protection operations remain the primitive API.
// These helpers add the protocol boundary needed by relay participants:
// metadata can be authenticated and returned with an opaque content value,
// while content opening is a separate operation that requires the final
// recipient identity.

#![cfg(feature = "crypto")]

use mtp_crypto::{Keyring, PublicKeyBundle, SignatureScheme};
use mtp_type_map::{CommunicationType, DataType, TypeMap};

use crate::{
    CommunicationValue, DataValue, MtpProtectionPurpose, ProtectionError, ProtectionPolicy,
    ReplayError, ReplayGuard,
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
    message_id: String,
    created_at: u64,
    metadata: Option<DataValue>,
    encrypted_content: DataValue,
    type_map: TypeMap,
    matched_signer_key_index: usize,
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

    pub fn message_id(&self) -> &str {
        &self.message_id
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
    pub message_type: String,
    pub content: DataValue,
}

/// Native sealed-relay builder shared by non-WASM applications.
///
/// The browser SDK and this builder intentionally produce the same reserved
/// metadata layout. Routing recipients are supplied separately from content
/// recipients so a metadata-only relay participant can open metadata without
/// receiving content keys.
pub struct SealedRelayBuilder<'a> {
    message_type: String,
    content: DataValue,
    signer_id: u64,
    final_recipient_id: u64,
    next_hop_id: u64,
    message_id: Option<String>,
    created_at: Option<u64>,
    metadata: Option<DataValue>,
    signer: &'a dyn SignatureScheme,
    metadata_recipients: Vec<PublicKeyBundle>,
    content_recipients: Vec<PublicKeyBundle>,
    type_map: Option<TypeMap>,
}

impl<'a> SealedRelayBuilder<'a> {
    pub fn new(
        message_type: impl Into<String>,
        content: DataValue,
        signer_id: u64,
        final_recipient_id: u64,
        next_hop_id: u64,
        signer: &'a dyn SignatureScheme,
    ) -> Self {
        Self {
            message_type: message_type.into(),
            content,
            signer_id,
            final_recipient_id,
            next_hop_id,
            message_id: None,
            created_at: None,
            metadata: None,
            signer,
            metadata_recipients: Vec::new(),
            content_recipients: Vec::new(),
            type_map: None,
        }
    }

    pub fn message_id(mut self, value: impl Into<String>) -> Self {
        self.message_id = Some(value.into());
        self
    }

    pub fn metadata(mut self, value: DataValue) -> Self {
        self.metadata = Some(value);
        self
    }

    /// Set `CreatedAt` as Unix epoch milliseconds.
    pub fn created_at(mut self, value: u64) -> Self {
        self.created_at = Some(value);
        self
    }

    pub fn metadata_recipients(mut self, recipients: Vec<PublicKeyBundle>) -> Self {
        self.metadata_recipients = recipients;
        self
    }

    pub fn content_recipients(mut self, recipients: Vec<PublicKeyBundle>) -> Self {
        self.content_recipients = recipients;
        self
    }

    /// Build the reserved relay fields against a negotiated type map. The
    /// default is the current map, but native callers handling an older
    /// negotiated frame should pass that map explicitly.
    pub fn type_map(mut self, type_map: &TypeMap) -> Self {
        self.type_map = Some(type_map.clone());
        self
    }

    pub fn build(self) -> Result<CommunicationValue, RelayError> {
        let message_id = self.message_id.ok_or(RelayError::InvalidLayout(
            "relay builder requires a message ID",
        ))?;
        let created_at = self.created_at.ok_or(RelayError::InvalidLayout(
            "relay builder requires a creation timestamp",
        ))?;
        if self.message_type.is_empty() || message_id.is_empty() {
            return Err(RelayError::InvalidLayout(
                "relay builder identifiers must be non-empty",
            ));
        }
        if self.metadata_recipients.is_empty() || self.content_recipients.is_empty() {
            return Err(RelayError::InvalidLayout(
                "relay builder requires metadata and content recipients",
            ));
        }

        let type_map = self.type_map.unwrap_or_else(TypeMap::latest);
        validate_application_message_type(&self.message_type, &type_map)?;
        let message_type_id = relay_field(DataType::MessageType, &type_map)?;
        let content_id = relay_field(DataType::Content, &type_map)?;
        let message_id_id = relay_field(DataType::MessageId, &type_map)?;
        let final_recipient_id = relay_field(DataType::FinalRecipientId, &type_map)?;
        let created_at_id = relay_field(DataType::CreatedAt, &type_map)?;
        let metadata_id = relay_field(DataType::Metadata, &type_map)?;
        let relay_version_id = relay_field(DataType::RelayVersion, &type_map)?;

        let content = DataValue::Container(vec![
            (message_type_id, DataValue::Str(self.message_type)),
            (content_id, self.content),
        ]);
        let signed_content = content.sign(
            self.signer_id,
            MtpProtectionPurpose::RelayContentSignature.into(),
            self.signer,
        )?;
        let encrypted_content = signed_content.encrypt_for(
            &self.content_recipients,
            MtpProtectionPurpose::RelayContentEncryption.into(),
        )?;
        let mut metadata_fields = vec![
            (
                relay_version_id,
                DataValue::UnsignedNumber(CURRENT_RELAY_VERSION as u128),
            ),
            (message_id_id, DataValue::Str(message_id)),
            (
                final_recipient_id,
                DataValue::UnsignedNumber(self.final_recipient_id as u128),
            ),
            (created_at_id, DataValue::UnsignedNumber(created_at as u128)),
            (content_id, encrypted_content),
        ];
        if let Some(application_metadata) = self.metadata {
            metadata_fields.push((metadata_id, application_metadata));
        }
        let metadata = DataValue::Container(metadata_fields);
        let signed_metadata = metadata.sign(
            self.signer_id,
            MtpProtectionPurpose::RelayMetadataSignature.into(),
            self.signer,
        )?;
        let encrypted_metadata = signed_metadata.encrypt_for(
            &self.metadata_recipients,
            MtpProtectionPurpose::RelayMetadataEncryption.into(),
        )?;
        Ok(
            CommunicationValue::new_with_type_map(CommunicationType::Relay, &type_map)
                .without_sender()
                .with_receiver(self.next_hop_id)
                .with_payload(encrypted_metadata),
        )
    }
}

fn relay_field(
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<mtp_type_map::DataTypeId, RelayError> {
    data_type
        .try_to_id(type_map)
        .ok_or(RelayError::InvalidLayout(
            "reserved relay type is unavailable",
        ))
}

fn validate_application_message_type(
    message_type: &str,
    type_map: &TypeMap,
) -> Result<(), RelayError> {
    let communication_type = CommunicationType::from_name(message_type)
        .ok_or(RelayError::InvalidLayout("relay message type is unknown"))?;
    let communication_id =
        communication_type
            .try_to_id(type_map)
            .ok_or(RelayError::InvalidLayout(
                "relay message type is unavailable",
            ))?;
    if communication_id.is_reserved() {
        return Err(RelayError::ReservedApplicationType(message_type.to_owned()));
    }
    Ok(())
}

fn field<'a>(
    value: &'a DataValue,
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<&'a DataValue, RelayError> {
    value
        .get_field(relay_field(data_type, type_map)?)
        .ok_or(RelayError::InvalidLayout("required relay field is missing"))
}

fn string_field(
    value: &DataValue,
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<String, RelayError> {
    field(value, data_type, type_map)?
        .as_string()
        .filter(|value| !value.is_empty())
        .ok_or(RelayError::InvalidLayout(
            "relay field is not a non-empty string",
        ))
}

fn optional_metadata_field(
    value: &DataValue,
    type_map: &TypeMap,
) -> Result<Option<DataValue>, RelayError> {
    Ok(value
        .get_field(relay_field(DataType::Metadata, type_map)?)
        .cloned())
}

fn unsigned_field(
    value: &DataValue,
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<u128, RelayError> {
    field(value, data_type, type_map)?
        .as_unsigned_number()
        .ok_or(RelayError::InvalidLayout("relay field is not unsigned"))
}

#[derive(Debug)]
struct RelayMetadataV1 {
    final_recipient_id: u64,
    message_id: String,
    created_at: u64,
    metadata: Option<DataValue>,
    encrypted_content: DataValue,
}

fn relay_version(value: &DataValue, type_map: &TypeMap) -> Result<u64, RelayError> {
    let version_id = relay_field(DataType::RelayVersion, type_map)?;
    let version = value
        .get_field(version_id)
        .ok_or(RelayError::MissingRelayVersion)?
        .as_unsigned_number()
        .ok_or(RelayError::InvalidLayout("relay version is not unsigned"))?;
    u64::try_from(version).map_err(|_| RelayError::InvalidLayout("relay version is out of range"))
}

fn parse_relay_v1(value: &DataValue, type_map: &TypeMap) -> Result<RelayMetadataV1, RelayError> {
    let final_recipient_id =
        u64::try_from(unsigned_field(value, DataType::FinalRecipientId, type_map)?)
            .map_err(|_| RelayError::InvalidLayout("final recipient ID is out of range"))?;
    let created_at = u64::try_from(unsigned_field(value, DataType::CreatedAt, type_map)?)
        .map_err(|_| RelayError::InvalidLayout("created-at value is out of range"))?;
    let encrypted_content = field(value, DataType::Content, type_map)?.clone();
    if encrypted_content.as_encrypted().is_none() {
        return Err(RelayError::InvalidLayout("content is not encrypted"));
    }
    Ok(RelayMetadataV1 {
        final_recipient_id,
        message_id: string_field(value, DataType::MessageId, type_map)?,
        created_at,
        metadata: optional_metadata_field(value, type_map)?,
        encrypted_content,
    })
}

/// Decrypt and verify relay metadata, without opening its content.
///
/// `expected_signer_id` is required when the caller already knows the sender.
/// For sealed-sender operation use [`open_relay_metadata_with`] and resolve a
/// trusted key by the claimed, unverified signer ID. The ID is authenticated
/// only after the returned key history verifies the signature.
pub fn open_relay_metadata(
    frame: &CommunicationValue,
    keyring: &Keyring,
    expected_signer_id: u64,
    signer_public_key: &PublicKeyBundle,
    policy: ProtectionPolicy,
) -> Result<VerifiedRelayMetadata, RelayError> {
    open_relay_metadata_with(
        frame,
        std::slice::from_ref(&keyring),
        Some(expected_signer_id),
        |_| Some(vec![signer_public_key.clone()]),
        policy,
        None,
    )
}

fn validate_relay_frame(frame: &CommunicationValue) -> Result<(), RelayError> {
    if !frame.is_type(CommunicationType::Relay) {
        return Err(RelayError::NotRelay);
    }
    if frame.sender().is_some() {
        return Err(RelayError::OuterSenderPresent);
    }
    if frame.receiver().is_none() {
        return Err(RelayError::MissingNextHop);
    }
    Ok(())
}

/// Return the claimed signer ID from relay metadata without verifying its
/// signature or interpreting the versioned relay schema. The result is
/// untrusted and may only select the key history that is then bound to the
/// same signer ID during [`open_relay_metadata_with_keys`].
pub fn relay_metadata_claimed_signer_id(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
) -> Result<u64, RelayError> {
    validate_relay_frame(frame)?;

    let decrypted = frame.payload().decrypt_with_keyrings(
        keyrings,
        MtpProtectionPurpose::RelayMetadataEncryption.into(),
    )?;
    let signed = decrypted
        .as_signed()
        .ok_or(RelayError::InvalidLayout("metadata is not signed"))?;
    Ok(signed.signer_id)
}

/// Decrypt and verify relay metadata against an already resolved signing-key
/// history. All relay version and field interpretation remains in the native
/// codec rather than being duplicated by language bindings.
pub fn open_relay_metadata_with_keys(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    expected_signer_id: u64,
    signer_public_keys: &[PublicKeyBundle],
    policy: ProtectionPolicy,
) -> Result<VerifiedRelayMetadata, RelayError> {
    let signer_public_keys = signer_public_keys.to_vec();
    open_relay_metadata_with(
        frame,
        keyrings,
        Some(expected_signer_id),
        move |_| Some(signer_public_keys.clone()),
        policy,
        None,
    )
}

/// Decrypt and verify relay metadata using recipient-key history and a
/// signer-key resolver. The resolver receives a claimed, unverified signer
/// ID used only as a trusted-key lookup key. The ID becomes authenticated
/// only after signature verification. This is the native counterpart of the
/// browser relay API and supports sealed sender plus signing-key rotation.
pub fn open_relay_metadata_with<F>(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    expected_signer_id: Option<u64>,
    resolve_signer_keys: F,
    policy: ProtectionPolicy,
    mut replay_guard: Option<&mut dyn ReplayGuard>,
) -> Result<VerifiedRelayMetadata, RelayError>
where
    F: Fn(u64) -> Option<Vec<PublicKeyBundle>>,
{
    validate_relay_frame(frame)?;

    let type_map = frame.type_map().cloned().unwrap_or_else(TypeMap::latest);
    let decrypted = frame.payload().decrypt_with_keyrings(
        keyrings,
        MtpProtectionPurpose::RelayMetadataEncryption.into(),
    )?;
    let signed = decrypted
        .as_signed()
        .ok_or(RelayError::InvalidLayout("metadata is not signed"))?;
    if let Some(expected_signer_id) = expected_signer_id
        && signed.signer_id != expected_signer_id
    {
        return Err(ProtectionError::SignerIdMismatch {
            expected: expected_signer_id,
            actual: signed.signer_id,
        }
        .into());
    }
    let signer_keys = resolve_signer_keys(signed.signer_id)
        .ok_or(ProtectionError::SignerKeyNotFound(signed.signer_id))?;
    let matched_signer_key_index = signed.verify_with_key_history_index(
        signed.signer_id,
        &signer_keys,
        MtpProtectionPurpose::RelayMetadataSignature.into(),
        policy,
    )?;
    let metadata = signed
        .value
        .as_container()
        .ok_or(RelayError::InvalidLayout("metadata is not a container"))?;
    let metadata = DataValue::Container(metadata);
    let relay_version = relay_version(&metadata, &type_map)?;
    let parsed = match relay_version {
        1 => parse_relay_v1(&metadata, &type_map)?,
        other => return Err(RelayError::UnsupportedRelayVersion(other)),
    };

    let result = VerifiedRelayMetadata {
        relay_version,
        signer_id: signed.signer_id,
        final_recipient_id: parsed.final_recipient_id,
        message_id: parsed.message_id,
        created_at: parsed.created_at,
        metadata: parsed.metadata,
        encrypted_content: parsed.encrypted_content,
        type_map,
        matched_signer_key_index,
        _verified: VerifiedMarker,
    };
    if let Some(guard) = replay_guard.as_mut()
        && !guard.accept(result.signer_id, &result.message_id, result.created_at)?
    {
        return Err(RelayError::Replay);
    }
    Ok(result)
}

/// Open and verify content after metadata has been authenticated.
pub fn open_relay_content(
    metadata: &VerifiedRelayMetadata,
    keyring: &Keyring,
    signer_public_key: &PublicKeyBundle,
    expected_recipient_id: u64,
    policy: ProtectionPolicy,
) -> Result<VerifiedRelayContent, RelayError> {
    open_relay_content_with_keys(
        metadata,
        keyring,
        std::slice::from_ref(signer_public_key),
        expected_recipient_id,
        policy,
    )
}

/// Open relay content against trusted signing-key history for the metadata's
/// authenticated signer ID.
pub fn open_relay_content_with_keys(
    metadata: &VerifiedRelayMetadata,
    keyring: &Keyring,
    signer_public_keys: &[PublicKeyBundle],
    expected_recipient_id: u64,
    policy: ProtectionPolicy,
) -> Result<VerifiedRelayContent, RelayError> {
    open_relay_content_with_keyrings(
        metadata,
        std::slice::from_ref(&keyring),
        signer_public_keys,
        Some(expected_recipient_id),
        policy,
    )
}

/// Open relay content against recipient-key history and trusted signing-key
/// history. The expected final recipient is optional for callers that only
/// have decryption material and do not have a local identity ID.
pub fn open_relay_content_with_keyrings(
    metadata: &VerifiedRelayMetadata,
    keyrings: &[&Keyring],
    signer_public_keys: &[PublicKeyBundle],
    expected_recipient_id: Option<u64>,
    policy: ProtectionPolicy,
) -> Result<VerifiedRelayContent, RelayError> {
    if expected_recipient_id.is_some_and(|id| metadata.final_recipient_id != id) {
        return Err(RelayError::NotFinalRecipient);
    }

    let type_map = &metadata.type_map;
    let decrypted = metadata.encrypted_content.decrypt_with_keyrings(
        keyrings,
        MtpProtectionPurpose::RelayContentEncryption.into(),
    )?;
    let signed = decrypted
        .as_signed()
        .ok_or(RelayError::InvalidLayout("content is not signed"))?;
    if signed.signer_id != metadata.signer_id {
        return Err(RelayError::InvalidLayout(
            "metadata and content signer IDs differ",
        ));
    }
    // Content is a separately signed value and must not inherit a weaker
    // metadata policy.
    signed.verify_with_key_history(
        metadata.signer_id,
        signer_public_keys,
        MtpProtectionPurpose::RelayContentSignature.into(),
        policy,
    )?;
    let content = signed
        .value
        .as_container()
        .ok_or(RelayError::InvalidLayout("content is not a container"))?;
    let content = DataValue::Container(content);
    let message_type = string_field(&content, DataType::MessageType, type_map)?;
    validate_application_message_type(&message_type, type_map)?;
    Ok(VerifiedRelayContent {
        signer_id: signed.signer_id,
        final_recipient_id: metadata.final_recipient_id,
        message_type,
        content: field(&content, DataType::Content, type_map)?.clone(),
    })
}

/// Change only the clear next-hop routing field of a sealed relay frame.
/// The authenticated encrypted payload is cloned byte-for-byte, so a relay
/// cannot alter the final recipient or message metadata while forwarding.
pub fn forward_relay_frame(
    frame: &CommunicationValue,
    next_hop_receiver_id: u64,
) -> Result<CommunicationValue, RelayError> {
    validate_relay_frame(frame)?;
    Ok(frame.clone().with_receiver(next_hop_receiver_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryReplayGuard;
    use mtp_crypto::{Ed25519Signer, Keyring};
    use mtp_type_map::DataTypeId;

    fn ed_signer(keyring: &Keyring) -> Ed25519Signer {
        Ed25519Signer::new(&keyring.sig_cl_secret_key).expect("Ed25519 signer")
    }

    fn relay_frame_with_version(
        version: Option<u64>,
        include_v1_fields: bool,
        sender: &Keyring,
        recipient: &Keyring,
    ) -> CommunicationValue {
        let signer = ed_signer(sender);
        let type_map = TypeMap::latest();
        let mut fields = Vec::new();
        if let Some(version) = version {
            fields.push((
                relay_field(DataType::RelayVersion, &type_map).expect("RelayVersion mapping"),
                DataValue::UnsignedNumber(version as u128),
            ));
        }
        if include_v1_fields {
            let content = DataValue::Container(vec![
                (
                    relay_field(DataType::MessageType, &type_map).expect("MessageType mapping"),
                    DataValue::Str("ProtectedMessage".into()),
                ),
                (
                    relay_field(DataType::Content, &type_map).expect("Content mapping"),
                    DataValue::Null,
                ),
            ])
            .sign(
                7,
                MtpProtectionPurpose::RelayContentSignature.into(),
                &signer,
            )
            .expect("sign content")
            .encrypt_for(
                &[recipient.public_key_bundle()],
                MtpProtectionPurpose::RelayContentEncryption.into(),
            )
            .expect("encrypt content");
            fields.extend([
                (
                    relay_field(DataType::MessageId, &type_map).expect("MessageId mapping"),
                    DataValue::Str("version-test".into()),
                ),
                (
                    relay_field(DataType::FinalRecipientId, &type_map)
                        .expect("FinalRecipientId mapping"),
                    DataValue::UnsignedNumber(42),
                ),
                (
                    relay_field(DataType::CreatedAt, &type_map).expect("CreatedAt mapping"),
                    DataValue::UnsignedNumber(123),
                ),
                (
                    relay_field(DataType::Metadata, &type_map).expect("Metadata mapping"),
                    DataValue::Null,
                ),
                (
                    relay_field(DataType::Content, &type_map).expect("Content mapping"),
                    content,
                ),
            ]);
        }
        let payload = DataValue::Container(fields)
            .sign(
                7,
                MtpProtectionPurpose::RelayMetadataSignature.into(),
                &signer,
            )
            .expect("sign metadata")
            .encrypt_for(
                &[recipient.public_key_bundle()],
                MtpProtectionPurpose::RelayMetadataEncryption.into(),
            )
            .expect("encrypt metadata");
        CommunicationValue::new_with_type_map(CommunicationType::Relay, &type_map)
            .without_sender()
            .with_receiver(9)
            .with_payload(payload)
    }

    #[test]
    fn relay_version_one_round_trips() {
        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let frame =
            relay_frame_with_version(Some(CURRENT_RELAY_VERSION), true, &sender, &recipient);
        let metadata = open_relay_metadata(
            &frame,
            &recipient,
            7,
            &sender.public_key_bundle(),
            ProtectionPolicy::from(crate::SignaturePolicy::Ed25519),
        )
        .expect("version 1 metadata");
        assert_eq!(metadata.relay_version(), CURRENT_RELAY_VERSION);
    }

    #[test]
    fn missing_relay_version_is_rejected() {
        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let frame = relay_frame_with_version(None, true, &sender, &recipient);
        let result = open_relay_metadata(
            &frame,
            &recipient,
            7,
            &sender.public_key_bundle(),
            ProtectionPolicy::from(crate::SignaturePolicy::Ed25519),
        );
        assert!(matches!(result, Err(RelayError::MissingRelayVersion)));
    }

    #[test]
    fn unknown_relay_version_is_rejected_before_v1_fields_are_parsed() {
        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let frame = relay_frame_with_version(Some(99), false, &sender, &recipient);
        let result = open_relay_metadata(
            &frame,
            &recipient,
            7,
            &sender.public_key_bundle(),
            ProtectionPolicy::from(crate::SignaturePolicy::Ed25519),
        );
        assert!(matches!(
            result,
            Err(RelayError::UnsupportedRelayVersion(99))
        ));
    }

    #[test]
    fn relay_created_at_preserves_exact_milliseconds() {
        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let signer = ed_signer(&sender);
        let created_at = 1_720_000_000_123;
        let frame = SealedRelayBuilder::new(
            "ProtectedMessage",
            DataValue::Str("timestamp content".into()),
            11,
            42,
            42,
            &signer,
        )
        .message_id("relay-created-at-millis")
        .created_at(created_at)
        .metadata_recipients(vec![recipient.public_key_bundle()])
        .content_recipients(vec![recipient.public_key_bundle()])
        .build()
        .expect("relay frame");

        let type_map = frame.type_map().cloned().unwrap_or_else(TypeMap::latest);
        let decrypted = frame
            .payload()
            .decrypt(
                &recipient,
                MtpProtectionPurpose::RelayMetadataEncryption.into(),
            )
            .expect("metadata decryption");
        let signed = decrypted.as_signed().expect("signed metadata");
        let created_at_id = DataType::CreatedAt
            .try_to_id(&type_map)
            .expect("CreatedAt mapping");

        assert_eq!(
            signed.value.get_field(created_at_id),
            Some(&DataValue::UnsignedNumber(created_at as u128))
        );
        let verified = open_relay_metadata(
            &frame,
            &recipient,
            11,
            &sender.public_key_bundle(),
            ProtectionPolicy::from(crate::SignaturePolicy::Ed25519),
        )
        .expect("verified metadata");
        assert_eq!(verified.created_at(), created_at);
    }

    #[test]
    fn relay_metadata_policy_and_replay_guard_are_receiver_controls() {
        let sender = Keyring::generate();
        let metadata_recipient = Keyring::generate();
        let final_recipient = Keyring::generate();
        let signer = ed_signer(&sender);
        let application_metadata = DataValue::Container(vec![
            (DataTypeId(32), DataValue::Str("opaque-field".into())),
            (DataTypeId(33), DataValue::UnsignedNumber(7)),
        ]);
        let frame = SealedRelayBuilder::new(
            "ProtectedMessage",
            DataValue::Str("hello".into()),
            7,
            42,
            9,
            &signer,
        )
        .message_id("message-1")
        .created_at(123)
        .metadata(application_metadata.clone())
        .metadata_recipients(vec![
            metadata_recipient.public_key_bundle(),
            final_recipient.public_key_bundle(),
        ])
        .content_recipients(vec![final_recipient.public_key_bundle()])
        .build()
        .expect("relay frame");
        let frame =
            CommunicationValue::from_bytes(&frame.to_bytes().expect("relay frame encoding"))
                .expect("relay frame decoding");

        assert_eq!(frame.sender(), None);
        assert_eq!(frame.receiver(), Some(9));

        let policy = ProtectionPolicy::from(crate::SignaturePolicy::Ed25519);
        let mut guard = InMemoryReplayGuard::default();
        let metadata = open_relay_metadata_with(
            &frame,
            &[&metadata_recipient],
            None,
            |signer_id| (signer_id == 7).then(|| vec![sender.public_key_bundle()]),
            policy,
            Some(&mut guard),
        )
        .expect("metadata");
        assert_eq!(metadata.signer_id(), 7);
        assert_eq!(metadata.relay_version(), CURRENT_RELAY_VERSION);
        assert_eq!(metadata.final_recipient_id(), 42);
        assert_eq!(metadata.message_id(), "message-1");
        assert_eq!(metadata.created_at(), 123);
        assert_eq!(metadata.metadata(), Some(&application_metadata));

        // A final recipient may be included in the metadata recipient set and
        // therefore open both authenticated layers directly.
        let final_metadata = open_relay_metadata(
            &frame,
            &final_recipient,
            7,
            &sender.public_key_bundle(),
            policy,
        )
        .expect("final recipient metadata");
        assert_eq!(final_metadata.metadata(), Some(&application_metadata));
        let final_content = open_relay_content(
            &final_metadata,
            &final_recipient,
            &sender.public_key_bundle(),
            42,
            policy,
        )
        .expect("final recipient content");
        assert_eq!(final_content.content, DataValue::Str("hello".into()));

        assert!(matches!(
            open_relay_metadata(
                &frame,
                &metadata_recipient,
                8,
                &sender.public_key_bundle(),
                policy,
            ),
            Err(RelayError::Protection(ProtectionError::SignerIdMismatch {
                expected: 8,
                actual: 7,
            }))
        ));

        let wrong_signer = Keyring::generate();
        assert!(matches!(
            open_relay_metadata(
                &frame,
                &metadata_recipient,
                7,
                &wrong_signer.public_key_bundle(),
                policy,
            ),
            Err(RelayError::Protection(_))
        ));

        assert!(matches!(
            open_relay_metadata(
                &frame.clone().with_sender(99),
                &metadata_recipient,
                7,
                &sender.public_key_bundle(),
                policy,
            ),
            Err(RelayError::OuterSenderPresent)
        ));

        assert!(
            open_relay_content(
                &metadata,
                &metadata_recipient,
                &sender.public_key_bundle(),
                42,
                policy,
            )
            .is_err()
        );

        let content = open_relay_content(
            &metadata,
            &final_recipient,
            &sender.public_key_bundle(),
            42,
            policy,
        )
        .expect("content");
        assert_eq!(content.signer_id, 7);
        assert_eq!(content.final_recipient_id, 42);
        assert_eq!(content.message_type, "ProtectedMessage");
        assert_eq!(content.content, DataValue::Str("hello".into()));
        assert!(matches!(
            open_relay_content(
                &metadata,
                &final_recipient,
                &sender.public_key_bundle(),
                43,
                policy,
            ),
            Err(RelayError::NotFinalRecipient)
        ));

        let replay = open_relay_metadata_with(
            &frame,
            &[&metadata_recipient],
            None,
            |signer_id| (signer_id == 7).then(|| vec![sender.public_key_bundle()]),
            policy,
            Some(&mut guard),
        );
        assert!(matches!(replay, Err(RelayError::Replay)));
    }

    #[test]
    fn relay_metadata_preserves_generic_values_and_absence() {
        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let signer = ed_signer(&sender);
        let values = vec![
            DataValue::Null,
            DataValue::Bool(true),
            DataValue::Str("scalar metadata".into()),
            DataValue::Bytes(vec![1, 2, 3]),
            DataValue::Array(vec![DataValue::UnsignedNumber(7), DataValue::BoolFalse]),
            DataValue::Container(vec![(DataTypeId(32), DataValue::Str("typed".into()))]),
        ];

        for (index, value) in values.into_iter().enumerate() {
            let frame =
                SealedRelayBuilder::new("ProtectedMessage", DataValue::Null, 7, 42, 9, &signer)
                    .message_id(format!("metadata-{index}"))
                    .created_at(123)
                    .metadata(value.clone())
                    .metadata_recipients(vec![recipient.public_key_bundle()])
                    .content_recipients(vec![recipient.public_key_bundle()])
                    .build()
                    .expect("relay frame");
            let opened = open_relay_metadata(
                &frame,
                &recipient,
                7,
                &sender.public_key_bundle(),
                ProtectionPolicy::from(crate::SignaturePolicy::Ed25519),
            )
            .expect("relay metadata");
            assert_eq!(opened.metadata(), Some(&value));
        }

        let absent =
            SealedRelayBuilder::new("ProtectedMessage", DataValue::Null, 7, 42, 9, &signer)
                .message_id("metadata-absent")
                .created_at(123)
                .metadata_recipients(vec![recipient.public_key_bundle()])
                .content_recipients(vec![recipient.public_key_bundle()])
                .build()
                .expect("relay frame");
        let opened = open_relay_metadata(
            &absent,
            &recipient,
            7,
            &sender.public_key_bundle(),
            ProtectionPolicy::from(crate::SignaturePolicy::Ed25519),
        )
        .expect("relay metadata");
        assert_eq!(opened.metadata(), None);
    }

    #[test]
    fn relay_keyring_boundary_helpers_open_verified_handles() {
        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let signer = ed_signer(&sender);
        let frame = SealedRelayBuilder::new(
            "ProtectedMessage",
            DataValue::Str("hello".into()),
            7,
            42,
            9,
            &signer,
        )
        .message_id("boundary-message")
        .created_at(123)
        .metadata_recipients(vec![recipient.public_key_bundle()])
        .content_recipients(vec![recipient.public_key_bundle()])
        .build()
        .expect("relay frame");

        assert_eq!(
            relay_metadata_claimed_signer_id(&frame, &[&recipient]).expect("signer ID"),
            7
        );
        let metadata = open_relay_metadata_with_keys(
            &frame,
            &[&recipient],
            7,
            &[sender.public_key_bundle()],
            ProtectionPolicy::from(crate::SignaturePolicy::Ed25519),
        )
        .expect("relay metadata");
        let content = open_relay_content_with_keyrings(
            &metadata,
            &[&recipient],
            &[sender.public_key_bundle()],
            Some(42),
            ProtectionPolicy::from(crate::SignaturePolicy::Ed25519),
        )
        .expect("relay content");

        assert_eq!(content.signer_id, 7);
        assert_eq!(content.final_recipient_id, 42);
        assert_eq!(content.message_type, "ProtectedMessage");
        assert_eq!(content.content, DataValue::Str("hello".into()));
    }

    #[test]
    fn relay_content_opening_accepts_previous_recipient_key_history() {
        let sender = Keyring::generate();
        let metadata_recipient = Keyring::generate();
        let current_content_recipient = Keyring::generate();
        let previous_content_recipient = Keyring::generate();
        let signer = ed_signer(&sender);
        let frame = SealedRelayBuilder::new(
            "ProtectedMessage",
            DataValue::Str("opened with a previous recipient key".into()),
            7,
            42,
            9,
            &signer,
        )
        .message_id("recipient-rotation-1")
        .created_at(123)
        .metadata_recipients(vec![metadata_recipient.public_key_bundle()])
        .content_recipients(vec![previous_content_recipient.public_key_bundle()])
        .build()
        .expect("relay frame");
        let policy = ProtectionPolicy::from(crate::SignaturePolicy::Ed25519);

        let metadata = open_relay_metadata_with(
            &frame,
            &[&metadata_recipient],
            Some(7),
            |signer_id| (signer_id == 7).then(|| vec![sender.public_key_bundle()]),
            policy,
            None,
        )
        .expect("relay metadata");

        let content = open_relay_content_with_keyrings(
            &metadata,
            &[&current_content_recipient, &previous_content_recipient],
            &[sender.public_key_bundle()],
            Some(42),
            policy,
        )
        .expect("previous content recipient key should decrypt");

        assert_eq!(content.signer_id, 7);
        assert_eq!(content.final_recipient_id, 42);
        assert_eq!(content.message_type, "ProtectedMessage");
        assert_eq!(
            content.content,
            DataValue::Str("opened with a previous recipient key".into())
        );
    }

    #[test]
    fn dual_policy_rejects_a_valid_ed25519_relay() {
        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let signer = ed_signer(&sender);
        let frame = SealedRelayBuilder::new("ProtectedMessage", DataValue::Null, 7, 42, 9, &signer)
            .message_id("message-2")
            .created_at(123)
            .metadata_recipients(vec![recipient.public_key_bundle()])
            .content_recipients(vec![recipient.public_key_bundle()])
            .build()
            .expect("relay frame");

        let result = open_relay_metadata(
            &frame,
            &recipient,
            7,
            &sender.public_key_bundle(),
            ProtectionPolicy::from(crate::SignaturePolicy::Dual),
        );
        assert!(matches!(
            result,
            Err(RelayError::Protection(
                ProtectionError::SignaturePolicyMismatch { .. }
            ))
        ));
    }

    #[test]
    fn forwarding_changes_only_the_outer_next_hop() {
        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let signer = ed_signer(&sender);
        let frame = SealedRelayBuilder::new("ProtectedMessage", DataValue::Null, 7, 42, 9, &signer)
            .message_id("message-3")
            .created_at(123)
            .metadata_recipients(vec![recipient.public_key_bundle()])
            .content_recipients(vec![recipient.public_key_bundle()])
            .build()
            .expect("relay frame");
        let forwarded = forward_relay_frame(&frame, 10).expect("forward");
        assert_eq!(frame.payload(), forwarded.payload());
        assert_eq!(
            frame.payload().to_bytes().expect("original payload bytes"),
            forwarded
                .payload()
                .to_bytes()
                .expect("forwarded payload bytes")
        );
        assert_eq!(forwarded.receiver(), Some(10));
        assert_eq!(forwarded.sender(), None);
    }

    #[test]
    fn relay_signer_key_rotation_accepts_previous_key_history() {
        let old_signer_keyring = Keyring::generate();
        let current_signer_keyring = Keyring::generate();
        let recipient = Keyring::generate();
        let old_signer = ed_signer(&old_signer_keyring);
        let old_signer_public = old_signer_keyring.public_key_bundle();
        let current_signer_public = current_signer_keyring.public_key_bundle();
        let frame = SealedRelayBuilder::new(
            "ProtectedMessage",
            DataValue::Str("signed with the previous key".into()),
            77,
            42,
            9,
            &old_signer,
        )
        .message_id("rotation-1")
        .created_at(456)
        .metadata(DataValue::Str("rotation metadata".into()))
        .metadata_recipients(vec![recipient.public_key_bundle()])
        .content_recipients(vec![recipient.public_key_bundle()])
        .build()
        .expect("relay frame");
        let policy = ProtectionPolicy::from(crate::SignaturePolicy::Ed25519);

        let metadata = open_relay_metadata_with(
            &frame,
            &[&recipient],
            Some(77),
            |signer_id| {
                (signer_id == 77)
                    .then(|| vec![current_signer_public.clone(), old_signer_public.clone()])
            },
            policy,
            None,
        )
        .expect("metadata signed by a previous key should verify");
        assert_eq!(metadata.matched_signer_key_index(), 1);
        let content = open_relay_content_with_keys(
            &metadata,
            &recipient,
            &[current_signer_public, old_signer_public],
            42,
            policy,
        )
        .expect("content signed by a previous key should verify");
        assert_eq!(content.message_type, "ProtectedMessage");
        assert_eq!(
            content.content,
            DataValue::Str("signed with the previous key".into())
        );
    }

    #[test]
    fn builder_preserves_the_negotiated_type_map_context() {
        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let signer = ed_signer(&sender);
        let type_map = TypeMap::latest();
        let frame = SealedRelayBuilder::new("ProtectedMessage", DataValue::Null, 7, 42, 9, &signer)
            .message_id("message-4")
            .created_at(123)
            .metadata_recipients(vec![recipient.public_key_bundle()])
            .content_recipients(vec![recipient.public_key_bundle()])
            .type_map(&type_map)
            .build()
            .expect("relay frame");

        assert_eq!(frame.type_map(), Some(&type_map));
    }

    #[test]
    fn builder_rejects_reserved_application_message_types() {
        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let signer = ed_signer(&sender);
        let result = SealedRelayBuilder::new("Ping", DataValue::Null, 7, 42, 9, &signer)
            .message_id("reserved-message")
            .created_at(123)
            .metadata_recipients(vec![recipient.public_key_bundle()])
            .content_recipients(vec![recipient.public_key_bundle()])
            .build();

        assert!(matches!(
            result,
            Err(RelayError::ReservedApplicationType(type_name)) if type_name == "Ping"
        ));
    }
}
