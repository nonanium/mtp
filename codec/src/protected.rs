//! Native codec for direct protected application messages.
//!
//! The protected envelope is an MTP protocol structure. Keeping its schema,
//! version checks, and routing authentication here gives native applications
//! and language bindings one implementation to consume.

#![cfg(feature = "crypto")]

use mtp_crypto::{Keyring, PublicKeyBundle, SignatureScheme};
use mtp_type_map::{CommunicationType, DataType, TypeMap};
use std::collections::HashSet;

use crate::{CommunicationValue, DataValue, ProtectionError, ProtectionPolicy, ProtectionPurpose};

/// The direct protected-message envelope schema version emitted by this
/// codec.
pub const CURRENT_PROTECTED_VERSION: u64 = 1;

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
        message_id: &str,
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
#[derive(Debug, Default)]
pub struct InMemoryReplayGuard {
    accepted: HashSet<(u64, String)>,
}

impl ReplayGuard for InMemoryReplayGuard {
    fn accept(
        &mut self,
        signer_id: u64,
        message_id: &str,
        _created_at: u64,
    ) -> Result<bool, ReplayError> {
        Ok(self.accepted.insert((signer_id, message_id.to_owned())))
    }
}

/// A direct protected-message builder shared by native applications and
/// language bindings.
pub struct ProtectedMessageBuilder<'a> {
    message_type: String,
    content: DataValue,
    signer_id: u64,
    final_recipient_id: u64,
    message_id: Option<String>,
    created_at: Option<u64>,
    signer: &'a dyn SignatureScheme,
    recipients: Vec<PublicKeyBundle>,
    signature_purpose: ProtectionPurpose,
    encryption_purpose: ProtectionPurpose,
    type_map: Option<TypeMap>,
    frame_id: Option<u32>,
    expose_sender: bool,
}

impl<'a> ProtectedMessageBuilder<'a> {
    pub fn new(
        message_type: impl Into<String>,
        content: DataValue,
        signer_id: u64,
        final_recipient_id: u64,
        signer: &'a dyn SignatureScheme,
        signature_purpose: ProtectionPurpose,
        encryption_purpose: ProtectionPurpose,
    ) -> Self {
        Self {
            message_type: message_type.into(),
            content,
            signer_id,
            final_recipient_id,
            message_id: None,
            created_at: None,
            signer,
            recipients: Vec::new(),
            signature_purpose,
            encryption_purpose,
            type_map: None,
            frame_id: None,
            expose_sender: false,
        }
    }

    pub fn message_id(mut self, value: impl Into<String>) -> Self {
        self.message_id = Some(value.into());
        self
    }

    /// Set `CreatedAt` as Unix epoch milliseconds.
    pub fn created_at(mut self, value: u64) -> Self {
        self.created_at = Some(value);
        self
    }

    pub fn recipients(mut self, recipients: Vec<PublicKeyBundle>) -> Self {
        self.recipients = recipients;
        self
    }

    /// Build against an explicitly negotiated type map.
    pub fn type_map(mut self, type_map: &TypeMap) -> Self {
        self.type_map = Some(type_map.clone());
        self
    }

    /// Set the clear outer MTP frame ID. The protected envelope's
    /// authenticated `MessageId` remains independent from this transport
    /// correlation field.
    pub fn frame_id(mut self, value: u32) -> Self {
        self.frame_id = Some(value);
        self
    }

    /// Include the authenticated signer ID in the clear outer frame sender
    /// field. The default keeps the outer sender hidden.
    pub fn expose_sender(mut self, expose: bool) -> Self {
        self.expose_sender = expose;
        self
    }

    pub fn build(self) -> Result<CommunicationValue, ProtectedError> {
        let message_id = self.message_id.ok_or(ProtectedError::InvalidLayout(
            "protected builder requires a message ID",
        ))?;
        let created_at = self.created_at.ok_or(ProtectedError::InvalidLayout(
            "protected builder requires a creation timestamp",
        ))?;
        if self.message_type.is_empty() || message_id.is_empty() {
            return Err(ProtectedError::InvalidLayout(
                "protected identifiers must be non-empty",
            ));
        }
        if self.recipients.is_empty() {
            return Err(ProtectedError::InvalidLayout(
                "protected builder requires at least one recipient",
            ));
        }

        let type_map = self.type_map.unwrap_or_else(TypeMap::latest);
        let application_type = validate_application_message_type(&self.message_type, &type_map)?;
        let protected_version_id = protected_field_id(DataType::ProtectedVersion, &type_map)?;
        let message_type_id = protected_field_id(DataType::MessageType, &type_map)?;
        let final_recipient_id = protected_field_id(DataType::FinalRecipientId, &type_map)?;
        let message_id_id = protected_field_id(DataType::MessageId, &type_map)?;
        let created_at_id = protected_field_id(DataType::CreatedAt, &type_map)?;
        let content_id = protected_field_id(DataType::Content, &type_map)?;

        let envelope = DataValue::Container(vec![
            (
                protected_version_id,
                DataValue::UnsignedNumber(CURRENT_PROTECTED_VERSION as u128),
            ),
            (message_type_id, DataValue::Str(self.message_type)),
            (
                final_recipient_id,
                DataValue::UnsignedNumber(self.final_recipient_id as u128),
            ),
            (message_id_id, DataValue::Str(message_id)),
            (created_at_id, DataValue::UnsignedNumber(created_at as u128)),
            (content_id, self.content),
        ]);
        let signed = envelope.sign(self.signer_id, self.signature_purpose, self.signer)?;
        let encrypted = signed.encrypt_for(&self.recipients, self.encryption_purpose)?;

        let mut frame = CommunicationValue::new_with_type_map(application_type, &type_map)
            .with_receiver(self.final_recipient_id)
            .with_payload(encrypted);
        if let Some(frame_id) = self.frame_id {
            frame = frame.with_id(frame_id);
        }
        if self.expose_sender {
            frame = frame.with_sender(self.signer_id);
        }
        Ok(frame)
    }
}

/// A direct protected message after the encrypted envelope and its signature
/// have been authenticated.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedProtectedMessage {
    pub protected_version: u64,
    pub signer_id: u64,
    pub final_recipient_id: u64,
    pub message_id: String,
    pub created_at: u64,
    pub message_type: String,
    pub content: DataValue,
    pub matched_signer_key_index: usize,
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
        }
    }
}

fn protected_field_id(
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<mtp_type_map::DataTypeId, ProtectedError> {
    data_type
        .try_to_id(type_map)
        .ok_or(ProtectedError::InvalidLayout(
            "reserved protected type is unavailable",
        ))
}

fn validate_application_message_type(
    message_type: &str,
    type_map: &TypeMap,
) -> Result<CommunicationType, ProtectedError> {
    let communication_type = CommunicationType::from_name(message_type).ok_or(
        ProtectedError::InvalidLayout("protected message type is unknown"),
    )?;
    let communication_id =
        communication_type
            .try_to_id(type_map)
            .ok_or(ProtectedError::InvalidLayout(
                "protected message type is unavailable",
            ))?;
    if communication_id.is_reserved() {
        return Err(ProtectedError::ReservedApplicationType(
            message_type.to_owned(),
        ));
    }
    Ok(communication_type)
}

fn validate_protected_frame(frame: &CommunicationValue) -> Result<TypeMap, ProtectedError> {
    let type_map = frame.type_map().cloned().unwrap_or_else(TypeMap::latest);
    let Some(communication_type) = frame.get_comm_type_enum() else {
        return Err(ProtectedError::NotApplicationFrame);
    };
    let communication_id = communication_type
        .try_to_id(&type_map)
        .ok_or(ProtectedError::NotApplicationFrame)?;
    if communication_id.is_reserved() {
        return Err(ProtectedError::ReservedApplicationType(
            communication_type.name().to_owned(),
        ));
    }
    if frame.receiver().is_none() {
        return Err(ProtectedError::MissingReceiver);
    }
    Ok(type_map)
}

fn field<'a>(
    value: &'a DataValue,
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<&'a DataValue, ProtectedError> {
    value
        .get_field(protected_field_id(data_type, type_map)?)
        .ok_or(ProtectedError::InvalidLayout(
            "required protected field is missing",
        ))
}

fn unsigned_field(
    value: &DataValue,
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<u128, ProtectedError> {
    field(value, data_type, type_map)?
        .as_unsigned_number()
        .ok_or(ProtectedError::InvalidLayout(
            "protected field is not unsigned",
        ))
}

fn string_field(
    value: &DataValue,
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<String, ProtectedError> {
    field(value, data_type, type_map)?
        .as_string()
        .filter(|value| !value.is_empty())
        .ok_or(ProtectedError::InvalidLayout(
            "protected field is not a non-empty string",
        ))
}

fn protected_version(value: &DataValue, type_map: &TypeMap) -> Result<u64, ProtectedError> {
    let version_id = protected_field_id(DataType::ProtectedVersion, type_map)?;
    let version = value
        .get_field(version_id)
        .ok_or(ProtectedError::MissingProtectedVersion)?
        .as_unsigned_number()
        .ok_or(ProtectedError::InvalidLayout(
            "protected version is not unsigned",
        ))?;
    u64::try_from(version)
        .map_err(|_| ProtectedError::InvalidLayout("protected version is out of range"))
}

fn decrypt_protected_payload(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    encryption_purpose: ProtectionPurpose,
) -> Result<DataValue, ProtectedError> {
    frame
        .payload()
        .decrypt_with_keyrings(keyrings, encryption_purpose)
        .map_err(|error| match error {
            ProtectionError::NotEncrypted => ProtectedError::PayloadNotEncrypted,
            other => ProtectedError::Protection(other),
        })
}

/// Return the claimed signer ID after decryption, without verifying its
/// signature. The value is untrusted and may only select the key history that
/// is then bound to the same signer ID during the subsequent open.
pub fn protected_claimed_signer_id(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    encryption_purpose: ProtectionPurpose,
) -> Result<u64, ProtectedError> {
    validate_protected_frame(frame)?;
    let decrypted = decrypt_protected_payload(frame, keyrings, encryption_purpose)?;
    let signed = decrypted
        .as_signed()
        .ok_or(ProtectedError::PayloadNotSigned)?;
    Ok(signed.signer_id)
}

/// Open a direct protected message using a resolver for trusted signer keys.
/// The resolver receives a claimed, unverified signer ID only as a lookup key.
pub fn open_protected_with<F>(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    expected_signer_id: Option<u64>,
    resolve_signer_keys: F,
    options: ProtectedOpenOptions,
    replay_guard: Option<&mut dyn ReplayGuard>,
) -> Result<VerifiedProtectedMessage, ProtectedError>
where
    F: FnOnce(u64) -> Option<Vec<PublicKeyBundle>>,
{
    validate_protected_frame(frame)?;
    let type_map = frame.type_map().cloned().unwrap_or_else(TypeMap::latest);
    let decrypted = decrypt_protected_payload(frame, keyrings, options.encryption_purpose)?;
    let signed = decrypted
        .as_signed()
        .ok_or(ProtectedError::PayloadNotSigned)?;
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
    open_decrypted_protected(frame, type_map, signed, &signer_keys, options, replay_guard)
}

/// Open a direct protected message against already resolved trusted signer
/// keys. The signer ID is mandatory so a key history cannot be applied to a
/// different claimed identity.
pub fn open_protected_with_keys(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    expected_signer_id: u64,
    signer_public_keys: &[PublicKeyBundle],
    options: ProtectedOpenOptions,
    replay_guard: Option<&mut dyn ReplayGuard>,
) -> Result<VerifiedProtectedMessage, ProtectedError> {
    let type_map = validate_protected_frame(frame)?;
    let decrypted = decrypt_protected_payload(frame, keyrings, options.encryption_purpose)?;
    let signed = decrypted
        .as_signed()
        .ok_or(ProtectedError::PayloadNotSigned)?;
    if signed.signer_id != expected_signer_id {
        return Err(ProtectionError::SignerIdMismatch {
            expected: expected_signer_id,
            actual: signed.signer_id,
        }
        .into());
    }
    open_decrypted_protected(
        frame,
        type_map,
        signed,
        signer_public_keys,
        options,
        replay_guard,
    )
}

/// Open a direct protected message when the expected signer and one trusted
/// public key are already known.
pub fn open_protected(
    frame: &CommunicationValue,
    keyring: &Keyring,
    expected_signer_id: u64,
    signer_public_key: &PublicKeyBundle,
    options: ProtectedOpenOptions,
    replay_guard: Option<&mut dyn ReplayGuard>,
) -> Result<VerifiedProtectedMessage, ProtectedError> {
    open_protected_with_keys(
        frame,
        std::slice::from_ref(&keyring),
        expected_signer_id,
        std::slice::from_ref(signer_public_key),
        options,
        replay_guard,
    )
}

fn open_decrypted_protected(
    frame: &CommunicationValue,
    type_map: TypeMap,
    signed: &crate::SignedValue,
    signer_public_keys: &[PublicKeyBundle],
    options: ProtectedOpenOptions,
    mut replay_guard: Option<&mut dyn ReplayGuard>,
) -> Result<VerifiedProtectedMessage, ProtectedError> {
    let matched_signer_key_index = signed.verify_with_key_history_index(
        signed.signer_id,
        signer_public_keys,
        options.signature_purpose,
        options.policy,
    )?;
    let receiver_id = frame.receiver().ok_or(ProtectedError::MissingReceiver)?;
    if options
        .expected_receiver_id
        .is_some_and(|expected| expected != receiver_id)
    {
        return Err(ProtectedError::ExpectedReceiverMismatch);
    }
    if frame
        .sender()
        .is_some_and(|sender| sender != signed.signer_id)
    {
        return Err(ProtectedError::SenderMismatch);
    }
    let envelope = signed
        .value
        .as_container()
        .ok_or(ProtectedError::MissingEnvelope)?;
    let envelope = DataValue::Container(envelope);
    let version = protected_version(&envelope, &type_map)?;
    if version != CURRENT_PROTECTED_VERSION {
        return Err(ProtectedError::UnsupportedProtectedVersion(version));
    }
    let message_type = string_field(&envelope, DataType::MessageType, &type_map)?;
    let application_type = validate_application_message_type(&message_type, &type_map)?;
    if frame.get_comm_type_enum() != Some(application_type) {
        return Err(ProtectedError::MessageTypeMismatch);
    }
    let final_recipient_id = u64::try_from(unsigned_field(
        &envelope,
        DataType::FinalRecipientId,
        &type_map,
    )?)
    .map_err(|_| ProtectedError::InvalidLayout("final recipient ID is out of range"))?;
    if final_recipient_id != receiver_id {
        return Err(ProtectedError::FinalRecipientMismatch);
    }
    let message_id = string_field(&envelope, DataType::MessageId, &type_map)?;
    let created_at = u64::try_from(unsigned_field(&envelope, DataType::CreatedAt, &type_map)?)
        .map_err(|_| ProtectedError::InvalidLayout("created-at value is out of range"))?;
    let content = field(&envelope, DataType::Content, &type_map)?.clone();

    if let Some(guard) = replay_guard.as_mut()
        && !guard.accept(signed.signer_id, &message_id, created_at)?
    {
        return Err(ProtectedError::Replay);
    }

    Ok(VerifiedProtectedMessage {
        protected_version: version,
        signer_id: signed.signer_id,
        final_recipient_id,
        message_id,
        created_at,
        message_type,
        content,
        matched_signer_key_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mtp_crypto::{Ed25519Signer, Keyring};
    use mtp_type_map::{DataType, DataTypeId};

    const SIGNATURE_PURPOSE: ProtectionPurpose = ProtectionPurpose(0x40);
    const ENCRYPTION_PURPOSE: ProtectionPurpose = ProtectionPurpose(0x41);

    fn open_options(expected_receiver_id: Option<u64>) -> ProtectedOpenOptions {
        ProtectedOpenOptions::new(
            expected_receiver_id,
            SIGNATURE_PURPOSE,
            ENCRYPTION_PURPOSE,
            ProtectionPolicy::from(crate::SignaturePolicy::Ed25519),
        )
    }

    #[derive(Default)]
    struct RecordingReplayGuard {
        created_at: Option<u64>,
        accepted: bool,
    }

    impl ReplayGuard for RecordingReplayGuard {
        fn accept(
            &mut self,
            _signer_id: u64,
            _message_id: &str,
            created_at: u64,
        ) -> Result<bool, ReplayError> {
            self.created_at = Some(created_at);
            if self.accepted {
                Ok(false)
            } else {
                self.accepted = true;
                Ok(true)
            }
        }
    }

    fn protected_field(data_type: DataType, type_map: &TypeMap) -> DataTypeId {
        data_type
            .try_to_id(type_map)
            .expect("protected type mapping")
    }

    fn envelope(
        type_map: &TypeMap,
        version: Option<u128>,
        message_type: &str,
        final_recipient_id: u64,
        message_id: &str,
        created_at: u64,
        content: DataValue,
    ) -> DataValue {
        let mut fields = Vec::new();
        if let Some(version) = version {
            fields.push((
                protected_field(DataType::ProtectedVersion, type_map),
                DataValue::UnsignedNumber(version),
            ));
        }
        fields.extend([
            (
                protected_field(DataType::MessageType, type_map),
                DataValue::Str(message_type.into()),
            ),
            (
                protected_field(DataType::FinalRecipientId, type_map),
                DataValue::UnsignedNumber(final_recipient_id as u128),
            ),
            (
                protected_field(DataType::MessageId, type_map),
                DataValue::Str(message_id.into()),
            ),
            (
                protected_field(DataType::CreatedAt, type_map),
                DataValue::UnsignedNumber(created_at as u128),
            ),
            (protected_field(DataType::Content, type_map), content),
        ]);
        DataValue::Container(fields)
    }

    fn encrypted_frame(
        envelope: DataValue,
        signer_keyring: &Keyring,
        signer_id: u64,
        recipient_keyring: &Keyring,
        receiver_id: Option<u64>,
        sender_id: Option<u64>,
    ) -> CommunicationValue {
        let type_map = TypeMap::latest();
        let application_type = CommunicationType::from_name("ProtectedMessage")
            .expect("ProtectedMessage communication type");
        let signer = Ed25519Signer::new(&signer_keyring.sig_cl_secret_key).expect("Ed25519 signer");
        let signed = envelope
            .sign(signer_id, SIGNATURE_PURPOSE, &signer)
            .expect("protected envelope signing");
        let encrypted = signed
            .encrypt_for(&[recipient_keyring.public_key_bundle()], ENCRYPTION_PURPOSE)
            .expect("protected envelope encryption");
        let mut frame = CommunicationValue::new_with_type_map(application_type, &type_map)
            .with_payload(encrypted);
        if let Some(receiver_id) = receiver_id {
            frame = frame.with_receiver(receiver_id);
        }
        if let Some(sender_id) = sender_id {
            frame = frame.with_sender(sender_id);
        }
        frame
    }

    fn valid_frame(
        signer_keyring: &Keyring,
        recipient_keyring: &Keyring,
        content: DataValue,
    ) -> CommunicationValue {
        ProtectedMessageBuilder::new(
            "ProtectedMessage",
            content,
            7,
            42,
            &Ed25519Signer::new(&signer_keyring.sig_cl_secret_key).expect("Ed25519 signer"),
            SIGNATURE_PURPOSE,
            ENCRYPTION_PURPOSE,
        )
        .message_id("protected-test")
        .created_at(1_700_000_000_000)
        .recipients(vec![recipient_keyring.public_key_bundle()])
        .build()
        .expect("protected frame")
    }

    #[test]
    fn protected_message_round_trips_and_rejects_replay() {
        let type_map = TypeMap::latest();
        let Some(application_type) = CommunicationType::from_name("ProtectedMessage") else {
            return;
        };
        if application_type.try_to_id(&type_map).is_none() {
            return;
        }

        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let signer = Ed25519Signer::new(&sender.sig_cl_secret_key).expect("Ed25519 signer");
        let frame = ProtectedMessageBuilder::new(
            "ProtectedMessage",
            DataValue::Str("hello".into()),
            7,
            42,
            &signer,
            SIGNATURE_PURPOSE,
            ENCRYPTION_PURPOSE,
        )
        .message_id("protected-test")
        .created_at(1_700_000_000_000)
        .recipients(vec![recipient.public_key_bundle()])
        .type_map(&type_map)
        .build()
        .expect("protected frame");

        let mut guard = RecordingReplayGuard::default();
        let opened = open_protected(
            &frame,
            &recipient,
            7,
            &sender.public_key_bundle(),
            open_options(Some(42)),
            Some(&mut guard),
        )
        .expect("protected message should open");
        assert_eq!(opened.message_type, "ProtectedMessage");
        assert_eq!(opened.message_id, "protected-test");
        assert_eq!(guard.created_at, Some(1_700_000_000_000));
        assert_eq!(opened.content, DataValue::Str("hello".into()));
        assert!(matches!(
            open_protected(
                &frame,
                &recipient,
                7,
                &sender.public_key_bundle(),
                open_options(Some(42)),
                Some(&mut guard),
            ),
            Err(ProtectedError::Replay)
        ));
    }

    #[test]
    fn builder_owns_outer_sender_and_frame_id() {
        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let signer = Ed25519Signer::new(&sender.sig_cl_secret_key).expect("Ed25519 signer");
        let frame = ProtectedMessageBuilder::new(
            "ProtectedMessage",
            DataValue::Str("hello".into()),
            7,
            42,
            &signer,
            SIGNATURE_PURPOSE,
            ENCRYPTION_PURPOSE,
        )
        .message_id("outer-fields")
        .created_at(123)
        .frame_id(99)
        .expose_sender(true)
        .recipients(vec![recipient.public_key_bundle()])
        .build()
        .expect("protected frame");

        assert_eq!(frame.id(), Some(99));
        assert_eq!(frame.sender(), Some(7));
        assert_eq!(frame.receiver(), Some(42));
        open_protected(
            &frame,
            &recipient,
            7,
            &sender.public_key_bundle(),
            open_options(Some(42)),
            None,
        )
        .expect("outer fields should verify");
    }

    #[test]
    fn protected_version_is_required_and_versioned() {
        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let type_map = TypeMap::latest();
        let missing = encrypted_frame(
            envelope(
                &type_map,
                None,
                "ProtectedMessage",
                42,
                "missing-version",
                123,
                DataValue::Str("hello".into()),
            ),
            &sender,
            7,
            &recipient,
            Some(42),
            None,
        );
        assert!(matches!(
            open_protected(
                &missing,
                &recipient,
                7,
                &sender.public_key_bundle(),
                open_options(Some(42)),
                None,
            ),
            Err(ProtectedError::MissingProtectedVersion)
        ));

        let unsupported = encrypted_frame(
            envelope(
                &type_map,
                Some((CURRENT_PROTECTED_VERSION + 1) as u128),
                "ProtectedMessage",
                42,
                "unsupported-version",
                123,
                DataValue::Str("hello".into()),
            ),
            &sender,
            7,
            &recipient,
            Some(42),
            None,
        );
        assert!(matches!(
            open_protected(
                &unsupported,
                &recipient,
                7,
                &sender.public_key_bundle(),
                open_options(Some(42)),
                None,
            ),
            Err(ProtectedError::UnsupportedProtectedVersion(2))
        ));
    }

    #[test]
    fn protected_builder_rejects_reserved_application_types() {
        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let signer = Ed25519Signer::new(&sender.sig_cl_secret_key).expect("Ed25519 signer");
        assert!(matches!(
            ProtectedMessageBuilder::new(
                "Ping",
                DataValue::Null,
                7,
                42,
                &signer,
                SIGNATURE_PURPOSE,
                ENCRYPTION_PURPOSE,
            )
            .message_id("reserved")
            .created_at(123)
            .recipients(vec![recipient.public_key_bundle()])
            .build(),
            Err(ProtectedError::ReservedApplicationType(type_name)) if type_name == "Ping"
        ));
    }

    #[test]
    fn protected_opening_rejects_type_and_receiver_tampering() {
        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let frame = valid_frame(&sender, &recipient, DataValue::Str("hello".into()));
        let alternate_type = CommunicationType::from_name("AlternateMessage");
        let Some(alternate_type) = alternate_type else {
            return;
        };
        let type_map = TypeMap::latest();
        let payload = frame.payload().clone();
        let changed_type = CommunicationValue::new_with_type_map(alternate_type, &type_map)
            .with_receiver(42)
            .with_payload(payload.clone());
        assert!(matches!(
            open_protected(
                &changed_type,
                &recipient,
                7,
                &sender.public_key_bundle(),
                open_options(None),
                None,
            ),
            Err(ProtectedError::MessageTypeMismatch)
        ));

        let changed_receiver = frame.clone().with_receiver(43);
        assert!(matches!(
            open_protected(
                &changed_receiver,
                &recipient,
                7,
                &sender.public_key_bundle(),
                open_options(None),
                None,
            ),
            Err(ProtectedError::FinalRecipientMismatch)
        ));

        let signed_recipient_mismatch = encrypted_frame(
            envelope(
                &type_map,
                Some(CURRENT_PROTECTED_VERSION as u128),
                "ProtectedMessage",
                43,
                "signed-recipient-mismatch",
                123,
                DataValue::Str("hello".into()),
            ),
            &sender,
            7,
            &recipient,
            Some(42),
            None,
        );
        assert!(matches!(
            open_protected(
                &signed_recipient_mismatch,
                &recipient,
                7,
                &sender.public_key_bundle(),
                open_options(None),
                None,
            ),
            Err(ProtectedError::FinalRecipientMismatch)
        ));

        assert!(matches!(
            open_protected(
                &frame,
                &recipient,
                7,
                &sender.public_key_bundle(),
                open_options(Some(43)),
                None,
            ),
            Err(ProtectedError::ExpectedReceiverMismatch)
        ));
    }

    #[test]
    fn protected_opening_validates_exposed_sender() {
        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let signer = Ed25519Signer::new(&sender.sig_cl_secret_key).expect("Ed25519 signer");
        let frame = ProtectedMessageBuilder::new(
            "ProtectedMessage",
            DataValue::Str("hello".into()),
            7,
            42,
            &signer,
            SIGNATURE_PURPOSE,
            ENCRYPTION_PURPOSE,
        )
        .message_id("sender-check")
        .created_at(123)
        .expose_sender(true)
        .recipients(vec![recipient.public_key_bundle()])
        .build()
        .expect("protected frame");
        open_protected(
            &frame,
            &recipient,
            7,
            &sender.public_key_bundle(),
            open_options(Some(42)),
            None,
        )
        .expect("matching exposed sender");
        assert!(matches!(
            open_protected(
                &frame.with_sender(8),
                &recipient,
                7,
                &sender.public_key_bundle(),
                open_options(Some(42)),
                None,
            ),
            Err(ProtectedError::SenderMismatch)
        ));
    }

    #[test]
    fn protected_opening_rejects_unsigned_and_unencrypted_payloads() {
        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let type_map = TypeMap::latest();
        let application_type = CommunicationType::from_name("ProtectedMessage")
            .expect("ProtectedMessage communication type");
        let type_map_frame = |payload: DataValue| {
            CommunicationValue::new_with_type_map(application_type, &type_map)
                .with_receiver(42)
                .with_payload(payload)
        };
        let signer = Ed25519Signer::new(&sender.sig_cl_secret_key).expect("Ed25519 signer");
        let envelope = envelope(
            &type_map,
            Some(CURRENT_PROTECTED_VERSION as u128),
            "ProtectedMessage",
            42,
            "payload-shape",
            123,
            DataValue::Str("hello".into()),
        );
        let signed = envelope
            .clone()
            .sign(7, SIGNATURE_PURPOSE, &signer)
            .expect("signing");
        assert!(matches!(
            open_protected(
                &type_map_frame(signed),
                &recipient,
                7,
                &sender.public_key_bundle(),
                open_options(Some(42)),
                None,
            ),
            Err(ProtectedError::PayloadNotEncrypted)
        ));
        let encrypted_unsigned = DataValue::Str("not signed".into())
            .encrypt_for(&[recipient.public_key_bundle()], ENCRYPTION_PURPOSE)
            .expect("encryption");
        assert!(matches!(
            open_protected(
                &type_map_frame(encrypted_unsigned),
                &recipient,
                7,
                &sender.public_key_bundle(),
                open_options(Some(42)),
                None,
            ),
            Err(ProtectedError::PayloadNotSigned)
        ));
    }

    #[test]
    fn protected_opening_checks_expected_signer_before_resolving_keys() {
        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let frame = valid_frame(&sender, &recipient, DataValue::Str("hello".into()));
        let mut resolver_calls = 0;
        let result = open_protected_with(
            &frame,
            &[&recipient],
            Some(99),
            |_| {
                resolver_calls += 1;
                Some(vec![sender.public_key_bundle()])
            },
            open_options(Some(42)),
            None,
        );
        assert!(matches!(
            result,
            Err(ProtectedError::Protection(
                ProtectionError::SignerIdMismatch {
                    expected: 99,
                    actual: 7,
                }
            ))
        ));
        assert_eq!(resolver_calls, 0);
    }

    #[test]
    fn protected_opening_accepts_signer_and_recipient_key_history() {
        let old_sender = Keyring::generate();
        let current_sender = Keyring::generate();
        let current_recipient = Keyring::generate();
        let old_recipient = Keyring::generate();
        let signer = Ed25519Signer::new(&old_sender.sig_cl_secret_key).expect("Ed25519 signer");
        let frame = ProtectedMessageBuilder::new(
            "ProtectedMessage",
            DataValue::Str("rotated".into()),
            7,
            42,
            &signer,
            SIGNATURE_PURPOSE,
            ENCRYPTION_PURPOSE,
        )
        .message_id("history")
        .created_at(123)
        .recipients(vec![old_recipient.public_key_bundle()])
        .build()
        .expect("protected frame");

        let opened = open_protected_with_keys(
            &frame,
            &[&current_recipient, &old_recipient],
            7,
            &[
                current_sender.public_key_bundle(),
                old_sender.public_key_bundle(),
            ],
            open_options(Some(42)),
            None,
        )
        .expect("key history should open");
        assert_eq!(opened.matched_signer_key_index, 1);
        assert_eq!(opened.content, DataValue::Str("rotated".into()));
    }

    #[test]
    fn protected_opening_accepts_arbitrary_application_values() {
        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let frame = valid_frame(
            &sender,
            &recipient,
            DataValue::Array(vec![
                DataValue::Str("value".into()),
                DataValue::UnsignedNumber(7),
                DataValue::Bytes(vec![1, 2, 3]),
            ]),
        );
        let opened = open_protected(
            &frame,
            &recipient,
            7,
            &sender.public_key_bundle(),
            open_options(Some(42)),
            None,
        )
        .expect("arbitrary application value should open");
        assert_eq!(
            opened.content,
            DataValue::Array(vec![
                DataValue::Str("value".into()),
                DataValue::UnsignedNumber(7),
                DataValue::Bytes(vec![1, 2, 3]),
            ])
        );
    }
}
