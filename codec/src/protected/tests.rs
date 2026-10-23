use super::*;
use mtp_crypto::{Ed25519Signer, Keyring, PublicKeyBundle};
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

// Keep the existing test cases concise while making the production API
// choice explicit: every call below is routed to either the checked or
// the named without-replay entry point.
fn open_protected(
    frame: &CommunicationValue,
    keyring: &Keyring,
    expected_signer_id: u64,
    signer_public_key: &PublicKeyBundle,
    options: ProtectedOpenOptions,
    replay_guard: Option<&mut dyn ReplayGuard>,
) -> Result<VerifiedProtectedMessage, ProtectedError> {
    match replay_guard {
        Some(replay_guard) => super::open_protected_checked(
            frame,
            keyring,
            expected_signer_id,
            signer_public_key,
            options,
            replay_guard,
        ),
        None => super::open_protected_without_replay(
            frame,
            keyring,
            expected_signer_id,
            signer_public_key,
            options,
        ),
    }
}

fn open_protected_with<F>(
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
    match replay_guard {
        Some(replay_guard) => super::open_protected_with_checked(
            frame,
            keyrings,
            expected_signer_id,
            resolve_signer_keys,
            options,
            replay_guard,
        ),
        None => super::open_protected_with_without_replay(
            frame,
            keyrings,
            expected_signer_id,
            resolve_signer_keys,
            options,
        ),
    }
}

fn open_protected_with_keys(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    expected_signer_id: u64,
    signer_public_keys: &[PublicKeyBundle],
    options: ProtectedOpenOptions,
    replay_guard: Option<&mut dyn ReplayGuard>,
) -> Result<VerifiedProtectedMessage, ProtectedError> {
    match replay_guard {
        Some(replay_guard) => super::open_protected_with_keys_checked(
            frame,
            keyrings,
            expected_signer_id,
            signer_public_keys,
            options,
            replay_guard,
        ),
        None => super::open_protected_with_keys_without_replay(
            frame,
            keyrings,
            expected_signer_id,
            signer_public_keys,
            options,
        ),
    }
}

#[derive(Default)]
struct RecordingReplayGuard {
    created_at: Option<u64>,
    accepted: bool,
    calls: usize,
}

impl ReplayGuard for RecordingReplayGuard {
    fn accept(
        &mut self,
        _signer_id: u64,
        _message_id: MessageId,
        created_at: u64,
    ) -> Result<bool, ReplayError> {
        self.calls += 1;
        self.created_at = Some(created_at);
        if self.accepted {
            Ok(false)
        } else {
            self.accepted = true;
            Ok(true)
        }
    }
}

#[test]
fn in_memory_replay_guard_is_bounded_and_deduplicates() {
    let mut guard = InMemoryReplayGuard::with_capacity(2);
    assert!(
        guard
            .accept(7, MessageId::new(1), 1)
            .expect("first replay decision")
    );
    assert!(
        guard
            .accept(7, MessageId::new(2), 2)
            .expect("second replay decision")
    );
    assert!(
        !guard
            .accept(7, MessageId::new(1), 3)
            .expect("duplicate replay decision")
    );
    assert_eq!(guard.len(), 2);

    assert!(
        guard
            .accept(7, MessageId::new(3), 4)
            .expect("third replay decision")
    );
    assert_eq!(guard.len(), 2);
    assert!(
        guard
            .accept(7, MessageId::new(1), 5)
            .expect("evicted replay decision")
    );

    let mut disabled = InMemoryReplayGuard::with_capacity(0);
    assert!(
        !disabled
            .accept(7, MessageId::new(1), 1)
            .expect("disabled replay decision")
    );
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
    message_id: u128,
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
            DataValue::UnsignedNumber(message_id),
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
    let mut frame =
        CommunicationValue::new_with_type_map(application_type, &type_map).with_payload(encrypted);
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
        CommunicationType::ProtectedMessage,
        content,
        7,
        42,
        &Ed25519Signer::new(&signer_keyring.sig_cl_secret_key).expect("Ed25519 signer"),
        SIGNATURE_PURPOSE,
        ENCRYPTION_PURPOSE,
    )
    .message_id(1u128)
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
        CommunicationType::ProtectedMessage,
        DataValue::Str("hello".into()),
        7,
        42,
        &signer,
        SIGNATURE_PURPOSE,
        ENCRYPTION_PURPOSE,
    )
    .message_id(1u128)
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
    assert_eq!(opened.message_type, CommunicationType::ProtectedMessage);
    assert_eq!(opened.message_id(), MessageId::new(1));
    assert_eq!(guard.created_at, Some(1_700_000_000_000));
    assert_eq!(guard.calls, 1);
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
fn string_message_id_is_rejected_before_replay_guard() {
    let sender = Keyring::generate();
    let recipient = Keyring::generate();
    let options = open_options(Some(42));
    let type_map = TypeMap::latest();
    let mut envelope = envelope(
        &type_map,
        Some(CURRENT_PROTECTED_VERSION as u128),
        "ProtectedMessage",
        42,
        1,
        123,
        DataValue::Str("hello".into()),
    );
    let DataValue::Container(fields) = &mut envelope else {
        unreachable!("test envelope is a container");
    };
    let message_id_id = protected_field(DataType::MessageId, &type_map);
    fields
        .iter_mut()
        .find(|(id, _)| *id == message_id_id)
        .expect("message ID field")
        .1 = DataValue::Str("old-string-id".into());
    let frame = encrypted_frame(envelope, &sender, 7, &recipient, Some(42), None);
    let mut guard = RecordingReplayGuard::default();

    assert!(matches!(
        open_protected_checked(
            &frame,
            &recipient,
            7,
            &sender.public_key_bundle(),
            options,
            &mut guard,
        ),
        Err(ProtectedError::InvalidLayout(
            "protected message ID is not unsigned"
        ))
    ));
    assert_eq!(guard.calls, 0);
}

#[test]
fn builder_owns_outer_sender_and_frame_id() {
    let sender = Keyring::generate();
    let recipient = Keyring::generate();
    let signer = Ed25519Signer::new(&sender.sig_cl_secret_key).expect("Ed25519 signer");
    let frame = ProtectedMessageBuilder::new(
        CommunicationType::ProtectedMessage,
        DataValue::Str("hello".into()),
        7,
        42,
        &signer,
        SIGNATURE_PURPOSE,
        ENCRYPTION_PURPOSE,
    )
    .message_id(2u128)
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
            10,
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
            11,
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
            CommunicationType::Ping,
            DataValue::Null,
            7,
            42,
            &signer,
            SIGNATURE_PURPOSE,
            ENCRYPTION_PURPOSE,
        )
        .message_id(3u128)
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
            12,
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
        CommunicationType::ProtectedMessage,
        DataValue::Str("hello".into()),
        7,
        42,
        &signer,
        SIGNATURE_PURPOSE,
        ENCRYPTION_PURPOSE,
    )
    .message_id(4u128)
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
        13,
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
        CommunicationType::ProtectedMessage,
        DataValue::Str("rotated".into()),
        7,
        42,
        &signer,
        SIGNATURE_PURPOSE,
        ENCRYPTION_PURPOSE,
    )
    .message_id(5u128)
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
