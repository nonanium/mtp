use super::*;
use crate::InMemoryReplayGuard;
use mtp_crypto::{Ed25519Signer, Keyring, PublicKeyBundle};
use mtp_type_map::DataTypeId;

fn ed_signer(keyring: &Keyring) -> Ed25519Signer {
    Ed25519Signer::new(&keyring.sig_cl_secret_key).expect("Ed25519 signer")
}

fn content_open_options(
    metadata: &VerifiedRelayMetadata,
    policy: ProtectionPolicy,
) -> RelayOpenOptions {
    RelayOpenOptions {
        policy,
        decode_limits: metadata.decode_limits,
        encode_limits: metadata.encode_limits,
        protected_limits: metadata.protected_limits,
    }
}

// Test-only compatibility shims keep older fixture setup readable while
// routing every invocation to an explicit replay choice in production.
fn open_relay_metadata(
    frame: &CommunicationValue,
    keyring: &Keyring,
    expected_signer_id: u64,
    signer_public_key: &PublicKeyBundle,
    policy: ProtectionPolicy,
) -> Result<VerifiedRelayMetadata, RelayError> {
    super::open_relay_metadata_without_replay(
        frame,
        keyring,
        expected_signer_id,
        signer_public_key,
        RelayOpenOptions::new(policy),
    )
}

fn open_relay_metadata_with<F>(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    expected_signer_id: Option<u64>,
    resolve_signer_keys: F,
    policy: ProtectionPolicy,
    replay_guard: Option<&mut dyn ReplayGuard>,
) -> Result<VerifiedRelayMetadata, RelayError>
where
    F: Fn(u64) -> Option<Vec<PublicKeyBundle>>,
{
    match replay_guard {
        Some(replay_guard) => super::open_relay_metadata_with_checked(
            frame,
            keyrings,
            expected_signer_id,
            resolve_signer_keys,
            RelayOpenOptions::new(policy),
            replay_guard,
        ),
        None => super::open_relay_metadata_with_without_replay(
            frame,
            keyrings,
            expected_signer_id,
            resolve_signer_keys,
            RelayOpenOptions::new(policy),
        ),
    }
}

fn open_relay_metadata_with_keys(
    frame: &CommunicationValue,
    keyrings: &[&Keyring],
    expected_signer_id: u64,
    signer_public_keys: &[PublicKeyBundle],
    policy: ProtectionPolicy,
) -> Result<VerifiedRelayMetadata, RelayError> {
    let signer_public_keys = signer_public_keys.to_vec();
    super::open_relay_metadata_with_limits_without_replay(
        frame,
        keyrings,
        Some(expected_signer_id),
        move |_| Some(signer_public_keys),
        RelayOpenOptions::new(policy),
    )
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
    fields.push((
        relay_field(DataType::DictionaryFingerprint, &type_map).unwrap(),
        DataValue::Bytes(type_map.fingerprint().unwrap().to_vec()),
    ));
    if let Some(version) = version {
        fields.push((
            relay_field(DataType::RelayVersion, &type_map).expect("RelayVersion mapping"),
            DataValue::UnsignedNumber(version as u128),
        ));
    }
    if include_v1_fields {
        let content = DataValue::Container(vec![
            (
                relay_field(DataType::DictionaryFingerprint, &type_map).unwrap(),
                DataValue::Bytes(type_map.fingerprint().unwrap().to_vec()),
            ),
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
                DataValue::UnsignedNumber(1),
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
    let frame = relay_frame_with_version(Some(CURRENT_RELAY_VERSION), true, &sender, &recipient);
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
        CommunicationType::ProtectedMessage,
        DataValue::Str("timestamp content".into()),
        11,
        42,
        42,
        &signer,
    )
    .message_id(1u128)
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
        CommunicationType::ProtectedMessage,
        DataValue::Str("hello".into()),
        7,
        42,
        9,
        &signer,
    )
    .message_id(1u128)
    .created_at(123)
    .metadata(application_metadata.clone())
    .metadata_recipients(vec![
        metadata_recipient.public_key_bundle(),
        final_recipient.public_key_bundle(),
    ])
    .content_recipients(vec![final_recipient.public_key_bundle()])
    .build()
    .expect("relay frame");
    let frame = CommunicationValue::from_bytes(&frame.to_bytes().expect("relay frame encoding"))
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
    assert_eq!(metadata.message_id(), MessageId::new(1));
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
    let final_content = open_relay_content_with_limits_without_replay(
        &final_metadata,
        &[&final_recipient],
        std::slice::from_ref(&sender.public_key_bundle()),
        Some(42),
        content_open_options(&final_metadata, policy),
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
        open_relay_content_with_limits_without_replay(
            &metadata,
            &[&metadata_recipient],
            std::slice::from_ref(&sender.public_key_bundle()),
            Some(42),
            content_open_options(&metadata, policy),
        )
        .is_err()
    );

    let content = open_relay_content_with_limits_without_replay(
        &metadata,
        &[&final_recipient],
        std::slice::from_ref(&sender.public_key_bundle()),
        Some(42),
        content_open_options(&metadata, policy),
    )
    .expect("content");
    assert_eq!(content.signer_id, 7);
    assert_eq!(content.final_recipient_id, 42);
    assert_eq!(content.message_type, CommunicationType::ProtectedMessage);
    assert_eq!(content.content, DataValue::Str("hello".into()));
    assert!(matches!(
        open_relay_content_with_limits_without_replay(
            &metadata,
            &[&final_recipient],
            std::slice::from_ref(&sender.public_key_bundle()),
            Some(43),
            content_open_options(&metadata, policy),
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
        let frame = SealedRelayBuilder::new(
            CommunicationType::ProtectedMessage,
            DataValue::Null,
            7,
            42,
            9,
            &signer,
        )
        .message_id(index as u128)
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

    let absent = SealedRelayBuilder::new(
        CommunicationType::ProtectedMessage,
        DataValue::Null,
        7,
        42,
        9,
        &signer,
    )
    .message_id(100u128)
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
        CommunicationType::ProtectedMessage,
        DataValue::Str("hello".into()),
        7,
        42,
        9,
        &signer,
    )
    .message_id(101u128)
    .created_at(123)
    .metadata_recipients(vec![recipient.public_key_bundle()])
    .content_recipients(vec![recipient.public_key_bundle()])
    .build()
    .expect("relay frame");

    assert_eq!(
        relay_metadata_claimed_signer_id_with_limits(
            &frame,
            &[&recipient],
            DecodeLimits::default(),
        )
        .expect("signer ID"),
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
    let content = open_relay_content_with_limits_without_replay(
        &metadata,
        &[&recipient],
        &[sender.public_key_bundle()],
        Some(42),
        content_open_options(
            &metadata,
            ProtectionPolicy::from(crate::SignaturePolicy::Ed25519),
        ),
    )
    .expect("relay content");

    assert_eq!(content.signer_id, 7);
    assert_eq!(content.final_recipient_id, 42);
    assert_eq!(content.message_type, CommunicationType::ProtectedMessage);
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
        CommunicationType::ProtectedMessage,
        DataValue::Str("opened with a previous recipient key".into()),
        7,
        42,
        9,
        &signer,
    )
    .message_id(102u128)
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

    let content = open_relay_content_with_limits_without_replay(
        &metadata,
        &[&current_content_recipient, &previous_content_recipient],
        &[sender.public_key_bundle()],
        Some(42),
        content_open_options(&metadata, policy),
    )
    .expect("previous content recipient key should decrypt");

    assert_eq!(content.signer_id, 7);
    assert_eq!(content.final_recipient_id, 42);
    assert_eq!(content.message_type, CommunicationType::ProtectedMessage);
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
    let frame = SealedRelayBuilder::new(
        CommunicationType::ProtectedMessage,
        DataValue::Null,
        7,
        42,
        9,
        &signer,
    )
    .message_id(2u128)
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
    let frame = SealedRelayBuilder::new(
        CommunicationType::ProtectedMessage,
        DataValue::Null,
        7,
        42,
        9,
        &signer,
    )
    .message_id(3u128)
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
        CommunicationType::ProtectedMessage,
        DataValue::Str("signed with the previous key".into()),
        77,
        42,
        9,
        &old_signer,
    )
    .message_id(4u128)
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
    let content = open_relay_content_with_limits_without_replay(
        &metadata,
        &[&recipient],
        &[current_signer_public, old_signer_public],
        Some(42),
        content_open_options(&metadata, policy),
    )
    .expect("content signed by a previous key should verify");
    assert_eq!(content.message_type, CommunicationType::ProtectedMessage);
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
    let frame = SealedRelayBuilder::new(
        CommunicationType::ProtectedMessage,
        DataValue::Null,
        7,
        42,
        9,
        &signer,
    )
    .message_id(5u128)
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
    let result =
        SealedRelayBuilder::new(CommunicationType::Ping, DataValue::Null, 7, 42, 9, &signer)
            .message_id(6u128)
            .created_at(123)
            .metadata_recipients(vec![recipient.public_key_bundle()])
            .content_recipients(vec![recipient.public_key_bundle()])
            .build();

    assert!(matches!(
        result,
        Err(RelayError::ReservedApplicationType(type_name)) if type_name == "Ping"
    ));
}
