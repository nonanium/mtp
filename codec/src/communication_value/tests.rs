use super::*;
use crate::data_value::{MergeConflictPolicy, MergePath};

#[test]
fn canonical_flags_and_eight_byte_ids_roundtrip() {
    const SENDER_ID: u64 = 0x0102_0304_0506_0708;
    const RECEIVER_ID: u64 = 0x1112_1314_1516_1718;

    let cases = [
        (
            CommunicationValue::new(CommunicationType::Ping)
                .with_id(0x0102_0304)
                .without_sender()
                .without_receiver(),
            0x01,
        ),
        (
            CommunicationValue::new(CommunicationType::Ping)
                .without_id()
                .with_sender(SENDER_ID)
                .without_receiver(),
            0x02,
        ),
        (
            CommunicationValue::new(CommunicationType::Ping)
                .without_id()
                .without_sender()
                .with_receiver(RECEIVER_ID),
            0x04,
        ),
        (
            CommunicationValue::new(CommunicationType::Ping)
                .with_id(0)
                .with_sender(SENDER_ID)
                .with_receiver(RECEIVER_ID),
            0x07,
        ),
    ];

    for (value, expected_flags) in cases {
        let bytes = value.to_bytes().unwrap();
        assert_eq!(bytes[6], expected_flags);
        if expected_flags == FLAG_HAS_SENDER {
            assert_eq!(&bytes[7..15], &SENDER_ID.to_be_bytes());
        }
        if expected_flags == FLAG_HAS_RECEIVER {
            assert_eq!(&bytes[7..15], &RECEIVER_ID.to_be_bytes());
        }
        assert_eq!(CommunicationValue::from_bytes(&bytes).unwrap(), value);
    }
}

#[test]
fn absent_and_zero_are_distinct() {
    let absent = CommunicationValue::new(CommunicationType::Ping).without_id();
    let zero = CommunicationValue::new(CommunicationType::Ping).with_id(0);
    assert!(absent.id().is_none());
    assert_eq!(zero.id(), Some(0));
    assert_ne!(absent.to_bytes().unwrap(), zero.to_bytes().unwrap());
}

#[test]
fn reserved_flags_are_rejected() {
    let bytes = CommunicationValue::new(CommunicationType::Ping)
        .to_bytes()
        .unwrap();
    for unknown_flag in [0x08, 0x10, 0x20, 0x40, 0x80] {
        let mut invalid = bytes.clone();
        invalid[6] |= unknown_flag;
        assert_eq!(
            CommunicationValue::from_bytes(&invalid),
            Err(CodecError::InvalidEncoding),
            "flag bit {unknown_flag:#04x} must be rejected"
        );
    }
}

#[test]
fn protected_or_scalar_payload_is_not_treated_as_data() {
    let frame =
        CommunicationValue::new(CommunicationType::Ping).with_payload(DataValue::Bytes(vec![1]));
    assert!(frame.data().is_none());
    assert_eq!(frame.get_data(DataType::Version), None);
}

#[test]
fn replies_retain_the_request_type_map() {
    let type_map = TypeMap::new(mtp_type_map::Version::new(3, 0));
    let request = CommunicationValue::new_with_type_map(CommunicationType::Ping, &type_map)
        .with_sender(7)
        .with_receiver(9);
    let reply = request.reply_to(CommunicationType::Pong);

    assert_eq!(
        reply.type_map().map(|map| &map.version),
        Some(&type_map.version)
    );
    assert_eq!(reply.sender(), Some(9));
    assert_eq!(reply.receiver(), Some(7));
}

#[test]
#[allow(deprecated)]
fn try_merge_rejects_frames_from_different_type_maps() {
    let left_map = TypeMap::new(mtp_type_map::Version::new(3, 0));
    let right_map = TypeMap::new(mtp_type_map::Version::new(4, 0));
    let mut left = CommunicationValue::new_with_type_map(CommunicationType::Ping, &left_map);
    let right = CommunicationValue::new_with_type_map(CommunicationType::Ping, &right_map);

    assert_eq!(
        left.try_merge(&right),
        Err(CodecError::TypeMapMismatch {
            expected: "3.0".into(),
            actual: "4.0".into(),
        })
    );
    assert_eq!(left.data_len(), 0);
}

#[test]
fn merge_payload_is_left_biased_and_preserves_order() {
    let mut left =
        CommunicationValue::new(CommunicationType::Ping).with_payload(DataValue::Container(vec![
            (DataTypeId(2), DataValue::UnsignedNumber(2)),
            (DataTypeId(1), DataValue::UnsignedNumber(1)),
        ]));
    let right =
        CommunicationValue::new(CommunicationType::Ping).with_payload(DataValue::Container(vec![
            (DataTypeId(3), DataValue::UnsignedNumber(3)),
            (DataTypeId(1), DataValue::UnsignedNumber(99)),
            (DataTypeId(4), DataValue::UnsignedNumber(4)),
        ]));

    let report = left.try_merge_payload_from(&right).unwrap();

    assert_eq!(
        report.inserted,
        vec![
            MergePath::new(vec![DataTypeId(3)]),
            MergePath::new(vec![DataTypeId(4)])
        ]
    );
    assert_eq!(report.preserved, vec![MergePath::new(vec![DataTypeId(1)])]);
    assert_eq!(
        left.data(),
        Some(
            &[
                (DataTypeId(2), DataValue::UnsignedNumber(2)),
                (DataTypeId(1), DataValue::UnsignedNumber(1)),
                (DataTypeId(3), DataValue::UnsignedNumber(3)),
                (DataTypeId(4), DataValue::UnsignedNumber(4)),
            ][..]
        )
    );
}

#[test]
fn bounded_frame_merge_uses_complete_frame_size_limits() {
    let payload = DataValue::Container(vec![(DataTypeId(1), DataValue::BoolTrue)]);
    let mut destination = CommunicationValue::new(CommunicationType::Ping)
        .with_id(7)
        .with_payload(payload.clone());
    let source = CommunicationValue::new(CommunicationType::Ping)
        .with_id(7)
        .with_payload(DataValue::Container(Vec::new()));
    let before = destination.clone();
    let limits = EncodeLimits {
        // The payload is six bytes alone, but this frame has an eleven-byte
        // header and therefore cannot fit into sixteen bytes.
        max_output_size: 16,
        ..EncodeLimits::default()
    };

    assert!(payload.to_bytes_with_limits(limits).is_ok());
    assert!(destination.to_bytes_with_limits(limits).is_err());
    assert!(
        destination
            .try_merge_payload_from_with_limits(&source, MergeOptions::default(), limits)
            .is_err()
    );
    assert_eq!(destination, before);
}

#[test]
fn merge_payload_rejects_malformed_containers_without_mutating_destination() {
    let original = DataValue::Container(vec![(DataTypeId(1), DataValue::BoolTrue)]);
    let mut left = CommunicationValue::new(CommunicationType::Ping).with_payload(original.clone());
    let right =
        CommunicationValue::new(CommunicationType::Ping).with_payload(DataValue::Container(vec![
            (DataTypeId(2), DataValue::BoolTrue),
            (DataTypeId(2), DataValue::BoolFalse),
        ]));

    assert_eq!(
        left.try_merge_payload_from(&right),
        Err(MergeError::Container(
            ContainerMergeError::SourceDuplicateField(DataTypeId(2))
        ))
    );
    assert_eq!(left.payload(), &original);

    let malformed_left = DataValue::Container(vec![
        (DataTypeId(3), DataValue::BoolTrue),
        (DataTypeId(3), DataValue::BoolFalse),
    ]);
    let mut left =
        CommunicationValue::new(CommunicationType::Ping).with_payload(malformed_left.clone());
    let right =
        CommunicationValue::new(CommunicationType::Ping).with_payload(DataValue::Container(vec![
            (DataTypeId(4), DataValue::BoolTrue),
        ]));
    assert_eq!(
        left.try_merge_payload_from(&right),
        Err(MergeError::Container(
            ContainerMergeError::DestinationDuplicateField(DataTypeId(3))
        ))
    );
    assert_eq!(left.payload(), &malformed_left);
}

#[test]
fn merge_payload_rejects_nested_malformed_source_without_mutating_destination() {
    let original = DataValue::Container(vec![(DataTypeId(1), DataValue::BoolTrue)]);
    let mut left = CommunicationValue::new(CommunicationType::Ping).with_payload(original.clone());
    let right =
        CommunicationValue::new(CommunicationType::Ping).with_payload(DataValue::Container(vec![
            (
                DataTypeId(2),
                DataValue::Container(vec![
                    (DataTypeId(3), DataValue::BoolTrue),
                    (DataTypeId(3), DataValue::BoolFalse),
                ]),
            ),
        ]));

    assert_eq!(
        left.try_merge_payload_from(&right),
        Err(MergeError::Container(
            ContainerMergeError::InvalidStructure(CodecError::InvalidEncoding)
        ))
    );
    assert_eq!(left.payload(), &original);

    let malformed_destination = DataValue::Container(vec![(
        DataTypeId(4),
        DataValue::Container(vec![
            (DataTypeId(5), DataValue::BoolTrue),
            (DataTypeId(5), DataValue::BoolFalse),
        ]),
    )]);
    let mut left = CommunicationValue::new(CommunicationType::Ping)
        .with_payload(malformed_destination.clone());
    let right =
        CommunicationValue::new(CommunicationType::Ping).with_payload(DataValue::Container(vec![
            (DataTypeId(6), DataValue::BoolTrue),
        ]));
    assert_eq!(
        left.try_merge_payload_from(&right),
        Err(MergeError::Container(
            ContainerMergeError::InvalidStructure(CodecError::InvalidEncoding)
        ))
    );
    assert_eq!(left.payload(), &malformed_destination);
}

#[test]
fn merge_payload_policies_and_recursion_are_explicit() {
    let left_payload = DataValue::Container(vec![(
        DataTypeId(1),
        DataValue::Container(vec![(DataTypeId(2), DataValue::UnsignedNumber(2))]),
    )]);
    let right =
        CommunicationValue::new(CommunicationType::Ping).with_payload(DataValue::Container(vec![
            (
                DataTypeId(1),
                DataValue::Container(vec![
                    (DataTypeId(2), DataValue::UnsignedNumber(99)),
                    (DataTypeId(3), DataValue::UnsignedNumber(3)),
                ]),
            ),
        ]));

    let mut shallow =
        CommunicationValue::new(CommunicationType::Ping).with_payload(left_payload.clone());
    shallow.try_merge_payload_from(&right).unwrap();
    assert_eq!(shallow.payload(), &left_payload);

    let mut recursive = CommunicationValue::new(CommunicationType::Ping).with_payload(left_payload);
    let report = recursive
        .try_merge_payload_from_with(
            &right,
            MergeOptions {
                conflicts: MergeConflictPolicy::KeepLeft,
                recursive_containers: true,
            },
        )
        .unwrap();
    assert_eq!(
        report.inserted,
        vec![MergePath::new(vec![DataTypeId(1), DataTypeId(3)])]
    );
    assert_eq!(
        report.preserved,
        vec![MergePath::new(vec![DataTypeId(1), DataTypeId(2)])]
    );
    assert_eq!(report.recursed, vec![MergePath::new(vec![DataTypeId(1)])]);

    let mut replacing =
        CommunicationValue::new(CommunicationType::Ping).with_payload(DataValue::Container(vec![
            (DataTypeId(4), DataValue::BoolTrue),
        ]));
    let replacement =
        CommunicationValue::new(CommunicationType::Ping).with_payload(DataValue::Container(vec![
            (DataTypeId(4), DataValue::BoolFalse),
        ]));
    assert_eq!(
        replacing
            .try_merge_payload_from_with(
                &replacement,
                MergeOptions {
                    conflicts: MergeConflictPolicy::RequireEqual,
                    recursive_containers: false,
                },
            )
            .unwrap_err(),
        MergeError::Container(ContainerMergeError::Conflict(MergePath::new(vec![
            DataTypeId(4)
        ])))
    );
    let report = replacing
        .try_merge_payload_from_with(
            &replacement,
            MergeOptions {
                conflicts: MergeConflictPolicy::KeepRight,
                recursive_containers: false,
            },
        )
        .unwrap();
    assert_eq!(report.replaced, vec![MergePath::new(vec![DataTypeId(4)])]);

    let mut equal =
        CommunicationValue::new(CommunicationType::Ping).with_payload(DataValue::Container(vec![
            (DataTypeId(5), DataValue::BoolTrue),
        ]));
    let equal_source =
        CommunicationValue::new(CommunicationType::Ping).with_payload(DataValue::Container(vec![
            (DataTypeId(5), DataValue::BoolTrue),
        ]));
    assert_eq!(
        equal
            .try_merge_payload_from_with(
                &equal_source,
                MergeOptions {
                    conflicts: MergeConflictPolicy::RequireEqual,
                    recursive_containers: false,
                },
            )
            .unwrap()
            .matched,
        vec![MergePath::new(vec![DataTypeId(5)])]
    );
    assert_eq!(
        equal
            .try_merge_payload_from_with(
                &equal_source,
                MergeOptions {
                    conflicts: MergeConflictPolicy::Reject,
                    recursive_containers: false,
                },
            )
            .unwrap_err(),
        MergeError::Container(ContainerMergeError::Conflict(MergePath::new(vec![
            DataTypeId(5)
        ])))
    );
}

#[test]
fn merge_payload_rejects_incompatible_frame_metadata() {
    let mut left = CommunicationValue::new(CommunicationType::Ping).with_sender(7);
    let different_type = CommunicationValue::new(CommunicationType::Pong);
    assert_eq!(
        left.try_merge_payload_from(&different_type),
        Err(MergeError::CommunicationTypeMismatch)
    );

    let different_sender = CommunicationValue::new(CommunicationType::Ping).with_sender(8);
    assert_eq!(
        left.try_merge_payload_from(&different_sender),
        Err(MergeError::SenderMismatch)
    );

    let receiver_left = CommunicationValue::new(CommunicationType::Ping).with_receiver(7);
    let receiver_right = CommunicationValue::new(CommunicationType::Ping).with_receiver(8);
    assert_eq!(
        receiver_left
            .clone()
            .try_merge_payload_from(&receiver_right),
        Err(MergeError::ReceiverMismatch)
    );
}

#[test]
fn merge_payload_keeps_destination_frame_id() {
    let mut left = CommunicationValue::new(CommunicationType::Ping)
        .with_id(123)
        .with_payload(DataValue::Container(vec![]));
    let right = CommunicationValue::new(CommunicationType::Ping)
        .with_id(456)
        .with_payload(DataValue::Container(vec![(
            DataTypeId(1),
            DataValue::BoolTrue,
        )]));

    left.try_merge_payload_from(&right).unwrap();
    assert_eq!(left.id(), Some(123));
}

#[test]
fn default_merge_is_identity_for_empty_and_idempotent_for_same_source() {
    let mut destination =
        CommunicationValue::new(CommunicationType::Ping).with_payload(DataValue::Container(vec![
            (DataTypeId(1), DataValue::BoolTrue),
        ]));
    let empty = CommunicationValue::new(CommunicationType::Ping);
    assert_eq!(
        destination.try_merge_payload_from(&empty).unwrap(),
        MergeReport::default()
    );

    let source =
        CommunicationValue::new(CommunicationType::Ping).with_payload(DataValue::Container(vec![
            (DataTypeId(2), DataValue::BoolFalse),
        ]));
    destination.try_merge_payload_from(&source).unwrap();
    let once = destination.payload().clone();
    destination.try_merge_payload_from(&source).unwrap();
    assert_eq!(destination.payload(), &once);
}

#[test]
fn merge_payload_rejects_non_container_payloads() {
    let mut scalar_left =
        CommunicationValue::new(CommunicationType::Ping).with_payload(DataValue::BoolTrue);
    let container = CommunicationValue::new(CommunicationType::Ping);
    assert_eq!(
        scalar_left.try_merge_payload_from(&container),
        Err(MergeError::LeftPayloadNotContainer)
    );

    let mut container_left = CommunicationValue::new(CommunicationType::Ping);
    let scalar_right =
        CommunicationValue::new(CommunicationType::Ping).with_payload(DataValue::BoolTrue);
    assert_eq!(
        container_left.try_merge_payload_from(&scalar_right),
        Err(MergeError::RightPayloadNotContainer)
    );
}

#[test]
fn generic_payload_roundtrips_without_becoming_a_container() {
    let payload = DataValue::Array(vec![
        DataValue::Str("arbitrary".into()),
        DataValue::UnsignedNumber(7),
    ]);
    let encoded = CommunicationValue::new(CommunicationType::Ping)
        .with_payload(payload.clone())
        .to_bytes()
        .unwrap();

    let decoded = CommunicationValue::from_bytes(&encoded).unwrap();
    assert_eq!(decoded.payload(), &payload);
    assert_eq!(decoded.into_payload(), payload);
}

#[test]
fn add_data_rejects_a_non_container_payload() {
    let type_map = TypeMap::latest();
    let data_type = DataType::Version.try_to_id(&type_map).unwrap();
    let result = CommunicationValue::new(CommunicationType::Ping)
        .with_payload(DataValue::Null)
        .add_data(data_type, DataValue::Str("1".into()));

    assert_eq!(result, Err(CodecError::InvalidEncoding));
}

#[test]
fn trailing_value_after_payload_is_rejected() {
    let mut encoded = CommunicationValue::new(CommunicationType::Ping)
        .with_payload(DataValue::Null)
        .to_bytes()
        .unwrap();
    encoded.push(DataValue::BoolTrue.to_bytes().unwrap()[0]);
    let body_len = u32::try_from(encoded.len() - 4).unwrap();
    encoded[..4].copy_from_slice(&body_len.to_be_bytes());

    assert_eq!(
        CommunicationValue::from_bytes(&encoded),
        Err(CodecError::InvalidEncoding)
    );
}

#[cfg(feature = "crypto")]
#[test]
fn sealed_sender_is_a_frame_construction_rule() -> Result<(), Box<dyn std::error::Error>> {
    use crate::data_value::ProtectionPurpose;
    use mtp_crypto::{Ed25519Signer, Keyring};

    const SENDER_ID: u64 = 0x0102_0304_0506_0708;
    const RECEIVER_ID: u64 = 0x1112_1314_1516_1718;

    let (signer, _, signer_public_key) = Ed25519Signer::generate();
    let recipient = Keyring::generate();
    let clear_payload = DataValue::Container(vec![(
        DataTypeId(32),
        DataValue::Str("sealed content".into()),
    )]);
    let protected_payload = clear_payload
        .clone()
        .sign(SENDER_ID, ProtectionPurpose::from(1), &signer)?
        .encrypt_for(
            std::slice::from_ref(&recipient.public_key_bundle()),
            ProtectionPurpose::from(2),
        )?;

    let frame = CommunicationValue::new(CommunicationType::Ping)
        .without_sender()
        .with_receiver(RECEIVER_ID)
        .with_payload(protected_payload);
    assert!(frame.sender().is_none());
    assert!(frame.receiver().is_some());
    assert!(matches!(frame.payload(), DataValue::Encrypted(_)));

    let frame_id = frame.id();
    let encoded = frame.to_bytes()?;

    // Payload protection does not introduce frame flags. The header only
    // advertises the transport ID and visible next-hop receiver.
    assert_eq!(encoded[6], FLAG_HAS_ID | FLAG_HAS_RECEIVER);
    assert_eq!(&encoded[11..19], &RECEIVER_ID.to_be_bytes());
    assert_eq!(encoded[19], 0x0A);

    let decoded = CommunicationValue::from_bytes(&encoded)?;
    assert_eq!(decoded.id(), frame_id);
    assert_eq!(decoded.sender(), None);
    assert_eq!(decoded.receiver(), Some(RECEIVER_ID));
    assert!(matches!(decoded.payload(), DataValue::Encrypted(_)));

    let signed = decoded
        .payload()
        .decrypt(&recipient, ProtectionPurpose::from(2))?;
    let DataValue::Signed(signed_value) = &signed else {
        return Err("expected signed value inside encrypted payload".into());
    };
    assert_eq!(signed_value.signer_id, SENDER_ID);

    let mut signer_public_keys = recipient.public_key_bundle();
    signer_public_keys.sig_cl_public_key = signer_public_key;
    signed.verify_with_policy(
        SENDER_ID,
        &signer_public_keys,
        ProtectionPurpose::from(1),
        crate::ProtectionPolicy::any_supported(),
    )?;
    assert_eq!(
        signed.into_verified_with_policy(
            SENDER_ID,
            &signer_public_keys,
            ProtectionPurpose::from(1),
            crate::ProtectionPolicy::any_supported(),
        )?,
        clear_payload
    );
    Ok(())
}
