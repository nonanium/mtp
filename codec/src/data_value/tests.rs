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
fn nested_signed_values_hit_cumulative_allocation_limit() -> Result<(), Box<dyn std::error::Error>>
{
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
fn borrowed_merge_validates_the_final_candidate_transactionally() {
    let mut destination = vec![(DataTypeId(1), DataValue::BoolTrue)];
    let source = vec![(DataTypeId(2), DataValue::BoolFalse)];
    let before = destination.clone();

    let value_limits = EncodeLimits {
        max_values: 2,
        ..EncodeLimits::default()
    };
    assert!(validate_container_with_limits(&destination, value_limits).is_ok());
    assert!(validate_container_with_limits(&source, value_limits).is_ok());
    assert_eq!(
        merge_container_from_with_limits(
            &mut destination,
            &source,
            MergeOptions::default(),
            value_limits,
        ),
        Err(ContainerMergeError::InvalidStructure(
            CodecError::TooManyEntries
        ))
    );
    assert_eq!(destination, before);

    let output_limits = EncodeLimits {
        max_output_size: 6,
        ..EncodeLimits::default()
    };
    assert!(validate_container_with_limits(&destination, output_limits).is_ok());
    assert!(validate_container_with_limits(&source, output_limits).is_ok());
    assert_eq!(
        merge_container_from_with_limits(
            &mut destination,
            &source,
            MergeOptions::default(),
            output_limits,
        ),
        Err(ContainerMergeError::InvalidStructure(
            CodecError::TooManyEntries
        ))
    );
    assert_eq!(destination, before);
}

#[test]
fn owned_and_borrowed_merges_have_identical_reports_and_values() {
    let left = vec![
        (DataTypeId(1), DataValue::Bytes(vec![1, 2, 3])),
        (
            DataTypeId(2),
            DataValue::Container(vec![(DataTypeId(3), DataValue::BoolTrue)]),
        ),
    ];
    let right = vec![
        (DataTypeId(1), DataValue::Bytes(vec![4, 5, 6])),
        (
            DataTypeId(2),
            DataValue::Container(vec![
                (DataTypeId(3), DataValue::BoolFalse),
                (DataTypeId(4), DataValue::Bytes(vec![7, 8, 9])),
            ]),
        ),
        (DataTypeId(5), DataValue::Bytes(vec![10; 128])),
    ];

    for conflicts in [
        MergeConflictPolicy::KeepLeft,
        MergeConflictPolicy::KeepRight,
    ] {
        let options = MergeOptions {
            conflicts,
            recursive_containers: true,
        };
        let mut borrowed = left.clone();
        let borrowed_report = merge_container_from_with(&mut borrowed, &right, options).unwrap();
        let (owned, owned_report) =
            merge_containers_owned(left.clone(), right.clone(), options).unwrap();
        assert_eq!(owned, borrowed);
        assert_eq!(owned_report, borrowed_report);
    }

    let options = MergeOptions {
        conflicts: MergeConflictPolicy::RequireEqual,
        recursive_containers: true,
    };
    let mut borrowed = left.clone();
    assert_eq!(
        merge_container_from_with(&mut borrowed, &right, options),
        merge_containers_owned(left.clone(), right.clone(), options).map(|(_, report)| report),
    );

    let options = MergeOptions {
        conflicts: MergeConflictPolicy::Reject,
        recursive_containers: true,
    };
    let mut borrowed = left.clone();
    assert_eq!(
        merge_container_from_with(&mut borrowed, &right, options),
        merge_containers_owned(left, right, options).map(|(_, report)| report),
    );
}

#[test]
fn recursive_merging_reports_full_paths_and_applies_leaf_policies() {
    let parent = DataTypeId(10);
    let equal = DataTypeId(11);
    let added = DataTypeId(12);
    let mut destination = vec![(
        parent,
        DataValue::Container(vec![(equal, DataValue::UnsignedNumber(1))]),
    )];
    let source = vec![(
        parent,
        DataValue::Container(vec![
            (equal, DataValue::UnsignedNumber(1)),
            (added, DataValue::UnsignedNumber(2)),
        ]),
    )];
    let report = merge_container_from_with(
        &mut destination,
        &source,
        MergeOptions {
            conflicts: MergeConflictPolicy::RequireEqual,
            recursive_containers: true,
        },
    )
    .unwrap();
    assert_eq!(report.recursed, vec![MergePath::new(vec![parent])]);
    assert_eq!(report.matched, vec![MergePath::new(vec![parent, equal])]);
    assert_eq!(report.inserted, vec![MergePath::new(vec![parent, added])]);
    assert!(report.preserved.is_empty());

    let mut conflicting = vec![(
        parent,
        DataValue::Container(vec![(equal, DataValue::UnsignedNumber(1))]),
    )];
    let conflict_source = vec![(
        parent,
        DataValue::Container(vec![(equal, DataValue::UnsignedNumber(2))]),
    )];
    assert_eq!(
        merge_container_from_with(
            &mut conflicting,
            &conflict_source,
            MergeOptions {
                conflicts: MergeConflictPolicy::Reject,
                recursive_containers: true,
            },
        ),
        Err(ContainerMergeError::Conflict(MergePath::new(vec![
            parent, equal
        ])))
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
    let signed = DataValue::Str("original".into()).sign(41, ProtectionPurpose::from(7), &signer)?;

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
    let leaf = DataValue::Container(vec![(DataTypeId(60), DataValue::Str("deep secret".into()))]);
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
fn encrypted_authenticated_purpose_cannot_be_changed() -> Result<(), Box<dyn std::error::Error>> {
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
        ApplicationProtectionPurpose::new(MtpProtectionPurpose::RelayMetadataEncryption.value())
            .is_err()
    );
    let application = ApplicationProtectionPurpose::new(0x40).expect("application purpose");
    assert_eq!(ProtectionPurpose::from(application).0, 0x40);
}
