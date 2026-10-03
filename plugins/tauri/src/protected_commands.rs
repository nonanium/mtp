use mtp_codec::{
    CommunicationType, CommunicationValue, DataValue, ProtectedMessageBuilder,
    ProtectedOpenOptions, ProtectionPolicy, ProtectionPurpose,
};
use mtp_crypto::{DualSigner, Ed25519Signer, Keyring, PublicKeyBundle, SignatureScheme};
use serde_json::Value;

pub fn limits(
    options: &Value,
) -> Result<
    (
        mtp_codec::DecodeLimits,
        mtp_codec::EncodeLimits,
        mtp_codec::ProtectedLimits,
    ),
    String,
> {
    let mut decode = mtp_codec::DecodeLimits::default();
    let mut encode = mtp_codec::EncodeLimits::default();
    let mut protected = mtp_codec::ProtectedLimits::default();
    if let Some(limits) = options.get("limits") {
        let fields = limits.as_object().ok_or("limits must be an object")?;
        for (field, value) in fields {
            let value = value
                .as_u64()
                .and_then(|v| usize::try_from(v).ok())
                .filter(|v| *v > 0)
                .ok_or("limits must be positive integers")?;
            match field.as_str() {
                "maxDepth" => {
                    decode.max_depth = value;
                    encode.max_depth = value;
                }
                "maxValues" => {
                    decode.max_values = value;
                    encode.max_values = value;
                }
                "maxBlobSize" => decode.max_blob_size = value,
                "maxRecipients" => decode.max_recipients = value,
                "maxAllocatedBytes" => decode.max_allocated_bytes = value,
                "maxOutputSize" => encode.max_output_size = value,
                "maxMetadataEncodedBytes" => protected.max_metadata_encoded_bytes = value,
                "maxSignerKeyHistory" => protected.max_signer_key_history = value,
                "maxDecryptionKeyHistory" => protected.max_decryption_key_history = value,
                _ => return Err(format!("unknown receive limit {field}")),
            }
        }
    }
    Ok((decode, encode, protected))
}

pub fn key_history(keys: &Keyring, options: &Value) -> Result<Vec<Keyring>, String> {
    let mut history = vec![
        Keyring::from_bytes(&keys.try_to_bytes().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?,
    ];
    if let Some(values) = options.pointer("/recipient/keyringHistory") {
        for value in values.as_array().ok_or("keyringHistory must be an array")? {
            history.push(Keyring::from_bytes(&bytes(value)?).map_err(|e| e.to_string())?);
        }
    }
    if history.len() > limits(options)?.2.max_decryption_key_history {
        return Err("decryption key history limit exceeded".into());
    }
    Ok(history)
}

pub fn relay_options(
    options: &Value,
    policy: ProtectionPolicy,
) -> Result<mtp_codec::RelayOpenOptions, String> {
    let (decode_limits, encode_limits, protected_limits) = limits(options)?;
    Ok(mtp_codec::RelayOpenOptions {
        policy,
        decode_limits,
        encode_limits,
        protected_limits,
    })
}

pub fn integer(options: &Value, field: &str) -> Result<u64, String> {
    options
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{field} must be a decimal string"))?
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())
}
pub fn bytes(value: &Value) -> Result<Vec<u8>, String> {
    serde_json::from_value(value.clone()).map_err(|e| e.to_string())
}
pub fn policy(options: &Value) -> Result<ProtectionPolicy, String> {
    match options
        .get("signaturePolicy")
        .and_then(Value::as_str)
        .unwrap_or("ed25519")
    {
        "ed25519" => Ok(ProtectionPolicy::ed25519()),
        "dual" => Ok(ProtectionPolicy::dual()),
        "any-supported" => Ok(ProtectionPolicy::any_supported()),
        _ => Err("invalid signature policy".into()),
    }
}
pub fn purpose(options: &Value, field: &str) -> Result<u8, String> {
    options
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|n| u8::try_from(n).ok())
        .ok_or_else(|| format!("invalid {field}"))
}
pub fn bundles(options: &Value, field: &str) -> Result<Vec<PublicKeyBundle>, String> {
    options
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing {field}"))?
        .iter()
        .map(|v| {
            let key = PublicKeyBundle::from_bytes(&bytes(v)?).map_err(|e| e.to_string())?;
            key.validate().map_err(|e| e.to_string())?;
            Ok(key)
        })
        .collect()
}
pub fn build(
    keys: &Keyring,
    id: u64,
    type_name: &str,
    content: &[u8],
    options: &Value,
) -> Result<Vec<u8>, String> {
    let signer: Box<dyn SignatureScheme> = match options
        .get("signatureSuite")
        .and_then(Value::as_str)
        .unwrap_or("ed25519")
    {
        "ed25519" => {
            Box::new(Ed25519Signer::new(&keys.sig_cl_secret_key).map_err(|e| e.to_string())?)
        }
        "dual" => Box::new(
            DualSigner::new(
                &keys.sig_cl_secret_key,
                &keys.sig_pq_secret_key,
                &keys.sig_pq_public_key,
            )
            .map_err(|e| e.to_string())?,
        ),
        _ => return Err("invalid signature suite".into()),
    };
    let mut builder = ProtectedMessageBuilder::new(
        CommunicationType::from_name(type_name).ok_or("unknown communication type")?,
        DataValue::try_from_bytes_with_limits(content, limits(options)?.0)
            .map_err(|e| e.to_string())?,
        id,
        integer(options, "receiverId")?,
        signer.as_ref(),
        ProtectionPurpose(purpose(options, "signaturePurpose")?),
        ProtectionPurpose(purpose(options, "encryptionPurpose")?),
    )
    .recipients(bundles(options, "recipients")?)
    .encode_limits(limits(options)?.1)
    .protected_limits(limits(options)?.2);
    if let Some(value) = options.get("createdAt") {
        builder = builder.created_at(
            value
                .as_str()
                .ok_or("createdAt must be a string")?
                .parse::<u64>()
                .map_err(|e| e.to_string())?,
        );
    }
    if let Some(value) = options.get("messageId") {
        builder = builder.message_id(
            value
                .as_str()
                .ok_or("messageId must be a string")?
                .parse::<u128>()
                .map_err(|e| e.to_string())?,
        );
    }
    if let Some(value) = options.get("id") {
        builder = builder.frame_id(
            value
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or("invalid frame ID")?,
        );
    }
    if let Some(value) = options.get("exposeSender") {
        builder = builder.expose_sender(value.as_bool().ok_or("invalid exposeSender")?);
    }
    builder
        .build()
        .map_err(|e| e.to_string())?
        .to_bytes()
        .map_err(|e| e.to_string())
}
pub fn open(keys: &Keyring, frame: &[u8], options: &Value) -> Result<Value, String> {
    let signer = integer(options, "signerId")?;
    if options.get("expectedSignerId").is_some() && integer(options, "expectedSignerId")? != signer
    {
        return Err("unexpected signer".into());
    }
    let receiver = options
        .get("expectedReceiverId")
        .map(|_| integer(options, "expectedReceiverId"))
        .transpose()?;
    let (decode, encode, protected) = limits(options)?;
    let history = key_history(keys, options)?;
    let keyrings: Vec<_> = history.iter().collect();
    let mut open_options = ProtectedOpenOptions::new(
        receiver,
        ProtectionPurpose(purpose(options, "signaturePurpose")?),
        ProtectionPurpose(purpose(options, "encryptionPurpose")?),
        policy(options)?,
    );
    open_options.decode_limits = decode;
    open_options.encode_limits = encode;
    open_options.protected_limits = protected;
    let opened = mtp_codec::open_protected_with_keys_without_replay(
        &CommunicationValue::from_bytes_with_limits(frame, decode).map_err(|e| e.to_string())?,
        &keyrings,
        signer,
        &bundles(options, "signerPublicKeys")?,
        open_options,
    )
    .map_err(|e| e.to_string())?;
    Ok(
        serde_json::json!({"type": opened.message_type().to_string(), "protectedVersion": opened.protected_version().to_string(), "signerId": opened.signer_id().to_string(), "finalRecipientId": opened.final_recipient_id().to_string(), "messageId": opened.message_id().get().to_string(), "createdAt": opened.created_at().to_string(), "content": opened.content().to_bytes().map_err(|e| e.to_string())?}),
    )
}

pub fn build_relay(
    keys: &Keyring,
    id: u64,
    type_name: &str,
    content: &[u8],
    metadata: Option<&[u8]>,
    options: &Value,
) -> Result<Vec<u8>, String> {
    let signer: Box<dyn SignatureScheme> = match options
        .get("signatureSuite")
        .and_then(Value::as_str)
        .unwrap_or("ed25519")
    {
        "ed25519" => {
            Box::new(Ed25519Signer::new(&keys.sig_cl_secret_key).map_err(|e| e.to_string())?)
        }
        "dual" => Box::new(
            DualSigner::new(
                &keys.sig_cl_secret_key,
                &keys.sig_pq_secret_key,
                &keys.sig_pq_public_key,
            )
            .map_err(|e| e.to_string())?,
        ),
        _ => return Err("invalid signature suite".into()),
    };
    let mut builder = mtp_codec::SealedRelayBuilder::new(
        CommunicationType::from_name(type_name).ok_or("unknown communication type")?,
        DataValue::try_from_bytes_with_limits(content, limits(options)?.0)
            .map_err(|e| e.to_string())?,
        id,
        integer(options, "finalRecipientId")?,
        integer(options, "nextHopId")?,
        signer.as_ref(),
    )
    .metadata_recipients(bundles(options, "metadataRecipients")?)
    .content_recipients(bundles(options, "contentRecipients")?)
    .encode_limits(limits(options)?.1)
    .protected_limits(limits(options)?.2);
    if let Some(metadata) = metadata {
        builder = builder.metadata(
            DataValue::try_from_bytes_with_limits(metadata, limits(options)?.0)
                .map_err(|e| e.to_string())?,
        );
    }
    if options.get("createdAt").is_some() {
        builder = builder.created_at(integer(options, "createdAt")?);
    }
    if let Some(value) = options.get("messageId") {
        builder = builder.message_id(
            value
                .as_str()
                .ok_or("messageId must be a string")?
                .parse::<u128>()
                .map_err(|e| e.to_string())?,
        );
    }
    builder
        .build()
        .map_err(|e| e.to_string())?
        .to_bytes()
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_bridge_roundtrip_preserves_content_and_constraints() {
        let sender = Keyring::generate();
        let recipient = Keyring::generate();
        let content = DataValue::UnsignedNumber(u64::MAX as u128)
            .to_bytes()
            .unwrap();
        let options = serde_json::json!({"receiverId": "42", "recipients": [recipient.public_key_bundle().try_as_bytes().unwrap()], "signaturePurpose": 0x72, "encryptionPurpose": 0x73, "signatureSuite": "dual", "messageId": "123456789012345678901234567890", "createdAt": "1720000000123", "id": 17});
        let frame = build(&sender, 7, "ProtectedMessage", &content, &options).unwrap();
        let mut opening = serde_json::json!({"signerId": "7", "expectedSignerId": "7", "expectedReceiverId": "42", "signerPublicKeys": [sender.public_key_bundle().try_as_bytes().unwrap()], "signaturePurpose": 0x72, "encryptionPurpose": 0x73, "signaturePolicy": "dual"});
        let result = open(&recipient, &frame, &opening).unwrap();
        assert_eq!(result["messageId"], "123456789012345678901234567890");
        assert_eq!(bytes(&result["content"]).unwrap(), content);
        // Native verification is intentionally replay-free. SDK guards own
        // atomic acceptance, separately for each subscription.
        assert!(open(&recipient, &frame, &opening).is_ok());
        for (field, value) in [
            ("signaturePurpose", serde_json::json!(0x74)),
            ("encryptionPurpose", serde_json::json!(0x75)),
            ("expectedSignerId", serde_json::json!("8")),
        ] {
            let mut wrong = opening.clone();
            wrong[field] = value;
            assert!(open(&recipient, &frame, &wrong).is_err(), "{field}");
        }
        let mut wrong = opening.clone();
        wrong["signerPublicKeys"] = serde_json::json!([Keyring::generate()
            .public_key_bundle()
            .try_as_bytes()
            .unwrap()]);
        assert!(open(&recipient, &frame, &wrong).is_err());
        opening["expectedReceiverId"] = Value::String("43".into());
        assert!(open(&recipient, &frame, &opening).is_err());
    }

    #[test]
    fn history_and_allocation_limits_are_enforced() {
        let keys = Keyring::generate();
        let options = serde_json::json!({"limits": {"maxDecryptionKeyHistory": 1}, "recipient": {"keyringHistory": [keys.try_to_bytes().unwrap().to_vec()]}});
        assert!(key_history(&keys, &options).is_err());
        assert!(limits(&serde_json::json!({"limits": {"maxAllocatedBytes": 0}})).is_err());
        assert!(limits(&serde_json::json!({"limits": {"unknown": 1}})).is_err());
    }

    #[test]
    fn policy_registry_rejects_unknown_suites() {
        assert_eq!(
            policy(&serde_json::json!({"signaturePolicy":"dual"})).unwrap(),
            ProtectionPolicy::dual()
        );
        assert!(policy(&serde_json::json!({"signaturePolicy":"unknown"})).is_err());
    }

    #[test]
    fn identifiers_preserve_u64_range_and_reject_json_numbers() {
        assert_eq!(
            integer(&serde_json::json!({"id":"18446744073709551615"}), "id").unwrap(),
            u64::MAX
        );
        assert!(integer(&serde_json::json!({"id": 1}), "id").is_err());
    }
}
