use wasm_bindgen::prelude::*;

use mtp_codec::{
    DataValue, ProtectedError, ProtectedMessageBuilder, ProtectedOpenOptions, ProtectionError,
    ProtectionPurpose, VerifiedProtectedMessage,
};

use crate::crypto::{
    keyrings_from_js, protection_policy_from_suite, public_key_bundles_from_js,
    relay_signer_from_keyring,
};
use crate::relay::{decode_frame, structured_error};

const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

fn optional_u64(value: &JsValue, name: &str) -> Result<Option<u64>, JsValue> {
    if value.is_null() || value.is_undefined() {
        return Ok(None);
    }
    if let Some(number) = value.as_f64() {
        if !number.is_finite()
            || number.fract() != 0.0
            || !(0.0..=MAX_SAFE_INTEGER).contains(&number)
        {
            return Err(structured_error(
                "invalid-option",
                format!("{name} must be an exact non-negative integer"),
            ));
        }
        return Ok(Some(number as u64));
    }
    if value.js_typeof().as_string().as_deref() == Some("bigint") {
        let bigint = value.clone().unchecked_into::<js_sys::BigInt>();
        let text = bigint.to_string(10)?.as_string().ok_or_else(|| {
            structured_error("invalid-option", format!("failed to stringify {name}"))
        })?;
        return text
            .parse::<u64>()
            .map(Some)
            .map_err(|_| structured_error("invalid-option", format!("{name} is out of range")));
    }
    Err(structured_error(
        "invalid-option",
        format!("{name} must be a number or bigint"),
    ))
}

fn decode_data_value(value: &[u8]) -> Result<DataValue, JsValue> {
    DataValue::from_bytes(value)
        .ok_or_else(|| structured_error("invalid-data-value", "invalid DataValue"))
}

pub(crate) fn protected_error(error: ProtectedError) -> JsValue {
    let code = protected_error_code(&error);
    let value = structured_error(code, format!("protected opening failed: {error}"));
    if let ProtectedError::UnsupportedProtectedVersion(version) = &error {
        let _ = js_sys::Reflect::set(
            &value,
            &JsValue::from_str("protectedVersion"),
            &JsValue::bigint_from_str(&version.to_string()),
        );
    }
    if let ProtectedError::ReservedApplicationType(application_type) = &error {
        let _ = js_sys::Reflect::set(
            &value,
            &JsValue::from_str("applicationType"),
            &JsValue::from_str(application_type),
        );
    }
    value
}

fn protected_error_code(error: &ProtectedError) -> &'static str {
    match error {
        ProtectedError::NotApplicationFrame => "not-application-frame",
        ProtectedError::MissingReceiver => "missing-receiver",
        ProtectedError::PayloadNotEncrypted => "payload-not-encrypted",
        ProtectedError::PayloadNotSigned => "payload-not-signed",
        ProtectedError::MissingEnvelope => "missing-envelope",
        ProtectedError::InvalidLayout(_) => "invalid-layout",
        ProtectedError::MissingProtectedVersion => "missing-protected-version",
        ProtectedError::UnsupportedProtectedVersion(_) => "unsupported-protected-version",
        ProtectedError::MessageTypeMismatch => "message-type-mismatch",
        ProtectedError::FinalRecipientMismatch => "final-recipient-mismatch",
        ProtectedError::SenderMismatch => "sender-id-mismatch",
        ProtectedError::ExpectedReceiverMismatch => "receiver-id-mismatch",
        ProtectedError::ReservedApplicationType(_) => "reserved-application-type",
        ProtectedError::Replay => "replay",
        ProtectedError::ReplayGuard(_) => "replay-guard-error",
        ProtectedError::Protection(error) => match error {
            ProtectionError::NoMatchingRecipient => "no-matching-recipient",
            ProtectionError::InvalidSignature => "invalid-signature",
            ProtectionError::SignaturePolicyMismatch { .. } => "signature-policy-mismatch",
            ProtectionError::PurposeMismatch { .. } => "purpose-mismatch",
            ProtectionError::SignerIdMismatch { .. } => "signer-id-mismatch",
            ProtectionError::SignerKeyNotFound(_) => "signer-key-not-found",
            ProtectionError::Crypto(mtp_crypto::CryptoError::InvalidSignature)
            | ProtectionError::Crypto(mtp_crypto::CryptoError::VerificationFailed) => {
                "invalid-signature"
            }
            _ => "protection-error",
        },
    }
}

fn serialize_data_value(value: &DataValue) -> Result<Vec<u8>, JsValue> {
    value.to_bytes().map_err(|error| {
        structured_error(
            "invalid-data-value",
            format!("protected value encoding failed: {error}"),
        )
    })
}

fn serialize_frame(frame: &mtp_codec::CommunicationValue) -> Result<Vec<u8>, JsValue> {
    frame.to_bytes().map_err(|error| {
        structured_error(
            "invalid-frame",
            format!("protected frame encoding failed: {error}"),
        )
    })
}

#[wasm_bindgen]
pub struct WasmVerifiedProtectedMessage {
    inner: VerifiedProtectedMessage,
}

#[wasm_bindgen]
impl WasmVerifiedProtectedMessage {
    pub fn protected_version(&self) -> u64 {
        self.inner.protected_version
    }

    pub fn signer_id(&self) -> u64 {
        self.inner.signer_id
    }

    pub fn final_recipient_id(&self) -> u64 {
        self.inner.final_recipient_id
    }

    pub fn message_id(&self) -> String {
        self.inner.message_id.clone()
    }

    pub fn created_at(&self) -> u64 {
        self.inner.created_at
    }

    pub fn message_type(&self) -> String {
        self.inner.message_type.clone()
    }

    pub fn content(&self) -> Result<Vec<u8>, JsValue> {
        serialize_data_value(&self.inner.content)
    }

    pub fn matched_signer_key_index(&self) -> usize {
        self.inner.matched_signer_key_index
    }
}

/// Build a complete encrypted direct protected frame in the native codec.
/// The native builder owns both the protected envelope and the clear outer
/// routing fields, including the optional sender exposure and frame ID.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn build_protected_frame_with_keyring(
    message_type: &str,
    encoded_content: &[u8],
    signer_id: u64,
    final_recipient_id: u64,
    message_id: &str,
    created_at: u64,
    signature_purpose: u8,
    encryption_purpose: u8,
    keyring_bytes: &[u8],
    signature_suite: u8,
    frame_id: Option<u32>,
    expose_sender: bool,
    recipient_public_key_bundles: JsValue,
) -> Result<Vec<u8>, JsValue> {
    let content = decode_data_value(encoded_content)?;
    let keyring = mtp_crypto::Keyring::from_bytes(keyring_bytes).map_err(|error| {
        structured_error(
            "invalid-keyring",
            format!("keyring initialization failed: {error}"),
        )
    })?;
    let signer = relay_signer_from_keyring(&keyring, signature_suite)?;
    let recipients = public_key_bundles_from_js(&recipient_public_key_bundles)?;
    let mut builder = ProtectedMessageBuilder::new(
        message_type,
        content,
        signer_id,
        final_recipient_id,
        &signer,
        ProtectionPurpose::from(signature_purpose),
        ProtectionPurpose::from(encryption_purpose),
    )
    .message_id(message_id)
    .created_at(created_at)
    .recipients(recipients)
    .expose_sender(expose_sender);
    if let Some(frame_id) = frame_id {
        builder = builder.frame_id(frame_id);
    }
    let frame = builder.build().map_err(protected_error)?;
    serialize_frame(&frame)
}

/// Read the claimed, unverified signer ID after decrypting the protected
/// payload. The result may only select trusted keys for the same signer ID.
#[wasm_bindgen]
pub fn protected_claimed_signer_id(
    frame: &[u8],
    keyrings: JsValue,
    encryption_purpose: u8,
) -> Result<u64, JsValue> {
    let frame = decode_frame(frame)?;
    let keyrings = keyrings_from_js(&keyrings).map_err(|error| {
        structured_error(
            "invalid-recipient-keyrings",
            error.as_string().unwrap_or_default(),
        )
    })?;
    let references: Vec<&mtp_crypto::Keyring> = keyrings.iter().collect();
    mtp_codec::protected_claimed_signer_id(
        &frame,
        &references,
        ProtectionPurpose::from(encryption_purpose),
    )
    .map_err(protected_error)
}

/// Open and verify a direct protected message in the native codec using
/// trusted signer-key history supplied by the SDK.
#[wasm_bindgen]
pub fn open_protected_with_keyrings(
    frame: &[u8],
    keyrings: JsValue,
    expected_signer_id: JsValue,
    signer_public_key_bundles: JsValue,
    expected_receiver_id: JsValue,
    signature_purpose: u8,
    encryption_purpose: u8,
    signature_suite: u8,
) -> Result<WasmVerifiedProtectedMessage, JsValue> {
    let frame = decode_frame(frame)?;
    let keyrings = keyrings_from_js(&keyrings).map_err(|error| {
        structured_error(
            "invalid-recipient-keyrings",
            error.as_string().unwrap_or_default(),
        )
    })?;
    let references: Vec<&mtp_crypto::Keyring> = keyrings.iter().collect();
    let signer_public_keys =
        public_key_bundles_from_js(&signer_public_key_bundles).map_err(|error| {
            structured_error("invalid-signer-keys", error.as_string().unwrap_or_default())
        })?;
    let expected_signer_id = optional_u64(&expected_signer_id, "expectedSignerId")?
        .ok_or_else(|| structured_error("invalid-option", "expectedSignerId is required"))?;
    let expected_receiver_id = optional_u64(&expected_receiver_id, "expectedReceiverId")?;
    let policy = protection_policy_from_suite(signature_suite).map_err(|error| {
        structured_error(
            "unsupported-signature-suite",
            error.as_string().unwrap_or_default(),
        )
    })?;
    let message = mtp_codec::open_protected_with_keys(
        &frame,
        &references,
        expected_signer_id,
        &signer_public_keys,
        ProtectedOpenOptions::new(
            expected_receiver_id,
            ProtectionPurpose::from(signature_purpose),
            ProtectionPurpose::from(encryption_purpose),
            policy,
        ),
        None,
    )
    .map_err(protected_error)?;
    Ok(WasmVerifiedProtectedMessage { inner: message })
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::crypto::relay_signer_from_keyring;
    use mtp_codec::{CommunicationType, CommunicationValue, DataType, TypeMap};
    use wasm_bindgen::JsCast;
    use wasm_bindgen_test::*;

    const SIGNATURE_PURPOSE: u8 = 0x40;
    const ENCRYPTION_PURPOSE: u8 = 0x41;

    fn structured_error_code(error: JsValue) -> String {
        js_sys::Reflect::get(&error, &JsValue::from_str("code"))
            .expect("structured error code")
            .as_string()
            .expect("structured error code string")
    }

    fn protected_frame_with_version(
        sender: &mtp_crypto::Keyring,
        recipient: &mtp_crypto::Keyring,
        version: Option<u128>,
    ) -> Vec<u8> {
        let type_map = TypeMap::latest();
        let field = |data_type: DataType| data_type.try_to_id(&type_map).expect("field mapping");
        let mut fields = Vec::new();
        if let Some(version) = version {
            fields.push((
                field(DataType::ProtectedVersion),
                DataValue::UnsignedNumber(version),
            ));
        }
        fields.extend([
            (
                field(DataType::MessageType),
                DataValue::Str("ProtectedMessage".into()),
            ),
            (
                field(DataType::FinalRecipientId),
                DataValue::UnsignedNumber(42),
            ),
            (
                field(DataType::MessageId),
                DataValue::Str("wasm-structured-error".into()),
            ),
            (field(DataType::CreatedAt), DataValue::UnsignedNumber(123)),
            (field(DataType::Content), DataValue::Str("hello".into())),
        ]);
        let signer = relay_signer_from_keyring(sender, 1).expect("Ed25519 signer");
        let signed = DataValue::Container(fields)
            .sign(7, ProtectionPurpose::from(SIGNATURE_PURPOSE), &signer)
            .expect("sign protected envelope");
        let encrypted = signed
            .encrypt_for(
                &[recipient.public_key_bundle()],
                ProtectionPurpose::from(ENCRYPTION_PURPOSE),
            )
            .expect("encrypt protected envelope");
        CommunicationValue::new_with_type_map(
            CommunicationType::from_name("ProtectedMessage").expect("application type"),
            &type_map,
        )
        .with_receiver(42)
        .with_payload(encrypted)
        .to_bytes()
        .expect("encode protected frame")
    }

    fn open_for_error(
        frame: &[u8],
        sender: &mtp_crypto::Keyring,
        recipient: &mtp_crypto::Keyring,
    ) -> JsValue {
        let recipient_bytes = recipient.to_bytes();
        let signer_bundle_bytes = sender.public_key_bundle().as_bytes();
        match open_protected_with_keyrings(
            frame,
            js_sys::Uint8Array::from(&recipient_bytes[..]).into(),
            JsValue::bigint_from_str("7"),
            js_sys::Uint8Array::from(&signer_bundle_bytes[..]).into(),
            JsValue::bigint_from_str("42"),
            SIGNATURE_PURPOSE,
            ENCRYPTION_PURPOSE,
            1,
        ) {
            Ok(_) => panic!("protected opening should fail"),
            Err(error) => error,
        }
    }

    #[wasm_bindgen_test]
    fn protected_builder_returns_the_complete_frame() {
        let sender = mtp_crypto::Keyring::generate();
        let recipient = mtp_crypto::Keyring::generate();
        let sender_bytes = sender.to_bytes();
        let recipient_bundle_bytes = recipient.public_key_bundle().as_bytes();
        let content = DataValue::Str("complete-frame".into())
            .to_bytes()
            .expect("encode content");
        let frame = build_protected_frame_with_keyring(
            "ProtectedMessage",
            &content,
            7,
            42,
            "wasm-complete-frame",
            123,
            SIGNATURE_PURPOSE,
            ENCRYPTION_PURPOSE,
            &sender_bytes,
            1,
            Some(19),
            true,
            js_sys::Uint8Array::from(&recipient_bundle_bytes[..]).into(),
        )
        .expect("build complete protected frame");
        let decoded = CommunicationValue::from_bytes(&frame).expect("decode complete frame");
        assert_eq!(decoded.id(), Some(19));
        assert_eq!(decoded.sender(), Some(7));
        assert_eq!(decoded.receiver(), Some(42));
        assert!(decoded.payload().as_encrypted().is_some());
    }

    #[wasm_bindgen_test]
    fn protected_opening_maps_missing_and_unsupported_versions() {
        let sender = mtp_crypto::Keyring::generate();
        let recipient = mtp_crypto::Keyring::generate();
        let missing = protected_frame_with_version(&sender, &recipient, None);
        assert_eq!(
            structured_error_code(open_for_error(&missing, &sender, &recipient)),
            "missing-protected-version"
        );

        let unsupported = protected_frame_with_version(&sender, &recipient, Some(2));
        let error = open_for_error(&unsupported, &sender, &recipient);
        assert_eq!(
            structured_error_code(error.clone()),
            "unsupported-protected-version"
        );
        let version = js_sys::Reflect::get(&error, &JsValue::from_str("protectedVersion"))
            .expect("protected version");
        let version = version
            .unchecked_into::<js_sys::BigInt>()
            .to_string(10)
            .expect("protected version string")
            .as_string()
            .expect("protected version text");
        assert_eq!(version, "2");
    }
}
