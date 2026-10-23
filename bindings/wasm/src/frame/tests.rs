use super::*;
use mtp_codec::ProtectionPurpose;
use mtp_crypto::{
    Ed25519Signer, HybridKem, PublicKeyBundle, SignaturePqPublicKey, SignaturePublicKey,
};
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn build_ping_frame_roundtrip() {
    let bytes = build_ping_frame(42, "test-ping", 1234567890, &[]).expect("encode failed");
    let cv = CommunicationValue::from_bytes(&bytes).expect("decode failed");
    let tm = TypeMap::latest();

    assert_eq!(
        cv.get_type(),
        CommunicationType::Ping.try_to_id(&tm).unwrap()
    );
    assert_eq!(cv.sender(), Some(42));
    assert_eq!(
        cv.get_data(DataType::Description),
        Some(&DataValue::Str("test-ping".into()))
    );
    assert_eq!(
        cv.get_data(DataType::Timestamp),
        Some(&DataValue::UnsignedNumber(1234567890))
    );
}

#[wasm_bindgen_test]
fn build_ping_frame_with_data() {
    let payload = b"attachment-data";
    let bytes = build_ping_frame(99, "with-data", 555, payload).expect("encode failed");
    let cv = CommunicationValue::from_bytes(&bytes).expect("decode failed");
    let tm = TypeMap::latest();

    assert_eq!(
        cv.get_type(),
        CommunicationType::Ping.try_to_id(&tm).unwrap()
    );
    assert_eq!(cv.sender(), Some(99));
    assert_eq!(
        cv.get_data(DataType::Description),
        Some(&DataValue::Str("with-data".into()))
    );
    assert_eq!(
        cv.get_data(DataType::Timestamp),
        Some(&DataValue::UnsignedNumber(555))
    );
    assert_eq!(
        cv.get_data(DataType::Id),
        Some(&DataValue::Bytes(payload.to_vec()))
    );
}

#[wasm_bindgen_test]
fn build_ping_frame_client_id_zero() {
    let bytes = build_ping_frame(0, "zero-id", 0, &[]).expect("encode failed");
    let cv = CommunicationValue::from_bytes(&bytes).expect("decode failed");
    assert_eq!(cv.sender(), Some(0));
}

#[wasm_bindgen_test]
fn parse_frame_preserves_a_generic_payload() {
    let bytes = CommunicationValue::new(CommunicationType::Pong)
        .with_payload(DataValue::Bytes(vec![1, 2, 3]))
        .to_bytes()
        .expect("encode failed");

    let parsed = parse_frame_value(&bytes).expect("parse failed");
    let data =
        js_sys::Reflect::get(&parsed, &JsValue::from_str("data")).expect("data should be present");
    assert_eq!(js_sys::Uint8Array::new(&data).to_vec(), vec![1, 2, 3]);
}

#[wasm_bindgen_test]
fn integer_data_values_round_trip_without_losing_numeric_type() {
    let tm = TypeMap::latest();
    let cases = [
        (DataValue::UnsignedNumber(9_007_199_254_740_991), "number"),
        (DataValue::UnsignedNumber(9_007_199_254_740_992), "bigint"),
        (DataValue::SignedNumber(-9_007_199_254_740_992), "bigint"),
        (DataValue::SignedNumber(i128::MIN), "bigint"),
        (DataValue::UnsignedNumber(u128::from(u64::MAX)), "bigint"),
    ];

    for (original, expected_type) in cases {
        let javascript = data_value_to_js(&original, &tm).expect("decode value");
        assert_eq!(
            javascript.js_typeof().as_string().as_deref(),
            Some(expected_type)
        );
        assert_eq!(
            js_to_data_value(&javascript, &tm).expect("encode value"),
            original
        );
    }
}

#[wasm_bindgen_test]
fn parse_frame_preserves_signed_value_structure() {
    let (signer, _secret_key, _public_key) = Ed25519Signer::generate();
    let signed = DataValue::Str("signed payload".into())
        .sign(0xfeed_beef, ProtectionPurpose::from(7), &signer)
        .expect("signing failed");
    let bytes = CommunicationValue::new(CommunicationType::Pong)
        .with_payload(signed)
        .to_bytes()
        .expect("encode failed");

    let parsed = parse_frame_value(&bytes).expect("parse failed");
    let data = js_sys::Reflect::get(&parsed, &"data".into()).expect("data should be present");
    assert_eq!(
        js_sys::Reflect::get(&data, &"kind".into())
            .expect("kind should be present")
            .as_string()
            .as_deref(),
        Some("signed")
    );
    assert_eq!(
        js_sys::Reflect::get(&data, &"purpose".into())
            .expect("purpose should be present")
            .as_f64(),
        Some(7.0)
    );
    let signer_id = js_sys::Reflect::get(&data, &"signerId".into())
        .expect("signerId should be present")
        .unchecked_into::<js_sys::BigInt>()
        .to_string(10)
        .expect("signerId should stringify")
        .as_string();
    assert_eq!(signer_id.as_deref(), Some("4276993775"));
    assert_eq!(
        js_sys::Reflect::get(&data, &"value".into())
            .expect("value should be present")
            .as_string()
            .as_deref(),
        Some("signed payload")
    );
}

#[wasm_bindgen_test]
fn parse_frame_keeps_encrypted_contents_private() {
    let (_secret_key, public_key) = HybridKem::generate_keypair();
    let recipient = PublicKeyBundle::new(
        public_key,
        SignaturePqPublicKey::new(Vec::new()),
        SignaturePublicKey::new(Vec::new()),
    );
    let encrypted = DataValue::Str("secret payload".into())
        .encrypt_for(&[recipient], ProtectionPurpose::from(9))
        .expect("encryption failed");
    let encoded = encrypted.to_bytes().expect("encode protected value failed");
    let bytes = CommunicationValue::new(CommunicationType::Pong)
        .with_payload(encrypted)
        .to_bytes()
        .expect("encode failed");

    let parsed = parse_frame_value(&bytes).expect("parse failed");
    let data = js_sys::Reflect::get(&parsed, &"data".into()).expect("data should be present");
    assert_eq!(
        js_sys::Reflect::get(&data, &"kind".into())
            .expect("kind should be present")
            .as_string()
            .as_deref(),
        Some("encrypted")
    );
    assert_eq!(
        js_sys::Reflect::get(&data, &"recipientCount".into())
            .expect("recipientCount should be present")
            .as_f64(),
        Some(1.0)
    );
    assert!(!js_sys::Reflect::has(&data, &"value".into()).unwrap_or(false));
    assert_eq!(
        js_sys::Reflect::get(&data, &"encoded".into())
            .expect("encoded should be present")
            .unchecked_into::<js_sys::Uint8Array>()
            .to_vec(),
        encoded
    );
}

#[wasm_bindgen_test]
fn parse_frame_preserves_signed_encrypted_composition() {
    let (signer, _secret_key, _public_key) = Ed25519Signer::generate();
    let (_kem_secret_key, kem_public_key) = HybridKem::generate_keypair();
    let recipient = PublicKeyBundle::new(
        kem_public_key,
        SignaturePqPublicKey::new(Vec::new()),
        SignaturePublicKey::new(Vec::new()),
    );
    let encrypted = DataValue::Container(vec![(
        mtp_type_map::DataTypeId(32),
        DataValue::Str("secret payload".into()),
    )])
    .encrypt_for(&[recipient], ProtectionPurpose::from(9))
    .expect("encryption failed");
    let encrypted_bytes = encrypted.to_bytes().expect("encrypted value should encode");
    let signed = encrypted
        .sign(0x0102_0304_0506_0708, ProtectionPurpose::from(7), &signer)
        .expect("signing failed");
    let frame = CommunicationValue::new(CommunicationType::Pong)
        .with_payload(signed)
        .to_bytes()
        .expect("frame should encode");

    let parsed = parse_frame_value(&frame).expect("frame should parse");
    let signed =
        js_sys::Reflect::get(&parsed, &"data".into()).expect("signed payload should be present");
    assert_eq!(
        js_sys::Reflect::get(&signed, &"kind".into())
            .expect("signed kind should be present")
            .as_string()
            .as_deref(),
        Some("signed")
    );
    let encrypted = js_sys::Reflect::get(&signed, &"value".into())
        .expect("encrypted inner value should be present");
    assert_eq!(
        js_sys::Reflect::get(&encrypted, &"kind".into())
            .expect("encrypted kind should be present")
            .as_string()
            .as_deref(),
        Some("encrypted")
    );
    assert_eq!(
        js_sys::Reflect::get(&encrypted, &"encoded".into())
            .expect("encrypted encoding should be present")
            .unchecked_into::<js_sys::Uint8Array>()
            .to_vec(),
        encrypted_bytes
    );
}

#[wasm_bindgen_test]
fn frame_ids_use_bigints_without_lossy_number_casts() {
    let options = js_sys::Object::new();
    js_sys::Reflect::set(
        &options,
        &"sender".into(),
        &JsValue::bigint_from_str("18446744073709551615"),
    )
    .expect("sender option should be set");
    let bytes = build_frame("Pong", JsValue::NULL, options.into()).expect("build failed");
    let frame = CommunicationValue::from_bytes(&bytes).expect("decode failed");
    assert_eq!(frame.sender(), Some(u64::MAX));

    let unsafe_number = js_sys::Object::new();
    js_sys::Reflect::set(
        &unsafe_number,
        &"sender".into(),
        &JsValue::from_f64(MAX_SAFE_INT + 1.0),
    )
    .expect("sender option should be set");
    assert!(build_frame("Pong", JsValue::NULL, unsafe_number.into()).is_err());
}

#[wasm_bindgen_test]
fn build_frame_with_payload_preserves_clear_and_protected_payloads() {
    let (signer, _secret_key, _public_key) = Ed25519Signer::generate();
    let (_kem_secret_key, kem_public_key) = HybridKem::generate_keypair();
    let recipient = PublicKeyBundle::new(
        kem_public_key,
        SignaturePqPublicKey::new(Vec::new()),
        SignaturePublicKey::new(Vec::new()),
    );
    let clear = DataValue::Str("generic protected payload".into());
    let signed = clear
        .clone()
        .sign(0x0102_0304_0506_0708, ProtectionPurpose::from(7), &signer)
        .expect("signing failed");
    let encrypted = clear
        .clone()
        .encrypt_for(&[recipient.clone()], ProtectionPurpose::from(9))
        .expect("encryption failed");
    let signed_encrypted = signed
        .clone()
        .encrypt_for(&[recipient], ProtectionPurpose::from(9))
        .expect("signed encryption failed");

    for payload in [clear, signed, encrypted, signed_encrypted] {
        let serialized = payload.to_bytes().expect("payload encoding failed");
        let frame = build_frame_with_payload("Pong", &serialized, JsValue::NULL)
            .expect("frame encoding failed");
        let decoded = CommunicationValue::from_bytes(&frame).expect("frame decoding failed");
        assert_eq!(
            decoded
                .payload()
                .to_bytes()
                .expect("payload re-encoding failed"),
            serialized
        );
    }
}

#[wasm_bindgen_test]
fn build_frame_with_payload_applies_frame_options() {
    let payload = DataValue::Str("payload".into())
        .to_bytes()
        .expect("payload encoding failed");
    let options = js_sys::Object::new();
    js_sys::Reflect::set(&options, &"id".into(), &JsValue::from_f64(17.0))
        .expect("id option should be set");
    js_sys::Reflect::set(
        &options,
        &"sender".into(),
        &JsValue::bigint_from_str("18446744073709551615"),
    )
    .expect("sender option should be set");
    js_sys::Reflect::set(&options, &"receiver".into(), &JsValue::from_f64(23.0))
        .expect("receiver option should be set");

    let frame =
        build_frame_with_payload("Pong", &payload, options.into()).expect("frame encoding failed");
    let decoded = CommunicationValue::from_bytes(&frame).expect("frame decoding failed");
    assert_eq!(decoded.id(), Some(17));
    assert_eq!(decoded.sender(), Some(u64::MAX));
    assert_eq!(decoded.receiver(), Some(23));
    assert_eq!(
        decoded
            .payload()
            .to_bytes()
            .expect("payload re-encoding failed"),
        payload
    );
}

#[wasm_bindgen_test]
fn fractional_float_roundtrips_without_corruption() {
    let tm = TypeMap::new(PROTOCOL_VERSION);
    for expected in [-12.5, 0.125, 1.5e200] {
        let encoded =
            js_to_data_value(&JsValue::from_f64(expected), &tm).expect("JS float should encode");
        assert_eq!(encoded, DataValue::Float(expected));
        let decoded = data_value_to_js(&encoded, &tm).expect("float should decode");
        assert_eq!(decoded.as_f64(), Some(expected));
    }
}

#[wasm_bindgen_test]
fn parse_auth_response_success() {
    const ASSIGNED_ID: u128 = 9_007_199_254_740_993;
    const TIMESTAMP: u128 = 9_007_199_254_740_995;
    let resp = CommunicationValue::new(CommunicationType::IdentificationResponse)
        .add_typed_default(DataType::Connected, DataValue::BoolTrue)
        .add_typed_default(DataType::ClientNonce, DataValue::UnsignedNumber(999))
        .add_typed_default(DataType::Id, DataValue::UnsignedNumber(ASSIGNED_ID))
        .add_typed_default(DataType::Timestamp, DataValue::UnsignedNumber(TIMESTAMP))
        .to_bytes()
        .expect("encode failed");

    let result = parse_auth_response(&resp).expect("parse failed");

    let connected = js_sys::Reflect::get(&result, &"connected".into())
        .ok()
        .and_then(|v| v.as_bool());
    assert_eq!(connected, Some(true));

    let id = js_sys::Reflect::get(&result, &"assignedId".into())
        .expect("assignedId should be present")
        .unchecked_into::<js_sys::BigInt>()
        .to_string(10)
        .expect("assignedId should stringify")
        .as_string();
    assert_eq!(id.as_deref(), Some("9007199254740993"));

    let timestamp = js_sys::Reflect::get(&result, &"timestamp".into())
        .expect("timestamp should be present")
        .unchecked_into::<js_sys::BigInt>()
        .to_string(10)
        .expect("timestamp should stringify")
        .as_string();
    assert_eq!(timestamp.as_deref(), Some("9007199254740995"));
}

#[wasm_bindgen_test]
fn parse_auth_response_rejected() {
    let resp = CommunicationValue::new(CommunicationType::IdentificationResponse)
        .add_typed_default(DataType::Connected, DataValue::BoolFalse)
        .to_bytes()
        .expect("encode failed");

    let result = parse_auth_response(&resp).expect("parse failed");

    let connected = js_sys::Reflect::get(&result, &"connected".into())
        .ok()
        .and_then(|v| v.as_bool());
    assert_eq!(connected, Some(false));

    let has_id = js_sys::Reflect::has(&result, &"assignedId".into()).unwrap_or(false);
    assert!(!has_id);
}

#[wasm_bindgen_test]
fn parse_auth_response_with_signature() {
    let sig_bytes = vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe];
    let resp = CommunicationValue::new(CommunicationType::IdentificationResponse)
        .add_typed_default(DataType::Connected, DataValue::BoolTrue)
        .add_typed_default(DataType::Signature, DataValue::Bytes(sig_bytes.clone()))
        .to_bytes()
        .expect("encode failed");

    let result = parse_auth_response(&resp).expect("parse failed");

    let has_sig = js_sys::Reflect::has(&result, &"signature".into()).unwrap_or(false);
    assert!(has_sig);
}

#[wasm_bindgen_test]
fn parse_auth_response_invalid_frame() {
    let result = parse_auth_response(b"garbage-data");
    assert!(result.is_err());
}
