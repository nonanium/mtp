use wasm_bindgen::prelude::*;

use mtp_codec::{
    CommunicationType, CommunicationTypeId, CommunicationValue, DataType, DataTypeId, DataValue,
};
use mtp_crypto::{
    ChaCha20Poly1305, Ed25519Signer, Keyring, SigAlgorithm,
    derive_encryption_key,
};

use crate::error::js_error;

/// Build a simple Ping frame with description, timestamp, and optional data.
#[wasm_bindgen]
pub fn build_ping_frame(
    client_id: u64,
    description: &str,
    timestamp: u64,
    data: &[u8],
) -> Vec<u8> {
    let mut msg = CommunicationValue::new(CommunicationType::Ping)
        .add_typed_default(DataType::Description, DataValue::Str(description.to_string()))
        .add_typed_default(DataType::Timestamp, DataValue::UnsignedNumber(timestamp as u128))
        .with_sender(client_id);

    if !data.is_empty() {
        msg = msg.add_typed_default(DataType::Id, DataValue::Bytes(data.to_vec()));
    }

    msg.to_bytes()
}

/// Build a demo Ping frame with encrypted and signed containers
/// (mirrors the Rust client example but uses only reserved data types).
#[wasm_bindgen]
pub fn build_demo_message(client_id: u64, keyring_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let keyring = Keyring::from_bytes(keyring_bytes)
        .map_err(|e| js_error(&format!("invalid keyring: {}", e)))?;

    let enc_key = derive_encryption_key(
        b"MTP-demo-shared-secret",
        b"MTP-demo-salt",
        b"encrypted-container-demo",
    )
    .map_err(|e| js_error(&format!("key derivation failed: {}", e)))?;

    let cipher = ChaCha20Poly1305::new(enc_key);
    let signer = Ed25519Signer::new(&keyring.sig_cl_secret_key)
        .map_err(|e| js_error(&format!("signer creation failed: {}", e)))?;

    // Encrypted container (DataTypeId 1 = arbitrary custom)
    let inner_enc = DataValue::Container(vec![
        (DataTypeId(1), DataValue::Str("secret inner data".into())),
        (DataTypeId(2), DataValue::UnsignedNumber(42)),
    ]);
    let mut dv_enc = inner_enc;
    dv_enc.encrypt_container(&cipher, b"demo-aad")
        .ok_or_else(|| js_error("encryption failed"))?;

    // Signed container
    let inner_sig = DataValue::Container(vec![
        (DataTypeId(1), DataValue::Str("signed by client".into())),
        (DataTypeId(2), DataValue::UnsignedNumber(99)),
    ]);
    let mut dv_sig = inner_sig;
    dv_sig.sign_container(SigAlgorithm::ED25519, &signer)
        .ok_or_else(|| js_error("signing failed"))?;

    // Signed + encrypted container
    let inner_sec = DataValue::Container(vec![
        (DataTypeId(1), DataValue::Str("signed+encrypted payload".into())),
        (DataTypeId(2), DataValue::UnsignedNumber(7)),
    ]);
    let mut dv_sec = inner_sec;
    dv_sec.sign_and_encrypt_container(SigAlgorithm::ED25519, &signer, &cipher, b"demo-aad")
        .ok_or_else(|| js_error("sign+encrypt failed"))?;

    let timestamp = js_sys::Date::now() as u64;

    let msg = CommunicationValue::new(CommunicationType::Ping)
        .add_typed_default(DataType::Description, DataValue::Str("MTP WASM Demo".into()))
        .add_typed_default(DataType::Timestamp, DataValue::UnsignedNumber(timestamp as u128))
        .add_typed_default(DataType::Version, DataValue::Str("demo-wasm".into()))
        .with_sender(client_id);

    Ok(msg.to_bytes())
}

/// Parse an auth response frame into a JS object.
#[wasm_bindgen]
pub fn parse_auth_response(response: &[u8]) -> Result<JsValue, JsValue> {
    let comm = CommunicationValue::from_bytes(response)
        .map_err(|e| js_error(&format!("parse failed: {}", e)))?;

    let connected = matches!(comm.get_data(DataTypeId(11)), DataValue::BoolTrue);

    let client_nonce = match comm.get_data(DataTypeId(7)) {
        DataValue::UnsignedNumber(n) => Some(*n),
        _ => None,
    };

    let assigned_id = match comm.get_data(DataTypeId(6)) {
        DataValue::UnsignedNumber(n) => Some(*n as u64),
        _ => None,
    };

    let timestamp = match comm.get_data(DataTypeId(5)) {
        DataValue::UnsignedNumber(n) => Some(*n),
        _ => None,
    };

    let signature = match comm.get_data(DataTypeId(10)) {
        DataValue::Bytes(b) => Some(b.clone()),
        _ => None,
    };

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"connected".into(), &JsValue::from(connected)).ok();
    if let Some(n) = client_nonce {
        let arr = js_sys::Uint8Array::from(&n.to_be_bytes()[..]);
        js_sys::Reflect::set(&obj, &"clientNonce".into(), &arr).ok();
    }
    if let Some(id) = assigned_id {
        js_sys::Reflect::set(&obj, &"assignedId".into(), &JsValue::from(id as f64)).ok();
    }
    if let Some(ts) = timestamp {
        js_sys::Reflect::set(&obj, &"timestamp".into(), &JsValue::from(ts as f64)).ok();
    }
    if let Some(sig) = signature {
        let arr = js_sys::Uint8Array::from(&sig[..]);
        js_sys::Reflect::set(&obj, &"signature".into(), &arr).ok();
    }

    Ok(obj.into())
}

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn build_ping_frame_roundtrip() {
        let bytes = build_ping_frame(42, "test-ping", 1234567890, &[]);
        let cv = CommunicationValue::from_bytes(&bytes).expect("decode failed");

        assert_eq!(cv.get_type(), CommunicationTypeId(19)); // Ping
        assert_eq!(cv.get_sender(), 42);
        assert_eq!(cv.get_data(DataTypeId(4)), &DataValue::Str("test-ping".into()));
        assert_eq!(cv.get_data(DataTypeId(5)), &DataValue::UnsignedNumber(1234567890));
    }

    #[wasm_bindgen_test]
    fn build_ping_frame_with_data() {
        let payload = b"attachment-data";
        let bytes = build_ping_frame(99, "with-data", 555, payload);
        let cv = CommunicationValue::from_bytes(&bytes).expect("decode failed");

        assert_eq!(cv.get_type(), CommunicationTypeId(19));
        assert_eq!(cv.get_sender(), 99);
        assert_eq!(cv.get_data(DataTypeId(4)), &DataValue::Str("with-data".into()));
        assert_eq!(cv.get_data(DataTypeId(5)), &DataValue::UnsignedNumber(555));
        assert_eq!(cv.get_data(DataTypeId(6)), &DataValue::Bytes(payload.to_vec()));
    }

    #[wasm_bindgen_test]
    fn build_ping_frame_client_id_zero() {
        let bytes = build_ping_frame(0, "zero-id", 0, &[]);
        let cv = CommunicationValue::from_bytes(&bytes).expect("decode failed");
        assert_eq!(cv.get_sender(), 0);
    }

    #[wasm_bindgen_test]
    fn build_demo_message_roundtrip() {
        let (_signer, sk, pk) = Ed25519Signer::generate();
        let keyring = Keyring::new(
            mtp_crypto::KemPublicKey::new(vec![]),
            mtp_crypto::KemPrivateKey::new(vec![]),
            mtp_crypto::SignaturePqPublicKey::new(vec![]),
            mtp_crypto::SignaturePqPrivateKey::new(vec![]),
            pk,
            sk,
        );
        let keyring_bytes = keyring.to_bytes();

        let result = build_demo_message(7, &keyring_bytes);
        assert!(result.is_ok());

        let bytes = result.unwrap();
        let cv = CommunicationValue::from_bytes(&bytes).expect("decode failed");

        assert_eq!(cv.get_type(), CommunicationTypeId(19)); // Ping
        assert_eq!(cv.get_sender(), 7);
        assert_eq!(cv.get_data(DataTypeId(4)), &DataValue::Str("MTP WASM Demo".into()));
    }

    #[wasm_bindgen_test]
    fn build_demo_message_invalid_keyring() {
        let result = build_demo_message(1, b"not-a-valid-keyring");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.as_string().unwrap().contains("invalid keyring"));
    }

    #[wasm_bindgen_test]
    fn parse_auth_response_success() {
        let resp = CommunicationValue::new(CommunicationType::IdentificationResponse)
            .add_typed_default(DataType::Connected, DataValue::BoolTrue)
            .add_typed_default(DataType::ClientNonce, DataValue::UnsignedNumber(999))
            .add_typed_default(DataType::Id, DataValue::UnsignedNumber(42))
            .add_typed_default(DataType::Timestamp, DataValue::UnsignedNumber(12345))
            .to_bytes();

        let result = parse_auth_response(&resp).expect("parse failed");

        let connected = js_sys::Reflect::get(&result, &"connected".into())
            .ok().and_then(|v| v.as_bool());
        assert_eq!(connected, Some(true));

        let id = js_sys::Reflect::get(&result, &"assignedId".into())
            .ok().and_then(|v| v.as_f64());
        assert_eq!(id, Some(42.0));
    }

    #[wasm_bindgen_test]
    fn parse_auth_response_rejected() {
        let resp = CommunicationValue::new(CommunicationType::IdentificationResponse)
            .add_typed_default(DataType::Connected, DataValue::BoolFalse)
            .to_bytes();

        let result = parse_auth_response(&resp).expect("parse failed");

        let connected = js_sys::Reflect::get(&result, &"connected".into())
            .ok().and_then(|v| v.as_bool());
        assert_eq!(connected, Some(false));

        // rejected should have no assignedId
        let has_id = js_sys::Reflect::has(&result, &"assignedId".into()).unwrap_or(false);
        assert!(!has_id);
    }

    #[wasm_bindgen_test]
    fn parse_auth_response_with_signature() {
        let sig_bytes = vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe];
        let resp = CommunicationValue::new(CommunicationType::IdentificationResponse)
            .add_typed_default(DataType::Connected, DataValue::BoolTrue)
            .add_typed_default(DataType::Signature, DataValue::Bytes(sig_bytes.clone()))
            .to_bytes();

        let result = parse_auth_response(&resp).expect("parse failed");

        let has_sig = js_sys::Reflect::has(&result, &"signature".into()).unwrap_or(false);
        assert!(has_sig);
    }

    #[wasm_bindgen_test]
    fn parse_auth_response_invalid_frame() {
        let result = parse_auth_response(b"garbage-data");
        assert!(result.is_err());
    }
}
