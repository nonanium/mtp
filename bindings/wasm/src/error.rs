use wasm_bindgen::JsValue;

pub fn js_error(msg: impl Into<String>) -> JsValue {
    JsValue::from_str(&msg.into())
}

pub fn from_codec_error(e: mtp_common::CodecError) -> JsValue {
    js_error(e.to_string())
}

pub fn from_communication_error(e: mtp_common::CommunicationError) -> JsValue {
    let error = js_sys::Error::new(&e.to_string());
    let _ = js_sys::Reflect::set(
        error.as_ref(),
        &JsValue::from_str("code"),
        &JsValue::from_str(e.code().as_str()),
    );
    if let Some(phase) = e.phase() {
        let _ = js_sys::Reflect::set(
            error.as_ref(),
            &JsValue::from_str("phase"),
            &JsValue::from_str(phase.as_str()),
        );
    }
    error.into()
}

pub fn from_crypto_error(e: mtp_crypto::CryptoError) -> JsValue {
    js_error(e.to_string())
}

pub fn from_protection_error(e: mtp_codec::ProtectionError) -> JsValue {
    js_error(e.to_string())
}

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
mod tests {
    use super::*;
    use wasm_bindgen::JsCast;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn js_error_contains_message() {
        let err = js_error("test error message");
        assert_eq!(err.as_string(), Some("test error message".to_string()));
    }

    #[wasm_bindgen_test]
    fn js_error_from_string() {
        let err = js_error(String::from("owned string error"));
        assert_eq!(err.as_string(), Some("owned string error".to_string()));
    }

    #[wasm_bindgen_test]
    fn from_codec_error_invalid_encoding() {
        let err = from_codec_error(mtp_common::CodecError::InvalidEncoding);
        let msg = err.as_string().unwrap_or_default();
        assert!(msg.contains("Invalid encoding"));
    }

    #[wasm_bindgen_test]
    fn from_codec_error_unknown_version() {
        let err = from_codec_error(mtp_common::CodecError::UnknownVersion);
        let msg = err.as_string().unwrap_or_default();
        assert!(msg.contains("Unknown version"));
    }

    #[wasm_bindgen_test]
    fn from_communication_error_renders() {
        use mtp_common::CommunicationError;
        let err = from_communication_error(CommunicationError::ConnectionLost);
        let msg = err
            .unchecked_into::<js_sys::Error>()
            .message()
            .as_string()
            .unwrap_or_default();
        assert!(msg.contains("Connection terminated"));
    }

    #[wasm_bindgen_test]
    fn from_crypto_error_renders() {
        use mtp_crypto::CryptoError;
        let err = from_crypto_error(CryptoError::InvalidKeyLength);
        let msg = err.as_string().unwrap_or_default();
        assert!(msg.contains("invalid key length"));
    }
}
