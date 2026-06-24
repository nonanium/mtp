use wasm_bindgen::JsValue;

pub fn js_error(msg: impl Into<String>) -> JsValue {
    JsValue::from_str(&msg.into())
}

pub fn from_codec_error(e: mtp_common::CodecError) -> JsValue {
    js_error(e.to_string())
}

pub fn from_communication_error(e: mtp_common::CommunicationError) -> JsValue {
    js_error(e.to_string())
}

pub fn from_crypto_error(e: mtp_crypto::CryptoError) -> JsValue {
    js_error(e.to_string())
}
