use wasm_bindgen::{JsCast, prelude::*};

use mtp_codec::{
    CommunicationType, CommunicationValue, DataType, DataValue, communication_type_name,
    data_type_name,
};
use mtp_type_map::TypeMap;

use crate::error::js_error;

#[wasm_bindgen(typescript_custom_section)]
const PARSED_FRAME_TS: &'static str = r#"
export interface ParsedFrame {
  id?: number;
  type: string;
  sender?: bigint;
  receiver?: bigint;
  data: Record<string, unknown>;
  raw: Uint8Array;
}
"#;

fn set_prop(obj: &js_sys::Object, key: &str, value: &JsValue) -> Result<(), JsValue> {
    js_sys::Reflect::set(obj, &JsValue::from_str(key), value).map(|_| ())
}

fn integer_value(value: &str) -> JsValue {
    if let Ok(number) = value.parse::<f64>() {
        if number.fract() == 0.0 && number.abs() <= 9_007_199_254_740_991.0 {
            return JsValue::from_f64(number);
        }
    }
    JsValue::from_str(value)
}

fn data_value_to_js(value: &DataValue) -> Result<JsValue, JsValue> {
    match value {
        DataValue::BoolTrue => Ok(JsValue::TRUE),
        DataValue::BoolFalse => Ok(JsValue::FALSE),
        DataValue::Bool(v) => Ok(JsValue::from_bool(*v)),
        DataValue::SignedNumber(n) => Ok(integer_value(&n.to_string())),
        DataValue::UnsignedNumber(n) => Ok(integer_value(&n.to_string())),
        DataValue::Float(exp, mant) => {
            Ok(JsValue::from_f64((*mant as f64) * 10f64.powi(*exp as i32)))
        }
        DataValue::Str(s) => Ok(JsValue::from_str(s)),
        DataValue::Bytes(bytes) => Ok(js_sys::Uint8Array::from(&bytes[..]).into()),
        DataValue::Array(values) => {
            let arr = js_sys::Array::new();
            for value in values {
                arr.push(&data_value_to_js(value)?);
            }
            Ok(arr.into())
        }
        DataValue::Container(entries) => {
            let obj = js_sys::Object::new();
            for (key, value) in entries {
                let name = data_type_name(key.0)
                    .map(str::to_string)
                    .unwrap_or_else(|| key.0.to_string());
                set_prop(&obj, &name, &data_value_to_js(value)?)?;
            }
            Ok(obj.into())
        }
        DataValue::EncryptedContainer(bytes)
        | DataValue::SignedContainer(bytes)
        | DataValue::SignedEncryptedContainer(bytes) => {
            Ok(js_sys::Uint8Array::from(&bytes[..]).into())
        }
        DataValue::Null => Ok(JsValue::NULL),
    }
}

fn js_to_data_value(value: &JsValue) -> Result<DataValue, JsValue> {
    if value.is_null() || value.is_undefined() {
        return Ok(DataValue::Null);
    }
    if let Some(v) = value.as_bool() {
        return Ok(DataValue::Bool(v));
    }
    if let Some(v) = value.as_string() {
        return Ok(DataValue::Str(v));
    }
    if js_sys::Uint8Array::instanceof(value) {
        return Ok(DataValue::Bytes(js_sys::Uint8Array::new(value).to_vec()));
    }
    if js_sys::Array::is_array(value) {
        let array = js_sys::Array::from(value);
        let mut values = Vec::with_capacity(array.length() as usize);
        for item in array.iter() {
            values.push(js_to_data_value(&item)?);
        }
        return Ok(DataValue::Array(values));
    }
    if let Some(v) = value.as_f64() {
        if v.fract() == 0.0 {
            if v >= 0.0 {
                return Ok(DataValue::UnsignedNumber(v as u128));
            }
            return Ok(DataValue::SignedNumber(v as i128));
        }
        let mantissa = (v * 1_000_000.0).round() as u32;
        return Ok(DataValue::Float(246, mantissa));
    }

    let type_name = value.js_typeof().as_string().unwrap_or_default();
    if type_name == "bigint" {
        let bigint = value.clone().unchecked_into::<js_sys::BigInt>();
        let as_string = bigint
            .to_string(10)?
            .as_string()
            .ok_or_else(|| js_error("failed to stringify bigint"))?;
        if let Some(unsigned) = as_string.strip_prefix('-') {
            let n = unsigned
                .parse::<i128>()
                .map_err(|_| js_error("bigint out of range"))?;
            return Ok(DataValue::SignedNumber(-n));
        }
        let n = as_string
            .parse::<u128>()
            .map_err(|_| js_error("bigint out of range"))?;
        return Ok(DataValue::UnsignedNumber(n));
    }

    if value.is_object() {
        let object = js_sys::Object::from(value.clone());
        let keys = js_sys::Object::keys(&object);
        let mut entries = Vec::with_capacity(keys.length() as usize);
        for key in keys.iter() {
            let key = key
                .as_string()
                .ok_or_else(|| js_error("object key must be a string"))?;
            let data_type = DataType::from_name(&key)
                .ok_or_else(|| js_error(&format!("unknown data type: {key}")))?;
            let value = js_sys::Reflect::get(&object, &JsValue::from_str(&key))?;
            entries.push((
                data_type.to_id(&TypeMap::latest()),
                js_to_data_value(&value)?,
            ));
        }
        return Ok(DataValue::Container(entries));
    }

    Err(js_error("unsupported data value"))
}

fn option_u32(options: &JsValue, key: &str) -> Result<Option<u32>, JsValue> {
    let value = js_sys::Reflect::get(options, &JsValue::from_str(key))?;
    if value.is_null() || value.is_undefined() {
        return Ok(None);
    }
    let Some(n) = value.as_f64() else {
        return Err(js_error(&format!("{key} must be a number")));
    };
    Ok(Some(n as u32))
}

fn option_u64(options: &JsValue, key: &str) -> Result<Option<u64>, JsValue> {
    let value = js_sys::Reflect::get(options, &JsValue::from_str(key))?;
    if value.is_null() || value.is_undefined() {
        return Ok(None);
    }
    if let Some(n) = value.as_f64() {
        return Ok(Some(n as u64));
    }
    let type_name = value.js_typeof().as_string().unwrap_or_default();
    if type_name == "bigint" {
        let bigint = value.clone().unchecked_into::<js_sys::BigInt>();
        let as_string = bigint
            .to_string(10)?
            .as_string()
            .ok_or_else(|| js_error("failed to stringify bigint"))?;
        return as_string
            .parse::<u64>()
            .map(Some)
            .map_err(|_| js_error(&format!("{key} out of range")));
    }
    Err(js_error(&format!("{key} must be a number or bigint")))
}

pub(crate) fn parse_frame_value(frame: &[u8]) -> Result<JsValue, JsValue> {
    let comm = CommunicationValue::from_bytes(frame)
        .map_err(|e| js_error(&format!("parse failed: {}", e)))?;
    let obj = js_sys::Object::new();
    let data = js_sys::Object::new();

    if comm.get_id() != 0 {
        set_prop(&obj, "id", &JsValue::from_f64(comm.get_id() as f64))?;
    }

    let frame_type = communication_type_name(comm.get_type().0)
        .map(str::to_string)
        .unwrap_or_else(|| comm.get_type().0.to_string());
    set_prop(&obj, "type", &JsValue::from_str(&frame_type))?;

    if comm.get_sender() != 0 {
        set_prop(
            &obj,
            "sender",
            &JsValue::bigint_from_str(&comm.get_sender().to_string()),
        )?;
    }
    if comm.get_receiver() != 0 {
        set_prop(
            &obj,
            "receiver",
            &JsValue::bigint_from_str(&comm.get_receiver().to_string()),
        )?;
    }

    for (key, value) in comm.data() {
        let name = data_type_name(key.0)
            .map(str::to_string)
            .unwrap_or_else(|| key.0.to_string());
        set_prop(&data, &name, &data_value_to_js(value)?)?;
    }
    set_prop(&obj, "data", &data.into())?;
    set_prop(&obj, "raw", &js_sys::Uint8Array::from(frame).into())?;

    Ok(obj.into())
}

/// Build a protocol-level Ping frame with description, timestamp, and optional data.
#[wasm_bindgen]
pub fn build_ping_frame(
    client_id: u64,
    description: &str,
    timestamp: u64,
    data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let mut msg = CommunicationValue::new(CommunicationType::Ping)
        .add_typed_default(
            DataType::Description,
            DataValue::Str(description.to_string()),
        )
        .add_typed_default(
            DataType::Timestamp,
            DataValue::UnsignedNumber(timestamp as u128),
        )
        .with_sender(client_id);

    if !data.is_empty() {
        msg = msg.add_typed_default(DataType::Id, DataValue::Bytes(data.to_vec()));
    }

    msg.to_bytes()
        .map_err(|e| js_error(&format!("encode failed: {}", e)))
}

/// Parse an auth response frame into a JS object.
#[wasm_bindgen]
pub fn parse_auth_response(response: &[u8]) -> Result<JsValue, JsValue> {
    let comm = CommunicationValue::from_bytes(response)
        .map_err(|e| js_error(&format!("parse failed: {}", e)))?;

    let connected = matches!(comm.get_data(DataType::Connected), DataValue::BoolTrue);

    let client_nonce = match comm.get_data(DataType::ClientNonce) {
        DataValue::UnsignedNumber(n) => Some(*n),
        _ => None,
    };

    let assigned_id = match comm.get_data(DataType::Id) {
        DataValue::UnsignedNumber(n) => Some(*n as u64),
        _ => None,
    };

    let timestamp = match comm.get_data(DataType::Timestamp) {
        DataValue::UnsignedNumber(n) => Some(*n),
        _ => None,
    };

    let signature = match comm.get_data(DataType::Signature) {
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

/// Parse any MTP frame into the human-readable CommunicationValue display form.
#[wasm_bindgen]
pub fn format_frame(frame: &[u8]) -> Result<String, JsValue> {
    let comm = CommunicationValue::from_bytes(frame)
        .map_err(|e| js_error(&format!("parse failed: {}", e)))?;
    Ok(comm.to_string())
}

/// Parse any MTP frame into structured JavaScript data.
#[wasm_bindgen(unchecked_return_type = "ParsedFrame")]
pub fn parse_frame(frame: &[u8]) -> Result<JsValue, JsValue> {
    parse_frame_value(frame)
}

/// Build a typed MTP frame using generated communication/data type names.
#[wasm_bindgen]
pub fn build_frame(
    message_type: &str,
    data: JsValue,
    options: JsValue,
) -> Result<Vec<u8>, JsValue> {
    let comm_type = CommunicationType::from_name(message_type)
        .ok_or_else(|| js_error(&format!("unknown communication type: {message_type}")))?;
    let mut msg = CommunicationValue::new(comm_type);

    if !options.is_null() && !options.is_undefined() {
        if let Some(id) = option_u32(&options, "id")? {
            msg = msg.with_id(id);
        }
        if let Some(sender) = option_u64(&options, "sender")? {
            msg = msg.with_sender(sender);
        }
        if let Some(receiver) = option_u64(&options, "receiver")? {
            msg = msg.with_receiver(receiver);
        }
    }

    if data.is_object() && !js_sys::Uint8Array::instanceof(&data) && !js_sys::Array::is_array(&data)
    {
        let object = js_sys::Object::from(data);
        let keys = js_sys::Object::keys(&object);
        for key in keys.iter() {
            let key = key
                .as_string()
                .ok_or_else(|| js_error("object key must be a string"))?;
            let data_type = DataType::from_name(&key)
                .ok_or_else(|| js_error(&format!("unknown data type: {key}")))?;
            let value = js_sys::Reflect::get(&object, &JsValue::from_str(&key))?;
            msg = msg.add_data(
                data_type.to_id(&TypeMap::latest()),
                js_to_data_value(&value)?,
            );
        }
    } else if !data.is_null() && !data.is_undefined() {
        return Err(js_error(
            "frame data must be an object keyed by MTP data type",
        ));
    }

    msg.to_bytes()
        .map_err(|e| js_error(&format!("encode failed: {}", e)))
}

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn build_ping_frame_roundtrip() {
        let bytes = build_ping_frame(42, "test-ping", 1234567890, &[]).expect("encode failed");
        let cv = CommunicationValue::from_bytes(&bytes).expect("decode failed");
        let tm = TypeMap::latest();

        assert_eq!(cv.get_type(), CommunicationType::Ping.to_id(&tm));
        assert_eq!(cv.get_sender(), 42);
        assert_eq!(
            cv.get_data(DataType::Description),
            &DataValue::Str("test-ping".into())
        );
        assert_eq!(
            cv.get_data(DataType::Timestamp),
            &DataValue::UnsignedNumber(1234567890)
        );
    }

    #[wasm_bindgen_test]
    fn build_ping_frame_with_data() {
        let payload = b"attachment-data";
        let bytes = build_ping_frame(99, "with-data", 555, payload).expect("encode failed");
        let cv = CommunicationValue::from_bytes(&bytes).expect("decode failed");
        let tm = TypeMap::latest();

        assert_eq!(cv.get_type(), CommunicationType::Ping.to_id(&tm));
        assert_eq!(cv.get_sender(), 99);
        assert_eq!(
            cv.get_data(DataType::Description),
            &DataValue::Str("with-data".into())
        );
        assert_eq!(
            cv.get_data(DataType::Timestamp),
            &DataValue::UnsignedNumber(555)
        );
        assert_eq!(
            cv.get_data(DataType::Id),
            &DataValue::Bytes(payload.to_vec())
        );
    }

    #[wasm_bindgen_test]
    fn build_ping_frame_client_id_zero() {
        let bytes = build_ping_frame(0, "zero-id", 0, &[]).expect("encode failed");
        let cv = CommunicationValue::from_bytes(&bytes).expect("decode failed");
        assert_eq!(cv.get_sender(), 0);
    }

    #[wasm_bindgen_test]
    fn parse_auth_response_success() {
        let resp = CommunicationValue::new(CommunicationType::IdentificationResponse)
            .add_typed_default(DataType::Connected, DataValue::BoolTrue)
            .add_typed_default(DataType::ClientNonce, DataValue::UnsignedNumber(999))
            .add_typed_default(DataType::Id, DataValue::UnsignedNumber(42))
            .add_typed_default(DataType::Timestamp, DataValue::UnsignedNumber(12345))
            .to_bytes()
            .expect("encode failed");

        let result = parse_auth_response(&resp).expect("parse failed");

        let connected = js_sys::Reflect::get(&result, &"connected".into())
            .ok()
            .and_then(|v| v.as_bool());
        assert_eq!(connected, Some(true));

        let id = js_sys::Reflect::get(&result, &"assignedId".into())
            .ok()
            .and_then(|v| v.as_f64());
        assert_eq!(id, Some(42.0));
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
}
