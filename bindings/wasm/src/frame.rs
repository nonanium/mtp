mod values;
#[cfg(test)]
pub(crate) use values::js_to_data_value;
use values::set_prop;
pub(crate) use values::{data_value_to_js, js_to_data_value_with_limits};
pub use values::{
    encode_data_value, encode_data_value_with_limits, parse_data_value,
    parse_data_value_with_limits,
};
mod merge;
pub use merge::{
    merge_data_value_containers, merge_data_value_containers_detailed_with_limits,
    merge_frame_payload_from, merge_frame_payload_from_detailed,
    merge_frame_payload_from_detailed_with_limits,
};
use wasm_bindgen::{JsCast, prelude::*};

use mtp_codec::{
    CommunicationType, CommunicationValue, DataType, DataValue, DecodeLimits, EncodeLimits,
    MergeConflictPolicy, MergeOptions, MergePath, MergeReport, PROTOCOL_VERSION,
    merge_container_from_with_limits,
};
use mtp_type_map::TypeMap;

use crate::error::js_error;
use crate::relay::decode_error;

#[wasm_bindgen(typescript_custom_section)]
const PARSED_FRAME_TS: &'static str = r#"
export interface ParsedEncryptedValue {
  kind: "encrypted";
  encryptionType: number;
  purpose: number;
  recipientCount: number;
  encoded: Uint8Array;
}

export interface ParsedSignedValue {
  kind: "signed";
  signatureType: number;
  purpose: number;
  signerId: bigint;
  value: ParsedDataValue;
}

export type ParsedDataValue =
  | boolean
  | number
  | bigint
  | string
  | Uint8Array
  | ParsedDataValue[]
  | { [key: string]: ParsedDataValue }
  | ParsedEncryptedValue
  | ParsedSignedValue
  | null;

export interface ParsedFrame {
  id?: number;
  type: string;
  sender?: bigint;
  receiver?: bigint;
  data: ParsedDataValue;
  raw: Uint8Array;
}
"#;

const MAX_SAFE_INT: f64 = 9007199254740991.0; // 2^53 - 1

struct JsDataValueEncodeContext {
    limits: EncodeLimits,
    values: usize,
}

fn option_u32(options: &JsValue, key: &str) -> Result<Option<u32>, JsValue> {
    let value = js_sys::Reflect::get(options, &JsValue::from_str(key))?;
    if value.is_null() || value.is_undefined() {
        return Ok(None);
    }
    let Some(n) = value.as_f64() else {
        return Err(js_error(format!("{key} must be a number")));
    };
    if !n.is_finite() || n.fract() != 0.0 || !(0.0..=MAX_SAFE_INT).contains(&n) {
        return Err(js_error(format!("{key} must be an exact integer")));
    }
    let n = u32::try_from(n as u64).map_err(|_| js_error(format!("{key} out of range")))?;
    Ok(Some(n))
}

fn option_u64(options: &JsValue, key: &str) -> Result<Option<u64>, JsValue> {
    let value = js_sys::Reflect::get(options, &JsValue::from_str(key))?;
    if value.is_null() || value.is_undefined() {
        return Ok(None);
    }
    if let Some(n) = value.as_f64() {
        if !n.is_finite() || n.fract() != 0.0 || !(0.0..=MAX_SAFE_INT).contains(&n) {
            return Err(js_error(format!(
                "{key} must be an exact integer number at most 2^53-1 or a bigint"
            )));
        }
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
            .map_err(|_| js_error(format!("{key} out of range")));
    }
    Err(js_error(format!("{key} must be a number or bigint")))
}

fn apply_frame_options(
    mut message: CommunicationValue,
    options: &JsValue,
) -> Result<CommunicationValue, JsValue> {
    if !options.is_null() && !options.is_undefined() {
        if let Some(id) = option_u32(options, "id")? {
            message = message.with_id(id);
        }
        if let Some(sender) = option_u64(options, "sender")? {
            message = message.with_sender(sender);
        }
        if let Some(receiver) = option_u64(options, "receiver")? {
            message = message.with_receiver(receiver);
        }
    }
    Ok(message)
}

pub(crate) fn parse_frame_value(frame: &[u8]) -> Result<JsValue, JsValue> {
    parse_frame_value_with_limits(frame, &TypeMap::latest(), DecodeLimits::default())
}

pub(crate) fn parse_frame_value_with_limits(
    frame: &[u8],
    type_map: &TypeMap,
    limits: DecodeLimits,
) -> Result<JsValue, JsValue> {
    let comm = CommunicationValue::try_from_bytes_with_type_map_and_limits(frame, type_map, limits)
        .map_err(|error| decode_error(error, "parse failed"))?;
    let tm = type_map;
    let obj = js_sys::Object::new();

    if let Some(id) = comm.id() {
        set_prop(&obj, "id", &JsValue::from_f64(id as f64))?;
    }

    let frame_type = tm
        .communication_type_name(comm.get_type().0)
        .map(str::to_string)
        .unwrap_or_else(|| comm.get_type().0.to_string());
    set_prop(&obj, "type", &JsValue::from_str(&frame_type))?;

    if let Some(sender) = comm.sender() {
        set_prop(
            &obj,
            "sender",
            &JsValue::bigint_from_str(&sender.to_string()),
        )?;
    }
    if let Some(receiver) = comm.receiver() {
        set_prop(
            &obj,
            "receiver",
            &JsValue::bigint_from_str(&receiver.to_string()),
        )?;
    }

    set_prop(&obj, "data", &data_value_to_js(comm.payload(), tm)?)?;
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
        .map_err(|e| js_error(format!("encode failed: {}", e)))
}

/// Parse an auth response frame into a JS object.
#[wasm_bindgen(unchecked_return_type = "AuthResponse")]
pub fn parse_auth_response(response: &[u8]) -> Result<JsValue, JsValue> {
    let comm = CommunicationValue::try_from_bytes_with_limits(response, DecodeLimits::default())
        .map_err(|error| decode_error(error, "parse failed"))?;

    let connected = matches!(
        comm.get_data(DataType::Connected),
        Some(DataValue::BoolTrue)
    );

    let client_nonce = match comm.get_data(DataType::ClientNonce) {
        Some(DataValue::UnsignedNumber(n)) => Some(*n),
        _ => None,
    };

    let assigned_id = match comm.get_data(DataType::Id) {
        Some(DataValue::UnsignedNumber(n)) => {
            Some(u64::try_from(*n).map_err(|_| js_error("assigned ID is out of range"))?)
        }
        _ => None,
    };

    let timestamp = match comm.get_data(DataType::Timestamp) {
        Some(DataValue::UnsignedNumber(n)) => Some(*n),
        _ => None,
    };

    let signature = match comm.get_data(DataType::Signature) {
        Some(DataValue::Bytes(b)) => Some(b.clone()),
        _ => None,
    };

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"connected".into(), &JsValue::from(connected)).ok();
    if let Some(n) = client_nonce {
        let arr = js_sys::Uint8Array::from(&n.to_be_bytes()[..]);
        js_sys::Reflect::set(&obj, &"clientNonce".into(), &arr).ok();
    }
    if let Some(id) = assigned_id {
        js_sys::Reflect::set(
            &obj,
            &"assignedId".into(),
            &JsValue::bigint_from_str(&id.to_string()),
        )
        .ok();
    }
    if let Some(ts) = timestamp {
        js_sys::Reflect::set(
            &obj,
            &"timestamp".into(),
            &JsValue::bigint_from_str(&ts.to_string()),
        )
        .ok();
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
    let comm = CommunicationValue::try_from_bytes_with_limits(frame, DecodeLimits::default())
        .map_err(|error| decode_error(error, "parse failed"))?;
    Ok(comm.to_string())
}

/// Parse any MTP frame into structured JavaScript data.
#[wasm_bindgen(unchecked_return_type = "ParsedFrame")]
pub fn parse_frame(frame: &[u8]) -> Result<JsValue, JsValue> {
    parse_frame_value(frame)
}

/// Parse a frame with the caller's bounded receive policy. The compatibility
/// `parse_frame` entry point retains the default policy for existing callers.
#[wasm_bindgen(unchecked_return_type = "ParsedFrame")]
pub fn parse_frame_with_limits(frame: &[u8], limits: JsValue) -> Result<JsValue, JsValue> {
    let limits = crate::client::decode_limits_from_js(&limits)?;
    parse_frame_value_with_limits(frame, &TypeMap::latest(), limits)
}

/// Build a typed MTP frame using generated communication/data type names.
#[wasm_bindgen]
pub fn build_frame(
    message_type: &str,
    data: JsValue,
    options: JsValue,
) -> Result<Vec<u8>, JsValue> {
    build_frame_with_encode_limits(message_type, data, options, EncodeLimits::default())
}

fn build_frame_with_encode_limits(
    message_type: &str,
    data: JsValue,
    options: JsValue,
    limits: EncodeLimits,
) -> Result<Vec<u8>, JsValue> {
    let comm_type = CommunicationType::from_name(message_type)
        .ok_or_else(|| js_error(format!("unknown communication type: {message_type}")))?;
    let tm = TypeMap::new(PROTOCOL_VERSION);
    let mut msg = apply_frame_options(CommunicationValue::new(comm_type), &options)?;

    if data.is_object() && !js_sys::Uint8Array::instanceof(&data) && !js_sys::Array::is_array(&data)
    {
        let object = js_sys::Object::from(data);
        let keys = js_sys::Object::keys(&object);
        for key in keys.iter() {
            let key = key
                .as_string()
                .ok_or_else(|| js_error("object key must be a string"))?;
            let data_type = DataType::from_name(&key)
                .ok_or_else(|| js_error(format!("unknown data type: {key}")))?;
            let value = js_sys::Reflect::get(&object, &JsValue::from_str(&key))?;
            let id = data_type.try_to_id(&tm).ok_or_else(|| {
                js_error(format!(
                    "data type {key} is not available in protocol version {}",
                    tm.version
                ))
            })?;
            msg = msg
                .add_data(id, js_to_data_value_with_limits(&value, &tm, limits)?)
                .map_err(|e| js_error(format!("add data failed: {e}")))?;
        }
    } else if !data.is_null() && !data.is_undefined() {
        return Err(js_error(
            "frame data must be an object keyed by MTP data type",
        ));
    }

    msg.to_bytes_with_limits(limits)
        .map_err(|e| js_error(format!("encode failed: {}", e)))
}

/// Build a typed frame with explicit recursion and complete-frame output
/// limits. High-level SDK sends use this entry point with the transport's
/// admitted message size.
#[wasm_bindgen]
pub fn build_frame_with_limits(
    message_type: &str,
    data: JsValue,
    options: JsValue,
    limits: JsValue,
) -> Result<Vec<u8>, JsValue> {
    let limits = crate::client::encode_limits_from_js(&limits)?;
    build_frame_with_encode_limits(message_type, data, options, limits)
}

/// Build a typed MTP frame around a complete serialized `DataValue` payload.
///
/// Unlike [`build_frame`], this does not interpret the payload as a clear data
/// container. It can therefore carry any value supported by the codec,
/// including signed and encrypted protection wrappers.
#[wasm_bindgen]
pub fn build_frame_with_payload(
    message_type: &str,
    serialized_payload: &[u8],
    options: JsValue,
) -> Result<Vec<u8>, JsValue> {
    build_frame_with_payload_with_encode_limits(
        message_type,
        serialized_payload,
        options,
        EncodeLimits::default(),
    )
}

fn build_frame_with_payload_with_encode_limits(
    message_type: &str,
    serialized_payload: &[u8],
    options: JsValue,
    limits: EncodeLimits,
) -> Result<Vec<u8>, JsValue> {
    let comm_type = CommunicationType::from_name(message_type)
        .ok_or_else(|| js_error(format!("unknown communication type: {message_type}")))?;
    let payload = DataValue::try_from_bytes_with_limits(
        serialized_payload,
        DecodeLimits::for_transport_message_size(limits.max_output_size as u64),
    )
    .map_err(|error| decode_error(error, "invalid serialized DataValue payload"))?;
    let message =
        apply_frame_options(CommunicationValue::new(comm_type), &options)?.with_payload(payload);

    message
        .to_bytes_with_limits(limits)
        .map_err(|e| js_error(format!("encode failed: {e}")))
}

/// Build a typed frame around a serialized payload with explicit output
/// limits. The payload is also parsed with a policy derived from that limit so
/// an oversized/deep input cannot bypass the bounded builder.
#[wasm_bindgen]
pub fn build_frame_with_payload_with_limits(
    message_type: &str,
    serialized_payload: &[u8],
    options: JsValue,
    limits: JsValue,
) -> Result<Vec<u8>, JsValue> {
    let limits = crate::client::encode_limits_from_js(&limits)?;
    build_frame_with_payload_with_encode_limits(message_type, serialized_payload, options, limits)
}

#[cfg(test)]
mod merge_tests;

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
mod tests;
