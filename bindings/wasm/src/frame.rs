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

fn set_prop(obj: &js_sys::Object, key: &str, value: &JsValue) -> Result<(), JsValue> {
    js_sys::Reflect::set(obj, &JsValue::from_str(key), value).map(|_| ())
}

fn integer_value(value: &str) -> JsValue {
    if let Ok(number) = value.parse::<f64>()
        && number.fract() == 0.0
        && number.abs() <= 9_007_199_254_740_991.0
    {
        return JsValue::from_f64(number);
    }
    JsValue::bigint_from_str(value)
}

pub(crate) fn data_value_to_js(value: &DataValue, tm: &TypeMap) -> Result<JsValue, JsValue> {
    match value {
        DataValue::BoolTrue => Ok(JsValue::TRUE),
        DataValue::BoolFalse => Ok(JsValue::FALSE),
        DataValue::Bool(v) => Ok(JsValue::from_bool(*v)),
        DataValue::SignedNumber(n) => Ok(integer_value(&n.to_string())),
        DataValue::UnsignedNumber(n) => Ok(integer_value(&n.to_string())),
        DataValue::Float(value) => Ok(JsValue::from_f64(*value)),
        DataValue::Str(s) => Ok(JsValue::from_str(s)),
        DataValue::Bytes(bytes) => Ok(js_sys::Uint8Array::from(&bytes[..]).into()),
        DataValue::Array(values) => {
            let arr = js_sys::Array::new();
            for value in values {
                arr.push(&data_value_to_js(value, tm)?);
            }
            Ok(arr.into())
        }
        DataValue::Container(entries) => {
            let obj = js_sys::Object::new();
            for (key, value) in entries {
                let name = tm
                    .data_type_name(key.0)
                    .map(str::to_string)
                    .unwrap_or_else(|| key.0.to_string());
                set_prop(&obj, &name, &data_value_to_js(value, tm)?)?;
            }
            Ok(obj.into())
        }
        DataValue::Encrypted(encrypted) => {
            let obj = js_sys::Object::new();
            set_prop(&obj, "kind", &JsValue::from_str("encrypted"))?;
            set_prop(
                &obj,
                "encryptionType",
                &JsValue::from_f64(encrypted.encryption_type.to_byte() as f64),
            )?;
            set_prop(
                &obj,
                "purpose",
                &JsValue::from_f64(encrypted.purpose as f64),
            )?;
            set_prop(
                &obj,
                "recipientCount",
                &JsValue::from_f64(encrypted.recipients.len() as f64),
            )?;
            let encoded = value
                .to_bytes()
                .map_err(|e| js_error(format!("encode protected value: {e}")))?;
            set_prop(
                &obj,
                "encoded",
                &js_sys::Uint8Array::from(&encoded[..]).into(),
            )?;
            Ok(obj.into())
        }
        DataValue::Signed(signed) => {
            let obj = js_sys::Object::new();
            set_prop(&obj, "kind", &JsValue::from_str("signed"))?;
            set_prop(
                &obj,
                "signatureType",
                &JsValue::from_f64(signed.algorithm as f64),
            )?;
            set_prop(&obj, "purpose", &JsValue::from_f64(signed.purpose as f64))?;
            set_prop(
                &obj,
                "signerId",
                &JsValue::bigint_from_str(&signed.signer_id.to_string()),
            )?;
            set_prop(&obj, "value", &data_value_to_js(&signed.value, tm)?)?;
            Ok(obj.into())
        }
        DataValue::Null => Ok(JsValue::NULL),
    }
}

const MAX_SAFE_INT: f64 = 9007199254740991.0; // 2^53 - 1

struct JsDataValueEncodeContext {
    limits: EncodeLimits,
    values: usize,
}

impl JsDataValueEncodeContext {
    fn visit(&mut self, depth: usize) -> Result<(), JsValue> {
        if depth > self.limits.max_depth {
            return Err(js_error("MTP DataValue nesting-depth limit exceeded"));
        }
        self.values = self
            .values
            .checked_add(1)
            .ok_or_else(|| js_error("MTP DataValue value-count limit exceeded"))?;
        if self.values > self.limits.max_values {
            return Err(js_error("MTP DataValue value-count limit exceeded"));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn js_to_data_value(value: &JsValue, tm: &TypeMap) -> Result<DataValue, JsValue> {
    js_to_data_value_with_limits(value, tm, EncodeLimits::default())
}

pub(crate) fn js_to_data_value_with_limits(
    value: &JsValue,
    tm: &TypeMap,
    limits: EncodeLimits,
) -> Result<DataValue, JsValue> {
    let mut context = JsDataValueEncodeContext { limits, values: 0 };
    js_to_data_value_with_context(value, tm, &mut context, 0)
}

fn js_to_data_value_with_context(
    value: &JsValue,
    tm: &TypeMap,
    context: &mut JsDataValueEncodeContext,
    depth: usize,
) -> Result<DataValue, JsValue> {
    context.visit(depth)?;
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
        if array.length() as usize > context.limits.max_values {
            return Err(js_error("MTP DataValue value-count limit exceeded"));
        }
        let mut values = Vec::with_capacity(array.length() as usize);
        for item in array.iter() {
            values.push(js_to_data_value_with_context(
                &item,
                tm,
                context,
                depth + 1,
            )?);
        }
        return Ok(DataValue::Array(values));
    }
    if let Some(v) = value.as_f64() {
        if v.is_finite() && v.fract() == 0.0 && (-(MAX_SAFE_INT + 1.0)..=MAX_SAFE_INT).contains(&v)
        {
            if v >= 0.0 {
                return Ok(DataValue::UnsignedNumber(v as u128));
            } else {
                return Ok(DataValue::SignedNumber(v as i128));
            }
        }
        return Ok(DataValue::Float(v));
    }

    let type_name = value.js_typeof().as_string().unwrap_or_default();
    if type_name == "bigint" {
        let bigint = value.clone().unchecked_into::<js_sys::BigInt>();
        let as_string = bigint
            .to_string(10)?
            .as_string()
            .ok_or_else(|| js_error("failed to stringify bigint"))?;
        if let Some(unsigned) = as_string.strip_prefix('-') {
            let magnitude = unsigned
                .parse::<u128>()
                .map_err(|_| js_error("bigint out of range"))?;
            if magnitude > (1u128 << 127) {
                return Err(js_error("bigint out of range"));
            }
            if magnitude == (1u128 << 127) {
                return Ok(DataValue::SignedNumber(i128::MIN));
            }
            return Ok(DataValue::SignedNumber(-(magnitude as i128)));
        }
        let n = as_string
            .parse::<u128>()
            .map_err(|_| js_error("bigint out of range"))?;
        return Ok(DataValue::UnsignedNumber(n));
    }

    if value.is_object() {
        let object = js_sys::Object::from(value.clone());
        let keys = js_sys::Object::keys(&object);
        if keys.length() as usize > context.limits.max_values {
            return Err(js_error("MTP DataValue value-count limit exceeded"));
        }
        let mut entries = Vec::with_capacity(keys.length() as usize);
        for key in keys.iter() {
            let key = key
                .as_string()
                .ok_or_else(|| js_error("object key must be a string"))?;
            let data_type = DataType::from_name(&key)
                .ok_or_else(|| js_error(format!("unknown data type: {key}")))?;
            let value = js_sys::Reflect::get(&object, &JsValue::from_str(&key))?;
            let id = data_type.try_to_id(tm).ok_or_else(|| {
                js_error(format!(
                    "data type {key} is not available in protocol version {}",
                    tm.version
                ))
            })?;
            entries.push((
                id,
                js_to_data_value_with_context(&value, tm, context, depth + 1)?,
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

    set_prop(&obj, "data", &data_value_to_js(comm.payload(), &tm)?)?;
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

/// Parse a standalone serialized `DataValue` into the same structured form
/// used for frame payloads. Protected values remain opaque until the caller
/// explicitly opens and verifies them.
#[wasm_bindgen(unchecked_return_type = "ParsedDataValue")]
pub fn parse_data_value(value: &[u8]) -> Result<JsValue, JsValue> {
    parse_data_value_with_decode_limits(value, DecodeLimits::default())
}

fn parse_data_value_with_decode_limits(
    value: &[u8],
    limits: DecodeLimits,
) -> Result<JsValue, JsValue> {
    let value = DataValue::try_from_bytes_with_limits(value, limits)
        .map_err(|error| decode_error(error, "decode data value failed"))?;
    let tm = TypeMap::new(PROTOCOL_VERSION);
    data_value_to_js(&value, &tm)
}

/// Parse a standalone serialized `DataValue` with the caller's bounded
/// receive policy. The compatibility `parse_data_value` entry point retains
/// the default policy for existing callers.
#[wasm_bindgen(unchecked_return_type = "ParsedDataValue")]
pub fn parse_data_value_with_limits(value: &[u8], limits: JsValue) -> Result<JsValue, JsValue> {
    let limits = crate::client::decode_limits_from_js(&limits)?;
    parse_data_value_with_decode_limits(value, limits)
}

/// Encode one standalone `DataValue` using the negotiated/current type map.
#[wasm_bindgen]
pub fn encode_data_value(value: JsValue) -> Result<Vec<u8>, JsValue> {
    encode_data_value_with_encode_limits(value, EncodeLimits::default())
}

fn encode_data_value_with_encode_limits(
    value: JsValue,
    limits: EncodeLimits,
) -> Result<Vec<u8>, JsValue> {
    let tm = TypeMap::new(PROTOCOL_VERSION);
    js_to_data_value_with_limits(&value, &tm, limits)?
        .to_bytes_with_limits(limits)
        .map_err(|e| js_error(format!("encode data value failed: {e}")))
}

/// Encode one standalone `DataValue` using explicit recursion and output
/// limits. The compatibility entry point above keeps the historical default.
#[wasm_bindgen]
pub fn encode_data_value_with_limits(value: JsValue, limits: JsValue) -> Result<Vec<u8>, JsValue> {
    let limits = crate::client::encode_limits_from_js(&limits)?;
    encode_data_value_with_encode_limits(value, limits)
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

/// Merge the clear payload of `source` into `destination` using MTP's
/// shallow, left-biased payload merge rules.
///
/// The returned frame retains destination identity and routing metadata.
/// Both inputs must be complete, compatible MTP frames with clear container
/// payloads. Signed and encrypted payloads are intentionally opaque and are
/// therefore rejected by this operation.
#[wasm_bindgen]
pub fn merge_frame_payload_from(destination: &[u8], source: &[u8]) -> Result<Vec<u8>, JsValue> {
    Ok(merge_frames(
        destination,
        source,
        MergeOptions::default(),
        DecodeLimits::default(),
        EncodeLimits::default(),
    )?
    .0)
}

/// Merge clear payload fields and return the merged frame plus MTP diagnostics.
#[wasm_bindgen]
pub fn merge_frame_payload_from_detailed(
    destination: &[u8],
    source: &[u8],
    options: JsValue,
) -> Result<JsValue, JsValue> {
    let (frame, report) = merge_frames(
        destination,
        source,
        merge_options_from_js(&options)?,
        DecodeLimits::default(),
        EncodeLimits::default(),
    )?;
    merge_result_to_js(frame, report)
}

/// Bounded detailed frame merge. The decode policy applies to both inputs and
/// the encode policy applies to structural validation and the output frame.
#[wasm_bindgen]
pub fn merge_frame_payload_from_detailed_with_limits(
    destination: &[u8],
    source: &[u8],
    options: JsValue,
    decode_limits: JsValue,
    encode_limits: JsValue,
) -> Result<JsValue, JsValue> {
    let (frame, report) = merge_frames(
        destination,
        source,
        merge_options_from_js(&options)?,
        crate::client::decode_limits_from_js(&decode_limits)?,
        crate::client::encode_limits_from_js(&encode_limits)?,
    )?;
    merge_result_to_js(frame, report)
}

/// Merge two serialized clear `DataValue::Container` values before frame
/// construction, signing, or encryption.
#[wasm_bindgen]
pub fn merge_data_value_containers(destination: &[u8], source: &[u8]) -> Result<Vec<u8>, JsValue> {
    let (value, _) = merge_data_values(
        destination,
        source,
        MergeOptions::default(),
        DecodeLimits::default(),
        EncodeLimits::default(),
    )?;
    Ok(value)
}

#[wasm_bindgen]
pub fn merge_data_value_containers_detailed_with_limits(
    destination: &[u8],
    source: &[u8],
    options: JsValue,
    decode_limits: JsValue,
    encode_limits: JsValue,
) -> Result<JsValue, JsValue> {
    let (value, report) = merge_data_values(
        destination,
        source,
        merge_options_from_js(&options)?,
        crate::client::decode_limits_from_js(&decode_limits)?,
        crate::client::encode_limits_from_js(&encode_limits)?,
    )?;
    merge_result_to_js(value, report)
}

fn merge_frames(
    destination: &[u8],
    source: &[u8],
    options: MergeOptions,
    decode_limits: DecodeLimits,
    encode_limits: EncodeLimits,
) -> Result<(Vec<u8>, MergeReport), JsValue> {
    let mut destination =
        CommunicationValue::try_from_bytes_with_limits(destination, decode_limits)
            .map_err(|error| decode_error(error, "invalid destination frame"))?;
    let source = CommunicationValue::try_from_bytes_with_limits(source, decode_limits)
        .map_err(|error| decode_error(error, "invalid source frame"))?;

    let report = destination
        .try_merge_payload_from_with_limits(&source, options, encode_limits)
        .map_err(|error| js_error(format!("payload merge failed: {error}")))?;
    let frame = destination
        .to_bytes_with_limits(encode_limits)
        .map_err(|error| js_error(format!("encode merged frame failed: {error}")))?;
    Ok((frame, report))
}

fn merge_data_values(
    destination: &[u8],
    source: &[u8],
    options: MergeOptions,
    decode_limits: DecodeLimits,
    encode_limits: EncodeLimits,
) -> Result<(Vec<u8>, MergeReport), JsValue> {
    let mut destination = DataValue::try_from_bytes_with_limits(destination, decode_limits)
        .map_err(|error| decode_error(error, "invalid destination data value"))?;
    let source = DataValue::try_from_bytes_with_limits(source, decode_limits)
        .map_err(|error| decode_error(error, "invalid source data value"))?;
    let source_entries = source
        .container_entries()
        .ok_or_else(|| js_error("source data value is not a container"))?;
    let destination_entries = destination
        .container_entries_mut()
        .ok_or_else(|| js_error("destination data value is not a container"))?;
    let report = merge_container_from_with_limits(
        destination_entries,
        source_entries,
        options,
        encode_limits,
    )
    .map_err(|error| js_error(format!("data-value merge failed: {error}")))?;
    let value = destination
        .to_bytes_with_limits(encode_limits)
        .map_err(|error| js_error(format!("encode merged data value failed: {error}")))?;
    Ok((value, report))
}

fn merge_options_from_js(options: &JsValue) -> Result<MergeOptions, JsValue> {
    let mut result = MergeOptions::default();
    if options.is_null() || options.is_undefined() {
        return Ok(result);
    }
    let conflicts = js_sys::Reflect::get(options, &JsValue::from_str("conflicts"))?;
    if !conflicts.is_null() && !conflicts.is_undefined() {
        result.conflicts = match conflicts.as_string().as_deref() {
            Some("keep-left") => MergeConflictPolicy::KeepLeft,
            Some("keep-right") => MergeConflictPolicy::KeepRight,
            Some("require-equal") => MergeConflictPolicy::RequireEqual,
            Some("reject") => MergeConflictPolicy::Reject,
            _ => {
                return Err(js_error(
                    "conflicts must be keep-left, keep-right, require-equal, or reject",
                ));
            }
        };
    }
    let recursive = js_sys::Reflect::get(options, &JsValue::from_str("recursiveContainers"))?;
    if !recursive.is_null() && !recursive.is_undefined() {
        result.recursive_containers = recursive
            .as_bool()
            .ok_or_else(|| js_error("recursiveContainers must be a boolean"))?;
    }
    Ok(result)
}

fn merge_result_to_js(frame: Vec<u8>, report: MergeReport) -> Result<JsValue, JsValue> {
    let result = js_sys::Object::new();
    set_prop(
        &result,
        "frame",
        &js_sys::Uint8Array::from(frame.as_slice()).into(),
    )?;
    let report_value = js_sys::Object::new();
    for (name, paths) in [
        ("inserted", report.inserted),
        ("preserved", report.preserved),
        ("replaced", report.replaced),
        ("matched", report.matched),
        ("recursed", report.recursed),
    ] {
        let values = js_sys::Array::new();
        for path in paths {
            values.push(&merge_path_to_js(path));
        }
        set_prop(&report_value, name, &values.into())?;
    }
    set_prop(&result, "report", &report_value.into())?;
    Ok(result.into())
}

fn merge_path_to_js(path: MergePath) -> JsValue {
    let result = js_sys::Array::new();
    for id in path.into_vec() {
        result.push(&JsValue::from_f64(f64::from(id.0)));
    }
    result.into()
}

#[cfg(test)]
mod merge_tests {
    use super::*;
    use mtp_type_map::DataTypeId;

    #[test]
    fn frame_merge_uses_codec_left_bias() {
        let destination = CommunicationValue::new(CommunicationType::Ping)
            .with_id(7)
            .with_payload(DataValue::Container(vec![(
                DataTypeId(1),
                DataValue::UnsignedNumber(1),
            )]));
        let source = CommunicationValue::new(CommunicationType::Ping).with_payload(
            DataValue::Container(vec![
                (DataTypeId(1), DataValue::UnsignedNumber(99)),
                (DataTypeId(2), DataValue::UnsignedNumber(2)),
            ]),
        );

        let merged = merge_frame_payload_from(
            &destination.to_bytes().unwrap(),
            &source.to_bytes().unwrap(),
        )
        .unwrap();
        let merged = CommunicationValue::from_bytes(&merged).unwrap();
        assert_eq!(merged.id(), Some(7));
        assert_eq!(
            merged.data(),
            Some(
                &[
                    (DataTypeId(1), DataValue::UnsignedNumber(1)),
                    (DataTypeId(2), DataValue::UnsignedNumber(2)),
                ][..]
            )
        );
    }
}

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
mod tests {
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
        let data = js_sys::Reflect::get(&parsed, &JsValue::from_str("data"))
            .expect("data should be present");
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
        let signed = js_sys::Reflect::get(&parsed, &"data".into())
            .expect("signed payload should be present");
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

        let frame = build_frame_with_payload("Pong", &payload, options.into())
            .expect("frame encoding failed");
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
            let encoded = js_to_data_value(&JsValue::from_f64(expected), &tm)
                .expect("JS float should encode");
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
}
