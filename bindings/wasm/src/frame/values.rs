use super::*;

pub(super) fn set_prop(obj: &js_sys::Object, key: &str, value: &JsValue) -> Result<(), JsValue> {
    js_sys::Reflect::set(obj, &JsValue::from_str(key), value).map(|_| ())
}

pub(super) fn integer_value(value: &str) -> JsValue {
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

impl JsDataValueEncodeContext {
    pub(super) fn visit(&mut self, depth: usize) -> Result<(), JsValue> {
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

pub(super) fn js_to_data_value_with_context(
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

/// Parse a standalone serialized `DataValue` into the same structured form
/// used for frame payloads. Protected values remain opaque until the caller
/// explicitly opens and verifies them.
#[wasm_bindgen(unchecked_return_type = "ParsedDataValue")]
pub fn parse_data_value(value: &[u8]) -> Result<JsValue, JsValue> {
    parse_data_value_with_decode_limits(value, DecodeLimits::default())
}

pub(super) fn parse_data_value_with_decode_limits(
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

pub(super) fn encode_data_value_with_encode_limits(
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
