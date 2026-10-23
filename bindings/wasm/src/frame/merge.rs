use super::*;

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

pub(super) fn merge_frames(
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

pub(super) fn merge_data_values(
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

pub(super) fn merge_options_from_js(options: &JsValue) -> Result<MergeOptions, JsValue> {
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

pub(super) fn merge_result_to_js(frame: Vec<u8>, report: MergeReport) -> Result<JsValue, JsValue> {
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

pub(super) fn merge_path_to_js(path: MergePath) -> JsValue {
    let result = js_sys::Array::new();
    for id in path.into_vec() {
        result.push(&JsValue::from_f64(f64::from(id.0)));
    }
    result.into()
}
