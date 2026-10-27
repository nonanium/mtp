//! Dictionary negotiation uses reserved fields before any application decoding.
use crate::{CommunicationValue, DataType, DataValue, TypeMap, Version};
use mtp_common::CommunicationError;

fn incompatible() -> CommunicationError {
    CommunicationError::ProtocolViolation("incompatible type-map dictionary".into())
}

fn unique_field(
    frame: &CommunicationValue,
    kind: DataType,
) -> Result<&DataValue, CommunicationError> {
    let map = frame.type_map().ok_or_else(incompatible)?;
    let id = kind.try_to_id(map).ok_or_else(incompatible)?;
    let mut fields = frame
        .payload()
        .container_entries()
        .ok_or_else(incompatible)?
        .iter()
        .filter(|(key, _)| *key == id);
    let (_, value) = fields.next().ok_or_else(incompatible)?;
    if fields.next().is_some() {
        return Err(incompatible());
    }
    Ok(value)
}

pub fn offer(versions: &[Version]) -> Result<DataValue, CommunicationError> {
    if versions.is_empty() || versions.len() > 32 {
        return Err(incompatible());
    }
    Ok(DataValue::Array(
        versions
            .iter()
            .map(|version| {
                TypeMap::new(version.clone())
                    .fingerprint()
                    .map(|digest| DataValue::Bytes(digest.to_vec()))
                    .ok_or_else(incompatible)
            })
            .collect::<Result<_, _>>()?,
    ))
}

/// Fingerprints correspond positionally to the version offer. Never select a
/// lower version to conceal a dictionary conflict on the selected version.
pub fn verify_offer(
    frame: &CommunicationValue,
    versions: &[Version],
    selected: &TypeMap,
) -> Result<(), CommunicationError> {
    unique_field(frame, DataType::Version)?;
    let mut seen = std::collections::HashSet::new();
    if frame
        .payload()
        .container_entries()
        .ok_or_else(incompatible)?
        .iter()
        .any(|(key, _)| !seen.insert(*key))
    {
        return Err(incompatible());
    }
    let DataValue::Array(digests) = unique_field(frame, DataType::DictionaryFingerprint)? else {
        return Err(incompatible());
    };
    if versions.is_empty()
        || versions.len() > 32
        || digests.len() != versions.len()
        || versions
            .iter()
            .enumerate()
            .any(|(index, version)| versions[..index].contains(version))
    {
        return Err(incompatible());
    }
    let index = versions
        .iter()
        .position(|version| *version == selected.version)
        .ok_or_else(incompatible)?;
    for digest in digests {
        if !matches!(digest, DataValue::Bytes(bytes) if bytes.len() == 32) {
            return Err(incompatible());
        }
    }
    let expected = value(selected)?;
    if digests[index] != expected {
        return Err(incompatible());
    }
    Ok(())
}

pub fn value(map: &TypeMap) -> Result<DataValue, CommunicationError> {
    Ok(DataValue::Bytes(
        map.fingerprint().ok_or_else(incompatible)?.to_vec(),
    ))
}

pub fn verify_selection(
    frame: &CommunicationValue,
    map: &TypeMap,
) -> Result<(), CommunicationError> {
    if frame.get_data(DataType::Version).is_some()
        && unique_field(frame, DataType::Version)? != &DataValue::Str(map.version.to_string()) {
        return Err(incompatible());
    }
    if unique_field(frame, DataType::DictionaryFingerprint)? != &value(map)? {
        return Err(incompatible());
    }
    Ok(())
}

/// This domain and fixed-size digest bind every authentication signature to the
/// selected dictionary, including the host challenge and final confirmation.
pub fn bind_authentication(map: &TypeMap, payload: Vec<u8>) -> Result<Vec<u8>, CommunicationError> {
    let mut bound = b"mtp-dictionary-auth\0v1\0".to_vec();
    bound.extend_from_slice(&map.fingerprint().ok_or_else(incompatible)?);
    bound.extend_from_slice(&payload);
    Ok(bound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CommunicationType;

    fn opening(map: &TypeMap) -> CommunicationValue {
        CommunicationValue::new_with_type_map(CommunicationType::Identification, map)
            .add_typed_default(
                DataType::Version,
                DataValue::Array(vec![DataValue::Str(map.version.to_string())]),
            )
            .add_typed_default(
                DataType::DictionaryFingerprint,
                offer(std::slice::from_ref(&map.version)).unwrap(),
            )
    }

    #[test]
    fn same_version_requires_the_exact_dictionary() {
        let map = TypeMap::latest();
        let frame = opening(&map);
        verify_offer(&frame, std::slice::from_ref(&map.version), &map).unwrap();
        let wrong = frame.with_data(
            DataType::DictionaryFingerprint,
            DataValue::Array(vec![DataValue::Bytes(vec![0; 32])]),
        );
        assert!(verify_offer(&wrong, std::slice::from_ref(&map.version), &map).is_err());
    }

    #[test]
    fn missing_duplicate_and_misaligned_offers_are_incompatible() {
        let map = TypeMap::latest();
        let frame = opening(&map);
        let missing =
            CommunicationValue::new_with_type_map(CommunicationType::Identification, &map);
        let mut duplicated = frame.payload().clone();
        let id = DataType::DictionaryFingerprint.try_to_id(&map).unwrap();
        duplicated
            .container_entries_mut()
            .unwrap()
            .push((id, offer(std::slice::from_ref(&map.version)).unwrap()));
        let duplicate = frame.clone().with_payload(duplicated);
        let wrong_count =
            frame.with_data(DataType::DictionaryFingerprint, DataValue::Array(vec![]));
        for invalid in [missing, duplicate, wrong_count] {
            assert!(verify_offer(&invalid, std::slice::from_ref(&map.version), &map).is_err());
        }
        assert!(offer(&[Version(u16::MAX, u16::MAX)]).is_err());
    }

    #[test]
    fn selection_and_authentication_are_dictionary_bound() {
        let map = TypeMap::latest();
        let response =
            CommunicationValue::new_with_type_map(CommunicationType::IdentificationResponse, &map)
                .add_typed_default(DataType::DictionaryFingerprint, value(&map).unwrap());
        verify_selection(&response, &map).unwrap();
        assert!(
            verify_selection(
                &response.with_data(
                    DataType::DictionaryFingerprint,
                    DataValue::Bytes(vec![0; 32])
                ),
                &map
            )
            .is_err()
        );
        let signed = bind_authentication(&map, vec![0x10, 1, 2, 3]).unwrap();
        assert!(signed.starts_with(b"mtp-dictionary-auth\0v1\0"));
        assert!(
            signed
                .windows(32)
                .any(|bytes| bytes == map.fingerprint().unwrap())
        );
        assert!(signed.ends_with(&[0x10, 1, 2, 3]));
    }
}
