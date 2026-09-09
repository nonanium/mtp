use mtp_common::CodecError;
use mtp_type_map::{PROTOCOL_VERSION, TypeMap, Version};

use crate::CommunicationValue;
use crate::EncodeLimits;

pub use mtp_type_map::Registry;

/// Type map used until version negotiation selects an application map.
///
/// Opening handshake fields and communication types are reserved IDs, which
/// are stable across application type-map versions.  The latest map therefore
/// provides a version-independent representation for that bootstrap exchange.
pub fn bootstrap_type_map() -> TypeMap {
    TypeMap::latest()
}

/*
 * A version-aware codec that uses a multi-version registry to resolve
 * the correct TypeMap for encoding and decoding operations.
 */
#[derive(Clone, Debug)]
pub struct VersionedCodec {
    registry: Registry,
    type_map: TypeMap,
}

impl VersionedCodec {
    pub fn new(registry: Registry) -> Self {
        let type_map = registry
            .latest()
            .cloned()
            .unwrap_or_else(|| TypeMap::new(PROTOCOL_VERSION));
        Self { registry, type_map }
    }

    /// Create a codec bound to a negotiated protocol version.
    pub fn for_version(registry: Registry, version: Version) -> Option<Self> {
        let type_map = registry.get(&version)?.clone();
        Some(Self { registry, type_map })
    }

    /// Return the type map used by this codec.
    pub fn type_map(&self) -> &TypeMap {
        &self.type_map
    }

    /// Return the protocol version used by this codec.
    pub fn version(&self) -> &Version {
        &self.type_map.version
    }

    /// Encode a value using the codec's negotiated framing rules.
    pub fn encode(&self, value: &CommunicationValue) -> Result<Vec<u8>, CodecError> {
        self.encode_with_limits(value, EncodeLimits::default())
    }

    /// Encode using an explicit output/resource limit after verifying the
    /// value belongs to this codec's negotiated type map.
    pub fn encode_with_limits(
        &self,
        value: &CommunicationValue,
        limits: EncodeLimits,
    ) -> Result<Vec<u8>, CodecError> {
        let value_map = value.type_map().ok_or(CodecError::MissingTypeMap)?;
        if value_map.version != self.type_map.version {
            return Err(CodecError::TypeMapMismatch {
                expected: self.type_map.version.to_string(),
                actual: value_map.version.to_string(),
            });
        }
        value.to_bytes_with_limits(limits)
    }

    /// Explicitly migrate a clear frame to this codec's negotiated type map
    /// before encoding it.
    pub fn encode_migrating(&self, value: &CommunicationValue) -> Result<Vec<u8>, CodecError> {
        self.encode_migrating_with_limits(value, EncodeLimits::default())
    }

    /// Explicitly migrate and encode with bounded traversal/output.
    pub fn encode_migrating_with_limits(
        &self,
        value: &CommunicationValue,
        limits: EncodeLimits,
    ) -> Result<Vec<u8>, CodecError> {
        value
            .migrate_with_limits(&self.type_map, limits)?
            .to_bytes_with_limits(limits)
    }

    /// Decode a frame and retain the negotiated type map for typed access.
    pub fn decode(&self, bytes: &[u8]) -> Result<CommunicationValue, CodecError> {
        CommunicationValue::from_bytes_with(bytes, &self.type_map)
    }

    pub fn negotiate(&self, client_versions: &[Version]) -> Option<Version> {
        self.registry.negotiate(client_versions)
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DataValue;
    use mtp_type_map::{CommunicationType, Version};

    #[test]
    fn encode_rejects_a_value_from_another_negotiated_map() {
        let mut registry = Registry::new();
        let version_a = Version::new(3, 0);
        let version_b = Version::new(4, 0);
        registry.register(TypeMap::new(version_a.clone()));
        registry.register(TypeMap::new(version_b.clone()));

        let codec = VersionedCodec::for_version(registry, version_b).expect("codec version");
        let value = CommunicationValue::new_with_type_map(
            CommunicationType::Ping,
            &TypeMap::new(version_a.clone()),
        )
        .with_payload(DataValue::Null);

        assert_eq!(
            codec.encode(&value),
            Err(CodecError::TypeMapMismatch {
                expected: "4.0".into(),
                actual: "3.0".into(),
            })
        );
    }
}
