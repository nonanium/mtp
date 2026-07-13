use mtp_common::CodecError;
use mtp_type_map::{PROTOCOL_VERSION, TypeMap, Version};

use crate::CommunicationValue;

pub use mtp_type_map::Registry;

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
        value.to_bytes()
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
