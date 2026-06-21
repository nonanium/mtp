pub use registry::Registry;

use crate::{CodecError, DataValue, decode, encode};
use mtp_type_map::Version;

/*
 * A version-aware codec that uses a multi-version registry to resolve
 * the correct TypeMap for encoding and decoding operations.
 */
#[derive(Clone, Debug)]
pub struct VersionedCodec {
    registry: Registry,
}

impl VersionedCodec {
    pub fn new(registry: Registry) -> Self {
        Self { registry }
    }

    pub fn encode(&self, value: &DataValue, version: Version) -> Result<Vec<u8>, CodecError> {
        let typemap = self
            .registry
            .get(&version)
            .ok_or(CodecError::UnknownVersion)?;
        encode(value, typemap)
    }

    pub fn decode(&self, bytes: &[u8], version: Version) -> Result<DataValue, CodecError> {
        let typemap = self
            .registry
            .get(&version)
            .ok_or(CodecError::UnknownVersion)?;
        decode(bytes, typemap)
    }

    pub fn negotiate(&self, client_versions: &[Version]) -> Option<Version> {
        self.registry.negotiate(client_versions)
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}
