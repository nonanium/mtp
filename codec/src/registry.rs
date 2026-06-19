use crate::{CodecError, DataValue, decode, encode};
use std::collections::BTreeMap;
use type_map::{TypeMap, Version};

#[derive(Clone, Debug)]
pub struct Registry {
    versions: BTreeMap<Version, TypeMap>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            versions: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, typemap: TypeMap) {
        self.versions.insert(typemap.version.clone(), typemap);
    }

    pub fn get(&self, version: Version) -> Option<&TypeMap> {
        self.versions.get(&version)
    }

    pub fn negotiate(&self, client_versions: &[Version]) -> Option<Version> {
        client_versions
            .iter()
            .filter(|v| self.versions.contains_key(v))
            .max()
            .cloned()
    }

    pub fn latest(&self) -> Option<&TypeMap> {
        self.versions.last_key_value().map(|(_, v)| v)
    }
}

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
            .get(version)
            .ok_or(CodecError::UnknownVersion)?;
        encode(value, typemap)
    }

    pub fn decode(&self, bytes: &[u8], version: Version) -> Result<DataValue, CodecError> {
        let typemap = self
            .registry
            .get(version)
            .ok_or(CodecError::UnknownVersion)?;
        decode(bytes, typemap)
    }

    pub fn negotiate(&self, client_versions: &[Version]) -> Option<Version> {
        self.registry.negotiate(client_versions)
    }
}
