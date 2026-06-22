use mtp_type_map::Version;

pub use mtp_type_map::Registry;

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

    pub fn negotiate(&self, client_versions: &[Version]) -> Option<Version> {
        self.registry.negotiate(client_versions)
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}
