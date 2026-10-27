/*
 * try_new returns Result<Self, ()> deliberately: the only failure mode is "id
 * is in the reserved range", which carries no extra information worth an error
 * type. The unit error is the intended API.
 */
#![allow(clippy::result_unit_err)]

pub const INTERNAL_COMM_RESERVED: std::ops::Range<u16> = 0..32;
pub const INTERNAL_DATA_RESERVED: std::ops::Range<u16> = 0..32;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CommunicationTypeId(pub u16);

impl CommunicationTypeId {
    pub fn try_new(id: u16) -> Result<Self, ()> {
        if INTERNAL_COMM_RESERVED.contains(&id) {
            Err(())
        } else {
            Ok(Self(id))
        }
    }

    pub fn is_reserved(&self) -> bool {
        INTERNAL_COMM_RESERVED.contains(&self.0)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DataTypeId(pub u16);

impl DataTypeId {
    pub fn try_new(id: u16) -> Result<Self, ()> {
        if INTERNAL_DATA_RESERVED.contains(&id) {
            Err(())
        } else {
            Ok(Self(id))
        }
    }

    pub fn is_reserved(&self) -> bool {
        INTERNAL_DATA_RESERVED.contains(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(pub u16, pub u16);

impl Version {
    pub fn new(major: u16, minor: u16) -> Self {
        Self(major, minor)
    }

    pub fn parse(s: &str) -> Option<Self> {
        let (major, minor) = s.split_once('.')?;
        Some(Self(major.parse().ok()?, minor.parse().ok()?))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.0, self.1)
    }
}

impl Version {
    pub fn is_newer_than(&self, other: &Version) -> bool {
        self > other
    }

    pub fn is_compatible_with(&self, other: &Version) -> bool {
        self.0 == other.0
    }
}

/*
 * A single protocol version's type dictionary.
 * Compiled into the client, or loaded by the host via the registry.
 *
 * Type-to-wire-ID mappings are generated at compile time and dispatched
 * via `comm_id_enum` / `data_id_enum` based on `self.version`.
 */
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeMap {
    pub version: Version,
}

impl TypeMap {
    pub fn new(version: Version) -> Self {
        Self { version }
    }

    pub fn fingerprint_hex(&self) -> Option<String> {
        Some(
            self.fingerprint()?
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        )
    }
}

include!(concat!(env!("OUT_DIR"), "/types.rs"));

#[cfg(test)]
mod tests {
    use super::{DataType, TypeMap};

    #[test]
    fn current_relay_reserved_fields_use_generic_layout() {
        let type_map = TypeMap::latest();

        assert_eq!(
            DataType::MessageId.try_to_id(&type_map).map(|id| id.0),
            Some(15)
        );
        assert_eq!(
            DataType::FinalRecipientId
                .try_to_id(&type_map)
                .map(|id| id.0),
            Some(18)
        );
        assert_eq!(
            DataType::CreatedAt.try_to_id(&type_map).map(|id| id.0),
            Some(21)
        );
        assert_eq!(
            DataType::MessageType.try_to_id(&type_map).map(|id| id.0),
            Some(22)
        );
        assert_eq!(
            DataType::Content.try_to_id(&type_map).map(|id| id.0),
            Some(23)
        );
        assert_eq!(
            DataType::Metadata.try_to_id(&type_map).map(|id| id.0),
            Some(24)
        );
        assert_eq!(
            DataType::RelayVersion.try_to_id(&type_map).map(|id| id.0),
            Some(25)
        );

        for tombstoned_id in [16, 17, 19, 20] {
            assert_eq!(type_map.data_type_name(tombstoned_id), None);
        }
    }
}

/* ============================= REGISTRY ============================= */
#[cfg(feature = "registry")]
pub use registry::*;

#[cfg(feature = "registry")]
mod registry {
    use crate::{TypeMap, Version, builtin_type_maps};
    use std::collections::BTreeMap;

    /*
     * Multi-version type-map registry.
     *
     * Stores one `TypeMap` per protocol version and provides version
     * negotiation for the host. Hosts build this from the compiled-in
     * type maps (via `Registry::builtin()` or programmatically).
     */
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

        pub fn get(&self, version: &Version) -> Option<&TypeMap> {
            self.versions.get(version)
        }

        pub fn supports(&self, version: &Version) -> bool {
            self.versions.contains_key(version)
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

        pub fn versions(&self) -> impl Iterator<Item = &Version> {
            self.versions.keys()
        }

        pub fn builtin() -> Self {
            let mut r = Self::new();
            for tm in builtin_type_maps() {
                r.register(tm);
            }
            r
        }
    }

    impl Default for Registry {
        fn default() -> Self {
            Self::new()
        }
    }

    /* ================================ TESTS ================================ */
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn builtin_registers_only_the_current_codec_version() {
            let r = Registry::builtin();
            assert!(r.supports(&Version(3, 0)));
            for removed_version in [Version(0, 0), Version(1, 0), Version(2, 0)] {
                assert!(!r.supports(&removed_version));
                assert_eq!(r.negotiate(&[removed_version]), None);
            }
            assert_eq!(
                r.negotiate(&[Version(3, 0), Version(2, 0)]),
                Some(Version(3, 0))
            );
        }

        #[test]
        fn negotiate_finds_highest() {
            let mut r = Registry::new();
            r.register(TypeMap::new(Version(0, 0)));
            r.register(TypeMap::new(Version(1, 0)));
            r.register(TypeMap::new(Version(2, 0)));

            let client = &[Version(0, 0)];
            assert_eq!(r.negotiate(client), Some(Version(0, 0)));

            let client = &[Version(1, 0), Version(0, 0)];
            assert_eq!(r.negotiate(client), Some(Version(1, 0)));

            let client = &[Version(5, 0)];
            assert_eq!(r.negotiate(client), None);
        }

        #[test]
        fn latest_returns_highest() {
            let mut r = Registry::new();
            r.register(TypeMap::new(Version(0, 0)));
            r.register(TypeMap::new(Version(2, 0)));
            r.register(TypeMap::new(Version(1, 0)));

            assert_eq!(r.latest().unwrap().version, Version(2, 0));
        }
    }
}
