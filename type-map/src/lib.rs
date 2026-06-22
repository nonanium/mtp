#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CommunicationTypeId(pub u16);

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DataTypeId(pub u16);

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
}

include!(concat!(env!("OUT_DIR"), "/types.rs"));
