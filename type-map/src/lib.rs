use std::collections::HashMap;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CommTypeId(pub u8);

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DataTypeId(pub u16);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(pub u16);

/// A single protocol version's type dictionary.
/// Compiled into the client, or loaded by the host via the registry.
#[derive(Clone, Debug)]
pub struct TypeMap {
    pub version: Version,
    pub comm_types: HashMap<String, u8>,
    pub data_types: HashMap<String, u16>,
}

impl TypeMap {
    pub fn comm_id(&self, name: &str) -> Option<u8> {
        self.comm_types.get(name).copied()
    }
    pub fn data_id(&self, name: &str) -> Option<u16> {
        self.data_types.get(name).copied()
    }
}
