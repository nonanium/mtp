use common::RegistryError;
use std::collections::HashMap;

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CommTypeId(pub u8);

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DataTypeId(pub u16);

/*
 * # Reserved Internal Namespace
 * These are NEVER assigned by a RegistryConfig. They are fixed
 * across all versions for version negotiation & security.
 */

pub const INTERNAL_COMM_RESERVED: std::ops::Range<u8> = 0..16;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InternalCommType {
    VersionNegotiate = 0,
    SecurityHandshake = 1,
    RegistrySync = 2,
    // 3-15 reserved for future internal use
}

impl InternalCommType {
    pub fn as_id(self) -> CommTypeId {
        CommTypeId(self as u8)
    }
}

#[derive(Clone, Debug)]
//                (major  , minor  , patch  );
pub struct Version(pub u16, pub u16, pub u16);

pub struct Registry {
    pub version: Version,
    comm_name_to_id: HashMap<String, u8>,
    comm_id_to_name: HashMap<u8, String>,
    data_name_to_id: HashMap<String, u16>,
    data_id_to_name: HashMap<u16, String>,
}

pub struct RegistryConfig {
    pub version: Version,
    pub communication_types: HashMap<String, u8>,
    pub data_types: HashMap<String, u16>,
}

impl Registry {
    pub fn from_config(cfg: RegistryConfig) -> Result<Self, RegistryError> {
        for (name, &id) in &cfg.communication_types {
            if INTERNAL_COMM_RESERVED.contains(&id) {
                return Err(RegistryError::ReservedCommId(id, name.clone()));
            }
        }

        let mut comm_id_to_name = HashMap::with_capacity(cfg.communication_types.len());
        for (name, id) in &cfg.communication_types {
            comm_id_to_name.insert(*id, name.clone());
        }

        let mut data_id_to_name = HashMap::with_capacity(cfg.data_types.len());
        for (name, id) in &cfg.data_types {
            data_id_to_name.insert(*id, name.clone());
        }

        Ok(Self {
            version: cfg.version,
            comm_name_to_id: cfg.communication_types,
            comm_id_to_name,
            data_name_to_id: cfg.data_types,
            data_id_to_name,
        })
    }

    pub fn resolve_comm(&self, name: &str) -> Option<CommTypeId> {
        self.comm_name_to_id.get(name).copied().map(CommTypeId)
    }

    pub fn parse_comm(&self, id: CommTypeId) -> Option<&str> {
        self.comm_id_to_name.get(&id.0).map(|s| s.as_str())
    }

    pub fn resolve_data(&self, name: &str) -> Option<DataTypeId> {
        self.data_name_to_id.get(name).copied().map(DataTypeId)
    }

    pub fn parse_data(&self, id: DataTypeId) -> Option<&str> {
        self.data_id_to_name.get(&id.0).map(|s| s.as_str())
    }
}
