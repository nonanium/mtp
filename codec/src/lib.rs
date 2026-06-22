pub mod communication_value;
pub mod data_value;

pub use communication_value::CommunicationValue;
pub use data_value::{DataKind, DataValue};
pub use mtp_common::CodecError;

pub use mtp_type_map::{
    communication_type_name, data_type_name, CommunicationType, CommunicationTypeId, DataType,
    DataTypeId, TypeMap, Version, PROTOCOL_VERSION,
};

pub(crate) fn rand_u32() -> u32 {
    rand::random()
}

#[cfg(feature = "registry")]
pub mod registry;
