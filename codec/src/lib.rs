pub mod communication_value;
pub mod data_value;
pub mod util;

pub use communication_value::CommunicationValue;
pub use data_value::{DataKind, DataValue};

pub use util::rand_u32;

pub use mtp_type_map::{
    communication_type_name, data_type_name, CommunicationType, CommunicationTypeId, DataType,
    DataTypeId, PROTOCOL_VERSION, TypeMap, Version,
};

use mtp_common::CodecError;

pub fn encode(_value: &DataValue, _typemap: &TypeMap) -> Result<Vec<u8>, CodecError> {
    todo!()
}

pub fn decode(_bytes: &[u8], _typemap: &TypeMap) -> Result<DataValue, CodecError> {
    todo!()
}

#[cfg(feature = "registry")]
pub mod registry;
