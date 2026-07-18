pub mod communication_value;
pub mod data_value;

#[cfg(feature = "crypto")]
pub use communication_value::EncryptedPayload;
pub use communication_value::{CommunicationValue, MAX_WIRE_ID};
pub use data_value::{DataKind, DataValue};
pub use mtp_common::CodecError;

pub use mtp_type_map::{
    CommunicationType, CommunicationTypeId, DataType, DataTypeId, PROTOCOL_VERSION, TypeMap,
    Version,
};

pub(crate) fn rand_u32() -> u32 {
    rand::random()
}

#[cfg(feature = "registry")]
pub mod registry;
