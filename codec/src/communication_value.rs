mod merge;
mod migration;
mod wire;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use migration::compatible_optional;
use std::fmt;
use std::io::Cursor;

use crate::data_value::{
    ContainerMergeError, DataKind, DataValue, DecodeError, DecodeLimits, EncodeLimits,
    MergeOptions, MergeReport, merge_container_from_with_limits,
};
use crate::rand_u32;
use mtp_common::CodecError;
use mtp_type_map::{
    CommunicationType, CommunicationTypeId, DataType, DataTypeId, PROTOCOL_VERSION, TypeMap,
};

const FLAG_HAS_ID: u8 = 0b0000_0001;
const FLAG_HAS_SENDER: u8 = 0b0000_0010;
const FLAG_HAS_RECEIVER: u8 = 0b0000_0100;
const FLAG_KNOWN: u8 = FLAG_HAS_ID | FLAG_HAS_SENDER | FLAG_HAS_RECEIVER;

/// A reason why two communication values cannot be payload-merged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MergeError {
    #[error("communication value mapping is invalid: {0}")]
    Mapping(CodecError),
    #[error("type-map versions differ: expected {expected}, actual {actual}")]
    TypeMapMismatch { expected: String, actual: String },
    #[error("communication types differ")]
    CommunicationTypeMismatch,
    #[error("senders are incompatible")]
    SenderMismatch,
    #[error("receivers are incompatible")]
    ReceiverMismatch,
    #[error("left payload is not a container")]
    LeftPayloadNotContainer,
    #[error("right payload is not a container")]
    RightPayloadNotContainer,
    #[error("frame encode limit cannot accommodate merged payload: {0}")]
    FrameLimit(CodecError),
    #[error(transparent)]
    Container(#[from] ContainerMergeError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunicationValue {
    id: Option<u32>,
    comm_type: CommunicationTypeId,
    sender: Option<u64>,
    receiver: Option<u64>,
    payload: DataValue,
    type_map: Option<TypeMap>,
    mapping_error: Option<CodecError>,
}

impl CommunicationValue {
    #[must_use]
    pub fn new(comm_type: CommunicationType) -> Self {
        Self::new_with_type_map(comm_type, &TypeMap::new(PROTOCOL_VERSION))
    }

    /// Construct a frame using an explicitly negotiated type map.
    ///
    /// The type map is local codec context rather than wire data, so callers
    /// that build a frame for a non-latest negotiated version must retain it
    /// on the `CommunicationValue` as well as using it to resolve the fields.
    #[must_use]
    pub fn new_with_type_map(comm_type: CommunicationType, type_map: &TypeMap) -> Self {
        let id = comm_type.try_to_id(type_map);
        Self {
            id: Some(rand_u32()),
            comm_type: id.unwrap_or(CommunicationTypeId(0)),
            sender: None,
            receiver: None,
            payload: DataValue::Container(Vec::new()),
            type_map: Some(type_map.clone()),
            mapping_error: id
                .is_none()
                .then(|| CodecError::UnknownCommunicationType(comm_type.name().to_string())),
        }
    }

    #[cfg(feature = "registry")]
    #[must_use]
    pub fn from_comm(comm_type: CommunicationType, type_map: &TypeMap) -> Self {
        Self::new_with_type_map(comm_type, type_map)
    }

    #[must_use]
    pub fn with_id(mut self, id: u32) -> Self {
        self.id = Some(id);
        self
    }

    #[must_use]
    pub fn without_id(mut self) -> Self {
        self.id = None;
        self
    }

    pub fn id(&self) -> Option<u32> {
        self.id
    }

    #[must_use]
    pub fn with_sender(mut self, sender: u64) -> Self {
        self.sender = Some(sender);
        self
    }

    #[must_use]
    pub fn without_sender(mut self) -> Self {
        self.sender = None;
        self
    }

    pub fn sender(&self) -> Option<u64> {
        self.sender
    }

    #[must_use]
    pub fn with_receiver(mut self, receiver: u64) -> Self {
        self.receiver = Some(receiver);
        self
    }

    #[must_use]
    pub fn without_receiver(mut self) -> Self {
        self.receiver = None;
        self
    }

    pub fn receiver(&self) -> Option<u64> {
        self.receiver
    }

    pub fn get_type(&self) -> CommunicationTypeId {
        self.comm_type
    }

    pub fn type_map(&self) -> Option<&TypeMap> {
        self.type_map.as_ref()
    }

    pub fn set_type_map(&mut self, type_map: &TypeMap) {
        self.type_map = Some(type_map.clone());
    }

    /// Add a field to a clear container payload.
    pub fn add_data(mut self, data_type: DataTypeId, value: DataValue) -> Result<Self, CodecError> {
        self.insert_data(data_type, value)?;
        Ok(self)
    }

    #[cfg(feature = "registry")]
    #[must_use]
    pub fn add_typed(mut self, data: DataType, type_map: &TypeMap, value: DataValue) -> Self {
        match data.try_to_id(type_map) {
            Some(id) => {
                self.insert_data_or_record_error(id, value);
            }
            None if self.mapping_error.is_none() => {
                self.mapping_error = Some(CodecError::UnknownDataType(data.name().to_string()));
            }
            None => {}
        }
        self
    }

    #[must_use]
    pub fn add_typed_default(mut self, data: DataType, value: DataValue) -> Self {
        let type_map = self.type_map.clone().unwrap_or_else(TypeMap::latest);
        match data.try_to_id(&type_map) {
            Some(id) => {
                self.insert_data_or_record_error(id, value);
            }
            None if self.mapping_error.is_none() => {
                self.mapping_error = Some(CodecError::UnknownDataType(data.name().to_string()));
            }
            None => {}
        }
        self
    }

    fn insert_data(&mut self, data_type: DataTypeId, value: DataValue) -> Result<(), CodecError> {
        let entries = self
            .payload
            .container_entries_mut()
            .ok_or(CodecError::InvalidEncoding)?;
        if let Some((_, existing)) = entries.iter_mut().find(|(id, _)| *id == data_type) {
            *existing = value;
        } else {
            entries.push((data_type, value));
        }
        Ok(())
    }

    fn insert_data_or_record_error(&mut self, data_type: DataTypeId, value: DataValue) {
        if self.insert_data(data_type, value).is_err() {
            self.mapping_error
                .get_or_insert(CodecError::InvalidEncoding);
        }
    }

    pub fn get_data(&self, data_type: DataType) -> Option<&DataValue> {
        let type_map = self.type_map.clone().unwrap_or_else(TypeMap::latest);
        let id = type_map.data_id_enum(data_type)?;
        self.payload.get_field(DataTypeId(id))
    }

    pub fn has_data(&self, data_type: DataType) -> Option<DataKind> {
        self.get_data(data_type).map(DataValue::kind)
    }

    pub fn get_comm_type_enum(&self) -> Option<CommunicationType> {
        let type_map = self.type_map.clone().unwrap_or_else(TypeMap::latest);
        type_map.comm_enum_id(self.comm_type.0)
    }

    /// Return clear container entries. Protected or scalar payloads return
    /// `None` instead of being mistaken for an empty container.
    pub fn data(&self) -> Option<&[(DataTypeId, DataValue)]> {
        self.payload.container_entries()
    }

    pub fn payload(&self) -> &DataValue {
        &self.payload
    }

    pub fn into_payload(self) -> DataValue {
        self.payload
    }

    #[must_use]
    pub fn with_payload(mut self, payload: DataValue) -> Self {
        self.payload = payload;
        self
    }

    pub fn data_len(&self) -> usize {
        self.payload
            .container_entries()
            .map_or(0, |entries| entries.len())
    }

    pub fn payload_len(&self) -> usize {
        self.payload
            .container_entries()
            .map_or(1, |entries| entries.len())
    }

    pub fn is_type(&self, comm_type: CommunicationType) -> bool {
        self.get_comm_type_enum() == Some(comm_type)
    }

    pub fn get_type_name(&self) -> Option<&'static str> {
        self.type_map
            .as_ref()
            .and_then(|type_map| type_map.communication_type_name(self.comm_type.0))
    }

    pub fn set_data(&mut self, data: DataType, value: DataValue) {
        let type_map = self.type_map.clone().unwrap_or_else(TypeMap::latest);
        match data.try_to_id(&type_map) {
            Some(id) => {
                self.insert_data_or_record_error(id, value);
            }
            None if self.mapping_error.is_none() => {
                self.mapping_error = Some(CodecError::UnknownDataType(data.name().to_string()));
            }
            None => {}
        }
    }

    #[must_use]
    pub fn with_data(mut self, data: DataType, value: DataValue) -> Self {
        self.set_data(data, value);
        self
    }

    pub fn remove_data(&mut self, data: DataType) -> Option<DataValue> {
        let type_map = self.type_map.clone().unwrap_or_else(TypeMap::latest);
        let id = DataTypeId(type_map.data_id_enum(data)?);
        let entries = self.payload.container_entries_mut()?;
        let index = entries.iter().position(|(entry_id, _)| *entry_id == id)?;
        Some(entries.remove(index).1)
    }

    #[must_use]
    pub fn reply_to(&self, comm_type: CommunicationType) -> Self {
        let type_map = self
            .type_map
            .as_ref()
            .cloned()
            .unwrap_or_else(TypeMap::latest);
        let mut response = Self::new_with_type_map(comm_type, &type_map);
        response.sender = self.receiver;
        response.receiver = self.sender;
        response.id = self.id;
        response
    }

    pub fn iter_typed_data(&self) -> Box<dyn Iterator<Item = (Option<DataType>, &DataValue)> + '_> {
        let type_map = self.type_map.clone().unwrap_or_else(TypeMap::latest);
        match &self.payload {
            DataValue::Container(entries) => Box::new(
                entries
                    .iter()
                    .map(move |(id, value)| (type_map.data_enum_id(id.0), value)),
            ),
            _ => Box::new(std::iter::empty()),
        }
    }

    pub fn get_bool(&self, data: DataType) -> Option<bool> {
        self.get_data(data)?.as_bool()
    }
    pub fn get_str(&self, data: DataType) -> Option<&str> {
        self.get_data(data)?.as_str()
    }
    pub fn get_u128(&self, data: DataType) -> Option<u128> {
        self.get_data(data)?.as_unsigned_number()
    }
    pub fn get_i128(&self, data: DataType) -> Option<i128> {
        self.get_data(data)?.as_signed_number()
    }
    pub fn get_float(&self, data: DataType) -> Option<f64> {
        self.get_data(data)?.as_float()
    }
    pub fn get_bytes(&self, data: DataType) -> Option<&[u8]> {
        self.get_data(data)?.as_bytes_slice()
    }
    pub fn get_array(&self, data: DataType) -> Option<&[DataValue]> {
        self.get_data(data)?.as_array_slice()
    }
}

impl From<MergeError> for CodecError {
    fn from(error: MergeError) -> Self {
        match error {
            MergeError::Mapping(error) => error,
            MergeError::TypeMapMismatch { expected, actual } => {
                Self::TypeMapMismatch { expected, actual }
            }
            MergeError::CommunicationTypeMismatch
            | MergeError::SenderMismatch
            | MergeError::ReceiverMismatch
            | MergeError::LeftPayloadNotContainer
            | MergeError::RightPayloadNotContainer
            | MergeError::FrameLimit(_)
            | MergeError::Container(_) => Self::InvalidEncoding,
        }
    }
}

#[cfg(feature = "registry")]
struct MigrationContext {
    limits: EncodeLimits,
    depth: usize,
    values: usize,
}

impl fmt::Display for CommunicationValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let version = self
            .type_map
            .as_ref()
            .map(|tm| &tm.version)
            .unwrap_or(&PROTOCOL_VERSION);
        write!(f, "V{}, ", version)?;
        if let Some(id) = self.id {
            write!(f, "ID:{id:X}, ")?;
        }
        if let Some(sender) = self.sender {
            write!(f, "S:{sender:X}, ")?;
        }
        if let Some(receiver) = self.receiver {
            write!(f, "R:{receiver:X}, ")?;
        }
        let name = self
            .get_comm_type_enum()
            .map(|value| value.name())
            .unwrap_or("?");
        write!(f, "{name}: ")?;
        fmt_data_value(
            &self.payload,
            &self.type_map.clone().unwrap_or_else(TypeMap::latest),
            f,
        )
    }
}

fn fmt_data_value(
    value: &DataValue,
    type_map: &TypeMap,
    f: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    match value {
        DataValue::Container(entries) => {
            f.write_str("{")?;
            for (index, (id, value)) in entries.iter().enumerate() {
                if index > 0 {
                    f.write_str(", ")?;
                }
                write!(f, "{}: ", type_map.data_type_name(id.0).unwrap_or("?"))?;
                fmt_data_value(value, type_map, f)?;
            }
            f.write_str("}")
        }
        DataValue::Array(values) => {
            f.write_str("[")?;
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    f.write_str(", ")?;
                }
                fmt_data_value(value, type_map, f)?;
            }
            f.write_str("]")
        }
        #[cfg(feature = "crypto")]
        DataValue::Encrypted(_) => f.write_str("(Encrypted)"),
        #[cfg(feature = "crypto")]
        DataValue::Signed(_) => f.write_str("(Signed)"),
        other => write!(f, "{other}"),
    }
}

#[cfg(test)]
mod tests;
