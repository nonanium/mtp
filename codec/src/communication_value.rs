use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
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

    /// Merge clear payload fields from `other` into `self`.
    ///
    /// This operation is shallow and left-biased: fields already present in
    /// `self` are preserved, while fields present only in `other` are appended
    /// in their original order. Existing destination order is never changed.
    /// Frame identity and routing are not copied from `other`; contradictory
    /// sender or receiver values are rejected. Both payloads must be valid,
    /// unique-field containers, use the same type-map version, and have the
    /// same communication type. On error, `self` is unchanged.
    pub fn try_merge_payload_from(&mut self, other: &Self) -> Result<MergeReport, MergeError> {
        self.try_merge_payload_from_with(other, MergeOptions::default())
    }

    /// Merge clear payload fields with an explicit conflict and recursion policy.
    pub fn try_merge_payload_from_with(
        &mut self,
        other: &Self,
        options: MergeOptions,
    ) -> Result<MergeReport, MergeError> {
        self.try_merge_payload_from_with_limits(other, options, EncodeLimits::default())
    }

    /// Merge clear payload fields with explicit conflict, recursion, and
    /// structural resource policies.
    pub fn try_merge_payload_from_with_limits(
        &mut self,
        other: &Self,
        options: MergeOptions,
        limits: EncodeLimits,
    ) -> Result<MergeReport, MergeError> {
        if let Some(error) = &self.mapping_error {
            return Err(MergeError::Mapping(error.clone()));
        }
        let left = self
            .type_map()
            .ok_or(MergeError::Mapping(CodecError::MissingTypeMap))?;
        let right = other
            .type_map()
            .ok_or(MergeError::Mapping(CodecError::MissingTypeMap))?;
        if left.version != right.version {
            return Err(MergeError::TypeMapMismatch {
                expected: left.version.to_string(),
                actual: right.version.to_string(),
            });
        }
        if let Some(error) = &other.mapping_error {
            return Err(MergeError::Mapping(error.clone()));
        }
        if self.comm_type != other.comm_type {
            return Err(MergeError::CommunicationTypeMismatch);
        }
        if !compatible_optional(&self.sender, &other.sender) {
            return Err(MergeError::SenderMismatch);
        }
        if !compatible_optional(&self.receiver, &other.receiver) {
            return Err(MergeError::ReceiverMismatch);
        }

        if self.payload.container_entries().is_none() {
            return Err(MergeError::LeftPayloadNotContainer);
        }
        let other_entries = other
            .payload
            .container_entries()
            .ok_or(MergeError::RightPayloadNotContainer)?;

        let payload_limits = self
            .payload_encode_limits(limits)
            .map_err(MergeError::FrameLimit)?;

        // Container merging validates both complete recursive value trees and
        // applies its result only after all fallible work has completed.
        let destination = self
            .payload
            .container_entries_mut()
            .expect("payload was checked as a container");
        merge_container_from_with_limits(destination, other_entries, options, payload_limits)
            .map_err(MergeError::from)
    }

    /// Deprecated wrapper retaining the previous `CodecError` return type.
    /// It uses the new left-biased payload semantics.
    #[deprecated(note = "use try_merge_payload_from for left-biased payload merging")]
    pub fn try_merge(&mut self, other: &Self) -> Result<(), CodecError> {
        self.try_merge_payload_from(other)
            .map(|_| ())
            .map_err(CodecError::from)
    }

    // This legacy infallible API records a merge failure in the frame so it
    // cannot be silently sent later.
    #[deprecated(note = "use try_merge_payload_from to handle merge errors")]
    pub fn merge(&mut self, other: &Self) {
        if let Err(error) = self.try_merge_payload_from(other) {
            self.mapping_error.get_or_insert(error.into());
        }
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

    pub fn to_bytes(&self) -> Result<Vec<u8>, CodecError> {
        self.to_bytes_with_limits(EncodeLimits::default())
    }

    pub fn to_bytes_with_limits(&self, limits: EncodeLimits) -> Result<Vec<u8>, CodecError> {
        if let Some(error) = &self.mapping_error {
            return Err(error.clone());
        }
        let payload = self
            .payload
            .to_bytes_with_limits(self.payload_encode_limits(limits)?)?;
        let mut body = Vec::new();
        body.write_u16::<BigEndian>(self.comm_type.0)
            .map_err(|_| CodecError::InvalidEncoding)?;
        let mut flags = 0;
        if self.id.is_some() {
            flags |= FLAG_HAS_ID;
        }
        if self.sender.is_some() {
            flags |= FLAG_HAS_SENDER;
        }
        if self.receiver.is_some() {
            flags |= FLAG_HAS_RECEIVER;
        }
        body.push(flags);
        if let Some(id) = self.id {
            body.write_u32::<BigEndian>(id)
                .map_err(|_| CodecError::InvalidEncoding)?;
        }
        if let Some(sender) = self.sender {
            body.write_u64::<BigEndian>(sender)
                .map_err(|_| CodecError::InvalidEncoding)?;
        }
        if let Some(receiver) = self.receiver {
            body.write_u64::<BigEndian>(receiver)
                .map_err(|_| CodecError::InvalidEncoding)?;
        }
        body.extend_from_slice(&payload);
        let length = u32::try_from(body.len()).map_err(|_| CodecError::TooManyEntries)?;
        let total_len = 4usize
            .checked_add(body.len())
            .ok_or(CodecError::TooManyEntries)?;
        if total_len > limits.max_output_size {
            return Err(CodecError::TooManyEntries);
        }
        let mut out = Vec::with_capacity(total_len);
        out.write_u32::<BigEndian>(length)
            .map_err(|_| CodecError::InvalidEncoding)?;
        out.extend_from_slice(&body);
        Ok(out)
    }

    fn frame_header_len(&self) -> usize {
        4 + 2
            + 1
            + self.id.is_some() as usize * 4
            + self.sender.is_some() as usize * 8
            + self.receiver.is_some() as usize * 8
    }

    fn payload_encode_limits(&self, limits: EncodeLimits) -> Result<EncodeLimits, CodecError> {
        let max_output_size = limits
            .max_output_size
            .checked_sub(self.frame_header_len())
            .ok_or(CodecError::TooManyEntries)?;
        Ok(EncodeLimits {
            max_output_size,
            ..limits
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
        Self::from_bytes_with_limits(bytes, DecodeLimits::default())
    }

    pub fn from_bytes_with_limits(bytes: &[u8], limits: DecodeLimits) -> Result<Self, CodecError> {
        Self::try_from_bytes_with_limits(bytes, limits).map_err(|_| CodecError::InvalidEncoding)
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::try_from_bytes_with_limits(bytes, DecodeLimits::default())
    }

    pub fn try_from_bytes_with_limits(
        bytes: &[u8],
        limits: DecodeLimits,
    ) -> Result<Self, DecodeError> {
        let mut cursor = Cursor::new(bytes);
        let length = cursor
            .read_u32::<BigEndian>()
            .map_err(|_| DecodeError::MalformedEncoding)? as usize;
        let end = 4usize
            .checked_add(length)
            .ok_or(DecodeError::MalformedEncoding)?;
        if end != bytes.len() {
            return Err(DecodeError::MalformedEncoding);
        }
        let comm_type = CommunicationTypeId(
            cursor
                .read_u16::<BigEndian>()
                .map_err(|_| DecodeError::MalformedEncoding)?,
        );
        let flags = cursor
            .read_u8()
            .map_err(|_| DecodeError::MalformedEncoding)?;
        if flags & !FLAG_KNOWN != 0 {
            return Err(DecodeError::MalformedEncoding);
        }
        let id = if flags & FLAG_HAS_ID != 0 {
            Some(
                cursor
                    .read_u32::<BigEndian>()
                    .map_err(|_| DecodeError::MalformedEncoding)?,
            )
        } else {
            None
        };
        let sender = if flags & FLAG_HAS_SENDER != 0 {
            Some(
                cursor
                    .read_u64::<BigEndian>()
                    .map_err(|_| DecodeError::MalformedEncoding)?,
            )
        } else {
            None
        };
        let receiver = if flags & FLAG_HAS_RECEIVER != 0 {
            Some(
                cursor
                    .read_u64::<BigEndian>()
                    .map_err(|_| DecodeError::MalformedEncoding)?,
            )
        } else {
            None
        };
        let payload = DataValue::read_from_with_diagnostics(&mut cursor, limits)?;
        if cursor.position() as usize != end {
            return Err(DecodeError::MalformedEncoding);
        }
        Ok(Self {
            id,
            comm_type,
            sender,
            receiver,
            payload,
            type_map: Some(TypeMap::new(PROTOCOL_VERSION)),
            mapping_error: None,
        })
    }

    pub fn from_bytes_with(bytes: &[u8], type_map: &TypeMap) -> Result<Self, CodecError> {
        Self::try_from_bytes_with(bytes, type_map).map_err(|_| CodecError::InvalidEncoding)
    }

    pub fn try_from_bytes_with(bytes: &[u8], type_map: &TypeMap) -> Result<Self, DecodeError> {
        Self::try_from_bytes_with_type_map_and_limits(bytes, type_map, DecodeLimits::default())
    }

    pub fn try_from_bytes_with_type_map_and_limits(
        bytes: &[u8],
        type_map: &TypeMap,
        limits: DecodeLimits,
    ) -> Result<Self, DecodeError> {
        let mut value = Self::try_from_bytes_with_limits(bytes, limits)?;
        value.set_type_map(type_map);
        Ok(value)
    }

    #[cfg(feature = "registry")]
    pub fn migrate(&self, target: &TypeMap) -> Result<Self, CodecError> {
        self.migrate_with_limits(target, EncodeLimits::default())
    }

    /// Migrate a clear frame while bounding the recursive traversal used to
    /// translate its type IDs.
    #[cfg(feature = "registry")]
    pub fn migrate_with_limits(
        &self,
        target: &TypeMap,
        limits: EncodeLimits,
    ) -> Result<Self, CodecError> {
        if let Some(error) = &self.mapping_error {
            return Err(error.clone());
        }
        let source = self.type_map.as_ref().ok_or(CodecError::InvalidEncoding)?;
        let comm_name = source
            .communication_type_name(self.comm_type.0)
            .ok_or_else(|| CodecError::UnknownCommunicationType(self.comm_type.0.to_string()))?;
        let comm = CommunicationType::from_name(comm_name)
            .ok_or_else(|| CodecError::UnknownCommunicationType(comm_name.to_string()))?;
        let comm_type = CommunicationTypeId(
            target
                .comm_id_enum(comm)
                .ok_or_else(|| CodecError::UnknownCommunicationType(comm_name.to_string()))?,
        );
        let mut context = MigrationContext::new(limits);
        let payload = migrate_data_value(&self.payload, source, target, &mut context)?;
        Ok(Self {
            id: self.id,
            comm_type,
            sender: self.sender,
            receiver: self.receiver,
            payload,
            type_map: Some(target.clone()),
            mapping_error: None,
        })
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

fn compatible_optional<T: PartialEq>(left: &Option<T>, right: &Option<T>) -> bool {
    !matches!((left, right), (Some(left), Some(right)) if left != right)
}

#[cfg(feature = "registry")]
struct MigrationContext {
    limits: EncodeLimits,
    depth: usize,
    values: usize,
}

#[cfg(feature = "registry")]
impl MigrationContext {
    fn new(limits: EncodeLimits) -> Self {
        Self {
            limits,
            depth: 0,
            values: 0,
        }
    }

    fn value(&mut self) -> Result<(), CodecError> {
        self.values = self
            .values
            .checked_add(1)
            .ok_or(CodecError::TooManyEntries)?;
        if self.values > self.limits.max_values {
            return Err(CodecError::TooManyEntries);
        }
        Ok(())
    }

    fn enter(&mut self) -> Result<(), CodecError> {
        self.depth = self
            .depth
            .checked_add(1)
            .ok_or(CodecError::TooManyEntries)?;
        if self.depth > self.limits.max_depth {
            return Err(CodecError::TooManyEntries);
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }
}

#[cfg(feature = "registry")]
fn migrate_data_value(
    value: &DataValue,
    source: &TypeMap,
    target: &TypeMap,
    context: &mut MigrationContext,
) -> Result<DataValue, CodecError> {
    context.value()?;
    match value {
        DataValue::Container(entries) => {
            context.enter()?;
            let count = u16::try_from(entries.len()).map_err(|_| CodecError::TooManyEntries)?;
            let mut migrated = Vec::with_capacity(usize::from(count));
            for (old_id, value) in entries {
                let name = source
                    .data_type_name(old_id.0)
                    .ok_or_else(|| CodecError::UnknownDataType(old_id.0.to_string()))?;
                let data = DataType::from_name(name)
                    .ok_or_else(|| CodecError::UnknownDataType(name.to_string()))?;
                let new_id = DataTypeId(
                    target
                        .data_id_enum(data)
                        .ok_or_else(|| CodecError::UnknownDataType(name.to_string()))?,
                );
                migrated.push((new_id, migrate_data_value(value, source, target, context)?));
            }
            context.leave();
            Ok(DataValue::Container(migrated))
        }
        DataValue::Array(values) => {
            context.enter()?;
            let mut migrated = Vec::with_capacity(values.len());
            for value in values {
                migrated.push(migrate_data_value(value, source, target, context)?);
            }
            context.leave();
            Ok(DataValue::Array(migrated))
        }
        #[cfg(feature = "crypto")]
        DataValue::Signed(_) | DataValue::Encrypted(_) => Err(CodecError::InvalidEncoding),
        scalar => Ok(scalar.clone()),
    }
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
mod tests {
    use super::*;
    use crate::data_value::{MergeConflictPolicy, MergePath};

    #[test]
    fn canonical_flags_and_eight_byte_ids_roundtrip() {
        const SENDER_ID: u64 = 0x0102_0304_0506_0708;
        const RECEIVER_ID: u64 = 0x1112_1314_1516_1718;

        let cases = [
            (
                CommunicationValue::new(CommunicationType::Ping)
                    .with_id(0x0102_0304)
                    .without_sender()
                    .without_receiver(),
                0x01,
            ),
            (
                CommunicationValue::new(CommunicationType::Ping)
                    .without_id()
                    .with_sender(SENDER_ID)
                    .without_receiver(),
                0x02,
            ),
            (
                CommunicationValue::new(CommunicationType::Ping)
                    .without_id()
                    .without_sender()
                    .with_receiver(RECEIVER_ID),
                0x04,
            ),
            (
                CommunicationValue::new(CommunicationType::Ping)
                    .with_id(0)
                    .with_sender(SENDER_ID)
                    .with_receiver(RECEIVER_ID),
                0x07,
            ),
        ];

        for (value, expected_flags) in cases {
            let bytes = value.to_bytes().unwrap();
            assert_eq!(bytes[6], expected_flags);
            if expected_flags == FLAG_HAS_SENDER {
                assert_eq!(&bytes[7..15], &SENDER_ID.to_be_bytes());
            }
            if expected_flags == FLAG_HAS_RECEIVER {
                assert_eq!(&bytes[7..15], &RECEIVER_ID.to_be_bytes());
            }
            assert_eq!(CommunicationValue::from_bytes(&bytes).unwrap(), value);
        }
    }

    #[test]
    fn absent_and_zero_are_distinct() {
        let absent = CommunicationValue::new(CommunicationType::Ping).without_id();
        let zero = CommunicationValue::new(CommunicationType::Ping).with_id(0);
        assert!(absent.id().is_none());
        assert_eq!(zero.id(), Some(0));
        assert_ne!(absent.to_bytes().unwrap(), zero.to_bytes().unwrap());
    }

    #[test]
    fn reserved_flags_are_rejected() {
        let bytes = CommunicationValue::new(CommunicationType::Ping)
            .to_bytes()
            .unwrap();
        for unknown_flag in [0x08, 0x10, 0x20, 0x40, 0x80] {
            let mut invalid = bytes.clone();
            invalid[6] |= unknown_flag;
            assert_eq!(
                CommunicationValue::from_bytes(&invalid),
                Err(CodecError::InvalidEncoding),
                "flag bit {unknown_flag:#04x} must be rejected"
            );
        }
    }

    #[test]
    fn protected_or_scalar_payload_is_not_treated_as_data() {
        let frame = CommunicationValue::new(CommunicationType::Ping)
            .with_payload(DataValue::Bytes(vec![1]));
        assert!(frame.data().is_none());
        assert_eq!(frame.get_data(DataType::Version), None);
    }

    #[test]
    fn replies_retain_the_request_type_map() {
        let type_map = TypeMap::new(mtp_type_map::Version::new(3, 0));
        let request = CommunicationValue::new_with_type_map(CommunicationType::Ping, &type_map)
            .with_sender(7)
            .with_receiver(9);
        let reply = request.reply_to(CommunicationType::Pong);

        assert_eq!(
            reply.type_map().map(|map| &map.version),
            Some(&type_map.version)
        );
        assert_eq!(reply.sender(), Some(9));
        assert_eq!(reply.receiver(), Some(7));
    }

    #[test]
    #[allow(deprecated)]
    fn try_merge_rejects_frames_from_different_type_maps() {
        let left_map = TypeMap::new(mtp_type_map::Version::new(3, 0));
        let right_map = TypeMap::new(mtp_type_map::Version::new(4, 0));
        let mut left = CommunicationValue::new_with_type_map(CommunicationType::Ping, &left_map);
        let right = CommunicationValue::new_with_type_map(CommunicationType::Ping, &right_map);

        assert_eq!(
            left.try_merge(&right),
            Err(CodecError::TypeMapMismatch {
                expected: "3.0".into(),
                actual: "4.0".into(),
            })
        );
        assert_eq!(left.data_len(), 0);
    }

    #[test]
    fn merge_payload_is_left_biased_and_preserves_order() {
        let mut left = CommunicationValue::new(CommunicationType::Ping).with_payload(
            DataValue::Container(vec![
                (DataTypeId(2), DataValue::UnsignedNumber(2)),
                (DataTypeId(1), DataValue::UnsignedNumber(1)),
            ]),
        );
        let right = CommunicationValue::new(CommunicationType::Ping).with_payload(
            DataValue::Container(vec![
                (DataTypeId(3), DataValue::UnsignedNumber(3)),
                (DataTypeId(1), DataValue::UnsignedNumber(99)),
                (DataTypeId(4), DataValue::UnsignedNumber(4)),
            ]),
        );

        let report = left.try_merge_payload_from(&right).unwrap();

        assert_eq!(
            report.inserted,
            vec![
                MergePath::new(vec![DataTypeId(3)]),
                MergePath::new(vec![DataTypeId(4)])
            ]
        );
        assert_eq!(report.preserved, vec![MergePath::new(vec![DataTypeId(1)])]);
        assert_eq!(
            left.data(),
            Some(
                &[
                    (DataTypeId(2), DataValue::UnsignedNumber(2)),
                    (DataTypeId(1), DataValue::UnsignedNumber(1)),
                    (DataTypeId(3), DataValue::UnsignedNumber(3)),
                    (DataTypeId(4), DataValue::UnsignedNumber(4)),
                ][..]
            )
        );
    }

    #[test]
    fn bounded_frame_merge_uses_complete_frame_size_limits() {
        let payload = DataValue::Container(vec![(DataTypeId(1), DataValue::BoolTrue)]);
        let mut destination = CommunicationValue::new(CommunicationType::Ping)
            .with_id(7)
            .with_payload(payload.clone());
        let source = CommunicationValue::new(CommunicationType::Ping)
            .with_id(7)
            .with_payload(DataValue::Container(Vec::new()));
        let before = destination.clone();
        let limits = EncodeLimits {
            // The payload is six bytes alone, but this frame has an eleven-byte
            // header and therefore cannot fit into sixteen bytes.
            max_output_size: 16,
            ..EncodeLimits::default()
        };

        assert!(payload.to_bytes_with_limits(limits).is_ok());
        assert!(destination.to_bytes_with_limits(limits).is_err());
        assert!(
            destination
                .try_merge_payload_from_with_limits(&source, MergeOptions::default(), limits)
                .is_err()
        );
        assert_eq!(destination, before);
    }

    #[test]
    fn merge_payload_rejects_malformed_containers_without_mutating_destination() {
        let original = DataValue::Container(vec![(DataTypeId(1), DataValue::BoolTrue)]);
        let mut left =
            CommunicationValue::new(CommunicationType::Ping).with_payload(original.clone());
        let right = CommunicationValue::new(CommunicationType::Ping).with_payload(
            DataValue::Container(vec![
                (DataTypeId(2), DataValue::BoolTrue),
                (DataTypeId(2), DataValue::BoolFalse),
            ]),
        );

        assert_eq!(
            left.try_merge_payload_from(&right),
            Err(MergeError::Container(
                ContainerMergeError::SourceDuplicateField(DataTypeId(2))
            ))
        );
        assert_eq!(left.payload(), &original);

        let malformed_left = DataValue::Container(vec![
            (DataTypeId(3), DataValue::BoolTrue),
            (DataTypeId(3), DataValue::BoolFalse),
        ]);
        let mut left =
            CommunicationValue::new(CommunicationType::Ping).with_payload(malformed_left.clone());
        let right = CommunicationValue::new(CommunicationType::Ping).with_payload(
            DataValue::Container(vec![(DataTypeId(4), DataValue::BoolTrue)]),
        );
        assert_eq!(
            left.try_merge_payload_from(&right),
            Err(MergeError::Container(
                ContainerMergeError::DestinationDuplicateField(DataTypeId(3))
            ))
        );
        assert_eq!(left.payload(), &malformed_left);
    }

    #[test]
    fn merge_payload_rejects_nested_malformed_source_without_mutating_destination() {
        let original = DataValue::Container(vec![(DataTypeId(1), DataValue::BoolTrue)]);
        let mut left =
            CommunicationValue::new(CommunicationType::Ping).with_payload(original.clone());
        let right = CommunicationValue::new(CommunicationType::Ping).with_payload(
            DataValue::Container(vec![(
                DataTypeId(2),
                DataValue::Container(vec![
                    (DataTypeId(3), DataValue::BoolTrue),
                    (DataTypeId(3), DataValue::BoolFalse),
                ]),
            )]),
        );

        assert_eq!(
            left.try_merge_payload_from(&right),
            Err(MergeError::Container(
                ContainerMergeError::InvalidStructure(CodecError::InvalidEncoding)
            ))
        );
        assert_eq!(left.payload(), &original);

        let malformed_destination = DataValue::Container(vec![(
            DataTypeId(4),
            DataValue::Container(vec![
                (DataTypeId(5), DataValue::BoolTrue),
                (DataTypeId(5), DataValue::BoolFalse),
            ]),
        )]);
        let mut left = CommunicationValue::new(CommunicationType::Ping)
            .with_payload(malformed_destination.clone());
        let right = CommunicationValue::new(CommunicationType::Ping).with_payload(
            DataValue::Container(vec![(DataTypeId(6), DataValue::BoolTrue)]),
        );
        assert_eq!(
            left.try_merge_payload_from(&right),
            Err(MergeError::Container(
                ContainerMergeError::InvalidStructure(CodecError::InvalidEncoding)
            ))
        );
        assert_eq!(left.payload(), &malformed_destination);
    }

    #[test]
    fn merge_payload_policies_and_recursion_are_explicit() {
        let left_payload = DataValue::Container(vec![(
            DataTypeId(1),
            DataValue::Container(vec![(DataTypeId(2), DataValue::UnsignedNumber(2))]),
        )]);
        let right = CommunicationValue::new(CommunicationType::Ping).with_payload(
            DataValue::Container(vec![(
                DataTypeId(1),
                DataValue::Container(vec![
                    (DataTypeId(2), DataValue::UnsignedNumber(99)),
                    (DataTypeId(3), DataValue::UnsignedNumber(3)),
                ]),
            )]),
        );

        let mut shallow =
            CommunicationValue::new(CommunicationType::Ping).with_payload(left_payload.clone());
        shallow.try_merge_payload_from(&right).unwrap();
        assert_eq!(shallow.payload(), &left_payload);

        let mut recursive =
            CommunicationValue::new(CommunicationType::Ping).with_payload(left_payload);
        let report = recursive
            .try_merge_payload_from_with(
                &right,
                MergeOptions {
                    conflicts: MergeConflictPolicy::KeepLeft,
                    recursive_containers: true,
                },
            )
            .unwrap();
        assert_eq!(
            report.inserted,
            vec![MergePath::new(vec![DataTypeId(1), DataTypeId(3)])]
        );
        assert_eq!(
            report.preserved,
            vec![MergePath::new(vec![DataTypeId(1), DataTypeId(2)])]
        );
        assert_eq!(report.recursed, vec![MergePath::new(vec![DataTypeId(1)])]);

        let mut replacing = CommunicationValue::new(CommunicationType::Ping).with_payload(
            DataValue::Container(vec![(DataTypeId(4), DataValue::BoolTrue)]),
        );
        let replacement = CommunicationValue::new(CommunicationType::Ping).with_payload(
            DataValue::Container(vec![(DataTypeId(4), DataValue::BoolFalse)]),
        );
        assert_eq!(
            replacing
                .try_merge_payload_from_with(
                    &replacement,
                    MergeOptions {
                        conflicts: MergeConflictPolicy::RequireEqual,
                        recursive_containers: false,
                    },
                )
                .unwrap_err(),
            MergeError::Container(ContainerMergeError::Conflict(MergePath::new(vec![
                DataTypeId(4)
            ])))
        );
        let report = replacing
            .try_merge_payload_from_with(
                &replacement,
                MergeOptions {
                    conflicts: MergeConflictPolicy::KeepRight,
                    recursive_containers: false,
                },
            )
            .unwrap();
        assert_eq!(report.replaced, vec![MergePath::new(vec![DataTypeId(4)])]);

        let mut equal = CommunicationValue::new(CommunicationType::Ping).with_payload(
            DataValue::Container(vec![(DataTypeId(5), DataValue::BoolTrue)]),
        );
        let equal_source = CommunicationValue::new(CommunicationType::Ping).with_payload(
            DataValue::Container(vec![(DataTypeId(5), DataValue::BoolTrue)]),
        );
        assert_eq!(
            equal
                .try_merge_payload_from_with(
                    &equal_source,
                    MergeOptions {
                        conflicts: MergeConflictPolicy::RequireEqual,
                        recursive_containers: false,
                    },
                )
                .unwrap()
                .matched,
            vec![MergePath::new(vec![DataTypeId(5)])]
        );
        assert_eq!(
            equal
                .try_merge_payload_from_with(
                    &equal_source,
                    MergeOptions {
                        conflicts: MergeConflictPolicy::Reject,
                        recursive_containers: false,
                    },
                )
                .unwrap_err(),
            MergeError::Container(ContainerMergeError::Conflict(MergePath::new(vec![
                DataTypeId(5)
            ])))
        );
    }

    #[test]
    fn merge_payload_rejects_incompatible_frame_metadata() {
        let mut left = CommunicationValue::new(CommunicationType::Ping).with_sender(7);
        let different_type = CommunicationValue::new(CommunicationType::Pong);
        assert_eq!(
            left.try_merge_payload_from(&different_type),
            Err(MergeError::CommunicationTypeMismatch)
        );

        let different_sender = CommunicationValue::new(CommunicationType::Ping).with_sender(8);
        assert_eq!(
            left.try_merge_payload_from(&different_sender),
            Err(MergeError::SenderMismatch)
        );

        let receiver_left = CommunicationValue::new(CommunicationType::Ping).with_receiver(7);
        let receiver_right = CommunicationValue::new(CommunicationType::Ping).with_receiver(8);
        assert_eq!(
            receiver_left
                .clone()
                .try_merge_payload_from(&receiver_right),
            Err(MergeError::ReceiverMismatch)
        );
    }

    #[test]
    fn merge_payload_keeps_destination_frame_id() {
        let mut left = CommunicationValue::new(CommunicationType::Ping)
            .with_id(123)
            .with_payload(DataValue::Container(vec![]));
        let right = CommunicationValue::new(CommunicationType::Ping)
            .with_id(456)
            .with_payload(DataValue::Container(vec![(
                DataTypeId(1),
                DataValue::BoolTrue,
            )]));

        left.try_merge_payload_from(&right).unwrap();
        assert_eq!(left.id(), Some(123));
    }

    #[test]
    fn default_merge_is_identity_for_empty_and_idempotent_for_same_source() {
        let mut destination = CommunicationValue::new(CommunicationType::Ping).with_payload(
            DataValue::Container(vec![(DataTypeId(1), DataValue::BoolTrue)]),
        );
        let empty = CommunicationValue::new(CommunicationType::Ping);
        assert_eq!(
            destination.try_merge_payload_from(&empty).unwrap(),
            MergeReport::default()
        );

        let source = CommunicationValue::new(CommunicationType::Ping).with_payload(
            DataValue::Container(vec![(DataTypeId(2), DataValue::BoolFalse)]),
        );
        destination.try_merge_payload_from(&source).unwrap();
        let once = destination.payload().clone();
        destination.try_merge_payload_from(&source).unwrap();
        assert_eq!(destination.payload(), &once);
    }

    #[test]
    fn merge_payload_rejects_non_container_payloads() {
        let mut scalar_left =
            CommunicationValue::new(CommunicationType::Ping).with_payload(DataValue::BoolTrue);
        let container = CommunicationValue::new(CommunicationType::Ping);
        assert_eq!(
            scalar_left.try_merge_payload_from(&container),
            Err(MergeError::LeftPayloadNotContainer)
        );

        let mut container_left = CommunicationValue::new(CommunicationType::Ping);
        let scalar_right =
            CommunicationValue::new(CommunicationType::Ping).with_payload(DataValue::BoolTrue);
        assert_eq!(
            container_left.try_merge_payload_from(&scalar_right),
            Err(MergeError::RightPayloadNotContainer)
        );
    }

    #[test]
    fn generic_payload_roundtrips_without_becoming_a_container() {
        let payload = DataValue::Array(vec![
            DataValue::Str("arbitrary".into()),
            DataValue::UnsignedNumber(7),
        ]);
        let encoded = CommunicationValue::new(CommunicationType::Ping)
            .with_payload(payload.clone())
            .to_bytes()
            .unwrap();

        let decoded = CommunicationValue::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.payload(), &payload);
        assert_eq!(decoded.into_payload(), payload);
    }

    #[test]
    fn add_data_rejects_a_non_container_payload() {
        let type_map = TypeMap::latest();
        let data_type = DataType::Version.try_to_id(&type_map).unwrap();
        let result = CommunicationValue::new(CommunicationType::Ping)
            .with_payload(DataValue::Null)
            .add_data(data_type, DataValue::Str("1".into()));

        assert_eq!(result, Err(CodecError::InvalidEncoding));
    }

    #[test]
    fn trailing_value_after_payload_is_rejected() {
        let mut encoded = CommunicationValue::new(CommunicationType::Ping)
            .with_payload(DataValue::Null)
            .to_bytes()
            .unwrap();
        encoded.push(DataValue::BoolTrue.to_bytes().unwrap()[0]);
        let body_len = u32::try_from(encoded.len() - 4).unwrap();
        encoded[..4].copy_from_slice(&body_len.to_be_bytes());

        assert_eq!(
            CommunicationValue::from_bytes(&encoded),
            Err(CodecError::InvalidEncoding)
        );
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn sealed_sender_is_a_frame_construction_rule() -> Result<(), Box<dyn std::error::Error>> {
        use crate::data_value::ProtectionPurpose;
        use mtp_crypto::{Ed25519Signer, Keyring};

        const SENDER_ID: u64 = 0x0102_0304_0506_0708;
        const RECEIVER_ID: u64 = 0x1112_1314_1516_1718;

        let (signer, _, signer_public_key) = Ed25519Signer::generate();
        let recipient = Keyring::generate();
        let clear_payload = DataValue::Container(vec![(
            DataTypeId(32),
            DataValue::Str("sealed content".into()),
        )]);
        let protected_payload = clear_payload
            .clone()
            .sign(SENDER_ID, ProtectionPurpose::from(1), &signer)?
            .encrypt_for(
                std::slice::from_ref(&recipient.public_key_bundle()),
                ProtectionPurpose::from(2),
            )?;

        let frame = CommunicationValue::new(CommunicationType::Ping)
            .without_sender()
            .with_receiver(RECEIVER_ID)
            .with_payload(protected_payload);
        assert!(frame.sender().is_none());
        assert!(frame.receiver().is_some());
        assert!(matches!(frame.payload(), DataValue::Encrypted(_)));

        let frame_id = frame.id();
        let encoded = frame.to_bytes()?;

        // Payload protection does not introduce frame flags. The header only
        // advertises the transport ID and visible next-hop receiver.
        assert_eq!(encoded[6], FLAG_HAS_ID | FLAG_HAS_RECEIVER);
        assert_eq!(&encoded[11..19], &RECEIVER_ID.to_be_bytes());
        assert_eq!(encoded[19], 0x0A);

        let decoded = CommunicationValue::from_bytes(&encoded)?;
        assert_eq!(decoded.id(), frame_id);
        assert_eq!(decoded.sender(), None);
        assert_eq!(decoded.receiver(), Some(RECEIVER_ID));
        assert!(matches!(decoded.payload(), DataValue::Encrypted(_)));

        let signed = decoded
            .payload()
            .decrypt(&recipient, ProtectionPurpose::from(2))?;
        let DataValue::Signed(signed_value) = &signed else {
            return Err("expected signed value inside encrypted payload".into());
        };
        assert_eq!(signed_value.signer_id, SENDER_ID);

        let mut signer_public_keys = recipient.public_key_bundle();
        signer_public_keys.sig_cl_public_key = signer_public_key;
        signed.verify_with_policy(
            SENDER_ID,
            &signer_public_keys,
            ProtectionPurpose::from(1),
            crate::ProtectionPolicy::any_supported(),
        )?;
        assert_eq!(
            signed.into_verified_with_policy(
                SENDER_ID,
                &signer_public_keys,
                ProtectionPurpose::from(1),
                crate::ProtectionPolicy::any_supported(),
            )?,
            clear_payload
        );
        Ok(())
    }
}
