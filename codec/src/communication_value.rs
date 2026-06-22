use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{Cursor, Read};

use crate::data_value::DataValue;
use crate::rand_u32;
use mtp_common::CodecError;
use mtp_type_map::{
    communication_type_name, data_type_name, CommunicationType, CommunicationTypeId, DataType,
    DataTypeId, TypeMap, PROTOCOL_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunicationValue {
    id: u32,
    comm_type: CommunicationTypeId,
    sender: u64,
    receiver: u64,
    data: BTreeMap<DataTypeId, DataValue>,
    type_map: Option<TypeMap>,
}

impl CommunicationValue {
    #[must_use]
    pub fn new(comm_type: CommunicationType) -> Self {
        let tm = TypeMap::new(PROTOCOL_VERSION);
        let id = comm_type.to_id(&tm);
        Self {
            id: rand_u32(),
            comm_type: id,
            sender: 0,
            receiver: 0,
            data: BTreeMap::new(),
            type_map: Some(tm),
        }
    }

    #[cfg(feature = "registry")]
    #[must_use]
    pub fn from_comm(comm_type: CommunicationType, tm: &TypeMap) -> Self {
        let id = comm_type.to_id(tm);
        Self {
            id: rand_u32(),
            comm_type: id,
            sender: 0,
            receiver: 0,
            data: BTreeMap::new(),
            type_map: Some(tm.clone()),
        }
    }

    #[must_use]
    pub fn with_id(mut self, p0: u32) -> Self {
        self.id = p0;
        self
    }

    pub fn get_id(&self) -> u32 {
        self.id
    }

    #[must_use]
    pub fn with_sender(mut self, sender: u64) -> Self {
        self.sender = sender;
        self
    }

    pub fn get_sender(&self) -> u64 {
        self.sender
    }

    #[must_use]
    pub fn with_receiver(mut self, receiver: u64) -> Self {
        self.receiver = receiver;
        self
    }

    pub fn get_receiver(&self) -> u64 {
        self.receiver
    }

    pub fn get_type(&self) -> CommunicationTypeId {
        self.comm_type
    }

    #[must_use]
    pub fn add_data(mut self, data: DataTypeId, value: DataValue) -> Self {
        self.data.insert(data, value);
        self
    }

    #[cfg(feature = "registry")]
    #[must_use]
    pub fn add_typed(mut self, data: DataType, tm: &TypeMap, value: DataValue) -> Self {
        self.data.insert(data.to_id(tm), value);
        self
    }

    #[must_use]
    pub fn add_typed_default(mut self, data: DataType, value: DataValue) -> Self {
        let tm = self.type_map.clone().unwrap_or_else(TypeMap::latest);
        self.data.insert(data.to_id(&tm), value);
        self
    }

    pub fn get_data(&self, data_type: DataTypeId) -> &DataValue {
        self.data.get(&data_type).unwrap_or(&DataValue::Null)
    }

}

impl CommunicationValue {
    /*
     * Frame format (strict new format):
     * [4 bytes u32 total_length] // number of bytes after this field
     * [2 bytes u16 communication_type]
     * [1 byte flags]
     * [optional 4 bytes id]      // if flags bit2 set
     * [optional 6 bytes sender]  // if flags bit0 set
     * [optional 6 bytes receiver]// if flags bit1 set
     * [data container bytes...]
     *
     * Flags:
     * bit0 => has sender
     * bit1 => has receiver
     * bit2 => has id
     */
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut payload = Vec::new();

        let has_sender = self.sender != 0;
        let has_receiver = self.receiver != 0;
        let has_id = self.id != 0;

        let mut flags: u8 = 0;
        if has_sender {
            flags |= 0b0000_0001;
        }
        if has_receiver {
            flags |= 0b0000_0010;
        }
        if has_id {
            flags |= 0b0000_0100;
        }

        let _ = payload.write_u16::<BigEndian>(self.comm_type.0);
        payload.push(flags);

        if has_id {
            let _ = payload.write_u32::<BigEndian>(self.id);
        }

        if has_sender {
            let sender_be = self.sender.to_be_bytes();
            payload.extend_from_slice(&sender_be[2..]); // 6 bytes
        }

        if has_receiver {
            let receiver_be = self.receiver.to_be_bytes();
            payload.extend_from_slice(&receiver_be[2..]); // 6 bytes
        }

        let container_value = DataValue::container_from_map(&self.data);
        let container_bytes = container_value.to_bytes();
        payload.extend_from_slice(&container_bytes);

        let mut frame = Vec::with_capacity(4 + payload.len());
        let _ = frame.write_u32::<BigEndian>(payload.len() as u32);
        frame.extend_from_slice(&payload);

        frame
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut cursor = Cursor::new(bytes);

        let total_len = cursor
            .read_u32::<BigEndian>()
            .map_err(|_| CodecError::InvalidEncoding)? as usize;
        if bytes.len() < 4 + total_len {
            return Err(CodecError::InvalidEncoding);
        }

        let frame_end = 4 + total_len;

        let comm_type_num = cursor
            .read_u16::<BigEndian>()
            .map_err(|_| CodecError::InvalidEncoding)?;
        let comm_type = CommunicationTypeId(comm_type_num);

        let flags = cursor
            .read_u8()
            .map_err(|_| CodecError::InvalidEncoding)?;
        let has_sender = (flags & 0b0000_0001) != 0;
        let has_receiver = (flags & 0b0000_0010) != 0;
        let has_id = (flags & 0b0000_0100) != 0;

        let id = if has_id {
            cursor
                .read_u32::<BigEndian>()
                .map_err(|_| CodecError::InvalidEncoding)?
        } else {
            0
        };

        let sender = if has_sender {
            let mut buf = [0u8; 8];
            cursor
                .read_exact(&mut buf[2..])
                .map_err(|_| CodecError::InvalidEncoding)?;
            u64::from_be_bytes(buf)
        } else {
            0
        };

        let receiver = if has_receiver {
            let mut buf = [0u8; 8];
            cursor
                .read_exact(&mut buf[2..])
                .map_err(|_| CodecError::InvalidEncoding)?;
            u64::from_be_bytes(buf)
        } else {
            0
        };

        let pos = cursor.position() as usize;
        if pos > frame_end {
            return Err(CodecError::InvalidEncoding);
        }

        let data_bytes = &bytes[pos..frame_end];
        let data_value = DataValue::from_bytes(data_bytes).ok_or(CodecError::InvalidEncoding)?;
        let data = data_value.as_map().ok_or(CodecError::InvalidEncoding)?;

        Ok(Self {
            id,
            comm_type,
            sender,
            receiver,
            data,
            type_map: None,
        })
    }

    pub fn from_bytes_with(bytes: &[u8], tm: &TypeMap) -> Result<Self, CodecError> {
        let mut val = Self::from_bytes(bytes)?;
        val.type_map = Some(tm.clone());
        Ok(val)
    }

    #[cfg(feature = "registry")]
    pub fn migrate(&self, target_tm: &TypeMap) -> Result<Self, CodecError> {
        let comm_name =
            communication_type_name(self.comm_type.0).ok_or_else(|| {
                CodecError::UnknownCommunicationType(self.comm_type.0.to_string())
            })?;
        let comm_variant = CommunicationType::from_name(comm_name).ok_or_else(|| {
            CodecError::UnknownCommunicationType(comm_name.to_string())
        })?;
        let new_comm_id = CommunicationTypeId(
            target_tm
                .comm_id_enum(comm_variant)
                .ok_or_else(|| CodecError::UnknownCommunicationType(comm_name.to_string()))?,
        );

        let mut new_data = BTreeMap::new();
        for (&old_id, value) in &self.data {
            let name = data_type_name(old_id.0)
                .ok_or_else(|| CodecError::UnknownDataType(old_id.0.to_string()))?;
            let variant = DataType::from_name(name)
                .ok_or_else(|| CodecError::UnknownDataType(name.to_string()))?;
            let new_id = DataTypeId(
                target_tm
                    .data_id_enum(variant)
                    .ok_or_else(|| CodecError::UnknownDataType(name.to_string()))?,
            );
            new_data.insert(new_id, value.clone());
        }

        Ok(Self {
            id: self.id,
            comm_type: new_comm_id,
            sender: self.sender,
            receiver: self.receiver,
            data: new_data,
            type_map: Some(target_tm.clone()),
        })
    }
}

fn fmt_data_value(val: &DataValue, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match val {
        DataValue::Container(entries) => {
            write!(f, "{{")?;
            for (i, (key, value)) in entries.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                let name = data_type_name(key.0).unwrap_or("?");
                write!(f, "{}: ", name)?;
                fmt_data_value(value, f)?;
            }
            write!(f, "}}")
        }
        DataValue::Array(arr) => {
            write!(f, "[")?;
            for (i, value) in arr.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                fmt_data_value(value, f)?;
            }
            write!(f, "]")
        }
        #[cfg(feature = "crypto")]
        DataValue::EncryptedContainer(_) => write!(f, "(Secure)"),
        DataValue::Bytes(_) => write!(f, "(Binary)"),
        other => write!(f, "{}", other),
    }
}

#[cfg(debug_assertions)]
const BOLD_BLUE: &str = "\x1b[1;34m";
#[cfg(not(debug_assertions))]
const BOLD_BLUE: &str = "";
#[cfg(debug_assertions)]
const GREEN: &str = "\x1b[32m";
#[cfg(not(debug_assertions))]
const GREEN: &str = "";
#[cfg(debug_assertions)]
const YELLOW: &str = "\x1b[33m";
#[cfg(not(debug_assertions))]
const YELLOW: &str = "";
#[cfg(debug_assertions)]
const ORANGE: &str = "\x1b[38;5;208m";
#[cfg(not(debug_assertions))]
const ORANGE: &str = "";
#[cfg(debug_assertions)]
const RESET: &str = "\x1b[0m";
#[cfg(not(debug_assertions))]
const RESET: &str = "";

impl fmt::Display for CommunicationValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let version = self
            .type_map
            .as_ref()
            .map(|tm| &tm.version)
            .unwrap_or(&PROTOCOL_VERSION);

        write!(f, "V{}{}{}", BOLD_BLUE, version, RESET)?;

        if self.id != 0 {
            write!(f, ", ID:{}{:X}{}", GREEN, self.id, RESET)?;
        }
        if self.sender != 0 {
            write!(f, ", S:{}{:X}{}", YELLOW, self.sender, RESET)?;
        }
        if self.receiver != 0 {
            write!(f, ", R:{}{:X}{}", ORANGE, self.receiver, RESET)?;
        }

        let name = communication_type_name(self.comm_type.0).unwrap_or("?");
        write!(f, ", {}: ", name)?;

        write!(f, "{{")?;
        for (i, (key, value)) in self.data.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            let dname = data_type_name(key.0).unwrap_or("?");
            write!(f, "{}: ", dname)?;
            fmt_data_value(value, f)?;
        }
        write!(f, "}}")
    }
}

/* ================================ TESTS ================================ */
#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_value::DataValue;

    fn roundtrip(cv: CommunicationValue) -> CommunicationValue {
        let bytes = cv.to_bytes();
        let decoded = CommunicationValue::from_bytes(&bytes).expect("failed to deserialize");
        let bytes2 = decoded.to_bytes();
        assert_eq!(bytes, bytes2);
        decoded
    }

    #[test]
    fn test_flags_and_order_without_optional() {
        let cv = CommunicationValue::new(CommunicationType::ErrorParsing).with_id(0);
        let bytes = cv.to_bytes();

        // [u32 len][u16 type][flags]...
        assert!(bytes.len() >= 7);
        let mut c = Cursor::new(bytes.as_slice());
        let total_len = c.read_u32::<BigEndian>().expect("read len");
        assert_eq!(total_len as usize + 4, bytes.len());

        let typ = c.read_u16::<BigEndian>().expect("read type");
        assert_eq!(typ, 1);

        let flags = c.read_u8().expect("read flags");
        assert_eq!(flags & 0b0000_0111, 0);
    }

    #[test]
    fn test_flags_and_order_with_all_optional() {
        let cv = CommunicationValue::new(CommunicationType::ErrorBadVersion)
            .with_id(0xAABBCCDD)
            .with_sender(0x0000_1122_3344_5566)
            .with_receiver(0x0000_6677_8899_AABB);

        let bytes = cv.to_bytes();
        let mut c = Cursor::new(bytes.as_slice());

        let total_len = c.read_u32::<BigEndian>().expect("len");
        assert_eq!(total_len as usize + 4, bytes.len());

        let typ = c.read_u16::<BigEndian>().expect("read type");
        assert_eq!(typ, 2);

        let flags = c.read_u8().expect("read flags");
        assert_eq!(flags & 0b0000_0111, 0b0000_0111);

        let id = c.read_u32::<BigEndian>().expect("id");
        assert_eq!(id, 0xAABBCCDD);

        let mut sender6 = [0u8; 6];
        c.read_exact(&mut sender6).expect("sender");
        assert_eq!(sender6, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

        let mut receiver6 = [0u8; 6];
        c.read_exact(&mut receiver6).expect("receiver");
        assert_eq!(receiver6, [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
    }

    #[test]
    fn test_roundtrip_complex() {
        let cv = CommunicationValue::new(CommunicationType::Disconnect)
            .with_id(1234)
            .with_sender(111)
            .with_receiver(222)
            .add_data(DataTypeId(1), DataValue::Str("alice".to_string()))
            .add_data(DataTypeId(2), DataValue::SignedNumber(42))
            .add_data(DataTypeId(3), DataValue::BoolTrue)
            .add_data(
                DataTypeId(4),
                DataValue::Array(vec![DataValue::SignedNumber(1), DataValue::SignedNumber(2)]),
            );

        let decoded = roundtrip(cv.clone());

        assert_eq!(decoded.get_id(), 1234);
        assert_eq!(decoded.get_sender(), 111);
        assert_eq!(decoded.get_receiver(), 222);
        assert_eq!(decoded.get_type(), CommunicationTypeId(3));
        assert_eq!(
            decoded.get_data(DataTypeId(1)),
            &DataValue::Str("alice".to_string())
        );
        assert_eq!(
            decoded.get_data(DataTypeId(2)),
            &DataValue::SignedNumber(42)
        );
    }

    #[test]
    fn test_corrupted_length_returns_none() {
        let mut bad = vec![0u8; 8];
        // total_length claims more than available
        bad[0..4].copy_from_slice(&(1000u32.to_be_bytes()));
        assert!(CommunicationValue::from_bytes(&bad).is_err());
    }
}
