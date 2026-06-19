use base64::Engine;
use base64::engine::general_purpose;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::io::Cursor;

use type_map::DataTypeId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataKind {
    Bool,

    SignedNumber,
    UnsignedNumber,
    Float,

    Str,
    Bytes,
    Array(Box<DataKind>),

    Container,

    #[cfg(feature = "crypto")]
    EncryptedContainer,

    Null,
}

#[derive(Debug, Clone, Eq)]
pub enum DataValue {
    BoolTrue,
    BoolFalse,
    Bool(bool),

    SignedNumber(i128),
    UnsignedNumber(u128),
    Float(u8, u32),

    Str(String),
    Bytes(Vec<u8>),
    Array(Vec<DataValue>),

    Container(Vec<(DataTypeId, DataValue)>),

    #[cfg(feature = "crypto")]
    EncryptedContainer(Vec<(DataTypeId, DataValue)>),

    Null,
}

impl DataValue {
    /*
     * Container format:
     * [2 bytes u16 entry_count]       // number of key-value pairs
     * [1 byte kind]                   // DataValue kind marker
     * [if kind == BOOL_TRUE or BOOL_FALSE:]
     *     [1 byte key]                // DataTypes discriminant
     * [else:]
     *     [2 bytes u16 payload_len]   // length of the value payload
     *     [1 byte key]                // DataTypes discriminant
     *     [payload_len bytes payload] // value data (interpreted based on kind)
     *
     * Kind markers:
     * 0x01 => BoolTrue
     * 0x02 => BoolFalse
     * 0x03 => Number (i64, 8 bytes big-endian)
     * 0x04 => Str (UTF-8 bytes)
     * 0x05 => Array (nested container format)
     * 0x06 => Container (nested container format)
     * 0x07 => Null
     */
    const KIND_BOOL_TRUE: u8 = 0x01;
    const KIND_BOOL_FALSE: u8 = 0x02;

    const KIND_SIGNED_NUMBER: u8 = 0x03;
    const KIND_UNSIGNED_NUMBER: u8 = 0x04;
    const KIND_FLOAT: u8 = 0x05;

    const KIND_STR: u8 = 0x06;
    const KIND_BYTES: u8 = 0x07;
    const KIND_ARRAY: u8 = 0x08;

    const KIND_CONTAINER: u8 = 0x09;
    #[cfg(feature = "crypto")]
    const KIND_ENCRYPTED_CONTAINER: u8 = 0x0A;

    const KIND_NULL: u8 = 0x0B;

    pub fn container_from_map(map: &BTreeMap<DataTypeId, DataValue>) -> DataValue {
        let mut container = Vec::new();
        for (key, value) in map {
            container.push((key.clone(), value.clone()));
        }
        DataValue::Container(container)
    }

    pub fn kind(&self) -> DataKind {
        match self {
            DataValue::Bool(_) | DataValue::BoolTrue | DataValue::BoolFalse => DataKind::Bool,
            DataValue::SignedNumber(_) => DataKind::SignedNumber,
            DataValue::UnsignedNumber(_) => DataKind::UnsignedNumber,
            DataValue::Float(_, _) => DataKind::Float,
            DataValue::Str(_) => DataKind::Str,
            DataValue::Array(a) => {
                if let Some(first) = a.first() {
                    DataKind::Array(Box::new(first.kind()))
                } else {
                    DataKind::Array(Box::new(DataKind::Null))
                }
            }
            DataValue::Bytes(_) => DataKind::Bytes,
            DataValue::Container(_) => DataKind::Container,
            #[cfg(feature = "crypto")]
            DataValue::EncryptedContainer(_) => DataKind::EncryptedContainer,
            DataValue::Null => DataKind::Null,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            DataValue::BoolTrue => Some(true),
            DataValue::BoolFalse => Some(false),
            DataValue::Bool(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            DataValue::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<String> {
        self.as_str().map(|s| s.to_string())
    }

    pub fn as_signed_number(&self) -> Option<i128> {
        match self {
            DataValue::SignedNumber(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_unsigned_number(&self) -> Option<u128> {
        match self {
            DataValue::UnsignedNumber(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_float(&self) -> Option<(u8, u32)> {
        match self {
            DataValue::Float(a, b) => Some((*a, *b)),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<Vec<DataValue>> {
        match self {
            DataValue::Array(a) => Some(a.clone()),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<Vec<u8>> {
        match self {
            DataValue::Bytes(b) => Some(b.clone()),
            _ => None,
        }
    }

    pub fn as_container(&self) -> Option<Vec<(DataTypeId, DataValue)>> {
        match self {
            DataValue::Container(c) => Some(c.clone()),
            _ => None,
        }
    }

    #[cfg(feature = "crypto")]
    pub fn as_encrypted_container(&self) -> Option<Vec<(DataTypeId, DataValue)>> {
        match self {
            DataValue::EncryptedContainer(c) => Some(c.clone()),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<BTreeMap<DataTypeId, DataValue>> {
        match self {
            DataValue::Container(c) => {
                let mut out = BTreeMap::new();
                for (k, v) in c {
                    out.insert(k.clone(), v.clone());
                }
                Some(out)
            }
            _ => None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            DataValue::Container(entries) => Self::encode_container(entries),
            DataValue::Array(arr) => Self::encode_array(arr),
            _ => {
                let mut out = Vec::new();
                if Self::write_value_payload(&mut out, self).is_none() {
                    return Vec::new();
                }
                out
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut cursor = Cursor::new(bytes);
        let value = Self::read_value(&mut cursor, true)?;
        if cursor.position() as usize != bytes.len() {
            return None;
        }
        Some(value)
    }

    pub fn to_base64(&self) -> String {
        general_purpose::STANDARD.encode(self.to_bytes())
    }

    pub fn from_base64(base64_str: &str) -> Option<Self> {
        let bytes = general_purpose::STANDARD.decode(base64_str).ok()?;
        Self::from_bytes(&bytes)
    }

    fn encode_container(entries: &[(DataTypeId, DataValue)]) -> Vec<u8> {
        let mut out = Vec::new();
        if out
            .write_u16::<BigEndian>(u16::try_from(entries.len()).ok().unwrap_or(0))
            .is_err()
        {
            return Vec::new();
        }

        for (key, value) in entries {
            if !Self::write_container_entry(&mut out, key.clone(), value) {
                return Vec::new();
            }
        }
        out
    }

    fn write_container_entry(buf: &mut Vec<u8>, key: DataTypeId, value: &DataValue) -> bool {
        let kind = Self::kind_marker(value);
        buf.push(kind);

        if kind == Self::KIND_BOOL_TRUE || kind == Self::KIND_BOOL_FALSE {
            let key = u8::try_from(key.0).unwrap_or(0);
            buf.push(key);
            return true;
        }

        let mut payload = Vec::new();
        if Self::write_value_payload(&mut payload, value).is_none() {
            return false;
        }

        let len_u16 = match u16::try_from(payload.len()) {
            Ok(v) => v,
            Err(_) => return false,
        };

        if buf.write_u16::<BigEndian>(len_u16).is_err() {
            return false;
        }
        let key = u8::try_from(key.0).unwrap_or(0);
        buf.push(key);
        buf.extend_from_slice(&payload);
        true
    }

    fn encode_array(arr: &[DataValue]) -> Vec<u8> {
        let mut out = Vec::new();
        if out
            .write_u16::<BigEndian>(u16::try_from(arr.len()).ok().unwrap_or(0))
            .is_err()
        {
            return Vec::new();
        }

        for value in arr {
            if !Self::write_array_entry(&mut out, value) {
                return Vec::new();
            }
        }

        out
    }

    fn write_array_entry(buf: &mut Vec<u8>, value: &DataValue) -> bool {
        let kind = Self::kind_marker(value);
        buf.push(kind);

        if kind == Self::KIND_BOOL_TRUE || kind == Self::KIND_BOOL_FALSE {
            return true;
        }

        let mut payload = Vec::new();
        if Self::write_value_payload(&mut payload, value).is_none() {
            return false;
        }

        let len_u16 = match u16::try_from(payload.len()) {
            Ok(v) => v,
            Err(_) => return false,
        };

        if buf.write_u16::<BigEndian>(len_u16).is_err() {
            return false;
        }
        buf.extend_from_slice(&payload);
        true
    }

    fn write_value_payload(buf: &mut Vec<u8>, value: &DataValue) -> Option<()> {
        match value {
            DataValue::BoolTrue => Some(()),
            DataValue::BoolFalse => Some(()),
            DataValue::Bool(v) => {
                if *v {
                    Some(())
                } else {
                    Some(())
                }
            }
            DataValue::SignedNumber(n) => {
                buf.write_i128::<BigEndian>(*n).ok()?;
                Some(())
            }
            DataValue::UnsignedNumber(n) => {
                buf.write_u128::<BigEndian>(*n).ok()?;
                Some(())
            }
            DataValue::Float(a, b) => {
                buf.write_u8(*a).ok()?;
                buf.write_u32::<BigEndian>(*b).ok()?;
                Some(())
            }
            DataValue::Str(s) => {
                buf.extend_from_slice(s.as_bytes());
                Some(())
            }
            DataValue::Array(arr) => {
                let bytes = Self::encode_array(arr);
                buf.extend_from_slice(&bytes);
                Some(())
            }
            DataValue::Bytes(b) => {
                buf.extend_from_slice(b);
                Some(())
            }
            DataValue::Container(entries) => {
                let bytes = Self::encode_container(entries);
                buf.extend_from_slice(&bytes);
                Some(())
            }
            #[cfg(feature = "crypto")]
            DataValue::EncryptedContainer(entries) => {
                let bytes = Self::encode_container(entries);
                buf.extend_from_slice(&bytes);
                Some(())
            }

            DataValue::Null => Some(()),
        }
    }

    fn read_value(cursor: &mut Cursor<&[u8]>, top_level: bool) -> Option<Self> {
        if top_level {
            let start = cursor.position() as usize;
            let remaining = cursor.get_ref().len().checked_sub(start)?;
            if remaining < 2 {
                return None;
            }

            let snapshot = cursor.clone();
            if let Some(container) = Self::try_read_container(cursor) {
                return Some(container);
            }
            *cursor = snapshot;

            let array = Self::read_array(cursor)?;
            return Some(array);
        }

        let kind = cursor.read_u8().ok()?;
        Self::read_value_by_kind(cursor, kind, None)
    }

    fn try_read_container(cursor: &mut Cursor<&[u8]>) -> Option<Self> {
        let count = cursor.read_u16::<BigEndian>().ok()? as usize;
        let mut entries = Vec::with_capacity(count);

        for _ in 0..count {
            let kind = cursor.read_u8().ok()?;

            if kind == Self::KIND_BOOL_TRUE || kind == Self::KIND_BOOL_FALSE {
                let key = DataTypeId(cursor.read_u16::<BigEndian>().ok()?);
                let value = if kind == Self::KIND_BOOL_TRUE {
                    DataValue::BoolTrue
                } else {
                    DataValue::BoolFalse
                };
                entries.push((key, value));
                continue;
            }

            let len = cursor.read_u16::<BigEndian>().ok()? as usize;
            let key = DataTypeId(cursor.read_u16::<BigEndian>().ok()?);

            let start = cursor.position() as usize;
            let end = start.checked_add(len)?;
            if end > cursor.get_ref().len() {
                return None;
            }

            let payload = &cursor.get_ref()[start..end];
            let mut inner = Cursor::new(payload);
            let value = Self::read_value_by_kind(&mut inner, kind, Some(len))?;
            if inner.position() as usize != len {
                return None;
            }

            cursor.set_position(end as u64);
            entries.push((key, value));
        }

        Some(DataValue::Container(entries))
    }

    fn read_array(cursor: &mut Cursor<&[u8]>) -> Option<Self> {
        let count = cursor.read_u16::<BigEndian>().ok()? as usize;
        let mut out = Vec::with_capacity(count);

        for _ in 0..count {
            let kind = cursor.read_u8().ok()?;

            if kind == Self::KIND_BOOL_TRUE {
                out.push(DataValue::BoolTrue);
                continue;
            }
            if kind == Self::KIND_BOOL_FALSE {
                out.push(DataValue::BoolFalse);
                continue;
            }

            let len = cursor.read_u16::<BigEndian>().ok()? as usize;
            let start = cursor.position() as usize;
            let end = start.checked_add(len)?;
            if end > cursor.get_ref().len() {
                return None;
            }

            let payload = &cursor.get_ref()[start..end];
            let mut inner = Cursor::new(payload);
            let value = Self::read_value_by_kind(&mut inner, kind, Some(len))?;
            if inner.position() as usize != len {
                return None;
            }

            cursor.set_position(end as u64);
            out.push(value);
        }

        Some(DataValue::Array(out))
    }

    fn read_value_by_kind(
        cursor: &mut Cursor<&[u8]>,
        kind: u8,
        payload_len: Option<usize>,
    ) -> Option<Self> {
        match kind {
            Self::KIND_BOOL_TRUE => Some(DataValue::BoolTrue),
            Self::KIND_BOOL_FALSE => Some(DataValue::BoolFalse),
            Self::KIND_SIGNED_NUMBER => Some(DataValue::SignedNumber(
                cursor.read_i128::<BigEndian>().ok()?,
            )),
            Self::KIND_UNSIGNED_NUMBER => Some(DataValue::UnsignedNumber(
                cursor.read_u128::<BigEndian>().ok()?,
            )),
            Self::KIND_FLOAT => {
                let a = cursor.read_u8().ok()?;
                let b = cursor.read_u32::<BigEndian>().ok()?;
                Some(DataValue::Float(a, b))
            }
            Self::KIND_STR => {
                let len = payload_len?;
                let start = cursor.position() as usize;
                let end = start.checked_add(len)?;
                if end > cursor.get_ref().len() {
                    return None;
                }
                let s = std::str::from_utf8(&cursor.get_ref()[start..end])
                    .ok()?
                    .to_string();
                cursor.set_position(end as u64);
                Some(DataValue::Str(s))
            }
            Self::KIND_ARRAY => {
                let start = cursor.position() as usize;
                let len = payload_len?;
                let end = start.checked_add(len)?;
                if end > cursor.get_ref().len() {
                    return None;
                }
                let mut inner = Cursor::new(&cursor.get_ref()[start..end]);
                let arr = Self::read_array(&mut inner)?;
                if inner.position() as usize != len {
                    return None;
                }
                cursor.set_position(end as u64);
                Some(arr)
            }
            Self::KIND_CONTAINER => {
                let start = cursor.position() as usize;
                let len = payload_len?;
                let end = start.checked_add(len)?;
                if end > cursor.get_ref().len() {
                    return None;
                }
                let mut inner = Cursor::new(&cursor.get_ref()[start..end]);
                let c = Self::try_read_container(&mut inner)?;
                if inner.position() as usize != len {
                    return None;
                }
                cursor.set_position(end as u64);
                Some(c)
            }
            #[cfg(feature = "crypto")]
            Self::KIND_ENCRYPTED_CONTAINER => {
                let start = cursor.position() as usize;
                let len = payload_len?;
                let end = start.checked_add(len)?;
                if end > cursor.get_ref().len() {
                    return None;
                }
                let mut inner = Cursor::new(&cursor.get_ref()[start..end]);
                let c = Self::try_read_container(&mut inner)?;
                if inner.position() as usize != len {
                    return None;
                }
                cursor.set_position(end as u64);
                if let DataValue::Container(entries) = c {
                    Some(DataValue::EncryptedContainer(entries))
                } else {
                    None
                }
            }
            Self::KIND_NULL => Some(DataValue::Null),
            _ => None,
        }
    }

    fn kind_marker(value: &DataValue) -> u8 {
        match value {
            DataValue::BoolTrue => Self::KIND_BOOL_TRUE,
            DataValue::BoolFalse => Self::KIND_BOOL_FALSE,
            DataValue::Bool(v) => {
                if *v {
                    Self::KIND_BOOL_TRUE
                } else {
                    Self::KIND_BOOL_FALSE
                }
            }
            DataValue::SignedNumber(_) => Self::KIND_SIGNED_NUMBER,
            DataValue::UnsignedNumber(_) => Self::KIND_UNSIGNED_NUMBER,
            DataValue::Float(_, _) => Self::KIND_FLOAT,
            DataValue::Str(_) => Self::KIND_STR,
            DataValue::Array(_) => Self::KIND_ARRAY,
            DataValue::Bytes(_) => Self::KIND_BYTES,
            DataValue::Container(_) => Self::KIND_CONTAINER,
            #[cfg(feature = "crypto")]
            DataValue::EncryptedContainer(_) => Self::KIND_ENCRYPTED_CONTAINER,
            DataValue::Null => Self::KIND_NULL,
        }
    }
}

impl PartialEq for DataValue {
    fn eq(&self, other: &Self) -> bool {
        use DataValue::*;
        match (self, other) {
            (BoolTrue, BoolTrue) | (BoolFalse, BoolFalse) => true,
            (BoolTrue, Bool(true)) | (Bool(true), BoolTrue) => true,
            (BoolFalse, Bool(false)) | (Bool(false), BoolFalse) => true,
            (Bool(a), Bool(b)) => a == b,
            (SignedNumber(a), SignedNumber(b)) => a == b,
            (UnsignedNumber(a), UnsignedNumber(b)) => a == b,
            (Float(a, b), Float(c, d)) => a == c && b == d,
            (Str(a), Str(b)) => a == b,
            (Array(a), Array(b)) => a == b,
            (Bytes(a), Bytes(b)) => a == b,
            (Container(a), Container(b)) => a == b,
            #[cfg(feature = "crypto")]
            (EncryptedContainer(a), EncryptedContainer(b)) => a == b,
            (Null, Null) => true,
            _ => false,
        }
    }
}

impl Hash for DataValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        use DataValue::*;
        match self {
            BoolTrue | Bool(true) => {
                0u8.hash(state);
                true.hash(state);
            }
            BoolFalse | Bool(false) => {
                0u8.hash(state);
                false.hash(state);
            }
            SignedNumber(n) => {
                1u8.hash(state);
                n.hash(state);
            }
            UnsignedNumber(n) => {
                2u8.hash(state);
                n.hash(state);
            }
            Float(n, m) => {
                3u8.hash(state);
                n.hash(state);
                m.hash(state);
            }
            Str(s) => {
                2u8.hash(state);
                s.hash(state);
            }
            Array(a) => {
                3u8.hash(state);
                a.hash(state);
            }
            Bytes(a) => {
                4u8.hash(state);
                a.hash(state);
            }
            Container(c) => {
                5u8.hash(state);
                c.hash(state);
            }
            #[cfg(feature = "crypto")]
            EncryptedContainer(c) => {
                6u8.hash(state);
                c.hash(state);
            }
            Null => {
                6u8.hash(state);
            }
        }
    }
}
