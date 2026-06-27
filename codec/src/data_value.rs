use base64::Engine;
use base64::engine::general_purpose;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::collections::BTreeMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::Cursor;

use mtp_common::CodecError;
use mtp_type_map::DataTypeId;

#[cfg(test)]
use mtp_type_map::{DataType, TypeMap};

#[cfg(feature = "crypto")]
use mtp_crypto::{EncryptionType, Keyring, PublicKeyBundle, SigAlgorithm, SignatureScheme};

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
    #[cfg(feature = "crypto")]
    SignedContainer,
    #[cfg(feature = "crypto")]
    SignedEncryptedContainer,

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
    /*
     * Container format:
     * [2 bytes u16 entry_count]       // number of entries
     * [1 byte kind]                   // DataValue kind marker
     * [if kind == BOOL_TRUE or BOOL_FALSE:]
     *     [2 bytes u16 key]           // DataTypeId discriminant
     * [else:]
     *     [4 bytes u32 payload_len]   // length of the value payload
     *     [2 bytes u16 key]           // DataTypeId discriminant
     *     [payload_len bytes payload] // value data (interpreted based on kind)
     */
    Container(Vec<(DataTypeId, DataValue)>),

    /*
     * Container format:
     * [4 bytes u32 entry_count]       // length of the container
     * [binary data]
     * -> After decryption, the container is parsed as a regular container
     */
    #[cfg(feature = "crypto")]
    EncryptedContainer(Vec<u8>),

    /*
     * Container format:
     * [4 bytes u32 entry_count]       // length of the container
     * [binary data]
     * -> Can be turned into Container
     * -> Can be used with a public key to verify integrity
     */
    #[cfg(feature = "crypto")]
    SignedContainer(Vec<u8>),

    /*
     * Container format:
     * [4 bytes u32 entry_count]       // length of the container
     * [binary data]
     * -> After decryption, the container is parsed as a signed container
     */
    #[cfg(feature = "crypto")]
    SignedEncryptedContainer(Vec<u8>),

    Null,
}

impl DataValue {
    /*
     * Container format:
     * [2 bytes u16 entry_count]       // number of entries
     * [1 byte kind]                   // DataValue kind marker
     * [if kind == BOOL_TRUE or BOOL_FALSE:]
     *     [2 bytes u16 key]           // DataTypeId discriminant
     * [else:]
     *     [4 bytes u32 payload_len]   // length of the value payload
     *     [2 bytes u16 key]           // DataTypeId discriminant
     *     [payload_len bytes payload] // value data (interpreted based on kind)
     *
     * Array format (same as container but no keys):
     * [2 bytes u16 entry_count]
     * for each entry:
     *   [1 byte kind]
     *   [if kind == BOOL_TRUE or BOOL_FALSE:]
     *       (no payload)
     *   [else:]
     *       [4 bytes u32 payload_len]
     *       [payload_len bytes payload]
     *
     * Kind markers:
     * 0x01 => BoolTrue
     * 0x02 => BoolFalse
     * 0x03 => Signed Number (i128, 16 bytes big-endian)
     * 0x04 => Unsigned Number (u128, 16 bytes big-endian)
     * 0x05 => Float (1 byte exponent, 4 bytes mantissa)
     * 0x06 => Str (UTF-8 bytes)
     * 0x07 => Bytes
     * 0x08 => Array
     * 0x09 => Container
     * 0x0A => EncryptedContainer (1 byte EncryptionType + KEM ciphertext + AEAD payload)
     * 0x0B => SignedContainer (1 byte SigAlgorithm + signature + serialized container)
     * 0x0C => SignedEncryptedContainer (encrypted blob that decrypts to a SignedContainer)
     * 0xFF => Null
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
    #[cfg(feature = "crypto")]
    const KIND_SIGNED_CONTAINER: u8 = 0x0B;
    #[cfg(feature = "crypto")]
    const KIND_SIGNED_ENCRYPTED_CONTAINER: u8 = 0x0C;

    const KIND_NULL: u8 = 0xFF;

    /*
     * Smallest possible encoded entry, used to cap pre-reservation when
     * decoding containers/arrays so a small frame cannot force a huge
     * allocation from an attacker-controlled count. A bool/null entry in a
     * container is 3 bytes (1 kind + 2 key); a bare value in an array is 1
     * byte, so 1 is the safe lower bound shared by both.
     */
    const MIN_ENTRY_BYTES: usize = 1;

    pub fn container_from_map(map: &BTreeMap<DataTypeId, DataValue>) -> DataValue {
        let mut container = Vec::new();
        for (key, value) in map {
            container.push((*key, value.clone()));
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
            #[cfg(feature = "crypto")]
            DataValue::SignedContainer(_) => DataKind::SignedContainer,
            #[cfg(feature = "crypto")]
            DataValue::SignedEncryptedContainer(_) => DataKind::SignedEncryptedContainer,
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
    pub fn as_encrypted_container(&self) -> Option<Vec<u8>> {
        match self {
            DataValue::EncryptedContainer(c) => Some(c.clone()),
            _ => None,
        }
    }

    #[cfg(feature = "crypto")]
    pub fn as_signed_container(&self) -> Option<Vec<u8>> {
        match self {
            DataValue::SignedContainer(b) => Some(b.clone()),
            _ => None,
        }
    }

    #[cfg(feature = "crypto")]
    pub fn as_signed_encrypted_container(&self) -> Option<Vec<u8>> {
        match self {
            DataValue::SignedEncryptedContainer(c) => Some(c.clone()),
            _ => None,
        }
    }

    /*
     * Decrypt an `EncryptedContainer` in-place, replacing it with the
     * deserialized `Container`. The algorithm (and which keypair to use) is read
     * from the blob's leading `EncryptionType` byte; the matching key is taken
     * from `keyring`. Returns `None` if decryption or deserialization fails.
     */
    #[cfg(feature = "crypto")]
    pub fn decrypt_into_container(&mut self, keyring: &Keyring, aad: &[u8]) -> Option<()> {
        let data = self.as_encrypted_container()?;
        let plaintext = mtp_crypto::decrypt_with(&data, keyring, aad).ok()?;
        let dv = DataValue::from_bytes(&plaintext)?;
        match dv {
            DataValue::Container(entries) => {
                *self = DataValue::Container(entries);
                Some(())
            }
            _ => None,
        }
    }

    /*
     * Encrypt a `Container` into an `EncryptedContainer` in-place.
     * `enc_type` selects the algorithm and `recipient` provides the public key
     * encapsulated to. The resulting blob is self-describing: its leading byte
     * is `enc_type`, so `decrypt_into_container` needs only a `Keyring`.
     * Returns `None` if the value is not a `Container` or encryption fails.
     */
    #[cfg(feature = "crypto")]
    pub fn encrypt_container(
        &mut self,
        enc_type: EncryptionType,
        recipient: &PublicKeyBundle,
        aad: &[u8],
    ) -> Option<()> {
        let entries = self.as_container()?;
        let plaintext = DataValue::Container(entries).to_bytes().ok()?;
        let ct = mtp_crypto::encrypt_for(enc_type, recipient, &plaintext, aad).ok()?;
        *self = DataValue::EncryptedContainer(ct);
        Some(())
    }

    /*
     * Sign a `Container` in-place, replacing it with a `SignedContainer`.
     * The wire blob is: [1 byte alg] [N bytes sig] [serialized container bytes].
     * The signature covers only the serialized container bytes (not the alg byte).
     * Returns `None` if the value is not a `Container` or signing fails.
     */
    #[cfg(feature = "crypto")]
    pub fn sign_container(&mut self, algorithm: u8, signer: &impl SignatureScheme) -> Option<()> {
        let entries = self.as_container()?;
        let container_bytes = Self::encode_container(&entries).ok()?;

        let sig = signer.sign(&container_bytes).ok()?;

        let mut blob = Vec::with_capacity(1 + sig.len() + container_bytes.len());
        blob.push(algorithm);
        blob.extend_from_slice(&sig);
        blob.extend_from_slice(&container_bytes);

        *self = DataValue::SignedContainer(blob);
        Some(())
    }

    /*
     * Verify a `SignedContainer` in-place, replacing it with the deserialized
     * `Container` on success. Returns `None` if verification fails or the
     * blob is malformed.
     */
    #[cfg(feature = "crypto")]
    pub fn verify_into_container(&mut self, verifier: &impl SignatureScheme) -> Option<()> {
        let blob = self.as_signed_container()?;
        if blob.len() < 1 + 64 + 2 {
            return None;
        }

        let algorithm = blob[0];
        let sig_len = SigAlgorithm::length(algorithm)?;
        if blob.len() < 1 + sig_len + 2 {
            return None;
        }

        let signature = &blob[1..1 + sig_len];
        let container_bytes = &blob[1 + sig_len..];

        verifier.verify(container_bytes, signature).ok()?;

        let entries = DataValue::from_bytes(container_bytes)?.as_container()?;
        *self = DataValue::Container(entries);
        Some(())
    }

    /*
     * Encrypt a `Container` into a `SignedEncryptedContainer` in-place.
     * The container is first signed (with `algorithm`/`signer`), then the signed
     * blob is encrypted with `enc_type` to `recipient`. The result is an opaque
     * ciphertext that decrypts to a `SignedContainer`.
     */
    #[cfg(feature = "crypto")]
    pub fn sign_and_encrypt_container(
        &mut self,
        algorithm: u8,
        signer: &impl SignatureScheme,
        enc_type: EncryptionType,
        recipient: &PublicKeyBundle,
        aad: &[u8],
    ) -> Option<()> {
        self.sign_container(algorithm, signer)?;
        let blob = self.as_signed_container()?;
        let ct = mtp_crypto::encrypt_for(enc_type, recipient, &blob, aad).ok()?;
        *self = DataValue::SignedEncryptedContainer(ct);
        Some(())
    }

    /*
     * Decrypt a `SignedEncryptedContainer` in-place, replacing it with a
     * `SignedContainer`. The algorithm and keypair are resolved from the blob's
     * leading byte and `keyring`. Does NOT verify; call `verify_into_container`
     * next.
     */
    #[cfg(feature = "crypto")]
    pub fn decrypt_signed_encrypted_container(
        &mut self,
        keyring: &Keyring,
        aad: &[u8],
    ) -> Option<()> {
        let data = self.as_signed_encrypted_container()?;
        let plaintext = mtp_crypto::decrypt_with(&data, keyring, aad).ok()?;
        *self = DataValue::SignedContainer(plaintext);
        Some(())
    }

    pub fn as_map(&self) -> Option<BTreeMap<DataTypeId, DataValue>> {
        match self {
            DataValue::Container(c) => {
                let mut out = BTreeMap::new();
                for (k, v) in c {
                    out.insert(*k, v.clone());
                }
                Some(out)
            }
            _ => None,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, CodecError> {
        match self {
            DataValue::Container(entries) => Self::encode_container(entries),
            DataValue::Array(arr) => Self::encode_array(arr),
            _ => {
                let mut out = Vec::new();
                Self::write_value_payload(&mut out, self)?;
                Ok(out)
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

    pub fn to_base64(&self) -> Result<String, CodecError> {
        Ok(general_purpose::STANDARD.encode(self.to_bytes()?))
    }

    pub fn from_base64(base64_str: &str) -> Option<Self> {
        let bytes = general_purpose::STANDARD.decode(base64_str).ok()?;
        Self::from_bytes(&bytes)
    }

    fn encode_container(entries: &[(DataTypeId, DataValue)]) -> Result<Vec<u8>, CodecError> {
        let mut out = Vec::new();
        let count = u16::try_from(entries.len()).map_err(|_| CodecError::TooManyEntries)?;
        out.write_u16::<BigEndian>(count)
            .map_err(|_| CodecError::InvalidEncoding)?;

        for (key, value) in entries {
            Self::write_container_entry(&mut out, *key, value)?;
        }
        Ok(out)
    }

    fn write_container_entry(
        buf: &mut Vec<u8>,
        key: DataTypeId,
        value: &DataValue,
    ) -> Result<(), CodecError> {
        let kind = Self::kind_marker(value);
        buf.push(kind);

        if Self::kind_has_no_payload(kind) {
            buf.write_u16::<BigEndian>(key.0)
                .map_err(|_| CodecError::InvalidEncoding)?;
            return Ok(());
        }

        let mut payload = Vec::new();
        Self::write_value_payload(&mut payload, value)?;

        let len = u32::try_from(payload.len()).map_err(|_| CodecError::TooManyEntries)?;
        buf.write_u32::<BigEndian>(len)
            .map_err(|_| CodecError::InvalidEncoding)?;
        buf.write_u16::<BigEndian>(key.0)
            .map_err(|_| CodecError::InvalidEncoding)?;
        buf.extend_from_slice(&payload);
        Ok(())
    }

    fn encode_array(arr: &[DataValue]) -> Result<Vec<u8>, CodecError> {
        let mut out = Vec::new();
        let count = u16::try_from(arr.len()).map_err(|_| CodecError::TooManyEntries)?;
        out.write_u16::<BigEndian>(count)
            .map_err(|_| CodecError::InvalidEncoding)?;

        for value in arr {
            Self::write_array_entry(&mut out, value)?;
        }

        Ok(out)
    }

    fn write_array_entry(buf: &mut Vec<u8>, value: &DataValue) -> Result<(), CodecError> {
        let kind = Self::kind_marker(value);
        buf.push(kind);

        if Self::kind_has_no_payload(kind) {
            return Ok(());
        }

        let mut payload = Vec::new();
        Self::write_value_payload(&mut payload, value)?;

        let len = u32::try_from(payload.len()).map_err(|_| CodecError::TooManyEntries)?;
        buf.write_u32::<BigEndian>(len)
            .map_err(|_| CodecError::InvalidEncoding)?;
        buf.extend_from_slice(&payload);
        Ok(())
    }

    fn write_value_payload(buf: &mut Vec<u8>, value: &DataValue) -> Result<(), CodecError> {
        match value {
            DataValue::BoolTrue => Ok(()),
            DataValue::BoolFalse => Ok(()),
            #[allow(clippy::if_same_then_else)]
            DataValue::Bool(v) => {
                // Kept intentionally: the kind marker already encodes the boolean,
                // so both arms carry no payload. Retained for clear compatibility.
                if *v { Ok(()) } else { Ok(()) }
            }
            DataValue::SignedNumber(n) => {
                buf.write_i128::<BigEndian>(*n)
                    .map_err(|_| CodecError::InvalidEncoding)?;
                Ok(())
            }
            DataValue::UnsignedNumber(n) => {
                buf.write_u128::<BigEndian>(*n)
                    .map_err(|_| CodecError::InvalidEncoding)?;
                Ok(())
            }
            DataValue::Float(a, b) => {
                buf.write_u8(*a).map_err(|_| CodecError::InvalidEncoding)?;
                buf.write_u32::<BigEndian>(*b)
                    .map_err(|_| CodecError::InvalidEncoding)?;
                Ok(())
            }
            DataValue::Str(s) => {
                buf.extend_from_slice(s.as_bytes());
                Ok(())
            }
            DataValue::Array(arr) => {
                let bytes = Self::encode_array(arr)?;
                buf.extend_from_slice(&bytes);
                Ok(())
            }
            DataValue::Bytes(b) => {
                buf.extend_from_slice(b);
                Ok(())
            }
            DataValue::Container(entries) => {
                let bytes = Self::encode_container(entries)?;
                buf.extend_from_slice(&bytes);
                Ok(())
            }
            #[cfg(feature = "crypto")]
            DataValue::EncryptedContainer(data) => {
                buf.extend_from_slice(data);
                Ok(())
            }
            #[cfg(feature = "crypto")]
            DataValue::SignedContainer(data) => {
                buf.extend_from_slice(data);
                Ok(())
            }
            #[cfg(feature = "crypto")]
            DataValue::SignedEncryptedContainer(data) => {
                buf.extend_from_slice(data);
                Ok(())
            }

            DataValue::Null => Ok(()),
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
        let remaining = cursor
            .get_ref()
            .len()
            .saturating_sub(cursor.position() as usize);
        let mut entries = Vec::with_capacity(count.min(remaining / Self::MIN_ENTRY_BYTES));

        for _ in 0..count {
            let kind = cursor.read_u8().ok()?;

            if Self::kind_has_no_payload(kind) {
                let key = DataTypeId(cursor.read_u16::<BigEndian>().ok()?);
                let value = Self::read_payloadless_value(kind)?;
                entries.push((key, value));
                continue;
            }

            let len = cursor.read_u32::<BigEndian>().ok()? as usize;
            let key = DataTypeId(cursor.read_u16::<BigEndian>().ok()?);

            let payload = Self::read_payload_slice(cursor, len)?;
            let mut inner = Cursor::new(payload);
            let value = Self::read_value_by_kind(&mut inner, kind, Some(len))?;
            if inner.position() as usize != len {
                return None;
            }
            entries.push((key, value));
        }

        Some(DataValue::Container(entries))
    }

    fn read_array(cursor: &mut Cursor<&[u8]>) -> Option<Self> {
        let count = cursor.read_u16::<BigEndian>().ok()? as usize;
        let remaining = cursor
            .get_ref()
            .len()
            .saturating_sub(cursor.position() as usize);
        let mut out = Vec::with_capacity(count.min(remaining / Self::MIN_ENTRY_BYTES));

        for _ in 0..count {
            let kind = cursor.read_u8().ok()?;

            if Self::kind_has_no_payload(kind) {
                let value = Self::read_payloadless_value(kind)?;
                out.push(value);
                continue;
            }

            let len = cursor.read_u32::<BigEndian>().ok()? as usize;
            let payload = Self::read_payload_slice(cursor, len)?;
            let mut inner = Cursor::new(payload);
            let value = Self::read_value_by_kind(&mut inner, kind, Some(len))?;
            if inner.position() as usize != len {
                return None;
            }
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
                let s = std::str::from_utf8(Self::read_payload_slice(cursor, payload_len?)?)
                    .ok()?
                    .to_string();
                Some(DataValue::Str(s))
            }
            Self::KIND_BYTES => Some(DataValue::Bytes(Self::read_blob_payload(
                cursor,
                payload_len?,
            )?)),
            Self::KIND_ARRAY => {
                let len = payload_len?;
                let mut inner = Cursor::new(Self::read_payload_slice(cursor, len)?);
                let arr = Self::read_array(&mut inner)?;
                if inner.position() as usize != len {
                    return None;
                }
                Some(arr)
            }
            Self::KIND_CONTAINER => {
                let len = payload_len?;
                let mut inner = Cursor::new(Self::read_payload_slice(cursor, len)?);
                let c = Self::try_read_container(&mut inner)?;
                if inner.position() as usize != len {
                    return None;
                }
                Some(c)
            }
            #[cfg(feature = "crypto")]
            Self::KIND_ENCRYPTED_CONTAINER => Some(DataValue::EncryptedContainer(
                Self::read_blob_payload(cursor, payload_len?)?,
            )),
            #[cfg(feature = "crypto")]
            Self::KIND_SIGNED_CONTAINER => Some(DataValue::SignedContainer(
                Self::read_blob_payload(cursor, payload_len?)?,
            )),
            #[cfg(feature = "crypto")]
            Self::KIND_SIGNED_ENCRYPTED_CONTAINER => Some(DataValue::SignedEncryptedContainer(
                Self::read_blob_payload(cursor, payload_len?)?,
            )),
            Self::KIND_NULL => Some(DataValue::Null),
            #[cfg(not(feature = "crypto"))]
            0x0A | 0x0B | 0x0C => None,
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
            #[cfg(feature = "crypto")]
            DataValue::SignedContainer(_) => Self::KIND_SIGNED_CONTAINER,
            #[cfg(feature = "crypto")]
            DataValue::SignedEncryptedContainer(_) => Self::KIND_SIGNED_ENCRYPTED_CONTAINER,
            DataValue::Null => Self::KIND_NULL,
        }
    }

    fn kind_has_no_payload(kind: u8) -> bool {
        kind == Self::KIND_BOOL_TRUE || kind == Self::KIND_BOOL_FALSE || kind == Self::KIND_NULL
    }

    fn read_payloadless_value(kind: u8) -> Option<Self> {
        match kind {
            Self::KIND_BOOL_TRUE => Some(DataValue::BoolTrue),
            Self::KIND_BOOL_FALSE => Some(DataValue::BoolFalse),
            Self::KIND_NULL => Some(DataValue::Null),
            _ => None,
        }
    }

    fn read_payload_slice<'a>(cursor: &mut Cursor<&'a [u8]>, len: usize) -> Option<&'a [u8]> {
        let start = cursor.position() as usize;
        let end = start.checked_add(len)?;
        if end > cursor.get_ref().len() {
            return None;
        }
        cursor.set_position(end as u64);
        Some(&cursor.get_ref()[start..end])
    }

    fn read_blob_payload(cursor: &mut Cursor<&[u8]>, len: usize) -> Option<Vec<u8>> {
        Some(Self::read_payload_slice(cursor, len)?.to_vec())
    }
}

impl fmt::Display for DataValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataValue::BoolTrue => write!(f, "true"),
            DataValue::BoolFalse => write!(f, "false"),
            DataValue::Bool(v) => write!(f, "{}", v),
            DataValue::SignedNumber(n) => write!(f, "{}", n),
            DataValue::UnsignedNumber(n) => write!(f, "{}", n),
            DataValue::Float(exp, mant) => write!(f, "{}e{}", mant, exp),
            DataValue::Str(s) => write!(f, "\"{}\"", s),
            DataValue::Container(entries) => {
                write!(f, "{{")?;
                for (i, (key, value)) in entries.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", key.0, value)?;
                }
                write!(f, "}}")
            }
            DataValue::Array(arr) => {
                write!(f, "[")?;
                for (i, value) in arr.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", value)?;
                }
                write!(f, "]")
            }
            DataValue::Bytes(_) => write!(f, "(Binary)"),
            #[cfg(feature = "crypto")]
            DataValue::EncryptedContainer(_) => write!(f, "(Secure)"),
            #[cfg(feature = "crypto")]
            DataValue::SignedContainer(_) => write!(f, "(Signed)"),
            #[cfg(feature = "crypto")]
            DataValue::SignedEncryptedContainer(_) => write!(f, "(SignedSecure)"),
            DataValue::Null => write!(f, "null"),
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
            #[cfg(feature = "crypto")]
            (SignedContainer(a), SignedContainer(b)) => a == b,
            #[cfg(feature = "crypto")]
            (SignedEncryptedContainer(a), SignedEncryptedContainer(b)) => a == b,
            (Null, Null) => true,
            _ => false,
        }
    }
}

impl Hash for DataValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        use DataValue::*;
        // Use the wire kind marker as the per-variant discriminant. It is unique
        // per kind and maps BoolTrue/Bool(true) (and BoolFalse/Bool(false)) to the
        // same marker, keeping the hash consistent with the Eq bool equivalence.
        Self::kind_marker(self).hash(state);
        match self {
            BoolTrue | BoolFalse | Bool(_) | Null => {}
            SignedNumber(n) => n.hash(state),
            UnsignedNumber(n) => n.hash(state),
            Float(n, m) => {
                n.hash(state);
                m.hash(state);
            }
            Str(s) => s.hash(state),
            Array(a) => a.hash(state),
            Bytes(a) => a.hash(state),
            Container(c) => c.hash(state),
            #[cfg(feature = "crypto")]
            EncryptedContainer(c) => c.hash(state),
            #[cfg(feature = "crypto")]
            SignedContainer(c) => c.hash(state),
            #[cfg(feature = "crypto")]
            SignedEncryptedContainer(c) => c.hash(state),
        }
    }
}

/* ================================ TESTS ================================ */
#[cfg(test)]
mod tests {
    use super::*;

    fn container_roundtrip(values: Vec<(DataTypeId, DataValue)>) {
        let dv = DataValue::Container(values.clone());
        let bytes = dv.to_bytes().expect("encode failed");
        let decoded = DataValue::from_bytes(&bytes).expect("roundtrip failed");
        assert_eq!(dv, decoded, "container roundtrip mismatch");
    }

    fn array_roundtrip(values: Vec<DataValue>) {
        let dv = DataValue::Array(values.clone());
        let bytes = dv.to_bytes().expect("encode failed");
        let decoded = DataValue::from_bytes(&bytes).expect("roundtrip failed");
        assert_eq!(dv, decoded, "array roundtrip mismatch");
    }

    #[test]
    fn test_bool_in_container() {
        let tm = TypeMap::latest();
        container_roundtrip(vec![
            (DataType::Id.to_id(&tm), DataValue::BoolTrue),
            (DataType::ClientNonce.to_id(&tm), DataValue::BoolFalse),
        ]);
    }

    #[test]
    fn test_bool_true_eq() {
        assert_eq!(DataValue::BoolTrue, DataValue::Bool(true));
        assert_eq!(DataValue::BoolFalse, DataValue::Bool(false));
        assert_ne!(DataValue::BoolTrue, DataValue::Bool(false));
    }

    #[test]
    fn test_bool_as_bool() {
        assert_eq!(DataValue::BoolTrue.as_bool(), Some(true));
        assert_eq!(DataValue::BoolFalse.as_bool(), Some(false));
        assert_eq!(DataValue::Bool(true).as_bool(), Some(true));
        assert_eq!(DataValue::Null.as_bool(), None);
    }

    #[test]
    fn test_signed_number_in_container() {
        let tm = TypeMap::latest();
        container_roundtrip(vec![
            (DataType::Version.to_id(&tm), DataValue::SignedNumber(0)),
            (DataType::Id.to_id(&tm), DataValue::SignedNumber(42)),
            (
                DataType::ClientNonce.to_id(&tm),
                DataValue::SignedNumber(-42),
            ),
            (
                DataType::ServerNonce.to_id(&tm),
                DataValue::SignedNumber(i128::MAX),
            ),
            (
                DataType::PublicKeys.to_id(&tm),
                DataValue::SignedNumber(i128::MIN),
            ),
        ]);
    }

    #[test]
    fn test_unsigned_number_in_container() {
        let tm = TypeMap::latest();
        container_roundtrip(vec![
            (DataType::Version.to_id(&tm), DataValue::UnsignedNumber(0)),
            (DataType::Id.to_id(&tm), DataValue::UnsignedNumber(42)),
            (
                DataType::ClientNonce.to_id(&tm),
                DataValue::UnsignedNumber(u128::MAX),
            ),
        ]);
    }

    #[test]
    fn test_float_in_container() {
        let tm = TypeMap::latest();
        container_roundtrip(vec![
            (DataType::Version.to_id(&tm), DataValue::Float(0, 0)),
            (DataType::Id.to_id(&tm), DataValue::Float(2, 12345)),
            (
                DataType::ClientNonce.to_id(&tm),
                DataValue::Float(255, 4294967295),
            ),
        ]);
    }

    #[test]
    fn test_str_in_container() {
        let tm = TypeMap::latest();
        container_roundtrip(vec![
            (DataType::Version.to_id(&tm), DataValue::Str(String::new())),
            (DataType::Id.to_id(&tm), DataValue::Str("hello".to_string())),
            (
                DataType::ClientNonce.to_id(&tm),
                DataValue::Str("a".repeat(1000)),
            ),
        ]);
    }

    #[test]
    fn test_bytes_in_container() {
        let tm = TypeMap::latest();
        container_roundtrip(vec![
            (DataType::Version.to_id(&tm), DataValue::Bytes(vec![])),
            (
                DataType::Id.to_id(&tm),
                DataValue::Bytes(vec![0x00, 0xFF, 0xAB]),
            ),
            (
                DataType::ClientNonce.to_id(&tm),
                DataValue::Bytes(vec![0x42; 100]),
            ),
        ]);
    }

    #[test]
    fn test_null_in_container() {
        let tm = TypeMap::latest();
        container_roundtrip(vec![(DataType::Version.to_id(&tm), DataValue::Null)]);
    }

    #[test]
    fn test_array_non_empty_roundtrip() {
        array_roundtrip(vec![
            DataValue::BoolTrue,
            DataValue::SignedNumber(42),
            DataValue::Str("hello".to_string()),
            DataValue::Null,
        ]);
    }

    #[test]
    fn test_array_nested_roundtrip() {
        array_roundtrip(vec![
            DataValue::Array(vec![DataValue::BoolTrue, DataValue::BoolFalse]),
            DataValue::Array(vec![DataValue::SignedNumber(1), DataValue::SignedNumber(2)]),
        ]);
    }

    #[test]
    fn test_container_empty_roundtrip() {
        container_roundtrip(vec![]);
    }

    #[test]
    fn test_container_mixed_roundtrip() {
        let tm = TypeMap::latest();
        container_roundtrip(vec![
            (DataType::Version.to_id(&tm), DataValue::BoolTrue),
            (DataType::Id.to_id(&tm), DataValue::SignedNumber(-100)),
            (
                DataType::ClientNonce.to_id(&tm),
                DataValue::Str("test".to_string()),
            ),
            (
                DataType::ServerNonce.to_id(&tm),
                DataValue::UnsignedNumber(u128::MAX),
            ),
            (DataType::PublicKeys.to_id(&tm), DataValue::Null),
        ]);
    }

    #[test]
    fn test_container_nested_roundtrip() {
        let tm = TypeMap::latest();
        container_roundtrip(vec![
            (
                DataType::Version.to_id(&tm),
                DataValue::Container(vec![(DataType::Error.to_id(&tm), DataValue::BoolTrue)]),
            ),
            (
                DataType::Id.to_id(&tm),
                DataValue::Array(vec![DataValue::SignedNumber(1), DataValue::SignedNumber(2)]),
            ),
        ]);
    }

    #[test]
    fn test_container_base64_roundtrip() {
        let tm = TypeMap::latest();
        let dv = DataValue::Container(vec![(
            DataType::Description.to_id(&tm),
            DataValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        )]);
        let b64 = dv.to_base64().expect("encode failed");
        let decoded = DataValue::from_base64(&b64).expect("base64 roundtrip failed");
        assert_eq!(dv, decoded);
    }

    #[test]
    fn test_kind_classification() {
        assert_eq!(DataValue::BoolTrue.kind(), DataKind::Bool);
        assert_eq!(DataValue::Bool(false).kind(), DataKind::Bool);
        assert_eq!(DataValue::SignedNumber(0).kind(), DataKind::SignedNumber);
        assert_eq!(
            DataValue::UnsignedNumber(0).kind(),
            DataKind::UnsignedNumber
        );
        assert_eq!(DataValue::Float(0, 0).kind(), DataKind::Float);
        assert_eq!(DataValue::Str(String::new()).kind(), DataKind::Str);
        assert_eq!(DataValue::Bytes(vec![]).kind(), DataKind::Bytes);
        assert_eq!(
            DataValue::Array(vec![]).kind(),
            DataKind::Array(Box::new(DataKind::Null))
        );
        assert_eq!(DataValue::Container(vec![]).kind(), DataKind::Container);
        assert_eq!(DataValue::Null.kind(), DataKind::Null);
    }

    #[test]
    fn test_as_accessors() {
        let tm = TypeMap::latest();
        let dv = DataValue::Container(vec![
            (
                DataType::Version.to_id(&tm),
                DataValue::Str("alice".to_string()),
            ),
            (DataType::Id.to_id(&tm), DataValue::SignedNumber(42)),
            (
                DataType::ClientNonce.to_id(&tm),
                DataValue::Bytes(vec![0x01, 0x02]),
            ),
            (
                DataType::ServerNonce.to_id(&tm),
                DataValue::Array(vec![DataValue::BoolTrue]),
            ),
        ]);

        let map = dv.as_map().expect("should be a container");
        assert_eq!(
            map.get(&DataType::Version.to_id(&tm))
                .and_then(|v| v.as_str()),
            Some("alice")
        );
        assert_eq!(
            map.get(&DataType::Id.to_id(&tm))
                .and_then(|v| v.as_signed_number()),
            Some(42)
        );
        assert_eq!(
            map.get(&DataType::ClientNonce.to_id(&tm))
                .and_then(|v| v.as_bytes()),
            Some(vec![0x01, 0x02])
        );
        assert_eq!(
            map.get(&DataType::ServerNonce.to_id(&tm))
                .and_then(|v| v.as_array()),
            Some(vec![DataValue::BoolTrue])
        );
    }

    #[test]
    fn test_as_string() {
        let dv = DataValue::Str("hello".to_string());
        assert_eq!(dv.as_string(), Some("hello".to_string()));
        assert_eq!(dv.as_str(), Some("hello"));
        assert_eq!(DataValue::Null.as_string(), None);
    }

    #[test]
    fn test_as_float() {
        assert_eq!(DataValue::Float(3, 14).as_float(), Some((3, 14)));
        assert_eq!(DataValue::Null.as_float(), None);
    }

    #[test]
    fn test_container_from_map() {
        let tm = TypeMap::latest();
        let mut map = BTreeMap::new();
        map.insert(DataType::Version.to_id(&tm), DataValue::BoolTrue);
        map.insert(DataType::Id.to_id(&tm), DataValue::SignedNumber(99));
        let dv = DataValue::container_from_map(&map);
        let container = dv.as_container().expect("should be container");
        assert_eq!(container.len(), 2);
    }

    #[test]
    fn test_invalid_short_input() {
        assert!(DataValue::from_bytes(&[]).is_none());
        assert!(DataValue::from_bytes(&[0x01]).is_none());
    }

    #[test]
    fn test_invalid_kind_rejected() {
        let bytes = vec![0x00, 0x01, 0x0D, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x41];
        assert!(DataValue::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_truncated_container_rejected() {
        let tm = TypeMap::latest();
        let dv = DataValue::Container(vec![(
            DataType::Version.to_id(&tm),
            DataValue::Str("hello".to_string()),
        )]);
        let bytes = dv.to_bytes().expect("encode failed");
        // Truncate to fewer than 2 bytes so neither container nor array can be read
        assert!(DataValue::from_bytes(&bytes[..1]).is_none());
        assert!(DataValue::from_bytes(&bytes[..0]).is_none());
    }

    #[test]
    fn test_oversized_count_does_not_overallocate() {
        // A frame declaring 65535 entries but carrying almost no payload must be
        // rejected without pre-reserving a Vec for 65535 entries. The capacity is
        // capped against remaining bytes, so these decode attempts allocate at
        // most a handful of slots before failing.
        // Container path: count = 0xFFFF, no entries follow.
        assert!(DataValue::from_bytes(&[0xFF, 0xFF]).is_none());
        // Container path with one stray byte after the count.
        assert!(DataValue::from_bytes(&[0xFF, 0xFF, 0x01]).is_none());
        // Array path: force the container parse to fail first, then the array
        // parse also sees the oversized count. A leading kind byte that is not a
        // valid container entry makes try_read_container bail to the array path.
        assert!(DataValue::from_bytes(&[0xFF, 0xFF, 0x08, 0xFF, 0xFF]).is_none());
    }

    #[test]
    fn test_display_basic() {
        assert_eq!(format!("{}", DataValue::BoolTrue), "true");
        assert_eq!(format!("{}", DataValue::BoolFalse), "false");
        assert_eq!(format!("{}", DataValue::Null), "null");
        assert_eq!(format!("{}", DataValue::SignedNumber(42)), "42");
        assert_eq!(format!("{}", DataValue::UnsignedNumber(42)), "42");
        assert_eq!(format!("{}", DataValue::Str("hi".to_string())), "\"hi\"");
        assert_eq!(format!("{}", DataValue::Bytes(vec![])), "(Binary)");
    }

    #[test]
    fn test_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(DataValue::BoolTrue);
        set.insert(DataValue::BoolFalse);
        set.insert(DataValue::Null);
        set.insert(DataValue::SignedNumber(1));
        set.insert(DataValue::UnsignedNumber(1));
        assert_eq!(set.len(), 5);
        set.insert(DataValue::Bool(true));
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn test_float_display() {
        let s = format!("{}", DataValue::Float(2, 12345));
        assert_eq!(s, "12345e2");
    }

    #[test]
    fn test_container_display() {
        let tm = TypeMap::latest();
        let dv = DataValue::Container(vec![
            (
                DataType::ServerNonce.to_id(&tm),
                DataValue::Str("v2.0".to_string()),
            ),
            (
                DataType::PqSignature.to_id(&tm),
                DataValue::UnsignedNumber(42),
            ),
        ]);
        let s = format!("{}", dv);
        assert!(s.contains("3:"));
        assert!(s.contains("6:"));
    }

    #[test]
    fn test_array_display() {
        let dv = DataValue::Array(vec![DataValue::SignedNumber(1), DataValue::SignedNumber(2)]);
        let s = format!("{}", dv);
        assert_eq!(s, "[1, 2]");
    }

    /* ===== Crypto container tests ===== */

    #[cfg(feature = "crypto")]
    #[test]
    fn test_encrypt_decrypt_container_roundtrip() {
        use mtp_crypto::{EncryptionType, Keyring};
        let tm = TypeMap::latest();
        let keyring = Keyring::generate();
        let bundle = keyring.public_key_bundle();

        let mut dv = DataValue::Container(vec![
            (
                DataType::Version.to_id(&tm),
                DataValue::Str("secret".to_string()),
            ),
            (DataType::Id.to_id(&tm), DataValue::UnsignedNumber(42)),
        ]);

        assert!(
            dv.encrypt_container(EncryptionType::MlKemChaCha20Poly1305, &bundle, b"aad")
                .is_some()
        );
        assert!(matches!(dv, DataValue::EncryptedContainer(_)));

        assert!(dv.decrypt_into_container(&keyring, b"aad").is_some());
        assert!(matches!(dv, DataValue::Container(_)));

        let entries = dv.as_container().unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_encrypt_container_wrong_key_fails() {
        use mtp_crypto::{EncryptionType, Keyring};
        let tm = TypeMap::latest();
        let keyring_a = Keyring::generate();
        let keyring_b = Keyring::generate();

        let mut dv = DataValue::Container(vec![(
            DataType::Version.to_id(&tm),
            DataValue::Str("secret".to_string()),
        )]);

        assert!(
            dv.encrypt_container(
                EncryptionType::MlKemChaCha20Poly1305,
                &keyring_a.public_key_bundle(),
                b"aad"
            )
            .is_some()
        );
        assert!(dv.decrypt_into_container(&keyring_b, b"aad").is_none());
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_encrypt_container_wrong_aad_fails() {
        use mtp_crypto::{EncryptionType, Keyring};
        let tm = TypeMap::latest();
        let keyring = Keyring::generate();

        let mut dv = DataValue::Container(vec![(
            DataType::Version.to_id(&tm),
            DataValue::Str("secret".to_string()),
        )]);

        assert!(
            dv.encrypt_container(
                EncryptionType::MlKemChaCha20Poly1305,
                &keyring.public_key_bundle(),
                b"correct-aad"
            )
            .is_some()
        );
        assert!(dv.decrypt_into_container(&keyring, b"wrong-aad").is_none());
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_encrypt_non_container_fails() {
        use mtp_crypto::{EncryptionType, Keyring};
        let keyring = Keyring::generate();

        let mut dv = DataValue::Str("not a container".to_string());
        assert!(
            dv.encrypt_container(
                EncryptionType::MlKemChaCha20Poly1305,
                &keyring.public_key_bundle(),
                b"aad"
            )
            .is_none()
        );
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_sign_verify_container_roundtrip() {
        use mtp_crypto::{Ed25519Signer, EncryptionType, Keyring, SigAlgorithm};
        let tm = TypeMap::latest();

        let keyring = Keyring::generate();
        let (signer, sk, _pk) = Ed25519Signer::generate();

        let mut dv = DataValue::Container(vec![(
            DataType::Version.to_id(&tm),
            DataValue::Str("signed data".to_string()),
        )]);

        assert!(
            dv.sign_and_encrypt_container(
                SigAlgorithm::ED25519,
                &signer,
                EncryptionType::MlKemChaCha20Poly1305,
                &keyring.public_key_bundle(),
                b"aad"
            )
            .is_some()
        );
        assert!(matches!(dv, DataValue::SignedEncryptedContainer(_)));

        assert!(
            dv.decrypt_signed_encrypted_container(&keyring, b"aad")
                .is_some()
        );
        assert!(matches!(dv, DataValue::SignedContainer(_)));

        let verifier = Ed25519Signer::new(&sk).unwrap();
        assert!(dv.verify_into_container(&verifier).is_some());
        assert!(matches!(dv, DataValue::Container(_)));

        let entries = dv.as_container().unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_sign_container_wrong_key_fails() {
        use mtp_crypto::{Ed25519Signer, SigAlgorithm};
        let tm = TypeMap::latest();

        let (signer, _, _) = Ed25519Signer::generate();
        let (_, sk2, _) = Ed25519Signer::generate();
        let wrong_verifier = Ed25519Signer::new(&sk2).unwrap();

        let mut dv = DataValue::Container(vec![(
            DataType::Version.to_id(&tm),
            DataValue::Str("signed data".to_string()),
        )]);

        assert!(dv.sign_container(SigAlgorithm::ED25519, &signer).is_some());
        assert!(dv.verify_into_container(&wrong_verifier).is_none());
    }
}
