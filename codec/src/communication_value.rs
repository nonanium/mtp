use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{Cursor, Read};

use crate::data_value::DataValue;
use crate::rand_u32;
use mtp_common::CodecError;
use mtp_type_map::{
    CommunicationType, CommunicationTypeId, DataType, DataTypeId, PROTOCOL_VERSION, TypeMap,
    communication_type_name, data_type_name,
};

#[cfg(feature = "crypto")]
use mtp_crypto::SigAlgorithm;
#[cfg(feature = "crypto")]
use mtp_crypto::SignatureScheme;

const FLAG_HAS_SENDER: u8 = 0b0000_0001;
const FLAG_HAS_RECEIVER: u8 = 0b0000_0010;
const FLAG_HAS_ID: u8 = 0b0000_0100;
const FLAG_ENCRYPTED: u8 = 0b0000_1000;
const FLAG_SIGNED: u8 = 0b0001_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunicationValue {
    id: u32,
    comm_type: CommunicationTypeId,
    sender: u64,
    receiver: u64,
    data: BTreeMap<DataTypeId, DataValue>,
    type_map: Option<TypeMap>,
    #[cfg(feature = "crypto")]
    frame_signature: Option<(u8, Vec<u8>)>,
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
            #[cfg(feature = "crypto")]
            frame_signature: None,
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
            #[cfg(feature = "crypto")]
            frame_signature: None,
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
     * [4 bytes u32 total_length]           // number of bytes after this field
     * [2 bytes u16 communication_type]
     * [1 byte flags]
     * [optional 4 bytes id]                // if flags bit2 set
     * [optional 6 bytes sender]            // if flags bit0 set
     * [optional 6 bytes receiver]          // if flags bit1 set
     * [optional 1 byte signature type]     // if flags bit4 set; Type defines length of signature
     * [optional signature]                 // if flags bit4 set
     * [data container bytes...]
     *
     * Flags:
     * bit0 => has sender
     * bit1 => has receiver
     * bit2 => has id
     * bit3 => is data encrypted If so data bytes will be an encrypted container
     * bit4 => is communication value signed
     */
    /*
     * Build the canonical metadata header and data payload shared by both
     * `to_bytes` and `build_signed_payload`. Keeping a single source here
     * guarantees the serialized frame and the signed-over bytes stay in sync.
     *
     * Returns `(metadata, data_bytes)` where
     *   metadata = comm_type || flags || id? || sender? || receiver?
     *
     * `force_signed` forces the `FLAG_SIGNED` bit on regardless of whether a
     * signature is currently attached. The signed-payload path passes `true` so
     * that the bytes signed by `sign_frame` (before the signature is stored) and
     * the bytes verified by `verify_frame` (after it is stored) are identical.
     */
    fn build_metadata_and_data(
        &self,
        force_signed: bool,
    ) -> Result<(Vec<u8>, Vec<u8>), CodecError> {
        let has_sender = self.sender != 0;
        let has_receiver = self.receiver != 0;
        let has_id = self.id != 0;

        #[cfg(feature = "crypto")]
        let is_encrypted = self.data.len() == 1
            && self.data.values().any(|v| {
                matches!(
                    v,
                    DataValue::EncryptedContainer(_) | DataValue::SignedEncryptedContainer(_)
                )
            });
        #[cfg(not(feature = "crypto"))]
        let is_encrypted = false;

        #[cfg(feature = "crypto")]
        let has_frame_sig = self.frame_signature.is_some();
        #[cfg(not(feature = "crypto"))]
        let has_frame_sig = false;

        let mut flags: u8 = 0;
        if has_sender {
            flags |= FLAG_HAS_SENDER;
        }
        if has_receiver {
            flags |= FLAG_HAS_RECEIVER;
        }
        if has_id {
            flags |= FLAG_HAS_ID;
        }
        if is_encrypted {
            flags |= FLAG_ENCRYPTED;
        }
        if has_frame_sig || force_signed {
            flags |= FLAG_SIGNED;
        }

        let mut metadata = Vec::new();
        let _ = metadata.write_u16::<BigEndian>(self.comm_type.0);
        metadata.push(flags);

        if has_id {
            let _ = metadata.write_u32::<BigEndian>(self.id);
        }

        if has_sender {
            let sender_be = self.sender.to_be_bytes();
            metadata.extend_from_slice(&sender_be[2..]);
        }

        if has_receiver {
            let receiver_be = self.receiver.to_be_bytes();
            metadata.extend_from_slice(&receiver_be[2..]);
        }

        #[cfg(feature = "crypto")]
        let data_bytes = if is_encrypted {
            self.data
                .values()
                .find_map(|v| match v {
                    DataValue::EncryptedContainer(ct) => Some(ct.clone()),
                    DataValue::SignedEncryptedContainer(ct) => Some(ct.clone()),
                    _ => None,
                })
                .unwrap_or_default()
        } else {
            DataValue::container_from_map(&self.data).to_bytes()?
        };

        #[cfg(not(feature = "crypto"))]
        let data_bytes = DataValue::container_from_map(&self.data).to_bytes()?;

        Ok((metadata, data_bytes))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, CodecError> {
        let (metadata, data_bytes) = self.build_metadata_and_data(false)?;

        let mut payload = Vec::new();
        payload.extend_from_slice(&metadata);

        #[cfg(feature = "crypto")]
        if let Some((alg, sig)) = &self.frame_signature {
            // algorithm and signature are computed by sign_frame() and stored.
            // The frame bytes are built by using the pre-computed signature.
            payload.push(*alg);
            payload.extend_from_slice(sig);
        }

        payload.extend_from_slice(&data_bytes);

        let len = u32::try_from(payload.len()).map_err(|_| CodecError::TooManyEntries)?;
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame
            .write_u32::<BigEndian>(len)
            .map_err(|_| CodecError::InvalidEncoding)?;
        frame.extend_from_slice(&payload);

        Ok(frame)
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

        let flags = cursor.read_u8().map_err(|_| CodecError::InvalidEncoding)?;
        let has_sender = (flags & FLAG_HAS_SENDER) != 0;
        let has_receiver = (flags & FLAG_HAS_RECEIVER) != 0;
        let has_id = (flags & FLAG_HAS_ID) != 0;
        let is_encrypted = (flags & FLAG_ENCRYPTED) != 0;
        let is_signed = (flags & FLAG_SIGNED) != 0;

        #[cfg(not(feature = "crypto"))]
        if is_signed || is_encrypted {
            return Err(CodecError::InvalidEncoding);
        }

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

        #[cfg(feature = "crypto")]
        let frame_signature = if is_signed {
            let alg = cursor.read_u8().map_err(|_| CodecError::InvalidEncoding)?;
            let sig_len =
                SigAlgorithm::length(alg).ok_or(CodecError::InvalidEncoding)?;
            let mut sig = vec![0u8; sig_len];
            cursor
                .read_exact(&mut sig)
                .map_err(|_| CodecError::InvalidEncoding)?;
            Some((alg, sig))
        } else {
            None
        };

        let pos = cursor.position() as usize;
        if pos > frame_end {
            return Err(CodecError::InvalidEncoding);
        }

        let data_bytes = &bytes[pos..frame_end];

        #[cfg(feature = "crypto")]
        let data = if is_encrypted {
            let mut map = BTreeMap::new();
            map.insert(
                DataTypeId(0),
                DataValue::EncryptedContainer(data_bytes.to_vec()),
            );
            map
        } else {
            let data_value =
                DataValue::from_bytes(data_bytes).ok_or(CodecError::InvalidEncoding)?;
            data_value.as_map().ok_or(CodecError::InvalidEncoding)?
        };

        #[cfg(not(feature = "crypto"))]
        let data = {
            let data_value =
                DataValue::from_bytes(data_bytes).ok_or(CodecError::InvalidEncoding)?;
            data_value.as_map().ok_or(CodecError::InvalidEncoding)?
        };

        Ok(Self {
            id,
            comm_type,
            sender,
            receiver,
            data,
            type_map: None,
            #[cfg(feature = "crypto")]
            frame_signature,
        })
    }

    pub fn from_bytes_with(bytes: &[u8], tm: &TypeMap) -> Result<Self, CodecError> {
        let mut val = Self::from_bytes(bytes)?;
        val.type_map = Some(tm.clone());
        Ok(val)
    }

    /*
     * Sign the frame. Computes a signature over the canonical form:
     *   comm_type || flags || id? || sender? || receiver? || data_bytes
     *
     * After calling this, `to_bytes()` will embed the algorithm and
     * signature before the data payload.
     */
    #[cfg(feature = "crypto")]
    pub fn sign_frame(
        &mut self,
        algorithm: u8,
        signer: &impl SignatureScheme,
    ) -> Option<()> {
        let signed_payload = self.build_signed_payload().ok()?;
        let sig = signer.sign(&signed_payload).ok()?;
        self.frame_signature = Some((algorithm, sig));
        Some(())
    }

    /*
     * Verify the frame signature. Reconstructs the signed payload from
     * current state and checks it against the stored signature.
     */
    #[cfg(feature = "crypto")]
    pub fn verify_frame(&self, verifier: &impl SignatureScheme) -> Result<(), CodecError> {
        let (_algorithm, sig) = self
            .frame_signature
            .as_ref()
            .ok_or(CodecError::InvalidEncoding)?;

        let signed_payload = self.build_signed_payload()?;
        verifier
            .verify(&signed_payload, sig)
            .map_err(|_| CodecError::InvalidEncoding)
    }

    /*
     * Reconstruct the signed payload that the frame signature covers:
     *   comm_type || flags || id? || sender? || receiver? || data_bytes
     */
    #[cfg(feature = "crypto")]
    fn build_signed_payload(&self) -> Result<Vec<u8>, CodecError> {
        // Force FLAG_SIGNED on so the signed bytes match whether or not the
        // signature has been attached yet (sign_frame runs before storing it).
        let (metadata, data_bytes) = self.build_metadata_and_data(true)?;
        Ok([metadata, data_bytes].concat())
    }

    #[cfg(feature = "crypto")]
    pub fn get_frame_signature(&self) -> Option<&(u8, Vec<u8>)> {
        self.frame_signature.as_ref()
    }

    #[cfg(feature = "registry")]
    pub fn migrate(&self, target_tm: &TypeMap) -> Result<Self, CodecError> {
        let comm_name = communication_type_name(self.comm_type.0)
            .ok_or_else(|| CodecError::UnknownCommunicationType(self.comm_type.0.to_string()))?;
        let comm_variant = CommunicationType::from_name(comm_name)
            .ok_or_else(|| CodecError::UnknownCommunicationType(comm_name.to_string()))?;
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
            #[cfg(feature = "crypto")]
            frame_signature: self.frame_signature.clone(),
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
        let bytes = cv.to_bytes().expect("encode failed");
        let decoded = CommunicationValue::from_bytes(&bytes).expect("failed to deserialize");
        let bytes2 = decoded.to_bytes().expect("encode failed");
        assert_eq!(bytes, bytes2);
        decoded
    }

    #[test]
    fn test_flags_and_order_without_optional() {
        let cv = CommunicationValue::new(CommunicationType::ErrorParsing).with_id(0);
        let bytes = cv.to_bytes().expect("encode failed");

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

        let bytes = cv.to_bytes().expect("encode failed");
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

    #[cfg(feature = "crypto")]
    #[test]
    fn test_sign_verify_frame_roundtrip() {
        use mtp_crypto::{Ed25519Signer, SigAlgorithm};

        let (signer, sk, _pk) = Ed25519Signer::generate();

        let mut cv = CommunicationValue::new(CommunicationType::Ping)
            .with_id(7)
            .with_sender(1)
            .with_receiver(2)
            .add_data(DataTypeId(6), DataValue::UnsignedNumber(42));

        assert!(cv.sign_frame(SigAlgorithm::ED25519, &signer).is_some());

        // Same in-memory value verifies (FLAG_SIGNED forced on both sides).
        let verifier = Ed25519Signer::new(&sk).unwrap();
        assert!(cv.verify_frame(&verifier).is_ok());

        // Survives a wire round-trip.
        let bytes = cv.to_bytes().expect("encode failed");
        let decoded = CommunicationValue::from_bytes(&bytes).expect("decode failed");
        assert!(decoded.verify_frame(&verifier).is_ok());
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_verify_frame_wrong_key_fails() {
        use mtp_crypto::{Ed25519Signer, SigAlgorithm};

        let (signer, _, _) = Ed25519Signer::generate();
        let (_, other_sk, _) = Ed25519Signer::generate();

        let mut cv = CommunicationValue::new(CommunicationType::Ping)
            .add_data(DataTypeId(6), DataValue::UnsignedNumber(42));
        assert!(cv.sign_frame(SigAlgorithm::ED25519, &signer).is_some());

        let wrong = Ed25519Signer::new(&other_sk).unwrap();
        assert!(cv.verify_frame(&wrong).is_err());
    }
}
