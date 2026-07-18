use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{Cursor, Read};

use crate::data_value::{DataKind, DataValue};
use crate::rand_u32;
use mtp_common::CodecError;
#[cfg(all(test, feature = "registry"))]
use mtp_type_map::Version;
use mtp_type_map::{
    CommunicationType, CommunicationTypeId, DataType, DataTypeId, PROTOCOL_VERSION, TypeMap,
};

/// Largest sender or receiver identifier representable by the six-byte wire fields.
pub const MAX_WIRE_ID: u64 = (1 << 48) - 1;

#[cfg(feature = "crypto")]
use mtp_crypto::{PublicKeyBundle, SigAlgorithm, SignatureScheme};

const FLAG_HAS_SENDER: u8 = 0b0000_0001;
const FLAG_HAS_RECEIVER: u8 = 0b0000_0010;
const FLAG_HAS_ID: u8 = 0b0000_0100;
const FLAG_ENCRYPTED: u8 = 0b0000_1000;
const FLAG_SIGNED: u8 = 0b0001_0000;
const FLAG_SIGNED_ENCRYPTED: u8 = 0b0010_0000;

/// An opaque, frame-level encrypted payload.
///
/// This is separate from [`DataValue`] because encrypted frame bytes are not a
/// typed data map until they have been decrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "crypto")]
pub enum EncryptedPayload {
    Plain(Vec<u8>),
    Signed(Vec<u8>),
}

#[cfg(feature = "crypto")]
impl EncryptedPayload {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Plain(bytes) | Self::Signed(bytes) => bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunicationValue {
    id: u32,
    comm_type: CommunicationTypeId,
    sender: u64,
    receiver: u64,
    data: BTreeMap<DataTypeId, DataValue>,
    #[cfg(feature = "crypto")]
    encrypted_payload: Option<EncryptedPayload>,
    type_map: Option<TypeMap>,
    mapping_error: Option<CodecError>,
    #[cfg(feature = "crypto")]
    frame_signature: Option<(u8, Vec<u8>)>,
}

impl CommunicationValue {
    #[must_use]
    pub fn new(comm_type: CommunicationType) -> Self {
        let tm = TypeMap::new(PROTOCOL_VERSION);
        let id = comm_type.try_to_id(&tm);
        Self {
            id: rand_u32(),
            comm_type: id.unwrap_or(CommunicationTypeId(0)),
            sender: 0,
            receiver: 0,
            data: BTreeMap::new(),
            #[cfg(feature = "crypto")]
            encrypted_payload: None,
            type_map: Some(tm),
            mapping_error: id
                .is_none()
                .then(|| CodecError::UnknownCommunicationType(comm_type.name().to_string())),
            #[cfg(feature = "crypto")]
            frame_signature: None,
        }
    }

    #[cfg(feature = "registry")]
    #[must_use]
    pub fn from_comm(comm_type: CommunicationType, tm: &TypeMap) -> Self {
        let id = comm_type.try_to_id(tm);
        Self {
            id: rand_u32(),
            comm_type: id.unwrap_or(CommunicationTypeId(0)),
            sender: 0,
            receiver: 0,
            data: BTreeMap::new(),
            #[cfg(feature = "crypto")]
            encrypted_payload: None,
            type_map: Some(tm.clone()),
            mapping_error: id
                .is_none()
                .then(|| CodecError::UnknownCommunicationType(comm_type.name().to_string())),
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

    /// Returns the protocol type map attached to this frame.
    pub fn type_map(&self) -> Option<&TypeMap> {
        self.type_map.as_ref()
    }

    /// Binds the frame's numeric type identifiers to a protocol version.
    pub fn set_type_map(&mut self, tm: &TypeMap) {
        self.type_map = Some(tm.clone());
    }

    #[must_use]
    pub fn add_data(mut self, data: DataTypeId, value: DataValue) -> Self {
        #[cfg(feature = "crypto")]
        {
            self.encrypted_payload = None;
        }
        self.data.insert(data, value);
        self
    }

    #[cfg(feature = "registry")]
    #[must_use]
    pub fn add_typed(mut self, data: DataType, tm: &TypeMap, value: DataValue) -> Self {
        #[cfg(feature = "crypto")]
        {
            self.encrypted_payload = None;
        }
        if let Some(id) = data.try_to_id(tm) {
            self.data.insert(id, value);
        } else if self.mapping_error.is_none() {
            self.mapping_error = Some(CodecError::UnknownDataType(data.name().to_string()));
        }
        self
    }

    #[must_use]
    pub fn add_typed_default(mut self, data: DataType, value: DataValue) -> Self {
        #[cfg(feature = "crypto")]
        {
            self.encrypted_payload = None;
        }
        let tm = self.type_map.clone().unwrap_or_else(TypeMap::latest);
        if let Some(id) = data.try_to_id(&tm) {
            self.data.insert(id, value);
        } else if self.mapping_error.is_none() {
            self.mapping_error = Some(CodecError::UnknownDataType(data.name().to_string()));
        }
        self
    }

    pub fn get_data(&self, data_type: DataType) -> &DataValue {
        let tm_owned;
        let tm = match &self.type_map {
            Some(tm) => tm,
            None => {
                tm_owned = TypeMap::latest();
                &tm_owned
            }
        };
        match tm.data_id_enum(data_type) {
            Some(raw_id) => self
                .data
                .get(&DataTypeId(raw_id))
                .unwrap_or(&DataValue::Null),
            None => &DataValue::Null,
        }
    }

    pub fn get_data_opt(&self, data_type: DataType) -> Option<&DataValue> {
        let tm_owned;
        let tm = match &self.type_map {
            Some(tm) => tm,
            None => {
                tm_owned = TypeMap::latest();
                &tm_owned
            }
        };
        let raw_id = tm.data_id_enum(data_type)?;
        self.data.get(&DataTypeId(raw_id))
    }

    pub fn has_data(&self, data_type: DataType) -> Option<DataKind> {
        self.get_data_opt(data_type).map(|v| v.kind())
    }

    pub fn get_comm_type_enum(&self) -> Option<CommunicationType> {
        let tm_owned;
        let tm = match &self.type_map {
            Some(tm) => tm,
            None => {
                tm_owned = TypeMap::latest();
                &tm_owned
            }
        };
        tm.comm_enum_id(self.comm_type.0)
    }

    pub fn data(&self) -> &BTreeMap<DataTypeId, DataValue> {
        &self.data
    }

    /// Returns the number of cleartext data entries.
    ///
    /// An encrypted frame has no cleartext entries until
    /// [`Self::set_decrypted_container`] is called.
    pub fn data_len(&self) -> usize {
        self.data.len()
    }

    #[cfg(feature = "crypto")]
    #[must_use]
    pub fn with_encrypted_payload(mut self, payload: EncryptedPayload) -> Self {
        self.data.clear();
        self.encrypted_payload = Some(payload);
        self
    }

    #[cfg(feature = "crypto")]
    #[must_use]
    pub fn encrypted_payload(&self) -> Option<&EncryptedPayload> {
        self.encrypted_payload.as_ref()
    }

    #[cfg(feature = "crypto")]
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.encrypted_payload.is_some()
    }

    /// Replaces an opaque encrypted payload with its decrypted typed entries.
    #[cfg(feature = "crypto")]
    pub fn set_decrypted_container(
        &mut self,
        entries: impl IntoIterator<Item = (DataTypeId, DataValue)>,
    ) {
        self.data = entries.into_iter().collect();
        self.encrypted_payload = None;
    }

    /// Returns the number of logical payload items available in the frame.
    #[must_use]
    pub fn payload_len(&self) -> usize {
        #[cfg(feature = "crypto")]
        if self.encrypted_payload.is_some() {
            return 1;
        }
        self.data.len()
    }

    // ── type checks ──────────────────────────────────────────────────────────

    pub fn is_type(&self, comm_type: CommunicationType) -> bool {
        self.get_comm_type_enum() == Some(comm_type)
    }

    pub fn get_type_name(&self) -> Option<&'static str> {
        self.type_map
            .as_ref()
            .and_then(|tm| tm.communication_type_name(self.comm_type.0))
    }

    // ── mutation ─────────────────────────────────────────────────────────────

    pub fn set_data(&mut self, data_type: DataType, value: DataValue) {
        let tm = self.type_map.clone().unwrap_or_else(TypeMap::latest);
        if let Some(id) = data_type.try_to_id(&tm) {
            #[cfg(feature = "crypto")]
            {
                self.encrypted_payload = None;
            }
            self.data.insert(id, value);
        } else if self.mapping_error.is_none() {
            self.mapping_error = Some(CodecError::UnknownDataType(data_type.name().to_string()));
        }
    }

    #[must_use]
    pub fn with_data(mut self, data_type: DataType, value: DataValue) -> Self {
        self.set_data(data_type, value);
        self
    }

    pub fn remove_data(&mut self, data_type: DataType) -> Option<DataValue> {
        let tm_owned;
        let tm = match &self.type_map {
            Some(tm) => tm,
            None => {
                tm_owned = TypeMap::latest();
                &tm_owned
            }
        };
        let raw_id = tm.data_id_enum(data_type)?;
        self.data.remove(&DataTypeId(raw_id))
    }

    #[must_use]
    pub fn reply_to(&self, comm_type: CommunicationType) -> Self {
        Self::new(comm_type)
            .with_sender(self.receiver)
            .with_receiver(self.sender)
    }

    pub fn merge(&mut self, other: &CommunicationValue) {
        if self.mapping_error.is_none() {
            self.mapping_error.clone_from(&other.mapping_error);
        }
        #[cfg(feature = "crypto")]
        if !other.data.is_empty() {
            self.encrypted_payload = None;
        }
        for (id, value) in &other.data {
            self.data.insert(*id, value.clone());
        }
    }

    // ── typed iteration ──────────────────────────────────────────────────────

    pub fn iter_typed_data(&self) -> impl Iterator<Item = (Option<DataType>, &DataValue)> + '_ {
        let tm = self.type_map.clone().unwrap_or_else(TypeMap::latest);
        self.data
            .iter()
            .map(move |(id, val)| (tm.data_enum_id(id.0), val))
    }

    // ── typed field accessors ─────────────────────────────────────────────────

    pub fn get_bool(&self, data_type: DataType) -> Option<bool> {
        self.get_data_opt(data_type)?.as_bool()
    }

    pub fn get_str(&self, data_type: DataType) -> Option<&str> {
        self.get_data_opt(data_type)?.as_str()
    }

    pub fn get_u128(&self, data_type: DataType) -> Option<u128> {
        self.get_data_opt(data_type)?.as_unsigned_number()
    }

    pub fn get_i128(&self, data_type: DataType) -> Option<i128> {
        self.get_data_opt(data_type)?.as_signed_number()
    }

    pub fn get_float(&self, data_type: DataType) -> Option<f64> {
        self.get_data_opt(data_type)?.as_float()
    }

    pub fn get_bytes(&self, data_type: DataType) -> Option<&[u8]> {
        self.get_data_opt(data_type)?.as_bytes_slice()
    }

    pub fn get_array(&self, data_type: DataType) -> Option<&[DataValue]> {
        self.get_data_opt(data_type)?.as_array_slice()
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
     * bit5 => encrypted payload contains a signed container
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
        if let Some(error) = &self.mapping_error {
            return Err(error.clone());
        }
        if self.sender > MAX_WIRE_ID || self.receiver > MAX_WIRE_ID {
            return Err(CodecError::InvalidEncoding);
        }
        let has_sender = self.sender != 0;
        let has_receiver = self.receiver != 0;
        let has_id = self.id != 0;

        #[cfg(feature = "crypto")]
        let is_encrypted = self.encrypted_payload.is_some();
        #[cfg(not(feature = "crypto"))]
        let is_encrypted = false;

        #[cfg(feature = "crypto")]
        let is_signed_encrypted =
            matches!(self.encrypted_payload, Some(EncryptedPayload::Signed(_)));

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
        #[cfg(feature = "crypto")]
        if is_signed_encrypted {
            flags |= FLAG_SIGNED_ENCRYPTED;
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
        let data_bytes = match &self.encrypted_payload {
            Some(payload) => payload.as_bytes().to_vec(),
            None => DataValue::container_from_map(&self.data).to_bytes()?,
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
        let frame_end = 4usize
            .checked_add(total_len)
            .ok_or(CodecError::InvalidEncoding)?;
        if bytes.len() != frame_end {
            return Err(CodecError::InvalidEncoding);
        }

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
        let is_signed_encrypted = (flags & FLAG_SIGNED_ENCRYPTED) != 0;

        if is_signed_encrypted && !is_encrypted {
            return Err(CodecError::InvalidEncoding);
        }

        #[cfg(not(feature = "crypto"))]
        if is_signed || is_encrypted || is_signed_encrypted {
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
            let sig_len = SigAlgorithm::length(alg).ok_or(CodecError::InvalidEncoding)?;
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
        let (encrypted_payload, data) = if is_encrypted {
            let payload = if is_signed_encrypted {
                EncryptedPayload::Signed(data_bytes.to_vec())
            } else {
                EncryptedPayload::Plain(data_bytes.to_vec())
            };
            (Some(payload), BTreeMap::new())
        } else {
            let data_value =
                DataValue::from_bytes(data_bytes).ok_or(CodecError::InvalidEncoding)?;
            (
                None,
                data_value.as_map().ok_or(CodecError::InvalidEncoding)?,
            )
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
            #[cfg(feature = "crypto")]
            encrypted_payload,
            type_map: Some(TypeMap::new(PROTOCOL_VERSION)),
            mapping_error: None,
            #[cfg(feature = "crypto")]
            frame_signature,
        })
    }

    pub fn from_bytes_with(bytes: &[u8], tm: &TypeMap) -> Result<Self, CodecError> {
        let mut val = Self::from_bytes(bytes)?;
        val.set_type_map(tm);
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
    pub fn sign_frame(&mut self, algorithm: u8, signer: &impl SignatureScheme) -> Option<()> {
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

    /*
     * Verify the frame signature using a `PublicKeyBundle`. Dispatches to
     * Ed25519, ML-DSA-65, or both (DUAL) based on the stored algorithm byte.
     * Returns `false` if the frame has no signature or verification fails.
     */
    #[cfg(feature = "crypto")]
    pub fn validate_signature(&self, pk: &PublicKeyBundle) -> bool {
        let Some((alg, _)) = &self.frame_signature else {
            return false;
        };
        struct Ed25519Verifier<'a>(&'a mtp_crypto::SignaturePublicKey);
        impl SignatureScheme for Ed25519Verifier<'_> {
            fn sign(&self, _: &[u8]) -> Result<Vec<u8>, mtp_crypto::CryptoError> {
                Err(mtp_crypto::CryptoError::SigningFailed)
            }
            fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), mtp_crypto::CryptoError> {
                mtp_crypto::verify_ed25519(self.0, msg, sig)
            }
        }
        struct MlDsaVerifier<'a>(&'a mtp_crypto::SignaturePqPublicKey);
        impl SignatureScheme for MlDsaVerifier<'_> {
            fn sign(&self, _: &[u8]) -> Result<Vec<u8>, mtp_crypto::CryptoError> {
                Err(mtp_crypto::CryptoError::SigningFailed)
            }
            fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), mtp_crypto::CryptoError> {
                mtp_crypto::verify_ml_dsa(self.0, msg, sig)
            }
        }
        match *alg {
            SigAlgorithm::ED25519 => self
                .verify_frame(&Ed25519Verifier(&pk.sig_cl_public_key))
                .is_ok(),
            SigAlgorithm::ML_DSA_65 => self
                .verify_frame(&MlDsaVerifier(&pk.sig_pq_public_key))
                .is_ok(),
            SigAlgorithm::DUAL => {
                // For DUAL, verify_frame passes the full combined sig to the verifier.
                // We wrap a verifier that splits and checks both halves.
                struct DualVerifier<'a>(
                    &'a mtp_crypto::SignaturePublicKey,
                    &'a mtp_crypto::SignaturePqPublicKey,
                );
                impl SignatureScheme for DualVerifier<'_> {
                    fn sign(&self, _: &[u8]) -> Result<Vec<u8>, mtp_crypto::CryptoError> {
                        Err(mtp_crypto::CryptoError::SigningFailed)
                    }
                    fn verify(
                        &self,
                        msg: &[u8],
                        sig: &[u8],
                    ) -> Result<(), mtp_crypto::CryptoError> {
                        const ED_LEN: usize = 64;
                        if sig.len() < ED_LEN {
                            return Err(mtp_crypto::CryptoError::InvalidSignature);
                        }
                        mtp_crypto::verify_ed25519(self.0, msg, &sig[..ED_LEN])?;
                        mtp_crypto::verify_ml_dsa(self.1, msg, &sig[ED_LEN..])
                    }
                }
                self.verify_frame(&DualVerifier(&pk.sig_cl_public_key, &pk.sig_pq_public_key))
                    .is_ok()
            }
            _ => false,
        }
    }

    #[cfg(feature = "registry")]
    /// Migrates this frame to `target_tm`.
    ///
    /// Migration changes the signed wire representation, so any existing frame
    /// signature is discarded. Call [`Self::sign_frame`] after migration when
    /// the migrated frame needs to be authenticated.
    pub fn migrate(&self, target_tm: &TypeMap) -> Result<Self, CodecError> {
        if let Some(error) = &self.mapping_error {
            return Err(error.clone());
        }
        let source_tm = self.type_map.as_ref().ok_or(CodecError::InvalidEncoding)?;
        let comm_name = source_tm
            .communication_type_name(self.comm_type.0)
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
            let name = source_tm
                .data_type_name(old_id.0)
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
            #[cfg(feature = "crypto")]
            encrypted_payload: self.encrypted_payload.clone(),
            type_map: Some(target_tm.clone()),
            mapping_error: None,
            #[cfg(feature = "crypto")]
            frame_signature: None,
        })
    }
}

fn fmt_data_value(val: &DataValue, tm: &TypeMap, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match val {
        DataValue::Container(entries) => {
            write!(f, "{{")?;
            for (i, (key, value)) in entries.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                let name = tm.data_type_name(key.0).unwrap_or("?");
                write!(f, "{}: ", name)?;
                fmt_data_value(value, tm, f)?;
            }
            write!(f, "}}")
        }
        DataValue::Array(arr) => {
            write!(f, "[")?;
            for (i, value) in arr.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                fmt_data_value(value, tm, f)?;
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

        let name = self.get_comm_type_enum().map(|t| t.name()).unwrap_or("?");
        write!(f, ", {}: ", name)?;

        let tm = self.type_map.clone().unwrap_or_else(TypeMap::latest);
        write!(f, "{{")?;
        #[cfg(feature = "crypto")]
        if let Some(payload) = &self.encrypted_payload {
            match payload {
                EncryptedPayload::Plain(bytes) => write!(f, "(Encrypted, {} bytes)", bytes.len())?,
                EncryptedPayload::Signed(bytes) => {
                    write!(f, "(SignedEncrypted, {} bytes)", bytes.len())?
                }
            }
        }
        for (i, (raw_id, value)) in self.data.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            let dname = tm.data_enum_id(raw_id.0).map(|t| t.name()).unwrap_or("?");
            write!(f, "{}: ", dname)?;
            fmt_data_value(value, &tm, f)?;
        }
        write!(f, "}}")
    }
}

/* ================================ TESTS ================================ */
#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_value::DataValue;

    fn roundtrip(cv: CommunicationValue) -> Result<CommunicationValue, Box<dyn std::error::Error>> {
        let bytes = cv.to_bytes()?;
        let decoded = CommunicationValue::from_bytes(&bytes)?;
        let bytes2 = decoded.to_bytes()?;
        assert_eq!(bytes, bytes2);
        Ok(decoded)
    }

    #[test]
    fn test_flags_and_order_without_optional() -> Result<(), Box<dyn std::error::Error>> {
        let cv = CommunicationValue::new(CommunicationType::ErrorParsing).with_id(0);
        let bytes = cv.to_bytes()?;

        // [u32 len][u16 type][flags]...
        assert!(bytes.len() >= 7);
        let mut c = Cursor::new(bytes.as_slice());
        let total_len = c.read_u32::<BigEndian>()?;
        assert_eq!(total_len as usize + 4, bytes.len());

        let typ = c.read_u16::<BigEndian>()?;
        assert_eq!(typ, 12);

        let flags = c.read_u8()?;
        assert_eq!(flags & 0b0000_0111, 0);
        Ok(())
    }

    #[test]
    fn test_flags_and_order_with_all_optional() -> Result<(), Box<dyn std::error::Error>> {
        let cv = CommunicationValue::new(CommunicationType::ErrorBadVersion)
            .with_id(0xAABBCCDD)
            .with_sender(0x0000_1122_3344_5566)
            .with_receiver(0x0000_6677_8899_AABB);

        let bytes = cv.to_bytes()?;
        let mut c = Cursor::new(bytes.as_slice());

        let total_len = c.read_u32::<BigEndian>()?;
        assert_eq!(total_len as usize + 4, bytes.len());

        let typ = c.read_u16::<BigEndian>()?;
        assert_eq!(typ, 13);

        let flags = c.read_u8()?;
        assert_eq!(flags & 0b0000_0111, 0b0000_0111);

        let id = c.read_u32::<BigEndian>()?;
        assert_eq!(id, 0xAABBCCDD);

        let mut sender6 = [0u8; 6];
        c.read_exact(&mut sender6)?;
        assert_eq!(sender6, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

        let mut receiver6 = [0u8; 6];
        c.read_exact(&mut receiver6)?;
        assert_eq!(receiver6, [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
        Ok(())
    }

    #[test]
    fn test_roundtrip_complex() -> Result<(), Box<dyn std::error::Error>> {
        let tm = TypeMap::latest();
        let cv = CommunicationValue::new(CommunicationType::Disconnect)
            .with_id(1234)
            .with_sender(111)
            .with_receiver(222)
            .add_typed_default(DataType::Id, DataValue::Str("alice".to_string()))
            .add_typed_default(DataType::ClientNonce, DataValue::SignedNumber(42))
            .add_typed_default(DataType::ServerNonce, DataValue::BoolTrue)
            .add_typed_default(
                DataType::PublicKeys,
                DataValue::Array(vec![DataValue::SignedNumber(1), DataValue::SignedNumber(2)]),
            );

        let decoded = roundtrip(cv.clone())?;

        assert_eq!(decoded.get_id(), 1234);
        assert_eq!(decoded.get_sender(), 111);
        assert_eq!(decoded.get_receiver(), 222);
        assert_eq!(
            decoded.get_type(),
            CommunicationType::Disconnect
                .try_to_id(&tm)
                .expect("built-in type must be mapped")
        );
        assert_eq!(
            decoded.get_data(DataType::Id),
            &DataValue::Str("alice".to_string())
        );
        assert_eq!(
            decoded.get_data(DataType::ClientNonce),
            &DataValue::SignedNumber(42)
        );
        Ok(())
    }

    #[test]
    fn endpoint_ids_are_limited_to_wire_width() -> Result<(), Box<dyn std::error::Error>> {
        let max = CommunicationValue::new(CommunicationType::Ping)
            .with_sender(MAX_WIRE_ID)
            .with_receiver(MAX_WIRE_ID);
        let decoded = roundtrip(max)?;
        assert_eq!(decoded.get_sender(), MAX_WIRE_ID);
        assert_eq!(decoded.get_receiver(), MAX_WIRE_ID);

        assert!(
            CommunicationValue::new(CommunicationType::Ping)
                .with_sender(MAX_WIRE_ID + 1)
                .to_bytes()
                .is_err()
        );
        assert!(
            CommunicationValue::new(CommunicationType::Ping)
                .with_receiver(MAX_WIRE_ID + 1)
                .to_bytes()
                .is_err()
        );
        Ok(())
    }

    #[cfg(feature = "registry")]
    #[test]
    fn missing_version_mappings_return_codec_errors() {
        let v0 = TypeMap::new(Version(0, 0));
        assert_eq!(DataType::AnotherType.try_to_id(&v0), None);

        let data_error = CommunicationValue::from_comm(CommunicationType::Ping, &v0)
            .add_typed(
                DataType::AnotherType,
                &v0,
                DataValue::Str("not available in v0".into()),
            )
            .to_bytes();
        assert_eq!(
            data_error,
            Err(CodecError::UnknownDataType("AnotherType".into()))
        );

        let unknown_version = TypeMap::new(Version(99, 0));
        assert_eq!(CommunicationType::Ping.try_to_id(&unknown_version), None);
        assert_eq!(
            CommunicationValue::from_comm(CommunicationType::Ping, &unknown_version).to_bytes(),
            Err(CodecError::UnknownCommunicationType("Ping".into()))
        );
    }

    #[cfg(feature = "registry")]
    #[test]
    fn decoded_and_migrated_frames_use_the_source_version_map()
    -> Result<(), Box<dyn std::error::Error>> {
        let v1 = TypeMap::new(Version(1, 0));
        let v2 = TypeMap::new(Version(2, 0));
        let original = CommunicationValue::from_comm(CommunicationType::Ping, &v1).add_typed(
            DataType::SomeType,
            &v1,
            DataValue::Str("v1 value".into()),
        );
        let bytes = original.to_bytes()?;

        let decoded = CommunicationValue::from_bytes_with(&bytes, &v1)?;
        assert_eq!(decoded.get_type_name(), Some("Ping"));
        assert_eq!(
            decoded.get_data(DataType::SomeType),
            &DataValue::Str("v1 value".into())
        );
        assert_eq!(
            decoded.type_map().map(|tm| &tm.version),
            Some(&Version(1, 0))
        );

        let migrated = decoded.migrate(&v2)?;
        assert_eq!(
            migrated.get_data(DataType::SomeType).as_str(),
            Some("v1 value")
        );
        assert_eq!(
            migrated.data().get(
                &DataType::SomeType
                    .try_to_id(&v2)
                    .expect("SomeType must be mapped in v2"),
            ),
            Some(&DataValue::Str("v1 value".into()))
        );
        Ok(())
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_plain_encrypted_payload_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let ciphertext = vec![1, 2, 3, 4, 5];
        let cv = CommunicationValue::new(CommunicationType::Ping)
            .with_encrypted_payload(EncryptedPayload::Plain(ciphertext.clone()));

        let bytes = cv.to_bytes()?;
        assert_ne!(bytes[6] & FLAG_ENCRYPTED, 0);
        assert_eq!(bytes[6] & FLAG_SIGNED_ENCRYPTED, 0);

        let decoded = roundtrip(cv)?;
        assert_eq!(
            decoded.encrypted_payload(),
            Some(&EncryptedPayload::Plain(ciphertext))
        );
        assert!(decoded.data().is_empty());
        assert_eq!(decoded.data_len(), 0);
        assert_eq!(decoded.payload_len(), 1);
        assert_eq!(decoded.get_data(DataType::Version), &DataValue::Null);
        Ok(())
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_signed_encrypted_payload_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let ciphertext = vec![9, 8, 7, 6];
        let cv = CommunicationValue::new(CommunicationType::Ping)
            .with_encrypted_payload(EncryptedPayload::Signed(ciphertext.clone()));

        let bytes = cv.to_bytes()?;
        assert_ne!(bytes[6] & FLAG_ENCRYPTED, 0);
        assert_ne!(bytes[6] & FLAG_SIGNED_ENCRYPTED, 0);

        let decoded = roundtrip(cv)?;
        assert_eq!(
            decoded.encrypted_payload(),
            Some(&EncryptedPayload::Signed(ciphertext))
        );
        assert!(decoded.data().is_empty());
        Ok(())
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_decrypted_payload_serializes_as_cleartext() -> Result<(), Box<dyn std::error::Error>> {
        let tm = TypeMap::latest();
        let data_id = DataType::Version
            .try_to_id(&tm)
            .expect("built-in type must be mapped");
        let mut cv = CommunicationValue::new(CommunicationType::Ping)
            .with_encrypted_payload(EncryptedPayload::Plain(vec![1, 2, 3]));

        cv.set_decrypted_container([(data_id, DataValue::Str("clear".into()))]);

        assert!(!cv.is_encrypted());
        assert_eq!(cv.payload_len(), 1);
        assert_eq!(cv.get_data(DataType::Version).as_str(), Some("clear"));
        let bytes = cv.to_bytes()?;
        assert_eq!(bytes[6] & FLAG_ENCRYPTED, 0);
        assert_eq!(bytes[6] & FLAG_SIGNED_ENCRYPTED, 0);
        Ok(())
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_nested_encrypted_value_remains_typed_data() -> Result<(), Box<dyn std::error::Error>> {
        let cv = CommunicationValue::new(CommunicationType::Ping).add_typed_default(
            DataType::Version,
            DataValue::SignedEncryptedContainer(vec![4, 3, 2, 1]),
        );

        let bytes = cv.to_bytes()?;
        assert_eq!(bytes[6] & FLAG_ENCRYPTED, 0);
        assert_eq!(bytes[6] & FLAG_SIGNED_ENCRYPTED, 0);

        let decoded = roundtrip(cv)?;
        assert!(!decoded.is_encrypted());
        assert!(matches!(
            decoded.get_data(DataType::Version),
            DataValue::SignedEncryptedContainer(bytes) if bytes == &[4, 3, 2, 1]
        ));
        Ok(())
    }

    #[test]
    fn test_signed_encrypted_flag_requires_encrypted_flag() {
        let mut bytes = CommunicationValue::new(CommunicationType::Ping)
            .to_bytes()
            .expect("frame should encode");
        bytes[6] |= FLAG_SIGNED_ENCRYPTED;
        assert!(CommunicationValue::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_corrupted_length_returns_none() {
        let mut bad = vec![0u8; 8];
        // total_length claims more than available
        bad[0..4].copy_from_slice(&(1000u32.to_be_bytes()));
        assert!(CommunicationValue::from_bytes(&bad).is_err());
    }

    #[test]
    fn test_trailing_bytes_are_rejected() {
        let mut bytes = CommunicationValue::new(CommunicationType::Ping)
            .to_bytes()
            .expect("frame should encode");
        bytes.extend_from_slice(&[0xAA, 0xBB]);

        assert!(CommunicationValue::from_bytes(&bytes).is_err());
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_sign_verify_frame_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        use mtp_crypto::{Ed25519Signer, SigAlgorithm};

        let (signer, sk, _pk) = Ed25519Signer::generate();

        let mut cv = CommunicationValue::new(CommunicationType::Ping)
            .with_id(7)
            .with_sender(1)
            .with_receiver(2)
            .add_typed_default(DataType::PqSignature, DataValue::UnsignedNumber(42));

        assert!(cv.sign_frame(SigAlgorithm::ED25519, &signer).is_some());

        // Same in-memory value verifies (FLAG_SIGNED forced on both sides).
        let verifier = Ed25519Signer::new(&sk)?;
        assert!(cv.verify_frame(&verifier).is_ok());

        // Survives a wire round-trip.
        let bytes = cv.to_bytes()?;
        let decoded = CommunicationValue::from_bytes(&bytes)?;
        assert!(decoded.verify_frame(&verifier).is_ok());

        Ok(())
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_verify_frame_wrong_key_fails() -> Result<(), Box<dyn std::error::Error>> {
        use mtp_crypto::{Ed25519Signer, SigAlgorithm};

        let (signer, _, _) = Ed25519Signer::generate();
        let (_, other_sk, _) = Ed25519Signer::generate();

        let mut cv = CommunicationValue::new(CommunicationType::Ping)
            .add_typed_default(DataType::PqSignature, DataValue::UnsignedNumber(42));
        assert!(cv.sign_frame(SigAlgorithm::ED25519, &signer).is_some());

        let wrong = Ed25519Signer::new(&other_sk)?;
        assert!(cv.verify_frame(&wrong).is_err());

        Ok(())
    }

    #[cfg(all(feature = "crypto", feature = "registry"))]
    #[test]
    fn test_migrate_discards_frame_signature() -> Result<(), Box<dyn std::error::Error>> {
        use mtp_crypto::{Ed25519Signer, SigAlgorithm};
        use mtp_type_map::Version;

        let (signer, _, _) = Ed25519Signer::generate();
        let mut cv = CommunicationValue::new(CommunicationType::Ping)
            .add_typed_default(DataType::Version, DataValue::Str("1.0".into()));
        assert!(cv.sign_frame(SigAlgorithm::ED25519, &signer).is_some());
        assert!(cv.get_frame_signature().is_some());

        let migrated = cv.migrate(&TypeMap::new(Version(2, 0)))?;

        assert!(migrated.get_frame_signature().is_none());
        Ok(())
    }
}
