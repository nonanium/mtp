use super::*;

impl CommunicationValue {
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

    pub(super) fn frame_header_len(&self) -> usize {
        4 + 2
            + 1
            + self.id.is_some() as usize * 4
            + self.sender.is_some() as usize * 8
            + self.receiver.is_some() as usize * 8
    }

    pub(super) fn payload_encode_limits(
        &self,
        limits: EncodeLimits,
    ) -> Result<EncodeLimits, CodecError> {
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
}
