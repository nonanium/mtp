use super::*;

impl DecodeContext {
    pub(super) fn new(limits: DecodeLimits) -> Self {
        Self {
            limits,
            depth: 0,
            values: 0,
            allocated_bytes: 0,
        }
    }

    pub(super) fn allocate(&mut self, bytes: usize) -> Result<(), DecodeFailure> {
        self.allocated_bytes = self
            .allocated_bytes
            .checked_add(bytes)
            .ok_or(DecodeFailure::AllocationLimit)?;
        if self.allocated_bytes > self.limits.max_allocated_bytes {
            return Err(DecodeFailure::AllocationLimit);
        }
        Ok(())
    }

    pub(super) fn value(&mut self) -> Result<(), DecodeFailure> {
        self.values = self
            .values
            .checked_add(1)
            .ok_or(DecodeFailure::ValueCountLimit)?;
        (self.values <= self.limits.max_values)
            .then_some(())
            .ok_or(DecodeFailure::ValueCountLimit)
    }

    pub(super) fn enter(&mut self) -> Result<(), DecodeFailure> {
        self.depth = self.depth.checked_add(1).ok_or(DecodeFailure::DepthLimit)?;
        (self.depth <= self.limits.max_depth)
            .then_some(())
            .ok_or(DecodeFailure::DepthLimit)
    }

    pub(super) fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }
}

impl EncodeContext {
    pub(super) fn new(limits: EncodeLimits) -> Self {
        Self {
            limits,
            depth: 0,
            values: 0,
        }
    }

    pub(super) fn value(&mut self) -> Result<(), CodecError> {
        self.values = self
            .values
            .checked_add(1)
            .ok_or(CodecError::TooManyEntries)?;
        if self.values > self.limits.max_values {
            return Err(CodecError::TooManyEntries);
        }
        Ok(())
    }

    pub(super) fn enter(&mut self) -> Result<(), CodecError> {
        self.depth = self
            .depth
            .checked_add(1)
            .ok_or(CodecError::TooManyEntries)?;
        if self.depth > self.limits.max_depth {
            return Err(CodecError::TooManyEntries);
        }
        Ok(())
    }

    pub(super) fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    pub(super) fn check_output(&self, current: usize, additional: usize) -> Result<(), CodecError> {
        let next = current
            .checked_add(additional)
            .ok_or(CodecError::TooManyEntries)?;
        if next > self.limits.max_output_size {
            return Err(CodecError::TooManyEntries);
        }
        Ok(())
    }
}

impl DataValue {
    /// Encode with the compatibility resource policy.
    ///
    /// New protocol boundaries should pass an explicit [`EncodeLimits`] value
    /// derived from their admission policy.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CodecError> {
        self.to_bytes_with_limits(EncodeLimits::default())
    }

    pub fn to_bytes_with_limits(&self, limits: EncodeLimits) -> Result<Vec<u8>, CodecError> {
        let mut out = Vec::new();
        self.write_to_with_limits(&mut out, limits)?;
        Ok(out)
    }

    /// Encode into an existing output buffer while enforcing depth, node, and
    /// serialized-size limits before recursive output is produced.
    pub fn write_to(&self, out: &mut Vec<u8>) -> Result<(), CodecError> {
        self.write_to_with_limits(out, EncodeLimits::default())
    }

    pub fn write_to_with_limits(
        &self,
        out: &mut Vec<u8>,
        limits: EncodeLimits,
    ) -> Result<(), CodecError> {
        let mut sizing = EncodeContext::new(limits);
        let size = self.encoded_len_with_context(&mut sizing)?;
        sizing.check_output(out.len(), size)?;

        let mut context = EncodeContext::new(limits);
        self.write_to_with_context(out, &mut context)
    }

    pub(super) fn encoded_len_with_context(
        &self,
        context: &mut EncodeContext,
    ) -> Result<usize, CodecError> {
        context.value()?;
        let size = match self {
            Self::BoolTrue | Self::BoolFalse | Self::Bool(_) | Self::Null => 1,
            Self::SignedNumber(_) | Self::UnsignedNumber(_) => 1 + 16,
            Self::Float(_) => 1 + 8,
            Self::Str(value) => checked_add(1, blob_len(value.as_bytes())?)?,
            Self::Bytes(value) => checked_add(1, blob_len(value)?)?,
            Self::Array(values) => {
                context.enter()?;
                let _ = checked_count(values.len())?;
                let mut size = 1 + 2;
                for value in values {
                    size = checked_add(size, value.encoded_len_with_context(context)?)?;
                }
                context.leave();
                size
            }
            Self::Container(entries) => encoded_container_len_after_value(entries, context)?,
            #[cfg(feature = "crypto")]
            Self::Signed(value) => {
                context.enter()?;
                let signature_len =
                    SigAlgorithm::length(value.algorithm).ok_or(CodecError::InvalidEncoding)?;
                if value.signature.len() != signature_len {
                    return Err(CodecError::InvalidEncoding);
                }
                let inner_len = value.value.encoded_len_with_context(context)?;
                context.leave();
                let wrapper_len = checked_add(1 + 1 + 8 + signature_len, inner_len)?;
                checked_add(1, checked_add(4, wrapper_len)?)?
            }
            #[cfg(feature = "crypto")]
            Self::Encrypted(value) => {
                let envelope_len = encrypted_envelope_len(value)?;
                checked_add(1, checked_add(4, envelope_len)?)?
            }
        };
        Ok(size)
    }

    pub(super) fn write_to_with_context(
        &self,
        out: &mut Vec<u8>,
        context: &mut EncodeContext,
    ) -> Result<(), CodecError> {
        context.value()?;
        append_bytes(out, context, &[Self::kind_marker(self)])?;
        match self {
            Self::BoolTrue | Self::BoolFalse | Self::Bool(_) | Self::Null => {}
            Self::SignedNumber(value) => append_bytes(out, context, &value.to_be_bytes())?,
            Self::UnsignedNumber(value) => append_bytes(out, context, &value.to_be_bytes())?,
            Self::Float(value) => append_bytes(out, context, &value.to_bits().to_be_bytes())?,
            Self::Str(value) => write_blob_with_context(out, context, value.as_bytes())?,
            Self::Bytes(value) => write_blob_with_context(out, context, value)?,
            Self::Array(values) => {
                context.enter()?;
                append_bytes(out, context, &checked_count(values.len())?.to_be_bytes())?;
                for value in values {
                    value.write_to_with_context(out, context)?;
                }
                context.leave();
            }
            Self::Container(entries) => {
                ensure_unique_container_fields(entries)?;
                context.enter()?;
                append_bytes(out, context, &checked_count(entries.len())?.to_be_bytes())?;
                for (id, value) in entries {
                    append_bytes(out, context, &id.0.to_be_bytes())?;
                    value.write_to_with_context(out, context)?;
                }
                context.leave();
            }
            #[cfg(feature = "crypto")]
            Self::Signed(value) => {
                context.enter()?;
                let signature_len =
                    SigAlgorithm::length(value.algorithm).ok_or(CodecError::InvalidEncoding)?;
                if value.signature.len() != signature_len {
                    return Err(CodecError::InvalidEncoding);
                }
                let inner_len = value
                    .value
                    .encoded_len_with_context(&mut EncodeContext::new(context.limits))?;
                let wrapper_len = checked_add(1 + 1 + 8 + signature_len, inner_len)?;
                let wrapper_len =
                    u32::try_from(wrapper_len).map_err(|_| CodecError::InvalidEncoding)?;
                append_bytes(out, context, &wrapper_len.to_be_bytes())?;
                append_bytes(out, context, &[value.algorithm, value.purpose])?;
                append_bytes(out, context, &value.signer_id.to_be_bytes())?;
                append_bytes(out, context, &value.signature)?;
                value.value.write_to_with_context(out, context)?;
                context.leave();
            }
            #[cfg(feature = "crypto")]
            Self::Encrypted(value) => write_encrypted_with_context(out, context, value)?,
        }
        Ok(())
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Self::from_bytes_with_limits(bytes, DecodeLimits::default())
    }

    pub fn from_bytes_with_limits(bytes: &[u8], limits: DecodeLimits) -> Option<Self> {
        Self::try_from_bytes_with_limits(bytes, limits).ok()
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::try_from_bytes_with_limits(bytes, DecodeLimits::default())
    }

    pub fn try_from_bytes_with_limits(
        bytes: &[u8],
        limits: DecodeLimits,
    ) -> Result<Self, DecodeError> {
        let mut cursor = Cursor::new(bytes);
        let value = Self::read_from_with_diagnostics(&mut cursor, limits)?;
        if cursor.position() as usize != bytes.len() {
            return Err(DecodeError::MalformedEncoding);
        }
        Ok(value)
    }

    pub fn read_from(cursor: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Self::read_from_with_limits(cursor, DecodeLimits::default())
    }

    pub fn read_from_with_limits(
        cursor: &mut Cursor<&[u8]>,
        limits: DecodeLimits,
    ) -> Result<Self, CodecError> {
        Self::read_from_with_diagnostics(cursor, limits).map_err(|_| CodecError::InvalidEncoding)
    }

    pub fn read_from_with_diagnostics(
        cursor: &mut Cursor<&[u8]>,
        limits: DecodeLimits,
    ) -> Result<Self, DecodeError> {
        let mut context = DecodeContext::new(limits);
        Self::read_value(cursor, &mut context)
    }

    pub fn to_base64(&self) -> Result<String, CodecError> {
        Ok(general_purpose::STANDARD.encode(self.to_bytes()?))
    }

    pub fn from_base64(value: &str) -> Option<Self> {
        general_purpose::STANDARD
            .decode(value)
            .ok()
            .and_then(|bytes| Self::from_bytes(&bytes))
    }

    pub(super) fn kind_marker(value: &Self) -> u8 {
        match value {
            Self::BoolTrue => Self::KIND_BOOL_TRUE,
            Self::BoolFalse => Self::KIND_BOOL_FALSE,
            Self::Bool(value) => {
                if *value {
                    Self::KIND_BOOL_TRUE
                } else {
                    Self::KIND_BOOL_FALSE
                }
            }
            Self::SignedNumber(_) => Self::KIND_SIGNED_NUMBER,
            Self::UnsignedNumber(_) => Self::KIND_UNSIGNED_NUMBER,
            Self::Float(_) => Self::KIND_FLOAT,
            Self::Str(_) => Self::KIND_STR,
            Self::Bytes(_) => Self::KIND_BYTES,
            Self::Array(_) => Self::KIND_ARRAY,
            Self::Container(_) => Self::KIND_CONTAINER,
            #[cfg(feature = "crypto")]
            Self::Encrypted(_) => Self::KIND_ENCRYPTED,
            #[cfg(feature = "crypto")]
            Self::Signed(_) => Self::KIND_SIGNED,
            Self::Null => Self::KIND_NULL,
        }
    }

    pub(super) fn read_value(
        cursor: &mut Cursor<&[u8]>,
        context: &mut DecodeContext,
    ) -> Result<Self, DecodeFailure> {
        context.value()?;
        match cursor
            .read_u8()
            .map_err(|_| DecodeFailure::MalformedEncoding)?
        {
            Self::KIND_BOOL_TRUE => Ok(Self::BoolTrue),
            Self::KIND_BOOL_FALSE => Ok(Self::BoolFalse),
            Self::KIND_SIGNED_NUMBER => Ok(Self::SignedNumber(
                cursor
                    .read_i128::<BigEndian>()
                    .map_err(|_| DecodeFailure::MalformedEncoding)?,
            )),
            Self::KIND_UNSIGNED_NUMBER => Ok(Self::UnsignedNumber(
                cursor
                    .read_u128::<BigEndian>()
                    .map_err(|_| DecodeFailure::MalformedEncoding)?,
            )),
            Self::KIND_FLOAT => Ok(Self::Float(
                cursor
                    .read_f64::<BigEndian>()
                    .map_err(|_| DecodeFailure::MalformedEncoding)?,
            )),
            Self::KIND_STR => {
                let bytes = read_blob_owned(cursor, context)?;
                Ok(Self::Str(
                    String::from_utf8(bytes).map_err(|_| DecodeFailure::MalformedEncoding)?,
                ))
            }
            Self::KIND_BYTES => Ok(Self::Bytes(read_blob_owned(cursor, context)?)),
            Self::KIND_ARRAY => {
                context.enter()?;
                let count = cursor
                    .read_u16::<BigEndian>()
                    .map_err(|_| DecodeFailure::MalformedEncoding)?
                    as usize;
                context.allocate(
                    count
                        .checked_mul(size_of::<DataValue>())
                        .ok_or(DecodeFailure::AllocationLimit)?,
                )?;
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    values.push(Self::read_value(cursor, context)?);
                }
                context.leave();
                Ok(Self::Array(values))
            }
            Self::KIND_CONTAINER => {
                context.enter()?;
                let count = cursor
                    .read_u16::<BigEndian>()
                    .map_err(|_| DecodeFailure::MalformedEncoding)?
                    as usize;
                context.allocate(
                    count
                        .checked_mul(size_of::<(DataTypeId, DataValue)>())
                        .ok_or(DecodeFailure::AllocationLimit)?,
                )?;
                let mut values = Vec::with_capacity(count);
                /* DataTypeId is a u16, so a fixed bitset gives duplicate
                detection a predictable allocation instead of hidden
                per-node BTreeSet allocations. */
                let seen_words = (usize::from(u16::MAX) + 1) / 64;
                context.allocate(
                    seen_words
                        .checked_mul(size_of::<u64>())
                        .ok_or(DecodeFailure::AllocationLimit)?,
                )?;
                let mut seen = vec![0_u64; seen_words];
                for _ in 0..count {
                    let id = DataTypeId(
                        cursor
                            .read_u16::<BigEndian>()
                            .map_err(|_| DecodeFailure::MalformedEncoding)?,
                    );
                    let index = usize::from(id.0);
                    let word = index / 64;
                    let bit = 1_u64 << (index % 64);
                    if seen[word] & bit != 0 {
                        return Err(DecodeFailure::DuplicateField);
                    }
                    seen[word] |= bit;
                    values.push((id, Self::read_value(cursor, context)?));
                }
                context.leave();
                Ok(Self::Container(values))
            }
            #[cfg(feature = "crypto")]
            Self::KIND_SIGNED => {
                context.enter()?;
                let wrapper = read_blob_slice(cursor, context.limits.max_blob_size)?;
                let mut inner = Cursor::new(wrapper);
                let algorithm = inner
                    .read_u8()
                    .map_err(|_| DecodeFailure::MalformedEncoding)?;
                let purpose = inner
                    .read_u8()
                    .map_err(|_| DecodeFailure::MalformedEncoding)?;
                let signer_id = inner
                    .read_u64::<BigEndian>()
                    .map_err(|_| DecodeFailure::MalformedEncoding)?;
                let signature_len =
                    SigAlgorithm::length(algorithm).ok_or(DecodeFailure::MalformedEncoding)?;
                context.allocate(signature_len)?;
                let signature = read_slice(&mut inner, signature_len)
                    .ok_or(DecodeFailure::MalformedEncoding)?
                    .to_vec();
                let value = Self::read_value(&mut inner, context)?;
                if inner.position() as usize != wrapper.len() {
                    return Err(DecodeFailure::MalformedEncoding);
                }
                context.allocate(size_of::<DataValue>())?;
                context.leave();
                Ok(Self::Signed(SignedValue {
                    algorithm,
                    purpose,
                    signer_id,
                    signature,
                    value: Box::new(value),
                }))
            }
            #[cfg(feature = "crypto")]
            Self::KIND_ENCRYPTED => {
                let envelope = read_blob_slice(cursor, context.limits.max_blob_size)?;
                let message = mtp_crypto::MultiEncryptedMessageRef::from_bytes(envelope)
                    .map_err(|_| DecodeFailure::MalformedEncoding)?;
                if message.recipient_count() > context.limits.max_recipients {
                    return Err(DecodeFailure::RecipientLimit);
                }
                let kem_len = message.encryption_type().kem_ciphertext_len();
                let wrapped_len = message.encryption_type().wrapped_key_len();
                let entry_size = size_of::<mtp_crypto::RecipientEntry>()
                    .checked_add(kem_len)
                    .and_then(|size| size.checked_add(wrapped_len))
                    .ok_or(DecodeFailure::AllocationLimit)?;
                let owned_size = message
                    .recipient_count()
                    .checked_mul(entry_size)
                    .and_then(|size| size.checked_add(message.ciphertext().len()))
                    .ok_or(DecodeFailure::AllocationLimit)?;
                context.allocate(owned_size)?;
                let mut recipients = Vec::with_capacity(message.recipient_count());
                for index in 0..message.recipient_count() {
                    let (kem_ciphertext, encrypted_key) = message
                        .recipient(index)
                        .ok_or(DecodeFailure::MalformedEncoding)?;
                    recipients.push(mtp_crypto::RecipientEntry {
                        kem_ciphertext: kem_ciphertext.to_vec(),
                        encrypted_key: encrypted_key.to_vec(),
                    });
                }
                Ok(Self::Encrypted(EncryptedValue {
                    encryption_type: message.encryption_type(),
                    purpose: message.purpose(),
                    recipients,
                    ciphertext: message.ciphertext().to_vec(),
                }))
            }
            Self::KIND_NULL => Ok(Self::Null),
            // 0x0C was the old SignedEncryptedContainer kind and is reserved.
            _ => Err(DecodeFailure::MalformedEncoding),
        }
    }
}

pub(super) fn checked_count(count: usize) -> Result<u16, CodecError> {
    u16::try_from(count).map_err(|_| CodecError::TooManyEntries)
}

pub(super) fn checked_add(left: usize, right: usize) -> Result<usize, CodecError> {
    left.checked_add(right).ok_or(CodecError::TooManyEntries)
}

pub(super) fn blob_len(bytes: &[u8]) -> Result<usize, CodecError> {
    let _ = u32::try_from(bytes.len()).map_err(|_| CodecError::InvalidEncoding)?;
    checked_add(4, bytes.len())
}

pub(super) fn append_bytes(
    out: &mut Vec<u8>,
    context: &EncodeContext,
    bytes: &[u8],
) -> Result<(), CodecError> {
    context.check_output(out.len(), bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}

pub(super) fn write_blob_with_context(
    out: &mut Vec<u8>,
    context: &EncodeContext,
    bytes: &[u8],
) -> Result<(), CodecError> {
    let len = u32::try_from(bytes.len()).map_err(|_| CodecError::InvalidEncoding)?;
    append_bytes(out, context, &len.to_be_bytes())?;
    append_bytes(out, context, bytes)
}

#[cfg(feature = "crypto")]
pub(super) fn encrypted_envelope_len(value: &EncryptedValue) -> Result<usize, CodecError> {
    let kem_len = value.encryption_type.kem_ciphertext_len();
    let wrapped_len = value.encryption_type.wrapped_key_len();
    if value.recipients.is_empty()
        || value.recipients.len() > mtp_crypto::MAX_RECIPIENTS
        || value.ciphertext.len() < value.encryption_type.minimum_ciphertext_len()
        || value.recipients.iter().any(|recipient| {
            recipient.kem_ciphertext.len() != kem_len
                || recipient.encrypted_key.len() != wrapped_len
        })
    {
        return Err(CodecError::InvalidEncoding);
    }
    let _ = checked_count(value.recipients.len())?;
    let entry_len = kem_len
        .checked_add(wrapped_len)
        .ok_or(CodecError::TooManyEntries)?;
    let entries_len = value
        .recipients
        .len()
        .checked_mul(entry_len)
        .ok_or(CodecError::TooManyEntries)?;
    checked_add(4, checked_add(entries_len, value.ciphertext.len())?)
}

#[cfg(feature = "crypto")]
pub(super) fn write_encrypted_with_context(
    out: &mut Vec<u8>,
    context: &EncodeContext,
    value: &EncryptedValue,
) -> Result<(), CodecError> {
    let envelope_len = encrypted_envelope_len(value)?;
    let envelope_len = u32::try_from(envelope_len).map_err(|_| CodecError::InvalidEncoding)?;
    append_bytes(out, context, &envelope_len.to_be_bytes())?;
    append_bytes(
        out,
        context,
        &[value.encryption_type.to_byte(), value.purpose],
    )?;
    let count = checked_count(value.recipients.len())?;
    append_bytes(out, context, &count.to_be_bytes())?;
    for recipient in &value.recipients {
        append_bytes(out, context, &recipient.kem_ciphertext)?;
        append_bytes(out, context, &recipient.encrypted_key)?;
    }
    append_bytes(out, context, &value.ciphertext)
}

pub(super) fn read_blob_slice<'a>(
    cursor: &mut Cursor<&'a [u8]>,
    max_size: usize,
) -> Result<&'a [u8], DecodeFailure> {
    let len = cursor
        .read_u32::<BigEndian>()
        .map_err(|_| DecodeFailure::MalformedEncoding)? as usize;
    if len > max_size {
        return Err(DecodeFailure::BlobLimit);
    }
    read_slice(cursor, len).ok_or(DecodeFailure::MalformedEncoding)
}

pub(super) fn read_blob_owned(
    cursor: &mut Cursor<&[u8]>,
    context: &mut DecodeContext,
) -> Result<Vec<u8>, DecodeFailure> {
    let bytes = read_blob_slice(cursor, context.limits.max_blob_size)?;
    context.allocate(bytes.len())?;
    Ok(bytes.to_vec())
}

pub(super) fn read_slice<'a>(cursor: &mut Cursor<&'a [u8]>, len: usize) -> Option<&'a [u8]> {
    let start = cursor.position() as usize;
    let end = start.checked_add(len)?;
    if end > cursor.get_ref().len() {
        return None;
    }
    cursor.set_position(end as u64);
    Some(&cursor.get_ref()[start..end])
}
