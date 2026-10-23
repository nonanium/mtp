use super::*;

impl fmt::Display for DataValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoolTrue => f.write_str("true"),
            Self::BoolFalse => f.write_str("false"),
            Self::Bool(value) => write!(f, "{value}"),
            Self::SignedNumber(value) => write!(f, "{value}"),
            Self::UnsignedNumber(value) => write!(f, "{value}"),
            Self::Float(value) => write!(f, "{value}"),
            Self::Str(value) => write!(f, "\"{value}\""),
            Self::Bytes(_) => f.write_str("(Binary)"),
            Self::Array(values) => {
                f.write_str("[")?;
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{value}")?;
                }
                f.write_str("]")
            }
            Self::Container(entries) => {
                f.write_str("{")?;
                for (index, (id, value)) in entries.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{}: {value}", id.0)?;
                }
                f.write_str("}")
            }
            #[cfg(feature = "crypto")]
            Self::Encrypted(_) => f.write_str("(Encrypted)"),
            #[cfg(feature = "crypto")]
            Self::Signed(_) => f.write_str("(Signed)"),
            Self::Null => f.write_str("null"),
        }
    }
}

impl PartialEq for DataValue {
    fn eq(&self, other: &Self) -> bool {
        use DataValue::*;
        match (self, other) {
            (BoolTrue, BoolTrue)
            | (BoolFalse, BoolFalse)
            | (BoolTrue, Bool(true))
            | (Bool(true), BoolTrue)
            | (BoolFalse, Bool(false))
            | (Bool(false), BoolFalse) => true,
            (Bool(a), Bool(b)) => a == b,
            (SignedNumber(a), SignedNumber(b)) => a == b,
            (UnsignedNumber(a), UnsignedNumber(b)) => a == b,
            (Float(a), Float(b)) => a.to_bits() == b.to_bits(),
            (Str(a), Str(b)) => a == b,
            (Bytes(a), Bytes(b)) => a == b,
            (Array(a), Array(b)) => a == b,
            (Container(a), Container(b)) => a == b,
            #[cfg(feature = "crypto")]
            (Encrypted(a), Encrypted(b)) => a == b,
            #[cfg(feature = "crypto")]
            (Signed(a), Signed(b)) => a == b,
            (Null, Null) => true,
            _ => false,
        }
    }
}

impl Eq for DataValue {}

impl Hash for DataValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Self::kind_marker(self).hash(state);
        match self {
            Self::BoolTrue | Self::BoolFalse | Self::Bool(_) | Self::Null => {}
            Self::SignedNumber(value) => value.hash(state),
            Self::UnsignedNumber(value) => value.hash(state),
            Self::Float(value) => value.to_bits().hash(state),
            Self::Str(value) => value.hash(state),
            Self::Bytes(value) => value.hash(state),
            Self::Array(value) => value.hash(state),
            Self::Container(value) => value.hash(state),
            #[cfg(feature = "crypto")]
            Self::Encrypted(value) => value.to_bytes().hash(state),
            #[cfg(feature = "crypto")]
            Self::Signed(value) => value.to_bytes().hash(state),
        }
    }
}

#[cfg(feature = "crypto")]
impl EncryptedValue {
    pub(super) fn to_bytes(&self) -> Vec<u8> {
        mtp_crypto::MultiEncryptedMessage {
            encryption_type: self.encryption_type,
            purpose: self.purpose,
            recipients: self.recipients.clone(),
            ciphertext: self.ciphertext.clone(),
        }
        .to_bytes()
        .unwrap_or_default()
    }
}

#[cfg(feature = "crypto")]
impl SignedValue {
    pub(super) fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.algorithm);
        out.push(self.purpose);
        out.extend_from_slice(&self.signer_id.to_be_bytes());
        out.extend_from_slice(&self.signature);
        let _ = self.value.write_to(&mut out);
        out
    }
}

impl fmt::Display for DataValueTypeMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "expected {}, got {}", self.expected, self.got)
    }
}

impl std::error::Error for DataValueTypeMismatch {}

impl From<bool> for DataValue {
    fn from(value: bool) -> Self {
        if value {
            Self::BoolTrue
        } else {
            Self::BoolFalse
        }
    }
}

impl From<&str> for DataValue {
    fn from(value: &str) -> Self {
        Self::Str(value.to_owned())
    }
}

impl From<String> for DataValue {
    fn from(value: String) -> Self {
        Self::Str(value)
    }
}

impl From<i64> for DataValue {
    fn from(value: i64) -> Self {
        Self::SignedNumber(value as i128)
    }
}

impl From<i128> for DataValue {
    fn from(value: i128) -> Self {
        Self::SignedNumber(value)
    }
}

impl From<u64> for DataValue {
    fn from(value: u64) -> Self {
        Self::UnsignedNumber(value as u128)
    }
}

impl From<u128> for DataValue {
    fn from(value: u128) -> Self {
        Self::UnsignedNumber(value)
    }
}

impl From<Vec<u8>> for DataValue {
    fn from(value: Vec<u8>) -> Self {
        Self::Bytes(value)
    }
}

impl From<&[u8]> for DataValue {
    fn from(value: &[u8]) -> Self {
        Self::Bytes(value.to_vec())
    }
}

impl TryFrom<DataValue> for bool {
    type Error = DataValueTypeMismatch;
    fn try_from(value: DataValue) -> Result<Self, Self::Error> {
        value.as_bool().ok_or(DataValueTypeMismatch {
            expected: "Bool",
            got: value.type_name(),
        })
    }
}

impl TryFrom<DataValue> for String {
    type Error = DataValueTypeMismatch;
    fn try_from(value: DataValue) -> Result<Self, Self::Error> {
        match value {
            DataValue::Str(value) => Ok(value),
            other => Err(DataValueTypeMismatch {
                expected: "Str",
                got: other.type_name(),
            }),
        }
    }
}

impl TryFrom<DataValue> for i128 {
    type Error = DataValueTypeMismatch;
    fn try_from(value: DataValue) -> Result<Self, Self::Error> {
        value.as_signed_number().ok_or(DataValueTypeMismatch {
            expected: "SignedNumber",
            got: value.type_name(),
        })
    }
}

impl TryFrom<DataValue> for i64 {
    type Error = DataValueTypeMismatch;
    fn try_from(value: DataValue) -> Result<Self, Self::Error> {
        let value = i128::try_from(value)?;
        i64::try_from(value).map_err(|_| DataValueTypeMismatch {
            expected: "i64",
            got: "SignedNumber",
        })
    }
}

impl TryFrom<DataValue> for u128 {
    type Error = DataValueTypeMismatch;
    fn try_from(value: DataValue) -> Result<Self, Self::Error> {
        value.as_unsigned_number().ok_or(DataValueTypeMismatch {
            expected: "UnsignedNumber",
            got: value.type_name(),
        })
    }
}

impl TryFrom<DataValue> for u64 {
    type Error = DataValueTypeMismatch;
    fn try_from(value: DataValue) -> Result<Self, Self::Error> {
        let value = u128::try_from(value)?;
        u64::try_from(value).map_err(|_| DataValueTypeMismatch {
            expected: "u64",
            got: "UnsignedNumber",
        })
    }
}

impl TryFrom<DataValue> for Vec<u8> {
    type Error = DataValueTypeMismatch;
    fn try_from(value: DataValue) -> Result<Self, Self::Error> {
        match value {
            DataValue::Bytes(value) => Ok(value),
            other => Err(DataValueTypeMismatch {
                expected: "Bytes",
                got: other.type_name(),
            }),
        }
    }
}
