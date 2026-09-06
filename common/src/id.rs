use core::fmt;

/// Error returned when an identifier reserved as zero is constructed from zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZeroIdError {
    kind: &'static str,
}

impl ZeroIdError {
    const fn new(kind: &'static str) -> Self {
        Self { kind }
    }
}

impl fmt::Display for ZeroIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} must be non-zero", self.kind)
    }
}

impl std::error::Error for ZeroIdError {}

macro_rules! non_zero_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u32);

        impl $name {
            /// Construct an ID if `value` is valid for this domain.
            pub const fn new(value: u32) -> Option<Self> {
                if value == 0 { None } else { Some(Self(value)) }
            }

            /// Return the protocol representation of this ID.
            pub const fn get(self) -> u32 {
                self.0
            }

            /// Generate a cryptographically random valid ID.
            pub fn random() -> Self {
                loop {
                    if let Some(id) = Self::new(rand::random()) {
                        return id;
                    }
                }
            }
        }

        impl TryFrom<u32> for $name {
            type Error = ZeroIdError;

            fn try_from(value: u32) -> Result<Self, Self::Error> {
                Self::new(value).ok_or(ZeroIdError::new(stringify!($name)))
            }
        }

        impl From<$name> for u32 {
            fn from(value: $name) -> Self {
                value.get()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.get().fmt(f)
            }
        }
    };
}

non_zero_id!(
    PipeId,
    "Identifier for a pipe creation and its byte stream."
);
non_zero_id!(
    RequestId,
    "Identifier for an application request and response."
);

/// Identifier for a protected application message and replay record.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId(u128);

impl MessageId {
    /// Construct a message ID. Zero remains a valid protocol value.
    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    /// Return the protocol representation of this ID.
    pub const fn get(self) -> u128 {
        self.0
    }

    /// Generate a cryptographically random message ID.
    pub fn random() -> Self {
        Self::new(rand::random())
    }
}

impl From<u128> for MessageId {
    fn from(value: u128) -> Self {
        Self::new(value)
    }
}

impl From<MessageId> for u128 {
    fn from(value: MessageId) -> Self {
        value.get()
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(f)
    }
}

non_zero_id!(PingId, "Identifier correlating a ping with its pong.");

#[cfg(test)]
mod tests {
    use super::{MessageId, PingId, PipeId, RequestId};

    #[test]
    fn pipe_and_request_ids_reject_zero() {
        assert!(PipeId::new(0).is_none());
        assert!(RequestId::new(0).is_none());
        assert!(PipeId::try_from(0).is_err());
        assert!(RequestId::try_from(0).is_err());
    }

    #[test]
    fn ping_id_rejects_zero() {
        assert!(PingId::new(0).is_none());
        assert!(PingId::try_from(0).is_err());
        assert_eq!(PingId::new(u32::MAX).map(PingId::get), Some(u32::MAX));
    }

    #[test]
    fn message_id_preserves_full_numeric_range() {
        assert_eq!(MessageId::new(0).get(), 0);
        assert_eq!(MessageId::new(u128::MAX).get(), u128::MAX);
    }
}
