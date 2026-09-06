use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("Unknown version")]
    UnknownVersion,
    #[error("Unknown communication type: {0}")]
    UnknownCommunicationType(String),
    #[error("Unknown data type: {0}")]
    UnknownDataType(String),
    #[error("Reserved communication type: {0}")]
    ReservedCommunicationType(u16),
    #[error("Invalid encoding")]
    InvalidEncoding,
    #[error("Too many entries to encode")]
    TooManyEntries,
    #[error("Missing negotiated type map")]
    MissingTypeMap,
    #[error("Type-map mismatch: expected {expected}, actual {actual}")]
    TypeMapMismatch { expected: String, actual: String },
    #[error("Crypto failed: {0}")]
    CryptoFailed(String),
    #[error("Missing required field: {0}")]
    MissingField(String),
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CommunicationError {
    #[error("Use after Closed")]
    UseAfterClosed,
    #[error("Connection closed by local shutdown")]
    ClosedLocally,
    #[error("Connection closed by peer")]
    ClosedByPeer,
    #[error("Connection terminated unexpectedly")]
    ConnectionLost,
    #[error("ParseCommunicationValue error")]
    ParseCommunicationValue,
    #[error("Encode error")]
    Encode,
    #[error("Parse Certificate error")]
    CertificateParseFailed,
    #[error("Loading Certificate error")]
    CertificateLoadFailed,
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Connecting error: {0}")]
    ConnectingError(String),
    #[error("Message too large")]
    MessageTooLarge,
    #[error("Stream Closed")]
    StreamClosed,
    #[error("Stream Error")]
    StreamError,
    #[error("Stream failed after delivery may have started")]
    DeliveryUnknown,
    #[error("Crypto Provider Install Error")]
    CryptoProviderInstallFailed,
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    #[error("Other: {0}")]
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_keep_stable_messages_and_equality() {
        assert_eq!(CodecError::InvalidEncoding.to_string(), "Invalid encoding");
        assert_eq!(
            CommunicationError::StreamClosed.to_string(),
            "Stream Closed"
        );
        assert_eq!(
            CommunicationError::StreamError,
            CommunicationError::StreamError
        );
        assert!(
            CommunicationError::AuthenticationFailed("bad key".into())
                .to_string()
                .contains("bad key")
        );
    }
}
