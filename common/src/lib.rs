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
    #[error("Crypto failed: {0}")]
    CryptoFailed(String),
}

/* ================================ TESTS ================================ */
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codec_error_display() {
        let e = CodecError::InvalidEncoding;
        assert_eq!(format!("{}", e), "Invalid encoding");
    }

    #[test]
    fn test_codec_error_unknown_version() {
        assert_eq!(format!("{}", CodecError::UnknownVersion), "Unknown version");
    }

    #[test]
    fn test_codec_error_clone_eq() {
        let a = CodecError::InvalidEncoding;
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_communication_error_display() {
        assert_eq!(format!("{}", CommunicationError::UseAfterClosed), "Use after Closed");
        assert_eq!(format!("{}", CommunicationError::StreamClosed), "Stream Closed");
        assert_eq!(format!("{}", CommunicationError::StreamError), "Stream Error");
    }

    #[test]
    fn test_communication_error_clone() {
        let a = CommunicationError::UseAfterClosed;
        let b = a.clone();
        assert_eq!(format!("{:?}", a), format!("{:?}", b));
    }

    #[test]
    fn test_communication_error_authentication_failed() {
        let e = CommunicationError::AuthenticationFailed("bad key".into());
        assert!(format!("{}", e).contains("bad key"));
    }

    #[test]
    fn test_communication_error_other() {
        let e = CommunicationError::Other("custom error".into());
        assert!(format!("{}", e).contains("custom error"));
    }
}

#[derive(Debug, Error, Clone)]
pub enum CommunicationError {
    /* ====== NOTE on PartialEq ======
     * Manual PartialEq implementation below compares some inner
     * values (String, Vec<u8>) structurally and others only by
     * variant discriminant (types from quinn / wtransport that
     * don't themselves implement PartialEq).  Keep this impl in
     * sync if variants are added or changed.
     */
    #[error("Use after Closed")]
    UseAfterClosed,

    #[error("Connection closed by local shutdown")]
    ClosedLocally,

    #[error("Connection closed by peer")]
    ClosedByPeer,

    #[error("Connection terminated unexpectedly")]
    ConnectionLost,

    #[error("QUIC error: {0}")]
    Quinn(#[from] quinn::ConnectionError),

    #[error("ParseCommunicationValue error")]
    ParseCommunicationValue,

    #[error("Parse Certificate error")]
    CertificateParseFailed,

    #[error("Loading Certificate error")]
    CertificateLoadFailed,

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Connection error: {0}")]
    ConnectionError(#[from] wtransport::error::ConnectionError),

    #[error("Connecting error: {0}")]
    ConnectingError(String),

    #[error("ReadToEnd error: {0}")]
    ReadToEndError(#[from] quinn::ReadToEndError),

    #[error("Write error: {0}")]
    WriteError(#[from] quinn::WriteError),

    #[error("Closed error: {0}")]
    ClosedError(#[from] quinn::ClosedStream),

    #[error("Message too large")]
    MessageTooLarge,

    #[error("ReadExactError: {0}")]
    ReadExactError(#[from] quinn::ReadExactError),

    #[error("Stream Closed")]
    StreamClosed,

    #[error("Stream Error")]
    StreamError,

    #[error("Stream Error: {0}")]
    StreamWriteError(#[from] wtransport::error::StreamWriteError),

    #[error("Read Exact Error: {0}")]
    StreamReadExactError(#[from] wtransport::error::StreamReadExactError),

    #[error("Crypto Provider Install Error")]
    CryptoProviderInstallFailed,

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Other: {0}")]
    Other(String),
}

/* ===== Manual PartialEq =====
 *
 * Compare by variant, and structurally for String-holding variants.
 * Third-party error types (quinn, wtransport) are compared only by
 * discriminant since they don't implement PartialEq themselves.
 */
impl PartialEq for CommunicationError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::UseAfterClosed, Self::UseAfterClosed) => true,
            (Self::ClosedLocally, Self::ClosedLocally) => true,
            (Self::ClosedByPeer, Self::ClosedByPeer) => true,
            (Self::ConnectionLost, Self::ConnectionLost) => true,
            (Self::Quinn(_), Self::Quinn(_)) => true,
            (Self::ParseCommunicationValue, Self::ParseCommunicationValue) => true,
            (Self::CertificateParseFailed, Self::CertificateParseFailed) => true,
            (Self::CertificateLoadFailed, Self::CertificateLoadFailed) => true,
            (Self::ParseError(a), Self::ParseError(b)) => a == b,
            (Self::ConnectionError(_), Self::ConnectionError(_)) => true,
            (Self::ConnectingError(a), Self::ConnectingError(b)) => a == b,
            (Self::ReadToEndError(_), Self::ReadToEndError(_)) => true,
            (Self::WriteError(_), Self::WriteError(_)) => true,
            (Self::ClosedError(_), Self::ClosedError(_)) => true,
            (Self::MessageTooLarge, Self::MessageTooLarge) => true,
            (Self::ReadExactError(_), Self::ReadExactError(_)) => true,
            (Self::StreamClosed, Self::StreamClosed) => true,
            (Self::StreamError, Self::StreamError) => true,
            (Self::StreamWriteError(_), Self::StreamWriteError(_)) => true,
            (Self::StreamReadExactError(_), Self::StreamReadExactError(_)) => true,
            (Self::CryptoProviderInstallFailed, Self::CryptoProviderInstallFailed) => true,
            (Self::AuthenticationFailed(a), Self::AuthenticationFailed(b)) => a == b,
            (Self::Other(a), Self::Other(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for CommunicationError {}
