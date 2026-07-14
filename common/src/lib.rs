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
    #[error("Crypto failed: {0}")]
    CryptoFailed(String),
    #[error("Missing required field: {0}")]
    MissingField(String),
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
}

/* CommunicationError
 *
 * On native targets the full variant set (including quinn / wtransport
 * wrappers) is available.  On WASM only the transport-independent subset is
 * compiled. */

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Error, Clone)]
pub enum CommunicationError {
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

    #[error("Encode error")]
    Encode,

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

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Error, Clone)]
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

    #[error("Crypto Provider Install Error")]
    CryptoProviderInstallFailed,

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Other: {0}")]
    Other(String),
}

// ---- manual PartialEq (quinn / wtransport types don't impl PartialEq) ----

#[cfg(not(target_arch = "wasm32"))]
impl PartialEq for CommunicationError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::UseAfterClosed, Self::UseAfterClosed) => true,
            (Self::ClosedLocally, Self::ClosedLocally) => true,
            (Self::ClosedByPeer, Self::ClosedByPeer) => true,
            (Self::ConnectionLost, Self::ConnectionLost) => true,
            (Self::Quinn(_), Self::Quinn(_)) => true,
            (Self::ParseCommunicationValue, Self::ParseCommunicationValue) => true,
            (Self::Encode, Self::Encode) => true,
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

#[cfg(target_arch = "wasm32")]
impl PartialEq for CommunicationError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::UseAfterClosed, Self::UseAfterClosed) => true,
            (Self::ClosedLocally, Self::ClosedLocally) => true,
            (Self::ClosedByPeer, Self::ClosedByPeer) => true,
            (Self::ConnectionLost, Self::ConnectionLost) => true,
            (Self::ParseCommunicationValue, Self::ParseCommunicationValue) => true,
            (Self::Encode, Self::Encode) => true,
            (Self::CertificateParseFailed, Self::CertificateParseFailed) => true,
            (Self::CertificateLoadFailed, Self::CertificateLoadFailed) => true,
            (Self::ParseError(a), Self::ParseError(b)) => a == b,
            (Self::ConnectingError(a), Self::ConnectingError(b)) => a == b,
            (Self::MessageTooLarge, Self::MessageTooLarge) => true,
            (Self::StreamClosed, Self::StreamClosed) => true,
            (Self::StreamError, Self::StreamError) => true,
            (Self::CryptoProviderInstallFailed, Self::CryptoProviderInstallFailed) => true,
            (Self::AuthenticationFailed(a), Self::AuthenticationFailed(b)) => a == b,
            (Self::Other(a), Self::Other(b)) => a == b,
            _ => false,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Eq for CommunicationError {}

#[cfg(target_arch = "wasm32")]
impl Eq for CommunicationError {}

/* ================================ PipeError ================================ */

#[cfg(feature = "pipes")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipeError {
    Rejected,
    HandshakeTimeout,
    StreamClosed,
    IoError(String),
    ConnectionClosed,
}

#[cfg(feature = "pipes")]
impl std::fmt::Display for PipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipeError::Rejected => write!(f, "pipe request was rejected"),
            PipeError::HandshakeTimeout => write!(f, "pipe handshake timed out"),
            PipeError::StreamClosed => write!(f, "pipe stream closed unexpectedly"),
            PipeError::IoError(s) => write!(f, "pipe I/O error: {s}"),
            PipeError::ConnectionClosed => write!(f, "connection closed"),
        }
    }
}

#[cfg(feature = "pipes")]
impl std::error::Error for PipeError {}

#[cfg(feature = "pipes")]
impl From<CommunicationError> for PipeError {
    fn from(e: CommunicationError) -> Self {
        match e {
            CommunicationError::StreamClosed => PipeError::StreamClosed,
            CommunicationError::ConnectionError(_) => PipeError::ConnectionClosed,
            other => PipeError::IoError(other.to_string()),
        }
    }
}

/* ================================ TESTS ================================ */
#[cfg(test)]
mod communication_error_tests {
    use super::*;

    #[test]
    fn test_communication_error_display() {
        assert_eq!(
            format!("{}", CommunicationError::UseAfterClosed),
            "Use after Closed"
        );
        assert_eq!(
            format!("{}", CommunicationError::StreamClosed),
            "Stream Closed"
        );
        assert_eq!(
            format!("{}", CommunicationError::StreamError),
            "Stream Error"
        );
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

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_connecting_error_display() {
        let e = CommunicationError::ConnectingError("refused".into());
        assert!(format!("{}", e).contains("refused"));
    }
}

/* ================================ PipeError TESTS ================================ */
#[cfg(feature = "pipes")]
#[cfg(test)]
mod pipe_error_tests {
    use super::*;

    #[test]
    fn test_pipe_error_display() {
        assert_eq!(
            format!("{}", PipeError::Rejected),
            "pipe request was rejected"
        );
        assert_eq!(
            format!("{}", PipeError::HandshakeTimeout),
            "pipe handshake timed out"
        );
        assert_eq!(
            format!("{}", PipeError::StreamClosed),
            "pipe stream closed unexpectedly"
        );
        assert_eq!(
            format!("{}", PipeError::ConnectionClosed),
            "connection closed"
        );
        assert_eq!(
            format!("{}", PipeError::IoError("boom".into())),
            "pipe I/O error: boom"
        );
    }

    #[test]
    fn test_pipe_error_from_stream_closed() {
        let pe: PipeError = CommunicationError::StreamClosed.into();
        assert_eq!(pe, PipeError::StreamClosed);
    }

    #[test]
    fn test_pipe_error_from_connection_error() {
        let pe: PipeError = CommunicationError::ConnectionError(
            wtransport::error::ConnectionError::TimedOut,
        )
        .into();
        assert_eq!(pe, PipeError::ConnectionClosed);
    }

    #[test]
    fn test_pipe_error_from_other() {
        let pe: PipeError = CommunicationError::StreamError.into();
        assert_eq!(pe, PipeError::IoError("Stream Error".into()));
    }
}
