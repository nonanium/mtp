use thiserror::Error;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Errors returned when the system clock cannot be represented as MTP time.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TimeError {
    #[error("system clock is before the Unix epoch")]
    BeforeUnixEpoch,
    #[error("Unix epoch milliseconds exceed the u64 range")]
    OutOfRange,
}

fn duration_to_unix_time_millis(duration: Duration) -> Result<u64, TimeError> {
    u64::try_from(duration.as_millis()).map_err(|_| TimeError::OutOfRange)
}

/// Return the current Unix time in milliseconds.
///
/// MTP protocol fields that use `CreatedAt` store this value as an unsigned
/// integer. The conversion is centralized here so native writers do not
/// accidentally use seconds.
pub fn unix_time_millis() -> Result<u64, TimeError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TimeError::BeforeUnixEpoch)?;
    duration_to_unix_time_millis(duration)
}

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

/* ================================ TESTS ================================ */
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_time_millis_preserves_subsecond_precision() {
        let duration = Duration::new(1_786_449_600, 123_000_000);
        assert_eq!(
            duration_to_unix_time_millis(duration),
            Ok(1_786_449_600_123)
        );
    }

    #[test]
    fn unix_time_millis_rejects_values_outside_u64() {
        let duration = Duration::new(u64::MAX, 0);
        assert_eq!(
            duration_to_unix_time_millis(duration),
            Err(TimeError::OutOfRange)
        );
    }

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
    #[cfg(not(target_arch = "wasm32"))]
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
    #[cfg(not(target_arch = "wasm32"))]
    ConnectionError(#[from] wtransport::error::ConnectionError),

    #[error("Connecting error: {0}")]
    ConnectingError(String),

    #[error("ReadToEnd error: {0}")]
    #[cfg(not(target_arch = "wasm32"))]
    ReadToEndError(#[from] quinn::ReadToEndError),

    #[error("Write error: {0}")]
    #[cfg(not(target_arch = "wasm32"))]
    WriteError(#[from] quinn::WriteError),

    #[error("Closed error: {0}")]
    #[cfg(not(target_arch = "wasm32"))]
    ClosedError(#[from] quinn::ClosedStream),

    #[error("Message too large")]
    MessageTooLarge,

    #[error("ReadExactError: {0}")]
    #[cfg(not(target_arch = "wasm32"))]
    ReadExactError(#[from] quinn::ReadExactError),

    #[error("Stream Closed")]
    StreamClosed,

    #[error("Stream Error")]
    StreamError,

    #[error("Stream failed after delivery may have started")]
    DeliveryUnknown,

    #[error("Stream Error: {0}")]
    #[cfg(not(target_arch = "wasm32"))]
    StreamWriteError(#[from] wtransport::error::StreamWriteError),

    #[error("Read Exact Error: {0}")]
    #[cfg(not(target_arch = "wasm32"))]
    StreamReadExactError(#[from] wtransport::error::StreamReadExactError),

    #[error("Crypto Provider Install Error")]
    CryptoProviderInstallFailed,

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Other: {0}")]
    Other(String),
}

/// How the protocol layer should handle the first frame on a receive stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirstFrameDisposition {
    Message,
    Pipe(u32),
}

/// Classify a first frame without tying the decision to a WebTransport backend.
///
/// `PipeRequest` is used both as a control message and as the header of the raw
/// stream opened after that request is accepted. Only the protocol layer knows
/// which raw stream IDs are currently expected.
pub fn classify_first_frame(
    is_pipe_request: bool,
    pipe_id: Option<u32>,
    pipe_is_expected: bool,
) -> Result<FirstFrameDisposition, CommunicationError> {
    if !is_pipe_request {
        return Ok(FirstFrameDisposition::Message);
    }

    let pipe_id = pipe_id.filter(|id| *id != 0).ok_or_else(|| {
        CommunicationError::Other("PipeRequest frame must contain a non-zero id".into())
    })?;

    if pipe_is_expected {
        Ok(FirstFrameDisposition::Pipe(pipe_id))
    } else {
        Ok(FirstFrameDisposition::Message)
    }
}

// ---- manual PartialEq (quinn / wtransport types don't impl PartialEq) ----

impl PartialEq for CommunicationError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::UseAfterClosed, Self::UseAfterClosed) => true,
            (Self::ClosedLocally, Self::ClosedLocally) => true,
            (Self::ClosedByPeer, Self::ClosedByPeer) => true,
            (Self::ConnectionLost, Self::ConnectionLost) => true,
            #[cfg(not(target_arch = "wasm32"))]
            (Self::Quinn(_), Self::Quinn(_)) => true,
            (Self::ParseCommunicationValue, Self::ParseCommunicationValue) => true,
            (Self::Encode, Self::Encode) => true,
            (Self::CertificateParseFailed, Self::CertificateParseFailed) => true,
            (Self::CertificateLoadFailed, Self::CertificateLoadFailed) => true,
            (Self::ParseError(a), Self::ParseError(b)) => a == b,
            #[cfg(not(target_arch = "wasm32"))]
            (Self::ConnectionError(_), Self::ConnectionError(_)) => true,
            (Self::ConnectingError(a), Self::ConnectingError(b)) => a == b,
            #[cfg(not(target_arch = "wasm32"))]
            (Self::ReadToEndError(_), Self::ReadToEndError(_)) => true,
            #[cfg(not(target_arch = "wasm32"))]
            (Self::WriteError(_), Self::WriteError(_)) => true,
            #[cfg(not(target_arch = "wasm32"))]
            (Self::ClosedError(_), Self::ClosedError(_)) => true,
            (Self::MessageTooLarge, Self::MessageTooLarge) => true,
            #[cfg(not(target_arch = "wasm32"))]
            (Self::ReadExactError(_), Self::ReadExactError(_)) => true,
            (Self::StreamClosed, Self::StreamClosed) => true,
            (Self::StreamError, Self::StreamError) => true,
            (Self::DeliveryUnknown, Self::DeliveryUnknown) => true,
            #[cfg(not(target_arch = "wasm32"))]
            (Self::StreamWriteError(_), Self::StreamWriteError(_)) => true,
            #[cfg(not(target_arch = "wasm32"))]
            (Self::StreamReadExactError(_), Self::StreamReadExactError(_)) => true,
            (Self::CryptoProviderInstallFailed, Self::CryptoProviderInstallFailed) => true,
            (Self::AuthenticationFailed(a), Self::AuthenticationFailed(b)) => a == b,
            (Self::Other(a), Self::Other(b)) => a == b,
            _ => false,
        }
    }
}

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

/* ===================== Handshake Outcome Types ===================== */

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectionReason {
    BadVersion { supported_versions: Vec<String> },
    AuthenticationFailed { detail: String },
    RateLimited,
}

impl std::fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RejectionReason::BadVersion { supported_versions } => {
                write!(
                    f,
                    "unsupported protocol version; supported: {}",
                    supported_versions.join(", ")
                )
            }
            RejectionReason::AuthenticationFailed { detail } => {
                write!(f, "authentication failed: {detail}")
            }
            RejectionReason::RateLimited => write!(f, "rate limited"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeOutcome {
    Accepted { version: String, assigned_id: u64 },
    Rejected { reason: RejectionReason },
}

impl std::fmt::Display for HandshakeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeOutcome::Accepted {
                version,
                assigned_id,
            } => {
                write!(f, "accepted (version={version}, id={assigned_id})")
            }
            HandshakeOutcome::Rejected { reason } => write!(f, "rejected: {reason}"),
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
        let pe: PipeError =
            CommunicationError::ConnectionError(wtransport::error::ConnectionError::TimedOut)
                .into();
        assert_eq!(pe, PipeError::ConnectionClosed);
    }

    #[test]
    fn test_pipe_error_from_other() {
        let pe: PipeError = CommunicationError::StreamError.into();
        assert_eq!(pe, PipeError::IoError("Stream Error".into()));
    }
}

/* ==================== HandshakeOutcome TESTS ==================== */
#[cfg(test)]
mod handshake_outcome_tests {
    use super::*;

    #[test]
    fn test_accepted_display() {
        let outcome = HandshakeOutcome::Accepted {
            version: "1.0".into(),
            assigned_id: 42,
        };
        assert_eq!(format!("{outcome}"), "accepted (version=1.0, id=42)");
    }

    #[test]
    fn test_rejected_bad_version_display() {
        let outcome = HandshakeOutcome::Rejected {
            reason: RejectionReason::BadVersion {
                supported_versions: vec!["1.0".into(), "2.0".into()],
            },
        };
        let msg = format!("{outcome}");
        assert!(msg.contains("1.0"));
        assert!(msg.contains("2.0"));
    }

    #[test]
    fn test_rejected_auth_failed_display() {
        let outcome = HandshakeOutcome::Rejected {
            reason: RejectionReason::AuthenticationFailed {
                detail: "invalid signature".into(),
            },
        };
        assert!(format!("{outcome}").contains("invalid signature"));
    }

    #[test]
    fn test_rejected_rate_limited_display() {
        let outcome = HandshakeOutcome::Rejected {
            reason: RejectionReason::RateLimited,
        };
        assert_eq!(format!("{outcome}"), "rejected: rate limited");
    }

    #[test]
    fn test_rejection_reason_display() {
        assert!(
            format!(
                "{}",
                RejectionReason::BadVersion {
                    supported_versions: vec!["1.0".into()]
                }
            )
            .contains("1.0")
        );
        assert!(
            format!(
                "{}",
                RejectionReason::AuthenticationFailed {
                    detail: "bad".into()
                }
            )
            .contains("bad")
        );
        assert_eq!(format!("{}", RejectionReason::RateLimited), "rate limited");
    }

    #[test]
    fn test_handshake_outcome_clone_eq() {
        let a = HandshakeOutcome::Accepted {
            version: "1.0".into(),
            assigned_id: 1,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}
