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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransportPhase {
    Connect,
    Handshake,
    OpenStream,
    WriteFrame,
    FinishStream,
    ReadFrame,
    WaitResponse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommunicationErrorCode {
    Timeout,
    DeliveryUnknown,
    PeerClosed,
    LocalClosed,
    ConnectionLost,
    ProtocolViolation,
    AuthenticationFailed,
    MessageTooLarge,
    Certificate,
    Transport,
}

impl CommunicationErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::DeliveryUnknown => "delivery-unknown",
            Self::PeerClosed => "peer-closed",
            Self::LocalClosed => "local-closed",
            Self::ConnectionLost => "connection-lost",
            Self::ProtocolViolation => "protocol-violation",
            Self::AuthenticationFailed => "authentication-failed",
            Self::MessageTooLarge => "message-too-large",
            Self::Certificate => "certificate",
            Self::Transport => "transport",
        }
    }
}

impl TransportPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Handshake => "handshake",
            Self::OpenStream => "open-stream",
            Self::WriteFrame => "write-frame",
            Self::FinishStream => "finish-stream",
            Self::ReadFrame => "read-frame",
            Self::WaitResponse => "wait-response",
        }
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CommunicationError {
    #[error("{phase:?} timed out")]
    Timeout { phase: TransportPhase },
    #[error("Transport failure during {phase:?}: {detail}")]
    Transport {
        phase: TransportPhase,
        detail: String,
    },
    #[error("Protocol violation: {0}")]
    ProtocolViolation(String),
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
    #[error("Message too large")]
    MessageTooLarge,
    #[error("Delivery status is unknown after {phase:?}")]
    DeliveryUnknownAt { phase: TransportPhase },
    #[error("Crypto Provider Install Error")]
    CryptoProviderInstallFailed,
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    #[error(
        "protocol version negotiation failed: client offered {client_versions:?}, host supports {host_versions:?}"
    )]
    ProtocolVersionNegotiation {
        client_versions: Vec<String>,
        host_versions: Vec<String>,
    },
    #[error("Other: {0}")]
    Other(String),
}

impl CommunicationError {
    pub const fn timeout(phase: TransportPhase) -> Self {
        Self::Timeout { phase }
    }

    pub fn transport(phase: TransportPhase, detail: impl Into<String>) -> Self {
        Self::Transport {
            phase,
            detail: detail.into(),
        }
    }

    pub const fn code(&self) -> CommunicationErrorCode {
        match self {
            Self::Timeout { .. } => CommunicationErrorCode::Timeout,
            Self::DeliveryUnknownAt { .. } => CommunicationErrorCode::DeliveryUnknown,
            Self::ClosedByPeer => CommunicationErrorCode::PeerClosed,
            Self::UseAfterClosed | Self::ClosedLocally => CommunicationErrorCode::LocalClosed,
            Self::ConnectionLost => CommunicationErrorCode::ConnectionLost,
            Self::ParseCommunicationValue
            | Self::Encode
            | Self::ParseError(_)
            | Self::ProtocolViolation(_)
            | Self::ProtocolVersionNegotiation { .. } => CommunicationErrorCode::ProtocolViolation,
            Self::AuthenticationFailed(_) => CommunicationErrorCode::AuthenticationFailed,
            Self::MessageTooLarge => CommunicationErrorCode::MessageTooLarge,
            Self::CertificateParseFailed | Self::CertificateLoadFailed => {
                CommunicationErrorCode::Certificate
            }
            Self::CryptoProviderInstallFailed | Self::Other(_) | Self::Transport { .. } => {
                CommunicationErrorCode::Transport
            }
        }
    }

    pub const fn phase(&self) -> Option<TransportPhase> {
        match self {
            Self::Timeout { phase }
            | Self::Transport { phase, .. }
            | Self::DeliveryUnknownAt { phase } => Some(*phase),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_keep_stable_messages_and_equality() {
        assert_eq!(CodecError::InvalidEncoding.to_string(), "Invalid encoding");
        assert_eq!(
            CommunicationError::ClosedByPeer.to_string(),
            "Connection closed by peer"
        );
        assert!(
            CommunicationError::AuthenticationFailed("bad key".into())
                .to_string()
                .contains("bad key")
        );
    }
}
