use crate::CommunicationError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipeError {
    Rejected,
    Cancelled,
    HandshakeTimeout,
    StreamClosed,
    IoError(String),
    ConnectionClosed,
}

impl std::fmt::Display for PipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected => write!(f, "pipe request was rejected"),
            Self::Cancelled => write!(f, "pipe request was cancelled"),
            Self::HandshakeTimeout => write!(f, "pipe handshake timed out"),
            Self::StreamClosed => write!(f, "pipe stream closed unexpectedly"),
            Self::IoError(error) => write!(f, "pipe I/O error: {error}"),
            Self::ConnectionClosed => write!(f, "connection closed"),
        }
    }
}

impl std::error::Error for PipeError {}

impl From<CommunicationError> for PipeError {
    fn from(error: CommunicationError) -> Self {
        match error {
            CommunicationError::ClosedByPeer => Self::StreamClosed,
            CommunicationError::ConnectionLost | CommunicationError::ClosedLocally => {
                Self::ConnectionClosed
            }
            other => Self::IoError(other.to_string()),
        }
    }
}
