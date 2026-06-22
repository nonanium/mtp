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
