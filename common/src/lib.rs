use thiserror::Error;

pub enum RegistryError {
    ReservedCommId(u8, String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecError {
    UnknownVersion,
    UnknownCommunicationType(String),
    UnknownDataType(String),
    ReservedCommunicationType(u8),
    InvalidEncoding,
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

    #[error("ParseBool error: {0}")]
    ParseBool(#[from] std::str::ParseBoolError),

    #[error("ParseInt error: {0}")]
    ParseInt(#[from] std::num::ParseIntError),

    #[error("ParseFloat error: {0}")]
    ParseFloat(#[from] std::num::ParseFloatError),

    #[error("ParseAddr error: {0}")]
    ParseAddr(#[from] std::net::AddrParseError),

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

    #[error("Other: {0}")]
    Other(String),
}
