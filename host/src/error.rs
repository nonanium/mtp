use mtp_codec::Version;
use mtp_common::CommunicationError;
use std::{error::Error, fmt};

#[cfg(test)]
use mtp_codec::{CommunicationValue, DataType, DataValue};

#[cfg(feature = "crypto")]
pub(crate) fn random_client_id() -> u64 {
    rand::random::<u64>()
}

#[cfg(test)]
pub(crate) fn extract_version(msg: &CommunicationValue) -> Option<Version> {
    match msg.get_data(DataType::Version) {
        Some(DataValue::Str(s)) => Version::parse(s.as_str()),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptError {
    Receive(CommunicationError),
    MissingVersion,
    UnsupportedVersion(Version),
    AuthenticationFailed(String),
    AuthenticationTimedOut,
    Send(CommunicationError),
}

impl fmt::Display for AcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Receive(error) => write!(f, "failed to receive opening message: {error}"),
            Self::MissingVersion => write!(
                f,
                "opening message did not include a valid protocol version"
            ),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported protocol version: {version}")
            }
            Self::AuthenticationFailed(reason) => write!(f, "authentication failed: {reason}"),
            Self::AuthenticationTimedOut => write!(f, "authentication handshake timed out"),
            Self::Send(error) => write!(f, "failed to send handshake message: {error}"),
        }
    }
}

impl Error for AcceptError {}

#[cfg(feature = "crypto")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthState {
    Unauthenticated,
    Pending,
    Authenticated,
    Failed,
}
