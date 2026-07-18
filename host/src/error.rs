use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue, Version};
use mtp_common::{CommunicationError, RejectionReason};
use mtp_transport::Sender;
use std::{error::Error, fmt};

#[cfg(feature = "crypto")]
pub(crate) fn random_client_id() -> u64 {
    rand::random::<u64>() & mtp_codec::MAX_WIRE_ID
}

pub(crate) async fn send_rejection(sender: &Sender, reason: RejectionReason) {
    let response = match &reason {
        RejectionReason::BadVersion { supported_versions } => {
            CommunicationValue::new(CommunicationType::ErrorBadVersion)
                .add_typed_default(
                    DataType::Version,
                    DataValue::Str(supported_versions.join(",")),
                )
                .add_typed_default(DataType::ErrorMessage, DataValue::Str(reason.to_string()))
        }
        _ => CommunicationValue::new(CommunicationType::IdentificationResponse)
            .add_typed_default(DataType::Connected, DataValue::BoolFalse)
            .add_typed_default(DataType::ErrorMessage, DataValue::Str(reason.to_string())),
    };
    let _ = sender.send(&response).await;
}

pub(crate) async fn send_accepted(
    sender: &Sender,
    version: &Version,
    assigned_id: Option<u64>,
) -> Result<(), CommunicationError> {
    let mut response = CommunicationValue::new(CommunicationType::IdentificationResponse)
        .add_typed_default(DataType::Connected, DataValue::BoolTrue)
        .add_typed_default(DataType::Version, DataValue::Str(version.to_string()));
    if let Some(id) = assigned_id {
        response = response.add_typed_default(DataType::Id, DataValue::UnsignedNumber(id as u128));
    }
    sender.send(&response).await?;
    sender.finish_stream().await
}

pub(crate) fn extract_version(msg: &CommunicationValue) -> Option<Version> {
    let value = msg.get_data(DataType::Version);
    match value {
        DataValue::Str(s) => Version::parse(s.as_str()),
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
