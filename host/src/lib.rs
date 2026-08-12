pub mod config;
pub mod connection;
pub mod engine;
pub mod error;
pub mod handshake;
#[cfg(feature = "pipes")]
pub mod pipe;

pub use MTPConnection as Connection;
pub use MTPHost as Host;
pub use config::HostConfig;
pub use config::Policy;
pub use connection::{MTPConnection, MtpReceiverLike, MtpSenderLike};
pub use engine::{HandshakeEngine, HandshakeReceiver, HandshakeResult, HandshakeSender};
pub use error::AcceptError;
pub use handshake::MTPHost;
pub use mtp_transport::Receiver;
pub use mtp_transport::SendMode;
pub use mtp_transport::Sender;

#[cfg(feature = "pipes")]
pub use mtp_common::PipeError;
#[cfg(feature = "pipes")]
pub use mtp_transport::PipeWriter;
#[cfg(feature = "pipes")]
pub use pipe::PipeRequest;

pub use mtp_codec::registry::Registry;

#[cfg(feature = "crypto")]
pub use config::{
    AuthenticationPolicy, CompleteRegister, FindRegisteredClient, GetExistingClient,
    GuestIdGenerator,
};
#[cfg(feature = "crypto")]
pub use error::AuthState;

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "pipes"))]
    use mtp_codec::registry::VersionedCodec;
    use mtp_codec::{CommunicationType, DataType, DataValue};

    #[cfg(not(feature = "pipes"))]
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct AlternateSender;

    #[cfg(not(feature = "pipes"))]
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct AlternateReceiver;

    #[test]
    fn version_extraction() {
        let tm = mtp_codec::TypeMap::latest();
        let msg = mtp_codec::CommunicationValue::from_comm(CommunicationType::Identification, &tm)
            .add_typed(DataType::Version, &tm, DataValue::Str("3.0".to_string()));
        let version = error::extract_version(&msg);
        assert_eq!(version, Some(mtp_codec::Version(3, 0)));
    }

    #[test]
    fn version_extraction_returns_none_for_missing() {
        let tm = mtp_codec::TypeMap::latest();
        let msg = mtp_codec::CommunicationValue::from_comm(CommunicationType::Identification, &tm);
        assert!(error::extract_version(&msg).is_none());
    }

    #[test]
    fn version_extraction_bad_format() {
        let tm = mtp_codec::TypeMap::latest();
        let msg = mtp_codec::CommunicationValue::from_comm(CommunicationType::Identification, &tm)
            .add_typed(DataType::Version, &tm, DataValue::UnsignedNumber(42));
        assert!(error::extract_version(&msg).is_none());
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn auth_state_unauthenticated_is_not_authenticated() {
        assert_ne!(AuthState::Unauthenticated, AuthState::Authenticated);
        assert_ne!(AuthState::Pending, AuthState::Authenticated);
    }

    #[test]
    fn host_config_pongs_default_to_enabled() -> Result<(), Box<dyn std::error::Error>> {
        let config = HostConfig::new("127.0.0.1".parse()?, 4433, Vec::new(), Vec::new());
        assert!(config.send_pongs);
        #[cfg(feature = "crypto")]
        assert!(config.require_pq);
        assert!(!config.with_pongs(false).send_pongs);
        Ok(())
    }

    #[cfg(not(feature = "pipes"))]
    #[tokio::test]
    async fn alternative_transports_use_the_shared_connection_type() {
        let registry = Registry::builtin();
        let version = mtp_codec::Version(3, 0);
        let codec = VersionedCodec::for_version(registry, version.clone()).unwrap();
        let connection: MTPConnection<AlternateSender, AlternateReceiver> =
            MTPConnection::from_transport_parts(
                version.clone(),
                codec,
                AlternateSender,
                AlternateReceiver,
                "/mtp".into(),
                Some("browser".into()),
            );
        assert_eq!(connection.version, version);
        assert_eq!(connection.path, "/mtp");
        assert_eq!(connection.description.as_deref(), Some("browser"));
    }
}
