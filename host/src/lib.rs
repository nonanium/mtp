use mtp_codec::{
    CommunicationValue, DataTypeId, DataValue, Version,
    registry::{Registry, VersionedCodec},
};
use mtp_common::CommunicationError;
use mtp_transport::{Policy, Receiver, Sender};

// Host configuration.
pub struct HostConfig {
    pub ip: String,
    pub port: u16,
    pub tls_fullchain: Vec<u8>,
    pub tls_key: Vec<u8>,
}

// A connection that has completed version negotiation.
pub struct MTPConnection {
    pub version: Version,
    pub codec: VersionedCodec,
    pub sender: Sender,
    pub receiver: Receiver,
}

// High-level MTP host with built-in version negotiation.
pub struct MTPHost {
    transport: mtp_transport::Host,
    registry: Registry,
}

impl MTPHost {
    pub async fn new(config: HostConfig) -> Result<Self, CommunicationError> {
        let registry = Registry::builtin();

        let transport = mtp_transport::host(
            config.port,
            config.tls_fullchain,
            config.tls_key,
            Policy::default(),
        )
        .await?;

        Ok(Self {
            transport,
            registry,
        })
    }

    /*
     * Accept an incoming connection, negotiate the protocol version,
     * and return a ready-to-use `MTPConnection`.
     *
     * Returns `None` if the connection is closed or the version is
     * incompatible.
     */
    pub async fn accept(&mut self) -> Option<MTPConnection> {
        let (sender, receiver) = self.transport.next().await?;

        /* Read the first message (always encoded with reserved types). */
        let first_msg = receiver.receive().await.ok()?;

        /*
         * Extract the client's version from the first message.
         * The client is expected to send DataType::Version (reserved ID 3)
         * as a DataValue::Str("X.Y").
         *
         * Then negotiate the version for single-version clients
         */
        let client_version = extract_version(&first_msg)?;

        let negotiated = self.registry.negotiate(&[client_version])?;

        let codec = VersionedCodec::new(self.registry.clone());

        Some(MTPConnection {
            version: negotiated,
            codec,
            sender,
            receiver,
        })
    }

    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.transport.local_addr()
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}

/*
 * Extract the protocol version from an initial `CommunicationValue`.
 *
 * The client's first message must contain a `Version` data entry
 * (reserved ID 3) mapping to `DataValue::Str("major.minor")`.
 */
fn extract_version(msg: &CommunicationValue) -> Option<Version> {
    let value = msg.get_data(DataTypeId(3));
    match value {
        DataValue::Str(s) => Version::parse(s.as_str()),
        _ => None,
    }
}

/* ================================ TESTS ================================ */
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_extraction() {
        let msg = CommunicationValue::new(mtp_codec::CommunicationTypeId(15))
            .add_data(DataTypeId(3), DataValue::Str("2.0".to_string()));
        let version = extract_version(&msg);
        assert_eq!(version, Some(Version(2, 0)));
    }

    #[test]
    fn version_extraction_returns_none_for_missing() {
        let msg = CommunicationValue::new(mtp_codec::CommunicationTypeId(15));
        assert!(extract_version(&msg).is_none());
    }

    #[test]
    fn version_extraction_bad_format() {
        let msg = CommunicationValue::new(mtp_codec::CommunicationTypeId(15))
            .add_data(DataTypeId(3), DataValue::UnsignedNumber(42));
        assert!(extract_version(&msg).is_none());
    }
}
