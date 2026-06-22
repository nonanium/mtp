use mtp_codec::{CommunicationValue, DataTypeId, DataValue, Version};
use mtp_common::CommunicationError;
use mtp_transport::{Policy, Receiver, Sender};

/*
 * The compiled-in protocol version for this client.
 *
 * This is set by the `protocol_version` field in `type-maps.yaml`.
 * At build time, the generated `builtin_type_maps()` determines
 * which type maps are available, and the client always advertises
 * the latest one.
 */
pub use mtp_type_map::PROTOCOL_VERSION;

pub struct ClientConfig {
    pub url: String,
    pub server_cert: Option<Vec<u8>>,
}

// Established MTP connection with a single negotiated version.
pub struct MTPConnection {
    pub version: Version,
    pub sender: Sender,
    pub receiver: Receiver,
}

pub struct MTPClient;

impl MTPClient {
    /*
     * Connect to an MTP host.
     *
     * The first message includes the client's protocol version
     * (a reserved `Version` data entry) so the host can negotiate.
     */
    pub async fn connect(
        config: ClientConfig,
        client_id: u64,
    ) -> Result<MTPConnection, CommunicationError> {
        let (sender, receiver) =
            mtp_transport::connect(&config.url, config.server_cert, Policy::default()).await?;

        // Build the initial identification message with the protocol version.
        let version_str = format!("{}", PROTOCOL_VERSION);
        let ident = CommunicationValue::new(mtp_codec::CommunicationTypeId(15))
            .add_data(DataTypeId(3), DataValue::Str(version_str))
            .add_data(DataTypeId(6), DataValue::UnsignedNumber(client_id.into()));

        sender.send(&ident).await?;

        Ok(MTPConnection {
            version: PROTOCOL_VERSION,
            sender,
            receiver,
        })
    }
}
