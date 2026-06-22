#[cfg(feature = "crypto")]
use mtp_codec::DataType;
use mtp_codec::{CommunicationValue, DataTypeId, DataValue, PROTOCOL_VERSION, Version};
use mtp_common::CommunicationError;
use mtp_transport::{Policy, Receiver, Sender};

pub struct ClientConfig {
    pub url: String,
    pub server_cert: Option<Vec<u8>>,
}

// Established MTP connection with a single negotiated version.
pub struct MTPConnection {
    pub version: Version,
    pub sender: Sender,
    pub receiver: Receiver,
    #[cfg(feature = "crypto")]
    pub auth_state: AuthState,
    #[cfg(feature = "crypto")]
    pub client_id: u64,
}

#[cfg(feature = "crypto")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthState {
    Pending,
    Authenticated,
    Failed,
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
        let ident = CommunicationValue::new(mtp_codec::CommunicationType::Identification)
            .add_data(DataTypeId(3), DataValue::Str(version_str))
            .add_data(DataTypeId(6), DataValue::UnsignedNumber(client_id.into()));

        sender.send(&ident).await?;

        Ok(MTPConnection {
            version: PROTOCOL_VERSION,
            sender,
            receiver,
            #[cfg(feature = "crypto")]
            auth_state: AuthState::Authenticated,
            #[cfg(feature = "crypto")]
            client_id,
        })
    }
}

/* ===== Authentication ===== */
#[cfg(feature = "crypto")]
impl MTPClient {
    pub async fn auth_connect(
        config: ClientConfig,
        client_id: u64,
        keys: mtp_crypto::KeyGroup,
        host_public_key: mtp_crypto::SignaturePublicKey,
    ) -> Result<MTPConnection, CommunicationError> {
        use mtp_crypto::{Ed25519Signer, SignatureScheme, verify_ed25519};

        let (sender, receiver) =
            mtp_transport::connect(&config.url, config.server_cert, Policy::default()).await?;

        // 1. Receive host greeting (IdentificationResponse with host ID, public keys, nonce)
        let _greeting = receiver.receive().await?;

        // 2. Build and send Identification message with auth data
        let client_nonce: u128 = rand::random();
        let version_str = format!("{}", PROTOCOL_VERSION);

        let mut sig_payload = Vec::new();
        sig_payload.extend_from_slice(version_str.as_bytes());
        sig_payload.extend_from_slice(&client_id.to_be_bytes());
        sig_payload.extend_from_slice(&client_nonce.to_be_bytes());

        let signer = Ed25519Signer::new(&keys.signature_private_key)
            .map_err(|e| CommunicationError::Other(e.to_string()))?;

        /* ===== Signature ===== */
        // Current: signing concatenated bytes
        // Future: sign entire CommunicationValue
        let signature = signer
            .sign(&sig_payload)
            .map_err(|e| CommunicationError::Other(e.to_string()))?;
        /* ===== End Signature ===== */

        let ident = CommunicationValue::new(mtp_codec::CommunicationType::Identification)
            .add_typed_default(DataType::Version, DataValue::Str(version_str))
            .add_typed_default(DataType::Id, DataValue::UnsignedNumber(client_id as u128))
            .add_typed_default(
                DataType::ClientNonce,
                DataValue::UnsignedNumber(client_nonce),
            )
            .add_typed_default(DataType::Signature, DataValue::Bytes(signature));

        sender.send(&ident).await?;

        // 3. Receive host response
        let response = receiver.receive().await?;

        let connected = response.get_data(DataTypeId(11));
        match connected {
            DataValue::BoolTrue => {}
            DataValue::BoolFalse => {
                return Err(CommunicationError::AuthenticationFailed(
                    "Server rejected authentication".into(),
                ));
            }
            _ => {
                return Err(CommunicationError::AuthenticationFailed(
                    "Invalid response".into(),
                ));
            }
        }

        let echo_nonce = response.get_data(DataTypeId(7));
        match echo_nonce {
            DataValue::UnsignedNumber(n) if *n == client_nonce as u128 => {}
            _ => {
                return Err(CommunicationError::AuthenticationFailed(
                    "Nonce mismatch".into(),
                ));
            }
        }

        let host_new_nonce = match response.get_data(DataTypeId(5)) {
            DataValue::UnsignedNumber(n) => *n as u128,
            _ => {
                return Err(CommunicationError::AuthenticationFailed(
                    "Missing new nonce".into(),
                ));
            }
        };

        let host_sig = match response.get_data(DataTypeId(10)) {
            DataValue::Bytes(b) => b.clone(),
            _ => {
                return Err(CommunicationError::AuthenticationFailed(
                    "Missing signature".into(),
                ));
            }
        };

        let mut host_sig_payload = Vec::new();
        host_sig_payload.extend_from_slice(b"true");
        host_sig_payload.extend_from_slice(&client_nonce.to_be_bytes());
        host_sig_payload.extend_from_slice(&host_new_nonce.to_be_bytes());

        /* ===== Signature ===== */
        verify_ed25519(&host_public_key, &host_sig_payload, &host_sig).map_err(|_| {
            CommunicationError::AuthenticationFailed("Host signature invalid".into())
        })?;
        /* ===== End Signature ===== */

        Ok(MTPConnection {
            version: PROTOCOL_VERSION,
            sender,
            receiver,
            auth_state: AuthState::Authenticated,
            client_id,
        })
    }

    pub async fn auth_register(
        config: ClientConfig,
        keys: mtp_crypto::Keyring,
        host_public_key: mtp_crypto::SignaturePublicKey,
    ) -> Result<MTPConnection, CommunicationError> {
        use mtp_crypto::{Ed25519Signer, SignatureScheme, verify_ed25519};

        let (sender, receiver) =
            mtp_transport::connect(&config.url, config.server_cert, Policy::default()).await?;

        // 1. Receive host greeting (IdentificationResponse with host ID, public keys, nonce)
        let _greeting = receiver.receive().await?;

        // 2. Build and send Register message with public keys and auth data
        let client_nonce: u128 = rand::random();
        let version_str = format!("{}", PROTOCOL_VERSION);
        let pk_bundle = keys.public_key_bundle();
        let pk_bytes = pk_bundle.as_bytes();

        let mut sig_payload = Vec::new();
        sig_payload.extend_from_slice(version_str.as_bytes());
        sig_payload.extend_from_slice(&client_nonce.to_be_bytes());
        sig_payload.extend_from_slice(&pk_bytes);

        let signer = Ed25519Signer::new(&keys.sig_cl_secret_key)
            .map_err(|e| CommunicationError::Other(e.to_string()))?;

        /* ===== Signature ===== */
        let signature = signer
            .sign(&sig_payload)
            .map_err(|e| CommunicationError::Other(e.to_string()))?;
        /* ===== End Signature ===== */

        let register = CommunicationValue::new(mtp_codec::CommunicationType::Register)
            .add_typed_default(DataType::Version, DataValue::Str(version_str))
            .add_typed_default(
                DataType::ClientNonce,
                DataValue::UnsignedNumber(client_nonce),
            )
            .add_typed_default(DataType::PublicKeys, DataValue::Bytes(pk_bytes))
            .add_typed_default(DataType::Signature, DataValue::Bytes(signature));

        sender.send(&register).await?;

        // 3. Receive host response
        let response = receiver.receive().await?;

        let connected = response.get_data(DataTypeId(11));
        match connected {
            DataValue::BoolTrue => {}
            DataValue::BoolFalse => {
                return Err(CommunicationError::AuthenticationFailed(
                    "Server rejected registration".into(),
                ));
            }
            _ => {
                return Err(CommunicationError::AuthenticationFailed(
                    "Invalid response".into(),
                ));
            }
        }

        let assigned_id = match response.get_data(DataTypeId(6)) {
            DataValue::UnsignedNumber(n) => *n as u128,
            _ => {
                return Err(CommunicationError::AuthenticationFailed(
                    "Missing assigned ID".into(),
                ));
            }
        };

        let echo_nonce = response.get_data(DataTypeId(7));
        match echo_nonce {
            DataValue::UnsignedNumber(n) if *n == client_nonce as u128 => {}
            _ => {
                return Err(CommunicationError::AuthenticationFailed(
                    "Nonce mismatch".into(),
                ));
            }
        }

        let host_new_nonce = match response.get_data(DataTypeId(5)) {
            DataValue::UnsignedNumber(n) => *n as u128,
            _ => {
                return Err(CommunicationError::AuthenticationFailed(
                    "Missing new nonce".into(),
                ));
            }
        };

        let host_sig = match response.get_data(DataTypeId(10)) {
            DataValue::Bytes(b) => b.clone(),
            _ => {
                return Err(CommunicationError::AuthenticationFailed(
                    "Missing signature".into(),
                ));
            }
        };

        let mut host_sig_payload = Vec::new();
        host_sig_payload.extend_from_slice(b"true");
        host_sig_payload.extend_from_slice(&assigned_id.to_be_bytes());
        host_sig_payload.extend_from_slice(&client_nonce.to_be_bytes());
        host_sig_payload.extend_from_slice(&host_new_nonce.to_be_bytes());

        /* ===== Signature ===== */
        verify_ed25519(&host_public_key, &host_sig_payload, &host_sig).map_err(|_| {
            CommunicationError::AuthenticationFailed("Host signature invalid".into())
        })?;
        /* ===== End Signature ===== */

        Ok(MTPConnection {
            version: PROTOCOL_VERSION,
            sender,
            receiver,
            auth_state: AuthState::Authenticated,
            client_id: assigned_id as u64,
        })
    }
}
/* ===== End Authentication ===== */
