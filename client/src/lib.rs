use mtp_codec::{CommunicationValue, DataType, DataValue, PROTOCOL_VERSION, Version};
use mtp_common::CommunicationError;
use mtp_transport::{Policy, Receiver, Sender};

#[cfg(feature = "crypto")]
fn unexpected_response_type_error(
    context: &str,
    expected_type: mtp_codec::CommunicationTypeId,
    response: &CommunicationValue,
) -> CommunicationError {
    CommunicationError::AuthenticationFailed(format!(
        "unexpected response type during {context}: expected {:?}, got {:?}; parsed {}",
        expected_type,
        response.get_type(),
        response
    ))
}

pub struct ClientConfig {
    pub url: String,
    pub server_cert: Option<Vec<u8>>,
    pub client_id: u64,
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
    pub async fn connect(config: ClientConfig) -> Result<MTPConnection, CommunicationError> {
        let (sender, receiver) =
            mtp_transport::connect(&config.url, config.server_cert, Policy::default()).await?;

        // Build the initial identification message with the protocol version.
        let version_str = format!("{}", PROTOCOL_VERSION);
        let ident = CommunicationValue::new(mtp_codec::CommunicationType::Identification)
            .add_typed_default(DataType::Version, DataValue::Str(version_str))
            .add_typed_default(
                DataType::Id,
                DataValue::UnsignedNumber(config.client_id.into()),
            );

        sender.send(&ident).await?;

        Ok(MTPConnection {
            version: PROTOCOL_VERSION,
            sender,
            receiver,
            #[cfg(feature = "crypto")]
            auth_state: AuthState::Authenticated,
            #[cfg(feature = "crypto")]
            client_id: config.client_id,
        })
    }
}

/* ===== Authentication ===== */
#[cfg(feature = "crypto")]
impl MTPClient {
    pub async fn auth_connect(
        config: ClientConfig,
        keys: &mtp_crypto::Keyring,
        host_public_key_bundle: &mtp_crypto::PublicKeyBundle,
    ) -> Result<MTPConnection, CommunicationError> {
        use mtp_crypto::{
            Ed25519Signer, MlDsaSigner, SignatureScheme, verify_ed25519, verify_ml_dsa,
        };

        let (sender, receiver) =
            mtp_transport::connect(&config.url, config.server_cert, Policy::default()).await?;

        // 1. Build and send Identification message immediately (no greeting)
        let client_nonce: u128 = rand::random();
        let version_str = format!("{}", PROTOCOL_VERSION);

        let mut sig_payload = Vec::new();
        sig_payload.extend_from_slice(version_str.as_bytes());
        sig_payload.extend_from_slice(&config.client_id.to_be_bytes());
        sig_payload.extend_from_slice(&client_nonce.to_be_bytes());

        let signer = Ed25519Signer::new(&keys.sig_cl_secret_key)
            .map_err(|e| CommunicationError::Other(e.to_string()))?;

        /* ===== Signature ===== */
        let signature = signer
            .sign(&sig_payload)
            .map_err(|e| CommunicationError::Other(e.to_string()))?;

        let mut ident = CommunicationValue::new(mtp_codec::CommunicationType::Identification)
            .add_typed_default(DataType::Version, DataValue::Str(version_str))
            .add_typed_default(
                DataType::Id,
                DataValue::UnsignedNumber(config.client_id as u128),
            )
            .add_typed_default(
                DataType::ClientNonce,
                DataValue::UnsignedNumber(client_nonce),
            )
            .add_typed_default(DataType::Signature, DataValue::Bytes(signature));

        if !keys.sig_pq_secret_key.as_bytes().is_empty() {
            let pq_signer = MlDsaSigner::new(&keys.sig_pq_secret_key, &keys.sig_pq_public_key)
                .map_err(|e| CommunicationError::Other(e.to_string()))?;
            let pq_signature = pq_signer
                .sign(&sig_payload)
                .map_err(|e| CommunicationError::Other(e.to_string()))?;
            ident = ident.add_typed_default(DataType::PqSignature, DataValue::Bytes(pq_signature));
        }
        /* ===== End Signature ===== */

        sender.send(&ident).await?;

        // 2. Receive host response (single message)
        let response = receiver.receive().await?;

        let tm = mtp_codec::TypeMap::latest();

        let expected_type = mtp_codec::CommunicationType::IdentificationResponse.to_id(&tm);
        if response.get_type() != expected_type {
            return Err(unexpected_response_type_error(
                "auth_connect",
                expected_type,
                &response,
            ));
        }

        let connected = response.get_data(DataType::Connected.to_id(&tm));
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

        let echo_nonce = response.get_data(DataType::ClientNonce.to_id(&tm));
        match echo_nonce {
            DataValue::UnsignedNumber(n) if *n == client_nonce as u128 => {}
            _ => {
                return Err(CommunicationError::AuthenticationFailed(
                    "Nonce mismatch".into(),
                ));
            }
        }

        let host_new_nonce = match response.get_data(DataType::Timestamp.to_id(&tm)) {
            DataValue::UnsignedNumber(n) => *n,
            _ => {
                return Err(CommunicationError::AuthenticationFailed(
                    "Missing new nonce".into(),
                ));
            }
        };

        let host_sig = match response.get_data(DataType::Signature.to_id(&tm)) {
            DataValue::Bytes(b) => b.clone(),
            _ => {
                return Err(CommunicationError::AuthenticationFailed(
                    "Missing signature".into(),
                ));
            }
        };

        let host_pq_sig = match response.get_data(DataType::PqSignature.to_id(&tm)) {
            DataValue::Bytes(b) => b.clone(),
            _ => vec![],
        };

        let mut host_sig_payload = Vec::new();
        host_sig_payload.push(0x01);
        host_sig_payload.extend_from_slice(&config.client_id.to_be_bytes());
        host_sig_payload.extend_from_slice(&client_nonce.to_be_bytes());
        host_sig_payload.extend_from_slice(&host_new_nonce.to_be_bytes());

        /* ===== Signature ===== */
        verify_ed25519(
            &host_public_key_bundle.sig_cl_public_key,
            &host_sig_payload,
            &host_sig,
        )
        .map_err(|_| CommunicationError::AuthenticationFailed("Host signature invalid".into()))?;
        if !host_pq_sig.is_empty()
            && verify_ml_dsa(
                &host_public_key_bundle.sig_pq_public_key,
                &host_sig_payload,
                &host_pq_sig,
            )
            .is_err()
        {
            return Err(CommunicationError::AuthenticationFailed(
                "Host PQ signature invalid".into(),
            ));
        }
        /* ===== End Signature ===== */

        Ok(MTPConnection {
            version: PROTOCOL_VERSION,
            sender,
            receiver,
            auth_state: AuthState::Authenticated,
            client_id: config.client_id,
        })
    }

    pub async fn auth_register(
        config: ClientConfig,
        keys: &mtp_crypto::Keyring,
        host_public_key_bundle: &mtp_crypto::PublicKeyBundle,
    ) -> Result<MTPConnection, CommunicationError> {
        use mtp_crypto::{
            Ed25519Signer, MlDsaSigner, SignatureScheme, verify_ed25519, verify_ml_dsa,
        };

        let (sender, receiver) =
            mtp_transport::connect(&config.url, config.server_cert, Policy::default()).await?;

        // 1. Build and send Register message immediately
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

        let mut register = CommunicationValue::new(mtp_codec::CommunicationType::Register)
            .add_typed_default(DataType::Version, DataValue::Str(version_str))
            .add_typed_default(
                DataType::ClientNonce,
                DataValue::UnsignedNumber(client_nonce),
            )
            .add_typed_default(DataType::PublicKeys, DataValue::Bytes(pk_bytes))
            .add_typed_default(DataType::Signature, DataValue::Bytes(signature));

        if !keys.sig_pq_secret_key.as_bytes().is_empty() {
            let pq_signer = MlDsaSigner::new(&keys.sig_pq_secret_key, &keys.sig_pq_public_key)
                .map_err(|e| CommunicationError::Other(e.to_string()))?;
            let pq_signature = pq_signer
                .sign(&sig_payload)
                .map_err(|e| CommunicationError::Other(e.to_string()))?;
            register =
                register.add_typed_default(DataType::PqSignature, DataValue::Bytes(pq_signature));
        }
        /* ===== End Signature ===== */

        sender.send(&register).await?;

        // 2. Receive host response (single message)
        let response = receiver.receive().await?;

        let tm = mtp_codec::TypeMap::latest();

        let expected_type = mtp_codec::CommunicationType::RegisterResponse.to_id(&tm);
        if response.get_type() != expected_type {
            return Err(unexpected_response_type_error(
                "auth_register",
                expected_type,
                &response,
            ));
        }

        let connected = response.get_data(DataType::Connected.to_id(&tm));
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

        let assigned_id = match response.get_data(DataType::Id.to_id(&tm)) {
            DataValue::UnsignedNumber(n) => *n,
            _ => {
                return Err(CommunicationError::AuthenticationFailed(
                    "Missing assigned ID".into(),
                ));
            }
        };

        let echo_nonce = response.get_data(DataType::ClientNonce.to_id(&tm));
        match echo_nonce {
            DataValue::UnsignedNumber(n) if *n == client_nonce as u128 => {}
            _ => {
                return Err(CommunicationError::AuthenticationFailed(
                    "Nonce mismatch".into(),
                ));
            }
        }

        let host_new_nonce = match response.get_data(DataType::Timestamp.to_id(&tm)) {
            DataValue::UnsignedNumber(n) => *n,
            _ => {
                return Err(CommunicationError::AuthenticationFailed(
                    "Missing new nonce".into(),
                ));
            }
        };

        let host_sig = match response.get_data(DataType::Signature.to_id(&tm)) {
            DataValue::Bytes(b) => b.clone(),
            _ => {
                return Err(CommunicationError::AuthenticationFailed(
                    "Missing signature".into(),
                ));
            }
        };

        let host_pq_sig = match response.get_data(DataType::PqSignature.to_id(&tm)) {
            DataValue::Bytes(b) => b.clone(),
            _ => vec![],
        };

        let mut host_sig_payload = Vec::new();
        host_sig_payload.push(0x01);
        host_sig_payload.extend_from_slice(&(assigned_id as u64).to_be_bytes());
        host_sig_payload.extend_from_slice(&client_nonce.to_be_bytes());
        host_sig_payload.extend_from_slice(&host_new_nonce.to_be_bytes());

        /* ===== Signature ===== */
        verify_ed25519(
            &host_public_key_bundle.sig_cl_public_key,
            &host_sig_payload,
            &host_sig,
        )
        .map_err(|_| CommunicationError::AuthenticationFailed("Host signature invalid".into()))?;
        if !host_pq_sig.is_empty()
            && verify_ml_dsa(
                &host_public_key_bundle.sig_pq_public_key,
                &host_sig_payload,
                &host_pq_sig,
            )
            .is_err()
        {
            return Err(CommunicationError::AuthenticationFailed(
                "Host PQ signature invalid".into(),
            ));
        }
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

/* ================================ TESTS ================================ */
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config_url() {
        let config = ClientConfig {
            url: "https://example.com:4433".into(),
            server_cert: None,
            client_id: 0,
        };
        assert_eq!(config.url, "https://example.com:4433");
        assert!(config.server_cert.is_none());
    }

    #[test]
    fn test_client_config_with_cert() {
        let config = ClientConfig {
            url: "https://localhost:4433".into(),
            server_cert: Some(vec![0x01, 0x02, 0x03]),
            client_id: 42,
        };
        assert_eq!(config.server_cert, Some(vec![0x01, 0x02, 0x03]));
        assert_eq!(config.client_id, 42);
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_auth_state_derive() {
        assert_eq!(AuthState::Pending, AuthState::Pending);
        assert_ne!(AuthState::Authenticated, AuthState::Failed);
    }
}
