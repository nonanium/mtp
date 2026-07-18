pub mod config;
pub mod connection;
#[cfg(feature = "crypto")]
pub mod crypto;
pub mod ping;
pub mod pipe;

#[cfg(feature = "pipes")]
pub use mtp_common::PipeError;
#[cfg(feature = "pipes")]
pub use mtp_transport::PipeWriter;

pub use MTPClient as Client;
pub use MTPConnection as Connection;
pub use config::{ClientConfig, ClientTlsConfig, Policy};
pub use connection::MTPConnection;
pub use mtp_transport::Receiver;
pub use mtp_transport::SendMode;
pub use mtp_transport::Sender;

#[cfg(feature = "crypto")]
pub use error::AuthState;
mod error {
    #[cfg(feature = "crypto")]
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum AuthState {
        Unauthenticated,
        Pending,
        Authenticated,
        Failed,
    }
}

use mtp_codec::{CommunicationValue, DataType, DataValue, PROTOCOL_VERSION, Version};
use mtp_common::{CommunicationError, HandshakeOutcome, RejectionReason};

use connection::connection_from_parts;

fn parse_handshake_response(
    response: &CommunicationValue,
) -> Result<HandshakeOutcome, CommunicationError> {
    let tm = mtp_codec::TypeMap::latest();

    let bad_version = mtp_codec::CommunicationType::ErrorBadVersion.try_to_id(&tm);
    if Some(response.get_type()) == bad_version {
        let supported_versions = match response.get_data(DataType::Version) {
            DataValue::Str(v) if !v.is_empty() => v.split(',').map(String::from).collect(),
            _ => vec![],
        };
        return Ok(HandshakeOutcome::Rejected {
            reason: RejectionReason::BadVersion { supported_versions },
        });
    }

    let expected = mtp_codec::CommunicationType::IdentificationResponse
        .try_to_id(&tm)
        .ok_or_else(|| {
            CommunicationError::Other("IdentificationResponse is absent from the type map".into())
        })?;
    if response.get_type() != expected {
        let detail = response
            .get_str(DataType::ErrorMessage)
            .unwrap_or("host rejected the connection")
            .to_string();
        return Ok(HandshakeOutcome::Rejected {
            reason: RejectionReason::AuthenticationFailed { detail },
        });
    }

    match response.get_data(DataType::Connected) {
        DataValue::BoolTrue => {
            let version = match response.get_data(DataType::Version) {
                DataValue::Str(v) => v.clone(),
                _ => {
                    return Err(CommunicationError::Other(
                        "host omitted the negotiated version".into(),
                    ));
                }
            };
            let assigned_id = match response.get_data(DataType::Id) {
                DataValue::UnsignedNumber(n) => *n as u64,
                _ => 0,
            };
            Ok(HandshakeOutcome::Accepted {
                version,
                assigned_id,
            })
        }
        DataValue::BoolFalse => {
            let detail = response
                .get_str(DataType::ErrorMessage)
                .unwrap_or("host rejected the connection")
                .to_string();
            Ok(HandshakeOutcome::Rejected {
                reason: RejectionReason::AuthenticationFailed { detail },
            })
        }
        _ => Err(CommunicationError::Other("invalid response".into())),
    }
}

pub struct MTPClient;

impl MTPClient {
    pub async fn connect(config: ClientConfig) -> Result<MTPConnection, CommunicationError> {
        let (sender, receiver) =
            mtp_transport::connect(&config.url, config.server_cert(), config.policy).await?;

        let version_str = format!("{}", PROTOCOL_VERSION);
        let mut ident = CommunicationValue::new(mtp_codec::CommunicationType::Identification)
            .add_typed_default(DataType::Version, DataValue::Str(version_str))
            .add_typed_default(
                DataType::Id,
                DataValue::UnsignedNumber(config.client_id.into()),
            );
        if let Some(desc) = &config.description {
            ident = ident.add_typed_default(DataType::Description, DataValue::Str(desc.clone()));
        }

        sender.send(&ident).await?;

        let response = receiver.receive().await?;
        let outcome = parse_handshake_response(&response)?;
        let negotiated = match outcome {
            mtp_common::HandshakeOutcome::Accepted { version, .. } => Version::parse(&version)
                .ok_or_else(|| {
                    CommunicationError::Other("host returned an invalid negotiated version".into())
                })?,
            mtp_common::HandshakeOutcome::Rejected { reason } => {
                sender.close();
                return Err(CommunicationError::Other(reason.to_string()));
            }
        };

        #[cfg(feature = "crypto")]
        let client_id = config.client_id;
        #[cfg(feature = "crypto")]
        return Ok(connection_from_parts(
            config,
            sender,
            receiver,
            negotiated,
            error::AuthState::Unauthenticated,
            client_id,
        ));
        #[cfg(not(feature = "crypto"))]
        Ok(connection_from_parts(config, sender, receiver, negotiated))
    }
}

#[cfg(feature = "crypto")]
impl MTPClient {
    pub async fn auth_connect(
        config: ClientConfig,
        keys: &mtp_crypto::Keyring,
        host_public_key_bundle: &mtp_crypto::PublicKeyBundle,
    ) -> Result<MTPConnection, CommunicationError> {
        let timeout = config.auth_timeout;
        match tokio::time::timeout(
            timeout,
            Self::auth_connect_inner(config, keys, host_public_key_bundle),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(CommunicationError::AuthenticationFailed(
                "authentication timed out".into(),
            )),
        }
    }

    async fn auth_connect_inner(
        config: ClientConfig,
        keys: &mtp_crypto::Keyring,
        host_public_key_bundle: &mtp_crypto::PublicKeyBundle,
    ) -> Result<MTPConnection, CommunicationError> {
        use mtp_codec::CommunicationType;

        let (sender, receiver) =
            mtp_transport::connect(&config.url, config.server_cert(), config.policy).await?;

        let tm = mtp_codec::TypeMap::latest();
        let version_str = format!("{}", PROTOCOL_VERSION);

        let mut ident = CommunicationValue::new(CommunicationType::Identification)
            .add_typed_default(DataType::Version, DataValue::Str(version_str.clone()))
            .add_typed_default(
                DataType::Id,
                DataValue::UnsignedNumber(config.client_id as u128),
            );
        if let Some(desc) = &config.description {
            ident = ident.add_typed_default(DataType::Description, DataValue::Str(desc.clone()));
        }
        if let Err(e) = sender.send(&ident).await {
            sender.close();
            return Err(e);
        }

        let server_challenge = match crypto::receive_verified_challenge(
            &receiver,
            &tm,
            host_public_key_bundle,
            config.client_id,
            "auth_connect challenge",
            config.require_pq,
            !keys.sig_pq_secret_key.as_bytes().is_empty(),
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                sender.close();
                return Err(e);
            }
        };

        let client_nonce: u128 = rand::random();
        let proof_payload = mtp_crypto::auth::login_proof_payload(
            &version_str,
            config.client_id,
            server_challenge,
            client_nonce,
        );

        let proof = match crypto::signed_challenge_response(keys, &proof_payload, client_nonce) {
            Ok(p) => p,
            Err(e) => {
                sender.close();
                return Err(e);
            }
        };
        if let Err(e) = sender.send(&proof).await {
            sender.close();
            return Err(e);
        }

        let response = match receiver.receive().await {
            Ok(r) => r,
            Err(e) => {
                sender.close();
                return Err(e);
            }
        };
        let expected_type = CommunicationType::IdentificationResponse
            .try_to_id(&tm)
            .ok_or_else(|| {
                CommunicationError::Other(
                    "IdentificationResponse is absent from the type map".into(),
                )
            })?;
        if response.get_type() != expected_type {
            sender.close();
            return Err(crypto::unexpected_response_type_error(
                "auth_connect",
                expected_type,
                &response,
            ));
        }
        if let Err(e) = crypto::check_connected(&response, "Server rejected authentication") {
            sender.close();
            return Err(e);
        }
        if let Err(e) = crypto::verify_host_final(
            &response,
            host_public_key_bundle,
            config.client_id,
            client_nonce,
            server_challenge,
            config.require_pq,
        ) {
            sender.close();
            return Err(e);
        }

        let client_id = config.client_id;
        Ok(connection_from_parts(
            config,
            sender,
            receiver,
            crypto::negotiated_version(&response)?,
            error::AuthState::Authenticated,
            client_id,
        ))
    }

    pub async fn auth_register(
        config: ClientConfig,
        keys: &mtp_crypto::Keyring,
        host_public_key_bundle: &mtp_crypto::PublicKeyBundle,
    ) -> Result<MTPConnection, CommunicationError> {
        let timeout = config.auth_timeout;
        match tokio::time::timeout(
            timeout,
            Self::auth_register_inner(config, keys, host_public_key_bundle),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(CommunicationError::AuthenticationFailed(
                "authentication timed out".into(),
            )),
        }
    }

    pub async fn auth_connect_or_register(
        mut config: ClientConfig,
        existing_client_id: Option<u64>,
        keys: &mtp_crypto::Keyring,
        host_public_key_bundle: &mtp_crypto::PublicKeyBundle,
    ) -> Result<MTPConnection, CommunicationError> {
        match existing_client_id {
            Some(client_id) => {
                config.client_id = client_id;
                Self::auth_connect(config, keys, host_public_key_bundle).await
            }
            None => Self::auth_register(config, keys, host_public_key_bundle).await,
        }
    }

    async fn auth_register_inner(
        config: ClientConfig,
        keys: &mtp_crypto::Keyring,
        host_public_key_bundle: &mtp_crypto::PublicKeyBundle,
    ) -> Result<MTPConnection, CommunicationError> {
        use mtp_codec::CommunicationType;

        let (sender, receiver) =
            mtp_transport::connect(&config.url, config.server_cert(), config.policy).await?;

        let tm = mtp_codec::TypeMap::latest();
        let version_str = format!("{}", PROTOCOL_VERSION);
        let pk_bundle = keys.public_key_bundle();
        let pk_bytes = pk_bundle.as_bytes();

        let mut register = CommunicationValue::new(CommunicationType::Register)
            .add_typed_default(DataType::Version, DataValue::Str(version_str.clone()))
            .add_typed_default(DataType::PublicKeys, DataValue::Bytes(pk_bytes.clone()));
        if let Some(desc) = &config.description {
            register =
                register.add_typed_default(DataType::Description, DataValue::Str(desc.clone()));
        }
        if let Err(e) = sender.send(&register).await {
            sender.close();
            return Err(e);
        }

        let server_challenge = match crypto::receive_verified_challenge(
            &receiver,
            &tm,
            host_public_key_bundle,
            0,
            "auth_register challenge",
            config.require_pq,
            !keys.sig_pq_secret_key.as_bytes().is_empty(),
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                sender.close();
                return Err(e);
            }
        };

        let client_nonce: u128 = rand::random();
        let proof_payload = mtp_crypto::auth::register_proof_payload(
            &version_str,
            &pk_bytes,
            server_challenge,
            client_nonce,
        );

        let proof = match crypto::signed_challenge_response(keys, &proof_payload, client_nonce) {
            Ok(p) => p,
            Err(e) => {
                sender.close();
                return Err(e);
            }
        };
        if let Err(e) = sender.send(&proof).await {
            sender.close();
            return Err(e);
        }

        let response = match receiver.receive().await {
            Ok(r) => r,
            Err(e) => {
                sender.close();
                return Err(e);
            }
        };
        let expected_type = CommunicationType::RegisterResponse
            .try_to_id(&tm)
            .ok_or_else(|| {
                CommunicationError::Other("RegisterResponse is absent from the type map".into())
            })?;
        if response.get_type() != expected_type {
            sender.close();
            return Err(crypto::unexpected_response_type_error(
                "auth_register",
                expected_type,
                &response,
            ));
        }
        if let Err(e) = crypto::check_connected(&response, "Server rejected registration") {
            sender.close();
            return Err(e);
        }
        let assigned_id = match response.get_data(DataType::Id) {
            DataValue::UnsignedNumber(n) => *n as u64,
            _ => {
                sender.close();
                return Err(CommunicationError::AuthenticationFailed(
                    "Missing assigned ID".into(),
                ));
            }
        };
        if let Err(e) = crypto::verify_host_final(
            &response,
            host_public_key_bundle,
            assigned_id,
            client_nonce,
            server_challenge,
            config.require_pq,
        ) {
            sender.close();
            return Err(e);
        }

        Ok(connection_from_parts(
            config,
            sender,
            receiver,
            crypto::negotiated_version(&response)?,
            error::AuthState::Authenticated,
            assigned_id,
        ))
    }
}

/* ================================ TESTS ================================ */
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_client_config_url() {
        let config = ClientConfig::new("https://example.com:4433");
        assert_eq!(config.url, "https://example.com:4433");
        assert_eq!(config.tls, ClientTlsConfig::SystemRoots);
    }

    #[test]
    fn test_client_config_with_cert() {
        let config = ClientConfig::new("https://localhost:4433")
            .with_pinned_pem(vec![0x01, 0x02, 0x03])
            .with_client_id(42);
        assert_eq!(
            config.tls,
            ClientTlsConfig::PinnedPem(vec![0x01, 0x02, 0x03])
        );
        assert_eq!(config.client_id, 42);
    }

    #[test]
    fn test_ping_config() {
        let config = ClientConfig::new("https://localhost:4433")
            .with_ping_interval(Duration::from_secs(5))
            .with_max_missed_pings(2)
            .with_ping_timestamp(false);
        assert_eq!(config.ping_interval, Duration::from_secs(5));
        assert_eq!(config.ping_jitter, None);
        assert_eq!(config.max_missed_pings, 2);
        assert!(!config.ping_timestamp);
    }

    #[test]
    fn test_request_timeout_config() {
        let config = ClientConfig::new("https://localhost:4433");
        assert_eq!(config.request_timeout, Duration::from_secs(30));
        assert_eq!(
            config
                .with_request_timeout(Duration::from_secs(5))
                .request_timeout,
            Duration::from_secs(5)
        );
    }

    #[tokio::test]
    async fn test_dispatcher_routes_only_matching_request_id() {
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let dispatcher = pipe::PipeDispatcher {
            pending_requests: Mutex::new(HashMap::new()),
            #[cfg(feature = "pipes")]
            pending_creations: Mutex::new(HashMap::new()),
            #[cfg(feature = "pipes")]
            pending_pipes: Mutex::new(HashMap::new()),
            #[cfg(feature = "pipes")]
            policy: Arc::new(Policy::default()),
        };
        let (app_tx, mut app_rx) = tokio::sync::mpsc::channel(2);
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        dispatcher.pending_requests.lock().await.insert(
            7,
            pipe::PendingRequest {
                token: Arc::new(()),
                sender: response_tx,
            },
        );

        let unrelated = CommunicationValue::new(mtp_codec::CommunicationType::Ping).with_id(8);
        assert!(pipe::route_message(unrelated, &app_tx, &dispatcher).await);
        assert_eq!(app_rx.recv().await.unwrap().unwrap().get_id(), 8);

        let response = CommunicationValue::new(mtp_codec::CommunicationType::Pong).with_id(7);
        assert!(pipe::route_message(response, &app_tx, &dispatcher).await);
        assert_eq!(response_rx.await.unwrap().unwrap().get_id(), 7);
        assert!(app_rx.try_recv().is_err());
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_auth_state_unauthenticated_is_not_authenticated() {
        assert_ne!(
            error::AuthState::Unauthenticated,
            error::AuthState::Authenticated
        );
        assert_ne!(error::AuthState::Pending, error::AuthState::Authenticated);
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_auth_timeout_default() {
        let config = ClientConfig::new("https://localhost:4433");
        assert_eq!(config.auth_timeout, Duration::from_secs(30));
        assert!(config.require_pq);
        assert!(!config.with_require_pq(false).require_pq);
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_auth_timeout_custom() {
        let config =
            ClientConfig::new("https://localhost:4433").with_auth_timeout(Duration::from_secs(10));
        assert_eq!(config.auth_timeout, Duration::from_secs(10));
    }
}
