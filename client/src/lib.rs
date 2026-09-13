pub mod config;
pub mod connection;
#[cfg(feature = "crypto")]
pub mod crypto;
pub mod ping;
pub mod pipe;

#[cfg(feature = "pipes")]
pub use mtp_common::{PingId, PipeError, PipeId, RequestId};
#[cfg(feature = "pipes")]
pub use mtp_native::PipeWriter;

pub use MTPClient as Client;
pub use MTPConnection as Connection;
pub use config::{ClientConfig, ClientTlsConfig, Policy};
pub use connection::MTPConnection;
pub use mtp_native::Receiver;
pub use mtp_native::SendMode;
pub use mtp_native::Sender;

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

use mtp_codec::{
    CommunicationValue, DataType, DataValue, TypeMap, Version,
    registry::{Registry, VersionedCodec, bootstrap_type_map},
};
use mtp_common::{CommunicationError, HandshakeOutcome, RejectionReason};

use connection::connection_from_parts;

fn native_client_config(config: &ClientConfig) -> mtp_native::ClientConfig {
    match &config.tls {
        ClientTlsConfig::SystemRoots => mtp_native::ClientConfig::new(config.policy),
        ClientTlsConfig::PinnedPem(cert_pem) => {
            mtp_native::ClientConfig::new(config.policy).with_server_certificate(cert_pem.clone())
        }
        ClientTlsConfig::PinnedSpkiSha256(hash) => {
            mtp_native::ClientConfig::new(config.policy).with_pinned_certificate_hash(*hash)
        }
    }
}

fn parse_handshake_response(
    response: &CommunicationValue,
    type_map: &mtp_codec::TypeMap,
) -> Result<HandshakeOutcome, CommunicationError> {
    let bad_version = mtp_codec::CommunicationType::ErrorBadVersion.try_to_id(type_map);
    if Some(response.get_type()) == bad_version {
        let supported_versions = match response.get_data(DataType::Version) {
            Some(DataValue::Array(values)) => values
                .iter()
                .filter_map(|value| match value {
                    DataValue::Str(version) => Some(version.clone()),
                    _ => None,
                })
                .collect(),
            _ => vec![],
        };
        return Ok(HandshakeOutcome::Rejected {
            reason: RejectionReason::BadVersion { supported_versions },
        });
    }

    let expected = mtp_codec::CommunicationType::IdentificationResponse
        .try_to_id(type_map)
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
        Some(DataValue::BoolTrue) => {
            let version = match response.get_data(DataType::Version) {
                Some(DataValue::Str(v)) => v.clone(),
                _ => {
                    return Err(CommunicationError::Other(
                        "host omitted the negotiated version".into(),
                    ));
                }
            };
            let assigned_id = match response.get_data(DataType::Id) {
                Some(DataValue::UnsignedNumber(n)) => u64::try_from(*n).map_err(|_| {
                    CommunicationError::Other("host returned an out-of-range client id".into())
                })?,
                _ => {
                    return Err(CommunicationError::Other(
                        "host omitted the assigned client id".into(),
                    ));
                }
            };
            Ok(HandshakeOutcome::Accepted {
                version,
                assigned_id,
            })
        }
        Some(DataValue::BoolFalse) => {
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

fn codec_for_version(version: &Version) -> Result<VersionedCodec, CommunicationError> {
    VersionedCodec::for_version(Registry::builtin(), version.clone()).ok_or_else(|| {
        CommunicationError::Other(format!(
            "host returned unsupported protocol version {version}"
        ))
    })
}

fn supported_versions() -> Vec<Version> {
    let mut versions: Vec<_> = Registry::builtin().versions().cloned().collect();
    versions.sort_by(|left, right| right.cmp(left));
    versions
}

fn version_offer(versions: &[Version]) -> DataValue {
    DataValue::Array(
        versions
            .iter()
            .map(|version| DataValue::Str(version.to_string()))
            .collect(),
    )
}

async fn select_codec(
    sender: &mtp_native::Sender,
    receiver: &mtp_native::Receiver,
    bootstrap: &TypeMap,
    offered: &[Version],
) -> Result<(Version, VersionedCodec), CommunicationError> {
    let selection = receiver.receive().await?;
    let bad_version = mtp_codec::CommunicationType::ErrorBadVersion.try_to_id(bootstrap);
    if Some(selection.get_type()) == bad_version {
        let host_versions = match selection.get_data(DataType::Version) {
            Some(DataValue::Array(versions)) => versions
                .iter()
                .map(|version| match version {
                    DataValue::Str(version) => Ok(version.clone()),
                    _ => Err(CommunicationError::ProtocolViolation(
                        "host returned a malformed supported-version collection".into(),
                    )),
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => {
                return Err(CommunicationError::ProtocolViolation(
                    "host omitted the supported-version collection".into(),
                ));
            }
        };
        return Err(CommunicationError::ProtocolVersionNegotiation {
            client_versions: offered.iter().map(ToString::to_string).collect(),
            host_versions,
        });
    }
    let expected = mtp_codec::CommunicationType::IdentificationResponse
        .try_to_id(bootstrap)
        .ok_or_else(|| CommunicationError::Other("bootstrap response is unavailable".into()))?;
    if selection.get_type() != expected
        || selection.get_data(DataType::Connected) != Some(&DataValue::BoolTrue)
    {
        return Err(CommunicationError::Other(
            "host did not return a version selection".into(),
        ));
    }
    let version = match selection.get_data(DataType::Version) {
        Some(DataValue::Str(version)) => Version::parse(version),
        _ => None,
    }
    .ok_or_else(|| {
        CommunicationError::Other("host returned an invalid negotiated version".into())
    })?;
    if !offered.contains(&version) {
        return Err(CommunicationError::Other(
            "host selected a protocol version the client did not offer".into(),
        ));
    }
    let codec = codec_for_version(&version)?;
    sender.set_type_map(codec.type_map()).await;
    receiver.set_type_map(codec.type_map()).await;
    Ok((version, codec))
}

pub struct MTPClient;

impl MTPClient {
    pub async fn connect(config: ClientConfig) -> Result<MTPConnection, CommunicationError> {
        let (sender, receiver) =
            mtp_native::connect_with_config(&config.url, native_client_config(&config)).await?;
        let bootstrap = bootstrap_type_map();
        let offered = supported_versions();
        sender.set_type_map(&bootstrap).await;
        receiver.set_type_map(&bootstrap).await;
        let mut ident = CommunicationValue::new_with_type_map(
            mtp_codec::CommunicationType::Identification,
            &bootstrap,
        )
        .add_typed_default(DataType::Version, version_offer(&offered))
        .add_typed_default(
            DataType::Id,
            DataValue::UnsignedNumber(config.client_id.into()),
        );
        if let Some(desc) = &config.description {
            ident = ident.add_typed_default(DataType::Description, DataValue::Str(desc.clone()));
        }

        sender.send(&ident).await?;

        let (negotiated, codec) = select_codec(&sender, &receiver, &bootstrap, &offered).await?;

        let response = receiver.receive().await?;
        let outcome = parse_handshake_response(&response, codec.type_map())?;
        let (returned_version, assigned_id) = match outcome {
            mtp_common::HandshakeOutcome::Accepted {
                version,
                assigned_id,
            } => (
                Version::parse(&version).ok_or_else(|| {
                    CommunicationError::Other("host returned an invalid negotiated version".into())
                })?,
                assigned_id,
            ),
            mtp_common::HandshakeOutcome::Rejected { reason } => {
                sender.close().await;
                return Err(CommunicationError::Other(reason.to_string()));
            }
        };
        #[cfg(not(feature = "crypto"))]
        let _ = assigned_id;
        if returned_version != negotiated {
            sender.close().await;
            return Err(CommunicationError::Other(
                "host changed the negotiated protocol version".into(),
            ));
        }

        #[cfg(feature = "crypto")]
        let client_id = assigned_id;
        #[cfg(feature = "crypto")]
        return Ok(connection_from_parts(
            config,
            sender,
            receiver,
            negotiated,
            codec,
            error::AuthState::Unauthenticated,
            client_id,
        )
        .await);
        #[cfg(not(feature = "crypto"))]
        Ok(connection_from_parts(config, sender, receiver, negotiated, codec).await)
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
            mtp_native::connect_with_config(&config.url, native_client_config(&config)).await?;

        let bootstrap = bootstrap_type_map();
        let offered = supported_versions();
        sender.set_type_map(&bootstrap).await;
        receiver.set_type_map(&bootstrap).await;
        let public_key_bytes = keys
            .public_key_bundle()
            .try_as_bytes()
            .map_err(|error| CommunicationError::ParseError(error.to_string()))?;

        let mut ident =
            CommunicationValue::new_with_type_map(CommunicationType::Identification, &bootstrap)
                .add_typed_default(DataType::Version, version_offer(&offered))
                .add_typed_default(
                    DataType::Id,
                    DataValue::UnsignedNumber(config.client_id as u128),
                )
                // This capability marker lets a non-crypto host reject an
                // authentication attempt instead of treating it as a plain
                // unauthenticated connection.
                .add_typed_default(DataType::PublicKeys, DataValue::Bytes(public_key_bytes));
        if let Some(desc) = &config.description {
            ident = ident.add_typed_default(DataType::Description, DataValue::Str(desc.clone()));
        }
        if let Err(e) = sender.send(&ident).await {
            sender.close().await;
            return Err(e);
        }

        let (negotiated, handshake_codec) =
            select_codec(&sender, &receiver, &bootstrap, &offered).await?;
        let tm = handshake_codec.type_map().clone();
        let version_str = negotiated.to_string();

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
                sender.close().await;
                return Err(e);
            }
        };

        let client_nonce: u128 = rand::random();
        let proof_payload = mtp_crypto::auth::login_proof_payload(
            &version_str,
            config.description.as_deref(),
            config.client_id,
            server_challenge,
            client_nonce,
        );

        let proof =
            match crypto::signed_challenge_response(keys, proof_payload, client_nonce, &tm).await {
                Ok(p) => p,
                Err(e) => {
                    sender.close().await;
                    return Err(e);
                }
            };
        if let Err(e) = sender.send(&proof).await {
            sender.close().await;
            return Err(e);
        }

        let response = match receiver.receive().await {
            Ok(r) => r,
            Err(e) => {
                sender.close().await;
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
            sender.close().await;
            return Err(crypto::unexpected_response_type_error(
                "auth_connect",
                expected_type,
                &response,
            ));
        }
        if let Err(e) = crypto::check_connected(&response, "Server rejected authentication") {
            sender.close().await;
            return Err(e);
        }
        if let Err(e) = crypto::verify_host_final(
            &response,
            host_public_key_bundle,
            config.description.as_deref(),
            config.client_id,
            client_nonce,
            server_challenge,
            config.require_pq,
        )
        .await
        {
            sender.close().await;
            return Err(e);
        }

        let assigned_id = match response.get_data(DataType::Id) {
            Some(DataValue::UnsignedNumber(id)) => u64::try_from(*id).map_err(|_| {
                CommunicationError::AuthenticationFailed(
                    "host returned an out-of-range client id".into(),
                )
            })?,
            _ => {
                sender.close().await;
                return Err(CommunicationError::AuthenticationFailed(
                    "host omitted the authenticated client id".into(),
                ));
            }
        };
        if assigned_id != config.client_id {
            sender.close().await;
            return Err(CommunicationError::AuthenticationFailed(
                "host returned a different authenticated client id".into(),
            ));
        }

        let returned_version = crypto::negotiated_version(&response)?;
        if returned_version != negotiated {
            sender.close().await;
            return Err(CommunicationError::AuthenticationFailed(
                "host changed the negotiated protocol version".into(),
            ));
        }
        let codec = handshake_codec;
        let client_id = config.client_id;
        Ok(connection_from_parts(
            config,
            sender,
            receiver,
            negotiated,
            codec,
            error::AuthState::Authenticated,
            client_id,
        )
        .await)
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
            mtp_native::connect_with_config(&config.url, native_client_config(&config)).await?;

        let bootstrap = bootstrap_type_map();
        let offered = supported_versions();
        sender.set_type_map(&bootstrap).await;
        receiver.set_type_map(&bootstrap).await;
        let pk_bundle = keys.public_key_bundle();
        let pk_bytes = pk_bundle
            .try_as_bytes()
            .map_err(|error| CommunicationError::ParseError(error.to_string()))?;

        let mut register =
            CommunicationValue::new_with_type_map(CommunicationType::Register, &bootstrap)
                .add_typed_default(DataType::Version, version_offer(&offered))
                .add_typed_default(DataType::PublicKeys, DataValue::Bytes(pk_bytes.clone()));
        if let Some(desc) = &config.description {
            register =
                register.add_typed_default(DataType::Description, DataValue::Str(desc.clone()));
        }
        if let Err(e) = sender.send(&register).await {
            sender.close().await;
            return Err(e);
        }

        let (negotiated, handshake_codec) =
            select_codec(&sender, &receiver, &bootstrap, &offered).await?;
        let tm = handshake_codec.type_map().clone();
        let version_str = negotiated.to_string();

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
                sender.close().await;
                return Err(e);
            }
        };

        let client_nonce: u128 = rand::random();
        let proof_payload = mtp_crypto::auth::register_proof_payload(
            &version_str,
            config.description.as_deref(),
            &pk_bytes,
            server_challenge,
            client_nonce,
        );

        let proof =
            match crypto::signed_challenge_response(keys, proof_payload, client_nonce, &tm).await {
                Ok(p) => p,
                Err(e) => {
                    sender.close().await;
                    return Err(e);
                }
            };
        if let Err(e) = sender.send(&proof).await {
            sender.close().await;
            return Err(e);
        }

        let response = match receiver.receive().await {
            Ok(r) => r,
            Err(e) => {
                sender.close().await;
                return Err(e);
            }
        };
        let expected_type = CommunicationType::RegisterResponse
            .try_to_id(&tm)
            .ok_or_else(|| {
                CommunicationError::Other("RegisterResponse is absent from the type map".into())
            })?;
        if response.get_type() != expected_type {
            sender.close().await;
            return Err(crypto::unexpected_response_type_error(
                "auth_register",
                expected_type,
                &response,
            ));
        }
        if let Err(e) = crypto::check_connected(&response, "Server rejected registration") {
            sender.close().await;
            return Err(e);
        }
        let assigned_id = match response.get_data(DataType::Id) {
            Some(DataValue::UnsignedNumber(n)) => u64::try_from(*n).map_err(|_| {
                CommunicationError::AuthenticationFailed(
                    "host returned an out-of-range client id".into(),
                )
            })?,
            _ => {
                sender.close().await;
                return Err(CommunicationError::AuthenticationFailed(
                    "Missing assigned ID".into(),
                ));
            }
        };
        if let Err(e) = crypto::verify_host_final(
            &response,
            host_public_key_bundle,
            config.description.as_deref(),
            assigned_id,
            client_nonce,
            server_challenge,
            config.require_pq,
        )
        .await
        {
            sender.close().await;
            return Err(e);
        }

        let returned_version = crypto::negotiated_version(&response)?;
        if returned_version != negotiated {
            sender.close().await;
            return Err(CommunicationError::AuthenticationFailed(
                "host changed the negotiated protocol version".into(),
            ));
        }
        let codec = handshake_codec;
        Ok(connection_from_parts(
            config,
            sender,
            receiver,
            negotiated,
            codec,
            error::AuthState::Authenticated,
            assigned_id,
        )
        .await)
    }
}

/* ================================ TESTS ================================ */
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
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
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let dispatcher = pipe::PipeDispatcher {
            pending_requests: Mutex::new(mtp_common::RequestTracker::default()),
            #[cfg(feature = "pipes")]
            type_map: mtp_codec::TypeMap::latest(),
            #[cfg(feature = "pipes")]
            pending_creations: std::sync::Mutex::new(HashMap::new()),
            #[cfg(feature = "pipes")]
            expired_creations: std::sync::Mutex::new(mtp_common::ExpiringSet::new(
                Policy::default().pipe_tombstone_ttl.as_secs_f64() * 1000.0,
                Policy::default().pipe_tombstone_capacity,
            )),
            #[cfg(feature = "pipes")]
            pending_pipes: Mutex::new(HashMap::new()),
            #[cfg(feature = "pipes")]
            policy: Arc::new(Policy::default()),
        };
        let (app_tx, mut app_rx) = tokio::sync::mpsc::channel(2);
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        let _ = dispatcher.pending_requests.lock().await.insert(
            mtp_common::RequestId::new(7).unwrap(),
            pipe::PendingRequest {
                token: Arc::new(()),
                expected_type: None,
                sender: response_tx,
            },
            0.0,
        );

        let unrelated = CommunicationValue::new(mtp_codec::CommunicationType::Ping).with_id(8);
        assert!(pipe::route_message(unrelated, &app_tx, &dispatcher).await);
        assert_eq!(app_rx.recv().await.unwrap().unwrap().id(), Some(8));

        let response = CommunicationValue::new(mtp_codec::CommunicationType::Pong).with_id(7);
        assert!(pipe::route_message(response, &app_tx, &dispatcher).await);
        assert_eq!(response_rx.await.unwrap().unwrap().id(), Some(7));
        assert!(app_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_expired_request_response_is_consumed() {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let dispatcher = pipe::PipeDispatcher {
            pending_requests: Mutex::new(mtp_common::RequestTracker::default()),
            #[cfg(feature = "pipes")]
            type_map: mtp_codec::TypeMap::latest(),
            #[cfg(feature = "pipes")]
            pending_creations: std::sync::Mutex::new(HashMap::new()),
            #[cfg(feature = "pipes")]
            expired_creations: std::sync::Mutex::new(mtp_common::ExpiringSet::new(
                Policy::default().pipe_tombstone_ttl.as_secs_f64() * 1000.0,
                Policy::default().pipe_tombstone_capacity,
            )),
            #[cfg(feature = "pipes")]
            pending_pipes: Mutex::new(HashMap::new()),
            #[cfg(feature = "pipes")]
            policy: Arc::new(Policy::default()),
        };
        let token = Arc::new(());
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        let _ = dispatcher.pending_requests.lock().await.insert(
            mtp_common::RequestId::new(9).unwrap(),
            pipe::PendingRequest {
                token: token.clone(),
                expected_type: None,
                sender: response_tx,
            },
            0.0,
        );
        pipe::expire_pending_request(&dispatcher, mtp_common::RequestId::new(9).unwrap(), &token)
            .await;

        let (app_tx, mut app_rx) = tokio::sync::mpsc::channel(1);
        let response = CommunicationValue::new(mtp_codec::CommunicationType::Pong).with_id(9);
        assert!(pipe::route_message(response, &app_tx, &dispatcher).await);
        assert!(response_rx.await.is_err());
        assert!(app_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_dispatcher_routes_same_id_with_unexpected_type() {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let type_map = mtp_codec::TypeMap::latest();
        let expected_type = mtp_codec::CommunicationType::Pong
            .try_to_id(&type_map)
            .expect("Pong must be mapped");
        let dispatcher = pipe::PipeDispatcher {
            pending_requests: Mutex::new(mtp_common::RequestTracker::default()),
            #[cfg(feature = "pipes")]
            type_map: type_map.clone(),
            #[cfg(feature = "pipes")]
            pending_creations: std::sync::Mutex::new(HashMap::new()),
            #[cfg(feature = "pipes")]
            expired_creations: std::sync::Mutex::new(mtp_common::ExpiringSet::new(
                Policy::default().pipe_tombstone_ttl.as_secs_f64() * 1000.0,
                Policy::default().pipe_tombstone_capacity,
            )),
            #[cfg(feature = "pipes")]
            pending_pipes: Mutex::new(HashMap::new()),
            #[cfg(feature = "pipes")]
            policy: Arc::new(Policy::default()),
        };
        let (app_tx, mut app_rx) = tokio::sync::mpsc::channel(2);
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        let request_id = mtp_common::RequestId::new(42).unwrap();
        let _ = dispatcher.pending_requests.lock().await.insert(
            request_id,
            pipe::PendingRequest {
                token: Arc::new(()),
                expected_type: Some(expected_type),
                sender: response_tx,
            },
            0.0,
        );

        let unrelated = CommunicationValue::new(mtp_codec::CommunicationType::Ping).with_id(42);
        assert!(pipe::route_message(unrelated, &app_tx, &dispatcher).await);
        assert_eq!(app_rx.recv().await.unwrap().unwrap().id(), Some(42));
        assert!(
            dispatcher
                .pending_requests
                .lock()
                .await
                .pending
                .contains_key(&request_id)
        );

        let response = CommunicationValue::new(mtp_codec::CommunicationType::Pong).with_id(42);
        assert!(pipe::route_message(response, &app_tx, &dispatcher).await);
        assert_eq!(
            response_rx.await.unwrap().unwrap().get_type(),
            expected_type
        );
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
