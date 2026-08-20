//! Transport-independent MTP handshake engine.
//!
//! This module contains the shared state machine used by both native `MTPHost`
//! and the web server's `MTPWebServer` to perform the MTP opening handshake,
//! version negotiation, authentication, and guest assignment.

use crate::config::{AuthenticationContext, HostConfig};
use crate::error::AcceptError;
use mtp_codec::{
    CommunicationType, CommunicationValue, DataType, DataValue, TypeMap, Version,
    registry::{Registry, VersionedCodec},
};
use mtp_common::{CommunicationError, RejectionReason};
#[cfg(feature = "crypto")]
use std::collections::HashSet;
use std::sync::Arc;
#[cfg(feature = "crypto")]
use std::sync::Mutex;

/// Trait for sending handshake messages during the opening exchange.
///
/// Implemented by both the concrete `Sender` and `GenericSender<C>`.
pub trait HandshakeSender: Send + Sync {
    fn send(
        &self,
        msg: &CommunicationValue,
    ) -> impl std::future::Future<Output = Result<(), CommunicationError>> + Send;
    fn finish_stream(
        &self,
    ) -> impl std::future::Future<Output = Result<(), CommunicationError>> + Send;
    fn set_type_map(&self, _type_map: &TypeMap) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }
    fn close(&self);
}

/// Trait for receiving handshake messages during the opening exchange.
///
/// Implemented by both the concrete `Receiver` and `GenericReceiver<C>`.
pub trait HandshakeReceiver: Send + Sync {
    fn receive(
        &self,
    ) -> impl std::future::Future<Output = Result<CommunicationValue, CommunicationError>> + Send;

    /// Bind subsequently decoded frames to the negotiated type map.
    ///
    /// The opening frame must be decoded with the transport's bootstrap map so
    /// that it can reveal the version. Once negotiation succeeds, all later
    /// frames—including the remainder of the authentication exchange—must use
    /// the negotiated map rather than whichever map happens to be latest at
    /// compile time.
    fn set_type_map(&self, _type_map: &TypeMap) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }
}

/// A non-zero guest ID reserved for the lifetime of a connected session.
///
/// The lease is moved into the resulting `MTPConnection`, so dropping that
/// connection releases the ID for a later guest session.
#[cfg(feature = "crypto")]
#[derive(Debug)]
pub struct GuestIdLease {
    active_ids: Arc<Mutex<HashSet<u64>>>,
    id: u64,
}

#[cfg(feature = "crypto")]
impl Drop for GuestIdLease {
    fn drop(&mut self) {
        if let Ok(mut active_ids) = self.active_ids.lock() {
            active_ids.remove(&self.id);
        }
    }
}

/// The result of a successful handshake, containing everything needed to
/// construct the final `MTPConnection`.
#[derive(Debug)]
pub struct HandshakeResult {
    pub negotiated_version: Version,
    pub codec: VersionedCodec,
    pub description: Option<String>,
    #[cfg(feature = "crypto")]
    pub auth_state: crate::error::AuthState,
    #[cfg(feature = "crypto")]
    pub client_id: u64,
    #[cfg(feature = "crypto")]
    pub client_public_key: Option<mtp_crypto::PublicKeyBundle>,
    #[cfg(feature = "crypto")]
    pub guest_id_lease: Option<GuestIdLease>,
}

/// Transport-independent handshake state machine.
///
/// Both `MTPHost` and `MTPWebServer` create a `HandshakeEngine` with the
/// shared `HostConfig` and delegate the full opening handshake to it.
pub struct HandshakeEngine {
    registry: Registry,
    #[cfg(feature = "crypto")]
    config: Arc<HostConfig>,
}

impl HandshakeEngine {
    #[cfg(feature = "crypto")]
    pub fn new(registry: Registry, config: Arc<HostConfig>) -> Self {
        Self { registry, config }
    }

    #[cfg(not(feature = "crypto"))]
    pub fn new(registry: Registry, _config: Arc<HostConfig>) -> Self {
        Self { registry }
    }

    /// Run the complete opening handshake with the given transport pair.
    ///
    /// This handles:
    /// - Opening-frame timeout (when crypto is enabled)
    /// - Opening-type classification (Identification, Register, or other)
    /// - Version negotiation
    /// - Authentication-policy selection (Unauthenticated, AllowAuthentication, ForceAuthentication)
    /// - Guest allocation and collision avoidance
    /// - Full challenge/response authentication when required
    /// - PQ preflight checks and dual-signature verification
    /// - Rejection response construction on failure
    pub async fn accept<S: HandshakeSender, R: HandshakeReceiver>(
        &self,
        sender: &S,
        receiver: &R,
    ) -> Result<HandshakeResult, AcceptError> {
        self.accept_with_context(sender, receiver, AuthenticationContext::default())
            .await
    }

    /// Run the opening handshake with transport-provided authentication
    /// scoping information.
    pub async fn accept_with_context<S: HandshakeSender, R: HandshakeReceiver>(
        &self,
        sender: &S,
        receiver: &R,
        context: AuthenticationContext,
    ) -> Result<HandshakeResult, AcceptError> {
        #[cfg(feature = "crypto")]
        {
            self.accept_until_with_context(
                sender,
                receiver,
                tokio::time::Instant::now() + self.config.auth_timeout,
                context,
            )
            .await
        }
        #[cfg(not(feature = "crypto"))]
        {
            let result = self.accept_inner(sender, receiver, &context).await;
            if result.is_err() {
                sender.close();
            }
            result
        }
    }

    /// Run the crypto handshake until an absolute deadline.
    ///
    /// WebTransport authentication may wait for a shared semaphore before it
    /// reaches this engine. Passing the deadline through keeps that queueing
    /// time from silently granting the handshake another full timeout.
    #[cfg(feature = "crypto")]
    pub async fn accept_until<S: HandshakeSender, R: HandshakeReceiver>(
        &self,
        sender: &S,
        receiver: &R,
        deadline: tokio::time::Instant,
    ) -> Result<HandshakeResult, AcceptError> {
        self.accept_until_with_context(sender, receiver, deadline, AuthenticationContext::default())
            .await
    }

    /// Run the crypto handshake until a deadline with transport-provided
    /// authentication scoping information.
    #[cfg(feature = "crypto")]
    pub async fn accept_until_with_context<S: HandshakeSender, R: HandshakeReceiver>(
        &self,
        sender: &S,
        receiver: &R,
        deadline: tokio::time::Instant,
        context: AuthenticationContext,
    ) -> Result<HandshakeResult, AcceptError> {
        match tokio::time::timeout_at(deadline, self.accept_inner(sender, receiver, &context)).await
        {
            Ok(result) => {
                if result.is_err() {
                    sender.close();
                }
                result
            }
            Err(_) => {
                let error = AcceptError::AuthenticationTimedOut;
                send_rejection_generic(
                    sender,
                    RejectionReason::AuthenticationFailed {
                        detail: error.to_string(),
                    },
                    None,
                )
                .await;
                sender.close();
                Err(error)
            }
        }
    }

    async fn accept_inner<S: HandshakeSender, R: HandshakeReceiver>(
        &self,
        sender: &S,
        receiver: &R,
        _authentication_context: &AuthenticationContext,
    ) -> Result<HandshakeResult, AcceptError> {
        let mut first_msg = receiver.receive().await.map_err(AcceptError::Receive)?;
        tracing::debug!(
            message_type = ?first_msg.get_type(),
            version = ?first_msg.get_str(DataType::Version),
            client_id = ?first_msg.get_data(DataType::Id),
            "received MTP opening message"
        );

        let version_str = match first_msg.get_data(DataType::Version) {
            Some(DataValue::Str(s)) => s.clone(),
            _ => {
                send_rejection_generic(
                    sender,
                    RejectionReason::AuthenticationFailed {
                        detail: "opening message omitted a valid protocol version".into(),
                    },
                    None,
                )
                .await;
                sender.close();
                return Err(AcceptError::MissingVersion);
            }
        };
        let client_version = match Version::parse(&version_str) {
            Some(v) => v,
            _ => {
                send_rejection_generic(
                    sender,
                    RejectionReason::AuthenticationFailed {
                        detail: "opening message omitted a valid protocol version".into(),
                    },
                    None,
                )
                .await;
                sender.close();
                return Err(AcceptError::MissingVersion);
            }
        };

        let negotiated = match self
            .registry
            .negotiate(std::slice::from_ref(&client_version))
        {
            Some(v) => v,
            None => {
                send_rejection_generic(
                    sender,
                    RejectionReason::BadVersion {
                        supported_versions: self
                            .registry
                            .versions()
                            .map(|v| v.to_string())
                            .collect(),
                    },
                    None,
                )
                .await;
                sender.close();
                return Err(AcceptError::UnsupportedVersion(client_version));
            }
        };
        tracing::debug!(
            client_version = %client_version,
            negotiated_version = %negotiated,
            "MTP protocol version negotiated"
        );

        let codec = VersionedCodec::for_version(self.registry.clone(), negotiated.clone())
            .ok_or_else(|| AcceptError::UnsupportedVersion(negotiated.clone()))?;

        sender.set_type_map(codec.type_map()).await;
        receiver.set_type_map(codec.type_map()).await;
        first_msg.set_type_map(codec.type_map());

        let description = match first_msg.get_data(DataType::Description) {
            Some(DataValue::Str(s)) => Some(s.clone()),
            _ => None,
        };

        #[cfg(feature = "crypto")]
        {
            let claimed_client_id = match first_msg.get_data(DataType::Id) {
                Some(DataValue::UnsignedNumber(value)) => u64::try_from(*value).ok(),
                _ => None,
            };
            let registration = Some(first_msg.get_type())
                == CommunicationType::Register.try_to_id(codec.type_map());
            let authentication_requested = matches!(
                self.config.authentication_policy,
                crate::config::AuthenticationPolicy::ForceAuthentication
            ) || registration
                || first_msg.get_data(DataType::PublicKeys).is_some()
                || claimed_client_id.is_some_and(|client_id| client_id != 0);
            if authentication_requested {
                let attempt = crate::config::AuthenticationAttempt {
                    peer_network_identity: _authentication_context.peer_network_identity.clone(),
                    connection_id: _authentication_context.connection_id,
                    claimed_client_id,
                    registration,
                };
                match self.config.auth_limiter.allow(&attempt) {
                    Ok(true) => {}
                    Ok(false) | Err(_) => {
                        let error =
                            AcceptError::AuthenticationFailed("authentication rejected".into());
                        send_rejection_generic(
                            sender,
                            RejectionReason::RateLimited,
                            Some(codec.type_map()),
                        )
                        .await;
                        sender.close();
                        return Err(error);
                    }
                }
            }

            match self.config.authentication_policy {
                crate::config::AuthenticationPolicy::ForceAuthentication => {
                    self.force_auth_handshake(
                        sender,
                        receiver,
                        first_msg,
                        negotiated,
                        codec,
                        description,
                        &version_str,
                        client_version,
                    )
                    .await
                }
                crate::config::AuthenticationPolicy::AllowAuthentication => {
                    self.allow_auth_handshake(
                        sender,
                        receiver,
                        first_msg,
                        negotiated,
                        codec,
                        description,
                        &version_str,
                        client_version,
                    )
                    .await
                }
                crate::config::AuthenticationPolicy::Unauthenticated => {
                    self.unauthenticated_handshake(
                        sender,
                        first_msg,
                        negotiated,
                        codec,
                        description,
                    )
                    .await
                }
            }
        }

        #[cfg(not(feature = "crypto"))]
        {
            let authentication_requested = Some(first_msg.get_type())
                == CommunicationType::Register.try_to_id(codec.type_map())
                || first_msg.get_data(DataType::PublicKeys).is_some();
            if authentication_requested {
                let error = AcceptError::AuthenticationFailed(
                    "authentication is unavailable on this non-crypto host".into(),
                );
                send_rejection_generic(
                    sender,
                    RejectionReason::AuthenticationFailed {
                        detail: error.to_string(),
                    },
                    Some(codec.type_map()),
                )
                .await;
                sender.close();
                return Err(error);
            }
            let _ = receiver;
            send_accepted_generic(sender, &negotiated, codec.type_map(), Some(0))
                .await
                .map_err(AcceptError::Send)?;
            Ok(HandshakeResult {
                negotiated_version: negotiated,
                codec,
                description,
            })
        }
    }

    #[cfg(feature = "crypto")]
    async fn unauthenticated_handshake<S: HandshakeSender>(
        &self,
        sender: &S,
        first_msg: CommunicationValue,
        negotiated: Version,
        codec: VersionedCodec,
        description: Option<String>,
    ) -> Result<HandshakeResult, AcceptError> {
        let tm = codec.type_map();

        // Reject explicit authentication attempts on unauthenticated hosts.
        // Authenticated clients include PublicKeys in Identification as an
        // intent marker; this avoids acknowledging the opening as a guest
        // connection and leaving the client waiting for a Challenge.
        if Some(first_msg.get_type()) == CommunicationType::Register.try_to_id(tm)
            || first_msg.get_data(DataType::PublicKeys).is_some()
        {
            send_rejection_generic(
                sender,
                RejectionReason::AuthenticationFailed {
                    detail: "authentication not allowed on this host".into(),
                },
                Some(tm),
            )
            .await;
            sender.close();
            return Err(AcceptError::AuthenticationFailed(
                "authentication not allowed on this host".into(),
            ));
        }

        let guest_id_lease = match self.assign_guest_id().await {
            Ok(lease) => lease,
            Err(error) => {
                reject_error_generic(sender, &error, tm).await;
                return Err(error);
            }
        };
        let guest_id = guest_id_lease.id;
        send_accepted_generic(sender, &negotiated, tm, Some(guest_id))
            .await
            .map_err(AcceptError::Send)?;

        Ok(HandshakeResult {
            negotiated_version: negotiated,
            codec,
            description,
            auth_state: crate::error::AuthState::Unauthenticated,
            client_id: guest_id,
            client_public_key: None,
            guest_id_lease: Some(guest_id_lease),
        })
    }

    #[cfg(feature = "crypto")]
    #[allow(clippy::too_many_arguments)]
    async fn allow_auth_handshake<S: HandshakeSender, R: HandshakeReceiver>(
        &self,
        sender: &S,
        receiver: &R,
        first_msg: CommunicationValue,
        negotiated: Version,
        codec: VersionedCodec,
        description: Option<String>,
        version_str: &str,
        client_version: Version,
    ) -> Result<HandshakeResult, AcceptError> {
        let tm = codec.type_map();

        // Register frames always go through full authentication
        if Some(first_msg.get_type()) == CommunicationType::Register.try_to_id(tm) {
            let bundle = match extract_register_bundle(&first_msg) {
                Ok(bundle) => bundle,
                Err(error) => {
                    reject_error_generic(sender, &error, tm).await;
                    return Err(error);
                }
            };
            let pk_bytes = match bundle.try_as_bytes() {
                Ok(bytes) => bytes,
                Err(error) => {
                    let error = AcceptError::AuthenticationFailed(error.to_string());
                    reject_error_generic(sender, &error, tm).await;
                    return Err(error);
                }
            };
            return self
                .complete_auth_handshake(
                    sender,
                    receiver,
                    Flow::Register { bundle, pk_bytes },
                    CommunicationType::RegisterResponse,
                    &negotiated,
                    &codec,
                    description,
                    version_str,
                    client_version,
                )
                .await;
        }

        // Identification: try lookup, fall back to guest
        if Some(first_msg.get_type()) == CommunicationType::Identification.try_to_id(tm) {
            let cid = match first_msg.get_data(DataType::Id) {
                Some(DataValue::UnsignedNumber(n)) => u64::try_from(*n).unwrap_or(0),
                _ => 0,
            };

            if cid > 0
                && let Some(bundle) =
                    (self.config.get_existing_client)(cid, description.clone()).await
            {
                return self
                    .complete_auth_handshake(
                        sender,
                        receiver,
                        Flow::Login { id: cid, bundle },
                        CommunicationType::IdentificationResponse,
                        &negotiated,
                        &codec,
                        description,
                        version_str,
                        client_version,
                    )
                    .await;
            }

            // Unknown or zero ID: an Identification carrying PublicKeys is an
            // explicit authentication attempt, not a guest connection.
            if first_msg.get_data(DataType::PublicKeys).is_some() {
                if self.config.conceal_authentication_identities && cid > 0 {
                    /* Keep an unknown authenticated ID on the same
                    challenge/proof path as a known ID. The fixed host
                    identity makes the eventual proof fail without
                    disclosing whether the lookup succeeded. */
                    return self
                        .complete_auth_handshake(
                            sender,
                            receiver,
                            Flow::Login {
                                id: cid,
                                bundle: self.config.host_keyring.public_key_bundle(),
                            },
                            CommunicationType::IdentificationResponse,
                            &negotiated,
                            &codec,
                            description,
                            version_str,
                            client_version,
                        )
                        .await;
                }
                let error = AcceptError::AuthenticationFailed(
                    "unknown authenticated client identity".into(),
                );
                reject_error_generic(sender, &error, tm).await;
                return Err(error);
            }

            // Unknown or zero ID: fall back to guest
            let guest_id_lease = match self.assign_guest_id().await {
                Ok(lease) => lease,
                Err(error) => {
                    reject_error_generic(sender, &error, tm).await;
                    return Err(error);
                }
            };
            let guest_id = guest_id_lease.id;
            send_accepted_generic(sender, &negotiated, tm, Some(guest_id))
                .await
                .map_err(AcceptError::Send)?;
            return Ok(HandshakeResult {
                negotiated_version: negotiated,
                codec,
                description,
                auth_state: crate::error::AuthState::Unauthenticated,
                client_id: guest_id,
                client_public_key: None,
                guest_id_lease: Some(guest_id_lease),
            });
        }

        let error = AcceptError::AuthenticationFailed("unexpected message type".into());
        reject_error_generic(sender, &error, tm).await;
        Err(error)
    }

    #[cfg(feature = "crypto")]
    #[allow(clippy::too_many_arguments)]
    async fn force_auth_handshake<S: HandshakeSender, R: HandshakeReceiver>(
        &self,
        sender: &S,
        receiver: &R,
        first_msg: CommunicationValue,
        negotiated: Version,
        codec: VersionedCodec,
        description: Option<String>,
        version_str: &str,
        client_version: Version,
    ) -> Result<HandshakeResult, AcceptError> {
        let tm = codec.type_map();

        let (flow, response_type) = if Some(first_msg.get_type())
            == CommunicationType::Identification.try_to_id(tm)
        {
            let cid = match first_msg.get_data(DataType::Id) {
                Some(DataValue::UnsignedNumber(n)) => match u64::try_from(*n) {
                    Ok(id) => id,
                    Err(_) => {
                        let error =
                            AcceptError::AuthenticationFailed("client id is out of range".into());
                        reject_error_generic(sender, &error, tm).await;
                        return Err(error);
                    }
                },
                _ => {
                    let error = AcceptError::AuthenticationFailed("missing client id".into());
                    reject_error_generic(sender, &error, tm).await;
                    return Err(error);
                }
            };
            let bundle = match (self.config.get_existing_client)(cid, description.clone()).await {
                Some(b) => b,
                None => {
                    if self.config.conceal_authentication_identities {
                        // Use a valid fixed-cost dummy identity so an unknown
                        // client follows the same challenge/proof sequence as
                        // a registered client. The host public bundle is
                        // already public and the peer cannot produce its
                        // private-key proof.
                        self.config.host_keyring.public_key_bundle()
                    } else {
                        let rejection = CommunicationValue::new_with_type_map(
                            CommunicationType::IdentificationResponse,
                            tm,
                        )
                        .add_typed_default(DataType::Connected, DataValue::BoolFalse)
                        .add_typed_default(
                            DataType::ErrorMessage,
                            DataValue::Str("unknown client id".into()),
                        );
                        let _ = sender.send(&rejection).await;
                        sender.close();
                        return Err(AcceptError::AuthenticationFailed(
                            "unknown client id".into(),
                        ));
                    }
                }
            };
            (
                Flow::Login { id: cid, bundle },
                CommunicationType::IdentificationResponse,
            )
        } else if Some(first_msg.get_type()) == CommunicationType::Register.try_to_id(tm) {
            let bundle = match extract_register_bundle(&first_msg) {
                Ok(bundle) => bundle,
                Err(error) => {
                    reject_error_generic(sender, &error, tm).await;
                    return Err(error);
                }
            };
            let pk_bytes = match bundle.try_as_bytes() {
                Ok(bytes) => bytes,
                Err(error) => {
                    let error = AcceptError::AuthenticationFailed(error.to_string());
                    reject_error_generic(sender, &error, tm).await;
                    return Err(error);
                }
            };
            (
                Flow::Register { bundle, pk_bytes },
                CommunicationType::RegisterResponse,
            )
        } else {
            let error =
                AcceptError::AuthenticationFailed("unexpected authentication message".into());
            reject_error_generic(sender, &error, tm).await;
            return Err(error);
        };

        self.complete_auth_handshake(
            sender,
            receiver,
            flow,
            response_type,
            &negotiated,
            &codec,
            description,
            version_str,
            client_version,
        )
        .await
    }

    #[cfg(feature = "crypto")]
    #[allow(clippy::too_many_arguments)]
    async fn complete_auth_handshake<S: HandshakeSender, R: HandshakeReceiver>(
        &self,
        sender: &S,
        receiver: &R,
        flow: Flow,
        response_type: CommunicationType,
        negotiated: &Version,
        codec: &VersionedCodec,
        description: Option<String>,
        version_str: &str,
        _client_version: Version,
    ) -> Result<HandshakeResult, AcceptError> {
        use mtp_crypto::{Ed25519Signer, MlDsaSigner, SignatureScheme, auth, verify_ed25519};

        let tm = codec.type_map();

        // PQ preflight: host requiring PQ must have a PQ key
        let pq_enabled = !self
            .config
            .host_keyring
            .sig_pq_secret_key
            .as_bytes()
            .is_empty();
        if self.config.require_pq
            && (!pq_enabled
                || self
                    .config
                    .host_keyring
                    .sig_pq_public_key
                    .as_bytes()
                    .is_empty())
        {
            send_rejection_generic(
                sender,
                RejectionReason::AuthenticationFailed {
                    detail: "host requires PQ authentication but has no PQ signing key".into(),
                },
                Some(tm),
            )
            .await;
            sender.close();
            return Err(AcceptError::AuthenticationFailed(
                "PQ authentication is required but the host PQ key is absent".into(),
            ));
        }

        // Initialize host signers
        let host_pq_signer = if pq_enabled {
            Some(Arc::new(
                match MlDsaSigner::new(
                    &self.config.host_keyring.sig_pq_secret_key,
                    &self.config.host_keyring.sig_pq_public_key,
                ) {
                    Ok(signer) => signer,
                    Err(error) => {
                        let error = AcceptError::AuthenticationFailed(error.to_string());
                        reject_error_generic(sender, &error, tm).await;
                        return Err(error);
                    }
                },
            ))
        } else {
            None
        };

        let host_sign = |payload: Vec<u8>| async {
            let signer = Ed25519Signer::new(&self.config.host_keyring.sig_cl_secret_key)
                .map_err(|e| AcceptError::AuthenticationFailed(e.to_string()))?;
            if let Some(pq_signer) = host_pq_signer.as_ref() {
                mtp_crypto::sign_parallel::sign_dual_parallel_shared_pq(
                    signer,
                    Arc::clone(pq_signer),
                    payload,
                )
                .await
                .map_err(|e| AcceptError::AuthenticationFailed(e.to_string()))
            } else {
                let sig = signer
                    .sign(&payload)
                    .map_err(|e| AcceptError::AuthenticationFailed(e.to_string()))?;
                Ok((sig, Vec::new()))
            }
        };

        // Sign and send challenge
        let challenge_id = match &flow {
            Flow::Login { id, .. } => *id,
            Flow::Register { .. } => 0,
        };

        let server_challenge: u128 = rand::random();
        let (chal_sig, chal_pq_sig) =
            match host_sign(auth::challenge_payload(challenge_id, server_challenge)).await {
                Ok(signatures) => signatures,
                Err(error) => {
                    reject_error_generic(sender, &error, tm).await;
                    return Err(error);
                }
            };

        let mut challenge_msg =
            CommunicationValue::new_with_type_map(CommunicationType::Challenge, tm)
                .add_typed_default(
                    DataType::ServerNonce,
                    DataValue::UnsignedNumber(server_challenge),
                )
                .add_typed_default(DataType::Signature, DataValue::Bytes(chal_sig));
        challenge_msg = challenge_msg.add_typed_default(
            DataType::RequirePq,
            if self.config.require_pq {
                DataValue::BoolTrue
            } else {
                DataValue::BoolFalse
            },
        );
        if pq_enabled {
            challenge_msg = challenge_msg
                .add_typed_default(DataType::PqSignature, DataValue::Bytes(chal_pq_sig));
        }
        if let Err(e) = sender.send(&challenge_msg).await {
            sender.close();
            return Err(AcceptError::Send(e));
        }

        // Receive and verify client proof
        let proof = receiver.receive().await.map_err(|e| {
            sender.close();
            AcceptError::Receive(e)
        })?;
        if Some(proof.get_type()) != CommunicationType::ChallengeResponse.try_to_id(tm) {
            let error = AcceptError::AuthenticationFailed("missing challenge response".into());
            reject_error_generic(sender, &error, tm).await;
            return Err(error);
        }
        let client_nonce = match proof.get_data(DataType::ClientNonce) {
            Some(DataValue::UnsignedNumber(n)) => *n,
            _ => {
                let error = AcceptError::AuthenticationFailed("missing client nonce".into());
                reject_error_generic(sender, &error, tm).await;
                return Err(error);
            }
        };
        let sig_bytes = match proof.get_data(DataType::Signature) {
            Some(DataValue::Bytes(b)) => b.clone(),
            _ => {
                let error = AcceptError::AuthenticationFailed("missing challenge signature".into());
                reject_error_generic(sender, &error, tm).await;
                return Err(error);
            }
        };
        let pq_sig_bytes: Vec<u8> = match proof.get_data(DataType::PqSignature) {
            Some(DataValue::Bytes(b)) => b.clone(),
            _ => vec![],
        };

        let (proof_payload, bundle) = match &flow {
            Flow::Login { id, bundle } => (
                auth::login_proof_payload(version_str, *id, server_challenge, client_nonce),
                bundle,
            ),
            Flow::Register {
                bundle, pk_bytes, ..
            } => (
                auth::register_proof_payload(version_str, pk_bytes, server_challenge, client_nonce),
                bundle,
            ),
        };

        let has_client_pq_key = !bundle.sig_pq_public_key.as_bytes().is_empty();
        let proof_ok = if pq_sig_bytes.is_empty() {
            !self.config.require_pq
                && verify_ed25519(&bundle.sig_cl_public_key, &proof_payload, &sig_bytes).is_ok()
        } else if has_client_pq_key {
            mtp_crypto::sign_parallel::verify_dual_parallel(
                bundle.sig_cl_public_key.clone(),
                bundle.sig_pq_public_key.clone(),
                proof_payload,
                sig_bytes,
                pq_sig_bytes,
            )
            .await
            .is_ok()
        } else {
            false
        };

        if !proof_ok {
            send_rejection_generic(
                sender,
                RejectionReason::AuthenticationFailed {
                    detail: "client proof signature invalid".into(),
                },
                Some(tm),
            )
            .await;
            sender.close();
            return Err(AcceptError::AuthenticationFailed(
                "client proof signature invalid".into(),
            ));
        }

        // Register or login
        let (assigned_id, client_bundle) = match flow {
            Flow::Login { id, bundle } => (id, bundle),
            Flow::Register { bundle, .. } => {
                let _registration_guard = self.config.registration_lock.lock().await;
                let identity = match bundle.try_as_bytes() {
                    Ok(identity) => identity,
                    Err(error) => {
                        let error = AcceptError::AuthenticationFailed(error.to_string());
                        reject_error_generic(sender, &error, tm).await;
                        return Err(error);
                    }
                };
                let cached_id = self
                    .config
                    .registration_ids
                    .lock()
                    .ok()
                    .and_then(|registrations| registrations.get(&identity).copied());
                let new_id = if let Some(id) = cached_id {
                    id
                } else if let Some(lookup) = &self.config.find_registered_client {
                    match lookup(bundle.clone(), description.clone()).await {
                        Some(id) => id,
                        None => {
                            (self.config.complete_register)(bundle.clone(), description.clone())
                                .await
                        }
                    }
                } else {
                    (self.config.complete_register)(bundle.clone(), description.clone()).await
                };
                if new_id != 0
                    && let Ok(mut registrations) = self.config.registration_ids.lock()
                {
                    registrations.insert(identity, new_id);
                }
                if new_id == 0 {
                    let error = AcceptError::AuthenticationFailed(
                        "registration callback returned reserved client id 0".into(),
                    );
                    reject_error_generic(sender, &error, tm).await;
                    return Err(error);
                }
                (new_id, bundle)
            }
        };
        if assigned_id == 0 {
            let error = AcceptError::AuthenticationFailed(
                "client id 0 is reserved for no authenticated identity".into(),
            );
            reject_error_generic(sender, &error, tm).await;
            return Err(error);
        }

        // Sign and send final response
        let (host_sig, host_pq_sig) = match host_sign(auth::host_final_payload(
            assigned_id,
            client_nonce,
            server_challenge,
        ))
        .await
        {
            Ok(signatures) => signatures,
            Err(error) => {
                reject_error_generic(sender, &error, tm).await;
                return Err(error);
            }
        };

        let mut response = CommunicationValue::new_with_type_map(response_type, tm)
            .add_typed_default(DataType::Connected, DataValue::BoolTrue)
            .add_typed_default(DataType::Id, DataValue::UnsignedNumber(assigned_id as u128))
            .add_typed_default(
                DataType::ClientNonce,
                DataValue::UnsignedNumber(client_nonce),
            )
            .add_typed_default(DataType::Signature, DataValue::Bytes(host_sig));
        response =
            response.add_typed_default(DataType::Version, DataValue::Str(negotiated.to_string()));
        if pq_enabled {
            response =
                response.add_typed_default(DataType::PqSignature, DataValue::Bytes(host_pq_sig));
        }

        if let Err(e) = sender.send(&response).await {
            sender.close();
            return Err(AcceptError::Send(e));
        }
        if let Err(e) = sender.finish_stream().await {
            sender.close();
            return Err(AcceptError::Send(e));
        }

        Ok(HandshakeResult {
            negotiated_version: negotiated.clone(),
            codec: codec.clone(),
            description,
            auth_state: crate::error::AuthState::Authenticated,
            client_id: assigned_id,
            client_public_key: Some(client_bundle),
            guest_id_lease: None,
        })
    }
}

#[cfg(feature = "crypto")]
enum Flow {
    Login {
        id: u64,
        bundle: mtp_crypto::PublicKeyBundle,
    },
    Register {
        bundle: mtp_crypto::PublicKeyBundle,
        pk_bytes: Vec<u8>,
    },
}

// ---------------------------------------------------------------------------
// Guest ID allocation
// ---------------------------------------------------------------------------

#[cfg(feature = "crypto")]
impl HandshakeEngine {
    const GUEST_ID_MAX_RETRIES: u32 = 100;

    async fn assign_guest_id(&self) -> Result<GuestIdLease, AcceptError> {
        if let Some(ref generator) = self.config.guest_id_generator {
            let id = generator().await.ok_or_else(|| {
                AcceptError::AuthenticationFailed(
                    "guest id generator rejected the connection".into(),
                )
            })?;
            if id == 0 {
                return Err(AcceptError::AuthenticationFailed(
                    "guest id 0 is reserved for no authenticated identity".into(),
                ));
            }
            if let Some(lease) = self.try_reserve_guest_id(id).await? {
                return Ok(lease);
            }
        }
        self.random_guest_id().await
    }

    async fn random_guest_id(&self) -> Result<GuestIdLease, AcceptError> {
        for _ in 0..Self::GUEST_ID_MAX_RETRIES {
            let id = rand::random::<u64>();
            if let Some(lease) = self.try_reserve_guest_id(id).await? {
                return Ok(lease);
            }
        }
        Err(AcceptError::AuthenticationFailed(
            "failed to allocate a unique guest id after retries".into(),
        ))
    }

    async fn try_reserve_guest_id(&self, id: u64) -> Result<Option<GuestIdLease>, AcceptError> {
        if id == 0 || (self.config.get_existing_client)(id, None).await.is_some() {
            return Ok(None);
        }
        let mut active_ids = self.config.active_guest_ids.lock().map_err(|_| {
            AcceptError::AuthenticationFailed("guest ID registry is poisoned".into())
        })?;
        if !active_ids.insert(id) {
            return Ok(None);
        }
        Ok(Some(GuestIdLease {
            active_ids: Arc::clone(&self.config.active_guest_ids),
            id,
        }))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[cfg(feature = "crypto")]
fn extract_register_bundle(
    msg: &CommunicationValue,
) -> Result<mtp_crypto::PublicKeyBundle, AcceptError> {
    match msg.get_data(DataType::PublicKeys) {
        Some(DataValue::Bytes(b)) => mtp_crypto::PublicKeyBundle::from_bytes(b)
            .map_err(|_| AcceptError::AuthenticationFailed("invalid public key bundle".into())),
        _ => Err(AcceptError::AuthenticationFailed(
            "missing public keys".into(),
        )),
    }
}

async fn send_rejection_generic<S: HandshakeSender>(
    sender: &S,
    reason: RejectionReason,
    type_map: Option<&TypeMap>,
) {
    let type_map = type_map.cloned().unwrap_or_else(TypeMap::latest);
    let response = match &reason {
        RejectionReason::BadVersion { supported_versions } => {
            CommunicationValue::new_with_type_map(CommunicationType::ErrorBadVersion, &type_map)
                .add_typed_default(
                    DataType::Version,
                    DataValue::Str(supported_versions.join(",")),
                )
                .add_typed_default(DataType::ErrorMessage, DataValue::Str(reason.to_string()))
        }
        _ => CommunicationValue::new_with_type_map(
            CommunicationType::IdentificationResponse,
            &type_map,
        )
        .add_typed_default(DataType::Connected, DataValue::BoolFalse)
        .add_typed_default(DataType::ErrorMessage, DataValue::Str(reason.to_string())),
    };
    tracing::debug!(
        reason = %reason,
        response_type = ?response.get_type(),
        has_version = response.get_data(DataType::Version).is_some(),
        "sending MTP handshake rejection"
    );
    let _ = sender.send(&response).await;
}

#[cfg(feature = "crypto")]
async fn reject_error_generic<S: HandshakeSender>(
    sender: &S,
    error: &AcceptError,
    type_map: &TypeMap,
) {
    send_rejection_generic(
        sender,
        RejectionReason::AuthenticationFailed {
            detail: error.to_string(),
        },
        Some(type_map),
    )
    .await;
    sender.close();
}

async fn send_accepted_generic<S: HandshakeSender>(
    sender: &S,
    version: &Version,
    type_map: &TypeMap,
    assigned_id: Option<u64>,
) -> Result<(), CommunicationError> {
    let mut response =
        CommunicationValue::new_with_type_map(CommunicationType::IdentificationResponse, type_map)
            .add_typed_default(DataType::Connected, DataValue::BoolTrue)
            .add_typed_default(DataType::Version, DataValue::Str(version.to_string()));
    if let Some(id) = assigned_id {
        response = response.add_typed_default(DataType::Id, DataValue::UnsignedNumber(id as u128));
    }
    tracing::debug!(
        version = %version,
        assigned_id = ?assigned_id,
        "sending accepted MTP handshake response"
    );
    sender.send(&response).await?;
    sender.finish_stream().await
}

// ---------------------------------------------------------------------------
// Trait implementations for concrete transport types
// ---------------------------------------------------------------------------

impl HandshakeSender for mtp_transport::Sender {
    fn send(
        &self,
        msg: &CommunicationValue,
    ) -> impl std::future::Future<Output = Result<(), CommunicationError>> + Send {
        mtp_transport::Sender::send(self, msg)
    }
    fn finish_stream(
        &self,
    ) -> impl std::future::Future<Output = Result<(), CommunicationError>> + Send {
        mtp_transport::Sender::finish_stream(self)
    }
    async fn set_type_map(&self, type_map: &TypeMap) {
        self.set_type_map(type_map).await;
    }
    fn close(&self) {
        let sender = self.clone();
        tokio::spawn(async move { sender.close().await });
    }
}

impl HandshakeReceiver for mtp_transport::Receiver {
    fn receive(
        &self,
    ) -> impl std::future::Future<Output = Result<CommunicationValue, CommunicationError>> + Send
    {
        mtp_transport::Receiver::receive(self)
    }

    async fn set_type_map(&self, type_map: &TypeMap) {
        self.set_type_map(type_map).await;
    }
}

impl<C: mtp_transport::TransportConnection> HandshakeSender for mtp_transport::GenericSender<C> {
    fn send(
        &self,
        msg: &CommunicationValue,
    ) -> impl std::future::Future<Output = Result<(), CommunicationError>> + Send {
        mtp_transport::GenericSender::send(self, msg)
    }
    fn finish_stream(
        &self,
    ) -> impl std::future::Future<Output = Result<(), CommunicationError>> + Send {
        mtp_transport::GenericSender::finish_stream(self)
    }
    async fn set_type_map(&self, type_map: &TypeMap) {
        self.set_type_map(type_map).await;
    }
    fn close(&self) {
        mtp_transport::GenericSender::close(self);
    }
}

impl<C: mtp_transport::TransportConnection> HandshakeReceiver
    for mtp_transport::GenericReceiver<C>
{
    fn receive(
        &self,
    ) -> impl std::future::Future<Output = Result<CommunicationValue, CommunicationError>> + Send
    {
        mtp_transport::GenericReceiver::receive(self)
    }

    async fn set_type_map(&self, type_map: &TypeMap) {
        self.set_type_map(type_map).await;
    }
}

#[cfg(all(test, feature = "crypto"))]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[tokio::test]
    async fn guest_generator_accepts_full_width_id_after_collision_check()
    -> Result<(), Box<dyn std::error::Error>> {
        let lookups = Arc::new(Mutex::new(Vec::new()));
        let recorded_lookups = Arc::clone(&lookups);

        let mut config = HostConfig::new("127.0.0.1".parse()?, 4433, Vec::new(), Vec::new())
            .with_guest_id_generator(Box::new(|| Box::pin(async { Some(u64::MAX) })));
        config.get_existing_client = Box::new(move |id, description| {
            let recorded_lookups = Arc::clone(&recorded_lookups);
            Box::pin(async move {
                recorded_lookups
                    .lock()
                    .expect("guest ID lookup mutex should not be poisoned")
                    .push((id, description));
                None
            })
        });

        let engine = HandshakeEngine::new(Registry::builtin(), Arc::new(config));

        assert_eq!(engine.assign_guest_id().await?.id, u64::MAX);
        assert_eq!(
            *lookups
                .lock()
                .expect("guest ID lookup mutex should not be poisoned"),
            vec![(u64::MAX, None)]
        );
        Ok(())
    }

    #[tokio::test]
    async fn active_guest_ids_are_unique_and_released() -> Result<(), Box<dyn std::error::Error>> {
        let config = HostConfig::new("127.0.0.1".parse()?, 4433, Vec::new(), Vec::new());
        let engine = HandshakeEngine::new(Registry::builtin(), Arc::new(config));

        let first = engine.try_reserve_guest_id(1).await?.unwrap();
        assert!(engine.try_reserve_guest_id(1).await?.is_none());

        drop(first);
        assert!(engine.try_reserve_guest_id(1).await?.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn zero_is_rejected_as_a_guest_id() -> Result<(), Box<dyn std::error::Error>> {
        let config = HostConfig::new("127.0.0.1".parse()?, 4433, Vec::new(), Vec::new())
            .with_guest_id_generator(Box::new(|| Box::pin(async { Some(0) })));
        let engine = HandshakeEngine::new(Registry::builtin(), Arc::new(config));

        assert!(engine.assign_guest_id().await.is_err());
        Ok(())
    }
}
