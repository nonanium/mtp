//! Transport-independent MTP handshake engine.
//!
//! This module contains the shared state machine used by both native `MTPHost`
//! and the web server's `MTPWebServer` to perform the MTP opening handshake,
//! version negotiation, authentication, and guest assignment.

mod authentication;
#[cfg(feature = "crypto")]
mod guest_ids;
mod transport;

use crate::config::{AuthenticationContext, HostConfig};
use crate::error::AcceptError;
use mtp_codec::{
    CommunicationType, CommunicationValue, DataType, DataValue, TypeMap, Version,
    registry::{Registry, VersionedCodec, bootstrap_type_map},
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
        let bootstrap = bootstrap_type_map();
        sender.set_type_map(&bootstrap).await;
        receiver.set_type_map(&bootstrap).await;
        let mut first_msg = receiver.receive().await.map_err(AcceptError::Receive)?;
        tracing::debug!(
            message_type = ?first_msg.get_type(),
            version = ?first_msg.get_str(DataType::Version),
            client_id = ?first_msg.get_data(DataType::Id),
            "received MTP opening message"
        );

        let client_versions = match parse_version_offer(&first_msg) {
            Some(versions) => versions,
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
        let client_version = client_versions[0].clone();

        let negotiated = match self.registry.negotiate(&client_versions) {
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

        if let Err(error) =
            mtp_codec::dictionary::verify_offer(&first_msg, &client_versions, codec.type_map())
        {
            let rejection = CommunicationValue::new_with_type_map(CommunicationType::ErrorBadVersion, &bootstrap)
                .add_typed_default(DataType::Connected, DataValue::BoolFalse)
                .add_typed_default(DataType::Error, DataValue::Str("dictionary_mismatch".into()))
                .add_typed_default(DataType::Version, DataValue::Array(vec![DataValue::Str(negotiated.to_string())]))
                .add_typed_default(DataType::DictionaryFingerprint, mtp_codec::dictionary::value(codec.type_map()).map_err(AcceptError::Send)?);
            let _ = sender.send(&rejection).await;
            sender.close();
            return Err(AcceptError::Receive(error));
        }

        send_selection_bootstrap(sender, &negotiated, &bootstrap)
            .await
            .map_err(AcceptError::Send)?;
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
            tracing::info!(
                claimed_client_id = ?claimed_client_id,
                registration,
                authentication_requested,
                "classified MTP opening authentication mode"
            );
            if authentication_requested {
                let attempt = crate::config::AuthenticationAttempt {
                    peer_network_identity: _authentication_context.peer_network_identity,
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
                        negotiated.clone(),
                        codec,
                        description,
                        &negotiated.to_string(),
                        client_version,
                    )
                    .await
                }
                crate::config::AuthenticationPolicy::AllowAuthentication => {
                    self.allow_auth_handshake(
                        sender,
                        receiver,
                        first_msg,
                        negotiated.clone(),
                        codec,
                        description,
                        &negotiated.to_string(),
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
                    DataValue::Array(
                        supported_versions
                            .iter()
                            .cloned()
                            .map(DataValue::Str)
                            .collect(),
                    ),
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

fn parse_version_offer(message: &CommunicationValue) -> Option<Vec<Version>> {
    let DataValue::Array(values) = message.get_data(DataType::Version)? else {
        return None;
    };
    let versions: Option<Vec<_>> = values
        .iter()
        .map(|value| match value {
            DataValue::Str(version) => {
                Version::parse(version).filter(|parsed| parsed.to_string() == *version)
            }
            _ => None,
        })
        .collect();
    versions.filter(|versions| !versions.is_empty())
}

async fn send_selection_bootstrap<S: HandshakeSender>(
    sender: &S,
    version: &Version,
    bootstrap: &TypeMap,
) -> Result<(), CommunicationError> {
    let selection =
        CommunicationValue::new_with_type_map(CommunicationType::IdentificationResponse, bootstrap)
            .add_typed_default(DataType::Connected, DataValue::BoolTrue)
            .add_typed_default(DataType::Version, DataValue::Str(version.to_string()))
            .add_typed_default(
                DataType::DictionaryFingerprint,
                mtp_codec::dictionary::value(&TypeMap::new(version.clone()))?,
            );
    sender.send(&selection).await
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
            .add_typed_default(DataType::Version, DataValue::Str(version.to_string()))
            .add_typed_default(
                DataType::DictionaryFingerprint,
                mtp_codec::dictionary::value(type_map)?,
            );
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

#[cfg(all(test, feature = "crypto"))]
mod tests;
