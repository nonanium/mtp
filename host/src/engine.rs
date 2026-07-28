//! Transport-independent MTP handshake engine.
//!
//! This module contains the shared state machine used by both native `MTPHost`
//! and the web server's `MTPWebServer` to perform the MTP opening handshake,
//! version negotiation, authentication, and guest assignment.

use crate::config::HostConfig;
use crate::error::AcceptError;
use mtp_codec::{
    CommunicationType, CommunicationValue, DataType, DataValue, Version,
    registry::{Registry, VersionedCodec},
};
use mtp_common::{CommunicationError, RejectionReason};
use std::sync::Arc;

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
    fn close(&self);
}

/// Trait for receiving handshake messages during the opening exchange.
///
/// Implemented by both the concrete `Receiver` and `GenericReceiver<C>`.
pub trait HandshakeReceiver: Send + Sync {
    fn receive(
        &self,
    ) -> impl std::future::Future<Output = Result<CommunicationValue, CommunicationError>>
           + Send;
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
        #[cfg(feature = "crypto")]
        {
            let timeout = self.config.auth_timeout;
            tokio::time::timeout(timeout, self.accept_inner(sender, receiver))
                .await
                .unwrap_or(Err(AcceptError::AuthenticationTimedOut))
        }
        #[cfg(not(feature = "crypto"))]
        self.accept_inner(sender, receiver).await
    }

    async fn accept_inner<S: HandshakeSender, R: HandshakeReceiver>(
        &self,
        sender: &S,
        receiver: &R,
    ) -> Result<HandshakeResult, AcceptError> {
        let first_msg = receiver.receive().await.map_err(AcceptError::Receive)?;

        let version_str = match first_msg.get_data(DataType::Version) {
            DataValue::Str(s) => s.clone(),
            _ => {
                send_rejection_generic(
                    sender,
                    RejectionReason::AuthenticationFailed {
                        detail: "opening message omitted a valid protocol version".into(),
                    },
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
                )
                .await;
                sender.close();
                return Err(AcceptError::MissingVersion);
            }
        };

        let negotiated = match self.registry.negotiate(std::slice::from_ref(&client_version)) {
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
                )
                .await;
                sender.close();
                return Err(AcceptError::UnsupportedVersion(client_version));
            }
        };

        let codec = VersionedCodec::for_version(self.registry.clone(), negotiated.clone())
            .ok_or_else(|| AcceptError::UnsupportedVersion(negotiated.clone()))?;

        let description = match first_msg.get_data(DataType::Description) {
            DataValue::Str(s) => Some(s.clone()),
            _ => None,
        };

        #[cfg(feature = "crypto")]
        {
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
            let _ = sender;
            let _ = receiver;
            let _ = first_msg;
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
        let tm = mtp_codec::TypeMap::latest();

        // Reject Register frames on unauthenticated hosts
        if Some(first_msg.get_type()) == CommunicationType::Register.try_to_id(&tm) {
            send_rejection_generic(
                sender,
                RejectionReason::AuthenticationFailed {
                    detail: "authentication not allowed on this host".into(),
                },
            )
            .await;
            sender.close();
            return Err(AcceptError::AuthenticationFailed(
                "authentication not allowed on this host".into(),
            ));
        }

        let guest_id = self.assign_guest_id().await?;
        send_accepted_generic(sender, &negotiated, Some(guest_id))
            .await
            .map_err(AcceptError::Send)?;

        Ok(HandshakeResult {
            negotiated_version: negotiated,
            codec,
            description,
            auth_state: crate::error::AuthState::Unauthenticated,
            client_id: guest_id,
            client_public_key: None,
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
        let tm = mtp_codec::TypeMap::latest();

        // Register frames always go through full authentication
        if Some(first_msg.get_type()) == CommunicationType::Register.try_to_id(&tm) {
            let bundle = extract_register_bundle(&first_msg)?;
            let pk_bytes = bundle.as_bytes();
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
        if Some(first_msg.get_type()) == CommunicationType::Identification.try_to_id(&tm) {
            let cid = match first_msg.get_data(DataType::Id) {
                DataValue::UnsignedNumber(n) => *n as u64,
                _ => 0,
            };

            if cid > 0 {
                if let Some(bundle) =
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
            }

            // Unknown or zero ID: fall back to guest
            let guest_id = self.assign_guest_id().await?;
            send_accepted_generic(sender, &negotiated, Some(guest_id))
                .await
                .map_err(AcceptError::Send)?;
            return Ok(HandshakeResult {
                negotiated_version: negotiated,
                codec,
                description,
                auth_state: crate::error::AuthState::Unauthenticated,
                client_id: guest_id,
                client_public_key: None,
            });
        }

        sender.close();
        Err(AcceptError::AuthenticationFailed(
            "unexpected message type".into(),
        ))
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
        let tm = mtp_codec::TypeMap::latest();

        let (flow, response_type) = if Some(first_msg.get_type())
            == CommunicationType::Identification.try_to_id(&tm)
        {
            let cid = match first_msg.get_data(DataType::Id) {
                DataValue::UnsignedNumber(n) => *n as u64,
                _ => {
                    sender.close();
                    return Err(AcceptError::AuthenticationFailed(
                        "missing client id".into(),
                    ));
                }
            };
            let bundle = match (self.config.get_existing_client)(cid, description.clone()).await {
                Some(b) => b,
                None => {
                    let rejection =
                        CommunicationValue::new(CommunicationType::IdentificationResponse)
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
            };
            (
                Flow::Login { id: cid, bundle },
                CommunicationType::IdentificationResponse,
            )
        } else if Some(first_msg.get_type()) == CommunicationType::Register.try_to_id(&tm) {
            let bundle = extract_register_bundle(&first_msg)?;
            let pk_bytes = bundle.as_bytes();
            (
                Flow::Register { bundle, pk_bytes },
                CommunicationType::RegisterResponse,
            )
        } else {
            sender.close();
            return Err(AcceptError::AuthenticationFailed(
                "unexpected authentication message".into(),
            ));
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

        let tm = mtp_codec::TypeMap::latest();

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
                MlDsaSigner::new(
                    &self.config.host_keyring.sig_pq_secret_key,
                    &self.config.host_keyring.sig_pq_public_key,
                )
                .map_err(|e| AcceptError::AuthenticationFailed(e.to_string()))?,
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
            host_sign(auth::challenge_payload(challenge_id, server_challenge)).await?;

        let mut challenge_msg = CommunicationValue::new(CommunicationType::Challenge)
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
        if Some(proof.get_type()) != CommunicationType::ChallengeResponse.try_to_id(&tm) {
            sender.close();
            return Err(AcceptError::AuthenticationFailed(
                "missing challenge response".into(),
            ));
        }
        let client_nonce = match proof.get_data(DataType::ClientNonce) {
            DataValue::UnsignedNumber(n) => *n,
            _ => {
                sender.close();
                return Err(AcceptError::AuthenticationFailed(
                    "missing client nonce".into(),
                ));
            }
        };
        let sig_bytes = match proof.get_data(DataType::Signature) {
            DataValue::Bytes(b) => b.clone(),
            _ => {
                sender.close();
                return Err(AcceptError::AuthenticationFailed(
                    "missing challenge signature".into(),
                ));
            }
        };
        let pq_sig_bytes: Vec<u8> = match proof.get_data(DataType::PqSignature) {
            DataValue::Bytes(b) => b.clone(),
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
                let new_id =
                    (self.config.complete_register)(bundle.clone(), description.clone()).await;
                (new_id, bundle)
            }
        };

        // Sign and send final response
        let (host_sig, host_pq_sig) = host_sign(auth::host_final_payload(
            assigned_id,
            client_nonce,
            server_challenge,
        ))
        .await?;

        let mut response = CommunicationValue::new(response_type)
            .add_typed_default(DataType::Connected, DataValue::BoolTrue)
            .add_typed_default(DataType::Id, DataValue::UnsignedNumber(assigned_id as u128))
            .add_typed_default(
                DataType::ClientNonce,
                DataValue::UnsignedNumber(client_nonce),
            )
            .add_typed_default(DataType::Signature, DataValue::Bytes(host_sig));
        response = response
            .add_typed_default(DataType::Version, DataValue::Str(negotiated.to_string()));
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

    async fn assign_guest_id(&self) -> Result<u64, AcceptError> {
        if let Some(ref generator) = self.config.guest_id_generator {
            let id = generator().await.ok_or_else(|| {
                AcceptError::AuthenticationFailed(
                    "guest id generator rejected the connection".into(),
                )
            })?;
            if id > mtp_codec::MAX_WIRE_ID {
                return Err(AcceptError::AuthenticationFailed(
                    "guest id exceeds wire limit".into(),
                ));
            }
            if (self.config.get_existing_client)(id, None).await.is_none() {
                return Ok(id);
            }
        }
        self.random_guest_id().await
    }

    async fn random_guest_id(&self) -> Result<u64, AcceptError> {
        for _ in 0..Self::GUEST_ID_MAX_RETRIES {
            let id = rand::random::<u64>() & mtp_codec::MAX_WIRE_ID;
            if (self.config.get_existing_client)(id, None).await.is_none() {
                return Ok(id);
            }
        }
        Err(AcceptError::AuthenticationFailed(
            "failed to allocate a unique guest id after retries".into(),
        ))
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
        DataValue::Bytes(b) => mtp_crypto::PublicKeyBundle::from_bytes(b).map_err(|_| {
            AcceptError::AuthenticationFailed("invalid public key bundle".into())
        }),
        _ => Err(AcceptError::AuthenticationFailed(
            "missing public keys".into(),
        )),
    }
}

async fn send_rejection_generic<S: HandshakeSender>(
    sender: &S,
    reason: RejectionReason,
) {
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

#[cfg(feature = "crypto")]
async fn send_accepted_generic<S: HandshakeSender>(
    sender: &S,
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
    fn close(&self) {
        mtp_transport::GenericSender::close(self);
    }
}

impl<C: mtp_transport::TransportConnection> HandshakeReceiver for mtp_transport::GenericReceiver<C> {
    fn receive(
        &self,
    ) -> impl std::future::Future<Output = Result<CommunicationValue, CommunicationError>> + Send
    {
        mtp_transport::GenericReceiver::receive(self)
    }
}
