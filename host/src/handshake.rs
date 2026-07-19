#[cfg(feature = "crypto")]
use mtp_codec::{CommunicationType, CommunicationValue};
use mtp_codec::{
    DataType, DataValue, Version,
    registry::{Registry, VersionedCodec},
};
use mtp_common::RejectionReason;
use mtp_transport::{Receiver, Sender};
use std::sync::Arc;
use std::time::Instant;
#[cfg(feature = "pipes")]
use tokio::sync::mpsc;

#[cfg(feature = "crypto")]
use crate::config::AuthenticationPolicy;
use crate::config::HostConfig;
use crate::connection::MTPConnection;
#[cfg(feature = "crypto")]
use crate::error::AuthState;
use crate::error::{AcceptError, extract_version, send_accepted, send_rejection};
#[cfg(feature = "pipes")]
use crate::pipe::PipeDispatcher;
#[cfg(feature = "pipes")]
use crate::pipe::run_dispatcher;

pub struct MTPHost {
    pub(crate) transport: mtp_transport::Host,
    pub(crate) context: Arc<HandshakeContext>,
    pub(crate) handshakes: tokio::task::JoinSet<Result<Option<MTPConnection>, AcceptError>>,
    pub(crate) transport_closed: bool,
}

pub(crate) struct HandshakeContext {
    pub(crate) registry: Registry,
    pub(crate) config: Arc<HostConfig>,
}

impl MTPHost {
    pub async fn new(config: HostConfig) -> Result<Self, mtp_common::CommunicationError> {
        let registry = Registry::builtin();

        let transport = mtp_transport::host(
            config.ip,
            config.port,
            config.tls_fullchain.clone(),
            config.tls_key.clone(),
            config.policy,
        )
        .await?;

        Ok(Self {
            transport,
            context: Arc::new(HandshakeContext {
                registry,
                config: Arc::new(config),
            }),
            handshakes: tokio::task::JoinSet::new(),
            transport_closed: false,
        })
    }

    pub async fn accept(&mut self) -> Result<Option<MTPConnection>, AcceptError> {
        loop {
            if self.transport_closed {
                return match self.handshakes.join_next().await {
                    Some(Ok(result)) => result,
                    Some(Err(error)) => Err(AcceptError::AuthenticationFailed(format!(
                        "handshake task failed: {error}"
                    ))),
                    None => Ok(None),
                };
            }

            if self.handshakes.is_empty() {
                let incoming_started = Instant::now();
                match self.transport.next().await {
                    Some((sender, receiver)) => {
                        tracing::debug!(elapsed = ?incoming_started.elapsed(), "host accept loop: dispatch authentication handshake");
                        let context = self.context.clone();
                        self.handshakes.spawn(async move {
                            let handshake_started = Instant::now();
                            let result = context.accept_pair_timed(sender, receiver).await;
                            tracing::debug!(elapsed = ?handshake_started.elapsed(), success = result.is_ok(), "host accept loop: authentication handshake finished");
                            result
                        });
                        continue;
                    }
                    None => {
                        self.transport_closed = true;
                        continue;
                    }
                }
            }

            tokio::select! {
                completed = self.handshakes.join_next() => {
                    if let Some(completed) = completed {
                        return completed.unwrap_or_else(|error| {
                            Err(AcceptError::AuthenticationFailed(format!(
                                "handshake task failed: {error}"
                            )))
                        });
                    }
                }
                incoming = self.transport.next() => {
                    match incoming {
                        Some((sender, receiver)) => {
                            tracing::debug!("host accept loop: dispatch authentication handshake");
                            let context = self.context.clone();
                            self.handshakes
                                .spawn(async move {
                                    let handshake_started = Instant::now();
                                    let result = context.accept_pair_timed(sender, receiver).await;
                                    tracing::debug!(elapsed = ?handshake_started.elapsed(), success = result.is_ok(), "host accept loop: authentication handshake finished");
                                    result
                                });
                        }
                        None => self.transport_closed = true,
                    }
                }
            }
        }
    }

    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.transport.local_addr()
    }

    pub fn registry(&self) -> &Registry {
        &self.context.registry
    }
}

impl HandshakeContext {
    async fn accept_pair_timed(
        &self,
        sender: Sender,
        receiver: Receiver,
    ) -> Result<Option<MTPConnection>, AcceptError> {
        #[cfg(feature = "crypto")]
        {
            return tokio::time::timeout(
                self.config.auth_timeout,
                self.accept_pair(sender, receiver),
            )
            .await
            .unwrap_or(Err(AcceptError::AuthenticationTimedOut));
        }
        #[cfg(not(feature = "crypto"))]
        self.accept_pair(sender, receiver).await
    }

    async fn accept_pair(
        &self,
        sender: Sender,
        receiver: Receiver,
    ) -> Result<Option<MTPConnection>, AcceptError> {
        #[cfg(feature = "crypto")]
        match self.config.authentication_policy {
            AuthenticationPolicy::ForceAuthentication => {
                let timeout = self.config.auth_timeout;
                match tokio::time::timeout(timeout, self.accept_authenticated(sender, receiver))
                    .await
                {
                    Ok(result) => result,
                    Err(_) => Err(AcceptError::AuthenticationTimedOut),
                }
            }
            AuthenticationPolicy::AllowAuthentication => {
                return self.accept_allow_auth(sender, receiver).await;
            }
            AuthenticationPolicy::Unauthenticated => {
                let first_msg = match receiver.receive().await {
                    Ok(m) => m,
                    Err(e) => return Err(AcceptError::Receive(e)),
                };
                if Some(first_msg.get_type())
                    == CommunicationType::Register.try_to_id(&mtp_codec::TypeMap::latest())
                {
                    send_rejection(
                        &sender,
                        RejectionReason::AuthenticationFailed {
                            detail: "authentication not allowed on this host".into(),
                        },
                    )
                    .await;
                    sender.close().await;
                    return Err(AcceptError::AuthenticationFailed(
                        "authentication not allowed on this host".into(),
                    ));
                }
                let client_version = match extract_version(&first_msg) {
                    Some(v) => v,
                    None => {
                        send_rejection(
                            &sender,
                            RejectionReason::AuthenticationFailed {
                                detail: "opening message omitted a valid protocol version".into(),
                            },
                        )
                        .await;
                        sender.close().await;
                        return Err(AcceptError::MissingVersion);
                    }
                };
                let negotiated = match self
                    .registry
                    .negotiate(std::slice::from_ref(&client_version))
                {
                    Some(v) => v,
                    None => {
                        send_rejection(
                            &sender,
                            RejectionReason::BadVersion {
                                supported_versions: self
                                    .registry
                                    .versions()
                                    .map(|v| v.to_string())
                                    .collect(),
                            },
                        )
                        .await;
                        sender.close().await;
                        return Err(AcceptError::UnsupportedVersion(client_version));
                    }
                };
                let codec =
                    match VersionedCodec::for_version(self.registry.clone(), negotiated.clone()) {
                        Some(codec) => codec,
                        None => {
                            return Err(AcceptError::UnsupportedVersion(negotiated));
                        }
                    };
                let description = match first_msg.get_data(DataType::Description) {
                    DataValue::Str(s) => Some(s.clone()),
                    _ => None,
                };
                let guest_id = self.assign_guest_id().await;
                send_accepted(&sender, &negotiated, Some(guest_id))
                    .await
                    .map_err(AcceptError::Send)?;
                Ok(Some(self.connection_from_parts(
                    sender,
                    receiver,
                    negotiated,
                    codec,
                    description,
                    AuthState::Unauthenticated,
                    guest_id,
                    None,
                )))
            }
        }

        #[cfg(not(feature = "crypto"))]
        {
            let first_msg = match receiver.receive().await {
                Ok(m) => m,
                Err(e) => return Err(AcceptError::Receive(e)),
            };
            let client_version = match extract_version(&first_msg) {
                Some(v) => v,
                None => {
                    send_rejection(
                        &sender,
                        RejectionReason::AuthenticationFailed {
                            detail: "opening message omitted a valid protocol version".into(),
                        },
                    )
                    .await;
                    sender.close().await;
                    return Err(AcceptError::MissingVersion);
                }
            };
            let negotiated = match self
                .registry
                .negotiate(std::slice::from_ref(&client_version))
            {
                Some(v) => v,
                None => {
                    send_rejection(
                        &sender,
                        RejectionReason::BadVersion {
                            supported_versions: vec![mtp_codec::PROTOCOL_VERSION.to_string()],
                        },
                    )
                    .await;
                    sender.close().await;
                    return Err(AcceptError::UnsupportedVersion(client_version));
                }
            };
            let codec = match VersionedCodec::for_version(self.registry.clone(), negotiated.clone())
            {
                Some(codec) => codec,
                None => {
                    return Err(AcceptError::UnsupportedVersion(negotiated));
                }
            };
            let description = match first_msg.get_data(DataType::Description) {
                DataValue::Str(s) => Some(s.clone()),
                _ => None,
            };
            send_accepted(&sender, &negotiated, None)
                .await
                .map_err(AcceptError::Send)?;
            Ok(Some(self.connection_from_parts(
                sender,
                receiver,
                negotiated,
                codec,
                description,
            )))
        }
    }

    #[cfg(not(feature = "crypto"))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn connection_from_parts(
        &self,
        sender: Sender,
        receiver: Receiver,
        version: Version,
        codec: VersionedCodec,
        description: Option<String>,
    ) -> MTPConnection {
        let remote_addr = sender.handle().remote_addr();
        receiver.set_max_message_size(self.config.policy.max_message_size);
        #[cfg(feature = "pipes")]
        {
            if self.config.send_pongs {
                receiver.respond_to_pings(sender.clone());
            }

            let (app_tx, app_rx) = mpsc::channel(self.config.policy.receiver_queue_capacity);
            let (pipe_req_tx, pipe_req_rx) =
                mpsc::channel(self.config.policy.receiver_queue_capacity);

            let dispatcher = Arc::new(PipeDispatcher {
                pending_creations: tokio::sync::Mutex::new(std::collections::HashMap::new()),
                pending_pipes: tokio::sync::Mutex::new(std::collections::HashMap::new()),
                policy: Arc::new(self.config.policy),
            });

            let dispatcher_clone = dispatcher.clone();
            let receiver_clone = receiver.clone();
            let sender_clone = sender.clone();
            let task = tokio::spawn(run_dispatcher(
                receiver_clone,
                sender_clone,
                app_tx,
                pipe_req_tx,
                dispatcher_clone,
            ));

            MTPConnection {
                version,
                codec,
                sender,
                receiver,
                path: "/".to_string(),
                remote_addr,
                app_rx: tokio::sync::Mutex::new(app_rx),
                pipe_req_rx: tokio::sync::Mutex::new(pipe_req_rx),
                pipe_dispatcher: dispatcher,
                description,
                _dispatcher_task: task,
            }
        }

        #[cfg(not(feature = "pipes"))]
        {
            if self.config.send_pongs {
                receiver.respond_to_pings(sender.clone());
            }

            let task = tokio::spawn(async {});

            MTPConnection {
                version,
                codec,
                sender,
                receiver,
                path: "/".to_string(),
                remote_addr,
                _pipe_stream: std::marker::PhantomData,
                description,
                _dispatcher_task: task,
            }
        }
    }

    #[cfg(feature = "crypto")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn connection_from_parts(
        &self,
        sender: Sender,
        receiver: Receiver,
        version: Version,
        codec: VersionedCodec,
        description: Option<String>,
        auth_state: AuthState,
        client_id: u64,
        client_public_key: Option<mtp_crypto::PublicKeyBundle>,
    ) -> MTPConnection {
        let remote_addr = sender.handle().remote_addr();
        receiver.set_max_message_size(self.config.policy.max_message_size);
        #[cfg(feature = "pipes")]
        {
            if self.config.send_pongs {
                receiver.respond_to_pings(sender.clone());
            }

            let (app_tx, app_rx) = mpsc::channel(self.config.policy.receiver_queue_capacity);
            let (pipe_req_tx, pipe_req_rx) =
                mpsc::channel(self.config.policy.receiver_queue_capacity);

            let dispatcher = Arc::new(PipeDispatcher {
                pending_creations: tokio::sync::Mutex::new(std::collections::HashMap::new()),
                pending_pipes: tokio::sync::Mutex::new(std::collections::HashMap::new()),
                policy: Arc::new(self.config.policy),
            });

            let dispatcher_clone = dispatcher.clone();
            let receiver_clone = receiver.clone();
            let sender_clone = sender.clone();
            let task = tokio::spawn(run_dispatcher(
                receiver_clone,
                sender_clone,
                app_tx,
                pipe_req_tx,
                dispatcher_clone,
            ));

            MTPConnection {
                version,
                codec,
                sender,
                receiver,
                path: "/".to_string(),
                remote_addr,
                app_rx: tokio::sync::Mutex::new(app_rx),
                pipe_req_rx: tokio::sync::Mutex::new(pipe_req_rx),
                pipe_dispatcher: dispatcher,
                description,
                _dispatcher_task: task,
                auth_state,
                client_id,
                client_public_key,
            }
        }

        #[cfg(not(feature = "pipes"))]
        {
            if self.config.send_pongs {
                receiver.respond_to_pings(sender.clone());
            }

            let task = tokio::spawn(async {});

            MTPConnection {
                version,
                codec,
                sender,
                receiver,
                path: "/".to_string(),
                remote_addr,
                _pipe_stream: std::marker::PhantomData,
                description,
                _dispatcher_task: task,
                auth_state,
                client_id,
                client_public_key,
            }
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

#[cfg(feature = "crypto")]
impl HandshakeContext {
    const GUEST_ID_MAX_RETRIES: u32 = 100;

    async fn assign_guest_id(&self) -> u64 {
        if let Some(ref generator) = self.config.guest_id_generator {
            if let Some(id) = generator().await
                && id <= mtp_codec::MAX_WIRE_ID
            {
                return id;
            }
            return self.random_guest_id().await;
        }
        self.random_guest_id().await
    }

    async fn random_guest_id(&self) -> u64 {
        for _ in 0..Self::GUEST_ID_MAX_RETRIES {
            let id = rand::random::<u64>() & mtp_codec::MAX_WIRE_ID;
            if (self.config.get_existing_client)(id, None).await.is_none() {
                return id;
            }
        }
        rand::random::<u64>() & mtp_codec::MAX_WIRE_ID
    }

    async fn accept_authenticated(
        &self,
        sender: Sender,
        receiver: Receiver,
    ) -> Result<Option<MTPConnection>, AcceptError> {
        use mtp_crypto::PublicKeyBundle;

        let tm = mtp_codec::TypeMap::latest();

        let hello = match receiver.receive().await {
            Ok(m) => m,
            Err(e) => {
                sender.close().await;
                return Err(AcceptError::Receive(e));
            }
        };
        let version_str = match hello.get_data(DataType::Version) {
            DataValue::Str(s) => s.clone(),
            _ => {
                sender.close().await;
                return Err(AcceptError::MissingVersion);
            }
        };
        let client_version = match Version::parse(&version_str) {
            Some(v) => v,
            None => {
                sender.close().await;
                return Err(AcceptError::MissingVersion);
            }
        };

        let description = match hello.get_data(DataType::Description) {
            DataValue::Str(s) => Some(s.clone()),
            _ => None,
        };

        let (flow, response_type) = if Some(hello.get_type())
            == CommunicationType::Identification.try_to_id(&tm)
        {
            let cid = match hello.get_data(DataType::Id) {
                DataValue::UnsignedNumber(n) => *n as u64,
                _ => {
                    sender.close().await;
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
                    sender.close().await;
                    return Err(AcceptError::AuthenticationFailed(
                        "unknown client id".into(),
                    ));
                }
            };
            (
                Flow::Login { id: cid, bundle },
                CommunicationType::IdentificationResponse,
            )
        } else if Some(hello.get_type()) == CommunicationType::Register.try_to_id(&tm) {
            let bundle = match hello.get_data(DataType::PublicKeys) {
                DataValue::Bytes(b) => PublicKeyBundle::from_bytes(b).map_err(|_| {
                    AcceptError::AuthenticationFailed("invalid public key bundle".into())
                })?,
                _ => {
                    sender.close().await;
                    return Err(AcceptError::AuthenticationFailed(
                        "missing public keys".into(),
                    ));
                }
            };
            let pk_bytes = bundle.as_bytes();
            (
                Flow::Register { bundle, pk_bytes },
                CommunicationType::RegisterResponse,
            )
        } else {
            sender.close().await;
            return Err(AcceptError::AuthenticationFailed(
                "unexpected authentication message".into(),
            ));
        };

        self.complete_auth_handshake(
            sender,
            receiver,
            flow,
            response_type,
            &version_str,
            client_version,
            description,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn complete_auth_handshake(
        &self,
        sender: Sender,
        receiver: Receiver,
        flow: Flow,
        response_type: CommunicationType,
        version_str: &str,
        client_version: Version,
        description: Option<String>,
    ) -> Result<Option<MTPConnection>, AcceptError> {
        use mtp_crypto::{Ed25519Signer, MlDsaSigner, SignatureScheme, auth, verify_ed25519};

        let handshake_started = Instant::now();
        let tm = mtp_codec::TypeMap::latest();
        let negotiate_started = Instant::now();
        let negotiated = match self
            .registry
            .negotiate(std::slice::from_ref(&client_version))
        {
            Some(version) => version,
            None => {
                send_rejection(
                    &sender,
                    RejectionReason::BadVersion {
                        supported_versions: vec![mtp_codec::PROTOCOL_VERSION.to_string()],
                    },
                )
                .await;
                sender.close().await;
                return Err(AcceptError::UnsupportedVersion(client_version));
            }
        };
        tracing::debug!(elapsed = ?negotiate_started.elapsed(), "authentication handshake: version negotiation");
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
            send_rejection(
                &sender,
                RejectionReason::AuthenticationFailed {
                    detail: "host requires PQ authentication but has no PQ signing key".into(),
                },
            )
            .await;
            sender.close().await;
            return Err(AcceptError::AuthenticationFailed(
                "PQ authentication is required but the host PQ key is absent".into(),
            ));
        }

        let signer_init_started = Instant::now();
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
        tracing::debug!(elapsed = ?signer_init_started.elapsed(), "authentication handshake: signer initialization");

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

        let challenge_id = match &flow {
            Flow::Login { id, .. } => *id,
            Flow::Register { .. } => 0,
        };

        let server_challenge: u128 = rand::random();
        let sign_challenge_started = Instant::now();
        let (chal_sig, chal_pq_sig) =
            host_sign(auth::challenge_payload(challenge_id, server_challenge)).await?;
        tracing::debug!(elapsed = ?sign_challenge_started.elapsed(), "authentication handshake: sign challenge");

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
        let send_challenge_started = Instant::now();
        if let Err(e) = sender.send(&challenge_msg).await {
            sender.close().await;
            return Err(AcceptError::Send(e));
        }
        tracing::debug!(elapsed = ?send_challenge_started.elapsed(), "authentication handshake: send challenge");

        let receive_proof_started = Instant::now();
        let proof = match receiver.receive().await {
            Ok(m) => m,
            Err(e) => {
                sender.close().await;
                return Err(AcceptError::Receive(e));
            }
        };
        tracing::debug!(elapsed = ?receive_proof_started.elapsed(), "authentication handshake: receive client proof");
        if Some(proof.get_type()) != CommunicationType::ChallengeResponse.try_to_id(&tm) {
            sender.close().await;
            return Err(AcceptError::AuthenticationFailed(
                "missing challenge response".into(),
            ));
        }
        let client_nonce = match proof.get_data(DataType::ClientNonce) {
            DataValue::UnsignedNumber(n) => *n,
            _ => {
                sender.close().await;
                return Err(AcceptError::AuthenticationFailed(
                    "missing client nonce".into(),
                ));
            }
        };
        let sig_bytes = match proof.get_data(DataType::Signature) {
            DataValue::Bytes(b) => b.clone(),
            _ => {
                sender.close().await;
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
        let verify_proof_started = Instant::now();
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
        tracing::debug!(elapsed = ?verify_proof_started.elapsed(), "authentication handshake: verify client proof");

        if !proof_ok {
            send_rejection(
                &sender,
                RejectionReason::AuthenticationFailed {
                    detail: "client proof signature invalid".into(),
                },
            )
            .await;
            sender.close().await;
            return Err(AcceptError::AuthenticationFailed(
                "client proof signature invalid".into(),
            ));
        }

        let register_started = Instant::now();
        let (assigned_id, client_bundle) = match flow {
            Flow::Login { id, bundle } => (id, bundle),
            Flow::Register { bundle, .. } => {
                let new_id =
                    (self.config.complete_register)(bundle.clone(), description.clone()).await;
                (new_id, bundle)
            }
        };
        tracing::debug!(elapsed = ?register_started.elapsed(), "authentication handshake: registration callback");

        let sign_final_started = Instant::now();
        let (host_sig, host_pq_sig) = host_sign(auth::host_final_payload(
            assigned_id,
            client_nonce,
            server_challenge,
        ))
        .await?;
        tracing::debug!(elapsed = ?sign_final_started.elapsed(), "authentication handshake: sign final response");

        let mut response = CommunicationValue::new(response_type)
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

        let send_final_started = Instant::now();
        if let Err(e) = sender.send(&response).await {
            sender.close().await;
            return Err(AcceptError::Send(e));
        }
        if let Err(e) = sender.finish_stream().await {
            sender.close().await;
            return Err(AcceptError::Send(e));
        }
        tracing::debug!(elapsed = ?send_final_started.elapsed(), "authentication handshake: send final response");
        tracing::debug!(elapsed = ?handshake_started.elapsed(), "authentication handshake: complete");

        let codec = match VersionedCodec::for_version(self.registry.clone(), negotiated.clone()) {
            Some(codec) => codec,
            None => {
                return Err(AcceptError::UnsupportedVersion(negotiated));
            }
        };

        Ok(Some(self.connection_from_parts(
            sender,
            receiver,
            negotiated,
            codec,
            description,
            AuthState::Authenticated,
            assigned_id,
            Some(client_bundle),
        )))
    }

    async fn accept_allow_auth(
        &self,
        sender: Sender,
        receiver: Receiver,
    ) -> Result<Option<MTPConnection>, AcceptError> {
        use mtp_crypto::PublicKeyBundle;

        let tm = mtp_codec::TypeMap::latest();

        let hello = match receiver.receive().await {
            Ok(m) => m,
            Err(e) => return Err(AcceptError::Receive(e)),
        };

        let version_str = match hello.get_data(DataType::Version) {
            DataValue::Str(s) => s.clone(),
            _ => {
                sender.close().await;
                return Err(AcceptError::MissingVersion);
            }
        };
        let client_version = match Version::parse(&version_str) {
            Some(v) => v,
            None => {
                sender.close().await;
                return Err(AcceptError::MissingVersion);
            }
        };

        let description = match hello.get_data(DataType::Description) {
            DataValue::Str(s) => Some(s.clone()),
            _ => None,
        };

        if Some(hello.get_type()) == CommunicationType::Register.try_to_id(&tm) {
            let bundle = match hello.get_data(DataType::PublicKeys) {
                DataValue::Bytes(b) => PublicKeyBundle::from_bytes(b).map_err(|_| {
                    AcceptError::AuthenticationFailed("invalid public key bundle".into())
                })?,
                _ => {
                    sender.close().await;
                    return Err(AcceptError::AuthenticationFailed(
                        "missing public keys".into(),
                    ));
                }
            };
            sender.close().await;
            let pk_bytes = bundle.as_bytes();
            return self
                .complete_auth_handshake(
                    sender,
                    receiver,
                    Flow::Register { bundle, pk_bytes },
                    CommunicationType::RegisterResponse,
                    &version_str,
                    client_version,
                    description,
                )
                .await;
        }

        if Some(hello.get_type()) == CommunicationType::Identification.try_to_id(&tm) {
            let cid = match hello.get_data(DataType::Id) {
                DataValue::UnsignedNumber(n) => *n as u64,
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
                        &version_str,
                        client_version,
                        description,
                    )
                    .await;
            }

            let negotiated = match self
                .registry
                .negotiate(std::slice::from_ref(&client_version))
            {
                Some(v) => v,
                None => {
                    send_rejection(
                        &sender,
                        RejectionReason::BadVersion {
                            supported_versions: vec![mtp_codec::PROTOCOL_VERSION.to_string()],
                        },
                    )
                    .await;
                    sender.close().await;
                    return Err(AcceptError::UnsupportedVersion(client_version));
                }
            };
            let codec = match VersionedCodec::for_version(self.registry.clone(), negotiated.clone())
            {
                Some(codec) => codec,
                None => {
                    return Err(AcceptError::UnsupportedVersion(negotiated));
                }
            };
            let guest_id = self.assign_guest_id().await;
            send_accepted(&sender, &negotiated, Some(guest_id))
                .await
                .map_err(AcceptError::Send)?;
            return Ok(Some(self.connection_from_parts(
                sender,
                receiver,
                negotiated,
                codec,
                description,
                AuthState::Unauthenticated,
                guest_id,
                None,
            )));
        }

        sender.close().await;
        Err(AcceptError::AuthenticationFailed(
            "unexpected message type".into(),
        ))
    }
}
