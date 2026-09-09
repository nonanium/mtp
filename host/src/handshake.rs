#[cfg(feature = "crypto")]
use mtp_codec::registry::Registry;
#[cfg(not(feature = "crypto"))]
use mtp_codec::{
    Version,
    registry::{Registry, VersionedCodec},
};
use mtp_native::{Receiver, Sender};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
#[cfg(feature = "pipes")]
use tokio::sync::mpsc;
use tokio::time::{Instant as TokioInstant, timeout_at};

use crate::config::{AuthenticationContext, HostConfig};
use crate::connection::MTPConnection;
use crate::engine::HandshakeEngine;
use crate::error::AcceptError;
#[cfg(feature = "pipes")]
use crate::pipe::PipeDispatcher;
#[cfg(feature = "pipes")]
use crate::pipe::run_dispatcher;

pub struct MTPHost {
    pub(crate) transport: mtp_native::Host,
    pub(crate) context: Arc<HandshakeContext>,
    pub(crate) handshakes: tokio::task::JoinSet<Result<Option<MTPConnection>, AcceptError>>,
    pub(crate) authentication_limit: Arc<Semaphore>,
    pub(crate) transport_closed: bool,
}

pub(crate) struct HandshakeContext {
    pub(crate) registry: Registry,
    pub(crate) config: Arc<HostConfig>,
}

impl MTPHost {
    pub async fn new(config: HostConfig) -> Result<Self, mtp_common::CommunicationError> {
        let registry = Registry::builtin();

        let transport = mtp_native::host_with_config(
            config.ip,
            config.port,
            mtp_native::HostConfig::new(
                config.tls_fullchain.clone(),
                config.tls_key.clone(),
                config.policy,
            )
            .with_max_transport_handshakes(config.max_transport_handshakes)
            .with_max_pending_connections(config.max_pending_connections),
        )
        .await?;
        let authentication_limit = Arc::new(Semaphore::new(config.max_pending_authentications));

        Ok(Self {
            transport,
            context: Arc::new(HandshakeContext {
                registry,
                config: Arc::new(config),
            }),
            handshakes: tokio::task::JoinSet::new(),
            authentication_limit,
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
                        let Ok(permit) = self.authentication_limit.clone().try_acquire_owned()
                        else {
                            tracing::debug!("dropping connection: authentication budget exhausted");
                            continue;
                        };
                        self.handshakes.spawn(async move {
                            let _permit = permit;
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
                            let Ok(permit) = self.authentication_limit.clone().try_acquire_owned() else {
                                tracing::debug!("dropping connection: authentication budget exhausted");
                                continue;
                            };
                            self.handshakes
                                .spawn(async move {
                                    let _permit = permit;
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

    pub fn stop_accepting(&self) {
        self.transport.stop_accepting();
    }

    /// Stop admission, then reap authentication and transport work by the
    /// caller's deadline. Remaining work is aborted before return.
    pub async fn shutdown(&mut self, deadline: TokioInstant) {
        self.stop_accepting();
        while !self.handshakes.is_empty() {
            if timeout_at(deadline, self.handshakes.join_next())
                .await
                .is_err()
            {
                self.handshakes.abort_all();
                break;
            }
        }
        while self.handshakes.join_next().await.is_some() {}
        self.transport.shutdown(deadline).await;
    }
}

impl HandshakeContext {
    async fn accept_pair_timed(
        &self,
        sender: Sender,
        receiver: Receiver,
    ) -> Result<Option<MTPConnection>, AcceptError> {
        let engine = HandshakeEngine::new(self.registry.clone(), self.config.clone());
        let authentication_context = AuthenticationContext {
            peer_network_identity: sender.handle().remote_addr().map(|address| address.ip()),
            connection_id: sender.handle().connection_id(),
        };
        let result = engine
            .accept_with_context(&sender, &receiver, authentication_context)
            .await?;
        #[cfg(feature = "crypto")]
        {
            Ok(Some(self.connection_from_handshake_result(
                sender, receiver, result,
            )))
        }
        #[cfg(not(feature = "crypto"))]
        {
            Ok(Some(self.connection_from_parts(
                sender,
                receiver,
                result.negotiated_version,
                result.codec,
                result.description,
            )))
        }
    }

    #[cfg(feature = "crypto")]
    pub(crate) fn connection_from_handshake_result(
        &self,
        sender: Sender,
        receiver: Receiver,
        result: crate::engine::HandshakeResult,
    ) -> MTPConnection {
        let remote_addr = sender.handle().remote_addr();
        receiver.set_max_message_size(self.config.policy.max_message_size);
        #[cfg(feature = "pipes")]
        let type_map = result.codec.type_map().clone();
        #[cfg(feature = "pipes")]
        {
            if self.config.send_pongs {
                receiver.respond_to_pings(sender.clone());
            }

            let receiver_queue_capacity = self.config.policy.receiver_queue_capacity.max(1);
            let (app_tx, app_rx) = mpsc::channel(receiver_queue_capacity);
            let (pipe_req_tx, pipe_req_rx) = mpsc::channel(receiver_queue_capacity);

            let dispatcher = Arc::new(PipeDispatcher {
                pending_creations: std::sync::Mutex::new(std::collections::HashMap::new()),
                expired_creations: std::sync::Mutex::new(mtp_common::ExpiringSet::new(
                    self.config.policy.pipe_tombstone_ttl.as_secs_f64() * 1000.0,
                    self.config.policy.pipe_tombstone_capacity,
                )),
                pending_pipes: tokio::sync::Mutex::new(std::collections::HashMap::new()),
                policy: Arc::new(self.config.policy),
                type_map: type_map.clone(),
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
                version: result.negotiated_version,
                codec: result.codec,
                sender,
                receiver,
                path: "/".to_string(),
                remote_addr,
                app_rx: tokio::sync::Mutex::new(app_rx),
                pipe_req_rx: tokio::sync::Mutex::new(pipe_req_rx),
                pipe_dispatcher: dispatcher,
                description: result.description,
                _dispatcher_task: task,
                _connection_guard: None,
                _session_task: None,
                auth_state: result.auth_state,
                client_id: result.client_id,
                client_public_key: result.client_public_key,
                guest_id_lease: result.guest_id_lease,
            }
        }

        #[cfg(not(feature = "pipes"))]
        {
            if self.config.send_pongs {
                receiver.respond_to_pings(sender.clone());
            }

            let task = tokio::spawn(async {});

            MTPConnection {
                version: result.negotiated_version,
                codec: result.codec,
                sender,
                receiver,
                path: "/".to_string(),
                remote_addr,
                _pipe_stream: std::marker::PhantomData,
                description: result.description,
                _dispatcher_task: task,
                _connection_guard: None,
                _session_task: None,
                auth_state: result.auth_state,
                client_id: result.client_id,
                client_public_key: result.client_public_key,
                guest_id_lease: result.guest_id_lease,
            }
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
        let type_map = codec.type_map().clone();
        #[cfg(feature = "pipes")]
        {
            if self.config.send_pongs {
                receiver.respond_to_pings(sender.clone());
            }

            let receiver_queue_capacity = self.config.policy.receiver_queue_capacity.max(1);
            let (app_tx, app_rx) = mpsc::channel(receiver_queue_capacity);
            let (pipe_req_tx, pipe_req_rx) = mpsc::channel(receiver_queue_capacity);

            let dispatcher = Arc::new(PipeDispatcher {
                pending_creations: std::sync::Mutex::new(std::collections::HashMap::new()),
                expired_creations: std::sync::Mutex::new(mtp_common::ExpiringSet::new(
                    self.config.policy.pipe_tombstone_ttl.as_secs_f64() * 1000.0,
                    self.config.policy.pipe_tombstone_capacity,
                )),
                pending_pipes: tokio::sync::Mutex::new(std::collections::HashMap::new()),
                policy: Arc::new(self.config.policy),
                type_map,
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
                _connection_guard: None,
                _session_task: None,
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
                _connection_guard: None,
                _session_task: None,
            }
        }
    }
}
