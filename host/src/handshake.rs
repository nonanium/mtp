#[cfg(not(feature = "crypto"))]
use mtp_codec::{Version, registry::{Registry, VersionedCodec}};
#[cfg(feature = "crypto")]
use mtp_codec::registry::Registry;
use mtp_transport::{Receiver, Sender};
use std::sync::Arc;
use std::time::Instant;
#[cfg(feature = "pipes")]
use tokio::sync::mpsc;

use crate::config::HostConfig;
use crate::connection::MTPConnection;
use crate::engine::HandshakeEngine;
use crate::error::AcceptError;
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
        let engine = HandshakeEngine::new(self.registry.clone(), self.config.clone());
        let result = engine.accept(&sender, &receiver).await?;
        #[cfg(feature = "crypto")]
        {
            Ok(Some(self.connection_from_handshake_result(
                sender,
                receiver,
                result,
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
                auth_state: result.auth_state,
                client_id: result.client_id,
                client_public_key: result.client_public_key,
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
                auth_state: result.auth_state,
                client_id: result.client_id,
                client_public_key: result.client_public_key,
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
}
