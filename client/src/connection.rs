use mtp_codec::{CommunicationValue, Version, registry::VersionedCodec};
use mtp_common::{CommunicationError, RequestId, TransportPhase};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio::time::Duration;

use crate::config::ClientConfig;
#[cfg(feature = "crypto")]
use crate::error::AuthState;
use crate::ping::{PingSession, start_ping_session};
use crate::pipe::{PendingRequest, PipeDispatcher, run_dispatcher};
#[cfg(feature = "pipes")]
use mtp_pipes::PipeRequest;

pub struct MTPConnection {
    pub version: Version,
    pub codec: VersionedCodec,
    pub sender: mtp_native::Sender,
    pub receiver: mtp_native::Receiver,
    pub description: Option<String>,
    /// The peer address observed by the underlying QUIC connection.
    pub remote_addr: Option<SocketAddr>,
    pub(crate) ping: Option<PingSession>,
    pub(crate) app_rx: Mutex<mpsc::Receiver<Result<CommunicationValue, CommunicationError>>>,
    #[cfg(feature = "pipes")]
    pub(crate) pipe_req_rx: Mutex<
        mpsc::Receiver<
            PipeRequest<mtp_native::Sender, mtp_native::Receiver, mtp_native::NativeRecvStream>,
        >,
    >,
    pub(crate) pipe_dispatcher: Arc<PipeDispatcher>,
    pub(crate) request_timeout: Duration,
    pub(crate) _dispatcher_task: tokio::task::JoinHandle<()>,
    #[cfg(feature = "crypto")]
    pub auth_state: AuthState,
    #[cfg(feature = "crypto")]
    pub client_id: u64,
}

impl MTPConnection {
    pub fn get_ping(&self) -> Option<Duration> {
        self.ping.as_ref().and_then(PingSession::get_ping)
    }

    pub async fn request(
        &self,
        request: &CommunicationValue,
        expected_response: Option<mtp_codec::CommunicationType>,
    ) -> Result<CommunicationValue, CommunicationError> {
        self.request_with_timeout(request, expected_response, self.request_timeout)
            .await
    }

    pub async fn request_with_timeout(
        &self,
        request: &CommunicationValue,
        expected_response: Option<mtp_codec::CommunicationType>,
        timeout: Duration,
    ) -> Result<CommunicationValue, CommunicationError> {
        let request_id = request.id().and_then(RequestId::new).ok_or_else(|| {
            CommunicationError::Other("request frame must have a non-zero id".into())
        })?;
        let expected_type = expected_response
            .map(|expected| {
                expected.try_to_id(self.codec.type_map()).ok_or_else(|| {
                    CommunicationError::Other(format!(
                        "expected response type {expected:?} is absent from the type map"
                    ))
                })
            })
            .transpose()?;
        if crate::pipe::is_expired_request(&self.pipe_dispatcher, request_id).await {
            return Err(CommunicationError::Other(format!(
                "request id {} recently timed out; use a new request id",
                request_id.get()
            )));
        }

        let (sender, receiver) = tokio::sync::oneshot::channel();
        let token = Arc::new(());
        {
            let mut pending = self.pipe_dispatcher.pending_requests.lock().await;
            if pending.pending.contains_key(&request_id) {
                return Err(CommunicationError::Other(format!(
                    "request id {} is already pending",
                    request_id.get()
                )));
            }
            pending
                .insert(
                    request_id,
                    PendingRequest {
                        token: token.clone(),
                        expected_type,
                        sender,
                    },
                    mtp_common::unix_time_millis().unwrap_or_default() as f64,
                )
                .map_err(|_| CommunicationError::Other("request id is already pending".into()))?;
        }

        let _cancellation = RequestCancellation {
            dispatcher: self.pipe_dispatcher.clone(),
            request_id,
            token: token.clone(),
        };
        if let Err(error) = self.sender.send(request).await {
            crate::pipe::remove_pending_request(&self.pipe_dispatcher, request_id, &token).await;
            return Err(error);
        }

        let response = match tokio::time::timeout(timeout, receiver).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                crate::pipe::remove_pending_request(&self.pipe_dispatcher, request_id, &token)
                    .await;
                return Err(CommunicationError::ConnectionLost);
            }
            Err(_) => {
                crate::pipe::expire_pending_request(&self.pipe_dispatcher, request_id, &token)
                    .await;
                return Err(CommunicationError::timeout(TransportPhase::WaitResponse));
            }
        };

        if response.is_err() {
            crate::pipe::remove_pending_request(&self.pipe_dispatcher, request_id, &token).await;
        }
        response
    }

    pub async fn receive(&self) -> Result<CommunicationValue, CommunicationError> {
        let mut rx = self.app_rx.lock().await;
        match rx.recv().await {
            Some(result) => result,
            None => Err(CommunicationError::ConnectionLost),
        }
    }
}

struct RequestCancellation {
    dispatcher: Arc<PipeDispatcher>,
    request_id: RequestId,
    token: Arc<()>,
}

impl Drop for RequestCancellation {
    fn drop(&mut self) {
        let dispatcher = self.dispatcher.clone();
        let request_id = self.request_id;
        let token = self.token.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                crate::pipe::expire_pending_request(&dispatcher, request_id, &token).await;
            });
        }
    }
}

#[cfg(feature = "pipes")]
impl MTPConnection {
    pub async fn create_pipe(
        &self,
        description: &str,
    ) -> Result<
        mtp_pipes::PipeHandle<mtp_native::Sender, mtp_native::NativeRecvStream>,
        mtp_common::PipeError,
    > {
        self.pipe_dispatcher
            .pipes
            .create(self.sender.clone(), description)
            .await
    }

    pub async fn receive_pipe(
        &self,
    ) -> Result<
        PipeRequest<mtp_native::Sender, mtp_native::Receiver, mtp_native::NativeRecvStream>,
        CommunicationError,
    > {
        let mut rx = self.pipe_req_rx.lock().await;
        match rx.recv().await {
            Some(req) => Ok(req),
            None => Err(CommunicationError::ConnectionLost),
        }
    }
}

pub(crate) async fn connection_from_parts(
    config: ClientConfig,
    sender: mtp_native::Sender,
    receiver: mtp_native::Receiver,
    version: Version,
    codec: VersionedCodec,
    #[cfg(feature = "crypto")] auth_state: AuthState,
    #[cfg(feature = "crypto")] client_id: u64,
) -> MTPConnection {
    #[cfg(feature = "pipes")]
    let type_map = codec.type_map().clone();
    receiver.set_type_map(codec.type_map()).await;
    receiver.set_max_message_size(config.policy.max_message_size);
    let remote_addr = sender.handle().remote_addr();
    #[cfg(feature = "crypto")]
    let ping_client_id = client_id;
    #[cfg(not(feature = "crypto"))]
    let ping_client_id = config.client_id;
    let ping = start_ping_session(
        &config,
        sender.clone(),
        &receiver,
        codec.type_map(),
        ping_client_id,
    )
    .await;

    #[cfg(feature = "pipes")]
    {
        let receiver_queue_capacity = config.policy.receiver_queue_capacity.max(1);
        let (app_tx, app_rx) = mpsc::channel::<Result<CommunicationValue, CommunicationError>>(
            receiver_queue_capacity,
        );
        let (pipe_req_tx, pipe_req_rx) = mpsc::channel(receiver_queue_capacity);

        let dispatcher = Arc::new(PipeDispatcher {
            pending_requests: Mutex::new(mtp_common::RequestTracker::new(
                config.policy.request_tombstone_ttl.as_secs_f64() * 1000.0,
                config.policy.request_tombstone_capacity,
            )),
            pipes: mtp_pipes::PipeDispatcher::new(Arc::new(config.policy), type_map),
        });

        let dispatcher_clone = dispatcher.clone();
        let sender_clone = sender.clone();
        let dispatcher_task = tokio::spawn(run_dispatcher(
            receiver.clone(),
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
            app_rx: Mutex::new(app_rx),
            pipe_req_rx: Mutex::new(pipe_req_rx),
            pipe_dispatcher: dispatcher,
            request_timeout: config.request_timeout,
            description: config.description,
            remote_addr,
            ping,
            _dispatcher_task: dispatcher_task,
            #[cfg(feature = "crypto")]
            auth_state,
            #[cfg(feature = "crypto")]
            client_id,
        }
    }

    #[cfg(not(feature = "pipes"))]
    {
        let receiver_queue_capacity = config.policy.receiver_queue_capacity.max(1);
        let (app_tx, app_rx) = mpsc::channel::<Result<CommunicationValue, CommunicationError>>(
            receiver_queue_capacity,
        );
        let dispatcher = Arc::new(PipeDispatcher {
            pending_requests: Mutex::new(mtp_common::RequestTracker::new(
                config.policy.request_tombstone_ttl.as_secs_f64() * 1000.0,
                config.policy.request_tombstone_capacity,
            )),
        });
        let task = tokio::spawn(run_dispatcher(receiver.clone(), app_tx, dispatcher.clone()));

        MTPConnection {
            version,
            codec,
            sender,
            receiver,
            app_rx: Mutex::new(app_rx),
            pipe_dispatcher: dispatcher,
            request_timeout: config.request_timeout,
            description: config.description,
            remote_addr,
            ping,
            _dispatcher_task: task,
            #[cfg(feature = "crypto")]
            auth_state,
            #[cfg(feature = "crypto")]
            client_id,
        }
    }
}
