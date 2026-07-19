use mtp_codec::{CommunicationValue, Version};
#[cfg(feature = "pipes")]
use mtp_codec::{DataType, DataValue};
use mtp_common::CommunicationError;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio::time::Duration;

use crate::config::ClientConfig;
#[cfg(feature = "crypto")]
use crate::error::AuthState;
use crate::ping::{PingSession, start_ping_session};
#[cfg(feature = "pipes")]
use crate::pipe::PipeRequest;
use crate::pipe::{PendingRequest, PipeDispatcher, run_dispatcher};

pub struct MTPConnection {
    pub version: Version,
    pub sender: mtp_transport::Sender,
    pub receiver: mtp_transport::Receiver,
    pub description: Option<String>,
    /// The peer address observed by the underlying QUIC connection.
    pub remote_addr: Option<SocketAddr>,
    pub(crate) ping: Option<PingSession>,
    pub(crate) app_rx: Mutex<mpsc::Receiver<Result<CommunicationValue, CommunicationError>>>,
    #[cfg(feature = "pipes")]
    pub(crate) pipe_req_rx: Mutex<mpsc::Receiver<PipeRequest>>,
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
        let request_id = request.get_id();
        if request_id == 0 {
            return Err(CommunicationError::Other(
                "request frame must have a non-zero id".into(),
            ));
        }

        let (sender, receiver) = tokio::sync::oneshot::channel();
        let token = Arc::new(());
        {
            let mut pending = self.pipe_dispatcher.pending_requests.lock().await;
            if pending.contains_key(&request_id) {
                return Err(CommunicationError::Other(format!(
                    "request id {request_id} is already pending"
                )));
            }
            pending.insert(
                request_id,
                PendingRequest {
                    token: token.clone(),
                    sender,
                },
            );
        }

        let response = match tokio::time::timeout(self.request_timeout, async {
            self.sender.send(request).await?;
            receiver
                .await
                .map_err(|_| CommunicationError::StreamClosed)?
        })
        .await
        {
            Ok(result) => {
                if result.is_err() {
                    crate::pipe::remove_pending_request(&self.pipe_dispatcher, request_id, &token)
                        .await;
                }
                result?
            }
            Err(_) => {
                crate::pipe::remove_pending_request(&self.pipe_dispatcher, request_id, &token)
                    .await;
                return Err(CommunicationError::Other(format!(
                    "request {request_id} timed out after {:?}",
                    self.request_timeout
                )));
            }
        };

        if let Some(expected) = expected_response {
            let expected_type = expected.try_to_id(&mtp_codec::TypeMap::latest());
            if Some(response.get_type()) != expected_type {
                return Err(CommunicationError::Other(format!(
                    "unexpected response type: expected {:?}, got {:?}; parsed {}",
                    expected_type,
                    response.get_type(),
                    response
                )));
            }
        }

        Ok(response)
    }

    pub async fn receive(&self) -> Result<CommunicationValue, CommunicationError> {
        let mut rx = self.app_rx.lock().await;
        match rx.recv().await {
            Some(result) => result,
            None => Err(CommunicationError::StreamClosed),
        }
    }
}

#[cfg(feature = "pipes")]
impl MTPConnection {
    pub async fn create_pipe(
        &self,
        description: &str,
    ) -> Result<crate::pipe::PipeHandle, mtp_common::PipeError> {
        let pipe_id = rand::random::<u32>();
        let (tx, rx) = tokio::sync::oneshot::channel();

        {
            let mut pending = self.pipe_dispatcher.pending_creations.lock().await;
            pending.insert(pipe_id, tx);
        }

        let request = CommunicationValue::new(mtp_codec::CommunicationType::PipeRequest)
            .with_id(pipe_id)
            .add_typed_default(DataType::Description, DataValue::Str(description.into()));

        self.sender
            .send(&request)
            .await
            .map_err(mtp_common::PipeError::from)?;

        Ok(crate::pipe::PipeHandle {
            pipe_id,
            description: description.to_string(),
            sender: self.sender.clone(),
            response_rx: rx,
        })
    }

    pub async fn receive_pipe(&self) -> Result<PipeRequest, CommunicationError> {
        let mut rx = self.pipe_req_rx.lock().await;
        match rx.recv().await {
            Some(req) => Ok(req),
            None => Err(CommunicationError::StreamClosed),
        }
    }
}

pub(crate) fn connection_from_parts(
    config: ClientConfig,
    sender: mtp_transport::Sender,
    receiver: mtp_transport::Receiver,
    version: Version,
    #[cfg(feature = "crypto")] auth_state: AuthState,
    #[cfg(feature = "crypto")] client_id: u64,
) -> MTPConnection {
    let remote_addr = sender.handle().remote_addr();
    let ping = start_ping_session(&config, sender.clone(), &receiver);

    #[cfg(feature = "pipes")]
    {
        let (app_tx, app_rx) = mpsc::channel::<Result<CommunicationValue, CommunicationError>>(
            config.policy.receiver_queue_capacity,
        );
        let (pipe_req_tx, pipe_req_rx) =
            mpsc::channel::<PipeRequest>(config.policy.receiver_queue_capacity);

        let dispatcher = Arc::new(PipeDispatcher {
            pending_requests: Mutex::new(std::collections::HashMap::new()),
            pending_creations: Mutex::new(std::collections::HashMap::new()),
            pending_pipes: Mutex::new(std::collections::HashMap::new()),
            policy: Arc::new(config.policy),
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
        let (app_tx, app_rx) = mpsc::channel::<Result<CommunicationValue, CommunicationError>>(
            config.policy.receiver_queue_capacity,
        );
        let dispatcher = Arc::new(PipeDispatcher {
            pending_requests: Mutex::new(std::collections::HashMap::new()),
        });
        let task = tokio::spawn(run_dispatcher(receiver.clone(), app_tx, dispatcher.clone()));

        MTPConnection {
            version,
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
