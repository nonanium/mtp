use mtp_codec::CommunicationValue;
use mtp_common::CommunicationError;
use mtp_transport::Receiver;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

#[cfg(feature = "pipes")]
use mtp_codec::{CommunicationType, DataType, DataValue};
#[cfg(feature = "pipes")]
use mtp_common::PipeError;
#[cfg(feature = "pipes")]
use mtp_transport::{Policy, Sender};

#[cfg(feature = "pipes")]
pub struct PipeHandle {
    pub(crate) pipe_id: u32,
    pub(crate) description: String,
    pub(crate) sender: Sender,
    pub(crate) response_rx: tokio::sync::oneshot::Receiver<Result<bool, PipeError>>,
}

#[cfg(feature = "pipes")]
impl PipeHandle {
    pub fn pipe_id(&self) -> u32 {
        self.pipe_id
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub async fn wait(self) -> Result<Option<mtp_transport::PipeWriter>, PipeError> {
        match self.response_rx.await {
            Ok(Ok(true)) => {
                let writer = self
                    .sender
                    .open_pipe(self.pipe_id, &self.description)
                    .await
                    .map_err(PipeError::from)?;
                Ok(Some(writer))
            }
            Ok(Ok(false)) => Ok(None),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(PipeError::StreamClosed),
        }
    }
}

#[cfg(feature = "pipes")]
pub struct PipeRequest {
    pub(crate) pipe_id: u32,
    pub(crate) description: String,
    pub(crate) sender: Sender,
    pub(crate) dispatcher: Arc<PipeDispatcher>,
}

#[cfg(feature = "pipes")]
impl PipeRequest {
    pub fn id(&self) -> u32 {
        self.pipe_id
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub async fn accept(self) -> Result<mtp_transport::PipeReader, PipeError> {
        let (pipe_tx, pipe_rx) = tokio::sync::oneshot::channel();
        {
            let mut pending = self.dispatcher.pending_pipes.lock().await;
            pending.insert(self.pipe_id, pipe_tx);
        }

        let resp = CommunicationValue::new(CommunicationType::PipeResponse)
            .with_id(self.pipe_id)
            .add_typed_default(DataType::Accepted, DataValue::BoolTrue);
        self.sender.send(&resp).await.map_err(PipeError::from)?;

        let timeout = self.dispatcher.policy.read_timeout;
        tokio::time::timeout(timeout, pipe_rx)
            .await
            .map_err(|_| PipeError::HandshakeTimeout)?
            .map_err(|_| PipeError::StreamClosed)
    }

    pub async fn deny(self) -> Result<(), PipeError> {
        let resp = CommunicationValue::new(CommunicationType::PipeResponse)
            .with_id(self.pipe_id)
            .add_typed_default(DataType::Accepted, DataValue::BoolFalse);
        self.sender.send(&resp).await.map_err(PipeError::from)?;
        Ok(())
    }
}

pub(crate) struct PendingRequest {
    pub(crate) token: Arc<()>,
    pub(crate) sender: tokio::sync::oneshot::Sender<Result<CommunicationValue, CommunicationError>>,
}

pub(crate) struct PipeDispatcher {
    pub(crate) pending_requests: Mutex<HashMap<u32, PendingRequest>>,
    #[cfg(feature = "pipes")]
    pub(crate) pending_creations:
        Mutex<HashMap<u32, tokio::sync::oneshot::Sender<Result<bool, PipeError>>>>,
    #[cfg(feature = "pipes")]
    pub(crate) pending_pipes:
        Mutex<HashMap<u32, tokio::sync::oneshot::Sender<mtp_transport::PipeReader>>>,
    #[cfg(feature = "pipes")]
    pub(crate) policy: Arc<Policy>,
}

pub(crate) async fn route_message(
    msg: CommunicationValue,
    app_tx: &mpsc::Sender<Result<CommunicationValue, CommunicationError>>,
    dispatcher: &PipeDispatcher,
) -> bool {
    let pending = dispatcher
        .pending_requests
        .lock()
        .await
        .remove(&msg.get_id());
    if let Some(tx) = pending {
        let _ = tx.sender.send(Ok(msg));
        return true;
    }

    app_tx.send(Ok(msg)).await.is_ok()
}

pub(crate) async fn fail_pending_requests(dispatcher: &PipeDispatcher, error: CommunicationError) {
    let pending = std::mem::take(&mut *dispatcher.pending_requests.lock().await);
    for (_, pending) in pending {
        let _ = pending.sender.send(Err(error.clone()));
    }
}

pub(crate) async fn remove_pending_request(
    dispatcher: &PipeDispatcher,
    request_id: u32,
    token: &Arc<()>,
) {
    let mut pending = dispatcher.pending_requests.lock().await;
    if pending
        .get(&request_id)
        .is_some_and(|entry| Arc::ptr_eq(&entry.token, token))
    {
        pending.remove(&request_id);
    }
}

#[cfg(feature = "pipes")]
pub(crate) async fn run_dispatcher(
    receiver: Receiver,
    sender: Sender,
    app_tx: mpsc::Sender<Result<CommunicationValue, CommunicationError>>,
    pipe_req_tx: mpsc::Sender<PipeRequest>,
    dispatcher: Arc<PipeDispatcher>,
) {
    let pipe_req_type = CommunicationType::PipeRequest.try_to_id(&mtp_codec::TypeMap::latest());
    let pipe_resp_type = CommunicationType::PipeResponse.try_to_id(&mtp_codec::TypeMap::latest());

    loop {
        match receiver.receive_event().await {
            Ok(mtp_transport::TransportEvent::Message(msg)) => {
                if Some(msg.get_type()) == pipe_req_type {
                    let pipe_id = msg.get_id();
                    let description = msg.get_str(DataType::Description).unwrap_or("").to_string();
                    let req = PipeRequest {
                        pipe_id,
                        description,
                        sender: sender.clone(),
                        dispatcher: dispatcher.clone(),
                    };
                    let _ = pipe_req_tx.send(req).await;
                    continue;
                }

                if Some(msg.get_type()) == pipe_resp_type {
                    let pipe_id = msg.get_id();
                    let accepted = msg.get_bool(DataType::Accepted).unwrap_or(false);
                    let mut pending = dispatcher.pending_creations.lock().await;
                    if let Some(tx) = pending.remove(&pipe_id) {
                        let _ = tx.send(Ok(accepted));
                    }
                    continue;
                }

                if !route_message(msg, &app_tx, &dispatcher).await {
                    break;
                }
            }
            Ok(mtp_transport::TransportEvent::Pipe(reader)) => {
                let pipe_id = reader.pipe_id();
                let mut pending = dispatcher.pending_pipes.lock().await;
                if let Some(tx) = pending.remove(&pipe_id) {
                    let _ = tx.send(reader);
                }
            }
            Err(e) => {
                fail_pending_requests(&dispatcher, e.clone()).await;
                let _ = app_tx.send(Err(e)).await;
                break;
            }
        }
    }
}

#[cfg(not(feature = "pipes"))]
pub(crate) async fn run_dispatcher(
    receiver: Receiver,
    app_tx: mpsc::Sender<Result<CommunicationValue, CommunicationError>>,
    dispatcher: Arc<PipeDispatcher>,
) {
    loop {
        match receiver.receive().await {
            Ok(msg) => {
                if !route_message(msg, &app_tx, &dispatcher).await {
                    break;
                }
            }
            Err(e) => {
                fail_pending_requests(&dispatcher, e.clone()).await;
                let _ = app_tx.send(Err(e)).await;
                break;
            }
        }
    }
}
