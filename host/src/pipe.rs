use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue};

use mtp_common::PipeError;

use mtp_transport::{PipeReader, Policy, Receiver, Sender};

use std::collections::HashMap;

use std::sync::Arc;

use tokio::sync::{Mutex, mpsc};

use tracing::debug;

pub struct PipeHandle {
    pub(crate) pipe_id: u32,
    pub(crate) description: String,
    pub(crate) sender: Sender,
    pub(crate) response_rx: tokio::sync::oneshot::Receiver<Result<bool, PipeError>>,
}

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

pub struct PipeRequest {
    pub(crate) pipe_id: u32,
    pub(crate) description: String,
    pub(crate) sender: Sender,
    pub(crate) dispatcher: Arc<PipeDispatcher>,
}

impl PipeRequest {
    pub fn id(&self) -> u32 {
        self.pipe_id
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub async fn accept(self) -> Result<PipeReader, PipeError> {
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

pub(crate) struct PipeDispatcher {
    pub(crate) pending_creations:
        Mutex<HashMap<u32, tokio::sync::oneshot::Sender<Result<bool, PipeError>>>>,
    pub(crate) pending_pipes: Mutex<HashMap<u32, tokio::sync::oneshot::Sender<PipeReader>>>,
    pub(crate) policy: Arc<Policy>,
}

impl PipeDispatcher {
    pub(crate) fn default_for_external() -> Self {
        Self {
            pending_creations: Mutex::new(HashMap::new()),
            pending_pipes: Mutex::new(HashMap::new()),
            policy: Arc::new(Policy::default()),
        }
    }
}

pub(crate) async fn run_dispatcher(
    receiver: Receiver,
    sender: Sender,
    app_tx: mpsc::Sender<Result<CommunicationValue, mtp_common::CommunicationError>>,
    pipe_req_tx: mpsc::Sender<PipeRequest>,
    dispatcher: Arc<PipeDispatcher>,
) {
    let pipe_req_type = CommunicationType::PipeRequest.try_to_id(&mtp_codec::TypeMap::latest());
    let pipe_resp_type = CommunicationType::PipeResponse.try_to_id(&mtp_codec::TypeMap::latest());

    loop {
        match receiver.receive_event().await {
            Ok(mtp_transport::TransportEvent::Message(msg)) => {
                debug!(
                    target = "mtp.host",
                    message_type = ?msg.get_type(),
                    message_id = msg.get_id(),
                    "dispatcher received message"
                );
                if Some(msg.get_type()) == pipe_req_type {
                    let pipe_id = msg.get_id();
                    let description = msg.get_str(DataType::Description).unwrap_or("").to_string();
                    debug!(
                        target = "mtp.host",
                        pipe_id, description, "dispatcher classified pipe request"
                    );
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
                    debug!(
                        target = "mtp.host",
                        pipe_id, accepted, "dispatcher classified pipe response"
                    );
                    let mut pending = dispatcher.pending_creations.lock().await;
                    if let Some(tx) = pending.remove(&pipe_id) {
                        let _ = tx.send(Ok(accepted));
                    }
                    continue;
                }

                if app_tx.send(Ok(msg)).await.is_err() {
                    break;
                }
            }
            Ok(mtp_transport::TransportEvent::Pipe(reader)) => {
                let pipe_id = reader.pipe_id();
                debug!(
                    target = "mtp.host",
                    pipe_id,
                    description = reader.description(),
                    "dispatcher received pipe stream"
                );
                let mut pending = dispatcher.pending_pipes.lock().await;
                if let Some(tx) = pending.remove(&pipe_id) {
                    let _ = tx.send(reader);
                    continue;
                }

                debug!(
                    target = "mtp.host",
                    pipe_id, "dispatcher treating pipe stream as pipe request"
                );
                let req = PipeRequest {
                    pipe_id,
                    description: reader.description().to_string(),
                    sender: sender.clone(),
                    dispatcher: dispatcher.clone(),
                };
                let _ = pipe_req_tx.send(req).await;
            }
            Err(e) => {
                if app_tx.send(Err(e)).await.is_err() {
                    break;
                }
            }
        }
    }
}
