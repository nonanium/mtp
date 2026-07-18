use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp_common::{CommunicationError, PipeError};
use mtp_transport::{PipeReader, PipeWriter, Policy, TransportEvent};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

/// The sender operations needed by the transport-independent pipe protocol.
pub trait PipeSender: Clone + Send + Sync + 'static {
    type Writer: tokio::io::AsyncWrite + Send + Unpin + 'static;

    fn send_pipe_message(
        &self,
        message: &CommunicationValue,
    ) -> impl std::future::Future<Output = Result<(), CommunicationError>> + Send;

    fn open_pipe_stream(
        &self,
        pipe_id: u32,
        description: &str,
    ) -> impl std::future::Future<Output = Result<PipeWriter<Self::Writer>, CommunicationError>> + Send;
}

/// The receiver operations needed by the transport-independent pipe protocol.
pub trait PipeReceiver<P>: Clone + Send + Sync + 'static
where
    P: tokio::io::AsyncRead + Send + Unpin + 'static,
{
    fn receive_pipe_event(
        &self,
    ) -> impl std::future::Future<Output = Result<TransportEvent<P>, CommunicationError>> + Send;
}

impl PipeSender for mtp_transport::Sender {
    type Writer = wtransport::SendStream;

    async fn send_pipe_message(
        &self,
        message: &CommunicationValue,
    ) -> Result<(), CommunicationError> {
        self.send(message).await
    }

    async fn open_pipe_stream(
        &self,
        pipe_id: u32,
        description: &str,
    ) -> Result<PipeWriter<Self::Writer>, CommunicationError> {
        self.open_pipe(pipe_id, description).await
    }
}

impl PipeReceiver<wtransport::RecvStream> for mtp_transport::Receiver {
    async fn receive_pipe_event(
        &self,
    ) -> Result<TransportEvent<wtransport::RecvStream>, CommunicationError> {
        self.receive_event().await
    }
}

impl<C> PipeSender for mtp_transport::GenericSender<C>
where
    C: mtp_transport::TransportConnection,
    C::SendStream: tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    type Writer = C::SendStream;

    async fn send_pipe_message(
        &self,
        message: &CommunicationValue,
    ) -> Result<(), CommunicationError> {
        self.send(message).await
    }

    async fn open_pipe_stream(
        &self,
        pipe_id: u32,
        description: &str,
    ) -> Result<PipeWriter<Self::Writer>, CommunicationError> {
        self.open_pipe(pipe_id, description).await
    }
}

impl<C> PipeReceiver<C::RecvStream> for mtp_transport::GenericReceiver<C>
where
    C: mtp_transport::TransportConnection,
    C::RecvStream: tokio::io::AsyncRead + Send + Unpin + 'static,
{
    async fn receive_pipe_event(
        &self,
    ) -> Result<TransportEvent<C::RecvStream>, CommunicationError> {
        self.receive_event().await
    }
}

pub struct PipeHandle<S: PipeSender> {
    pub(crate) pipe_id: u32,
    pub(crate) description: String,
    pub(crate) sender: S,
    pub(crate) response_rx: tokio::sync::oneshot::Receiver<Result<bool, PipeError>>,
}

impl<S: PipeSender> PipeHandle<S> {
    pub fn pipe_id(&self) -> u32 {
        self.pipe_id
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub async fn wait(self) -> Result<Option<PipeWriter<S::Writer>>, PipeError> {
        match self.response_rx.await {
            Ok(Ok(true)) => self
                .sender
                .open_pipe_stream(self.pipe_id, &self.description)
                .await
                .map(Some)
                .map_err(PipeError::from),
            Ok(Ok(false)) => Ok(None),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(PipeError::StreamClosed),
        }
    }
}

pub struct PipeRequest<S, P> {
    pub(crate) pipe_id: u32,
    pub(crate) description: String,
    pub(crate) sender: S,
    pub(crate) dispatcher: Arc<PipeDispatcher<P>>,
}

impl<S, P> PipeRequest<S, P>
where
    S: PipeSender,
    P: tokio::io::AsyncRead + Send + Unpin + 'static,
{
    pub fn id(&self) -> u32 {
        self.pipe_id
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub async fn accept(self) -> Result<PipeReader<P>, PipeError> {
        let (pipe_tx, pipe_rx) = tokio::sync::oneshot::channel();
        self.dispatcher
            .pending_pipes
            .lock()
            .await
            .insert(self.pipe_id, pipe_tx);

        let response = CommunicationValue::new(CommunicationType::PipeResponse)
            .with_id(self.pipe_id)
            .add_typed_default(DataType::Accepted, DataValue::BoolTrue);
        self.sender
            .send_pipe_message(&response)
            .await
            .map_err(PipeError::from)?;

        tokio::time::timeout(self.dispatcher.policy.read_timeout, pipe_rx)
            .await
            .map_err(|_| PipeError::HandshakeTimeout)?
            .map_err(|_| PipeError::StreamClosed)
    }

    pub async fn deny(self) -> Result<(), PipeError> {
        let response = CommunicationValue::new(CommunicationType::PipeResponse)
            .with_id(self.pipe_id)
            .add_typed_default(DataType::Accepted, DataValue::BoolFalse);
        self.sender
            .send_pipe_message(&response)
            .await
            .map_err(PipeError::from)
    }
}

pub(crate) struct PipeDispatcher<P> {
    pub(crate) pending_creations:
        Mutex<HashMap<u32, tokio::sync::oneshot::Sender<Result<bool, PipeError>>>>,
    pub(crate) pending_pipes: Mutex<HashMap<u32, tokio::sync::oneshot::Sender<PipeReader<P>>>>,
    pub(crate) policy: Arc<Policy>,
}

pub(crate) async fn run_dispatcher<S, R, P>(
    receiver: R,
    sender: S,
    app_tx: mpsc::Sender<Result<CommunicationValue, CommunicationError>>,
    pipe_req_tx: mpsc::Sender<PipeRequest<S, P>>,
    dispatcher: Arc<PipeDispatcher<P>>,
) where
    S: PipeSender,
    R: PipeReceiver<P>,
    P: tokio::io::AsyncRead + Send + Unpin + 'static,
{
    let pipe_req_type = CommunicationType::PipeRequest.try_to_id(&mtp_codec::TypeMap::latest());
    let pipe_resp_type = CommunicationType::PipeResponse.try_to_id(&mtp_codec::TypeMap::latest());

    loop {
        match receiver.receive_pipe_event().await {
            Ok(TransportEvent::Message(message)) => {
                if Some(message.get_type()) == pipe_req_type {
                    let request = PipeRequest {
                        pipe_id: message.get_id(),
                        description: message
                            .get_str(DataType::Description)
                            .unwrap_or("")
                            .to_owned(),
                        sender: sender.clone(),
                        dispatcher: dispatcher.clone(),
                    };
                    let _ = pipe_req_tx.send(request).await;
                    continue;
                }
                if Some(message.get_type()) == pipe_resp_type {
                    let mut pending = dispatcher.pending_creations.lock().await;
                    if let Some(reply) = pending.remove(&message.get_id()) {
                        let _ =
                            reply.send(Ok(message.get_bool(DataType::Accepted).unwrap_or(false)));
                    }
                    continue;
                }
                if app_tx.send(Ok(message)).await.is_err() {
                    break;
                }
            }
            Ok(TransportEvent::Pipe(reader)) => {
                let pipe_id = reader.pipe_id();
                let mut pending = dispatcher.pending_pipes.lock().await;
                if let Some(reply) = pending.remove(&pipe_id) {
                    let _ = reply.send(reader);
                    continue;
                }
                drop(pending);
                let request = PipeRequest {
                    pipe_id,
                    description: reader.description().to_owned(),
                    sender: sender.clone(),
                    dispatcher: dispatcher.clone(),
                };
                let _ = pipe_req_tx.send(request).await;
            }
            Err(error) => {
                if app_tx.send(Err(error)).await.is_err() {
                    break;
                }
            }
        }
    }
}
