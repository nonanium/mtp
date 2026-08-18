use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};
use mtp_common::{CommunicationError, PipeError};
use mtp_transport::{PipeReader, PipeWriter, Policy, TransportEvent};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
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

pub struct PipeHandle<S: PipeSender, P = wtransport::RecvStream> {
    pub(crate) pipe_id: u32,
    pub(crate) description: String,
    pub(crate) sender: S,
    pub(crate) response_rx: tokio::sync::oneshot::Receiver<Result<bool, PipeError>>,
    pub(crate) dispatcher: Arc<PipeDispatcher<P>>,
    pub(crate) token: Arc<()>,
}

impl<S, P> PipeHandle<S, P>
where
    S: PipeSender,
    P: tokio::io::AsyncRead + Send + Unpin + 'static,
{
    pub fn pipe_id(&self) -> u32 {
        self.pipe_id
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub async fn wait(mut self) -> Result<Option<PipeWriter<S::Writer>>, PipeError> {
        let response =
            tokio::time::timeout(self.dispatcher.policy.read_timeout, &mut self.response_rx).await;
        match response {
            Ok(Ok(Ok(true))) => self
                .sender
                .open_pipe_stream(self.pipe_id, &self.description)
                .await
                .map(Some)
                .map_err(PipeError::from),
            Ok(Ok(Ok(false))) => Ok(None),
            Ok(Ok(Err(error))) => {
                expire_pending_creation(&self.dispatcher, self.pipe_id, &self.token);
                Err(error)
            }
            Ok(Err(_)) => {
                expire_pending_creation(&self.dispatcher, self.pipe_id, &self.token);
                Err(PipeError::StreamClosed)
            }
            Err(_) => {
                expire_pending_creation(&self.dispatcher, self.pipe_id, &self.token);
                Err(PipeError::HandshakeTimeout)
            }
        }
    }
}

impl<S, P> Drop for PipeHandle<S, P>
where
    S: PipeSender,
{
    fn drop(&mut self) {
        expire_pending_creation(&self.dispatcher, self.pipe_id, &self.token);
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

        let response = CommunicationValue::new_with_type_map(
            CommunicationType::PipeResponse,
            &self.dispatcher.type_map,
        )
        .with_id(self.pipe_id)
        .add_typed_default(DataType::Accepted, DataValue::BoolTrue);
        if let Err(error) = self.sender.send_pipe_message(&response).await {
            self.dispatcher
                .pending_pipes
                .lock()
                .await
                .remove(&self.pipe_id);
            return Err(PipeError::from(error));
        }

        match tokio::time::timeout(self.dispatcher.policy.read_timeout, pipe_rx).await {
            Ok(Ok(reader)) => Ok(reader),
            Ok(Err(_)) => {
                self.dispatcher
                    .pending_pipes
                    .lock()
                    .await
                    .remove(&self.pipe_id);
                Err(PipeError::StreamClosed)
            }
            Err(_) => {
                self.dispatcher
                    .pending_pipes
                    .lock()
                    .await
                    .remove(&self.pipe_id);
                Err(PipeError::HandshakeTimeout)
            }
        }
    }

    pub async fn deny(self) -> Result<(), PipeError> {
        let response = CommunicationValue::new_with_type_map(
            CommunicationType::PipeResponse,
            &self.dispatcher.type_map,
        )
        .with_id(self.pipe_id)
        .add_typed_default(DataType::Accepted, DataValue::BoolFalse);
        self.sender
            .send_pipe_message(&response)
            .await
            .map_err(PipeError::from)
    }
}

pub(crate) struct PipeDispatcher<P> {
    pub(crate) pending_creations: StdMutex<HashMap<u32, PendingCreation>>,
    pub(crate) expired_creations: StdMutex<HashMap<u32, tokio::time::Instant>>,
    pub(crate) pending_pipes: Mutex<HashMap<u32, tokio::sync::oneshot::Sender<PipeReader<P>>>>,
    pub(crate) policy: Arc<Policy>,
    pub(crate) type_map: TypeMap,
}

pub(crate) struct PendingCreation {
    pub(crate) token: Arc<()>,
    pub(crate) sender: tokio::sync::oneshot::Sender<Result<bool, PipeError>>,
}

pub(crate) struct PendingCreationGuard<P> {
    dispatcher: Arc<PipeDispatcher<P>>,
    pipe_id: u32,
    token: Arc<()>,
    armed: bool,
}

impl<P> PendingCreationGuard<P> {
    pub(crate) fn new(dispatcher: Arc<PipeDispatcher<P>>, pipe_id: u32, token: Arc<()>) -> Self {
        Self {
            dispatcher,
            pipe_id,
            token,
            armed: true,
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<P> Drop for PendingCreationGuard<P> {
    fn drop(&mut self) {
        if self.armed {
            expire_pending_creation(&self.dispatcher, self.pipe_id, &self.token);
        }
    }
}

const EXPIRED_CREATION_TOMBSTONE_TTL: tokio::time::Duration = tokio::time::Duration::from_secs(60);
const MAX_EXPIRED_CREATION_TOMBSTONES: usize = 1024;

pub(crate) fn expire_pending_creation<P>(
    dispatcher: &PipeDispatcher<P>,
    pipe_id: u32,
    token: &Arc<()>,
) {
    let removed = dispatcher
        .pending_creations
        .lock()
        .ok()
        .and_then(|mut pending| {
            if pending
                .get(&pipe_id)
                .is_some_and(|entry| Arc::ptr_eq(&entry.token, token))
            {
                pending.remove(&pipe_id);
                Some(())
            } else {
                None
            }
        });
    if removed.is_none() {
        return;
    }
    let Ok(mut expired) = dispatcher.expired_creations.lock() else {
        return;
    };
    let now = tokio::time::Instant::now();
    expired.retain(|_, expires_at| *expires_at > now);
    if expired.len() >= MAX_EXPIRED_CREATION_TOMBSTONES
        && let Some(oldest) = expired
            .iter()
            .min_by_key(|(_, expires_at)| **expires_at)
            .map(|(id, _)| *id)
    {
        expired.remove(&oldest);
    }
    expired.insert(pipe_id, now + EXPIRED_CREATION_TOMBSTONE_TTL);
}

fn consume_expired_creation<P>(dispatcher: &PipeDispatcher<P>, pipe_id: u32) -> bool {
    let Ok(mut expired) = dispatcher.expired_creations.lock() else {
        return false;
    };
    let now = tokio::time::Instant::now();
    expired.retain(|_, expires_at| *expires_at > now);
    expired.remove(&pipe_id).is_some()
}

pub(crate) fn is_expired_creation<P>(dispatcher: &PipeDispatcher<P>, pipe_id: u32) -> bool {
    let Ok(mut expired) = dispatcher.expired_creations.lock() else {
        return true;
    };
    let now = tokio::time::Instant::now();
    expired.retain(|_, expires_at| *expires_at > now);
    expired.contains_key(&pipe_id)
}

pub(crate) fn fail_pending_creations<P>(
    dispatcher: &PipeDispatcher<P>,
    error: &CommunicationError,
) {
    let pending = dispatcher
        .pending_creations
        .lock()
        .ok()
        .map(|mut pending| std::mem::take(&mut *pending));
    if let Some(pending) = pending {
        let error = PipeError::from(error.clone());
        for (_, pending) in pending {
            let _ = pending.sender.send(Err(error.clone()));
        }
    }
    if let Ok(mut expired) = dispatcher.expired_creations.lock() {
        expired.clear();
    }
}

pub(crate) async fn fail_pending_pipes<P>(dispatcher: &PipeDispatcher<P>) {
    dispatcher.pending_pipes.lock().await.clear();
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
    loop {
        match receiver.receive_pipe_event().await {
            Ok(TransportEvent::Message(message)) => {
                if message.is_type(CommunicationType::PipeRequest) {
                    let Some(pipe_id) = message.id().filter(|id| *id != 0) else {
                        let error = CommunicationError::Other(
                            "PipeRequest frame must contain a non-zero id".into(),
                        );
                        if app_tx.send(Err(error)).await.is_err() {
                            break;
                        }
                        continue;
                    };
                    let request = PipeRequest {
                        pipe_id,
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
                if message.is_type(CommunicationType::PipeResponse) {
                    let Some(pipe_id) = message.id().filter(|id| *id != 0) else {
                        let error = CommunicationError::Other(
                            "PipeResponse frame must contain a non-zero id".into(),
                        );
                        if app_tx.send(Err(error)).await.is_err() {
                            break;
                        }
                        continue;
                    };
                    let pending = dispatcher
                        .pending_creations
                        .lock()
                        .ok()
                        .and_then(|mut pending| pending.remove(&pipe_id));
                    if let Some(entry) = pending {
                        let _ = entry
                            .sender
                            .send(Ok(message.get_bool(DataType::Accepted).unwrap_or(false)));
                    } else if consume_expired_creation(&dispatcher, pipe_id) {
                        tracing::debug!(pipe_id, "ignored late pipe creation response");
                    }
                    continue;
                }
                if !matches!(message.id(), Some(id) if id != 0)
                    && message
                        .get_type_name()
                        .is_some_and(|name| name.ends_with("Response"))
                {
                    let error = CommunicationError::Other(
                        "response frame must contain a non-zero id".into(),
                    );
                    if app_tx.send(Err(error)).await.is_err() {
                        break;
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
                fail_pending_creations(&dispatcher, &error);
                fail_pending_pipes(&dispatcher).await;
                if app_tx.send(Err(error)).await.is_err() {
                    break;
                }
                break;
            }
        }
    }
}
