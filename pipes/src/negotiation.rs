#[cfg(target_arch = "wasm32")]
use crate::tokio;
use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};
use mtp_common::{CommunicationError, ExpiringSet, PipeError, PipeId};
use mtp_core::{PipeReader, PipeWriter, Policy};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use tokio::sync::{Mutex, mpsc};

/// A message or an incoming pipe stream delivered by a [`PipeReceiver`].
///
/// This remains generic so the host pipe dispatcher can work with both the
/// native adapter and transport-independent core receivers.
pub enum TransportEvent<P> {
    Message(CommunicationValue),
    Pipe(PipeReader<P>),
}

/// The sender operations needed by the transport-independent pipe protocol.
pub trait PipeSender: Clone + crate::PlatformSend + crate::PlatformSync + 'static {
    type Writer: tokio::io::AsyncWrite + crate::PlatformSend + Unpin + 'static;

    fn send_pipe_message(
        &self,
        message: &CommunicationValue,
    ) -> impl std::future::Future<Output = Result<(), CommunicationError>> + crate::PlatformSend;

    fn open_pipe_stream_id(
        &self,
        pipe_id: PipeId,
        description: &str,
    ) -> impl std::future::Future<Output = Result<PipeWriter<Self::Writer>, CommunicationError>>
    + crate::PlatformSend;
}

/// The receiver operations needed by the transport-independent pipe protocol.
pub trait PipeReceiver<P>: Clone + crate::PlatformSend + crate::PlatformSync + 'static
where
    P: tokio::io::AsyncRead + crate::PlatformSend + Unpin + 'static,
{
    fn expect_pipe_id(&self, pipe_id: PipeId) -> Result<(), CommunicationError>;

    fn cancel_expected_pipe_id(&self, pipe_id: PipeId);

    fn receive_pipe_event(
        &self,
    ) -> impl std::future::Future<Output = Result<TransportEvent<P>, CommunicationError>>
    + crate::PlatformSend;
}

impl<C> PipeSender for mtp_core::GenericSender<C>
where
    C: mtp_core::TransportConnection,
{
    type Writer = C::SendStream;

    async fn send_pipe_message(
        &self,
        message: &CommunicationValue,
    ) -> Result<(), CommunicationError> {
        self.send(message).await
    }

    async fn open_pipe_stream_id(
        &self,
        pipe_id: PipeId,
        description: &str,
    ) -> Result<PipeWriter<Self::Writer>, CommunicationError> {
        self.open_pipe_id(pipe_id, description).await
    }
}

impl<C> PipeReceiver<C::RecvStream> for mtp_core::GenericReceiver<C>
where
    C: mtp_core::TransportConnection,
{
    fn expect_pipe_id(&self, pipe_id: PipeId) -> Result<(), CommunicationError> {
        self.expect_pipe_id(pipe_id)
    }

    fn cancel_expected_pipe_id(&self, pipe_id: PipeId) {
        self.cancel_expected_pipe_id(pipe_id);
    }

    async fn receive_pipe_event(
        &self,
    ) -> Result<TransportEvent<C::RecvStream>, CommunicationError> {
        match self.receive_event().await? {
            mtp_core::TransportEvent::Message(message) => Ok(TransportEvent::Message(message)),
            mtp_core::TransportEvent::Pipe(reader) => Ok(TransportEvent::Pipe(reader)),
        }
    }
}

pub struct PipeHandle<S: PipeSender, P> {
    pub pipe_id: PipeId,
    pub description: String,
    pub sender: S,
    pub response_rx: tokio::sync::oneshot::Receiver<Result<bool, PipeError>>,
    pub dispatcher: Arc<PipeDispatcher<P>>,
    pub token: Arc<()>,
}

impl<S, P> PipeHandle<S, P>
where
    S: PipeSender,
    P: tokio::io::AsyncRead + crate::PlatformSend + Unpin + 'static,
{
    pub fn pipe_id_value(&self) -> PipeId {
        self.pipe_id
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub async fn wait(mut self) -> Result<Option<PipeWriter<S::Writer>>, PipeError> {
        let response = tokio::time::timeout(
            self.dispatcher.policy.pipe_decision_timeout,
            &mut self.response_rx,
        )
        .await;
        match response {
            Ok(Ok(Ok(true))) => self
                .sender
                .open_pipe_stream_id(self.pipe_id, &self.description)
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

    /// Withdraw this request before opening its byte stream.
    pub async fn cancel(self) -> Result<(), PipeError> {
        expire_pending_creation(&self.dispatcher, self.pipe_id, &self.token);
        let abort = CommunicationValue::new_with_type_map(
            CommunicationType::PipeAbort,
            &self.dispatcher.type_map,
        )
        .with_id(self.pipe_id.get());
        self.sender
            .send_pipe_message(&abort)
            .await
            .map_err(PipeError::from)
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

pub struct PipeRequest<S, R, P> {
    pub(crate) pipe_id: PipeId,
    pub(crate) description: String,
    pub(crate) sender: S,
    pub(crate) receiver: R,
    pub(crate) dispatcher: Arc<PipeDispatcher<P>>,
}

struct ExpectedPipeGuard<R, P>
where
    R: PipeReceiver<P>,
    P: tokio::io::AsyncRead + crate::PlatformSend + Unpin + 'static,
{
    receiver: R,
    pipe_id: PipeId,
    armed: bool,
    _stream: std::marker::PhantomData<P>,
}

impl<R, P> ExpectedPipeGuard<R, P>
where
    R: PipeReceiver<P>,
    P: tokio::io::AsyncRead + crate::PlatformSend + Unpin + 'static,
{
    fn new(receiver: R, pipe_id: PipeId) -> Self {
        Self {
            receiver,
            pipe_id,
            armed: true,
            _stream: std::marker::PhantomData,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<R, P> Drop for ExpectedPipeGuard<R, P>
where
    R: PipeReceiver<P>,
    P: tokio::io::AsyncRead + crate::PlatformSend + Unpin + 'static,
{
    fn drop(&mut self) {
        if self.armed {
            self.receiver.cancel_expected_pipe_id(self.pipe_id);
        }
    }
}

impl<S, R, P> PipeRequest<S, R, P>
where
    S: PipeSender,
    R: PipeReceiver<P>,
    P: tokio::io::AsyncRead + crate::PlatformSend + Unpin + 'static,
{
    pub fn id(&self) -> PipeId {
        self.pipe_id
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub async fn accept(self) -> Result<PipeReader<P>, PipeError> {
        self.receiver
            .expect_pipe_id(self.pipe_id)
            .map_err(PipeError::from)?;
        let mut expected_pipe = ExpectedPipeGuard::<R, P>::new(self.receiver.clone(), self.pipe_id);
        let (pipe_tx, pipe_rx) = tokio::sync::oneshot::channel();
        self.dispatcher
            .pending_pipes
            .lock()
            .await
            .insert(self.pipe_id, pipe_tx);
        let _pending_guard = PendingAcceptanceGuard {
            dispatcher: self.dispatcher.clone(),
            pipe_id: self.pipe_id,
        };

        let response = CommunicationValue::new_with_type_map(
            CommunicationType::PipeResponse,
            &self.dispatcher.type_map,
        )
        .with_id(self.pipe_id.get())
        .add_typed_default(DataType::Accepted, DataValue::BoolTrue);
        if let Err(error) = self.sender.send_pipe_message(&response).await {
            self.dispatcher
                .pending_pipes
                .lock()
                .await
                .remove(&self.pipe_id);
            return Err(PipeError::from(error));
        }

        match tokio::time::timeout(self.dispatcher.policy.pipe_stream_open_timeout, pipe_rx).await {
            Ok(Ok(reader)) => {
                expected_pipe.disarm();
                Ok(reader)
            }
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
        .with_id(self.pipe_id.get())
        .add_typed_default(DataType::Accepted, DataValue::BoolFalse);
        self.sender
            .send_pipe_message(&response)
            .await
            .map_err(PipeError::from)
    }
}

struct PendingAcceptanceGuard<P> {
    dispatcher: Arc<PipeDispatcher<P>>,
    pipe_id: PipeId,
}
impl<P> Drop for PendingAcceptanceGuard<P> {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.dispatcher.pending_pipes.try_lock() {
            pending.remove(&self.pipe_id);
        }
    }
}

pub struct PipeDispatcher<P> {
    pub pending_creations: StdMutex<HashMap<PipeId, PendingCreation>>,
    pub expired_creations: StdMutex<ExpiringSet<PipeId>>,
    pub pending_pipes: Mutex<HashMap<PipeId, tokio::sync::oneshot::Sender<PipeReader<P>>>>,
    pub policy: Arc<Policy>,
    pub type_map: TypeMap,
}

impl<P: tokio::io::AsyncRead + crate::PlatformSend + Unpin + 'static> PipeDispatcher<P> {
    pub fn new(policy: Arc<Policy>, type_map: TypeMap) -> Arc<Self> {
        Arc::new(Self {
            pending_creations: StdMutex::new(HashMap::new()),
            expired_creations: StdMutex::new(ExpiringSet::new(
                policy.pipe_tombstone_ttl.as_secs_f64() * 1000.0,
                policy.pipe_tombstone_capacity,
            )),
            pending_pipes: Mutex::new(HashMap::new()),
            policy,
            type_map,
        })
    }

    pub async fn create<S: PipeSender>(
        self: &Arc<Self>,
        sender: S,
        description: &str,
    ) -> Result<PipeHandle<S, P>, PipeError> {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        let (pipe_id, token) = {
            let mut pending = self
                .pending_creations
                .lock()
                .map_err(|_| PipeError::ConnectionClosed)?;
            let pipe_id = loop {
                let candidate = PipeId::random();
                if !pending.contains_key(&candidate) && !is_expired_creation(self, candidate) {
                    break candidate;
                }
            };
            let token = Arc::new(());
            pending.insert(
                pipe_id,
                PendingCreation {
                    token: token.clone(),
                    sender: response_tx,
                },
            );
            (pipe_id, token)
        };
        let mut guard = PendingCreationGuard::new(self.clone(), pipe_id, token.clone());
        let request =
            CommunicationValue::new_with_type_map(CommunicationType::PipeRequest, &self.type_map)
                .with_id(pipe_id.get())
                .add_typed_default(DataType::Description, DataValue::Str(description.into()));
        sender
            .send_pipe_message(&request)
            .await
            .map_err(PipeError::from)?;
        guard.disarm();
        Ok(PipeHandle {
            pipe_id,
            description: description.to_owned(),
            sender,
            response_rx,
            dispatcher: self.clone(),
            token,
        })
    }
}

pub struct PendingCreation {
    pub token: Arc<()>,
    pub sender: tokio::sync::oneshot::Sender<Result<bool, PipeError>>,
}

pub struct PendingCreationGuard<P> {
    dispatcher: Arc<PipeDispatcher<P>>,
    pipe_id: PipeId,
    token: Arc<()>,
    armed: bool,
}

impl<P> PendingCreationGuard<P> {
    pub fn new(dispatcher: Arc<PipeDispatcher<P>>, pipe_id: PipeId, token: Arc<()>) -> Self {
        Self {
            dispatcher,
            pipe_id,
            token,
            armed: true,
        }
    }

    pub fn disarm(&mut self) {
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

pub fn expire_pending_creation<P>(
    dispatcher: &PipeDispatcher<P>,
    pipe_id: PipeId,
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
    expired.insert(
        pipe_id,
        mtp_common::unix_time_millis().unwrap_or_default() as f64,
    );
}

fn consume_expired_creation<P>(dispatcher: &PipeDispatcher<P>, pipe_id: PipeId) -> bool {
    let Ok(mut expired) = dispatcher.expired_creations.lock() else {
        return false;
    };
    expired.consume(
        pipe_id,
        mtp_common::unix_time_millis().unwrap_or_default() as f64,
    )
}

pub fn is_expired_creation<P>(dispatcher: &PipeDispatcher<P>, pipe_id: PipeId) -> bool {
    let Ok(mut expired) = dispatcher.expired_creations.lock() else {
        return true;
    };
    expired.contains(
        pipe_id,
        mtp_common::unix_time_millis().unwrap_or_default() as f64,
    )
}

pub fn fail_pending_creations<P>(dispatcher: &PipeDispatcher<P>, error: &CommunicationError) {
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

pub async fn fail_pending_pipes<P>(dispatcher: &PipeDispatcher<P>) {
    dispatcher.pending_pipes.lock().await.clear();
}

pub async fn run_dispatcher<S, R, P>(
    receiver: R,
    sender: S,
    app_tx: mpsc::Sender<Result<CommunicationValue, CommunicationError>>,
    pipe_req_tx: mpsc::Sender<PipeRequest<S, R, P>>,
    dispatcher: Arc<PipeDispatcher<P>>,
) where
    S: PipeSender,
    R: PipeReceiver<P>,
    P: tokio::io::AsyncRead + crate::PlatformSend + Unpin + 'static,
{
    loop {
        match receiver.receive_pipe_event().await {
            Ok(TransportEvent::Message(message)) => {
                let pipe_type = [
                    (CommunicationType::PipeRequest, "PipeRequest"),
                    (CommunicationType::PipeResponse, "PipeResponse"),
                    (CommunicationType::PipeAbort, "PipeAbort"),
                ]
                .into_iter()
                .find_map(|(kind, name)| message.is_type(kind).then_some(name));
                let pipe_id = message.id().and_then(PipeId::new);
                if let Some(name) = pipe_type
                    && pipe_id.is_none()
                {
                    let error = CommunicationError::Other(format!(
                        "{name} frame must contain a non-zero id"
                    ));
                    if app_tx.send(Err(error)).await.is_err() {
                        break;
                    }
                    continue;
                }
                if let (Some("PipeRequest"), Some(pipe_id)) = (pipe_type, pipe_id) {
                    let request = PipeRequest {
                        pipe_id,
                        description: message
                            .get_str(DataType::Description)
                            .unwrap_or("")
                            .to_owned(),
                        sender: sender.clone(),
                        receiver: receiver.clone(),
                        dispatcher: dispatcher.clone(),
                    };
                    let _ = pipe_req_tx.send(request).await;
                    continue;
                }
                if let (Some("PipeResponse"), Some(pipe_id)) = (pipe_type, pipe_id) {
                    let Some(accepted) = message.get_bool(DataType::Accepted) else {
                        let error = CommunicationError::Other(
                            "PipeResponse frame must contain a boolean Accepted field".into(),
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
                        let _ = entry.sender.send(Ok(accepted));
                    } else if consume_expired_creation(&dispatcher, pipe_id) {
                        tracing::debug!(?pipe_id, "ignored late pipe creation response");
                    }
                    continue;
                }
                if let (Some("PipeAbort"), Some(pipe_id)) = (pipe_type, pipe_id) {
                    let pending = dispatcher
                        .pending_creations
                        .lock()
                        .ok()
                        .and_then(|mut pending| pending.remove(&pipe_id));
                    if let Some(entry) = pending {
                        let _ = entry.sender.send(Err(PipeError::Cancelled));
                    } else {
                        let _ = consume_expired_creation(&dispatcher, pipe_id);
                    }
                    receiver.cancel_expected_pipe_id(pipe_id);
                    if let Some(waiter) = dispatcher.pending_pipes.lock().await.remove(&pipe_id) {
                        drop(waiter);
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
                let pipe_id = reader.pipe_id_value();
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
                    receiver: receiver.clone(),
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
