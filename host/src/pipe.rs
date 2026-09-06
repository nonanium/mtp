use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};
use mtp_common::{CommunicationError, ExpiringSet, PipeError, PipeId};
use mtp_native::{PipeReader, PipeWriter, Policy, TransportEvent};
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

    fn open_pipe_stream_id(
        &self,
        pipe_id: PipeId,
        description: &str,
    ) -> impl std::future::Future<Output = Result<PipeWriter<Self::Writer>, CommunicationError>> + Send;

    #[deprecated(note = "use open_pipe_stream_id with PipeId")]
    fn open_pipe_stream(
        &self,
        pipe_id: u32,
        description: &str,
    ) -> impl std::future::Future<Output = Result<PipeWriter<Self::Writer>, CommunicationError>> + Send
    {
        async move {
            let pipe_id = PipeId::try_from(pipe_id)
                .map_err(|_| CommunicationError::Other("pipe id must be non-zero".into()))?;
            self.open_pipe_stream_id(pipe_id, description).await
        }
    }
}

/// The receiver operations needed by the transport-independent pipe protocol.
pub trait PipeReceiver<P>: Clone + Send + Sync + 'static
where
    P: tokio::io::AsyncRead + Send + Unpin + 'static,
{
    fn expect_pipe_id(&self, pipe_id: PipeId) -> Result<(), CommunicationError>;

    #[deprecated(note = "use expect_pipe_id with PipeId")]
    fn expect_pipe(&self, pipe_id: u32) -> Result<(), CommunicationError> {
        let pipe_id = PipeId::try_from(pipe_id)
            .map_err(|_| CommunicationError::Other("pipe id must be non-zero".into()))?;
        self.expect_pipe_id(pipe_id)
    }

    fn cancel_expected_pipe_id(&self, pipe_id: PipeId);

    #[deprecated(note = "use cancel_expected_pipe_id with PipeId")]
    fn cancel_expected_pipe(&self, pipe_id: u32) {
        if let Some(pipe_id) = PipeId::new(pipe_id) {
            self.cancel_expected_pipe_id(pipe_id);
        }
    }

    fn receive_pipe_event(
        &self,
    ) -> impl std::future::Future<Output = Result<TransportEvent<P>, CommunicationError>> + Send;
}

impl PipeSender for mtp_native::Sender {
    type Writer = wtransport::SendStream;

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
        Ok(PipeWriter::from_inner(
            self.open_pipe_id(pipe_id, description).await?.into_inner(),
        ))
    }
}

impl PipeReceiver<wtransport::RecvStream> for mtp_native::Receiver {
    fn expect_pipe_id(&self, pipe_id: PipeId) -> Result<(), CommunicationError> {
        self.expect_pipe_id(pipe_id)
    }

    fn cancel_expected_pipe_id(&self, pipe_id: PipeId) {
        self.cancel_expected_pipe_id(pipe_id);
    }

    async fn receive_pipe_event(
        &self,
    ) -> Result<TransportEvent<wtransport::RecvStream>, CommunicationError> {
        self.receive_event().await
    }
}

impl<C> PipeSender for mtp_core::GenericSender<C>
where
    C: mtp_core::TransportConnection,
    C::SendStream: tokio::io::AsyncWrite + Send + Unpin + 'static,
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
        Ok(PipeWriter::from_inner(
            self.open_pipe_id(pipe_id, description).await?.into_inner(),
        ))
    }
}

impl<C> PipeReceiver<C::RecvStream> for mtp_core::GenericReceiver<C>
where
    C: mtp_core::TransportConnection,
    C::RecvStream: tokio::io::AsyncRead + Send + Unpin + 'static,
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
            mtp_core::TransportEvent::Pipe(reader) => {
                let description = reader.description().to_owned();
                let pipe_id = reader.pipe_id_value();
                Ok(TransportEvent::Pipe(PipeReader::from_parts_id(
                    reader.into_inner(),
                    description,
                    pipe_id,
                )))
            }
        }
    }
}

pub struct PipeHandle<S: PipeSender, P = wtransport::RecvStream> {
    pub(crate) pipe_id: PipeId,
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
    pub fn pipe_id_value(&self) -> PipeId {
        self.pipe_id
    }

    #[deprecated(note = "use pipe_id_value")]
    pub fn pipe_id(&self) -> u32 {
        self.pipe_id.get()
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
    P: tokio::io::AsyncRead + Send + Unpin + 'static,
{
    receiver: R,
    pipe_id: PipeId,
    armed: bool,
    _stream: std::marker::PhantomData<P>,
}

impl<R, P> ExpectedPipeGuard<R, P>
where
    R: PipeReceiver<P>,
    P: tokio::io::AsyncRead + Send + Unpin + 'static,
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
    P: tokio::io::AsyncRead + Send + Unpin + 'static,
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
    P: tokio::io::AsyncRead + Send + Unpin + 'static,
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

pub(crate) struct PipeDispatcher<P> {
    pub(crate) pending_creations: StdMutex<HashMap<PipeId, PendingCreation>>,
    pub(crate) expired_creations: StdMutex<ExpiringSet<PipeId>>,
    pub(crate) pending_pipes: Mutex<HashMap<PipeId, tokio::sync::oneshot::Sender<PipeReader<P>>>>,
    pub(crate) policy: Arc<Policy>,
    pub(crate) type_map: TypeMap,
}

pub(crate) struct PendingCreation {
    pub(crate) token: Arc<()>,
    pub(crate) sender: tokio::sync::oneshot::Sender<Result<bool, PipeError>>,
}

pub(crate) struct PendingCreationGuard<P> {
    dispatcher: Arc<PipeDispatcher<P>>,
    pipe_id: PipeId,
    token: Arc<()>,
    armed: bool,
}

impl<P> PendingCreationGuard<P> {
    pub(crate) fn new(dispatcher: Arc<PipeDispatcher<P>>, pipe_id: PipeId, token: Arc<()>) -> Self {
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

pub(crate) fn expire_pending_creation<P>(
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

pub(crate) fn is_expired_creation<P>(dispatcher: &PipeDispatcher<P>, pipe_id: PipeId) -> bool {
    let Ok(mut expired) = dispatcher.expired_creations.lock() else {
        return true;
    };
    expired.contains(
        pipe_id,
        mtp_common::unix_time_millis().unwrap_or_default() as f64,
    )
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
    pipe_req_tx: mpsc::Sender<PipeRequest<S, R, P>>,
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
                    let Some(pipe_id) = message.id().and_then(PipeId::new) else {
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
                        receiver: receiver.clone(),
                        dispatcher: dispatcher.clone(),
                    };
                    let _ = pipe_req_tx.send(request).await;
                    continue;
                }
                if message.is_type(CommunicationType::PipeResponse) {
                    let Some(pipe_id) = message.id().and_then(PipeId::new) else {
                        let error = CommunicationError::Other(
                            "PipeResponse frame must contain a non-zero id".into(),
                        );
                        if app_tx.send(Err(error)).await.is_err() {
                            break;
                        }
                        continue;
                    };
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
                if message.is_type(CommunicationType::PipeAbort) {
                    let Some(pipe_id) = message.id().and_then(PipeId::new) else {
                        let error = CommunicationError::Other(
                            "PipeAbort frame must contain a non-zero id".into(),
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
