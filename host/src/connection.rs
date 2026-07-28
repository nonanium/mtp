#[cfg(feature = "pipes")]
use mtp_codec::{CommunicationType, DataType, DataValue};
use mtp_codec::{CommunicationValue, Version, registry::VersionedCodec};
use mtp_common::CommunicationError;
use std::net::SocketAddr;
use std::sync::Arc;
#[cfg(feature = "pipes")]
use tokio::sync::{Mutex, mpsc};

#[cfg(feature = "crypto")]
use crate::error::random_client_id;
#[cfg(feature = "pipes")]
use crate::pipe::{PipeDispatcher, PipeReceiver, PipeRequest, PipeSender, run_dispatcher};
use mtp_transport::Policy;

mod connection_capability {
    pub trait Sealed {}
}

pub trait MtpSenderLike: connection_capability::Sealed + Clone + Send + Sync {}
pub trait MtpReceiverLike: connection_capability::Sealed + Clone + Send + Sync {
    fn receive_message(
        &self,
    ) -> impl std::future::Future<Output = Result<CommunicationValue, CommunicationError>> + Send;
}

impl connection_capability::Sealed for mtp_transport::Sender {}
impl MtpSenderLike for mtp_transport::Sender {}
impl connection_capability::Sealed for mtp_transport::Receiver {}
impl MtpReceiverLike for mtp_transport::Receiver {
    async fn receive_message(&self) -> Result<CommunicationValue, CommunicationError> {
        self.receive().await
    }
}
impl<C: mtp_transport::TransportConnection> connection_capability::Sealed
    for mtp_transport::GenericSender<C>
{
}
impl<C: mtp_transport::TransportConnection> MtpSenderLike for mtp_transport::GenericSender<C> {}
impl<C: mtp_transport::TransportConnection> connection_capability::Sealed
    for mtp_transport::GenericReceiver<C>
{
}
impl<C: mtp_transport::TransportConnection> MtpReceiverLike for mtp_transport::GenericReceiver<C> {
    async fn receive_message(&self) -> Result<CommunicationValue, CommunicationError> {
        self.receive().await
    }
}

pub struct MTPConnection<
    S = mtp_transport::Sender,
    R = mtp_transport::Receiver,
    P = wtransport::RecvStream,
> {
    pub version: Version,
    pub codec: VersionedCodec,
    pub sender: S,
    pub receiver: R,
    /// The WebTransport request path used to establish this connection.
    ///
    /// Legacy `MTPHost` connections do not have an HTTP router in front of
    /// them, so they always use the root path.  Alternative hosts can retain
    /// the CONNECT request path when constructing an MTP connection.
    pub path: String,
    /// The address of the peer that established this connection, when exposed
    /// by the underlying transport.
    pub remote_addr: Option<SocketAddr>,
    #[cfg(feature = "pipes")]
    pub(crate) app_rx: Mutex<mpsc::Receiver<Result<CommunicationValue, CommunicationError>>>,
    #[cfg(feature = "pipes")]
    pub(crate) pipe_req_rx: Mutex<mpsc::Receiver<PipeRequest<S, P>>>,
    #[cfg(feature = "pipes")]
    pub(crate) pipe_dispatcher: Arc<PipeDispatcher<P>>,
    #[cfg(not(feature = "pipes"))]
    pub(crate) _pipe_stream: std::marker::PhantomData<P>,
    pub description: Option<String>,
    pub(crate) _dispatcher_task: tokio::task::JoinHandle<()>,
    #[cfg(feature = "crypto")]
    pub auth_state: crate::error::AuthState,
    #[cfg(feature = "crypto")]
    pub client_id: u64,
    #[cfg(feature = "crypto")]
    pub client_public_key: Option<mtp_crypto::PublicKeyBundle>,
}

#[cfg(feature = "pipes")]
impl<S, R, P> MTPConnection<S, R, P>
where
    S: PipeSender,
    R: PipeReceiver<P>,
    P: tokio::io::AsyncRead + Send + Unpin + 'static,
{
    /// Construct an MTP connection from an alternative transport backend.
    ///
    /// Native `MTPHost` users continue to receive the default
    /// `MTPConnection<Sender, Receiver>` type.  HTTP/3 WebTransport hosts use
    /// this constructor with their stream adapters while retaining the shared
    /// version, codec, path, and metadata representation.
    pub fn from_transport_parts(
        version: Version,
        codec: VersionedCodec,
        sender: S,
        receiver: R,
        path: String,
        description: Option<String>,
    ) -> Self {
        Self::from_transport_parts_with_remote_addr(
            version,
            codec,
            sender,
            receiver,
            path,
            description,
            None,
        )
    }

    pub fn from_transport_parts_with_remote_addr(
        version: Version,
        codec: VersionedCodec,
        sender: S,
        receiver: R,
        path: String,
        description: Option<String>,
        remote_addr: Option<SocketAddr>,
    ) -> Self {
        let policy = Arc::new(Policy::default());
        let (app_tx, app_rx) = mpsc::channel(policy.receiver_queue_capacity);
        let (pipe_req_tx, pipe_req_rx) = mpsc::channel(policy.receiver_queue_capacity);
        let dispatcher = Arc::new(PipeDispatcher {
            pending_creations: Mutex::new(std::collections::HashMap::new()),
            pending_pipes: Mutex::new(std::collections::HashMap::new()),
            policy,
        });
        let task = tokio::spawn(run_dispatcher(
            receiver.clone(),
            sender.clone(),
            app_tx,
            pipe_req_tx,
            dispatcher.clone(),
        ));
        Self {
            version,
            codec,
            sender,
            receiver,
            path,
            remote_addr,
            app_rx: Mutex::new(app_rx),
            pipe_req_rx: Mutex::new(pipe_req_rx),
            pipe_dispatcher: dispatcher,
            description,
            _dispatcher_task: task,
            #[cfg(feature = "crypto")]
            auth_state: crate::error::AuthState::Unauthenticated,
            #[cfg(feature = "crypto")]
            client_id: random_client_id(),
            #[cfg(feature = "crypto")]
            client_public_key: None,
        }
    }

    /// Construct an MTP connection with an explicit policy for pipe dispatch.
    pub fn from_transport_parts_with_policy(
        version: Version,
        codec: VersionedCodec,
        sender: S,
        receiver: R,
        path: String,
        description: Option<String>,
        remote_addr: Option<SocketAddr>,
        policy: Arc<Policy>,
    ) -> Self {
        let (app_tx, app_rx) = mpsc::channel(policy.receiver_queue_capacity);
        let (pipe_req_tx, pipe_req_rx) = mpsc::channel(policy.receiver_queue_capacity);
        let dispatcher = Arc::new(PipeDispatcher {
            pending_creations: Mutex::new(std::collections::HashMap::new()),
            pending_pipes: Mutex::new(std::collections::HashMap::new()),
            policy,
        });
        let task = tokio::spawn(run_dispatcher(
            receiver.clone(),
            sender.clone(),
            app_tx,
            pipe_req_tx,
            dispatcher.clone(),
        ));
        Self {
            version,
            codec,
            sender,
            receiver,
            path,
            remote_addr,
            app_rx: Mutex::new(app_rx),
            pipe_req_rx: Mutex::new(pipe_req_rx),
            pipe_dispatcher: dispatcher,
            description,
            _dispatcher_task: task,
            #[cfg(feature = "crypto")]
            auth_state: crate::error::AuthState::Unauthenticated,
            #[cfg(feature = "crypto")]
            client_id: random_client_id(),
            #[cfg(feature = "crypto")]
            client_public_key: None,
        }
    }
}

#[cfg(not(feature = "pipes"))]
impl<S, R, P> MTPConnection<S, R, P> {
    pub fn from_transport_parts(
        version: Version,
        codec: VersionedCodec,
        sender: S,
        receiver: R,
        path: String,
        description: Option<String>,
    ) -> Self {
        Self::from_transport_parts_with_remote_addr(
            version,
            codec,
            sender,
            receiver,
            path,
            description,
            None,
        )
    }

    pub fn from_transport_parts_with_remote_addr(
        version: Version,
        codec: VersionedCodec,
        sender: S,
        receiver: R,
        path: String,
        description: Option<String>,
        remote_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            version,
            codec,
            sender,
            receiver,
            path,
            remote_addr,
            description,
            _pipe_stream: std::marker::PhantomData,
            _dispatcher_task: tokio::spawn(async {}),
            #[cfg(feature = "crypto")]
            auth_state: crate::error::AuthState::Unauthenticated,
            #[cfg(feature = "crypto")]
            client_id: random_client_id(),
            #[cfg(feature = "crypto")]
            client_public_key: None,
        }
    }

    pub fn from_transport_parts_with_policy(
        version: Version,
        codec: VersionedCodec,
        sender: S,
        receiver: R,
        path: String,
        description: Option<String>,
        remote_addr: Option<SocketAddr>,
        _policy: Arc<Policy>,
    ) -> Self {
        Self {
            version,
            codec,
            sender,
            receiver,
            path,
            remote_addr,
            description,
            _pipe_stream: std::marker::PhantomData,
            _dispatcher_task: tokio::spawn(async {}),
            #[cfg(feature = "crypto")]
            auth_state: crate::error::AuthState::Unauthenticated,
            #[cfg(feature = "crypto")]
            client_id: random_client_id(),
            #[cfg(feature = "crypto")]
            client_public_key: None,
        }
    }
}

#[cfg(not(feature = "pipes"))]
impl<S: MtpSenderLike, R: MtpReceiverLike> MTPConnection<S, R> {
    pub async fn receive(&self) -> Result<CommunicationValue, CommunicationError> {
        let mut message = self.receiver.receive_message().await?;
        message.set_type_map(self.codec.type_map());
        Ok(message)
    }
}

#[cfg(feature = "pipes")]
impl<S, R, P> MTPConnection<S, R, P>
where
    S: PipeSender,
    P: tokio::io::AsyncRead + Send + Unpin + 'static,
{
    pub async fn receive(&self) -> Result<CommunicationValue, CommunicationError> {
        let mut rx = self.app_rx.lock().await;
        match rx.recv().await {
            Some(Ok(mut message)) => {
                message.set_type_map(self.codec.type_map());
                Ok(message)
            }
            Some(Err(error)) => Err(error),
            None => Err(CommunicationError::StreamClosed),
        }
    }

    pub async fn create_pipe(
        &self,
        description: &str,
    ) -> Result<crate::pipe::PipeHandle<S>, mtp_common::PipeError> {
        let pipe_id = rand::random::<u32>();
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        self.pipe_dispatcher
            .pending_creations
            .lock()
            .await
            .insert(pipe_id, response_tx);

        let request = CommunicationValue::new(CommunicationType::PipeRequest)
            .with_id(pipe_id)
            .add_typed_default(DataType::Description, DataValue::Str(description.into()));
        self.sender
            .send_pipe_message(&request)
            .await
            .map_err(mtp_common::PipeError::from)?;

        Ok(crate::pipe::PipeHandle {
            pipe_id,
            description: description.to_owned(),
            sender: self.sender.clone(),
            response_rx,
        })
    }

    pub async fn receive_pipe(&self) -> Result<PipeRequest<S, P>, CommunicationError> {
        self.pipe_req_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(CommunicationError::StreamClosed)
    }
}
