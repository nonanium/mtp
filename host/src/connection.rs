use mtp_codec::{CommunicationValue, Version, registry::VersionedCodec};
use mtp_common::CommunicationError;
use std::net::SocketAddr;
#[cfg(feature = "pipes")]
use std::sync::Arc;
#[cfg(feature = "pipes")]
use tokio::sync::{Mutex, mpsc};

#[cfg(feature = "crypto")]
use crate::error::random_client_id;
#[cfg(feature = "pipes")]
use mtp_core::Policy;
#[cfg(feature = "pipes")]
use mtp_pipes::{PipeDispatcher, PipeReceiver, PipeRequest, PipeSender, run_dispatcher};

mod connection_capability {
    pub trait Sealed {}
}

pub trait MtpSenderLike: connection_capability::Sealed + Clone + Send + Sync {}
pub trait MtpReceiverLike: connection_capability::Sealed + Clone + Send + Sync {
    fn receive_message(
        &self,
    ) -> impl std::future::Future<Output = Result<CommunicationValue, CommunicationError>> + Send;
}

impl connection_capability::Sealed for mtp_native::Sender {}
impl MtpSenderLike for mtp_native::Sender {}
impl connection_capability::Sealed for mtp_native::Receiver {}
impl MtpReceiverLike for mtp_native::Receiver {
    async fn receive_message(&self) -> Result<CommunicationValue, CommunicationError> {
        self.receive().await
    }
}
impl<C: mtp_core::TransportConnection> connection_capability::Sealed
    for mtp_core::GenericSender<C>
{
}
impl<C: mtp_core::TransportConnection> MtpSenderLike for mtp_core::GenericSender<C> {}
impl<C: mtp_core::TransportConnection> connection_capability::Sealed
    for mtp_core::GenericReceiver<C>
{
}
impl<C: mtp_core::TransportConnection> MtpReceiverLike for mtp_core::GenericReceiver<C> {
    async fn receive_message(&self) -> Result<CommunicationValue, CommunicationError> {
        self.receive().await
    }
}

pub struct MTPConnection<
    S = mtp_native::Sender,
    R = mtp_native::Receiver,
    P = mtp_native::NativeRecvStream,
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
    pub(crate) pipe_req_rx: Mutex<mpsc::Receiver<PipeRequest<S, R, P>>>,
    #[cfg(feature = "pipes")]
    pub(crate) pipe_dispatcher: Arc<PipeDispatcher<P>>,
    #[cfg(not(feature = "pipes"))]
    pub(crate) _pipe_stream: std::marker::PhantomData<P>,
    pub description: Option<String>,
    pub(crate) _dispatcher_task: tokio::task::JoinHandle<()>,
    /// Keeps an outer server admission permit alive for this MTP session.
    /// Native hosts leave it empty; WebTransport hosts use it to make the
    /// configured connection limit cover the session lifetime.
    pub(crate) _connection_guard: Option<tokio::sync::OwnedSemaphorePermit>,
    /// Cancels host-owned transport work when the application drops this connection.
    pub(crate) _session_task: Option<tokio::task::JoinHandle<()>>,
    #[cfg(feature = "crypto")]
    pub auth_state: crate::error::AuthState,
    #[cfg(feature = "crypto")]
    pub client_id: u64,
    #[cfg(feature = "crypto")]
    pub client_public_key: Option<mtp_crypto::PublicKeyBundle>,
    #[cfg(feature = "crypto")]
    pub(crate) guest_id_lease: Option<crate::engine::GuestIdLease>,
}

impl<S, R, P> MTPConnection<S, R, P> {
    /// Keep an outer server admission permit until this connection is dropped.
    pub fn set_connection_guard(&mut self, guard: tokio::sync::OwnedSemaphorePermit) {
        self._connection_guard = Some(guard);
    }

    /// Attach transport work whose lifetime must end with this connection.
    pub fn set_session_task(&mut self, task: tokio::task::JoinHandle<()>) {
        self._session_task = Some(task);
    }

    #[cfg(feature = "crypto")]
    pub fn set_guest_id_lease(&mut self, lease: Option<crate::engine::GuestIdLease>) {
        self.guest_id_lease = lease;
    }
}

impl<S, R, P> Drop for MTPConnection<S, R, P> {
    fn drop(&mut self) {
        if let Some(task) = self._session_task.take() {
            task.abort();
        }
    }
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
        let receiver_queue_capacity = policy.receiver_queue_capacity.max(1);
        let (app_tx, app_rx) = mpsc::channel(receiver_queue_capacity);
        let (pipe_req_tx, pipe_req_rx) = mpsc::channel(receiver_queue_capacity);
        let dispatcher = Arc::new(PipeDispatcher {
            pending_creations: std::sync::Mutex::new(std::collections::HashMap::new()),
            expired_creations: std::sync::Mutex::new(mtp_common::ExpiringSet::new(
                policy.pipe_tombstone_ttl.as_secs_f64() * 1000.0,
                policy.pipe_tombstone_capacity,
            )),
            pending_pipes: Mutex::new(std::collections::HashMap::new()),
            policy,
            type_map: codec.type_map().clone(),
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
            _connection_guard: None,
            _session_task: None,
            #[cfg(feature = "crypto")]
            auth_state: crate::error::AuthState::Unauthenticated,
            #[cfg(feature = "crypto")]
            client_id: random_client_id(),
            #[cfg(feature = "crypto")]
            client_public_key: None,
            #[cfg(feature = "crypto")]
            guest_id_lease: None,
        }
    }

    /// Construct an MTP connection with an explicit policy for pipe dispatch.
    // The shared transport constructor keeps its argument order aligned with
    // `from_transport_parts_with_remote_addr`; policy is required only here.
    #[allow(clippy::too_many_arguments)]
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
        let receiver_queue_capacity = policy.receiver_queue_capacity.max(1);
        let (app_tx, app_rx) = mpsc::channel(receiver_queue_capacity);
        let (pipe_req_tx, pipe_req_rx) = mpsc::channel(receiver_queue_capacity);
        let dispatcher = Arc::new(PipeDispatcher {
            pending_creations: std::sync::Mutex::new(std::collections::HashMap::new()),
            expired_creations: std::sync::Mutex::new(mtp_common::ExpiringSet::new(
                policy.pipe_tombstone_ttl.as_secs_f64() * 1000.0,
                policy.pipe_tombstone_capacity,
            )),
            pending_pipes: Mutex::new(std::collections::HashMap::new()),
            policy,
            type_map: codec.type_map().clone(),
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
            _connection_guard: None,
            _session_task: None,
            #[cfg(feature = "crypto")]
            auth_state: crate::error::AuthState::Unauthenticated,
            #[cfg(feature = "crypto")]
            client_id: random_client_id(),
            #[cfg(feature = "crypto")]
            client_public_key: None,
            #[cfg(feature = "crypto")]
            guest_id_lease: None,
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
            _connection_guard: None,
            _session_task: None,
            #[cfg(feature = "crypto")]
            auth_state: crate::error::AuthState::Unauthenticated,
            #[cfg(feature = "crypto")]
            client_id: random_client_id(),
            #[cfg(feature = "crypto")]
            client_public_key: None,
            #[cfg(feature = "crypto")]
            guest_id_lease: None,
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
            None => Err(CommunicationError::ConnectionLost),
        }
    }

    pub async fn create_pipe(
        &self,
        description: &str,
    ) -> Result<mtp_pipes::PipeHandle<S, P>, mtp_common::PipeError> {
        self.pipe_dispatcher
            .create(self.sender.clone(), description)
            .await
    }

    pub async fn receive_pipe(&self) -> Result<PipeRequest<S, R, P>, CommunicationError> {
        self.pipe_req_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(CommunicationError::ConnectionLost)
    }
}
