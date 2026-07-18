use mtp_codec::{CommunicationValue, Version, registry::VersionedCodec};
use mtp_common::CommunicationError;
#[cfg(feature = "pipes")]
use std::sync::Arc;
#[cfg(feature = "pipes")]
use tokio::sync::{Mutex, mpsc};

#[cfg(feature = "crypto")]
use crate::error::random_client_id;
#[cfg(feature = "pipes")]
use crate::pipe::{PipeDispatcher, PipeRequest};

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

pub struct MTPConnection<S = mtp_transport::Sender, R = mtp_transport::Receiver> {
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
    #[cfg(feature = "pipes")]
    pub(crate) app_rx: Mutex<mpsc::Receiver<Result<CommunicationValue, CommunicationError>>>,
    #[cfg(feature = "pipes")]
    pub(crate) pipe_req_rx: Mutex<mpsc::Receiver<PipeRequest>>,
    #[cfg(feature = "pipes")]
    pub(crate) pipe_dispatcher: Arc<PipeDispatcher>,
    pub description: Option<String>,
    pub(crate) _dispatcher_task: tokio::task::JoinHandle<()>,
    #[cfg(feature = "crypto")]
    pub auth_state: crate::error::AuthState,
    #[cfg(feature = "crypto")]
    pub client_id: u64,
    #[cfg(feature = "crypto")]
    pub client_public_key: Option<mtp_crypto::PublicKeyBundle>,
}

impl<S, R> MTPConnection<S, R> {
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
        #[cfg(feature = "pipes")]
        let (_, app_rx) = mpsc::channel::<Result<CommunicationValue, CommunicationError>>(1);
        #[cfg(feature = "pipes")]
        let (_, pipe_req_rx) = mpsc::channel::<PipeRequest>(1);
        #[cfg(feature = "pipes")]
        let dispatcher = Arc::new(PipeDispatcher::default_for_external());
        Self {
            version,
            codec,
            sender,
            receiver,
            path,
            #[cfg(feature = "pipes")]
            app_rx: Mutex::new(app_rx),
            #[cfg(feature = "pipes")]
            pipe_req_rx: Mutex::new(pipe_req_rx),
            #[cfg(feature = "pipes")]
            pipe_dispatcher: dispatcher,
            description,
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
