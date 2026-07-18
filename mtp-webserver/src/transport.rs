use bytes::Bytes;
use mtp_codec::{
    DataType, DataValue, Version,
    registry::{Registry, VersionedCodec},
};
use mtp_common::CommunicationError;
use mtp_host::AcceptError;
use mtp_transport::{
    GenericReceiver, GenericSender, Policy, TransportConnection, TransportRecvStream,
    TransportSendStream,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Session = h3_webtransport::server::WebTransportSession<h3_quinn::Connection, Bytes>;
type H3SendStream = h3_webtransport::stream::SendStream<h3_quinn::SendStream<Bytes>, Bytes>;
type H3RecvStream = h3_webtransport::stream::RecvStream<h3_quinn::RecvStream, Bytes>;

/// h3-webtransport implementation of MTP's transport connection boundary.
///
/// This is intentionally separate from [`WebMTPConnection`]: it is the
/// adapter used by the in-progress migration of `mtp_transport::Sender` and
/// `Receiver` away from concrete wtransport stream types.
#[derive(Clone)]
pub struct H3TransportConnection {
    session: Arc<Session>,
    quinn: quinn::Connection,
}

pub struct H3TransportSender {
    stream: H3SendStream,
}

pub struct H3TransportReceiver {
    stream: H3RecvStream,
}

impl H3TransportConnection {
    pub(crate) fn new(session: Arc<Session>, quinn: quinn::Connection) -> Self {
        Self { session, quinn }
    }
}

#[async_trait::async_trait]
impl TransportSendStream for H3TransportSender {
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), CommunicationError> {
        self.stream
            .write_all(buf)
            .await
            .map_err(|_| CommunicationError::StreamError)
    }

    async fn finish(&mut self) -> Result<(), CommunicationError> {
        self.stream
            .shutdown()
            .await
            .map_err(|_| CommunicationError::StreamError)
    }
}

#[async_trait::async_trait]
impl TransportRecvStream for H3TransportReceiver {
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), CommunicationError> {
        self.stream
            .read_exact(buf)
            .await
            .map(|_| ())
            .map_err(|_| CommunicationError::StreamError)
    }

    async fn read_chunk(&mut self, max: usize) -> Result<Option<Vec<u8>>, CommunicationError> {
        let mut buf = vec![0; max];
        match self.stream.read(&mut buf).await {
            Ok(0) => Ok(None),
            Ok(size) => {
                buf.truncate(size);
                Ok(Some(buf))
            }
            Err(_) => Err(CommunicationError::StreamError),
        }
    }
}

impl tokio::io::AsyncWrite for H3TransportSender {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl tokio::io::AsyncRead for H3TransportReceiver {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

#[async_trait::async_trait]
impl TransportConnection for H3TransportConnection {
    type SendStream = H3TransportSender;
    type RecvStream = H3TransportReceiver;

    async fn open_uni(&self) -> Result<Self::SendStream, CommunicationError> {
        self.session
            .open_uni(self.session.session_id())
            .await
            .map(|stream| H3TransportSender { stream })
            .map_err(|_| CommunicationError::StreamError)
    }

    async fn accept_uni(&self) -> Result<Self::RecvStream, CommunicationError> {
        loop {
            match self.session.accept_uni().await {
                Ok(Some((id, stream))) if id == self.session.session_id() => {
                    return Ok(H3TransportReceiver { stream });
                }
                Ok(Some(_)) => continue,
                Ok(None) => return Err(CommunicationError::StreamClosed),
                Err(_) => return Err(CommunicationError::StreamError),
            }
        }
    }

    fn close_reason(&self) -> Option<CommunicationError> {
        self.quinn
            .close_reason()
            .map(|_| CommunicationError::StreamClosed)
    }

    fn close(&self, code: u32, reason: &[u8]) {
        self.quinn.close(quinn::VarInt::from_u32(code), reason);
    }
}

/// Shared host MTP connection instantiated with HTTP/3 stream adapters.
pub type WebMtpSender = GenericSender<H3TransportConnection>;
pub type WebMtpReceiver = GenericReceiver<H3TransportConnection>;
pub type WebMTPConnection = mtp_host::MTPConnection<WebMtpSender, WebMtpReceiver>;

pub(crate) async fn accept_web_connection(
    session: Arc<Session>,
    path: String,
    quinn: quinn::Connection,
    send_pongs: bool,
    policy: Policy,
) -> Result<WebMTPConnection, AcceptError> {
    let transport = H3TransportConnection::new(session, quinn);
    let policy = Arc::new(policy);
    let receiver = WebMtpReceiver::new(transport.clone(), policy.clone());

    let first = receiver.receive().await.map_err(AcceptError::Receive)?;
    let version = match first.get_data(DataType::Version) {
        DataValue::Str(value) => Version::parse(value).ok_or(AcceptError::MissingVersion)?,
        _ => return Err(AcceptError::MissingVersion),
    };
    let registry = Registry::builtin();
    let negotiated = registry
        .negotiate(std::slice::from_ref(&version))
        .ok_or_else(|| AcceptError::UnsupportedVersion(version.clone()))?;
    let codec = VersionedCodec::for_version(registry, negotiated.clone())
        .ok_or_else(|| AcceptError::UnsupportedVersion(negotiated.clone()))?;
    let description = match first.get_data(DataType::Description) {
        DataValue::Str(value) => Some(value.clone()),
        _ => None,
    };
    let sender = WebMtpSender::new(transport, policy);
    if send_pongs {
        receiver.respond_to_pings(sender.clone()).await;
    }
    Ok(mtp_host::MTPConnection::from_transport_parts(
        negotiated,
        codec,
        sender,
        receiver,
        path,
        description,
    ))
}
