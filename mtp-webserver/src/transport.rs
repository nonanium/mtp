use bytes::Bytes;
use mtp_codec::registry::Registry;
use mtp_common::CommunicationError;
use mtp_host::AcceptError;
use mtp_host::HostConfig;
use mtp_transport::{
    GenericReceiver, GenericSender, Policy, TransportConnection, TransportRecvStream,
    TransportSendStream,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::error;

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

    pub(crate) fn remote_addr(&self) -> std::net::SocketAddr {
        self.quinn.remote_address()
    }
}

#[async_trait::async_trait]
impl TransportSendStream for H3TransportSender {
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), CommunicationError> {
        self.stream
            .write_all(buf)
            .await
            .map_err(|_| CommunicationError::StreamError)?;
        // Control/authentication frames use a persistent stream. h3 keeps
        // those writes buffered until flushed; without this the peer can wait
        // for the challenge while the server waits for its proof.
        self.stream
            .flush()
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
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    // Browser control frames are sent on one-frame uni streams.
                    // Reaching FIN while looking for another frame is normal.
                    return CommunicationError::StreamClosed;
                }
                error!("[mtp-webserver] receive stream read_exact failed ({} bytes): {error}", buf.len());
                tracing::warn!(len = buf.len(), %error, "WebTransport receive stream read_exact failed");
                CommunicationError::StreamError
            })
    }

    async fn read_chunk(&mut self, max: usize) -> Result<Option<Vec<u8>>, CommunicationError> {
        let mut buf = vec![0; max];
        match self.stream.read(&mut buf).await {
            Ok(0) => Ok(None),
            Ok(size) => {
                buf.truncate(size);
                Ok(Some(buf))
            }
            Err(error) => {
                error!(
                    "[mtp-webserver] receive stream read failed (max {} bytes): {error}",
                    max
                );
                tracing::warn!(max, %error, "WebTransport receive stream read failed");
                Err(CommunicationError::StreamError)
            }
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
        const MAX_CONSECUTIVE_ERRORS: u32 = 10;
        const INITIAL_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(20);

        let mut consecutive_errors = 0_u32;
        loop {
            match self.session.accept_uni().await {
                Ok(Some((id, stream))) if id == self.session.session_id() => {
                    return Ok(H3TransportReceiver { stream });
                }
                Ok(Some(_)) => {
                    consecutive_errors = 0;
                    continue;
                }
                Ok(None) => return Err(CommunicationError::StreamClosed),
                Err(error) => {
                    // A browser can reset an individual pipe stream while it
                    // is stopping MediaRecorder. h3-webtransport reports that
                    // through accept_uni even though the QUIC connection is
                    // still healthy. Do not turn that stream-local failure
                    // into a connection-wide MTP failure.
                    if self.quinn.close_reason().is_some() {
                        return Err(CommunicationError::StreamClosed);
                    }

                    consecutive_errors += 1;
                    if consecutive_errors > MAX_CONSECUTIVE_ERRORS {
                        tracing::warn!(
                            %error,
                            consecutive_errors,
                            "WebTransport receive-stream accept repeatedly failed"
                        );
                        return Err(CommunicationError::StreamError);
                    }

                    let multiplier = 1_u32 << consecutive_errors.saturating_sub(1).min(5);
                    let retry_delay = INITIAL_RETRY_DELAY * multiplier;
                    tracing::debug!(
                        %error,
                        consecutive_errors,
                        ?retry_delay,
                        "retrying transient WebTransport receive-stream error"
                    );
                    tokio::time::sleep(retry_delay).await;
                }
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
pub type WebMTPConnection =
    mtp_host::MTPConnection<WebMtpSender, WebMtpReceiver, H3TransportReceiver>;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn accept_web_connection(
    session: Arc<Session>,
    path: String,
    quinn: quinn::Connection,
    send_pongs: bool,
    policy: Policy,
    host_config: Arc<HostConfig>,
    #[allow(unused_variables)] auth_semaphore: Arc<tokio::sync::Semaphore>,
    connection_guard: Option<tokio::sync::OwnedSemaphorePermit>,
) -> Result<WebMTPConnection, AcceptError> {
    #[cfg(feature = "crypto")]
    {
        let deadline = tokio::time::Instant::now() + host_config.auth_timeout;
        let permit = tokio::time::timeout_at(deadline, auth_semaphore.clone().acquire_owned())
            .await
            .map_err(|_| AcceptError::AuthenticationTimedOut)?
            .map_err(|_| {
                AcceptError::AuthenticationFailed("authentication service stopped".into())
            })?;
        let result = accept_web_connection_inner(
            session,
            path,
            quinn,
            send_pongs,
            policy,
            host_config,
            Some(deadline),
            connection_guard,
        )
        .await;
        drop(permit);
        result
    }

    #[cfg(not(feature = "crypto"))]
    accept_web_connection_inner(
        session,
        path,
        quinn,
        send_pongs,
        policy,
        host_config,
        None,
        connection_guard,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn accept_web_connection_inner(
    session: Arc<Session>,
    path: String,
    quinn: quinn::Connection,
    send_pongs: bool,
    policy: Policy,
    host_config: Arc<HostConfig>,
    #[allow(unused_variables)] deadline: Option<tokio::time::Instant>,
    connection_guard: Option<tokio::sync::OwnedSemaphorePermit>,
) -> Result<WebMTPConnection, AcceptError> {
    let max_message_size = policy.max_message_size;
    let transport = H3TransportConnection::new(session, quinn);
    let remote_addr = transport.remote_addr();
    let policy = Arc::new(policy);
    let sender = WebMtpSender::new(transport.clone(), policy.clone());
    let receiver = WebMtpReceiver::new(transport, policy.clone());

    let engine = mtp_host::HandshakeEngine::new(Registry::builtin(), host_config);
    #[cfg(feature = "crypto")]
    let result = engine
        .accept_until(
            &sender,
            &receiver,
            deadline.expect("crypto WebTransport handshakes have a deadline"),
        )
        .await?;
    #[cfg(not(feature = "crypto"))]
    let result = engine.accept(&sender, &receiver).await?;

    let version = result.negotiated_version.clone();
    let codec = result.codec.clone();
    let description = result.description.clone();
    #[cfg(feature = "pipes")]
    let connection: WebMTPConnection = mtp_host::MTPConnection::from_transport_parts_with_policy(
        version,
        codec,
        sender,
        receiver,
        path,
        description,
        Some(remote_addr),
        policy,
    );
    #[cfg(not(feature = "pipes"))]
    let connection: WebMTPConnection =
        mtp_host::MTPConnection::from_transport_parts_with_remote_addr(
            version,
            codec,
            sender,
            receiver,
            path,
            description,
            Some(remote_addr),
        );

    let mut connection = connection;

    #[cfg(feature = "crypto")]
    {
        connection.auth_state = result.auth_state;
        connection.client_id = result.client_id;
        connection.client_public_key = result.client_public_key;
        connection.set_guest_id_lease(result.guest_id_lease);
    }
    if let Some(connection_guard) = connection_guard {
        connection.set_connection_guard(connection_guard);
    }

    if send_pongs {
        connection
            .receiver
            .respond_to_pings(connection.sender.clone())
            .await;
    }
    connection.receiver.set_max_message_size(max_message_size);
    Ok(connection)
}
