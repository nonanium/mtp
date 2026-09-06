use bytes::Bytes;
use mtp_common::CommunicationError;
use mtp_core::{TransportConnection, TransportRecvStream, TransportSendStream};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::error;

pub type Session = h3_webtransport::server::WebTransportSession<h3_quinn::Connection, Bytes>;
type H3SendStream = h3_webtransport::stream::SendStream<h3_quinn::SendStream<Bytes>, Bytes>;
type H3RecvStream = h3_webtransport::stream::RecvStream<h3_quinn::RecvStream, Bytes>;

/// h3-webtransport implementation of MTP's transport connection boundary.
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
    quinn: quinn::Connection,
    read_exact_calls: u64,
}

impl H3TransportConnection {
    pub fn new(session: Arc<Session>, quinn: quinn::Connection) -> Self {
        Self { session, quinn }
    }

    pub fn remote_addr(&self) -> std::net::SocketAddr {
        self.quinn.remote_address()
    }

    #[cfg(feature = "crypto")]
    pub fn connection_id(&self) -> u64 {
        self.quinn.stable_id() as u64
    }
}

#[async_trait::async_trait]
impl TransportSendStream for H3TransportSender {
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), CommunicationError> {
        self.stream
            .write_all(buf)
            .await
            .map_err(|_| CommunicationError::DeliveryUnknown)?;
        // Control/authentication frames use a persistent stream. h3 keeps
        // those writes buffered until flushed; without this the peer can wait
        // for the challenge while the server waits for its proof.
        self.stream
            .flush()
            .await
            .map_err(|_| CommunicationError::DeliveryUnknown)
    }

    async fn finish(&mut self) -> Result<(), CommunicationError> {
        self.stream
            .shutdown()
            .await
            .map_err(|_| CommunicationError::StreamError)
    }

    fn reset(&mut self, code: u32) -> Result<(), CommunicationError> {
        h3::quic::SendStream::reset(&mut self.stream, code as u64);
        Ok(())
    }
}

#[async_trait::async_trait]
impl TransportRecvStream for H3TransportReceiver {
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), CommunicationError> {
        let first_read = self.read_exact_calls == 0;
        self.read_exact_calls += 1;
        self.stream
            .read_exact(buf)
            .await
            .map(|_| {
                if first_read {
                    tracing::debug!(
                        remote = %self.quinn.remote_address(),
                        bytes = buf.len(),
                        header = ?buf,
                        "received first bytes from WebTransport MTP stream"
                    );
                }
            })
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::UnexpectedEof
                    || self.quinn.close_reason().is_some()
                {
                    /*
                     * Reaching FIN, or losing the enclosing QUIC connection,
                     * is a normal stream-closure path. Do not turn it into a
                     * frame-header failure and close the connection again.
                     */
                    return CommunicationError::StreamClosed;
                }
                error!(
                    "[mtp-webserver] receive stream read_exact failed ({} bytes): {error}",
                    buf.len()
                );
                tracing::warn!(
                    remote = %self.quinn.remote_address(),
                    first_read,
                    len = buf.len(),
                    %error,
                    "WebTransport receive stream read_exact failed"
                );
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
                if self.quinn.close_reason().is_some() {
                    return Err(CommunicationError::StreamClosed);
                }
                error!(
                    "[mtp-webserver] receive stream read failed (max {} bytes): {error}",
                    max
                );
                tracing::warn!(max, %error, "WebTransport receive stream read failed");
                Err(CommunicationError::StreamError)
            }
        }
    }

    fn stop(mut self, code: u32) -> Result<(), CommunicationError> {
        h3::quic::RecvStream::stop_sending(&mut self.stream, code as u64);
        Ok(())
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
                    let stream_id = h3::quic::RecvStream::recv_id(&stream);
                    tracing::debug!(
                        remote = %self.quinn.remote_address(),
                        session_id = ?self.session.session_id(),
                        stream_id = ?stream_id,
                        "accepted WebTransport MTP receive stream"
                    );
                    return Ok(H3TransportReceiver {
                        stream,
                        quinn: self.quinn.clone(),
                        read_exact_calls: 0,
                    });
                }
                Ok(Some((stream_session_id, _stream))) => {
                    consecutive_errors = 0;
                    tracing::debug!(
                        remote = %self.quinn.remote_address(),
                        session_id = ?self.session.session_id(),
                        stream_session_id = ?stream_session_id,
                        "ignored WebTransport receive stream belonging to another session"
                    );
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
