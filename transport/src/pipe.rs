use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug)]
pub struct PipeWriter {
    pub(crate) stream: wtransport::SendStream,
}

impl PipeWriter {
    pub async fn finish(mut self) -> Result<(), mtp_common::CommunicationError> {
        self.stream
            .finish()
            .await
            .map_err(|e| {
                log::warn!("[PipeWriter] finish failed: {e}");
                mtp_common::CommunicationError::StreamWriteError(e)
            })
    }

    pub fn abort(&mut self) -> Result<(), wtransport::error::ClosedStream> {
        self.stream.reset(wtransport::VarInt::from_u32(0))
    }
}

impl AsyncWrite for PipeWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[derive(Debug)]
pub struct PipeReader {
    pub(crate) stream: wtransport::RecvStream,
    pub(crate) description: String,
    pub(crate) pipe_id: u32,
}

impl PipeReader {
    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn pipe_id(&self) -> u32 {
        self.pipe_id
    }
}

impl AsyncRead for PipeReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
