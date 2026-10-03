use crate::transport::{BrowserRecvStream, BrowserSendStream};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use wasm_bindgen::prelude::*;

pub(crate) struct Duplex {
    pub(crate) read: BrowserRecvStream,
    pub(crate) write: BrowserSendStream,
}
impl Duplex {
    pub(crate) fn new(stream: JsValue) -> Self {
        Self {
            read: BrowserRecvStream::from_pipe(stream.clone(), Vec::new()),
            write: BrowserSendStream::from_pipe(stream),
        }
    }
}
impl tokio::io::AsyncRead for Duplex {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.read).poll_read(cx, buf)
    }
}
impl tokio::io::AsyncWrite for Duplex {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.write).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.write).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.write).poll_shutdown(cx)
    }
}
