#![cfg(feature = "pipes")]

use async_trait::async_trait;
use mtp_codec::CommunicationValue;
use mtp_common::CommunicationError;
use mtp_transport::{
    GenericReceiver, GenericSender, Policy, TransportConnection, TransportEvent,
    TransportRecvStream, TransportSendStream,
};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, duplex};
use tokio::sync::{Mutex, mpsc};

struct MockSendStream {
    inner: DuplexStream,
}

impl AsyncWrite for MockSendStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[async_trait]
impl TransportSendStream for MockSendStream {
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), CommunicationError> {
        AsyncWriteExt::write_all(&mut self.inner, buf)
            .await
            .map_err(|_| CommunicationError::StreamError)
    }

    async fn finish(&mut self) -> Result<(), CommunicationError> {
        self.inner
            .shutdown()
            .await
            .map_err(|_| CommunicationError::StreamError)
    }
}

struct MockRecvStream {
    inner: DuplexStream,
}

impl AsyncRead for MockRecvStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[async_trait]
impl TransportRecvStream for MockRecvStream {
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), CommunicationError> {
        AsyncReadExt::read_exact(&mut self.inner, buf)
            .await
            .map(|_| ())
            .map_err(|_| CommunicationError::StreamError)
    }

    async fn read_chunk(&mut self, max: usize) -> Result<Option<Vec<u8>>, CommunicationError> {
        let mut buf = vec![0u8; max];
        match AsyncReadExt::read(&mut self.inner, &mut buf).await {
            Ok(0) => Ok(None),
            Ok(n) => {
                buf.truncate(n);
                Ok(Some(buf))
            }
            Err(_) => Err(CommunicationError::StreamError),
        }
    }
}

#[derive(Clone)]
struct MockTransportConnection {
    pair_tx: mpsc::Sender<DuplexStream>,
    pair_rx: Arc<Mutex<mpsc::Receiver<DuplexStream>>>,
}

impl MockTransportConnection {
    fn pair() -> (Self, Self) {
        let (tx_a, rx_a) = mpsc::channel(16);
        let (tx_b, rx_b) = mpsc::channel(16);
        (
            Self {
                pair_tx: tx_a,
                pair_rx: Arc::new(Mutex::new(rx_b)),
            },
            Self {
                pair_tx: tx_b,
                pair_rx: Arc::new(Mutex::new(rx_a)),
            },
        )
    }
}

#[async_trait]
impl TransportConnection for MockTransportConnection {
    type SendStream = MockSendStream;
    type RecvStream = MockRecvStream;

    async fn open_uni(&self) -> Result<Self::SendStream, CommunicationError> {
        let (local, remote) = duplex(65536);
        self.pair_tx
            .send(remote)
            .await
            .map_err(|_| CommunicationError::StreamError)?;
        Ok(MockSendStream { inner: local })
    }

    async fn accept_uni(&self) -> Result<Self::RecvStream, CommunicationError> {
        let remote = self
            .pair_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(CommunicationError::StreamClosed)?;
        Ok(MockRecvStream { inner: remote })
    }

    fn close_reason(&self) -> Option<CommunicationError> {
        None
    }

    fn close(&self, _code: u32, _reason: &[u8]) {}
}

async fn mock_connected_pair() -> (MockTransportConnection, MockTransportConnection) {
    MockTransportConnection::pair()
}

#[tokio::test]
async fn test_open_pipe_and_receive_reader() -> Result<(), Box<dyn std::error::Error>> {
    let (conn_a, conn_b) = mock_connected_pair().await;
    let policy = Arc::new(Policy::default());
    let sender = GenericSender::new(conn_a, policy.clone());
    let receiver = GenericReceiver::new(conn_b, policy);

    let pipe_writer = sender.open_pipe(42, "test-pipe").await?;

    let pipe_reader = receiver.receive_pipe().await?;
    assert_eq!(pipe_reader.pipe_id(), 42);
    assert_eq!(pipe_reader.description(), "test-pipe");

    drop(pipe_writer);
    Ok(())
}

#[tokio::test]
async fn test_pipe_raw_data_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let (conn_a, conn_b) = mock_connected_pair().await;
    let policy = Arc::new(Policy::default());
    let sender = GenericSender::new(conn_a, policy.clone());
    let receiver = GenericReceiver::new(conn_b, policy);

    let mut pipe_writer = sender.open_pipe(1, "data-pipe").await?;

    let data = b"hello through the pipe";
    AsyncWriteExt::write_all(&mut pipe_writer, data).await?;
    pipe_writer.finish_async().await?;

    let mut pipe_reader = receiver.receive_pipe().await?;
    let mut buf = vec![0u8; data.len()];
    AsyncReadExt::read_exact(&mut pipe_reader, &mut buf).await?;
    assert_eq!(&buf, data);

    Ok(())
}

#[tokio::test]
async fn test_pipe_large_payload() -> Result<(), Box<dyn std::error::Error>> {
    let (conn_a, conn_b) = mock_connected_pair().await;
    let policy = Arc::new(Policy::default());
    let sender = GenericSender::new(conn_a, policy.clone());
    let receiver = GenericReceiver::new(conn_b, policy);

    let mut pipe_writer = sender.open_pipe(7, "big-pipe").await?;

    let data: Vec<u8> = (0..256 * 1024).map(|i| (i % 256) as u8).collect();
    let data_clone = data.clone();
    let write_handle = tokio::spawn(async move {
        AsyncWriteExt::write_all(&mut pipe_writer, &data_clone)
            .await
            .map_err(|_| CommunicationError::StreamError)?;
        pipe_writer.finish_async().await
    });

    let mut pipe_reader = receiver.receive_pipe().await?;
    let mut buf = Vec::new();
    AsyncReadExt::read_to_end(&mut pipe_reader, &mut buf).await?;
    assert_eq!(buf, data);

    write_handle.await??;

    Ok(())
}

#[tokio::test]
async fn test_receive_event_dispatches_pipe() -> Result<(), Box<dyn std::error::Error>> {
    let (conn_a, conn_b) = mock_connected_pair().await;
    let policy = Arc::new(Policy::default());
    let sender = GenericSender::new(conn_a, policy.clone());
    let receiver = GenericReceiver::new(conn_b, policy);

    let mut pipe_writer = sender.open_pipe(99, "event-pipe").await?;

    match receiver.receive_event().await? {
        TransportEvent::Pipe(mut reader) => {
            assert_eq!(reader.pipe_id(), 99);
            assert_eq!(reader.description(), "event-pipe");

            let data = b"event dispatch test";
            AsyncWriteExt::write_all(&mut pipe_writer, data).await?;
            pipe_writer.finish_async().await?;

            let mut buf = vec![0u8; data.len()];
            AsyncReadExt::read_exact(&mut reader, &mut buf).await?;
            assert_eq!(&buf, data);
        }
        TransportEvent::Message(_) => panic!("expected Pipe event, got Message"),
    }

    Ok(())
}

#[tokio::test]
async fn test_try_receive_pipe_returns_none_when_empty() -> Result<(), Box<dyn std::error::Error>> {
    let (conn_a, conn_b) = mock_connected_pair().await;
    let policy = Arc::new(Policy::default());
    let _sender = GenericSender::new(conn_a, policy.clone());
    let receiver = GenericReceiver::new(conn_b, policy);

    let result = receiver.try_receive_pipe()?;
    assert!(result.is_none());

    Ok(())
}

#[tokio::test]
async fn test_regular_messages_still_work_alongside_pipes() -> Result<(), Box<dyn std::error::Error>>
{
    let (conn_a, conn_b) = mock_connected_pair().await;
    let policy = Arc::new(Policy::default());
    let sender = GenericSender::new(conn_a, policy.clone());
    let receiver = GenericReceiver::new(conn_b, policy);

    let msg = CommunicationValue::new(mtp_codec::CommunicationType::BadRequest);
    sender.send(&msg).await?;

    let _pipe_writer = sender.open_pipe(1, "mixed-pipe").await?;

    let received = receiver.receive().await?;
    assert_eq!(
        received.get_type(),
        mtp_codec::CommunicationType::BadRequest
            .try_to_id(&mtp_codec::TypeMap::latest())
            .unwrap()
    );

    let pipe_reader = receiver.receive_pipe().await?;
    assert_eq!(pipe_reader.pipe_id(), 1);

    Ok(())
}

#[tokio::test]
async fn test_multiple_pipes() -> Result<(), Box<dyn std::error::Error>> {
    let (conn_a, conn_b) = mock_connected_pair().await;
    let policy = Arc::new(Policy::default());
    let sender = GenericSender::new(conn_a, policy.clone());
    let receiver = GenericReceiver::new(conn_b, policy);

    let mut pw1 = sender.open_pipe(10, "first").await?;
    let mut pw2 = sender.open_pipe(20, "second").await?;

    let r1 = receiver.receive_pipe().await?;
    assert_eq!(r1.pipe_id(), 10);
    let r2 = receiver.receive_pipe().await?;
    assert_eq!(r2.pipe_id(), 20);

    let data1 = b"pipe-one-data";
    AsyncWriteExt::write_all(&mut pw1, data1).await?;
    pw1.finish_async().await?;

    let data2 = b"pipe-two-data";
    AsyncWriteExt::write_all(&mut pw2, data2).await?;
    pw2.finish_async().await?;

    let mut buf1 = vec![0u8; data1.len()];
    let mut reader1 = r1;
    AsyncReadExt::read_exact(&mut reader1, &mut buf1).await?;
    assert_eq!(&buf1, data1);

    let mut buf2 = vec![0u8; data2.len()];
    let mut reader2 = r2;
    AsyncReadExt::read_exact(&mut reader2, &mut buf2).await?;
    assert_eq!(&buf2, data2);

    Ok(())
}
