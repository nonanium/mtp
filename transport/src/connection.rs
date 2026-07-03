use crate::ConnectionHandle;
use mtp_codec::CommunicationValue;
use mtp_common::CommunicationError;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, sleep, timeout};
use wtransport::Connection;

const APPLICATION_CLOSE_REASON: &str = "mtp-close";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendMode {
    PersistentStream,
    SingleStreamPerMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub send_mode: SendMode,
    pub max_message_size: u64,
    pub close_frame_len: u32,
    pub application_close_code: u32,
    pub open_stream_timeout: Duration,
    pub write_timeout: Duration,
    pub accept_stream_timeout: Duration,
    pub read_timeout: Duration,
    pub keep_alive_interval: Option<Duration>,
    pub max_idle_timeout: Option<Duration>,
    pub force_close_delay: Duration,
    pub max_transient_recv_errors: usize,
    pub transient_recv_backoff: Duration,
    pub receiver_queue_capacity: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            send_mode: SendMode::PersistentStream,
            max_message_size: 1_000_000_000,
            close_frame_len: u32::MAX,
            application_close_code: 0,
            open_stream_timeout: Duration::from_millis(2_000),
            write_timeout: Duration::from_millis(2_000),
            accept_stream_timeout: Duration::from_millis(10_000),
            read_timeout: Duration::from_millis(30_000),
            keep_alive_interval: Some(Duration::from_secs(3)),
            max_idle_timeout: Some(Duration::from_secs(30)),
            force_close_delay: Duration::from_millis(300),
            max_transient_recv_errors: 20,
            transient_recv_backoff: Duration::from_millis(100),
            receiver_queue_capacity: 1000,
        }
    }
}

impl Policy {
    pub fn with_send_mode(mut self, send_mode: SendMode) -> Self {
        self.send_mode = send_mode;
        self
    }

    pub fn with_max_message_size(mut self, max_message_size: u64) -> Self {
        self.max_message_size = max_message_size;
        self
    }

    pub fn with_timeouts(
        mut self,
        open_stream_timeout: Duration,
        write_timeout: Duration,
        read_timeout: Duration,
    ) -> Self {
        self.open_stream_timeout = open_stream_timeout;
        self.write_timeout = write_timeout;
        self.read_timeout = read_timeout;
        self
    }

    pub fn with_keep_alive(mut self, keep_alive_interval: Option<Duration>) -> Self {
        self.keep_alive_interval = keep_alive_interval;
        self
    }

    pub fn with_max_idle_timeout(mut self, max_idle_timeout: Option<Duration>) -> Self {
        self.max_idle_timeout = max_idle_timeout;
        self
    }

    pub fn with_receiver_queue_capacity(mut self, receiver_queue_capacity: usize) -> Self {
        self.receiver_queue_capacity = receiver_queue_capacity;
        self
    }
}

enum ReceivedFrame {
    Message(CommunicationValue),
    ClosedByPeer,
    Idle,
}

pub struct Sender {
    send_guard: Mutex<()>,
    stream_guard: Arc<Mutex<Option<wtransport::SendStream>>>,
    handle: Arc<ConnectionHandle>,
    connection: Connection,
    policy: Arc<Policy>,
}

impl Sender {
    pub fn new(connection: Connection, handle: Arc<ConnectionHandle>, policy: Arc<Policy>) -> Self {
        Self {
            send_guard: Mutex::new(()),
            stream_guard: Arc::new(Mutex::new(None)),
            handle,
            connection,
            policy,
        }
    }

    async fn write_frame(
        stream: &mut wtransport::SendStream,
        data: &CommunicationValue,
        policy: &Policy,
    ) -> Result<(), CommunicationError> {
        let bytes = data.to_bytes().map_err(|_| CommunicationError::Encode)?;
        if bytes.len() as u64 > policy.max_message_size
            || bytes.len() as u64 >= policy.close_frame_len as u64
        {
            return Err(CommunicationError::MessageTooLarge);
        }

        use tokio::io::AsyncWriteExt;

        timeout(policy.write_timeout, stream.write_u32(bytes.len() as u32))
            .await
            .map_err(|_| CommunicationError::StreamError)?
            .map_err(|_| CommunicationError::StreamError)?;

        timeout(policy.write_timeout, stream.write_all(&bytes))
            .await
            .map_err(|_| CommunicationError::StreamError)?
            .map_err(CommunicationError::from)?;

        Ok(())
    }

    fn normalize_send_error(error: CommunicationError) -> CommunicationError {
        match error {
            CommunicationError::ConnectionError(_)
            | CommunicationError::ReadExactError(_)
            | CommunicationError::ClosedError(_)
            | CommunicationError::StreamReadExactError(_)
            | CommunicationError::StreamError => CommunicationError::StreamClosed,
            other => other,
        }
    }

    async fn open_uni_stream(
        conn: &Connection,
        policy: &Policy,
    ) -> Result<wtransport::SendStream, CommunicationError> {
        let opening = timeout(policy.open_stream_timeout, conn.open_uni())
            .await
            .map_err(|_| CommunicationError::StreamError)?
            .map_err(CommunicationError::ConnectionError)?;

        let stream = timeout(policy.open_stream_timeout, opening)
            .await
            .map_err(|_| CommunicationError::StreamError)?
            .map_err(|_| CommunicationError::StreamError)?;

        Ok(stream)
    }

    async fn ensure_stream<'a>(
        conn: &Connection,
        stream_opt: &'a mut Option<wtransport::SendStream>,
        policy: &Policy,
    ) -> Result<&'a mut wtransport::SendStream, CommunicationError> {
        if stream_opt.is_none() {
            *stream_opt = Some(Self::open_uni_stream(conn, policy).await?);
        }

        match stream_opt.as_mut() {
            Some(stream) => Ok(stream),
            _ => Err(CommunicationError::StreamError),
        }
    }

    async fn send_on_persistent_stream(
        conn: &Connection,
        stream_opt: &mut Option<wtransport::SendStream>,
        data: &CommunicationValue,
        policy: &Policy,
    ) -> Result<(), CommunicationError> {
        let mut tries = 0usize;
        loop {
            if conn.quic_connection().close_reason().is_some() {
                return Err(CommunicationError::StreamClosed);
            }

            let res = {
                let stream = Self::ensure_stream(conn, stream_opt, policy).await?;
                Self::write_frame(stream, data, policy).await
            };

            if res.is_ok() {
                return Ok(());
            }

            *stream_opt = None;
            tries += 1;
            if tries >= 4 {
                let stream = Self::ensure_stream(conn, stream_opt, policy).await?;
                return Self::write_frame(stream, data, policy).await;
            }

            tokio::time::sleep(std::time::Duration::from_millis(20 * tries as u64)).await;
        }
    }

    async fn send_on_single_stream(
        conn: &Connection,
        data: &CommunicationValue,
        policy: &Policy,
    ) -> Result<(), CommunicationError> {
        let mut stream = Self::open_uni_stream(conn, policy).await?;
        Self::write_frame(&mut stream, data, policy).await?;

        timeout(policy.write_timeout, stream.finish())
            .await
            .map_err(|_| CommunicationError::StreamError)?
            .map_err(|_| CommunicationError::StreamError)?;

        Ok(())
    }
    async fn send_close_frame(
        conn: &Connection,
        policy: &Policy,
    ) -> Result<(), CommunicationError> {
        let mut stream = Self::open_uni_stream(conn, policy).await?;

        use tokio::io::AsyncWriteExt;
        timeout(
            policy.write_timeout,
            stream.write_u32(policy.close_frame_len),
        )
        .await
        .map_err(|_| CommunicationError::StreamError)?
        .map_err(|_| CommunicationError::StreamError)?;

        if let Err(e) = timeout(policy.write_timeout, stream.finish())
            .await
            .map_err(|_| CommunicationError::StreamError)?
        {
            log::warn!("[Sender] close frame finish failed: {e}");
        }

        Ok(())
    }

    pub async fn send(&self, data: &CommunicationValue) -> Result<(), CommunicationError> {
        if self.handle.is_closed() {
            return Err(self
                .handle
                .close_reason()
                .unwrap_or(CommunicationError::UseAfterClosed));
        }

        let _send_lock = self.send_guard.lock().await;

        if self.connection.quic_connection().close_reason().is_some() {
            let reason = self
                .handle
                .close_reason()
                .unwrap_or(CommunicationError::StreamClosed);
            self.handle.close(Some(reason.clone()));
            return Err(reason);
        }

        let res = match self.policy.send_mode {
            SendMode::PersistentStream => {
                let mut stream_opt = self.stream_guard.lock().await;
                let r = Self::send_on_persistent_stream(
                    &self.connection,
                    &mut stream_opt,
                    data,
                    &self.policy,
                )
                .await;
                if r.is_err() {
                    *stream_opt = None;
                }
                r
            }
            SendMode::SingleStreamPerMessage => {
                Self::send_on_single_stream(&self.connection, data, &self.policy).await
            }
        };

        match res {
            Ok(()) => Ok(()),
            Err(e) => {
                let normalized = Self::normalize_send_error(e);

                if self.connection.quic_connection().close_reason().is_some()
                    || matches!(normalized, CommunicationError::StreamClosed)
                {
                    self.handle.close(Some(normalized.clone()));
                }

                Err(normalized)
            }
        }
    }

    pub async fn finish_stream(&self) -> Result<(), CommunicationError> {
        let _send_lock = self.send_guard.lock().await;
        let mut stream_opt = self.stream_guard.lock().await;
        if let Some(mut stream) = stream_opt.take() {
            timeout(self.policy.write_timeout, stream.finish())
                .await
                .map_err(|_| CommunicationError::StreamError)?
                .map_err(|_| CommunicationError::StreamError)?;
        }
        Ok(())
    }

    pub fn handle(&self) -> &Arc<ConnectionHandle> {
        &self.handle
    }

    pub fn close(&self) {
        let connection = self.connection.clone();
        let handle = self.handle.clone();
        let policy = self.policy.clone();
        let stream_guard = self.stream_guard.clone();

        tokio::spawn(async move {
            if connection.quic_connection().close_reason().is_some() || handle.is_closed() {
                handle.close(Some(CommunicationError::StreamClosed));
                return;
            }

            if let Some(mut stream) = stream_guard.lock().await.take() {
                match timeout(policy.write_timeout, stream.finish()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => log::warn!("[Sender] persistent stream finish failed: {e}"),
                    Err(_) => log::warn!("[Sender] persistent stream finish timed out"),
                }
            }

            let _ = Self::send_close_frame(&connection, &policy).await;

            handle.close(Some(CommunicationError::StreamClosed));

            sleep(policy.force_close_delay).await;
            if connection.quic_connection().close_reason().is_none() {
                connection.quic_connection().close(
                    policy.application_close_code.into(),
                    APPLICATION_CLOSE_REASON.as_bytes(),
                );
            }
        });
    }

    pub fn is_open(&self) -> bool {
        self.handle.is_open()
    }

    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    pub fn close_reason(&self) -> Option<CommunicationError> {
        self.handle.close_reason()
    }
}

pub struct Receiver {
    rx: Mutex<mpsc::Receiver<Result<CommunicationValue, CommunicationError>>>,
    _accept_task: tokio::task::JoinHandle<()>,
    handle: Arc<ConnectionHandle>,
}

impl Drop for Receiver {
    fn drop(&mut self) {
        // The accept loop holds clones of the connection and the shared
        // ConnectionHandle. Without this, dropping a Receiver without first
        // closing the connection would leave that task running forever. Abort
        // it directly rather than closing the shared handle, so a still-live
        // Sender on the same connection is unaffected. abort() is a no-op if
        // the task already finished (e.g. the connection was closed).
        self._accept_task.abort();
    }
}

impl Receiver {
    pub fn new(connection: Connection, handle: Arc<ConnectionHandle>, policy: Arc<Policy>) -> Self {
        let (tx, rx) = mpsc::channel::<Result<CommunicationValue, CommunicationError>>(
            policy.receiver_queue_capacity,
        );

        let conn_handle = handle.clone();
        let accept_connection = connection.clone();
        let accept_policy = policy.clone();

        let accept_task = tokio::spawn(async move {
            let mut close_rx = conn_handle.subscribe_close();

            loop {
                tokio::select! {
                    _ = close_rx.changed() => {
                        if close_rx.borrow().is_some() {
                            break;
                        }
                    }

                    accepted = timeout(
                        accept_policy.accept_stream_timeout,
                        accept_connection.accept_uni()
                    ) => {
                        match accepted {
                            Ok(Ok(stream)) => {
                                let tx_stream = tx.clone();
                                let stream_handle = conn_handle.clone();
                                let stream_policy = accept_policy.clone();

                                tokio::spawn(async move {
                                    let mut s = stream;
                                    loop {
                                        match Self::read_one_frame(&mut s, &stream_policy).await {
                                            Ok(ReceivedFrame::Message(msg)) => {
                                                if tx_stream.send(Ok(msg)).await.is_err() {
                                                    break;
                                                }
                                            }
                                            Ok(ReceivedFrame::ClosedByPeer) => {
                                                let close_error = CommunicationError::StreamClosed;
                                                let _ = tx_stream.send(Err(close_error.clone())).await;
                                                stream_handle.close(Some(close_error));
                                                break;
                                            }
                                            Ok(ReceivedFrame::Idle) => {
                                                break;
                                            }
                                            Err(e) => {
                                                let close_error = match e {
                                                    CommunicationError::ConnectionError(_)
                                                    | CommunicationError::ReadExactError(_)
                                                    | CommunicationError::ClosedError(_)
                                                    | CommunicationError::StreamReadExactError(_)
                                                    | CommunicationError::StreamError => CommunicationError::StreamClosed,
                                                    other => other,
                                                };

                                                let _ = tx_stream.send(Err(close_error.clone())).await;
                                                stream_handle.close(Some(close_error));
                                                break;
                                            }
                                        }
                                    }
                                });
                            }

                            Ok(Err(_e)) => {
                                // A connection error from accept_uni means the connection is permanently closed.
                                let close_error = CommunicationError::StreamClosed;
                                let _ = tx.send(Err(close_error.clone())).await;
                                conn_handle.close(Some(close_error));
                                break;
                            }

                            Err(_) => {
                                if accept_connection.quic_connection().close_reason().is_some() {
                                    let close_error = CommunicationError::StreamClosed;
                                    let _ = tx.send(Err(close_error.clone())).await;
                                    conn_handle.close(Some(close_error));
                                    break;
                                }
                            }
                        }
                    }
                }

                if conn_handle.is_closed() {
                    break;
                }
            }
        });

        Self {
            rx: Mutex::new(rx),
            _accept_task: accept_task,
            handle,
        }
    }

    async fn read_one_frame(
        stream: &mut wtransport::RecvStream,
        policy: &Policy,
    ) -> Result<ReceivedFrame, CommunicationError> {
        use std::io::ErrorKind;
        use tokio::io::AsyncReadExt;

        let mut attempts = 0;
        let len = loop {
            match stream.read_u32().await {
                Ok(len) => break len,
                Err(e) => {
                    if e.kind() == ErrorKind::Interrupted && attempts < 3 {
                        attempts += 1;
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        continue;
                    }
                    if e.kind() == ErrorKind::UnexpectedEof {
                        return Ok(ReceivedFrame::Idle);
                    }
                    log::warn!("[Receiver] read_u32 failed: {e}");
                    return Err(CommunicationError::StreamError);
                }
            }
        };

        if len == policy.close_frame_len {
            return Ok(ReceivedFrame::ClosedByPeer);
        }

        let len = len as usize;
        if len as u64 > policy.max_message_size {
            return Err(CommunicationError::MessageTooLarge);
        }

        let mut buf = vec![0u8; len];
        match timeout(policy.read_timeout, stream.read_exact(&mut buf)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => match timeout(policy.read_timeout, stream.read_exact(&mut buf)).await {
                Ok(Ok(())) => {}
                _ => return Err(e.into()),
            },
            Err(_) => {
                log::warn!("[Receiver] read_exact timed out (len={})", len);
                return Err(CommunicationError::StreamError);
            }
        }

        let message = CommunicationValue::from_bytes(&buf)
            .map_err(|_| CommunicationError::ParseCommunicationValue)?;

        Ok(ReceivedFrame::Message(message))
    }

    pub async fn receive(&self) -> Result<CommunicationValue, CommunicationError> {
        if self.handle.is_closed() {
            return Err(self
                .handle
                .close_reason()
                .unwrap_or(CommunicationError::StreamClosed));
        }

        let mut rx = self.rx.lock().await;
        match rx.recv().await {
            Some(result) => result,
            _ => Err(self
                .handle
                .close_reason()
                .unwrap_or(CommunicationError::StreamClosed)),
        }
    }

    pub fn handle(&self) -> &Arc<ConnectionHandle> {
        &self.handle
    }

    pub fn close(&self) {
        self.handle.close(None);
    }

    pub fn is_open(&self) -> bool {
        self.handle.is_open()
    }

    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    pub fn close_reason(&self) -> Option<CommunicationError> {
        self.handle.close_reason()
    }
}

/* ================================ TESTS ================================ */
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_mode_derive() {
        assert_eq!(SendMode::PersistentStream, SendMode::PersistentStream);
        assert_ne!(SendMode::PersistentStream, SendMode::SingleStreamPerMessage);
    }

    #[test]
    fn test_policy_default_values() {
        let p = Policy::default();
        assert_eq!(p.send_mode, SendMode::PersistentStream);
        assert_eq!(p.max_message_size, 1_000_000_000);
        assert_eq!(p.close_frame_len, u32::MAX);
        assert_eq!(p.application_close_code, 0);
        assert_eq!(p.open_stream_timeout, Duration::from_millis(2_000));
        assert_eq!(p.write_timeout, Duration::from_millis(2_000));
        assert_eq!(p.accept_stream_timeout, Duration::from_millis(10_000));
        assert_eq!(p.read_timeout, Duration::from_millis(30_000));
        assert_eq!(p.keep_alive_interval, Some(Duration::from_secs(3)));
        assert_eq!(p.max_idle_timeout, Some(Duration::from_secs(30)));
        assert_eq!(p.force_close_delay, Duration::from_millis(300));
        assert_eq!(p.max_transient_recv_errors, 20);
        assert_eq!(p.transient_recv_backoff, Duration::from_millis(100));
        assert_eq!(p.receiver_queue_capacity, 1000);
    }

    #[test]
    fn test_policy_clone() {
        let p = Policy::default();
        let cloned = p.clone();
        assert_eq!(p.send_mode, cloned.send_mode);
    }

    #[test]
    fn test_policy_debug() {
        let p = Policy::default();
        let debug_str = format!("{:?}", p);
        assert!(debug_str.contains("Policy"));
    }
}
