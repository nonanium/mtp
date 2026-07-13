use crate::ConnectionHandle;
use mtp_codec::CommunicationValue;
use mtp_common::CommunicationError;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, Notify, RwLock, Semaphore};
use tokio::time::{Duration, sleep, timeout};
use wtransport::Connection;
use tracing::{debug, info, instrument, trace};

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
    pub persistent_stream_max_retries: usize,
    pub persistent_stream_retry_backoff: Duration,
    pub receiver_queue_capacity: usize,
    pub max_concurrent_stream_tasks: usize,
    pub max_frames_per_stream: Option<usize>,
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
            persistent_stream_max_retries: 4,
            persistent_stream_retry_backoff: Duration::from_millis(20),
            receiver_queue_capacity: 1000,
            max_concurrent_stream_tasks: 128,
            max_frames_per_stream: None,
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

    pub fn with_persistent_stream_retries(
        mut self,
        persistent_stream_max_retries: usize,
        persistent_stream_retry_backoff: Duration,
    ) -> Self {
        self.persistent_stream_max_retries = persistent_stream_max_retries;
        self.persistent_stream_retry_backoff = persistent_stream_retry_backoff;
        self
    }

    pub fn with_max_concurrent_stream_tasks(
        mut self,
        max_concurrent_stream_tasks: usize,
    ) -> Self {
        self.max_concurrent_stream_tasks = max_concurrent_stream_tasks;
        self
    }

    pub fn with_max_frames_per_stream(mut self, max_frames_per_stream: Option<usize>) -> Self {
        self.max_frames_per_stream = max_frames_per_stream;
        self
    }
}

enum ReceivedFrame {
    Message(CommunicationValue),
    ClosedByPeer,
    Idle,
}

#[derive(Clone)]
pub struct Sender {
    send_guard: Arc<Mutex<()>>,
    stream_guard: Arc<Mutex<Option<wtransport::SendStream>>>,
    handle: Arc<ConnectionHandle>,
    connection: Connection,
    policy: Arc<Policy>,
}

impl Sender {
    pub fn new(connection: Connection, handle: Arc<ConnectionHandle>, policy: Arc<Policy>) -> Self {
        Self {
            send_guard: Arc::new(Mutex::new(())),
            stream_guard: Arc::new(Mutex::new(None)),
            handle,
            connection,
            policy,
        }
    }

    #[instrument(skip(stream, data, policy), level = "trace")]
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

        let len_bytes = (bytes.len() as u32).to_be_bytes();
        let write_result = async {
            stream.write_all(&len_bytes).await?;
            stream.write_all(&bytes).await?;
            Ok::<(), wtransport::error::StreamWriteError>(())
        };

        match timeout(policy.write_timeout, write_result).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(wtransport::error::StreamWriteError::Stopped(code))) => {
                log::warn!("[Sender] write failed: peer sent STOP_SENDING (error code {code})");
                Err(CommunicationError::StreamClosed)
            }
            Ok(Err(other)) => {
                log::warn!("[Sender] write failed: {other}");
                Err(CommunicationError::StreamError)
            }
            Err(_) => {
                log::warn!("[Sender] write timed out (len={})", bytes.len());
                Err(CommunicationError::StreamError)
            }
        }
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

    #[instrument(skip(conn, policy), level = "trace")]
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

    #[instrument(skip(conn, stream_opt, data, policy), level = "trace")]
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

            let res = match Self::ensure_stream(conn, stream_opt, policy).await {
                Ok(stream) => Self::write_frame(stream, data, policy).await,
                Err(e) => Err(e),
            };

            if res.is_ok() {
                return Ok(());
            }

            let err = res.err().unwrap_or(CommunicationError::StreamError);
            *stream_opt = None;
            tries += 1;
            if tries > policy.persistent_stream_max_retries {
                return Err(err);
            }

            let backoff = policy.persistent_stream_retry_backoff * tries as u32;
            tokio::time::sleep(backoff).await;
        }
    }

    #[instrument(skip(conn, data, policy), level = "trace")]
    async fn send_on_single_stream(
        conn: &Connection,
        data: &CommunicationValue,
        policy: &Policy,
    ) -> Result<(), CommunicationError> {
        let mut stream = Self::open_uni_stream(conn, policy).await?;
        Self::write_frame(&mut stream, data, policy).await?;

        match timeout(policy.write_timeout, stream.finish()).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(wtransport::error::StreamWriteError::Stopped(code))) => {
                log::warn!("[Sender] finish failed: peer sent STOP_SENDING (error code {code})");
                Err(CommunicationError::StreamClosed)
            }
            Ok(Err(other)) => {
                log::warn!("[Sender] finish failed: {other}");
                Err(CommunicationError::StreamError)
            }
            Err(_) => {
                log::warn!("[Sender] finish timed out");
                Err(CommunicationError::StreamError)
            }
        }
    }

    #[instrument(skip(conn, policy), level = "trace")]
    async fn send_close_frame(
        conn: &Connection,
        policy: &Policy,
    ) -> Result<(), CommunicationError> {
        let mut stream = Self::open_uni_stream(conn, policy).await?;

        let len_bytes = policy.close_frame_len.to_be_bytes();
        match timeout(policy.write_timeout, stream.write_all(&len_bytes)).await {
            Ok(Ok(())) => {}
            Ok(Err(wtransport::error::StreamWriteError::Stopped(code))) => {
                log::warn!(
                    "[Sender] close frame write failed: peer sent STOP_SENDING (error code {code})"
                );
            }
            Ok(Err(other)) => {
                log::warn!("[Sender] close frame write failed: {other}");
            }
            Err(_) => {
                log::warn!("[Sender] close frame write timed out");
            }
        }

        match timeout(policy.write_timeout, stream.finish()).await {
            Ok(Ok(())) => {}
            Ok(Err(wtransport::error::StreamWriteError::Stopped(code))) => {
                log::warn!(
                    "[Sender] close frame finish failed: peer sent STOP_SENDING (error code {code})"
                );
            }
            Ok(Err(other)) => {
                log::warn!("[Sender] close frame finish failed: {other}");
            }
            Err(_) => {
                log::warn!("[Sender] close frame finish timed out");
            }
        }

        Ok(())
    }

    #[instrument(skip(self, data), level = "trace")]
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

    #[instrument(skip(self), level = "trace")]
    pub async fn finish_stream(&self) -> Result<(), CommunicationError> {
        let _send_lock = self.send_guard.lock().await;
        let mut stream_opt = self.stream_guard.lock().await;
        if let Some(mut stream) = stream_opt.take() {
            match timeout(self.policy.write_timeout, stream.finish()).await {
                Ok(Ok(())) => {}
                Ok(Err(wtransport::error::StreamWriteError::Stopped(code))) => {
                    log::warn!(
                        "[Sender] finish_stream: peer sent STOP_SENDING (error code {code})"
                    );
                    return Err(CommunicationError::StreamClosed);
                }
                Ok(Err(other)) => {
                    log::warn!("[Sender] finish_stream failed: {other}");
                    return Err(CommunicationError::StreamError);
                }
                Err(_) => {
                    log::warn!("[Sender] finish_stream timed out");
                    return Err(CommunicationError::StreamError);
                }
            }
        }
        Ok(())
    }

    pub fn handle(&self) -> &Arc<ConnectionHandle> {
        &self.handle
    }

    #[instrument(skip(self), level = "trace")]
    pub fn close(&self) {
        info!(target = "mtp.transport", "fire-and-forget close requested");
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
                    Ok(Err(wtransport::error::StreamWriteError::Stopped(code))) => log::warn!(
                        "[Sender] persistent stream finish failed: peer sent STOP_SENDING (error code {code})"
                    ),
                    Ok(Err(e)) => {
                        log::warn!("[Sender] persistent stream finish failed: {e}")
                    }
                    Err(_) => log::warn!("[Sender] persistent stream finish timed out"),
                }
            }

            let _ = Self::send_close_frame(&connection, &policy).await;

            handle.close(Some(CommunicationError::StreamClosed));
            info!(target = "mtp.transport", "connection closed");

            sleep(policy.force_close_delay).await;
            if connection.quic_connection().close_reason().is_none() {
                connection.quic_connection().close(
                    policy.application_close_code.into(),
                    APPLICATION_CLOSE_REASON.as_bytes(),
                );
            }
        });
    }

    #[instrument(skip(self), level = "trace")]
    /// Initiate a best-effort graceful close and wait for the configured force-close delay.
    pub async fn close_and_wait(&self) {
        info!(target = "mtp.transport", "graceful close initiated");
        let connection = self.connection.clone();
        let handle = self.handle.clone();
        let policy = self.policy.clone();
        let mut stream_opt = self.stream_guard.lock().await;

        if connection.quic_connection().close_reason().is_some() || handle.is_closed() {
            handle.close(Some(CommunicationError::StreamClosed));
            return;
        }

        if let Some(mut stream) = stream_opt.take() {
            let close_bytes = policy.close_frame_len.to_be_bytes();
            let close_write = async {
                stream.write_all(&close_bytes).await?;
                stream.finish().await
            };

            match timeout(policy.write_timeout, close_write).await {
                Ok(Ok(())) => {}
                Ok(Err(wtransport::error::StreamWriteError::Stopped(code))) => log::warn!(
                    "[Sender] close_and_wait failed: peer sent STOP_SENDING (error code {code})"
                ),
                Ok(Err(e)) => log::warn!("[Sender] close_and_wait failed: {e}"),
                Err(_) => log::warn!("[Sender] close_and_wait timed out"),
            }
        } else {
            let _ = Self::send_close_frame(&connection, &policy).await;
        }

        handle.close(Some(CommunicationError::StreamClosed));
        info!(target = "mtp.transport", "connection closed");

        sleep(policy.force_close_delay).await;
        if connection.quic_connection().close_reason().is_none() {
            connection.quic_connection().close(
                policy.application_close_code.into(),
                APPLICATION_CLOSE_REASON.as_bytes(),
            );
        }
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

/// Single-consumer framed message receiver.
///
/// `receive()` is intended to be driven by one task at a time. Internally the
/// underlying `mpsc::Receiver` is protected by a mutex so the type remains
/// `Sync`, but it is not a multi-consumer queue.
pub struct Receiver {
    rx: Mutex<mpsc::Receiver<Result<CommunicationValue, CommunicationError>>>,
    _accept_task: tokio::task::JoinHandle<()>,
    handle: Arc<ConnectionHandle>,
    ping_control: Arc<RwLock<PingControl>>,
    queue_notify: Arc<Notify>,
}

#[derive(Clone, Default)]
struct PingControl {
    pong_sender: Option<Sender>,
    pong_observer: Option<mpsc::UnboundedSender<CommunicationValue>>,
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
        let ping_control = Arc::new(RwLock::new(PingControl::default()));
        let accept_ping_control = ping_control.clone();
        let queue_notify = Arc::new(Notify::new());
        let accept_queue_notify = queue_notify.clone();
        let stream_limit = Arc::new(Semaphore::new(policy.max_concurrent_stream_tasks.max(1)));
        let accept_stream_limit = stream_limit.clone();
        debug!(
            target = "mtp.transport",
            max_concurrent_stream_tasks = policy.max_concurrent_stream_tasks,
            receiver_queue_capacity = policy.receiver_queue_capacity,
            "receiver accept loop started"
        );
        info!(
            target = "mtp.transport",
            max_concurrent_stream_tasks = policy.max_concurrent_stream_tasks,
            receiver_queue_capacity = policy.receiver_queue_capacity,
            "connection accepted"
        );

        let accept_task = tokio::spawn(async move {
            let mut close_rx = conn_handle.subscribe_close();

            loop {
                if tx.capacity() == 0 {
                    trace!(target = "mtp.transport", "accept loop paused: receiver queue full");
                    tokio::select! {
                        _ = close_rx.changed() => {
                            if close_rx.borrow().is_some() {
                                break;
                            }
                        }
                        _ = accept_queue_notify.notified() => {}
                    }
                    continue;
                }

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
                                let permit = match accept_stream_limit.clone().acquire_owned().await {
                                    Ok(permit) => permit,
                                    Err(_) => break,
                                };
                                let tx_stream = tx.clone();
                                let stream_handle = conn_handle.clone();
                                let stream_policy = accept_policy.clone();
                                let stream_ping_control = accept_ping_control.clone();

                                tokio::spawn(async move {
                                    let _permit = permit;
                                    let mut s = stream;
                                    let mut frame_count = 0usize;
                                    loop {
                                        if let Some(max_frames) = stream_policy.max_frames_per_stream
                                            && frame_count >= max_frames
                                        {
                                            let close_error = CommunicationError::StreamError;
                                            let _ = tx_stream.send(Err(close_error.clone())).await;
                                            stream_handle.close(Some(close_error));
                                            break;
                                        }

                                        match Self::read_one_frame(&mut s, &stream_policy).await {
                                            Ok(ReceivedFrame::Message(msg)) => {
                                                frame_count += 1;
                                                let ping_type = mtp_codec::CommunicationType::Ping
                                                    .to_id(&mtp_codec::TypeMap::latest());
                                                let pong_type = mtp_codec::CommunicationType::Pong
                                                    .to_id(&mtp_codec::TypeMap::latest());
                                                let control = {
                                                    let control = stream_ping_control.read().await;
                                                    if msg.get_type() == ping_type {
                                                        control
                                                            .pong_sender
                                                            .clone()
                                                            .map(|sender| (Some(sender), None))
                                                    } else if msg.get_type() == pong_type {
                                                        control
                                                            .pong_observer
                                                            .clone()
                                                            .map(|observer| (None, Some(observer)))
                                                    } else {
                                                        None
                                                    }
                                                };

                                                if let Some((Some(sender), _)) = control {
                                                    let mut pong = CommunicationValue::new(mtp_codec::CommunicationType::Pong)
                                                        .with_id(msg.get_id());
                                                    if let Some(timestamp) = msg.get_data_opt(mtp_codec::DataType::Timestamp) {
                                                            pong = pong.add_typed_default(
                                                                mtp_codec::DataType::Timestamp,
                                                                timestamp.clone(),
                                                            );
                                                    }
                                                    if let Err(e) = sender.send(&pong).await {
                                                        log::warn!("[Receiver] failed to send Pong: {e}");
                                                    }
                                                    continue;
                                                }

                                                if let Some((_, Some(observer))) = control {
                                                    let _ = observer.send(msg);
                                                    continue;
                                                }

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
            ping_control,
            queue_notify,
        }
    }

    /* Respond to reserved Ping frames without exposing them to application I/O. */
    pub fn respond_to_pings(&self, sender: Sender) {
        if let Ok(mut control) = self.ping_control.try_write() {
            control.pong_sender = Some(sender);
        } else {
            log::warn!("[Receiver] could not register Ping responder: control lock busy");
        }
    }

    /* Route reserved Pong frames to a connection-level observer. */
    pub fn observe_pongs(&self, observer: mpsc::UnboundedSender<CommunicationValue>) {
        if let Ok(mut control) = self.ping_control.try_write() {
            control.pong_observer = Some(observer);
        } else {
            log::warn!("[Receiver] could not register Pong observer: control lock busy");
        }
    }

    #[instrument(skip(stream, policy), level = "trace")]
    async fn read_one_frame(
        stream: &mut wtransport::RecvStream,
        policy: &Policy,
    ) -> Result<ReceivedFrame, CommunicationError> {
        use wtransport::error::{StreamReadError, StreamReadExactError};

        let mut len_buf = [0u8; 4];
        match timeout(policy.read_timeout, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(())) => {}
            Ok(Err(StreamReadExactError::FinishedEarly(0))) => {
                return Ok(ReceivedFrame::Idle);
            }
            Ok(Err(StreamReadExactError::FinishedEarly(n))) => {
                log::warn!(
                    "[Receiver] length-prefix read ended early ({n}/4 bytes): stream closed by peer"
                );
                return Err(CommunicationError::StreamError);
            }
            Ok(Err(StreamReadExactError::Read(StreamReadError::Reset(code)))) => {
                log::warn!(
                    "[Receiver] length-prefix read failed: peer sent RESET_STREAM (error code {code})"
                );
                return Err(CommunicationError::StreamError);
            }
            Ok(Err(other)) => {
                log::warn!("[Receiver] length-prefix read failed: {other}");
                return Err(CommunicationError::StreamError);
            }
            Err(_) => {
                log::warn!("[Receiver] length-prefix read timed out");
                return Err(CommunicationError::StreamError);
            }
        }

        let len = u32::from_be_bytes(len_buf);
        if len == policy.close_frame_len {
            return Ok(ReceivedFrame::ClosedByPeer);
        }

        let len_usize = len as usize;
        if len as u64 > policy.max_message_size {
            return Err(CommunicationError::MessageTooLarge);
        }

        let mut buf = vec![0u8; len_usize];
        match timeout(policy.read_timeout, stream.read_exact(&mut buf)).await {
            Ok(Ok(())) => {}
            Ok(Err(StreamReadExactError::FinishedEarly(n))) => {
                log::warn!(
                    "[Receiver] body read ended early ({n}/{len_usize} bytes): stream closed by peer"
                );
                return Err(CommunicationError::StreamError);
            }
            Ok(Err(StreamReadExactError::Read(StreamReadError::Reset(code)))) => {
                log::warn!(
                    "[Receiver] body read failed: peer sent RESET_STREAM (error code {code})"
                );
                return Err(CommunicationError::StreamError);
            }
            Ok(Err(other)) => {
                log::warn!("[Receiver] body read failed: {other}");
                return Err(CommunicationError::StreamError);
            }
            Err(_) => {
                log::warn!("[Receiver] body read timed out (len={len_usize})");
                return Err(CommunicationError::StreamError);
            }
        }

        let message = CommunicationValue::from_bytes(&buf)
            .map_err(|_| CommunicationError::ParseCommunicationValue)?;

        Ok(ReceivedFrame::Message(message))
    }

    #[instrument(skip(self), level = "trace")]
    pub async fn receive(&self) -> Result<CommunicationValue, CommunicationError> {
        if self.handle.is_closed() {
            return Err(self
                .handle
                .close_reason()
                .unwrap_or(CommunicationError::StreamClosed));
        }

        let mut rx = self.rx.lock().await;
        match rx.recv().await {
            Some(result) => {
                self.queue_notify.notify_one();
                result
            }
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
        assert_eq!(p.persistent_stream_max_retries, 4);
        assert_eq!(p.persistent_stream_retry_backoff, Duration::from_millis(20));
        assert_eq!(p.receiver_queue_capacity, 1000);
        assert_eq!(p.max_concurrent_stream_tasks, 128);
        assert_eq!(p.max_frames_per_stream, None);
    }

    #[test]
    fn test_policy_clone() {
        let p = Policy::default();
        let cloned = p;
        assert_eq!(p.send_mode, cloned.send_mode);
    }

    #[test]
    fn test_policy_debug() {
        let p = Policy::default();
        let debug_str = format!("{:?}", p);
        assert!(debug_str.contains("Policy"));
    }
}
