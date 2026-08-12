use crate::ConnectionHandle;
#[cfg(feature = "pipes")]
use crate::pipe::PipeReader;
use mtp_codec::{CommunicationValue, DecodeLimits, TypeMap};
use mtp_common::CommunicationError;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Mutex, Notify, RwLock, Semaphore, mpsc};
use tokio::time::{Duration, sleep, timeout};
use tracing::{debug, info, instrument, trace, warn};
use wtransport::Connection;

#[cfg(feature = "pipes")]
#[derive(Debug)]
pub enum TransportEvent<R = wtransport::RecvStream> {
    Message(CommunicationValue),
    Pipe(PipeReader<R>),
}

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
    /// Receive limit used until the application-level handshake completes.
    pub handshake_max_message_size: u64,
    pub close_frame_len: u32,
    pub application_close_code: u32,
    pub open_stream_timeout: Duration,
    pub write_timeout: Duration,
    pub accept_stream_timeout: Duration,
    pub read_timeout: Duration,
    pub keep_alive_interval: Option<Duration>,
    pub max_idle_timeout: Option<Duration>,
    pub force_close_delay: Duration,
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
            max_message_size: 16 * 1024 * 1024,
            handshake_max_message_size: 64 * 1024,
            close_frame_len: u32::MAX,
            application_close_code: 0,
            open_stream_timeout: Duration::from_millis(2_000),
            write_timeout: Duration::from_millis(2_000),
            accept_stream_timeout: Duration::from_millis(500),
            read_timeout: Duration::from_millis(30_000),
            keep_alive_interval: Some(Duration::from_secs(3)),
            max_idle_timeout: Some(Duration::from_secs(30)),
            force_close_delay: Duration::from_millis(300),
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

    pub fn with_handshake_max_message_size(mut self, max_message_size: u64) -> Self {
        self.handshake_max_message_size = max_message_size;
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

    pub fn with_max_concurrent_stream_tasks(mut self, max_concurrent_stream_tasks: usize) -> Self {
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
    type_map: Arc<RwLock<TypeMap>>,
}

impl Sender {
    pub fn new(connection: Connection, handle: Arc<ConnectionHandle>, policy: Arc<Policy>) -> Self {
        Self {
            send_guard: Arc::new(Mutex::new(())),
            stream_guard: Arc::new(Mutex::new(None)),
            handle,
            connection,
            policy,
            type_map: Arc::new(RwLock::new(TypeMap::latest())),
        }
    }

    /// Bind control frames created by this sender to the negotiated protocol map.
    pub async fn set_type_map(&self, type_map: &TypeMap) {
        *self.type_map.write().await = type_map.clone();
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

        let write_result = async {
            stream.write_all(&bytes).await?;
            Ok::<(), wtransport::error::StreamWriteError>(())
        };

        match timeout(policy.write_timeout, write_result).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(wtransport::error::StreamWriteError::Stopped(code))) => {
                warn!("[Sender] write failed: peer sent STOP_SENDING (error code {code})");
                Err(CommunicationError::StreamClosed)
            }
            Ok(Err(other)) => {
                warn!("[Sender] write failed: {other}");
                Err(CommunicationError::StreamError)
            }
            Err(_) => {
                warn!("[Sender] write timed out (len={})", bytes.len());
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
            if !matches!(
                err,
                CommunicationError::StreamError | CommunicationError::StreamClosed
            ) {
                return Err(err);
            }
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
                warn!("[Sender] finish failed: peer sent STOP_SENDING (error code {code})");
                Err(CommunicationError::StreamClosed)
            }
            Ok(Err(other)) => {
                warn!("[Sender] finish failed: {other}");
                Err(CommunicationError::StreamError)
            }
            Err(_) => {
                warn!("[Sender] finish timed out");
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
                warn!(
                    "[Sender] close frame write failed: peer sent STOP_SENDING (error code {code})"
                );
            }
            Ok(Err(other)) => {
                warn!("[Sender] close frame write failed: {other}");
            }
            Err(_) => {
                warn!("[Sender] close frame write timed out");
            }
        }

        match timeout(policy.write_timeout, stream.finish()).await {
            Ok(Ok(())) => {}
            Ok(Err(wtransport::error::StreamWriteError::Stopped(code))) => {
                warn!(
                    "[Sender] close frame finish failed: peer sent STOP_SENDING (error code {code})"
                );
            }
            Ok(Err(other)) => {
                warn!("[Sender] close frame finish failed: {other}");
            }
            Err(_) => {
                warn!("[Sender] close frame finish timed out");
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
                    warn!("[Sender] finish_stream: peer sent STOP_SENDING (error code {code})");
                    return Err(CommunicationError::StreamClosed);
                }
                Ok(Err(other)) => {
                    warn!("[Sender] finish_stream failed: {other}");
                    return Err(CommunicationError::StreamError);
                }
                Err(_) => {
                    warn!("[Sender] finish_stream timed out");
                    return Err(CommunicationError::StreamError);
                }
            }
        }
        Ok(())
    }

    pub fn handle(&self) -> &Arc<ConnectionHandle> {
        &self.handle
    }

    #[cfg(feature = "pipes")]
    #[instrument(skip(self, description), level = "trace")]
    pub async fn open_pipe(
        &self,
        pipe_id: u32,
        description: &str,
    ) -> Result<crate::pipe::PipeWriter, CommunicationError> {
        if self.handle.is_closed() {
            return Err(self
                .handle
                .close_reason()
                .unwrap_or(CommunicationError::UseAfterClosed));
        }

        if self.connection.quic_connection().close_reason().is_some() {
            let reason = self
                .handle
                .close_reason()
                .unwrap_or(CommunicationError::StreamClosed);
            self.handle.close(Some(reason.clone()));
            return Err(reason);
        }

        let mut stream = Self::open_uni_stream(&self.connection, &self.policy).await?;

        let type_map = self.type_map.read().await.clone();
        let request = CommunicationValue::new_with_type_map(
            mtp_codec::CommunicationType::PipeRequest,
            &type_map,
        )
        .with_id(pipe_id)
        .add_typed_default(
            mtp_codec::DataType::Description,
            mtp_codec::DataValue::Str(description.to_string()),
        );

        Self::write_frame(&mut stream, &request, &self.policy).await?;

        Ok(crate::pipe::PipeWriter { stream })
    }

    #[instrument(skip(self), level = "trace")]
    pub fn close_immediate(&self) {
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
                    Ok(Err(wtransport::error::StreamWriteError::Stopped(code))) => warn!(
                        "[Sender] persistent stream finish failed: peer sent STOP_SENDING (error code {code})"
                    ),
                    Ok(Err(e)) => {
                        warn!("[Sender] persistent stream finish failed: {e}")
                    }
                    Err(_) => warn!("[Sender] persistent stream finish timed out"),
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
    pub async fn close(&self) {
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
                Ok(Err(wtransport::error::StreamWriteError::Stopped(code))) => {
                    warn!("[Sender] close failed: peer sent STOP_SENDING (error code {code})")
                }
                Ok(Err(e)) => warn!("[Sender] close failed: {e}"),
                Err(_) => warn!("[Sender] close timed out"),
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

/// Framed message receiver.
///
/// When the `pipes` feature is disabled, `receive()` is intended to be driven
/// by one task at a time. When `pipes` is enabled, an internal dispatcher task
/// consumes events from the channel; applications should use the
/// `MTPConnection::receive()` and `MTPConnection::receive_pipe()` methods
/// instead of calling `receiver.receive()` directly.
///
/// The type is cheaply cloneable: all clones share the same internal channel.
pub struct Receiver {
    inner: Arc<ReceiverInner>,
}

struct ReceiverInner {
    #[cfg(feature = "pipes")]
    msg_rx: Mutex<mpsc::Receiver<Result<CommunicationValue, CommunicationError>>>,
    #[cfg(feature = "pipes")]
    pipe_rx: Mutex<mpsc::Receiver<PipeReader>>,
    #[cfg(not(feature = "pipes"))]
    rx: Mutex<mpsc::Receiver<Result<CommunicationValue, CommunicationError>>>,
    _accept_task: tokio::task::JoinHandle<()>,
    handle: Arc<ConnectionHandle>,
    ping_control: Arc<RwLock<PingControl>>,
    queue_notify: Arc<Notify>,
    max_message_size: Arc<AtomicU64>,
    type_map: Arc<RwLock<TypeMap>>,
}

impl Clone for Receiver {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) == 1 {
            self.inner._accept_task.abort();
        }
    }
}

#[derive(Clone, Default)]
struct PingControl {
    pong_sender: Option<Sender>,
    pong_observer: Option<mpsc::UnboundedSender<CommunicationValue>>,
}

impl Receiver {
    pub fn new(connection: Connection, handle: Arc<ConnectionHandle>, policy: Arc<Policy>) -> Self {
        Self::new_with_max_message_size(connection, handle, policy.clone(), policy.max_message_size)
    }

    #[cfg(feature = "host")]
    pub(crate) fn new_for_handshake(
        connection: Connection,
        handle: Arc<ConnectionHandle>,
        policy: Arc<Policy>,
    ) -> Self {
        let initial_max = policy
            .handshake_max_message_size
            .min(policy.max_message_size);
        Self::new_with_max_message_size(connection, handle, policy, initial_max)
    }

    fn new_with_max_message_size(
        connection: Connection,
        handle: Arc<ConnectionHandle>,
        policy: Arc<Policy>,
        initial_max_message_size: u64,
    ) -> Self {
        #[cfg(feature = "pipes")]
        let (msg_tx, msg_rx) = mpsc::channel::<Result<CommunicationValue, CommunicationError>>(
            policy.receiver_queue_capacity,
        );
        #[cfg(feature = "pipes")]
        let (pipe_tx, pipe_rx) = mpsc::channel::<PipeReader>(policy.receiver_queue_capacity);
        #[cfg(not(feature = "pipes"))]
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
        let max_message_size = Arc::new(AtomicU64::new(initial_max_message_size));
        let accept_max_message_size = max_message_size.clone();
        let type_map = Arc::new(RwLock::new(TypeMap::latest()));
        let accept_type_map = type_map.clone();
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
                #[cfg(feature = "pipes")]
                let cap_full = msg_tx.capacity() == 0 || pipe_tx.capacity() == 0;
                #[cfg(not(feature = "pipes"))]
                let cap_full = tx.capacity() == 0;

                if cap_full {
                    trace!(
                        target = "mtp.transport",
                        "accept loop paused: receiver queue full"
                    );
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
                                #[cfg(feature = "pipes")]
                                let msg_tx_stream = msg_tx.clone();
                                #[cfg(feature = "pipes")]
                                let pipe_tx_stream = pipe_tx.clone();
                                #[cfg(not(feature = "pipes"))]
                                let tx_stream = tx.clone();
                                let stream_handle = conn_handle.clone();
                                let stream_policy = accept_policy.clone();
                                let stream_ping_control = accept_ping_control.clone();
                                let stream_max_message_size = accept_max_message_size.clone();
                                let stream_type_map = accept_type_map.clone();

                                tokio::spawn(async move {
                                    let _permit = permit;
                                    let mut s = stream;
                                    let mut frame_count = 0usize;
                                    loop {
                                        if let Some(max_frames) = stream_policy.max_frames_per_stream
                                            && frame_count >= max_frames
                                        {
                                            let close_error = CommunicationError::StreamError;
                                            #[cfg(feature = "pipes")]
                                            let _ = msg_tx_stream.send(Err(close_error.clone())).await;
                                            #[cfg(not(feature = "pipes"))]
                                            let _ = tx_stream.send(Err(close_error.clone())).await;
                                            stream_handle.close(Some(close_error));
                                            break;
                                        }

                                        let frame_limit = stream_max_message_size.load(Ordering::Relaxed);
                                        match Self::read_one_frame(&mut s, &stream_policy, frame_limit).await {
                                            Ok(ReceivedFrame::Message(mut msg)) => {
                                                let negotiated_type_map =
                                                    stream_type_map.read().await.clone();
                                                msg.set_type_map(&negotiated_type_map);
                                                frame_count += 1;

                                                #[cfg(feature = "pipes")]
                                                {
                                                    if msg.is_type(mtp_codec::CommunicationType::PipeRequest)
                                                        && frame_count == 1
                                                    {
                                                        let Some(pipe_id) = msg.id().filter(|id| *id != 0) else {
                                                            let error = CommunicationError::Other(
                                                                "PipeRequest frame must contain a non-zero id".into(),
                                                            );
                                                            let _ = msg_tx_stream.send(Err(error.clone())).await;
                                                            stream_handle.close(Some(error));
                                                            break;
                                                        };
                                                        let description = msg
                                                            .get_str(mtp_codec::DataType::Description)
                                                            .unwrap_or("")
                                                            .to_string();

                                                        let pipe_reader = crate::pipe::PipeReader {
                                                            stream: s,
                                                            description,
                                                            pipe_id,
                                                        };

                                                        if pipe_tx_stream
                                                            .send(pipe_reader)
                                                            .await
                                                            .is_err()
                                                        {
                                                            stream_handle.close(Some(
                                                                CommunicationError::StreamClosed,
                                                            ));
                                                        }
                                                        break;
                                                    }
                                                }

                                                let control = {
                                                    let control = stream_ping_control.read().await;
                                                    if msg.is_type(mtp_codec::CommunicationType::Ping) {
                                                        control
                                                            .pong_sender
                                                            .clone()
                                                            .map(|sender| (Some(sender), None))
                                                    } else if msg.is_type(mtp_codec::CommunicationType::Pong) {
                                                        control
                                                            .pong_observer
                                                            .clone()
                                                            .map(|observer| (None, Some(observer)))
                                                    } else {
                                                        None
                                                    }
                                                };

                                                if let Some((Some(sender), _)) = control {
                                                    let mut pong = CommunicationValue::new_with_type_map(
                                                        mtp_codec::CommunicationType::Pong,
                                                        &negotiated_type_map,
                                                    );
                                                    if let Some(id) = msg.id() {
                                                        pong = pong.with_id(id);
                                                    } else {
                                                        pong = pong.without_id();
                                                    }
                                                    if let Some(timestamp) = msg.get_data(mtp_codec::DataType::Timestamp) {
                                                            pong = pong.add_typed_default(
                                                                mtp_codec::DataType::Timestamp,
                                                                timestamp.clone(),
                                                            );
                                                    }
                                                    if let Err(e) = sender.send(&pong).await {
                                                        warn!("[Receiver] failed to send Pong: {e}");
                                                    }
                                                    continue;
                                                }

                                                if let Some((_, Some(observer))) = control {
                                                    let _ = observer.send(msg);
                                                    continue;
                                                }

                                                #[cfg(feature = "pipes")]
                                                if msg_tx_stream
                                                    .send(Ok(msg))
                                                    .await
                                                    .is_err()
                                                {
                                                    break;
                                                }
                                                #[cfg(not(feature = "pipes"))]
                                                if tx_stream.send(Ok(msg)).await.is_err() {
                                                    break;
                                                }
                                            }
                                            Ok(ReceivedFrame::ClosedByPeer) => {
                                                let close_error = CommunicationError::StreamClosed;
                                                #[cfg(feature = "pipes")]
                                                let _ = msg_tx_stream.send(Err(close_error.clone())).await;
                                                #[cfg(not(feature = "pipes"))]
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

                                                #[cfg(feature = "pipes")]
                                                let _ = msg_tx_stream.send(Err(close_error.clone())).await;
                                                #[cfg(not(feature = "pipes"))]
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
                                #[cfg(feature = "pipes")]
                                let _ = msg_tx.send(Err(close_error.clone())).await;
                                #[cfg(not(feature = "pipes"))]
                                let _ = tx.send(Err(close_error.clone())).await;
                                conn_handle.close(Some(close_error));
                                break;
                            }

                            Err(_) => {
                                if accept_connection.quic_connection().close_reason().is_some() {
                                    let close_error = CommunicationError::StreamClosed;
                                    #[cfg(feature = "pipes")]
                                    let _ = msg_tx.send(Err(close_error.clone())).await;
                                    #[cfg(not(feature = "pipes"))]
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
            inner: Arc::new(ReceiverInner {
                #[cfg(feature = "pipes")]
                msg_rx: Mutex::new(msg_rx),
                #[cfg(feature = "pipes")]
                pipe_rx: Mutex::new(pipe_rx),
                #[cfg(not(feature = "pipes"))]
                rx: Mutex::new(rx),
                _accept_task: accept_task,
                handle,
                ping_control,
                queue_notify,
                max_message_size,
                type_map,
            }),
        }
    }

    /// Change the receive cap for subsequently parsed frames.
    pub fn set_max_message_size(&self, max_message_size: u64) {
        self.inner
            .max_message_size
            .store(max_message_size, Ordering::Relaxed);
    }

    /// Bind subsequently decoded frames to the negotiated protocol version.
    pub async fn set_type_map(&self, type_map: &TypeMap) {
        *self.inner.type_map.write().await = type_map.clone();
    }

    /* Respond to reserved Ping frames without exposing them to application I/O. */
    pub fn respond_to_pings(&self, sender: Sender) {
        if let Ok(mut control) = self.inner.ping_control.try_write() {
            control.pong_sender = Some(sender);
        } else {
            warn!("[Receiver] could not register Ping responder: control lock busy");
        }
    }

    /* Route reserved Pong frames to a connection-level observer. */
    pub async fn observe_pongs(&self, observer: mpsc::UnboundedSender<CommunicationValue>) {
        self.inner.ping_control.write().await.pong_observer = Some(observer);
    }

    #[instrument(skip(stream, policy), level = "trace")]
    async fn read_one_frame(
        stream: &mut wtransport::RecvStream,
        policy: &Policy,
        max_message_size: u64,
    ) -> Result<ReceivedFrame, CommunicationError> {
        use wtransport::error::{StreamReadError, StreamReadExactError};

        let mut len_buf = [0u8; 4];
        match timeout(policy.read_timeout, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(())) => {}
            Ok(Err(StreamReadExactError::FinishedEarly(0))) => {
                return Ok(ReceivedFrame::Idle);
            }
            Ok(Err(StreamReadExactError::FinishedEarly(n))) => {
                warn!(
                    "[Receiver] length-prefix read ended early ({n}/4 bytes): stream closed by peer"
                );
                return Err(CommunicationError::StreamError);
            }
            Ok(Err(StreamReadExactError::Read(StreamReadError::Reset(code)))) => {
                warn!(
                    "[Receiver] length-prefix read failed: peer sent RESET_STREAM (error code {code})"
                );
                return Err(CommunicationError::StreamError);
            }
            Ok(Err(other)) => {
                warn!("[Receiver] length-prefix read failed: {other}");
                return Err(CommunicationError::StreamError);
            }
            Err(_) => {
                return Ok(ReceivedFrame::Idle);
            }
        }

        let len = u32::from_be_bytes(len_buf);
        if len == policy.close_frame_len {
            return Ok(ReceivedFrame::ClosedByPeer);
        }

        let body_len = len as usize;
        let frame_len = body_len
            .checked_add(4)
            .ok_or(CommunicationError::MessageTooLarge)?;
        if frame_len as u64 > max_message_size {
            return Err(CommunicationError::MessageTooLarge);
        }

        // Grow in bounded chunks instead of trusting the peer's length prefix
        // enough to allocate the complete frame up front.
        let mut buf = Vec::new();
        buf.try_reserve(body_len.min(16 * 1024))
            .map_err(|_| CommunicationError::MessageTooLarge)?;
        while buf.len() < body_len {
            let chunk_len = (body_len - buf.len()).min(16 * 1024);
            let mut chunk = [0u8; 16 * 1024];
            match timeout(
                policy.read_timeout,
                stream.read_exact(&mut chunk[..chunk_len]),
            )
            .await
            {
                Ok(Ok(())) => {
                    buf.try_reserve(chunk_len)
                        .map_err(|_| CommunicationError::MessageTooLarge)?;
                    buf.extend_from_slice(&chunk[..chunk_len]);
                }
                Ok(Err(StreamReadExactError::FinishedEarly(n))) => {
                    warn!(
                        "[Receiver] body read ended early ({}/{body_len} bytes): stream closed by peer",
                        buf.len() + n
                    );
                    return Err(CommunicationError::StreamError);
                }
                Ok(Err(StreamReadExactError::Read(StreamReadError::Reset(code)))) => {
                    warn!(
                        "[Receiver] body read failed: peer sent RESET_STREAM (error code {code})"
                    );
                    return Err(CommunicationError::StreamError);
                }
                Ok(Err(other)) => {
                    warn!("[Receiver] body read failed: {other}");
                    return Err(CommunicationError::StreamError);
                }
                Err(_) => {
                    warn!("[Receiver] body read timed out (len={body_len})");
                    return Err(CommunicationError::StreamError);
                }
            }
        }

        let mut frame = Vec::with_capacity(frame_len);
        frame.extend_from_slice(&len_buf);
        frame.extend_from_slice(&buf);
        let message = CommunicationValue::from_bytes_with_limits(
            &frame,
            DecodeLimits::for_transport_message_size(max_message_size),
        )
        .map_err(|_| CommunicationError::ParseCommunicationValue)?;

        Ok(ReceivedFrame::Message(message))
    }

    #[instrument(skip(self), level = "trace")]
    pub async fn receive(&self) -> Result<CommunicationValue, CommunicationError> {
        let mut close_rx = self.inner.handle.subscribe_close();
        if close_rx.borrow().is_some() {
            return Err(self
                .inner
                .handle
                .close_reason()
                .unwrap_or(CommunicationError::StreamClosed));
        }

        #[cfg(feature = "pipes")]
        {
            let mut rx = self.inner.msg_rx.lock().await;
            let result = tokio::select! {
                message = rx.recv() => message,
                _ = close_rx.changed() => return Err(close_rx
                    .borrow()
                    .clone()
                    .unwrap_or(CommunicationError::StreamClosed)),
            };
            match result {
                Some(Ok(msg)) => {
                    self.inner.queue_notify.notify_one();
                    Ok(msg)
                }
                Some(Err(e)) => Err(e),
                None => Err(self
                    .inner
                    .handle
                    .close_reason()
                    .unwrap_or(CommunicationError::StreamClosed)),
            }
        }
        #[cfg(not(feature = "pipes"))]
        {
            let mut rx = self.inner.rx.lock().await;
            let result = tokio::select! {
                message = rx.recv() => message,
                _ = close_rx.changed() => return Err(close_rx
                    .borrow()
                    .clone()
                    .unwrap_or(CommunicationError::StreamClosed)),
            };
            match result {
                Some(result) => {
                    self.inner.queue_notify.notify_one();
                    result
                }
                None => Err(self
                    .inner
                    .handle
                    .close_reason()
                    .unwrap_or(CommunicationError::StreamClosed)),
            }
        }
    }

    #[cfg(feature = "pipes")]
    #[instrument(skip(self), level = "trace")]
    pub async fn receive_event(&self) -> Result<TransportEvent, CommunicationError> {
        if self.inner.handle.is_closed() {
            return Err(self
                .inner
                .handle
                .close_reason()
                .unwrap_or(CommunicationError::StreamClosed));
        }

        let mut msg_rx = self.inner.msg_rx.lock().await;
        let mut pipe_rx = self.inner.pipe_rx.lock().await;
        tokio::select! {
            msg = msg_rx.recv() => {
                match msg {
                    Some(Ok(val)) => {
                        self.inner.queue_notify.notify_one();
                        Ok(TransportEvent::Message(val))
                    }
                    Some(Err(e)) => Err(e),
                    None => Err(self
                        .inner
                        .handle
                        .close_reason()
                        .unwrap_or(CommunicationError::StreamClosed)),
                }
            }
            pipe = pipe_rx.recv() => {
                match pipe {
                    Some(reader) => {
                        self.inner.queue_notify.notify_one();
                        Ok(TransportEvent::Pipe(reader))
                    }
                    None => Err(self
                        .inner
                        .handle
                        .close_reason()
                        .unwrap_or(CommunicationError::StreamClosed)),
                }
            }
        }
    }

    #[cfg(feature = "pipes")]
    #[instrument(skip(self), level = "trace")]
    pub async fn receive_pipe(&self) -> Result<PipeReader, CommunicationError> {
        if self.inner.handle.is_closed() {
            return Err(self
                .inner
                .handle
                .close_reason()
                .unwrap_or(CommunicationError::StreamClosed));
        }

        let mut rx = self.inner.pipe_rx.lock().await;
        match rx.recv().await {
            Some(reader) => {
                self.inner.queue_notify.notify_one();
                Ok(reader)
            }
            None => Err(self
                .inner
                .handle
                .close_reason()
                .unwrap_or(CommunicationError::StreamClosed)),
        }
    }

    #[cfg(feature = "pipes")]
    pub fn try_receive_pipe(&self) -> Result<Option<PipeReader>, CommunicationError> {
        if self.inner.handle.is_closed() {
            return Err(self
                .inner
                .handle
                .close_reason()
                .unwrap_or(CommunicationError::StreamClosed));
        }

        match self.inner.pipe_rx.try_lock() {
            Ok(mut rx) => match rx.try_recv() {
                Ok(reader) => {
                    self.inner.queue_notify.notify_one();
                    Ok(Some(reader))
                }
                Err(mpsc::error::TryRecvError::Empty) => Ok(None),
                Err(mpsc::error::TryRecvError::Disconnected) => Err(self
                    .inner
                    .handle
                    .close_reason()
                    .unwrap_or(CommunicationError::StreamClosed)),
            },
            Err(_) => Ok(None),
        }
    }

    pub fn handle(&self) -> &Arc<ConnectionHandle> {
        &self.inner.handle
    }

    pub fn close(&self) {
        self.inner.handle.close(None);
    }

    pub fn is_open(&self) -> bool {
        self.inner.handle.is_open()
    }

    pub fn is_closed(&self) -> bool {
        self.inner.handle.is_closed()
    }

    pub fn close_reason(&self) -> Option<CommunicationError> {
        self.inner.handle.close_reason()
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
