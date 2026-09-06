use crate::ConnectionHandle;
use crate::framing::RetryClassifier;
#[cfg(feature = "pipes")]
use crate::pipe::PipeReader;
use mtp_codec::{CommunicationValue, DecodeError, DecodeLimits, EncodeLimits, TypeMap};
use mtp_common::CommunicationError;
#[cfg(feature = "pipes")]
use mtp_common::{FirstFrameDisposition, classify_first_frame};
use mtp_core::RuntimePolicy;
pub use mtp_core::{DecodeRejectionClass, Policy, SendMode, classify_decode_error};
#[cfg(feature = "pipes")]
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Mutex, Notify, RwLock, Semaphore, mpsc};
use tokio::time::{Instant, sleep, timeout, timeout_at};
use tracing::{debug, info, instrument, trace, warn};
use wtransport::Connection;

#[cfg(feature = "pipes")]
#[derive(Debug)]
pub enum TransportEvent<R = wtransport::RecvStream> {
    Message(CommunicationValue),
    Pipe(PipeReader<R>),
}

const APPLICATION_CLOSE_REASON: &str = "mtp-close";

#[derive(Debug, Default)]
pub struct DecodeRejectionCounters {
    malformed: AtomicU64,
    resource_limit: AtomicU64,
    duplicate_field: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecodeRejectionCounts {
    pub malformed: u64,
    pub resource_limit: u64,
    pub duplicate_field: u64,
}

impl DecodeRejectionCounters {
    pub(crate) fn record(&self, error: &DecodeError) {
        match classify_decode_error(error) {
            DecodeRejectionClass::Malformed => {
                self.malformed.fetch_add(1, Ordering::Relaxed);
            }
            DecodeRejectionClass::ResourceLimit => {
                self.resource_limit.fetch_add(1, Ordering::Relaxed);
            }
            DecodeRejectionClass::DuplicateField => {
                self.duplicate_field.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub(crate) fn snapshot(&self) -> DecodeRejectionCounts {
        DecodeRejectionCounts {
            malformed: self.malformed.load(Ordering::Relaxed),
            resource_limit: self.resource_limit.load(Ordering::Relaxed),
            duplicate_field: self.duplicate_field.load(Ordering::Relaxed),
        }
    }
}

enum ReceivedFrame {
    Message(CommunicationValue),
    ClosedByPeer,
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SenderState {
    Open,
    Closing,
    Closed,
}

#[derive(Clone)]
pub struct Sender {
    send_guard: Arc<Mutex<()>>,
    stream_guard: Arc<Mutex<Option<wtransport::SendStream>>>,
    state: Arc<Mutex<SenderState>>,
    handle: Arc<ConnectionHandle>,
    connection: Connection,
    policy: Arc<RuntimePolicy>,
    type_map: Arc<RwLock<TypeMap>>,
}

impl Sender {
    pub fn new(connection: Connection, handle: Arc<ConnectionHandle>, policy: Arc<Policy>) -> Self {
        let policy = Arc::new(RuntimePolicy::new(&policy));
        Self {
            send_guard: Arc::new(Mutex::new(())),
            stream_guard: Arc::new(Mutex::new(None)),
            state: Arc::new(Mutex::new(SenderState::Open)),
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
        let bytes = data
            .to_bytes_with_limits(EncodeLimits::for_transport_message_size(
                policy.max_message_size,
            ))
            .map_err(|_| CommunicationError::Encode)?;
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
                Err(CommunicationError::DeliveryUnknown)
            }
            Ok(Err(other)) => {
                warn!("[Sender] write failed: {other}");
                Err(CommunicationError::DeliveryUnknown)
            }
            Err(_) => {
                warn!("[Sender] write timed out (len={})", bytes.len());
                Err(CommunicationError::DeliveryUnknown)
            }
        }
    }

    fn normalize_send_error(error: CommunicationError) -> CommunicationError {
        match error {
            CommunicationError::ConnectionLost | CommunicationError::StreamError => {
                CommunicationError::StreamClosed
            }
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
            .map_err(|_| CommunicationError::ConnectionLost)?;

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

            let err = match res {
                Ok(()) => return Ok(()),
                Err(error) => error,
            };
            if !RetryClassifier::retry_persistent_stream(&err) {
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
                Err(CommunicationError::DeliveryUnknown)
            }
            Ok(Err(other)) => {
                warn!("[Sender] finish failed: {other}");
                Err(CommunicationError::DeliveryUnknown)
            }
            Err(_) => {
                warn!("[Sender] finish timed out");
                Err(CommunicationError::DeliveryUnknown)
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
        let _send_lock = self.send_guard.lock().await;

        {
            let state = self.state.lock().await;
            if *state != SenderState::Open {
                return Err(self
                    .handle
                    .close_reason()
                    .unwrap_or(CommunicationError::StreamClosed));
            }
        }

        if self.connection.quic_connection().close_reason().is_some() {
            let reason = self
                .handle
                .close_reason()
                .unwrap_or(CommunicationError::StreamClosed);
            *self.state.lock().await = SenderState::Closed;
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
                    *self.state.lock().await = SenderState::Closed;
                    self.handle.close(Some(normalized.clone()));
                }

                Err(normalized)
            }
        }
    }

    #[instrument(skip(self), level = "trace")]
    pub async fn finish_stream(&self) -> Result<(), CommunicationError> {
        let _send_lock = self.send_guard.lock().await;
        if *self.state.lock().await != SenderState::Open {
            return Err(self
                .handle
                .close_reason()
                .unwrap_or(CommunicationError::StreamClosed));
        }
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
        let _send_lock = self.send_guard.lock().await;
        if *self.state.lock().await != SenderState::Open {
            return Err(self
                .handle
                .close_reason()
                .unwrap_or(CommunicationError::StreamClosed));
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
        let send_guard = self.send_guard.clone();
        let state = self.state.clone();

        tokio::spawn(async move {
            let _send_lock = send_guard.lock().await;
            {
                let mut sender_state = state.lock().await;
                if *sender_state != SenderState::Open {
                    return;
                }
                *sender_state = SenderState::Closing;
            }

            if connection.quic_connection().close_reason().is_some() || handle.is_closed() {
                *state.lock().await = SenderState::Closed;
                handle.close(Some(CommunicationError::StreamClosed));
                return;
            }

            {
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
            }

            let _ = Self::send_close_frame(&connection, &policy).await;

            *state.lock().await = SenderState::Closed;
            handle.close(Some(CommunicationError::StreamClosed));
            info!(target = "mtp.transport", "connection closed");

            drop(_send_lock);
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
        let _send_lock = self.send_guard.lock().await;
        {
            let mut state = self.state.lock().await;
            if *state != SenderState::Open {
                return;
            }
            *state = SenderState::Closing;
        }

        if connection.quic_connection().close_reason().is_some() || handle.is_closed() {
            *self.state.lock().await = SenderState::Closed;
            handle.close(Some(CommunicationError::StreamClosed));
            return;
        }

        {
            let mut stream_opt = self.stream_guard.lock().await;
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
        }

        *self.state.lock().await = SenderState::Closed;
        handle.close(Some(CommunicationError::StreamClosed));
        info!(target = "mtp.transport", "connection closed");

        drop(_send_lock);
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
    decode_rejections: Arc<DecodeRejectionCounters>,
    #[cfg(feature = "pipes")]
    expected_pipes: Arc<std::sync::Mutex<HashSet<u32>>>,
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
    pong_observer: Option<mpsc::Sender<CommunicationValue>>,
    expected_pong_id: Option<u32>,
}

impl PingControl {
    fn accepts_pong(&mut self, id: Option<u32>) -> bool {
        if self.expected_pong_id == id && id.is_some() {
            self.expected_pong_id = None;
            true
        } else {
            false
        }
    }
}

impl Receiver {
    pub fn new(connection: Connection, handle: Arc<ConnectionHandle>, policy: Arc<Policy>) -> Self {
        let policy = Arc::new(RuntimePolicy::new(&policy));
        let max_message_size = policy.max_message_size;
        Self::new_with_max_message_size(connection, handle, policy, max_message_size)
    }

    #[cfg(feature = "host")]
    pub(crate) fn new_for_handshake(
        connection: Connection,
        handle: Arc<ConnectionHandle>,
        policy: Arc<Policy>,
    ) -> Self {
        let policy = Arc::new(RuntimePolicy::new(&policy));
        let initial_max = policy
            .handshake_max_message_size
            .min(policy.max_message_size);
        Self::new_with_max_message_size(connection, handle, policy, initial_max)
    }

    fn new_with_max_message_size(
        connection: Connection,
        handle: Arc<ConnectionHandle>,
        policy: Arc<RuntimePolicy>,
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
        let decode_rejections = Arc::new(DecodeRejectionCounters::default());
        let accept_decode_rejections = decode_rejections.clone();
        #[cfg(feature = "pipes")]
        let expected_pipes = Arc::new(std::sync::Mutex::new(HashSet::new()));
        #[cfg(feature = "pipes")]
        let accept_expected_pipes = expected_pipes.clone();
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
                                let stream_decode_rejections = accept_decode_rejections.clone();
                                #[cfg(feature = "pipes")]
                                let stream_expected_pipes = accept_expected_pipes.clone();

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
                                        match Self::read_one_frame(
                                            &mut s,
                                            &stream_policy,
                                            frame_limit,
                                            &stream_decode_rejections,
                                        )
                                        .await
                                        {
                                            Ok(ReceivedFrame::Message(mut msg)) => {
                                                let negotiated_type_map =
                                                    stream_type_map.read().await.clone();
                                                msg.set_type_map(&negotiated_type_map);
                                                frame_count += 1;

                                                #[cfg(feature = "pipes")]
                                                {
                                                    if frame_count == 1 {
                                                        let is_pipe_request = msg.is_type(
                                                            mtp_codec::CommunicationType::PipeRequest,
                                                        );
                                                        let pipe_id = msg.id().filter(|id| *id != 0);
                                                        let pipe_is_expected = is_pipe_request && pipe_id.is_some_and(|pipe_id| {
                                                            stream_expected_pipes
                                                                .lock()
                                                                .is_ok_and(|mut expected| expected.remove(&pipe_id))
                                                        });
                                                        let disposition = match classify_first_frame(
                                                            is_pipe_request,
                                                            msg.id(),
                                                            pipe_is_expected,
                                                        ) {
                                                            Ok(disposition) => disposition,
                                                            Err(error) => {
                                                                let _ = msg_tx_stream
                                                                    .send(Err(error.clone()))
                                                                    .await;
                                                                stream_handle.close(Some(error));
                                                                break;
                                                            }
                                                        };

                                                        if let FirstFrameDisposition::Pipe(pipe_id) = disposition {
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
                                                }

                                                let pong_sender = if msg.is_type(mtp_codec::CommunicationType::Ping) {
                                                    stream_ping_control
                                                        .read()
                                                        .await
                                                        .pong_sender
                                                        .clone()
                                                } else {
                                                    None
                                                };

                                                if let Some(sender) = pong_sender {
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

                                                if msg.is_type(mtp_codec::CommunicationType::Pong) {
                                                    let observer = {
                                                        let mut control = stream_ping_control.write().await;
                                                        if control.accepts_pong(msg.id()) {
                                                            control.pong_observer.clone()
                                                        } else {
                                                            None
                                                        }
                                                    };
                                                    if let Some(observer) = observer {
                                                        let _ = observer.try_send(msg);
                                                    }
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
                                                    CommunicationError::ConnectionLost
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
                decode_rejections,
                #[cfg(feature = "pipes")]
                expected_pipes,
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

    #[cfg(feature = "pipes")]
    pub fn expect_pipe(&self, pipe_id: u32) -> Result<(), CommunicationError> {
        if pipe_id == 0 {
            return Err(CommunicationError::Other("pipe id must be non-zero".into()));
        }
        self.inner
            .expected_pipes
            .lock()
            .map_err(|_| CommunicationError::Other("expected pipe state is unavailable".into()))?
            .insert(pipe_id);
        Ok(())
    }

    #[cfg(feature = "pipes")]
    pub fn cancel_expected_pipe(&self, pipe_id: u32) {
        if let Ok(mut expected) = self.inner.expected_pipes.lock() {
            expected.remove(&pipe_id);
        }
    }

    /// Return local counts for frames rejected by the structured decoder.
    ///
    /// These counters are intentionally local-only; peers continue to receive
    /// the generic protocol parse failure.
    pub fn decode_rejection_counts(&self) -> DecodeRejectionCounts {
        self.inner.decode_rejections.snapshot()
    }

    /* Respond to reserved Ping frames without exposing them to application I/O. */
    pub fn respond_to_pings(&self, sender: Sender) {
        if let Ok(mut control) = self.inner.ping_control.try_write() {
            control.pong_sender = Some(sender);
        } else {
            warn!("[Receiver] could not register Ping responder: control lock busy");
        }
    }

    /* Route only the currently expected reserved Pong through a bounded observer. */
    pub async fn observe_pongs_bounded(&self, observer: mpsc::Sender<CommunicationValue>) {
        self.inner.ping_control.write().await.pong_observer = Some(observer);
    }

    pub async fn set_expected_pong_id(&self, expected_pong_id: Option<u32>) {
        self.inner.ping_control.write().await.expected_pong_id = expected_pong_id;
    }

    #[instrument(skip(stream, policy, decode_rejections), level = "trace")]
    async fn read_one_frame(
        stream: &mut wtransport::RecvStream,
        policy: &RuntimePolicy,
        max_message_size: u64,
        decode_rejections: &DecodeRejectionCounters,
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
        let deadline = Instant::now() + policy.read_timeout;

        let body_len = len as usize;
        let frame_len = body_len
            .checked_add(4)
            .ok_or(CommunicationError::MessageTooLarge)?;
        if frame_len as u64 > max_message_size {
            return Err(CommunicationError::MessageTooLarge);
        }

        // The length has already been checked against the admitted frame
        // limit, so reserve one bounded framing buffer and decode it without a
        // second prefix-plus-body allocation/copy.
        let mut frame = Vec::new();
        frame
            .try_reserve_exact(frame_len)
            .map_err(|_| CommunicationError::MessageTooLarge)?;
        frame.extend_from_slice(&len_buf);
        frame.resize(frame_len, 0);
        let mut body_offset = 4usize;
        while body_offset < frame_len {
            let chunk_len = (frame_len - body_offset).min(16 * 1024);
            match timeout_at(
                deadline,
                stream.read_exact(&mut frame[body_offset..body_offset + chunk_len]),
            )
            .await
            {
                Ok(Ok(())) => body_offset += chunk_len,
                Ok(Err(StreamReadExactError::FinishedEarly(n))) => {
                    warn!(
                        "[Receiver] body read ended early ({}/{body_len} bytes): stream closed by peer",
                        body_offset.saturating_sub(4) + n
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

        let message = match CommunicationValue::try_from_bytes_with_limits(
            &frame,
            DecodeLimits::for_transport_message_size(max_message_size),
        ) {
            Ok(message) => message,
            Err(error) => {
                decode_rejections.record(&error);
                warn!(
                    ?error,
                    class = ?classify_decode_error(&error),
                    "[Receiver] rejected frame during bounded decode"
                );
                return Err(CommunicationError::ParseCommunicationValue);
            }
        };

        Ok(ReceivedFrame::Message(message))
    }

    #[instrument(skip(self), level = "trace")]
    pub async fn receive(&self) -> Result<CommunicationValue, CommunicationError> {
        let mut close_rx = self.inner.handle.subscribe_close();

        #[cfg(feature = "pipes")]
        {
            let mut rx = self.inner.msg_rx.lock().await;
            let result = tokio::select! {
                biased;
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
                biased;
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
        let mut close_rx = self.inner.handle.subscribe_close();
        let mut msg_rx = self.inner.msg_rx.lock().await;
        let mut pipe_rx = self.inner.pipe_rx.lock().await;
        tokio::select! {
            biased;
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
            _ = close_rx.changed() => Err(close_rx
                .borrow()
                .clone()
                .unwrap_or(CommunicationError::StreamClosed)),
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

    #[test]
    fn runtime_policy_normalizes_zero_channel_and_task_limits() {
        let policy = Policy {
            receiver_queue_capacity: 0,
            max_concurrent_stream_tasks: 0,
            ..Policy::default()
        };

        let runtime = RuntimePolicy::new(&policy);

        assert_eq!(runtime.receiver_queue_capacity, 1);
        assert_eq!(runtime.max_concurrent_stream_tasks, 1);
        assert_eq!(policy.receiver_queue_capacity, 0);
        assert_eq!(policy.max_concurrent_stream_tasks, 0);
    }

    #[test]
    fn ping_control_accepts_only_the_current_expected_id() {
        let mut control = PingControl {
            expected_pong_id: Some(7),
            ..PingControl::default()
        };

        assert!(!control.accepts_pong(Some(6)));
        assert_eq!(control.expected_pong_id, Some(7));
        assert!(control.accepts_pong(Some(7)));
        assert_eq!(control.expected_pong_id, None);
        assert!(!control.accepts_pong(Some(7)));
    }

    #[test]
    fn decode_rejection_classes_are_stable_and_counted() {
        assert_eq!(
            classify_decode_error(&DecodeError::MalformedEncoding),
            DecodeRejectionClass::Malformed
        );
        assert_eq!(
            classify_decode_error(&DecodeError::AllocationLimit),
            DecodeRejectionClass::ResourceLimit
        );
        assert_eq!(
            classify_decode_error(&DecodeError::DuplicateField),
            DecodeRejectionClass::DuplicateField
        );

        let counters = DecodeRejectionCounters::default();
        counters.record(&DecodeError::MalformedEncoding);
        counters.record(&DecodeError::DepthLimit);
        counters.record(&DecodeError::DuplicateField);
        assert_eq!(
            counters.snapshot(),
            DecodeRejectionCounts {
                malformed: 1,
                resource_limit: 1,
                duplicate_field: 1,
            }
        );
    }
}
