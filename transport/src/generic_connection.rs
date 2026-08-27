//! Transport-neutral MTP framing.
//!
//! These types are used by non-wtransport backends.  The established
//! [`crate::Sender`] and [`crate::Receiver`] remain source compatible native
//! wrappers while the framing implementation below is shared by adapters.

use crate::{
    Policy, TransportConnection, TransportRecvStream, TransportSendStream,
    connection::{DecodeRejectionCounters, RuntimePolicy, classify_decode_error},
    framing::{RetryClassifier, write_frame},
};
use mtp_codec::{CommunicationValue, DataType, DecodeLimits, TypeMap};
use mtp_common::{CommunicationError, FirstFrameDisposition, classify_first_frame};
#[cfg(feature = "pipes")]
use std::collections::HashSet;
use std::sync::Arc;
#[cfg(feature = "pipes")]
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Mutex, Notify, RwLock, Semaphore, mpsc};
use tokio::time::{Instant, timeout, timeout_at};

#[cfg(feature = "pipes")]
use crate::pipe::{PipeReader, PipeWriter};

pub struct GenericSender<C: TransportConnection> {
    connection: C,
    policy: Arc<RuntimePolicy>,
    persistent: Arc<Mutex<Option<C::SendStream>>>,
    send_lock: Arc<Mutex<()>>,
    type_map: Arc<RwLock<TypeMap>>,
}

impl<C: TransportConnection> Clone for GenericSender<C> {
    fn clone(&self) -> Self {
        Self {
            connection: self.connection.clone(),
            policy: self.policy.clone(),
            persistent: self.persistent.clone(),
            send_lock: self.send_lock.clone(),
            type_map: self.type_map.clone(),
        }
    }
}

impl<C: TransportConnection> GenericSender<C> {
    pub fn new(connection: C, policy: Arc<Policy>) -> Self {
        let policy = Arc::new(RuntimePolicy::from_public(&policy));
        Self {
            connection,
            policy,
            persistent: Arc::new(Mutex::new(None)),
            send_lock: Arc::new(Mutex::new(())),
            type_map: Arc::new(RwLock::new(TypeMap::latest())),
        }
    }

    /// Bind control frames created by this sender to the negotiated protocol map.
    pub async fn set_type_map(&self, type_map: &TypeMap) {
        *self.type_map.write().await = type_map.clone();
    }

    async fn open(&self) -> Result<C::SendStream, CommunicationError> {
        timeout(self.policy.open_stream_timeout, self.connection.open_uni())
            .await
            .map_err(|_| CommunicationError::StreamError)?
    }

    pub async fn send(&self, value: &CommunicationValue) -> Result<(), CommunicationError> {
        let _lock = self.send_lock.lock().await;
        if self.connection.close_reason().is_some() {
            return Err(CommunicationError::StreamClosed);
        }
        if let Some(version) = value.get_str(DataType::Version) {
            tracing::debug!(
                message_type = ?value.get_type(),
                version,
                connected = ?value.get_data(DataType::Connected),
                client_id = ?value.get_data(DataType::Id),
                "sending MTP handshake response frame"
            );
        }
        match self.policy.send_mode {
            crate::SendMode::SingleStreamPerMessage => {
                let mut stream = self.open().await?;
                timeout(
                    self.policy.write_timeout,
                    write_frame(&mut stream, value, &self.policy),
                )
                .await
                .map_err(|_| CommunicationError::StreamError)??;
                match timeout(self.policy.write_timeout, stream.finish()).await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(_)) | Err(_) => Err(CommunicationError::DeliveryUnknown),
                }
            }
            crate::SendMode::PersistentStream => {
                let mut stream = self.persistent.lock().await;
                let mut attempts = 0;
                loop {
                    if stream.is_none() {
                        *stream = Some(self.open().await?);
                    }
                    let result = match stream.as_mut() {
                        Some(stream) => timeout(
                            self.policy.write_timeout,
                            write_frame(stream, value, &self.policy),
                        )
                        .await
                        .map_err(|_| CommunicationError::StreamError)
                        .and_then(|result| result),
                        None => Err(CommunicationError::StreamError),
                    };
                    if result.is_ok() {
                        return Ok(());
                    }
                    let error = match result {
                        Ok(()) => return Ok(()),
                        Err(error) => error,
                    };
                    if !RetryClassifier::retry_persistent_stream(&error) {
                        return Err(error);
                    }
                    *stream = None;
                    attempts += 1;
                    if attempts > self.policy.persistent_stream_max_retries {
                        return Err(error);
                    }
                    tokio::time::sleep(
                        self.policy.persistent_stream_retry_backoff * attempts as u32,
                    )
                    .await;
                }
            }
        }
    }

    #[cfg(feature = "pipes")]
    pub async fn open_pipe(
        &self,
        pipe_id: u32,
        description: &str,
    ) -> Result<PipeWriter<C::SendStream>, CommunicationError> {
        let _send_lock = self.send_lock.lock().await;
        if self.connection.close_reason().is_some() {
            return Err(CommunicationError::StreamClosed);
        }

        let mut stream = self.open().await?;

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

        timeout(
            self.policy.write_timeout,
            write_frame(&mut stream, &request, &self.policy),
        )
        .await
        .map_err(|_| CommunicationError::StreamError)??;

        Ok(PipeWriter { stream })
    }

    pub fn close(&self) {
        self.connection
            .close(self.policy.application_close_code, b"mtp-close");
    }

    /// Finish the current persistent stream.
    ///
    /// This is used by hosts that put the opening/authentication exchange on
    /// a persistent stream and then transition to application streams.
    pub async fn finish_stream(&self) -> Result<(), CommunicationError> {
        let _lock = self.send_lock.lock().await;
        let mut stream = self.persistent.lock().await;
        let Some(mut stream) = stream.take() else {
            return Ok(());
        };
        timeout(self.policy.write_timeout, stream.finish())
            .await
            .map_err(|_| CommunicationError::StreamError)?
    }
    pub fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }
    pub fn is_open(&self) -> bool {
        !self.is_closed()
    }
    pub fn close_reason(&self) -> Option<CommunicationError> {
        self.connection.close_reason()
    }
}

pub struct GenericReceiver<C: TransportConnection> {
    incoming: Arc<Mutex<mpsc::Receiver<Result<CommunicationValue, CommunicationError>>>>,
    #[cfg(feature = "pipes")]
    pipes: Arc<Mutex<mpsc::Receiver<PipeReader<C::RecvStream>>>>,
    connection: C,
    ping_sender: Arc<RwLock<Option<GenericSender<C>>>>,
    max_message_size: Arc<AtomicU64>,
    type_map: Arc<RwLock<TypeMap>>,
    queue_notify: Arc<Notify>,
    decode_rejections: Arc<DecodeRejectionCounters>,
    #[cfg(feature = "pipes")]
    expected_pipes: Arc<StdMutex<HashSet<u32>>>,
    _accept_task: Arc<tokio::task::JoinHandle<()>>,
}

impl<C: TransportConnection> Clone for GenericReceiver<C> {
    fn clone(&self) -> Self {
        Self {
            incoming: self.incoming.clone(),
            #[cfg(feature = "pipes")]
            pipes: self.pipes.clone(),
            connection: self.connection.clone(),
            ping_sender: self.ping_sender.clone(),
            max_message_size: self.max_message_size.clone(),
            type_map: self.type_map.clone(),
            queue_notify: self.queue_notify.clone(),
            decode_rejections: self.decode_rejections.clone(),
            #[cfg(feature = "pipes")]
            expected_pipes: self.expected_pipes.clone(),
            _accept_task: self._accept_task.clone(),
        }
    }
}

impl<C: TransportConnection> Drop for GenericReceiver<C> {
    fn drop(&mut self) {
        if Arc::strong_count(&self._accept_task) == 1 {
            self._accept_task.abort();
        }
    }
}

impl<C: TransportConnection> GenericReceiver<C> {
    pub fn new(connection: C, policy: Arc<Policy>) -> Self {
        let policy = Arc::new(RuntimePolicy::from_public(&policy));
        let (tx, rx) = mpsc::channel(policy.receiver_queue_capacity);
        #[cfg(feature = "pipes")]
        let (pipe_tx, pipe_rx) = mpsc::channel(policy.receiver_queue_capacity);
        let ping_sender: Arc<RwLock<Option<GenericSender<C>>>> = Arc::new(RwLock::new(None));
        let max_message_size = Arc::new(AtomicU64::new(
            policy
                .handshake_max_message_size
                .min(policy.max_message_size),
        ));
        let task_ping_sender = ping_sender.clone();
        let task_connection = connection.clone();
        let task_policy = policy.clone();
        let task_max_message_size = max_message_size.clone();
        let type_map = Arc::new(RwLock::new(TypeMap::latest()));
        let task_type_map = type_map.clone();
        let queue_notify = Arc::new(Notify::new());
        let task_queue_notify = queue_notify.clone();
        let decode_rejections = Arc::new(DecodeRejectionCounters::default());
        let task_decode_rejections = decode_rejections.clone();
        #[cfg(feature = "pipes")]
        let expected_pipes = Arc::new(StdMutex::new(HashSet::new()));
        #[cfg(feature = "pipes")]
        let task_expected_pipes = expected_pipes.clone();
        let task_accept_task_tx = tx.clone();
        #[cfg(feature = "pipes")]
        let task_accept_task_pipe_tx = pipe_tx.clone();
        let accept_task = tokio::spawn(async move {
            let limit = Arc::new(Semaphore::new(
                task_policy.max_concurrent_stream_tasks.max(1),
            ));
            loop {
                // Backpressure: stop accepting new streams if the output queue is full.
                #[cfg(feature = "pipes")]
                let cap_full =
                    task_accept_task_tx.capacity() == 0 || task_accept_task_pipe_tx.capacity() == 0;
                #[cfg(not(feature = "pipes"))]
                let cap_full = task_accept_task_tx.capacity() == 0;

                let notified = task_queue_notify.notified();
                tokio::pin!(notified);
                if cap_full {
                    notified.await;
                    continue;
                }

                let stream = match tokio::time::timeout(
                    task_policy.accept_stream_timeout,
                    task_connection.accept_uni(),
                )
                .await
                {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(error)) => {
                        let _ = task_accept_task_tx.send(Err(error)).await;
                        break;
                    }
                    Err(_) => {
                        if task_connection.close_reason().is_some() {
                            let _ = task_accept_task_tx
                                .send(Err(CommunicationError::StreamClosed))
                                .await;
                            break;
                        } else {
                            continue;
                        }
                    }
                };
                // Acquire semaphore permit BEFORE spawning the task.
                let permit = match limit.clone().acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => break,
                };
                let tx = task_accept_task_tx.clone();
                #[cfg(feature = "pipes")]
                let pipe_tx = task_accept_task_pipe_tx.clone();
                let policy = task_policy.clone();
                let max_message_size = task_max_message_size.clone();
                let ping_sender = task_ping_sender.clone();
                let connection = task_connection.clone();
                let type_map = task_type_map.clone();
                let decode_rejections = task_decode_rejections.clone();
                #[cfg(feature = "pipes")]
                let expected_pipes = task_expected_pipes.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let mut stream = stream;
                    let mut frames = 0usize;
                    'stream: loop {
                        if policy
                            .max_frames_per_stream
                            .is_some_and(|max| frames >= max)
                        {
                            let close_error = CommunicationError::StreamError;
                            let _ = tx.send(Err(close_error.clone())).await;
                            connection.close(policy.application_close_code, b"max frames exceeded");
                            break;
                        }
                        let mut len = [0; 4];
                        match tokio::time::timeout(policy.read_timeout, stream.read_exact(&mut len))
                            .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(CommunicationError::StreamClosed)) => break,
                            Ok(Err(error)) => {
                                tracing::warn!(%error, "MTP receive stream failed while reading frame header");
                                let _ = tx.send(Err(error)).await;
                                connection.close(
                                    policy.application_close_code,
                                    b"frame header read error",
                                );
                                break 'stream;
                            }
                            Err(_) => {
                                if frames == 0 {
                                    tracing::warn!(
                                        timeout = ?policy.read_timeout,
                                        "MTP receive stream timed out before its first complete frame"
                                    );
                                } else {
                                    tracing::debug!(
                                        frames,
                                        timeout = ?policy.read_timeout,
                                        "MTP receive stream idle timeout"
                                    );
                                }
                                break;
                            }
                        }
                        let len = u32::from_be_bytes(len);
                        if len == policy.close_frame_len {
                            break;
                        }
                        let deadline = Instant::now() + policy.read_timeout;
                        let frame_limit = max_message_size.load(Ordering::Relaxed);
                        let body_len = len as usize;
                        let frame_len = match body_len.checked_add(4) {
                            Some(frame_len) => frame_len,
                            None => {
                                let _ = tx.send(Err(CommunicationError::MessageTooLarge)).await;
                                connection.close(policy.application_close_code, b"frame too large");
                                break;
                            }
                        };
                        if frame_len as u64 > frame_limit {
                            tracing::warn!(frame_len, "MTP receive stream frame is too large");
                            let _ = tx.send(Err(CommunicationError::MessageTooLarge)).await;
                            connection.close(policy.application_close_code, b"frame too large");
                            break;
                        }
                        let mut frame = Vec::new();
                        if frame.try_reserve_exact(frame_len).is_err() {
                            tracing::warn!(frame_len, "MTP receive stream could not reserve frame");
                            let _ = tx.send(Err(CommunicationError::MessageTooLarge)).await;
                            connection
                                .close(policy.application_close_code, b"frame allocation failed");
                            break;
                        }
                        frame.extend_from_slice(&len.to_be_bytes());
                        frame.resize(frame_len, 0);
                        let mut body_offset = 4usize;
                        while body_offset < frame_len {
                            let chunk_len = (frame_len - body_offset).min(16 * 1024);
                            let body_read = timeout_at(
                                deadline,
                                stream.read_exact(&mut frame[body_offset..body_offset + chunk_len]),
                            )
                            .await;
                            if !matches!(&body_read, Ok(Ok(()))) {
                                if matches!(&body_read, Ok(Err(CommunicationError::StreamClosed))) {
                                    break 'stream;
                                }
                                tracing::warn!(
                                    pipe_chunk_len = chunk_len,
                                    ?body_read,
                                    "MTP receive stream failed while reading frame body"
                                );
                                let _ = tx.send(Err(CommunicationError::StreamError)).await;
                                connection
                                    .close(policy.application_close_code, b"frame body read error");
                                break 'stream;
                            }
                            body_offset += chunk_len;
                        }
                        frames += 1;
                        let mut message = match CommunicationValue::try_from_bytes_with_limits(
                            &frame,
                            DecodeLimits::for_transport_message_size(frame_limit),
                        ) {
                            Ok(message) => message,
                            Err(error) => {
                                tracing::warn!(
                                    ?error,
                                    class = ?classify_decode_error(&error),
                                    "MTP receive stream rejected by bounded decode"
                                );
                                decode_rejections.record(&error);
                                let _ = tx
                                    .send(Err(CommunicationError::ParseCommunicationValue))
                                    .await;
                                connection.close(policy.application_close_code, b"invalid frame");
                                break;
                            }
                        };
                        tracing::debug!(
                            frames,
                            frame_len,
                            message_type = ?message.get_type(),
                            "decoded MTP receive frame"
                        );
                        let negotiated_type_map = type_map.read().await.clone();
                        message.set_type_map(&negotiated_type_map);

                        #[cfg(feature = "pipes")]
                        {
                            if frames == 1 {
                                let is_pipe_request =
                                    message.is_type(mtp_codec::CommunicationType::PipeRequest);
                                let pipe_id = message.id().filter(|id| *id != 0);
                                let pipe_is_expected = is_pipe_request
                                    && pipe_id.is_some_and(|pipe_id| {
                                        expected_pipes
                                            .lock()
                                            .is_ok_and(|mut expected| expected.remove(&pipe_id))
                                    });
                                let disposition = match classify_first_frame(
                                    is_pipe_request,
                                    message.id(),
                                    pipe_is_expected,
                                ) {
                                    Ok(disposition) => disposition,
                                    Err(error) => {
                                        let _ = tx.send(Err(error.clone())).await;
                                        connection.close(
                                            policy.application_close_code,
                                            b"pipe request missing id",
                                        );
                                        break;
                                    }
                                };

                                if let FirstFrameDisposition::Pipe(pipe_id) = disposition {
                                    let description = message
                                        .get_str(mtp_codec::DataType::Description)
                                        .unwrap_or("")
                                        .to_string();

                                    let pipe_reader = PipeReader {
                                        stream,
                                        description,
                                        pipe_id,
                                    };

                                    tracing::debug!(pipe_id, description = %pipe_reader.description, "classified incoming pipe stream");

                                    if pipe_tx.send(pipe_reader).await.is_err() {
                                        break;
                                    }
                                    return;
                                }
                            }
                        }

                        if message.is_type(mtp_codec::CommunicationType::Ping) {
                            if let Some(sender) = ping_sender.read().await.clone() {
                                let mut pong = CommunicationValue::new_with_type_map(
                                    mtp_codec::CommunicationType::Pong,
                                    &negotiated_type_map,
                                );
                                if let Some(id) = message.id() {
                                    pong = pong.with_id(id);
                                } else {
                                    pong = pong.without_id();
                                }
                                if let Some(timestamp) =
                                    message.get_data(mtp_codec::DataType::Timestamp)
                                {
                                    pong = pong.add_typed_default(
                                        mtp_codec::DataType::Timestamp,
                                        timestamp.clone(),
                                    );
                                }
                                let _ = sender.send(&pong).await;
                            }
                            continue;
                        }
                        if tx.send(Ok(message)).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        Self {
            incoming: Arc::new(Mutex::new(rx)),
            #[cfg(feature = "pipes")]
            pipes: Arc::new(Mutex::new(pipe_rx)),
            connection,
            ping_sender,
            max_message_size,
            type_map,
            queue_notify,
            decode_rejections,
            #[cfg(feature = "pipes")]
            expected_pipes,
            _accept_task: Arc::new(accept_task),
        }
    }
    pub async fn respond_to_pings(&self, sender: GenericSender<C>) {
        *self.ping_sender.write().await = Some(sender);
    }

    #[cfg(feature = "pipes")]
    pub fn expect_pipe(&self, pipe_id: u32) -> Result<(), CommunicationError> {
        if pipe_id == 0 {
            return Err(CommunicationError::Other("pipe id must be non-zero".into()));
        }
        self.expected_pipes
            .lock()
            .map_err(|_| CommunicationError::Other("expected pipe state is unavailable".into()))?
            .insert(pipe_id);
        Ok(())
    }

    #[cfg(feature = "pipes")]
    pub fn cancel_expected_pipe(&self, pipe_id: u32) {
        if let Ok(mut expected) = self.expected_pipes.lock() {
            expected.remove(&pipe_id);
        }
    }

    /// Switch from the handshake frame limit to the application frame limit.
    pub fn set_max_message_size(&self, max_message_size: u64) {
        self.max_message_size
            .store(max_message_size, Ordering::Relaxed);
    }

    /// Bind subsequently decoded frames to the negotiated protocol version.
    pub async fn set_type_map(&self, type_map: &TypeMap) {
        *self.type_map.write().await = type_map.clone();
    }

    /// Return local counts for frames rejected by the structured decoder.
    pub fn decode_rejection_counts(&self) -> crate::DecodeRejectionCounts {
        self.decode_rejections.snapshot()
    }
    pub async fn receive(&self) -> Result<CommunicationValue, CommunicationError> {
        let result = self
            .incoming
            .lock()
            .await
            .recv()
            .await
            .unwrap_or(Err(CommunicationError::StreamClosed));
        if result.is_ok() {
            self.queue_notify.notify_one();
        }
        result
    }

    #[cfg(feature = "pipes")]
    pub async fn receive_event(
        &self,
    ) -> Result<crate::TransportEvent<C::RecvStream>, CommunicationError> {
        let mut incoming = self.incoming.lock().await;
        let mut pipes = self.pipes.lock().await;
        tokio::select! {
            msg = incoming.recv() => {
                match msg {
                    Some(Ok(val)) => {
                        self.queue_notify.notify_one();
                        Ok(crate::TransportEvent::Message(val))
                    }
                    Some(Err(e)) => Err(e),
                    None => Err(self
                        .connection
                        .close_reason()
                        .unwrap_or(CommunicationError::StreamClosed)),
                }
            }
            pipe = pipes.recv() => {
                match pipe {
                    Some(reader) => {
                        self.queue_notify.notify_one();
                        Ok(crate::TransportEvent::Pipe(reader))
                    }
                    None => Err(self
                        .connection
                        .close_reason()
                        .unwrap_or(CommunicationError::StreamClosed)),
                }
            }
        }
    }

    #[cfg(feature = "pipes")]
    pub async fn receive_pipe(&self) -> Result<PipeReader<C::RecvStream>, CommunicationError> {
        let result = self
            .pipes
            .lock()
            .await
            .recv()
            .await
            .ok_or(CommunicationError::StreamClosed);
        if result.is_ok() {
            self.queue_notify.notify_one();
        }
        result
    }

    #[cfg(feature = "pipes")]
    pub fn try_receive_pipe(
        &self,
    ) -> Result<Option<PipeReader<C::RecvStream>>, CommunicationError> {
        match self.pipes.try_lock() {
            Ok(mut rx) => match rx.try_recv() {
                Ok(reader) => {
                    self.queue_notify.notify_one();
                    Ok(Some(reader))
                }
                Err(mpsc::error::TryRecvError::Empty) => Ok(None),
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    Err(CommunicationError::StreamClosed)
                }
            },
            Err(_) => Ok(None),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }
    pub fn is_open(&self) -> bool {
        !self.is_closed()
    }
    pub fn close_reason(&self) -> Option<CommunicationError> {
        self.connection.close_reason()
    }
}
