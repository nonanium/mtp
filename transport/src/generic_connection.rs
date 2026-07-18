//! Transport-neutral MTP framing.
//!
//! These types are used by non-wtransport backends.  The established
//! [`crate::Sender`] and [`crate::Receiver`] remain source compatible native
//! wrappers while the framing implementation below is shared by adapters.

use crate::{
    Policy, TransportConnection, TransportRecvStream, TransportSendStream, framing::write_frame,
};
use mtp_codec::CommunicationValue;
use mtp_common::CommunicationError;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, Semaphore, mpsc};
use tokio::time::timeout;

#[cfg(feature = "pipes")]
use crate::pipe::{PipeReader, PipeWriter};

pub struct GenericSender<C: TransportConnection> {
    connection: C,
    policy: Arc<Policy>,
    persistent: Arc<Mutex<Option<C::SendStream>>>,
    send_lock: Arc<Mutex<()>>,
}

impl<C: TransportConnection> Clone for GenericSender<C> {
    fn clone(&self) -> Self {
        Self {
            connection: self.connection.clone(),
            policy: self.policy.clone(),
            persistent: self.persistent.clone(),
            send_lock: self.send_lock.clone(),
        }
    }
}

impl<C: TransportConnection> GenericSender<C> {
    pub fn new(connection: C, policy: Arc<Policy>) -> Self {
        Self {
            connection,
            policy,
            persistent: Arc::new(Mutex::new(None)),
            send_lock: Arc::new(Mutex::new(())),
        }
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
        match self.policy.send_mode {
            crate::SendMode::SingleStreamPerMessage => {
                let mut stream = self.open().await?;
                timeout(
                    self.policy.write_timeout,
                    write_frame(&mut stream, value, &self.policy),
                )
                .await
                .map_err(|_| CommunicationError::StreamError)??;
                timeout(self.policy.write_timeout, stream.finish())
                    .await
                    .map_err(|_| CommunicationError::StreamError)?
            }
            crate::SendMode::PersistentStream => {
                let mut stream = self.persistent.lock().await;
                let mut attempts = 0;
                loop {
                    if stream.is_none() {
                        *stream = Some(self.open().await?);
                    }
                    let result = timeout(
                        self.policy.write_timeout,
                        write_frame(stream.as_mut().unwrap(), value, &self.policy),
                    )
                    .await
                    .map_err(|_| CommunicationError::StreamError)
                    .and_then(|r| r);
                    if result.is_ok() {
                        return result;
                    }
                    *stream = None;
                    attempts += 1;
                    if attempts > self.policy.persistent_stream_max_retries {
                        return result;
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
        if self.connection.close_reason().is_some() {
            return Err(CommunicationError::StreamClosed);
        }

        let mut stream = self.open().await?;

        let request = CommunicationValue::new(mtp_codec::CommunicationType::PipeRequest)
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
}

impl<C: TransportConnection> Clone for GenericReceiver<C> {
    fn clone(&self) -> Self {
        Self {
            incoming: self.incoming.clone(),
            #[cfg(feature = "pipes")]
            pipes: self.pipes.clone(),
            connection: self.connection.clone(),
            ping_sender: self.ping_sender.clone(),
        }
    }
}

impl<C: TransportConnection> GenericReceiver<C> {
    pub fn new(connection: C, policy: Arc<Policy>) -> Self {
        let (tx, rx) = mpsc::channel(policy.receiver_queue_capacity);
        #[cfg(feature = "pipes")]
        let (pipe_tx, pipe_rx) = mpsc::channel(policy.receiver_queue_capacity);
        let ping_sender: Arc<RwLock<Option<GenericSender<C>>>> = Arc::new(RwLock::new(None));
        let task_ping_sender = ping_sender.clone();
        let task_connection = connection.clone();
        let task_policy = policy.clone();
        tokio::spawn(async move {
            let limit = Arc::new(Semaphore::new(
                task_policy.max_concurrent_stream_tasks.max(1),
            ));
            loop {
                let stream = match timeout(
                    task_policy.accept_stream_timeout,
                    task_connection.accept_uni(),
                )
                .await
                {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(error)) => {
                        let _ = tx.send(Err(error)).await;
                        break;
                    }
                    Err(_) => {
                        if task_connection.close_reason().is_some() {
                            let _ = tx.send(Err(CommunicationError::StreamClosed)).await;
                            break;
                        } else {
                            continue;
                        }
                    }
                };
                let tx = tx.clone();
                #[cfg(feature = "pipes")]
                let pipe_tx = pipe_tx.clone();
                let policy = task_policy.clone();
                let permit = limit.clone();
                let ping_sender = task_ping_sender.clone();
                tokio::spawn(async move {
                    let Ok(_permit) = permit.acquire_owned().await else {
                        return;
                    };
                    let mut stream = stream;
                    let mut frames = 0usize;
                    loop {
                        if policy
                            .max_frames_per_stream
                            .is_some_and(|max| frames >= max)
                        {
                            let _ = tx.send(Err(CommunicationError::StreamError)).await;
                            break;
                        }
                        let mut len = [0; 4];
                        match timeout(policy.read_timeout, stream.read_exact(&mut len)).await {
                            Ok(Ok(())) => {}
                            Ok(Err(_)) | Err(_) => break,
                        }
                        let len = u32::from_be_bytes(len);
                        if len == policy.close_frame_len {
                            let _ = tx.send(Err(CommunicationError::StreamClosed)).await;
                            break;
                        }
                        if len as u64 > policy.max_message_size {
                            let _ = tx.send(Err(CommunicationError::MessageTooLarge)).await;
                            break;
                        }
                        let target_len = len as usize;
                        let mut body = Vec::new();
                        if body.try_reserve(target_len.min(16 * 1024)).is_err() {
                            let _ = tx.send(Err(CommunicationError::MessageTooLarge)).await;
                            break;
                        }
                        while body.len() < target_len {
                            let chunk_len = (target_len - body.len()).min(16 * 1024);
                            let mut chunk = [0u8; 16 * 1024];
                            if !matches!(
                                timeout(
                                    policy.read_timeout,
                                    stream.read_exact(&mut chunk[..chunk_len]),
                                )
                                .await,
                                Ok(Ok(()))
                            ) || body.try_reserve(chunk_len).is_err()
                            {
                                let _ = tx.send(Err(CommunicationError::StreamError)).await;
                                break;
                            }
                            body.extend_from_slice(&chunk[..chunk_len]);
                        }
                        if body.len() != target_len {
                            break;
                        }
                        frames += 1;
                        let message = match CommunicationValue::from_bytes(&body) {
                            Ok(message) => message,
                            Err(_) => {
                                let _ = tx
                                    .send(Err(CommunicationError::ParseCommunicationValue))
                                    .await;
                                break;
                            }
                        };

                        #[cfg(feature = "pipes")]
                        {
                            let pipe_request_type = mtp_codec::CommunicationType::PipeRequest
                                .try_to_id(&mtp_codec::TypeMap::latest());
                            if Some(message.get_type()) == pipe_request_type && frames == 1 {
                                let pipe_id = message.get_id();
                                let description = message
                                    .get_str(mtp_codec::DataType::Description)
                                    .unwrap_or("")
                                    .to_string();

                                let pipe_reader = PipeReader {
                                    stream,
                                    description,
                                    pipe_id,
                                };

                                if pipe_tx.send(pipe_reader).await.is_err() {
                                    break;
                                }
                                return;
                            }
                        }

                        if message.is_type(mtp_codec::CommunicationType::Ping) {
                            if let Some(sender) = ping_sender.read().await.clone() {
                                let mut pong =
                                    CommunicationValue::new(mtp_codec::CommunicationType::Pong)
                                        .with_id(message.get_id());
                                if let Some(timestamp) =
                                    message.get_data_opt(mtp_codec::DataType::Timestamp)
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
        }
    }
    pub async fn respond_to_pings(&self, sender: GenericSender<C>) {
        *self.ping_sender.write().await = Some(sender);
    }
    pub async fn receive(&self) -> Result<CommunicationValue, CommunicationError> {
        self.incoming
            .lock()
            .await
            .recv()
            .await
            .unwrap_or(Err(CommunicationError::StreamClosed))
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
                    Some(Ok(val)) => Ok(crate::TransportEvent::Message(val)),
                    Some(Err(e)) => Err(e),
                    None => Err(self
                        .connection
                        .close_reason()
                        .unwrap_or(CommunicationError::StreamClosed)),
                }
            }
            pipe = pipes.recv() => {
                match pipe {
                    Some(reader) => Ok(crate::TransportEvent::Pipe(reader)),
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
        self.pipes
            .lock()
            .await
            .recv()
            .await
            .ok_or(CommunicationError::StreamClosed)
    }

    #[cfg(feature = "pipes")]
    pub fn try_receive_pipe(
        &self,
    ) -> Result<Option<PipeReader<C::RecvStream>>, CommunicationError> {
        match self.pipes.try_lock() {
            Ok(mut rx) => match rx.try_recv() {
                Ok(reader) => Ok(Some(reader)),
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
