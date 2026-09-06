use mtp_codec::CommunicationValue;
#[cfg(feature = "pipes")]
use mtp_codec::TypeMap;
use mtp_common::CommunicationError;
use mtp_native::Receiver;
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(feature = "pipes")]
use std::sync::Mutex as StdMutex;
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, Instant};

#[cfg(feature = "pipes")]
use mtp_codec::{CommunicationType, DataType, DataValue};
#[cfg(feature = "pipes")]
use mtp_common::PipeError;
#[cfg(feature = "pipes")]
use mtp_native::{Policy, Sender};

#[cfg(feature = "pipes")]
pub struct PipeHandle {
    pub(crate) pipe_id: u32,
    pub(crate) description: String,
    pub(crate) sender: Sender,
    pub(crate) response_rx: tokio::sync::oneshot::Receiver<Result<bool, PipeError>>,
    pub(crate) dispatcher: Arc<PipeDispatcher>,
    pub(crate) token: Arc<()>,
}

#[cfg(feature = "pipes")]
impl PipeHandle {
    pub fn pipe_id(&self) -> u32 {
        self.pipe_id
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub async fn wait(mut self) -> Result<Option<mtp_native::PipeWriter>, PipeError> {
        let response =
            tokio::time::timeout(self.dispatcher.policy.read_timeout, &mut self.response_rx).await;
        match response {
            Ok(Ok(Ok(true))) => {
                let writer = self
                    .sender
                    .open_pipe(self.pipe_id, &self.description)
                    .await
                    .map_err(PipeError::from)?;
                Ok(Some(writer))
            }
            Ok(Ok(Ok(false))) => Ok(None),
            Ok(Ok(Err(error))) => {
                expire_pending_creation(&self.dispatcher, self.pipe_id, &self.token);
                Err(error)
            }
            Ok(Err(_)) => {
                expire_pending_creation(&self.dispatcher, self.pipe_id, &self.token);
                Err(PipeError::StreamClosed)
            }
            Err(_) => {
                expire_pending_creation(&self.dispatcher, self.pipe_id, &self.token);
                Err(PipeError::HandshakeTimeout)
            }
        }
    }
}

#[cfg(feature = "pipes")]
impl Drop for PipeHandle {
    fn drop(&mut self) {
        expire_pending_creation(&self.dispatcher, self.pipe_id, &self.token);
    }
}

#[cfg(feature = "pipes")]
pub struct PipeRequest {
    pub(crate) pipe_id: u32,
    pub(crate) description: String,
    pub(crate) sender: Sender,
    pub(crate) receiver: Receiver,
    pub(crate) dispatcher: Arc<PipeDispatcher>,
}

#[cfg(feature = "pipes")]
struct ExpectedPipeGuard {
    receiver: Receiver,
    pipe_id: u32,
    armed: bool,
}

#[cfg(feature = "pipes")]
impl ExpectedPipeGuard {
    fn new(receiver: Receiver, pipe_id: u32) -> Self {
        Self {
            receiver,
            pipe_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(feature = "pipes")]
impl Drop for ExpectedPipeGuard {
    fn drop(&mut self) {
        if self.armed {
            self.receiver.cancel_expected_pipe(self.pipe_id);
        }
    }
}

#[cfg(feature = "pipes")]
impl PipeRequest {
    pub fn id(&self) -> u32 {
        self.pipe_id
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub async fn accept(self) -> Result<mtp_native::PipeReader, PipeError> {
        self.receiver
            .expect_pipe(self.pipe_id)
            .map_err(PipeError::from)?;
        let mut expected_pipe = ExpectedPipeGuard::new(self.receiver.clone(), self.pipe_id);
        let (pipe_tx, pipe_rx) = tokio::sync::oneshot::channel();
        {
            let mut pending = self.dispatcher.pending_pipes.lock().await;
            pending.insert(self.pipe_id, pipe_tx);
        }

        let resp = CommunicationValue::new_with_type_map(
            CommunicationType::PipeResponse,
            &self.dispatcher.type_map,
        )
        .with_id(self.pipe_id)
        .add_typed_default(DataType::Accepted, DataValue::BoolTrue);
        if let Err(error) = self.sender.send(&resp).await {
            self.dispatcher
                .pending_pipes
                .lock()
                .await
                .remove(&self.pipe_id);
            return Err(PipeError::from(error));
        }

        let timeout = self.dispatcher.policy.read_timeout;
        match tokio::time::timeout(timeout, pipe_rx).await {
            Ok(Ok(reader)) => {
                expected_pipe.disarm();
                Ok(reader)
            }
            Ok(Err(_)) => {
                self.dispatcher
                    .pending_pipes
                    .lock()
                    .await
                    .remove(&self.pipe_id);
                Err(PipeError::StreamClosed)
            }
            Err(_) => {
                self.dispatcher
                    .pending_pipes
                    .lock()
                    .await
                    .remove(&self.pipe_id);
                Err(PipeError::HandshakeTimeout)
            }
        }
    }

    pub async fn deny(self) -> Result<(), PipeError> {
        let resp = CommunicationValue::new_with_type_map(
            CommunicationType::PipeResponse,
            &self.dispatcher.type_map,
        )
        .with_id(self.pipe_id)
        .add_typed_default(DataType::Accepted, DataValue::BoolFalse);
        self.sender.send(&resp).await.map_err(PipeError::from)?;
        Ok(())
    }
}

pub(crate) struct PendingRequest {
    pub(crate) token: Arc<()>,
    pub(crate) sender: tokio::sync::oneshot::Sender<Result<CommunicationValue, CommunicationError>>,
}

#[cfg(feature = "pipes")]
pub(crate) struct PendingCreation {
    pub(crate) token: Arc<()>,
    pub(crate) sender: tokio::sync::oneshot::Sender<Result<bool, PipeError>>,
}

#[cfg(feature = "pipes")]
pub(crate) struct PendingCreationGuard {
    dispatcher: Arc<PipeDispatcher>,
    pipe_id: u32,
    token: Arc<()>,
    armed: bool,
}

#[cfg(feature = "pipes")]
impl PendingCreationGuard {
    pub(crate) fn new(dispatcher: Arc<PipeDispatcher>, pipe_id: u32, token: Arc<()>) -> Self {
        Self {
            dispatcher,
            pipe_id,
            token,
            armed: true,
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(feature = "pipes")]
impl Drop for PendingCreationGuard {
    fn drop(&mut self) {
        if self.armed {
            expire_pending_creation(&self.dispatcher, self.pipe_id, &self.token);
        }
    }
}

pub(crate) struct PipeDispatcher {
    pub(crate) pending_requests: Mutex<HashMap<u32, PendingRequest>>,
    pub(crate) expired_requests: Mutex<HashMap<u32, Instant>>,
    #[cfg(feature = "pipes")]
    pub(crate) type_map: TypeMap,
    #[cfg(feature = "pipes")]
    pub(crate) pending_creations: StdMutex<HashMap<u32, PendingCreation>>,
    #[cfg(feature = "pipes")]
    pub(crate) expired_creations: StdMutex<HashMap<u32, Instant>>,
    #[cfg(feature = "pipes")]
    pub(crate) pending_pipes:
        Mutex<HashMap<u32, tokio::sync::oneshot::Sender<mtp_native::PipeReader>>>,
    #[cfg(feature = "pipes")]
    pub(crate) policy: Arc<Policy>,
}

#[cfg(feature = "pipes")]
const EXPIRED_CREATION_TOMBSTONE_TTL: Duration = Duration::from_secs(60);
#[cfg(feature = "pipes")]
const MAX_EXPIRED_CREATION_TOMBSTONES: usize = 1024;

#[cfg(feature = "pipes")]
pub(crate) fn expire_pending_creation(dispatcher: &PipeDispatcher, pipe_id: u32, token: &Arc<()>) {
    let removed = dispatcher
        .pending_creations
        .lock()
        .ok()
        .and_then(|mut pending| {
            if pending
                .get(&pipe_id)
                .is_some_and(|entry| Arc::ptr_eq(&entry.token, token))
            {
                pending.remove(&pipe_id);
                Some(())
            } else {
                None
            }
        });
    if removed.is_none() {
        return;
    }
    let Ok(mut expired) = dispatcher.expired_creations.lock() else {
        return;
    };
    let now = Instant::now();
    expired.retain(|_, expires_at| *expires_at > now);
    if expired.len() >= MAX_EXPIRED_CREATION_TOMBSTONES
        && let Some(oldest) = expired
            .iter()
            .min_by_key(|(_, expires_at)| **expires_at)
            .map(|(id, _)| *id)
    {
        expired.remove(&oldest);
    }
    expired.insert(pipe_id, now + EXPIRED_CREATION_TOMBSTONE_TTL);
}

#[cfg(feature = "pipes")]
fn consume_expired_creation(dispatcher: &PipeDispatcher, pipe_id: u32) -> bool {
    let Ok(mut expired) = dispatcher.expired_creations.lock() else {
        return false;
    };
    let now = Instant::now();
    expired.retain(|_, expires_at| *expires_at > now);
    expired.remove(&pipe_id).is_some()
}

#[cfg(feature = "pipes")]
pub(crate) fn is_expired_creation(dispatcher: &PipeDispatcher, pipe_id: u32) -> bool {
    let Ok(mut expired) = dispatcher.expired_creations.lock() else {
        return true;
    };
    let now = Instant::now();
    expired.retain(|_, expires_at| *expires_at > now);
    expired.contains_key(&pipe_id)
}

#[cfg(feature = "pipes")]
pub(crate) fn fail_pending_creations(dispatcher: &PipeDispatcher, error: &CommunicationError) {
    let pending = dispatcher
        .pending_creations
        .lock()
        .ok()
        .map(|mut pending| std::mem::take(&mut *pending));
    if let Some(pending) = pending {
        let error = PipeError::from(error.clone());
        for (_, pending) in pending {
            let _ = pending.sender.send(Err(error.clone()));
        }
    }
    if let Ok(mut expired) = dispatcher.expired_creations.lock() {
        expired.clear();
    }
}

#[cfg(feature = "pipes")]
pub(crate) async fn fail_pending_pipes(dispatcher: &PipeDispatcher) {
    dispatcher.pending_pipes.lock().await.clear();
}

pub(crate) async fn route_message(
    msg: CommunicationValue,
    app_tx: &mpsc::Sender<Result<CommunicationValue, CommunicationError>>,
    dispatcher: &PipeDispatcher,
) -> bool {
    if !matches!(msg.id(), Some(id) if id != 0)
        && msg
            .get_type_name()
            .is_some_and(|name| name.ends_with("Response"))
    {
        return app_tx
            .send(Err(CommunicationError::Other(
                "response frame must contain a non-zero id".into(),
            )))
            .await
            .is_ok();
    }
    if let Some(id) = msg.id() {
        let pending = dispatcher.pending_requests.lock().await.remove(&id);
        if let Some(tx) = pending {
            let _ = tx.sender.send(Ok(msg));
            return true;
        }
        if consume_expired_request(dispatcher, id).await {
            return true;
        }
    }

    app_tx.send(Ok(msg)).await.is_ok()
}

pub(crate) async fn fail_pending_requests(dispatcher: &PipeDispatcher, error: CommunicationError) {
    let pending = std::mem::take(&mut *dispatcher.pending_requests.lock().await);
    for (_, pending) in pending {
        let _ = pending.sender.send(Err(error.clone()));
    }
}

const EXPIRED_REQUEST_TOMBSTONE_TTL: Duration = Duration::from_secs(60);
const MAX_EXPIRED_REQUEST_TOMBSTONES: usize = 1024;

pub(crate) async fn expire_pending_request(
    dispatcher: &PipeDispatcher,
    request_id: u32,
    token: &Arc<()>,
) {
    let mut pending = dispatcher.pending_requests.lock().await;
    if pending
        .get(&request_id)
        .is_some_and(|entry| Arc::ptr_eq(&entry.token, token))
    {
        pending.remove(&request_id);
        drop(pending);
        let mut expired = dispatcher.expired_requests.lock().await;
        let now = Instant::now();
        expired.retain(|_, expires_at| *expires_at > now);
        if expired.len() >= MAX_EXPIRED_REQUEST_TOMBSTONES
            && let Some(oldest) = expired
                .iter()
                .min_by_key(|(_, expires_at)| **expires_at)
                .map(|(id, _)| *id)
        {
            expired.remove(&oldest);
        }
        expired.insert(request_id, now + EXPIRED_REQUEST_TOMBSTONE_TTL);
    }
}

pub(crate) async fn is_expired_request(dispatcher: &PipeDispatcher, request_id: u32) -> bool {
    let mut expired = dispatcher.expired_requests.lock().await;
    let now = Instant::now();
    expired.retain(|_, expires_at| *expires_at > now);
    expired.contains_key(&request_id)
}

pub(crate) async fn remove_pending_request(
    dispatcher: &PipeDispatcher,
    request_id: u32,
    token: &Arc<()>,
) {
    let mut pending = dispatcher.pending_requests.lock().await;
    if pending
        .get(&request_id)
        .is_some_and(|entry| Arc::ptr_eq(&entry.token, token))
    {
        pending.remove(&request_id);
    }
}

async fn consume_expired_request(dispatcher: &PipeDispatcher, request_id: u32) -> bool {
    let mut expired = dispatcher.expired_requests.lock().await;
    let now = Instant::now();
    expired.retain(|_, expires_at| *expires_at > now);
    expired.remove(&request_id).is_some()
}

#[cfg(feature = "pipes")]
pub(crate) async fn run_dispatcher(
    receiver: Receiver,
    sender: Sender,
    app_tx: mpsc::Sender<Result<CommunicationValue, CommunicationError>>,
    pipe_req_tx: mpsc::Sender<PipeRequest>,
    dispatcher: Arc<PipeDispatcher>,
) {
    loop {
        match receiver.receive_event().await {
            Ok(mtp_native::TransportEvent::Message(msg)) => {
                if msg.is_type(CommunicationType::PipeRequest) {
                    let Some(pipe_id) = msg.id().filter(|id| *id != 0) else {
                        let error = CommunicationError::Other(
                            "PipeRequest frame must contain a non-zero id".into(),
                        );
                        if app_tx.send(Err(error)).await.is_err() {
                            break;
                        }
                        continue;
                    };
                    let description = msg.get_str(DataType::Description).unwrap_or("").to_string();
                    let req = PipeRequest {
                        pipe_id,
                        description,
                        sender: sender.clone(),
                        receiver: receiver.clone(),
                        dispatcher: dispatcher.clone(),
                    };
                    let _ = pipe_req_tx.send(req).await;
                    continue;
                }

                if msg.is_type(CommunicationType::PipeResponse) {
                    let Some(pipe_id) = msg.id().filter(|id| *id != 0) else {
                        let error = CommunicationError::Other(
                            "PipeResponse frame must contain a non-zero id".into(),
                        );
                        if app_tx.send(Err(error)).await.is_err() {
                            break;
                        }
                        continue;
                    };
                    let accepted = msg.get_bool(DataType::Accepted).unwrap_or(false);
                    let pending = dispatcher
                        .pending_creations
                        .lock()
                        .ok()
                        .and_then(|mut pending| pending.remove(&pipe_id));
                    if let Some(entry) = pending {
                        let _ = entry.sender.send(Ok(accepted));
                    } else {
                        let _ = consume_expired_creation(&dispatcher, pipe_id);
                    }
                    continue;
                }

                if !route_message(msg, &app_tx, &dispatcher).await {
                    break;
                }
            }
            Ok(mtp_native::TransportEvent::Pipe(reader)) => {
                let pipe_id = reader.pipe_id();
                let mut pending = dispatcher.pending_pipes.lock().await;
                if let Some(tx) = pending.remove(&pipe_id) {
                    let _ = tx.send(reader);
                }
            }
            Err(e) => {
                fail_pending_requests(&dispatcher, e.clone()).await;
                #[cfg(feature = "pipes")]
                fail_pending_creations(&dispatcher, &e);
                #[cfg(feature = "pipes")]
                fail_pending_pipes(&dispatcher).await;
                let _ = app_tx.send(Err(e)).await;
                break;
            }
        }
    }
}

#[cfg(not(feature = "pipes"))]
pub(crate) async fn run_dispatcher(
    receiver: Receiver,
    app_tx: mpsc::Sender<Result<CommunicationValue, CommunicationError>>,
    dispatcher: Arc<PipeDispatcher>,
) {
    loop {
        match receiver.receive().await {
            Ok(msg) => {
                if !route_message(msg, &app_tx, &dispatcher).await {
                    break;
                }
            }
            Err(e) => {
                fail_pending_requests(&dispatcher, e.clone()).await;
                #[cfg(feature = "pipes")]
                fail_pending_creations(&dispatcher, &e);
                #[cfg(feature = "pipes")]
                fail_pending_pipes(&dispatcher).await;
                let _ = app_tx.send(Err(e)).await;
                break;
            }
        }
    }
}
