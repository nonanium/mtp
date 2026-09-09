use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use futures_channel::oneshot;
use futures_util::{FutureExt, pin_mut, select};
use tracing::debug;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp_common::{PipeId, RequestId, RequestTracker};

use crate::error::js_error;
use crate::pipe::PipeReader;
use crate::transport::WasmTransport;

pub(crate) struct PendingRequest {
    pub(crate) generation: u32,
    pub(crate) token: Rc<()>,
    pub(crate) response_type: Option<String>,
    pub(crate) sender: oneshot::Sender<Result<JsValue, JsValue>>,
}

pub(crate) struct PendingPipeCreation {
    pub(crate) generation: u32,
    pub(crate) token: Rc<()>,
    pub(crate) sender: oneshot::Sender<Result<bool, JsValue>>,
}
pub(crate) type PendingPipeCreations = Rc<RefCell<HashMap<PipeId, PendingPipeCreation>>>;
type PipeResponseReceiver = oneshot::Receiver<Result<bool, JsValue>>;
type PipeResponseCell = Rc<RefCell<Option<PipeResponseReceiver>>>;

const DEFAULT_PIPE_DECISION_TIMEOUT_MS: u32 = 30_000;
const DEFAULT_PIPE_STREAM_OPEN_TIMEOUT_MS: u32 = 30_000;
const EXPIRED_PIPE_CREATION_TOMBSTONE_TTL_MS: f64 = 60_000.0;
const MAX_EXPIRED_PIPE_CREATION_TOMBSTONES: usize = 1024;

pub(crate) struct PendingPipe {
    pub(crate) generation: u32,
    pub(crate) sender: oneshot::Sender<Result<PipeReader, JsValue>>,
}

pub(crate) type PendingPipes = Rc<RefCell<HashMap<PipeId, PendingPipe>>>;

pub(crate) fn remove_pending_request(
    pending_requests: &Rc<RefCell<RequestTracker<PendingRequest>>>,
    request_id: RequestId,
    token: &Rc<()>,
) {
    pending_requests
        .borrow_mut()
        .remove_if(request_id, |entry| Rc::ptr_eq(&entry.token, token));
}

pub(crate) fn expire_pending_request(
    pending_requests: &Rc<RefCell<RequestTracker<PendingRequest>>>,
    request_id: RequestId,
    token: &Rc<()>,
) {
    pending_requests.borrow_mut().expire_if(
        request_id,
        |entry| Rc::ptr_eq(&entry.token, token),
        js_sys::Date::now(),
    );
}

pub(crate) fn is_expired_request(
    pending_requests: &Rc<RefCell<RequestTracker<PendingRequest>>>,
    request_id: RequestId,
) -> bool {
    pending_requests
        .borrow_mut()
        .is_expired(request_id, js_sys::Date::now())
}

#[wasm_bindgen]
pub struct WasmPipeHandle {
    pipe_id: PipeId,
    description: String,
    transport: WasmTransport,
    response_rx: PipeResponseCell,
    pending: PendingPipeCreations,
    expired: Rc<RefCell<HashMap<PipeId, f64>>>,
    generation: u32,
    token: Rc<()>,
}

#[wasm_bindgen]
impl WasmPipeHandle {
    pub async fn wait(&self) -> Result<JsValue, JsValue> {
        let rx = self
            .response_rx
            .borrow_mut()
            .take()
            .ok_or_else(|| js_error("handle already consumed"))?;

        let response = rx.fuse();
        let timeout = wait_for_timeout(DEFAULT_PIPE_DECISION_TIMEOUT_MS).fuse();
        pin_mut!(response, timeout);
        let accepted = select! {
            result = response => match result {
                Ok(result) => result,
                Err(_) => {
                    expire_pending_pipe_creation(
                        &self.pending,
                        &self.expired,
                        self.pipe_id,
                        self.generation,
                        &self.token,
                    );
                    return Err(js_error("pipe handle channel closed"));
                }
            },
            result = timeout => {
                result?;
                expire_pending_pipe_creation(
                    &self.pending,
                    &self.expired,
                    self.pipe_id,
                    self.generation,
                    &self.token,
                );
                return Err(js_error(format!(
                    "pipe decision timed out after {DEFAULT_PIPE_DECISION_TIMEOUT_MS}ms"
                )));
            },
        };

        match accepted {
            Ok(true) => {
                let writer = self
                    .transport
                    .open_pipe(self.pipe_id.get(), &self.description)
                    .await?;
                Ok(JsValue::from(writer))
            }
            Ok(false) => Ok(JsValue::NULL),
            Err(e) => Err(e),
        }
    }

    /// Withdraw this request before opening its byte stream.
    pub async fn cancel(&self) -> Result<(), JsValue> {
        expire_pending_pipe_creation(
            &self.pending,
            &self.expired,
            self.pipe_id,
            self.generation,
            &self.token,
        );
        let type_map = self.transport.type_map();
        let abort = CommunicationValue::new_with_type_map(CommunicationType::PipeAbort, &type_map)
            .with_id(self.pipe_id.get());
        let bytes = abort
            .to_bytes()
            .map_err(|error| js_error(format!("encode failed: {error}")))?;
        self.transport.send_frame(&bytes).await
    }

    #[wasm_bindgen(getter)]
    pub fn pipe_id(&self) -> u32 {
        self.pipe_id.get()
    }

    #[wasm_bindgen(getter)]
    pub fn description(&self) -> String {
        self.description.clone()
    }
}

impl Drop for WasmPipeHandle {
    fn drop(&mut self) {
        expire_pending_pipe_creation(
            &self.pending,
            &self.expired,
            self.pipe_id,
            self.generation,
            &self.token,
        );
    }
}

pub(crate) fn random_pipe_id() -> Result<u32, JsValue> {
    let mut bytes = [0u8; 4];
    getrandom_v04::fill(&mut bytes).map_err(|_| js_error("rng failed"))?;
    Ok(u32::from_be_bytes(bytes))
}

pub(crate) fn reject_pending_pipe_creations(pending: &PendingPipeCreations, message: &str) {
    let pending = std::mem::take(&mut *pending.borrow_mut());
    for (_, entry) in pending {
        let _ = entry.sender.send(Err(js_error(message)));
    }
}

async fn wait_for_timeout(timeout_ms: u32) -> Result<(), JsValue> {
    let promise = js_sys::Promise::new(&mut |resolve, reject| {
        let result = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("setTimeout"))
            .and_then(|value| value.dyn_into::<js_sys::Function>())
            .and_then(|set_timeout| {
                set_timeout.call2(
                    &JsValue::NULL,
                    &resolve,
                    &JsValue::from_f64(timeout_ms as f64),
                )
            });
        if let Err(error) = result {
            let _ = reject.call1(&JsValue::NULL, &error);
        }
    });
    JsFuture::from(promise).await?;
    Ok(())
}

fn expire_pending_pipe_creation(
    pending: &PendingPipeCreations,
    expired: &Rc<RefCell<HashMap<PipeId, f64>>>,
    pipe_id: PipeId,
    generation: u32,
    token: &Rc<()>,
) {
    let removed = {
        let mut pending = pending.borrow_mut();
        if pending
            .get(&pipe_id)
            .is_some_and(|entry| entry.generation == generation && Rc::ptr_eq(&entry.token, token))
        {
            pending.remove(&pipe_id);
            true
        } else {
            false
        }
    };
    if !removed {
        return;
    }
    let now = js_sys::Date::now();
    let mut expired = expired.borrow_mut();
    expired.retain(|_, expires_at| *expires_at > now);
    if expired.len() >= MAX_EXPIRED_PIPE_CREATION_TOMBSTONES
        && let Some(oldest) = expired
            .iter()
            .min_by(|(_, left), (_, right)| left.total_cmp(right))
            .map(|(id, _)| *id)
    {
        expired.remove(&oldest);
    }
    expired.insert(pipe_id, now + EXPIRED_PIPE_CREATION_TOMBSTONE_TTL_MS);
}

struct PendingPipeCreationGuard {
    pending: PendingPipeCreations,
    expired: Rc<RefCell<HashMap<PipeId, f64>>>,
    pipe_id: PipeId,
    generation: u32,
    token: Rc<()>,
    armed: bool,
}

impl PendingPipeCreationGuard {
    fn new(
        pending: PendingPipeCreations,
        expired: Rc<RefCell<HashMap<PipeId, f64>>>,
        pipe_id: PipeId,
        generation: u32,
        token: Rc<()>,
    ) -> Self {
        Self {
            pending,
            expired,
            pipe_id,
            generation,
            token,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingPipeCreationGuard {
    fn drop(&mut self) {
        if self.armed {
            expire_pending_pipe_creation(
                &self.pending,
                &self.expired,
                self.pipe_id,
                self.generation,
                &self.token,
            );
        }
    }
}

struct PendingPipeGuard {
    pending: PendingPipes,
    pipe_id: PipeId,
    generation: u32,
}

impl PendingPipeGuard {
    fn new(pending: PendingPipes, pipe_id: PipeId, generation: u32) -> Self {
        Self {
            pending,
            pipe_id,
            generation,
        }
    }
}

impl Drop for PendingPipeGuard {
    fn drop(&mut self) {
        remove_pending_pipe(&self.pending, self.pipe_id, self.generation);
    }
}

pub(crate) fn consume_expired_pipe_creation(
    expired: &Rc<RefCell<HashMap<PipeId, f64>>>,
    pipe_id: PipeId,
) -> bool {
    let now = js_sys::Date::now();
    let mut expired = expired.borrow_mut();
    expired.retain(|_, expires_at| *expires_at > now);
    expired.remove(&pipe_id).is_some()
}

fn is_expired_pipe_creation(expired: &Rc<RefCell<HashMap<PipeId, f64>>>, pipe_id: PipeId) -> bool {
    let now = js_sys::Date::now();
    let mut expired = expired.borrow_mut();
    expired.retain(|_, expires_at| *expires_at > now);
    expired.contains_key(&pipe_id)
}

pub(crate) fn reject_pending_pipes(pending: &PendingPipes, message: &str) {
    let pending = std::mem::take(&mut *pending.borrow_mut());
    for (_, entry) in pending {
        let _ = entry.sender.send(Err(js_error(message)));
    }
}

pub(crate) async fn wasm_create_pipe(
    transport: &WasmTransport,
    description: &str,
    pipe_id: u32,
    pending_pipe_creations: &PendingPipeCreations,
    expired_pipe_creations: &Rc<RefCell<HashMap<PipeId, f64>>>,
    generation: u32,
    current_generation: &Rc<std::cell::Cell<u32>>,
) -> Result<WasmPipeHandle, JsValue> {
    let (tx, rx) = oneshot::channel();
    let token = Rc::new(());
    let mut pipe_id = PipeId::new(pipe_id).ok_or_else(|| js_error("pipe id must be non-zero"))?;
    for _ in 0..128 {
        let occupied = pending_pipe_creations.borrow().contains_key(&pipe_id)
            || is_expired_pipe_creation(expired_pipe_creations, pipe_id);
        if !occupied {
            break;
        }
        pipe_id =
            PipeId::new(random_pipe_id()?).ok_or_else(|| js_error("generated zero pipe id"))?;
    }
    if pending_pipe_creations.borrow().contains_key(&pipe_id)
        || is_expired_pipe_creation(expired_pipe_creations, pipe_id)
    {
        return Err(js_error("could not allocate a unique pipe id"));
    }
    let type_map = transport.type_map();
    let request = CommunicationValue::new_with_type_map(CommunicationType::PipeRequest, &type_map)
        .with_id(pipe_id.get())
        .add_typed_default(
            DataType::Description,
            DataValue::Str(description.to_string()),
        );
    let request_bytes = request
        .to_bytes()
        .map_err(|e| js_error(format!("encode failed: {}", e)))?;
    pending_pipe_creations.borrow_mut().insert(
        pipe_id,
        PendingPipeCreation {
            generation,
            token: token.clone(),
            sender: tx,
        },
    );
    let mut creation_guard = PendingPipeCreationGuard::new(
        pending_pipe_creations.clone(),
        expired_pipe_creations.clone(),
        pipe_id,
        generation,
        token.clone(),
    );
    debug!(
        target = "mtp.wasm",
        ?pipe_id,
        description,
        frame_len = request_bytes.len(),
        "sending pipe request"
    );
    if let Err(error) = transport.send_frame(&request_bytes).await {
        return Err(error);
    }
    if current_generation.get() != generation {
        return Err(js_error("connection attempt superseded"));
    }

    creation_guard.disarm();
    Ok(WasmPipeHandle {
        pipe_id,
        description: description.to_string(),
        transport: transport.clone(),
        response_rx: Rc::new(RefCell::new(Some(rx))),
        pending: pending_pipe_creations.clone(),
        expired: expired_pipe_creations.clone(),
        generation,
        token,
    })
}

pub(crate) async fn wasm_accept_pipe(
    transport: &WasmTransport,
    pipe_id: u32,
    pending_pipes: &PendingPipes,
    generation: u32,
    current_generation: &Rc<std::cell::Cell<u32>>,
) -> Result<PipeReader, JsValue> {
    let pipe_id = PipeId::new(pipe_id).ok_or_else(|| js_error("pipe id must be non-zero"))?;
    if current_generation.get() != generation {
        return Err(js_error("connection attempt superseded"));
    }

    let type_map = transport.type_map();
    let resp = CommunicationValue::new_with_type_map(CommunicationType::PipeResponse, &type_map)
        .with_id(pipe_id.get())
        .add_typed_default(DataType::Accepted, DataValue::BoolTrue);
    let resp_bytes = resp
        .to_bytes()
        .map_err(|e| js_error(format!("encode failed: {}", e)))?;

    let (tx, rx) = oneshot::channel();
    {
        let mut pending = pending_pipes.borrow_mut();
        if pending.contains_key(&pipe_id) {
            return Err(js_error(format!(
                "pipe {} is already pending",
                pipe_id.get()
            )));
        }
        pending.insert(
            pipe_id,
            PendingPipe {
                generation,
                sender: tx,
            },
        );
    }
    let _acceptance_guard = PendingPipeGuard::new(pending_pipes.clone(), pipe_id, generation);

    debug!(
        target = "mtp.wasm",
        ?pipe_id,
        accepted = true,
        frame_len = resp_bytes.len(),
        "sending pipe response"
    );
    if let Err(error) = transport.send_frame(&resp_bytes).await {
        return Err(error);
    }
    if current_generation.get() != generation {
        return Err(js_error("connection attempt superseded"));
    }

    let response = rx.fuse();
    let timeout = wait_for_timeout(DEFAULT_PIPE_STREAM_OPEN_TIMEOUT_MS).fuse();
    pin_mut!(response, timeout);
    let result = select! {
        result = response => match result {
            Ok(result) => result,
            Err(_) => {
                remove_pending_pipe(pending_pipes, pipe_id, generation);
                return Err(js_error("pipe closed before stream arrived"));
            }
        },
        result = timeout => {
            result?;
            remove_pending_pipe(pending_pipes, pipe_id, generation);
            return Err(js_error(format!(
                "pipe stream opening timed out after {DEFAULT_PIPE_STREAM_OPEN_TIMEOUT_MS}ms"
            )));
        },
    };
    result
}

fn remove_pending_pipe(pending_pipes: &PendingPipes, pipe_id: PipeId, generation: u32) {
    let mut pending = pending_pipes.borrow_mut();
    if pending
        .get(&pipe_id)
        .is_some_and(|entry| entry.generation == generation)
    {
        pending.remove(&pipe_id);
    }
}

pub(crate) async fn wasm_deny_pipe(transport: &WasmTransport, pipe_id: u32) -> Result<(), JsValue> {
    let pipe_id = PipeId::new(pipe_id).ok_or_else(|| js_error("pipe id must be non-zero"))?;
    let type_map = transport.type_map();
    let resp = CommunicationValue::new_with_type_map(CommunicationType::PipeResponse, &type_map)
        .with_id(pipe_id.get())
        .add_typed_default(DataType::Accepted, DataValue::BoolFalse);
    let resp_bytes = resp
        .to_bytes()
        .map_err(|e| js_error(format!("encode failed: {}", e)))?;
    transport.send_frame(&resp_bytes).await
}
