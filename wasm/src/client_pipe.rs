use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use futures_channel::oneshot;
use tracing::debug;
use wasm_bindgen::prelude::*;

use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue};

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
    pub(crate) sender: oneshot::Sender<Result<bool, JsValue>>,
}
pub(crate) type PendingPipeCreations = Rc<RefCell<HashMap<u32, PendingPipeCreation>>>;
type PipeResponseReceiver = oneshot::Receiver<Result<bool, JsValue>>;
type PipeResponseCell = Rc<RefCell<Option<PipeResponseReceiver>>>;

pub(crate) struct PendingPipe {
    pub(crate) generation: u32,
    pub(crate) sender: oneshot::Sender<Result<PipeReader, JsValue>>,
}

pub(crate) type PendingPipes = Rc<RefCell<HashMap<u32, PendingPipe>>>;

pub(crate) fn remove_pending_request(
    pending_requests: &Rc<RefCell<HashMap<u32, PendingRequest>>>,
    request_id: u32,
    token: &Rc<()>,
) {
    let mut pending = pending_requests.borrow_mut();
    if pending
        .get(&request_id)
        .is_some_and(|entry| Rc::ptr_eq(&entry.token, token))
    {
        pending.remove(&request_id);
    }
}

const EXPIRED_REQUEST_TOMBSTONE_TTL_MS: f64 = 60_000.0;
const MAX_EXPIRED_REQUEST_TOMBSTONES: usize = 1024;

pub(crate) fn expire_pending_request(
    pending_requests: &Rc<RefCell<HashMap<u32, PendingRequest>>>,
    expired_requests: &Rc<RefCell<HashMap<u32, f64>>>,
    request_id: u32,
    token: &Rc<()>,
) {
    let mut pending = pending_requests.borrow_mut();
    if pending
        .get(&request_id)
        .is_some_and(|entry| Rc::ptr_eq(&entry.token, token))
    {
        pending.remove(&request_id);
        drop(pending);
        let now = js_sys::Date::now();
        let mut expired = expired_requests.borrow_mut();
        expired.retain(|_, expires_at| *expires_at > now);
        if expired.len() >= MAX_EXPIRED_REQUEST_TOMBSTONES
            && let Some(oldest) = expired
                .iter()
                .min_by(|(_, left), (_, right)| left.total_cmp(right))
                .map(|(id, _)| *id)
        {
            expired.remove(&oldest);
        }
        expired.insert(request_id, now + EXPIRED_REQUEST_TOMBSTONE_TTL_MS);
    }
}

pub(crate) fn consume_expired_request(
    expired_requests: &Rc<RefCell<HashMap<u32, f64>>>,
    request_id: u32,
) -> bool {
    let now = js_sys::Date::now();
    let mut expired = expired_requests.borrow_mut();
    expired.retain(|_, expires_at| *expires_at > now);
    expired.remove(&request_id).is_some()
}

pub(crate) fn is_expired_request(
    expired_requests: &Rc<RefCell<HashMap<u32, f64>>>,
    request_id: u32,
) -> bool {
    let now = js_sys::Date::now();
    let mut expired = expired_requests.borrow_mut();
    expired.retain(|_, expires_at| *expires_at > now);
    expired.contains_key(&request_id)
}

#[wasm_bindgen(typescript_custom_section)]
const PIPE_HANDLE_TS: &str = r#"
export interface WasmPipeHandle {
  wait(): Promise<PipeWriter | null>;
  readonly pipeId: number;
  readonly description: string;
}
"#;

#[wasm_bindgen]
pub struct WasmPipeHandle {
    pipe_id: u32,
    description: String,
    transport: WasmTransport,
    response_rx: PipeResponseCell,
}

#[wasm_bindgen]
impl WasmPipeHandle {
    pub async fn wait(&self) -> Result<JsValue, JsValue> {
        let rx = self
            .response_rx
            .borrow_mut()
            .take()
            .ok_or_else(|| js_error("handle already consumed"))?;

        let accepted = rx
            .await
            .map_err(|_| js_error("pipe handle channel closed"))?;

        match accepted {
            Ok(true) => {
                let writer = self
                    .transport
                    .open_pipe(self.pipe_id, &self.description)
                    .await?;
                Ok(JsValue::from(writer))
            }
            Ok(false) => Ok(JsValue::NULL),
            Err(e) => Err(e),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn pipe_id(&self) -> u32 {
        self.pipe_id
    }

    #[wasm_bindgen(getter)]
    pub fn description(&self) -> String {
        self.description.clone()
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
    generation: u32,
    current_generation: &Rc<std::cell::Cell<u32>>,
) -> Result<WasmPipeHandle, JsValue> {
    let (tx, rx) = oneshot::channel();
    let mut pipe_id = pipe_id;
    for _ in 0..128 {
        let occupied = pipe_id == 0 || pending_pipe_creations.borrow().contains_key(&pipe_id);
        if !occupied {
            break;
        }
        pipe_id = random_pipe_id()?;
    }
    if pipe_id == 0 || pending_pipe_creations.borrow().contains_key(&pipe_id) {
        return Err(js_error("could not allocate a unique pipe id"));
    }
    let type_map = transport.type_map();
    let request = CommunicationValue::new_with_type_map(CommunicationType::PipeRequest, &type_map)
        .with_id(pipe_id)
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
            sender: tx,
        },
    );
    debug!(
        target = "mtp.wasm",
        pipe_id,
        description,
        frame_len = request_bytes.len(),
        "sending pipe request"
    );
    if let Err(error) = transport.send_frame(&request_bytes).await {
        let mut pending = pending_pipe_creations.borrow_mut();
        if pending
            .get(&pipe_id)
            .is_some_and(|entry| entry.generation == generation)
        {
            pending.remove(&pipe_id);
        }
        return Err(error);
    }
    if current_generation.get() != generation {
        let mut pending = pending_pipe_creations.borrow_mut();
        if pending
            .get(&pipe_id)
            .is_some_and(|entry| entry.generation == generation)
        {
            pending.remove(&pipe_id);
        }
        return Err(js_error("connection attempt superseded"));
    }

    Ok(WasmPipeHandle {
        pipe_id,
        description: description.to_string(),
        transport: transport.clone(),
        response_rx: Rc::new(RefCell::new(Some(rx))),
    })
}

pub(crate) async fn wasm_accept_pipe(
    transport: &WasmTransport,
    pipe_id: u32,
    pending_pipes: &PendingPipes,
    generation: u32,
    current_generation: &Rc<std::cell::Cell<u32>>,
) -> Result<PipeReader, JsValue> {
    if pipe_id == 0 {
        return Err(js_error("pipe id must be non-zero"));
    }
    if current_generation.get() != generation {
        return Err(js_error("connection attempt superseded"));
    }

    let type_map = transport.type_map();
    let resp = CommunicationValue::new_with_type_map(CommunicationType::PipeResponse, &type_map)
        .with_id(pipe_id)
        .add_typed_default(DataType::Accepted, DataValue::BoolTrue);
    let resp_bytes = resp
        .to_bytes()
        .map_err(|e| js_error(format!("encode failed: {}", e)))?;

    let (tx, rx) = oneshot::channel();
    {
        let mut pending = pending_pipes.borrow_mut();
        if pending.contains_key(&pipe_id) {
            return Err(js_error(format!("pipe {pipe_id} is already pending")));
        }
        pending.insert(
            pipe_id,
            PendingPipe {
                generation,
                sender: tx,
            },
        );
    }

    debug!(
        target = "mtp.wasm",
        pipe_id,
        accepted = true,
        frame_len = resp_bytes.len(),
        "sending pipe response"
    );
    if let Err(error) = transport.send_frame(&resp_bytes).await {
        let mut pending = pending_pipes.borrow_mut();
        if pending
            .get(&pipe_id)
            .is_some_and(|entry| entry.generation == generation)
        {
            pending.remove(&pipe_id);
        }
        return Err(error);
    }
    if current_generation.get() != generation {
        let mut pending = pending_pipes.borrow_mut();
        if pending
            .get(&pipe_id)
            .is_some_and(|entry| entry.generation == generation)
        {
            pending.remove(&pipe_id);
        }
        return Err(js_error("connection attempt superseded"));
    }

    rx.await
        .map_err(|_| js_error("pipe closed before stream arrived"))?
}

pub(crate) async fn wasm_deny_pipe(transport: &WasmTransport, pipe_id: u32) -> Result<(), JsValue> {
    if pipe_id == 0 {
        return Err(js_error("pipe id must be non-zero"));
    }
    let type_map = transport.type_map();
    let resp = CommunicationValue::new_with_type_map(CommunicationType::PipeResponse, &type_map)
        .with_id(pipe_id)
        .add_typed_default(DataType::Accepted, DataValue::BoolFalse);
    let resp_bytes = resp
        .to_bytes()
        .map_err(|e| js_error(format!("encode failed: {}", e)))?;
    transport.send_frame(&resp_bytes).await
}
