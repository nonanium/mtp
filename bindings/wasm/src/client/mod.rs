// WASM client facade. Lifecycle, authentication, receive dispatch, and pipes
// live in private child modules below.
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::rc::Rc;

use futures_channel::oneshot;
use futures_util::{FutureExt, pin_mut, select};
use wasm_bindgen::prelude::*;

use mtp_codec::{CommunicationValue, DecodeLimits, EncodeLimits};

use crate::client_pipe::{self, PendingRequest};
use crate::error::js_error;
use crate::transport::WasmTransport;
use mtp_common::{RequestId, RequestTracker};

mod authentication;
mod connection;
mod dispatch;
mod pipes;
mod receive;
use dispatch::{PingTimer, PingTracker, wait_for_timeout};

const DEFAULT_REQUEST_TIMEOUT_MS: u32 = 30_000;
const MAX_SAFE_JS_INTEGER: f64 = 9_007_199_254_740_991.0;

fn decode_limit(value: &JsValue, key: &str, default: usize) -> Result<usize, JsValue> {
    if value.is_null() || value.is_undefined() {
        return Ok(default);
    }
    let value = js_sys::Reflect::get(value, &JsValue::from_str(key))?;
    if value.is_null() || value.is_undefined() {
        return Ok(default);
    }
    let Some(number) = value.as_f64() else {
        return Err(js_error(format!("{key} must be a number")));
    };
    if !number.is_finite() || number.fract() != 0.0 || number < 0.0 || number > MAX_SAFE_JS_INTEGER
    {
        return Err(js_error(format!("{key} must be a non-negative integer")));
    }
    usize::try_from(number as u64).map_err(|_| js_error(format!("{key} is out of range")))
}

pub(crate) fn encode_limits_from_js(value: &JsValue) -> Result<EncodeLimits, JsValue> {
    let defaults = EncodeLimits::default();
    Ok(EncodeLimits {
        max_depth: decode_limit(value, "maxDepth", defaults.max_depth)?,
        max_values: decode_limit(value, "maxValues", defaults.max_values)?,
        max_output_size: decode_limit(value, "maxOutputSize", defaults.max_output_size)?,
    })
}

pub(crate) fn decode_limits_from_js(value: &JsValue) -> Result<DecodeLimits, JsValue> {
    let defaults = DecodeLimits::default();
    Ok(DecodeLimits {
        max_depth: decode_limit(value, "maxDepth", defaults.max_depth)?,
        max_values: decode_limit(value, "maxValues", defaults.max_values)?,
        max_blob_size: decode_limit(value, "maxBlobSize", defaults.max_blob_size)?,
        max_recipients: decode_limit(value, "maxRecipients", defaults.max_recipients)?,
        max_allocated_bytes: decode_limit(
            value,
            "maxAllocatedBytes",
            defaults.max_allocated_bytes,
        )?,
    })
}

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected = 0,
    Connecting = 1,
    Connected = 2,
    Failed = 3,
}

#[wasm_bindgen]
pub struct WasmClient {
    transport: Rc<RefCell<Option<WasmTransport>>>,
    attempt_transport: Rc<RefCell<Option<WasmTransport>>>,
    connection_generation: Rc<Cell<u32>>,
    state: Rc<Cell<ConnectionState>>,
    pending_state_callbacks: Rc<RefCell<VecDeque<ConnectionState>>>,
    state_callback: Closure<dyn FnMut()>,
    pub(crate) on_message: js_sys::Function,
    pub(crate) on_error: js_sys::Function,
    subscriptions: Rc<RefCell<HashMap<u32, (String, js_sys::Function)>>>,
    next_subscription_id: Rc<Cell<u32>>,
    pending_requests: Rc<RefCell<RequestTracker<PendingRequest>>>,
    ping_timer: Rc<RefCell<Option<PingTimer>>>,
    ping_tracker: Rc<RefCell<PingTracker>>,
    ping_ms: Rc<Cell<Option<f64>>>,
    pending_pipe_creations: client_pipe::PendingPipeCreations,
    expired_pipe_creations: Rc<RefCell<HashMap<mtp_common::PipeId, f64>>>,
    pending_pipes: client_pipe::PendingPipes,
    connection_client_id: Rc<Cell<u64>>,
    on_pipe_request: Rc<RefCell<Option<js_sys::Function>>>,
    receive_decode_limits: Rc<RefCell<Option<DecodeLimits>>>,
}

#[wasm_bindgen]
#[allow(deprecated)]
impl WasmClient {
    #[wasm_bindgen(constructor)]
    pub fn new(
        on_state_change: Option<js_sys::Function>,
        on_message: Option<js_sys::Function>,
        on_error: Option<js_sys::Function>,
    ) -> Self {
        let noop = || js_sys::Function::new_no_args("");
        let on_state_change = on_state_change.unwrap_or_else(noop);
        let pending_state_callbacks = Rc::new(RefCell::new(VecDeque::new()));
        let callback_queue = pending_state_callbacks.clone();
        let callback = on_state_change.clone();
        let state_callback = Closure::wrap(Box::new(move || {
            let state = callback_queue.borrow_mut().pop_front();
            if let Some(state) = state {
                let _ = callback.call1(&JsValue::NULL, &JsValue::from(state as u8));
            }
        }) as Box<dyn FnMut()>);
        Self {
            transport: Rc::new(RefCell::new(None)),
            attempt_transport: Rc::new(RefCell::new(None)),
            connection_generation: Rc::new(Cell::new(0)),
            state: Rc::new(Cell::new(ConnectionState::Disconnected)),
            pending_state_callbacks,
            state_callback,
            on_message: on_message.unwrap_or_else(noop),
            on_error: on_error.unwrap_or_else(noop),
            subscriptions: Rc::new(RefCell::new(HashMap::new())),
            next_subscription_id: Rc::new(Cell::new(1)),
            pending_requests: Rc::new(RefCell::new(RequestTracker::default())),
            ping_timer: Rc::new(RefCell::new(None)),
            ping_tracker: Rc::new(RefCell::new(PingTracker::default())),
            ping_ms: Rc::new(Cell::new(None)),
            pending_pipe_creations: Rc::new(RefCell::new(HashMap::new())),
            expired_pipe_creations: Rc::new(RefCell::new(HashMap::new())),
            pending_pipes: Rc::new(RefCell::new(HashMap::new())),
            connection_client_id: Rc::new(Cell::new(0)),
            on_pipe_request: Rc::new(RefCell::new(None)),
            receive_decode_limits: Rc::new(RefCell::new(None)),
        }
    }
    pub fn is_supported() -> bool {
        js_sys::Reflect::has(&js_sys::global(), &JsValue::from_str("WebTransport")).unwrap_or(false)
    }

    #[wasm_bindgen(getter)]
    pub fn state(&self) -> u8 {
        self.state.get() as u8
    }

    #[wasm_bindgen(getter)]
    pub fn ping_ms(&self) -> Option<f64> {
        self.ping_ms.get()
    }

    #[wasm_bindgen(getter)]
    pub fn client_id(&self) -> u64 {
        self.connection_client_id.get()
    }

    /// Apply one decoder policy to frames received by this raw WASM client.
    /// The high-level SDK calls this before authentication so handshake,
    /// transport, and protected opening share the same policy input.
    #[wasm_bindgen]
    pub fn set_receive_limits(&self, limits: JsValue) -> Result<(), JsValue> {
        let parsed = if limits.is_null() || limits.is_undefined() {
            None
        } else {
            Some(decode_limits_from_js(&limits)?)
        };
        *self.receive_decode_limits.borrow_mut() = parsed;
        Ok(())
    }

    pub(super) fn receive_decode_limits(&self) -> Option<DecodeLimits> {
        *self.receive_decode_limits.borrow()
    }

    #[wasm_bindgen]
    #[deprecated(
        note = "use the SDK connection methods; this raw method remains for compatibility"
    )]
    pub async fn send(&self, frame: Vec<u8>) -> Result<(), JsValue> {
        if self.state.get() != ConnectionState::Connected {
            return Err(js_error("not connected"));
        }
        let transport = self.transport.borrow().clone();
        match transport {
            Some(t) => t.send_frame(&frame).await,
            None => Err(js_error("not connected")),
        }
    }

    #[wasm_bindgen]
    pub async fn request(
        &self,
        frame: Vec<u8>,
        response_type: Option<String>,
        timeout_ms: Option<u32>,
    ) -> Result<JsValue, JsValue> {
        if self.state.get() != ConnectionState::Connected {
            return Err(js_error("not connected"));
        }
        let generation = self.connection_generation.get();
        let Some(transport) = self.transport.borrow().clone() else {
            return Err(js_error("not connected"));
        };
        let request = CommunicationValue::try_from_bytes_with_type_map_and_limits(
            &frame,
            &transport.type_map(),
            transport.decode_limits(),
        )
        .map_err(|e| js_error(format!("parse request: {}", e)))?;
        let request_id = request
            .id()
            .and_then(RequestId::new)
            .ok_or_else(|| js_error("request frame must have a non-zero id"))?;
        if client_pipe::is_expired_request(&self.pending_requests, request_id) {
            return Err(js_error(format!(
                "request id {} recently timed out; use a new request id",
                request_id.get()
            )));
        }

        let (sender, receiver) = oneshot::channel();
        let token = Rc::new(());
        {
            let mut pending = self.pending_requests.borrow_mut();
            if pending.pending.contains_key(&request_id) {
                return Err(js_error(format!(
                    "request id {} is already pending",
                    request_id.get()
                )));
            }
            pending
                .insert(
                    request_id,
                    PendingRequest {
                        generation,
                        token: token.clone(),
                        response_type,
                        sender,
                    },
                    js_sys::Date::now(),
                )
                .map_err(|_| js_error("request id is already pending"))?;
        }

        let timeout_ms = timeout_ms.unwrap_or(DEFAULT_REQUEST_TIMEOUT_MS);
        let response = async {
            transport.send_frame(&frame).await?;
            match receiver.await {
                Ok(result) => result,
                Err(_) => Err(js_error("request cancelled")),
            }
        }
        .fuse();
        let timeout = wait_for_timeout(timeout_ms).fuse();
        pin_mut!(response, timeout);
        select! {
            result = response => {
                if result.is_err() {
                    client_pipe::remove_pending_request(&self.pending_requests, request_id, &token);
                }
                result
            },
            result = timeout => {
                client_pipe::expire_pending_request(&self.pending_requests, request_id, &token);
                result?;
                Err(js_error(format!(
                    "request {} timed out after {timeout_ms}ms", request_id.get()
                )))
            },
        }
    }

    #[wasm_bindgen]
    pub fn subscribe(&self, message_type: String, callback: js_sys::Function) -> u32 {
        let id = self.next_subscription_id.get();
        self.next_subscription_id.set(id.wrapping_add(1).max(1));
        self.subscriptions
            .borrow_mut()
            .insert(id, (message_type, callback));
        id
    }

    #[wasm_bindgen]
    pub fn unsubscribe(&self, id: u32) -> bool {
        self.subscriptions.borrow_mut().remove(&id).is_some()
    }
}
