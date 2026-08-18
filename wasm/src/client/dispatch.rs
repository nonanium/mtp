use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

use wasm_bindgen::prelude::*;

use crate::client::ConnectionState;
use crate::client_pipe::{self, PendingRequest};

pub(super) struct PingTimer {
    pub(super) id: i32,
    pub(super) closure: Closure<dyn FnMut()>,
}

pub(super) struct PendingPing {
    pub(super) generation: u32,
    pub(super) sent_at: f64,
}

pub(super) fn frame_property(frame: &JsValue, key: &str) -> Option<JsValue> {
    js_sys::Reflect::get(frame, &JsValue::from_str(key))
        .ok()
        .filter(|value| !value.is_null() && !value.is_undefined())
}

pub(super) fn frame_id(frame: &JsValue) -> Option<u32> {
    frame_property(frame, "id")
        .and_then(|value| value.as_f64())
        .filter(|value| {
            value.is_finite() && value.fract() == 0.0 && (0.0..=u32::MAX as f64).contains(value)
        })
        .and_then(|value| u32::try_from(value as u64).ok())
}

pub(super) fn frame_type(frame: &JsValue) -> Option<String> {
    frame_property(frame, "type").and_then(|value| value.as_string())
}

pub(super) fn route_incoming_frame(
    frame: &JsValue,
    generation: u32,
    on_message: &js_sys::Function,
    subscriptions: &Rc<RefCell<HashMap<u32, (String, js_sys::Function)>>>,
    pending_requests: &Rc<RefCell<HashMap<u32, PendingRequest>>>,
    expired_requests: &Rc<RefCell<HashMap<u32, f64>>>,
    pending_pings: &Rc<RefCell<HashMap<u32, PendingPing>>>,
    ping_ms: &Rc<Cell<Option<f64>>>,
) {
    let message_type = frame_type(frame);

    if message_type.as_deref() == Some("Pong")
        && let Some(ping_id) = frame_id(frame)
    {
        let sent_at = pending_pings
            .borrow()
            .get(&ping_id)
            .filter(|ping| ping.generation == generation)
            .map(|ping| ping.sent_at);
        if let Some(sent_at) = sent_at {
            pending_pings.borrow_mut().remove(&ping_id);
            ping_ms.set(Some(js_sys::Date::now() - sent_at));
            return;
        }
    }

    if let Some(request_id) = frame_id(frame) {
        let pending = {
            let mut requests = pending_requests.borrow_mut();
            if requests
                .get(&request_id)
                .is_some_and(|request| request.generation == generation)
            {
                requests.remove(&request_id)
            } else {
                None
            }
        };
        if let Some(pending) = pending {
            let type_matches = pending
                .response_type
                .as_ref()
                .zip(message_type.as_ref())
                .map(|(expected, actual)| expected == actual)
                .unwrap_or(true);
            if type_matches {
                let _ = pending.sender.send(Ok(frame.clone()));
            } else {
                let actual = message_type.clone().unwrap_or_else(|| "unknown".into());
                let _ = pending.sender.send(Err(crate::error::js_error(format!(
                    "unexpected response type: expected {}, got {}",
                    pending.response_type.unwrap_or_else(|| "unknown".into()),
                    actual
                ))));
            }
            return;
        }
        if client_pipe::consume_expired_request(expired_requests, request_id) {
            return;
        }
    }

    let _ = on_message.call1(&JsValue::NULL, frame);
    let Some(message_type) = message_type else {
        return;
    };
    let callbacks: Vec<js_sys::Function> = subscriptions
        .borrow()
        .iter()
        .filter(|(_, (t, _))| t == &message_type)
        .map(|(_, (_, cb))| cb.clone())
        .collect();
    for callback in callbacks {
        let _ = callback.call1(&JsValue::NULL, frame);
    }
}

pub(super) fn stop_ping_timer(ping_timer: &Rc<RefCell<Option<PingTimer>>>) {
    let Some(timer) = ping_timer.borrow_mut().take() else {
        return;
    };
    if let Ok(clear_interval) =
        js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("clearInterval"))
            .and_then(|value| value.dyn_into::<js_sys::Function>())
    {
        let _ = clear_interval.call1(&JsValue::NULL, &JsValue::from_f64(timer.id as f64));
    }
    drop(timer.closure);
}

pub(super) fn reject_pending_requests(
    pending_requests: &Rc<RefCell<HashMap<u32, PendingRequest>>>,
    message: &str,
) {
    let pending = std::mem::take(&mut *pending_requests.borrow_mut());
    for (_, pending) in pending {
        let _ = pending.sender.send(Err(crate::error::js_error(message)));
    }
}

pub(super) async fn wait_for_timeout(timeout_ms: u32) -> Result<(), JsValue> {
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
    wasm_bindgen_futures::JsFuture::from(promise).await?;
    Ok(())
}

pub(super) fn set_shared_state(
    state: &Rc<Cell<ConnectionState>>,
    pending_state_callbacks: &Rc<RefCell<VecDeque<ConnectionState>>>,
    state_callback: &JsValue,
    new_state: ConnectionState,
) {
    state.set(new_state);
    pending_state_callbacks.borrow_mut().push_back(new_state);

    let global = js_sys::global();
    let qmt = js_sys::Reflect::get(&global, &JsValue::from_str("queueMicrotask"))
        .and_then(|f| f.dyn_into::<js_sys::Function>());
    let scheduled = qmt
        .and_then(|qmt| qmt.call1(&global, state_callback))
        .is_ok();
    if !scheduled
        && js_sys::Reflect::get(&global, &JsValue::from_str("setTimeout"))
            .and_then(|f| f.dyn_into::<js_sys::Function>())
            .and_then(|set_timeout| {
                set_timeout.call2(&global, state_callback, &JsValue::from_f64(0.0))
            })
            .is_err()
    {
        pending_state_callbacks.borrow_mut().pop_back();
    }
}
