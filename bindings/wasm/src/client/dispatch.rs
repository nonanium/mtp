use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

use wasm_bindgen::prelude::*;

use crate::client::ConnectionState;
use crate::client_pipe::PendingRequest;
use mtp_common::{PingId, RequestId, RequestTracker, RouteResult};

pub(super) struct PingTimer {
    pub(super) id: i32,
    pub(super) closure: Closure<dyn FnMut()>,
}

pub(super) type PingTracker = mtp_common::PingTracker<f64>;

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
    pending_requests: &Rc<RefCell<RequestTracker<PendingRequest>>>,
    ping_tracker: &Rc<RefCell<PingTracker>>,
    ping_ms: &Rc<Cell<Option<f64>>>,
) {
    let message_type = frame_type(frame);

    if message_type.as_deref() == Some("Pong") {
        if let Some(ping_id) = frame_id(frame).and_then(PingId::new)
            && let Some(sent_at) = ping_tracker.borrow_mut().received(ping_id)
        {
            ping_ms.set(Some(js_sys::Date::now() - sent_at));
        }
        return;
    }

    let route = pending_requests.borrow_mut().route(
        frame_id(frame).and_then(RequestId::new),
        frame.clone(),
        |request| {
            request.generation == generation
                && request
                    .response_type
                    .as_ref()
                    .is_none_or(|expected| message_type.as_ref() == Some(expected))
        },
        js_sys::Date::now(),
    );
    match route {
        RouteResult::Response { frame, pending } => {
            let _ = pending.sender.send(Ok(frame));
            return;
        }
        RouteResult::Expired => return,
        RouteResult::Application(_) => {}
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
    pending_requests: &Rc<RefCell<RequestTracker<PendingRequest>>>,
    message: &str,
) {
    let pending = pending_requests
        .borrow_mut()
        .take_pending()
        .collect::<Vec<_>>();
    for pending in pending {
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

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::rc::Rc;

    use futures_channel::oneshot;
    use wasm_bindgen::JsCast;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_test::*;

    use super::{PingTracker, route_incoming_frame};
    use crate::client_pipe::PendingRequest;
    use mtp_common::{PingId, RequestId, RequestTracker};

    #[test]
    fn matching_pong_resets_consecutive_misses() {
        let mut tracker = PingTracker::default();
        tracker.sent(PingId::new(10).unwrap(), 1.0);
        assert_eq!(tracker.begin_round(), 1);

        tracker.sent(PingId::new(11).unwrap(), 2.0);
        assert_eq!(tracker.received(PingId::new(11).unwrap()), Some(2.0));

        tracker.sent(PingId::new(12).unwrap(), 3.0);
        assert_eq!(tracker.begin_round(), 1);
    }

    #[test]
    fn stale_pong_does_not_acknowledge_current_round() {
        let mut tracker = PingTracker::default();
        tracker.sent(PingId::new(10).unwrap(), 1.0);
        assert_eq!(tracker.begin_round(), 1);
        tracker.sent(PingId::new(11).unwrap(), 2.0);

        assert_eq!(tracker.received(PingId::new(10).unwrap()), None);
        assert_eq!(tracker.begin_round(), 2);
    }

    #[wasm_bindgen_test(async)]
    async fn same_id_unexpected_type_is_routed_without_consuming_request() {
        let callback_count = Rc::new(Cell::new(0));
        let count = callback_count.clone();
        let on_message = Closure::wrap(Box::new(move |_frame: JsValue| {
            count.set(count.get() + 1);
        }) as Box<dyn FnMut(JsValue)>);
        let subscriptions = Rc::new(RefCell::new(HashMap::new()));
        let pending_requests = Rc::new(RefCell::new(RequestTracker::default()));
        let ping_tracker = Rc::new(RefCell::new(PingTracker::default()));
        let ping_ms = Rc::new(Cell::new(None));
        let request_id = RequestId::new(42).unwrap();
        let (sender, receiver) = oneshot::channel();
        assert!(
            pending_requests
                .borrow_mut()
                .insert(
                    request_id,
                    PendingRequest {
                        generation: 1,
                        token: Rc::new(()),
                        response_type: Some("ExpectedResponse".into()),
                        sender,
                    },
                    0.0,
                )
                .is_ok()
        );

        let wrong = js_sys::Object::new();
        js_sys::Reflect::set(&wrong, &JsValue::from_str("id"), &JsValue::from_f64(42.0)).unwrap();
        js_sys::Reflect::set(
            &wrong,
            &JsValue::from_str("type"),
            &JsValue::from_str("Notification"),
        )
        .unwrap();
        route_incoming_frame(
            wrong.as_ref(),
            1,
            on_message.as_ref().unchecked_ref(),
            &subscriptions,
            &pending_requests,
            &ping_tracker,
            &ping_ms,
        );
        assert_eq!(callback_count.get(), 1);
        assert!(pending_requests.borrow().pending.contains_key(&request_id));

        let matching = js_sys::Object::new();
        js_sys::Reflect::set(
            &matching,
            &JsValue::from_str("id"),
            &JsValue::from_f64(42.0),
        )
        .unwrap();
        js_sys::Reflect::set(
            &matching,
            &JsValue::from_str("type"),
            &JsValue::from_str("ExpectedResponse"),
        )
        .unwrap();
        route_incoming_frame(
            matching.as_ref(),
            1,
            on_message.as_ref().unchecked_ref(),
            &subscriptions,
            &pending_requests,
            &ping_tracker,
            &ping_ms,
        );
        assert!(!pending_requests.borrow().pending.contains_key(&request_id));
        let delivered: JsValue = receiver.await.unwrap().unwrap();
        assert_eq!(delivered, JsValue::from(matching));
        assert_eq!(callback_count.get(), 1);
    }
}
