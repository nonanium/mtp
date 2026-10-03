use wasm_bindgen::prelude::*;

use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue};

use crate::client::{ConnectionState, WasmClient};
use crate::client_pipe;
use crate::error::js_error;
use crate::transport::WasmTransport;
use mtp_common::PingId;

use super::MAX_SAFE_JS_INTEGER;
use super::dispatch::{
    PingTimer, reject_pending_requests, route_incoming_frame, set_shared_state, stop_ping_timer,
};

const DEFAULT_MAX_MISSED_PINGS: usize = 3;

#[wasm_bindgen]
impl WasmClient {
    pub fn start_protocol_pings(&self, interval_ms: u32, client_id: u64) -> Result<(), JsValue> {
        self.stop_protocol_pings();
        if interval_ms == 0 {
            return Ok(());
        }
        if self.state.get() != ConnectionState::Connected {
            return Err(js_error("not connected"));
        }
        let Some(transport) = self.transport.borrow().clone() else {
            return Err(js_error("not connected"));
        };
        let generation = self.connection_generation.get();
        let current_generation = self.connection_generation.clone();
        let interval_ms =
            i32::try_from(interval_ms).map_err(|_| js_error("ping interval is too large"))?;
        let on_error = self.on_error.clone();
        let ping_tracker = self.ping_tracker.clone();
        let closure = Closure::wrap(Box::new(move || {
            if current_generation.get() != generation {
                return;
            }
            let transport = transport.clone();
            let on_error = on_error.clone();
            let ping_tracker = ping_tracker.clone();
            let current_generation = current_generation.clone();
            wasm_bindgen_futures::spawn_local(async move {
                if current_generation.get() != generation {
                    return;
                }
                let sent_at = js_sys::Date::now();
                let missed_pings = ping_tracker.borrow_mut().begin_round();
                if missed_pings >= DEFAULT_MAX_MISSED_PINGS {
                    transport.close();
                    return;
                }
                let timestamp = if sent_at.is_finite()
                    && (0.0..=MAX_SAFE_JS_INTEGER).contains(&sent_at)
                    && sent_at.fract() == 0.0
                {
                    sent_at as u64
                } else {
                    let _ = on_error.call1(&JsValue::NULL, &js_error("invalid clock value"));
                    return;
                };
                let type_map = transport.type_map();
                let frame =
                    CommunicationValue::new_with_type_map(CommunicationType::Ping, &type_map)
                        .add_typed_default(
                            DataType::Timestamp,
                            DataValue::UnsignedNumber(timestamp as u128),
                        )
                        .with_sender(client_id);
                let Some(ping_id) = frame.id() else {
                    let _ = on_error.call1(&JsValue::NULL, &js_error("ping frame has no id"));
                    transport.close();
                    return;
                };
                let frame = frame
                    .to_bytes()
                    .map_err(|e| js_error(format!("encode ping failed: {}", e)));
                match frame {
                    Ok(frame) => {
                        if current_generation.get() != generation {
                            return;
                        }
                        let Some(ping_id) = PingId::new(ping_id) else {
                            let _ =
                                on_error.call1(&JsValue::NULL, &js_error("ping frame has zero id"));
                            transport.close();
                            return;
                        };
                        ping_tracker.borrow_mut().sent(ping_id, sent_at);
                        if let Err(error) = transport.send_frame(&frame).await {
                            ping_tracker.borrow_mut().clear();
                            let _ = on_error.call1(&JsValue::NULL, &error);
                            transport.close();
                        }
                    }
                    Err(error) => {
                        let _ = on_error.call1(&JsValue::NULL, &error);
                        transport.close();
                    }
                }
            });
        }) as Box<dyn FnMut()>);

        let set_interval =
            js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("setInterval"))?
                .dyn_into::<js_sys::Function>()?;
        let id = set_interval
            .call2(
                &JsValue::NULL,
                closure.as_ref().unchecked_ref(),
                &JsValue::from_f64(interval_ms as f64),
            )?
            .as_f64()
            .filter(|value| {
                value.is_finite()
                    && value.fract() == 0.0
                    && (i32::MIN as f64..=i32::MAX as f64).contains(value)
            })
            .and_then(|value| i32::try_from(value as i64).ok())
            .ok_or_else(|| js_error("setInterval did not return a valid id"))?;
        *self.ping_timer.borrow_mut() = Some(PingTimer { id, closure });
        Ok(())
    }

    #[wasm_bindgen]
    pub fn stop_protocol_pings(&self) {
        self.ping_tracker.borrow_mut().clear();
        self.ping_ms.set(None);
        let Some(timer) = self.ping_timer.borrow_mut().take() else {
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

    pub(super) fn start_receive_loop(
        &self,
        transport: WasmTransport,
        generation: u32,
        client_id: u64,
    ) -> bool {
        if self.connection_generation.get() != generation {
            transport.close();
            return false;
        }
        let loop_transport = transport.clone();
        self.attempt_transport.borrow_mut().take();
        *self.transport.borrow_mut() = Some(transport);
        self.set_state(ConnectionState::Connected);

        let connection_generation = self.connection_generation.clone();
        let error_generation = connection_generation.clone();
        let state = self.state.clone();
        let pending_state_callbacks = self.pending_state_callbacks.clone();
        let state_callback = self.state_callback.as_ref().clone();
        let on_msg = self.on_message.clone();
        let on_err = self.on_error.clone();
        let subscriptions = self.subscriptions.clone();
        let pending_requests = self.pending_requests.clone();
        let loop_pending_requests = pending_requests.clone();
        let ping_timer = self.ping_timer.clone();
        let ping_tracker = self.ping_tracker.clone();
        let loop_ping_tracker = ping_tracker.clone();
        let ping_ms = self.ping_ms.clone();
        let loop_ping_ms = ping_ms.clone();
        let pending_pipe_creations = self.pending_pipe_creations.clone();
        let pending_pipes = self.pending_pipes.clone();
        let self_pending_pipes = pending_pipes.clone();
        let on_pipe_request = self.on_pipe_request.clone();
        let loop_generation = generation;
        let frame_generation = connection_generation.clone();
        let transport_for_cleanup = self.transport.clone();
        let connection_client_id = self.connection_client_id.clone();
        let dispatcher = mtp_pipes::PipeDispatcher::new(
            std::sync::Arc::new(mtp_core::Policy::default()),
            loop_transport.type_map(),
        );
        *pending_pipe_creations.borrow_mut() = Some(dispatcher.clone());
        let (app_tx, mut app_rx) = tokio::sync::mpsc::channel(1000);
        let (pipe_tx, mut pipe_rx) = tokio::sync::mpsc::channel(1000);
        loop_transport.enable_application_frames();
        let receiver = loop_transport.receiver.clone();
        let sender = loop_transport.sender.clone();
        wasm_bindgen_futures::spawn_local(async move {
            mtp_pipes::run_dispatcher(receiver, sender, app_tx, pipe_tx, dispatcher).await;
        });
        wasm_bindgen_futures::spawn_local(async move {
            while let Some(request) = pipe_rx.recv().await {
                if frame_generation.get() != loop_generation {
                    break;
                }
                let obj = js_sys::Object::new();
                let _ = js_sys::Reflect::set(
                    &obj,
                    &"pipeId".into(),
                    &JsValue::from_f64(request.id().get() as f64),
                );
                let _ = js_sys::Reflect::set(
                    &obj,
                    &"description".into(),
                    &JsValue::from_str(request.description()),
                );
                pending_pipes.borrow_mut().insert(request.id(), request);
                if let Some(callback) = on_pipe_request.borrow().as_ref() {
                    let _ = callback.call1(&JsValue::NULL, &obj);
                }
            }
        });
        wasm_bindgen_futures::spawn_local(async move {
            while let Some(result) = app_rx.recv().await {
                if connection_generation.get() != loop_generation {
                    break;
                }
                match result {
                    Ok(message) => {
                        let frame = match message
                            .to_bytes()
                            .map_err(|e| js_error(e.to_string()))
                            .and_then(|bytes| {
                                crate::frame::parse_frame_value_with_limits(
                                    &bytes,
                                    &loop_transport.type_map(),
                                    loop_transport.decode_limits(),
                                )
                            }) {
                            Ok(frame) => frame,
                            Err(error) => {
                                let _ = on_err.call1(&JsValue::NULL, &error);
                                continue;
                            }
                        };
                        route_incoming_frame(
                            &frame,
                            loop_generation,
                            &on_msg,
                            &subscriptions,
                            &loop_pending_requests,
                            &loop_ping_tracker,
                            &loop_ping_ms,
                        );
                    }
                    Err(error) => {
                        if error_generation.get() == generation {
                            let _ = on_err.call1(
                                &JsValue::NULL,
                                &crate::error::from_communication_error(error),
                            );
                        }
                        break;
                    }
                }
            }
            if connection_generation.get() != generation {
                return;
            }
            if let Some(current_transport) = transport_for_cleanup.borrow_mut().take() {
                current_transport.close();
            }
            set_shared_state(
                &state,
                &pending_state_callbacks,
                &state_callback,
                ConnectionState::Disconnected,
            );
            stop_ping_timer(&ping_timer);
            ping_tracker.borrow_mut().clear();
            ping_ms.set(None);
            reject_pending_requests(&pending_requests, "disconnected");
            pending_requests.borrow_mut().clear_expired();
            client_pipe::reject_pending_pipe_creations(&pending_pipe_creations, "disconnected");
            client_pipe::reject_pending_pipes(&self_pending_pipes, "disconnected");
            connection_client_id.set(0);
        });
        self.connection_client_id.set(client_id);
        true
    }

    pub(super) fn reject_pending_requests(&self, message: &str) {
        reject_pending_requests(&self.pending_requests, message);
        self.pending_requests.borrow_mut().clear_expired();
    }
}
