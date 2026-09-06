use wasm_bindgen::prelude::*;

use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue};

use crate::client::{ConnectionState, WasmClient};
use crate::client_pipe;
use crate::error::js_error;
use crate::pipe::PipeReader;
use crate::transport::WasmTransport;

use super::MAX_SAFE_JS_INTEGER;
use super::dispatch::{
    PendingPing, PingTimer, frame_id, frame_property, frame_type, reject_pending_requests,
    route_incoming_frame, set_shared_state, stop_ping_timer,
};

#[wasm_bindgen]
impl WasmClient {
    pub fn start_protocol_pings(&self, interval_ms: u32, client_id: u64) -> Result<(), JsValue> {
        self.stop_protocol_pings();
        if self.state.get() != ConnectionState::Connected {
            return Err(js_error("not connected"));
        }
        let Some(transport) = self.transport.borrow().clone() else {
            return Err(js_error("not connected"));
        };
        let generation = self.connection_generation.get();
        let current_generation = self.connection_generation.clone();
        let interval_ms = i32::try_from(interval_ms.max(1_000))
            .map_err(|_| js_error("ping interval is too large"))?;
        let on_error = self.on_error.clone();
        let pending_pings = self.pending_pings.clone();
        let closure = Closure::wrap(Box::new(move || {
            if current_generation.get() != generation {
                return;
            }
            let transport = transport.clone();
            let on_error = on_error.clone();
            let pending_pings = pending_pings.clone();
            let current_generation = current_generation.clone();
            wasm_bindgen_futures::spawn_local(async move {
                if current_generation.get() != generation {
                    return;
                }
                let sent_at = js_sys::Date::now();
                pending_pings.borrow_mut().retain(|_, pending| {
                    pending.generation == generation
                        && sent_at - pending.sent_at < interval_ms as f64 * 3.0
                });
                let timestamp = if sent_at.is_finite()
                    && sent_at >= 0.0
                    && sent_at <= MAX_SAFE_JS_INTEGER
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
                            DataType::Description,
                            DataValue::Str("protocol ping".into()),
                        )
                        .add_typed_default(
                            DataType::Timestamp,
                            DataValue::UnsignedNumber(timestamp as u128),
                        )
                        .with_sender(client_id);
                let Some(ping_id) = frame.id() else {
                    let _ = on_error.call1(&JsValue::NULL, &js_error("ping frame has no id"));
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
                        pending_pings.borrow_mut().insert(
                            ping_id,
                            PendingPing {
                                generation,
                                sent_at,
                            },
                        );
                        if let Err(error) = transport.send_frame(&frame).await {
                            if pending_pings
                                .borrow()
                                .get(&ping_id)
                                .is_some_and(|ping| ping.generation == generation)
                            {
                                pending_pings.borrow_mut().remove(&ping_id);
                            }
                            let _ = on_error.call1(&JsValue::NULL, &error);
                        }
                    }
                    Err(error) => {
                        let _ = on_error.call1(&JsValue::NULL, &error);
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
        self.pending_pings.borrow_mut().clear();
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
        let expired_requests = self.expired_requests.clone();
        let loop_expired_requests = expired_requests.clone();
        let ping_timer = self.ping_timer.clone();
        let pending_pings = self.pending_pings.clone();
        let loop_pending_pings = pending_pings.clone();
        let ping_ms = self.ping_ms.clone();
        let loop_ping_ms = ping_ms.clone();
        let pending_pipe_creations = self.pending_pipe_creations.clone();
        let expired_pipe_creations = self.expired_pipe_creations.clone();
        let pending_pipes = self.pending_pipes.clone();
        let loop_pending_pipes = pending_pipes.clone();
        let expected_pending_pipes = pending_pipes.clone();
        let on_pipe_request = self.on_pipe_request.clone();
        let loop_pipe_creations = pending_pipe_creations.clone();
        let loop_expired_pipe_creations = expired_pipe_creations.clone();
        let loop_generation = generation;
        let frame_generation = connection_generation.clone();
        let transport_for_cleanup = self.transport.clone();
        let connection_client_id = self.connection_client_id.clone();
        wasm_bindgen_futures::spawn_local(async move {
            loop_transport
                .receive_loop_with_pipes(
                    move |frame: JsValue| {
                        if frame_generation.get() != loop_generation {
                            return;
                        }
                        let message_type = frame_type(&frame);
                        if let Some(ref msg_type) = message_type {
                            if msg_type == "PipeRequest" {
                                let Some(pipe_id) = frame_id(&frame).filter(|id| *id != 0) else {
                                    return;
                                };
                                let description = frame_property(&frame, "data")
                                    .and_then(|data| {
                                        let desc = js_sys::Reflect::get(
                                            &data,
                                            &JsValue::from_str("Description"),
                                        )
                                        .ok()?;
                                        desc.as_string()
                                    })
                                    .unwrap_or_default();

                                let cb = on_pipe_request.borrow();
                                if let Some(ref callback) = *cb {
                                    let obj = js_sys::Object::new();
                                    let _ = js_sys::Reflect::set(
                                        &obj,
                                        &"pipeId".into(),
                                        &JsValue::from_f64(pipe_id as f64),
                                    );
                                    let _ = js_sys::Reflect::set(
                                        &obj,
                                        &"description".into(),
                                        &JsValue::from_str(&description),
                                    );
                                    let _ = callback.call1(&JsValue::NULL, &obj.into());
                                }
                                return;
                            }

                            if msg_type == "PipeResponse" {
                                let Some(pipe_id) = frame_id(&frame).filter(|id| *id != 0) else {
                                    return;
                                };
                                let accepted = frame_property(&frame, "data")
                                    .and_then(|data| {
                                        let acc = js_sys::Reflect::get(
                                            &data,
                                            &JsValue::from_str("Accepted"),
                                        )
                                        .ok()?;
                                        acc.as_bool()
                                    })
                                    .unwrap_or(false);

                                let pending = {
                                    let mut pending = loop_pipe_creations.borrow_mut();
                                    if pending
                                        .get(&pipe_id)
                                        .is_some_and(|entry| entry.generation == loop_generation)
                                    {
                                        pending.remove(&pipe_id)
                                    } else {
                                        None
                                    }
                                };
                                if let Some(entry) = pending {
                                    let _ = entry.sender.send(Ok(accepted));
                                } else {
                                    let _ = client_pipe::consume_expired_pipe_creation(
                                        &loop_expired_pipe_creations,
                                        pipe_id,
                                    );
                                }
                                return;
                            }
                        }

                        route_incoming_frame(
                            &frame,
                            loop_generation,
                            &on_msg,
                            &subscriptions,
                            &loop_pending_requests,
                            &loop_expired_requests,
                            &loop_pending_pings,
                            &loop_ping_ms,
                        );
                    },
                    move |error| {
                        if error_generation.get() == generation {
                            let _ = on_err.call1(&JsValue::NULL, &error);
                        }
                    },
                    move |pipe_reader: PipeReader| {
                        let pipe_id = pipe_reader.pipe_id();
                        let mut pending = loop_pending_pipes.borrow_mut();
                        if pending
                            .get(&pipe_id)
                            .is_some_and(|entry| entry.generation == loop_generation)
                            && let Some(entry) = pending.remove(&pipe_id)
                        {
                            let _ = entry.sender.send(Ok(pipe_reader));
                        }
                    },
                    move |pipe_id| {
                        expected_pending_pipes
                            .borrow()
                            .get(&pipe_id)
                            .is_some_and(|entry| entry.generation == loop_generation)
                    },
                )
                .await;
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
            pending_pings.borrow_mut().clear();
            ping_ms.set(None);
            reject_pending_requests(&pending_requests, "disconnected");
            expired_requests.borrow_mut().clear();
            client_pipe::reject_pending_pipe_creations(&pending_pipe_creations, "disconnected");
            expired_pipe_creations.borrow_mut().clear();
            client_pipe::reject_pending_pipes(&pending_pipes, "disconnected");
            connection_client_id.set(0);
        });
        self.connection_client_id.set(client_id);
        true
    }

    pub(super) fn reject_pending_requests(&self, message: &str) {
        reject_pending_requests(&self.pending_requests, message);
        self.expired_requests.borrow_mut().clear();
    }
}
