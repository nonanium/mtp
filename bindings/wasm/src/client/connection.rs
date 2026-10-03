use wasm_bindgen::prelude::*;

use crate::client::{ConnectionState, WasmClient};
use crate::client_pipe;
use crate::transport::WasmTransport;

use super::dispatch::set_shared_state;

#[wasm_bindgen]
impl WasmClient {
    pub fn disconnect(&self) {
        self.connection_generation
            .set(self.connection_generation.get().wrapping_add(1));
        self.stop_protocol_pings();
        if let Some(t) = self.transport.borrow_mut().take() {
            t.close();
        }
        if let Some(t) = self.attempt_transport.borrow_mut().take() {
            t.close();
        }
        self.subscriptions.borrow_mut().clear();
        self.reject_pending_requests("disconnected");
        client_pipe::reject_pending_pipe_creations(&self.pending_pipe_creations, "disconnected");
        client_pipe::reject_pending_pipes(&self.pending_pipes, "disconnected");
        self.connection_client_id.set(0);
        self.set_state(ConnectionState::Disconnected);
    }

    pub(super) fn set_state(&self, new_state: ConnectionState) {
        set_shared_state(
            &self.state,
            &self.pending_state_callbacks,
            self.state_callback.as_ref(),
            new_state,
        );
    }

    pub(super) fn set_state_if_current(&self, generation: u32, new_state: ConnectionState) {
        if self.connection_generation.get() == generation {
            self.set_state(new_state);
        }
    }

    pub(super) fn install_attempt_transport(
        &self,
        transport: &WasmTransport,
        generation: u32,
    ) -> bool {
        if self.connection_generation.get() != generation {
            transport.close();
            return false;
        }
        *self.attempt_transport.borrow_mut() = Some(transport.clone());
        true
    }

    pub(super) fn abort_attempt(&self, transport: &WasmTransport, generation: u32) {
        transport.close();
        if self.connection_generation.get() != generation {
            return;
        }
        if let Some(current) = self.attempt_transport.borrow_mut().take() {
            current.close();
        }
        if let Some(current) = self.transport.borrow_mut().take() {
            current.close();
        }
        self.stop_protocol_pings();
        self.reject_pending_requests("connection failed");
        client_pipe::reject_pending_pipe_creations(
            &self.pending_pipe_creations,
            "connection failed",
        );
        client_pipe::reject_pending_pipes(&self.pending_pipes, "connection failed");
        self.connection_client_id.set(0);
        self.set_state(ConnectionState::Disconnected);
    }

    pub(super) fn begin_connection(&self) -> u32 {
        let generation = self.connection_generation.get().wrapping_add(1);
        self.connection_generation.set(generation);
        self.stop_protocol_pings();
        if let Some(transport) = self.transport.borrow_mut().take() {
            transport.close();
        }
        if let Some(transport) = self.attempt_transport.borrow_mut().take() {
            transport.close();
        }
        self.reject_pending_requests("connection replaced");
        client_pipe::reject_pending_pipe_creations(
            &self.pending_pipe_creations,
            "connection replaced",
        );
        client_pipe::reject_pending_pipes(&self.pending_pipes, "connection replaced");
        self.connection_client_id.set(0);
        self.set_state(ConnectionState::Connecting);
        generation
    }
}
