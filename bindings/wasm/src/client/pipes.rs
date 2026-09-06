use wasm_bindgen::prelude::*;

use crate::client::{ConnectionState, WasmClient};
use crate::client_pipe;
use crate::error::js_error;
use crate::pipe::PipeReader;

#[wasm_bindgen]
impl WasmClient {
    pub fn set_on_pipe_request(&self, callback: Option<js_sys::Function>) {
        *self.on_pipe_request.borrow_mut() = callback;
    }

    #[wasm_bindgen]
    pub async fn create_pipe(
        &self,
        description: &str,
    ) -> Result<client_pipe::WasmPipeHandle, JsValue> {
        if self.state.get() != ConnectionState::Connected {
            return Err(js_error("not connected"));
        }
        let transport = self
            .transport
            .borrow()
            .clone()
            .ok_or_else(|| js_error("not connected"))?;

        let pipe_id = client_pipe::random_pipe_id()?;
        client_pipe::wasm_create_pipe(
            &transport,
            description,
            pipe_id,
            &self.pending_pipe_creations,
            &self.expired_pipe_creations,
            self.connection_generation.get(),
            &self.connection_generation,
        )
        .await
    }

    #[wasm_bindgen]
    pub async fn accept_pipe(&self, pipe_id: u32) -> Result<PipeReader, JsValue> {
        if self.state.get() != ConnectionState::Connected {
            return Err(js_error("not connected"));
        }
        let transport = self
            .transport
            .borrow()
            .clone()
            .ok_or_else(|| js_error("not connected"))?;

        let generation = self.connection_generation.get();
        client_pipe::wasm_accept_pipe(
            &transport,
            pipe_id,
            &self.pending_pipes,
            generation,
            &self.connection_generation,
        )
        .await
    }

    #[wasm_bindgen]
    pub async fn deny_pipe(&self, pipe_id: u32) -> Result<(), JsValue> {
        if self.state.get() != ConnectionState::Connected {
            return Err(js_error("not connected"));
        }
        let transport = self
            .transport
            .borrow()
            .clone()
            .ok_or_else(|| js_error("not connected"))?;

        client_pipe::wasm_deny_pipe(&transport, pipe_id).await
    }
}
