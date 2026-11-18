//! Browser bindings. Validate these separately with the wasm32 target.
#![cfg(target_arch = "wasm32")]

pub mod auth;
pub mod client;
pub mod client_pipe;
pub mod config;
pub mod crypto;
pub mod encrypted_pipe;
mod encrypted_pipe_duplex;
pub mod error;
pub mod frame;
pub mod logging;
pub mod pipe;
pub mod protected;
pub mod relay;
pub mod subscription;
pub mod transport;

pub use client::WasmClient;
pub use config::{ConnectionConfig, WasmClientConfig};
pub use crypto::{decrypt_data_value, encrypt_data_value, encrypt_data_value_for_recipients};

use wasm_bindgen::prelude::*;

#[cfg(not(test))]
#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn usage_diagnostics(action: &str, argument: &str, value: f64) -> String {
    use mtp_common::diagnostics;
    match action {
        "restore" => {
            diagnostics::restore(argument);
        }
        "clear" => diagnostics::clear(),
        "enabled" => diagnostics::set_enabled(argument == "true"),
        "event" if value.is_finite() && value >= 0.0 => {
            diagnostics::runtime_event(argument, value as u64)
        }
        _ => {}
    }
    if action == "snapshot" {
        serde_json::to_string(&diagnostics::snapshot()).unwrap_or_default()
    } else {
        String::new()
    }
}

thread_local! {
    static DIAGNOSTIC_CHECKPOINT: std::cell::RefCell<Option<js_sys::Function>> = const { std::cell::RefCell::new(None) };
}

#[wasm_bindgen]
pub fn on_usage_diagnostics_checkpoint(callback: js_sys::Function) {
    DIAGNOSTIC_CHECKPOINT.with(|stored| *stored.borrow_mut() = Some(callback));
    mtp_common::diagnostics::set_sampler(|| {
        DIAGNOSTIC_CHECKPOINT.with(|stored| {
            let callback = stored.borrow().clone();
            if let Some(callback) = callback {
                let _ = callback.call0(&JsValue::NULL);
            }
        });
    });
}
