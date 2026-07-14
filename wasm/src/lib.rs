pub mod client;
pub mod config;
pub mod crypto;
pub mod error;
pub mod frame;
pub mod logging;
pub mod pipe;
pub mod subscription;
pub mod transport;

pub use client::WasmClient;
pub use config::{ConnectionConfig, WasmClientConfig};

#[cfg(not(test))]
use wasm_bindgen::prelude::*;

#[cfg(not(test))]
#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
}
