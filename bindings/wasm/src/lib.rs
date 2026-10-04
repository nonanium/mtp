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

#[cfg(not(test))]
use wasm_bindgen::prelude::*;

#[cfg(not(test))]
#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
}
