pub mod error;
pub mod transport;
pub mod client;
pub mod crypto;
pub mod message;

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
    web_sys::console::log_1(&"mtp-wasm: module loaded".into());
}
