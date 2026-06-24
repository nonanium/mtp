pub mod client;
pub mod crypto;
pub mod error;
pub mod message;
pub mod transport;

use wasm_bindgen::prelude::*;

#[cfg(not(test))]
#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
    web_sys::console::log_1(&"mtp-wasm: module loaded".into());
}
