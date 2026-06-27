use wasm_bindgen::prelude::*;

/// Log severity used by the public SDK when translating raw WASM events.
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmLogHint {
    Info = 0,
    Warning = 1,
    Error = 2,
}
