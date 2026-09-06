use wasm_bindgen::prelude::*;

#[cfg(not(test))]
pub(crate) fn init_tracing() {
    use tracing::Level;
    use wasm_tracing::prelude::WasmLayerConfig;

    let config = WasmLayerConfig::new()
        .set_max_level(Level::DEBUG)
        .to_owned();
    let _ = wasm_tracing::set_as_global_default_with_config(config);
}

/// Log severity used by the public SDK when translating raw WASM events.
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmLogHint {
    Info = 0,
    Warning = 1,
    Error = 2,
}
