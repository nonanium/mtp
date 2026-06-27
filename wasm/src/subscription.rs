use std::collections::HashMap;

use wasm_bindgen::prelude::*;

/// Minimal message router used by higher-level SDK subscription code.
#[wasm_bindgen]
pub struct WasmSubscriptionRouter {
    handlers: HashMap<String, js_sys::Function>,
}

#[wasm_bindgen]
impl WasmSubscriptionRouter {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    #[wasm_bindgen]
    pub fn subscribe(&mut self, message_type: String, callback: js_sys::Function) {
        self.handlers.insert(message_type, callback);
    }

    #[wasm_bindgen]
    pub fn unsubscribe(&mut self, message_type: &str) -> bool {
        self.handlers.remove(message_type).is_some()
    }

    #[wasm_bindgen]
    pub fn dispatch(&self, message_type: &str, message: JsValue) -> bool {
        let Some(callback) = self.handlers.get(message_type) else {
            return false;
        };
        let _ = callback.call1(&JsValue::NULL, &message);
        true
    }
}

impl Default for WasmSubscriptionRouter {
    fn default() -> Self {
        Self::new()
    }
}
