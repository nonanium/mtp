use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct ConnectionConfig {
    pub(crate) url: String,
    pub(crate) server_certificate_hashes: Option<Vec<String>>,
    pub(crate) client_id: u64,
    pub(crate) max_message_size: u32,
    pub(crate) description: Option<String>,
}

#[wasm_bindgen]
impl ConnectionConfig {
    #[wasm_bindgen(constructor)]
    pub fn new(url: String) -> Self {
        Self {
            url,
            server_certificate_hashes: None,
            client_id: 0,
            max_message_size: 1_000_000_000,
            description: None,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn url(&self) -> String {
        self.url.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_client_id(&mut self, id: u64) {
        self.client_id = id;
    }

    #[wasm_bindgen(getter)]
    pub fn client_id(&self) -> u64 {
        self.client_id
    }

    #[wasm_bindgen(setter)]
    pub fn set_server_certificate_hashes(&mut self, hashes: Vec<String>) {
        self.server_certificate_hashes = Some(hashes);
    }

    #[wasm_bindgen(setter)]
    pub fn set_max_message_size(&mut self, max_message_size: u32) {
        self.max_message_size = max_message_size;
    }

    #[wasm_bindgen(getter)]
    pub fn max_message_size(&self) -> u32 {
        self.max_message_size
    }

    #[wasm_bindgen(setter)]
    pub fn set_description(&mut self, description: String) {
        self.description = Some(description);
    }

    #[wasm_bindgen(getter)]
    pub fn description(&self) -> Option<String> {
        self.description.clone()
    }
}
