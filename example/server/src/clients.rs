use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};

use mtp::crypto::PublicKeyBundle;

pub fn load_client_db(
    path: &str,
) -> Result<(Arc<Mutex<HashMap<u64, PublicKeyBundle>>>, Arc<Mutex<u64>>), Box<dyn std::error::Error>>
{
    let clients_map = match fs::read_to_string(path) {
        Ok(data) => match serde_json::from_str(&data) {
            Ok(clients) => clients,
            Err(e) => {
                eprintln!("Failed to parse {path}; starting with empty client database: {e}");
                HashMap::new()
            }
        },
        Err(_) => HashMap::new(),
    };
    let clients: Arc<Mutex<HashMap<u64, PublicKeyBundle>>> = Arc::new(Mutex::new(clients_map));
    let next_value = clients.lock().unwrap().keys().max().unwrap_or(&999) + 1;
    let next_id = Arc::new(Mutex::new(next_value));
    Ok((clients, next_id))
}
