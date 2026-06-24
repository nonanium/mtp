use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};

use mtp::crypto::PublicKeyBundle;

pub fn load_client_db(
    path: &str,
) -> Result<(Arc<Mutex<HashMap<u64, PublicKeyBundle>>>, Arc<Mutex<u64>>), Box<dyn std::error::Error>>
{
    let clients: Arc<Mutex<HashMap<u64, PublicKeyBundle>>> =
        Arc::new(Mutex::new(if let Ok(data) = fs::read_to_string(path) {
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            HashMap::new()
        }));
    let next_id = Arc::new(Mutex::new(
        clients.lock().unwrap().keys().max().unwrap_or(&999) + 1,
    ));
    Ok((clients, next_id))
}
