//! Synthetic compatibility fixture. Never feed real proxy credentials.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::io::{self, BufRead};

fn main() {
    let mut key = [0u8; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = index as u8;
    }
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let result = serde_json::from_str::<Value>(&line)
            .ok()
            .and_then(|input| xcli_panel_import::request::prepare(&input, 1000, &key, 0).ok());
        if let Some(request) = result {
            println!(
                "{}",
                json!({"ok":true,"encrypted":STANDARD.encode(request.encrypted())})
            );
        } else {
            println!("{{\"ok\":false}}");
        }
    }
}
