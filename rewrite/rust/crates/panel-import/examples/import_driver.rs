//! Synthetic cross-implementation fixture. Never feed real proxy credentials.
use serde_json::{json, Value};
use std::io::{self, BufRead};
use xcli_panel_import::parse_fixed;

fn main() {
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let input: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(_) => {
                println!("{{\"ok\":false}}");
                continue;
            }
        };
        let result = input
            .get("text")
            .and_then(Value::as_str)
            .ok_or(())
            .and_then(|text| parse_fixed(text).map_err(|_| ()));
        match result {
            Ok(proxies) => println!("{}", json!({"ok":true,"count":proxies.len()})),
            Err(_) => println!("{{\"ok\":false}}"),
        }
    }
}
