//! Test-only driver for comparing node grants against the legacy agent.
use serde_json::{json, Value};
use std::io::{self, BufRead};
use xcli_node_protocol::validate_response;

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("test input must be readable");
        let input: Value = serde_json::from_str(&line).expect("test input must be JSON");
        let result = validate_response(
            &input["response"],
            &input["pending"],
            input["now"].as_f64().unwrap(),
        );
        println!(
            "{}",
            match result {
                Ok(grant) =>
                    json!({"ok":true,"users":grant.users,"remaining":grant.remaining_at(input["now"].as_f64().unwrap()).unwrap()}),
                Err(_) => json!({"ok":false}),
            }
        );
    }
}
