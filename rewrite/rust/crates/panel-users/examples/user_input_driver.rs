//! Test-only JSON-lines driver, with no database access.
use serde_json::{json, Value};
use std::io::{self, BufRead};

fn main() {
    for line in io::stdin().lock().lines() {
        let value: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let result = xcli_panel_users::validate(&value);
        println!(
            "{}",
            match result {
                Ok(value) => json!({"ok":true,"value":value}),
                Err(_) => json!({"ok":false}),
            }
        );
    }
}
