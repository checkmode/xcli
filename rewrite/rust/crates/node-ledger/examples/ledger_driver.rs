//! Test-only JSON-lines driver for comparing against the legacy Python ledger.
use serde_json::{json, Value};
use std::io::{self, BufRead};
use std::path::Path;
use xcli_node_ledger::Ledger;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("test database path required");
    let mut ledger = Ledger::open(Path::new(&path)).expect("test database must open");
    for line in io::stdin().lock().lines() {
        let line = line.expect("test input must be readable");
        let input: Value = serde_json::from_str(&line).expect("test input must be JSON");
        let result = match input["op"].as_str() {
            Some("record") => ledger
                .record(
                    input["generation"].as_str().unwrap_or(""),
                    &input["counters"],
                )
                .map(|_| json!(null)),
            Some("pending") => ledger
                .pending(input["limit"].as_u64().unwrap_or(0) as usize)
                .map(|v| json!(v)),
            Some("acknowledge") => ledger.acknowledge(&input["entries"]).map(|_| json!(null)),
            _ => panic!("unknown test operation"),
        };
        println!(
            "{}",
            match result {
                Ok(value) => json!({"ok":true,"value":value}),
                Err(_) => json!({"ok":false}),
            }
        );
    }
}
