//! Test-only JSON-lines driver for an isolated database and synthetic node key.
use serde_json::{json, Value};
use std::io::{self, BufRead};
use std::path::Path;
use xcli_panel_nodes::NodeSync;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("expected disposable database");
    let mut sync = NodeSync::open(Path::new(&path)).expect("test database");
    for line in io::stdin().lock().lines() {
        let value: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let now = value["now"].as_i64().unwrap();
        let result = match value["op"].as_str().unwrap_or("sync") {
            "sync" => sync
                .sync(
                    value["authorization"].as_str().unwrap(),
                    &value["input"],
                    now,
                )
                .map_err(|error| format!("{error:?}")),
            "list" => sync.list().map_err(|error| format!("{error:?}")),
            "add" => sync
                .add(&value["input"], now)
                .map_err(|error| format!("{error:?}")),
            "update" => sync
                .update(value["id"].as_str().unwrap(), &value["input"], now)
                .map_err(|error| format!("{error:?}")),
            _ => panic!("unknown operation"),
        };
        println!(
            "{}",
            match result {
                Ok(value) => json!({"ok":true,"value":value}),
                Err(error) => json!({"ok":false,"error":error}),
            }
        );
    }
}
