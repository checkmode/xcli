//! Test-only JSON-lines driver. Accepts a disposable database only.
use serde_json::{json, Value};
use std::io::{self, BufRead};
use std::path::Path;
use xcli_panel_users::Repository;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("expected a disposable database");
    let mut store = Repository::open(Path::new(&path)).expect("cannot open test database");
    for line in io::stdin().lock().lines() {
        let input: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let now = input["now"].as_i64().unwrap();
        let id = input["id"].as_str().unwrap_or("");
        let result = match input["op"].as_str() {
            Some("create") => store
                .create(&input["value"], now)
                .map(|id| json!({ "id": id })),
            Some("update") => store.update(id, &input["value"], now).map(|_| json!(null)),
            Some("rotate") => store.rotate(id, now).map(|_| json!(null)),
            Some("delete") => store.delete(id, now).map(|_| json!(null)),
            Some("list") => store.list(now).map(|items| json!(items)),
            _ => panic!("unknown test operation"),
        };
        println!(
            "{}",
            match result {
                Ok(value) => json!({"ok":true,"value":value}),
                Err(error) => json!({"ok":false,"error":format!("{error:?}")}),
            }
        );
    }
}
