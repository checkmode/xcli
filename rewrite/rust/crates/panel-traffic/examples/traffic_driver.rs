//! Test-only JSON-lines driver for a disposable legacy database.
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};
use std::io::{self, BufRead};
use xcli_panel_traffic::{apply, Counter};

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("expected disposable database");
    let mut db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap();
    for line in io::stdin().lock().lines() {
        let input: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let counters = input["counters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| Counter {
                name: value["name"].as_str().unwrap().to_owned(),
                value: value["value"].as_i64().unwrap(),
            })
            .collect::<Vec<_>>();
        let result = apply(
            &mut db,
            input["generation"].as_str().unwrap(),
            &counters,
            input["now"].as_i64().unwrap(),
            5,
        );
        println!(
            "{}",
            match result {
                Ok((up, down)) => json!({"ok":true,"upload":up,"download":down}),
                Err(_) => json!({"ok":false}),
            }
        );
    }
}
