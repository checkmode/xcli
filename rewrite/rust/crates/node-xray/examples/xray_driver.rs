//! Test-only Xray adapter driver. Never point it at a production core.
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{self, BufRead};
use std::path::Path;
use xcli_node_controller::Core;
use xcli_node_protocol::User;
use xcli_node_xray::XrayCore;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        4,
        "expected test binary, configuration and loopback API"
    );
    let mut core = XrayCore::new(Path::new(&args[1]), Path::new(&args[2]), &args[3])
        .expect("test core configuration");
    for line in io::stdin().lock().lines() {
        let input: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let result = match input["op"].as_str() {
            Some("start") => core.start().map(|_| json!(null)),
            Some("stop") => {
                core.stop();
                Ok(json!(null))
            }
            Some("counters") => core.counters(),
            Some("apply") => {
                let mut users = BTreeMap::new();
                for entry in input["users"].as_array().unwrap() {
                    let id = entry["id"].as_str().unwrap().to_owned();
                    users.insert(
                        id.clone(),
                        User {
                            id,
                            uuid: entry["uuid"].as_str().unwrap().to_owned(),
                            expires: entry["expires"].as_i64().unwrap(),
                        },
                    );
                }
                core.apply(&users).map(|_| json!(null))
            }
            _ => panic!("unknown test operation"),
        };
        println!(
            "{}",
            match result {
                Ok(value) => json!({"ok":true,"value":value,"generation":core.generation()}),
                Err(_) => json!({"ok":false}),
            }
        );
    }
}
