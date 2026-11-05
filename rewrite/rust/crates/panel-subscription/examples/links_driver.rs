//! Test-only driver: use only synthetic credentials and configuration.
use serde_json::{json, Value};
use std::io::{self, BufRead};
use xcli_panel_subscription::{build, User};

fn main() {
    for line in io::stdin().lock().lines() {
        let input: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let user: User = serde_json::from_value(input["user"].clone()).unwrap();
        let result = build(
            &input["settings"],
            &user,
            input["remote_nodes"].as_array().unwrap(),
            input["dynamic_enabled"].as_bool().unwrap(),
        )
        .and_then(|links| {
            let (body, info) = links.generic_subscription(&user, input["now"].as_i64().unwrap())?;
            let entries: serde_json::Map<String, Value> = links
                .entries
                .into_iter()
                .map(|(key, value)| (key, json!(value)))
                .collect();
            Ok(json!({"links":entries,"body":body,"info":info}))
        });
        println!(
            "{}",
            match result {
                Ok(value) => json!({"ok":true,"value":value}),
                Err(error) => json!({"ok":false,"error":format!("{error:?}")}),
            }
        );
    }
}
