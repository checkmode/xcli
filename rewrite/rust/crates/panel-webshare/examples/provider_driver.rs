//! Disposable parser fixture. Input and output may contain synthetic secrets.
use serde_json::{json, Value};
use std::io::{self, BufRead};
use xcli_panel_webshare::provider::{credentials, plans, session_username, usage};

fn main() {
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            println!("{{\"ok\":false}}");
            continue;
        };
        let input = value.get("input").unwrap_or(&Value::Null);
        let result = match value.get("op").and_then(Value::as_str) {
            Some("plans") => plans(input).map(|value| json!(value)),
            Some("credentials") => credentials(input).map(
                |value| json!({"base":value.base.as_str(),"password":value.password.as_str()}),
            ),
            Some("username") => session_username(
                input["base"].as_str().unwrap_or(""),
                input["country"].as_str().unwrap_or(""),
                input["id"].as_str().unwrap_or(""),
            )
            .map(|value| json!(value.as_str())),
            Some("usage") => Ok(usage(input)),
            _ => {
                println!("{{\"ok\":false}}");
                continue;
            }
        };
        match result {
            Ok(value) => println!("{}", json!({"ok":true,"value":value})),
            Err(_) => println!("{{\"ok\":false}}"),
        }
    }
}
