//! Test-only JSON-lines auth driver. Never use a production database or key.
use serde_json::{json, Value};
use std::io::{self, BufRead};
use std::path::Path;
use std::time::Duration;
use xcli_panel_auth::AdminAuth;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "expected disposable database and synthetic key"
    );
    let key: [u8; 32] = hex::decode(&args[2]).unwrap().try_into().unwrap();
    let mut auth = AdminAuth::open(Path::new(&args[1]), key).expect("test database must open");
    for line in io::stdin().lock().lines() {
        let input: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let now = input["now"].as_i64().unwrap();
        let result = match input["op"].as_str() {
            Some("login") => auth
                .login(
                    input["username"].as_str().unwrap(),
                    input["password"].as_str().unwrap(),
                    input["code"].as_str().unwrap(),
                    input["ip"].as_str().unwrap(),
                    now,
                    Duration::from_secs(input["monotonic"].as_u64().unwrap()),
                )
                .map(|v| json!({"cookie":v.cookie,"csrf":v.csrf})),
            Some("session") => auth
                .session(
                    input["cookie"].as_str().unwrap(),
                    input["csrf"].as_str(),
                    now,
                )
                .map(|v| json!({"csrf":v.csrf})),
            Some("logout") => auth
                .logout(
                    input["cookie"].as_str().unwrap(),
                    input["csrf"].as_str().unwrap(),
                    now,
                )
                .map(|_| json!(null)),
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
