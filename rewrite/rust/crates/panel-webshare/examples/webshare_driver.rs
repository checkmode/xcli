//! Disposable compatibility fixture; never use real credentials in its input.
use serde_json::{json, Value};
use std::io::{self, BufRead};
use std::path::Path;
use xcli_panel_webshare::{ActiveSnapshot, Control, Error};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        std::process::exit(2);
    }
    let settings: Value = serde_json::from_slice(&std::fs::read(&args[2]).unwrap()).unwrap();
    let key: [u8; 32] = hex::decode(&args[3]).unwrap().try_into().unwrap();
    let control = Control::open(Path::new(&args[1]), settings, key).unwrap();
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let Ok(input) = serde_json::from_str::<Value>(&line) else {
            println!("{{\"ok\":false}}");
            continue;
        };
        let now = input.get("now").and_then(Value::as_i64).unwrap_or(-1);
        let result = match input.get("op").and_then(Value::as_str) {
            Some("status") => control.status(now),
            Some("configure") => control
                .configure(input.get("input").unwrap_or(&Value::Null), now)
                .map(|_| json!({})),
            Some("request") => control
                .request(input.get("input").unwrap_or(&Value::Null), now)
                .map(|_| json!({})),
            Some("active-save") => ActiveSnapshot::from_value(input.get("input").cloned().unwrap_or(Value::Null), &["US","JP"], now)
                .and_then(|snapshot|control.save_active(&snapshot)).map(|_|json!({})),
            Some("active-check") => control.load_active(&["US","JP"],now).and_then(|snapshot|snapshot.ok_or(Error::Unavailable)).map(|snapshot| {
                let state=snapshot.as_value();json!({"password_matches":state["active"]["credentials"]["password"]==input["input"]["password"],
                    "revision":state["processed_revision"],"us_count":state["pools"]["US"].as_array().map(Vec::len).unwrap_or(0),
                    "jp_count":state["pools"]["JP"].as_array().map(Vec::len).unwrap_or(0)})
            }),
            _ => Err(Error::Invalid("请求无效")),
        };
        match result {
            Ok(value) => println!("{}", json!({"ok":true,"value":value})),
            Err(Error::Invalid(_)) => println!("{}", json!({"ok":false,"error":"invalid"})),
            Err(Error::Unavailable) => println!("{}", json!({"ok":false,"error":"unavailable"})),
        }
    }
}
