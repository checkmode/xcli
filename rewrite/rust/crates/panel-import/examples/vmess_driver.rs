//! Synthetic compatibility fixture. Never send real share links or UUIDs.
use serde_json::{json, Value};
use std::io::{self, BufRead};
use xcli_panel_import::vmess::parse_links;

fn main() {
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let input: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(_) => {
                println!("{{\"ok\":false}}");
                continue;
            }
        };
        let result = input
            .get("text")
            .and_then(Value::as_str)
            .ok_or(())
            .and_then(|value| parse_links(value).map_err(|_| ()));
        match result {
            Ok(proxies) => {
                let ip = "8.8.8.8".parse().unwrap();
                let items: Vec<_> = proxies.iter().map(|proxy| {
                    let outbound = proxy.outbound(ip).unwrap();
                    json!({"address":proxy.address(),"port":proxy.port(),"outbound":outbound.as_value()})
                }).collect();
                println!("{}", json!({"ok":true,"items":items}));
            }
            Err(_) => println!("{{\"ok\":false}}"),
        }
    }
}
