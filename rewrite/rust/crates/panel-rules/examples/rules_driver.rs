use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let output = match serde_json::from_str(&line) {
            Ok(input) => match xcli_panel_rules::validate(&input) {
                Ok(value) => serde_json::json!({"ok":true,"value":value}),
                Err(error) => serde_json::json!({"ok":false,"detail":error.0}),
            },
            Err(_) => serde_json::json!({"ok":false}),
        };
        println!("{output}");
    }
}
