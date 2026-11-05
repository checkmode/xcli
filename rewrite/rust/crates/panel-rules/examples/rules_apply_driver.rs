use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let output = match serde_json::from_str::<serde_json::Value>(&line) {
            Ok(input) => {
                let mut config = input["config"].clone();
                match xcli_panel_rules::apply_template_rules(
                    &mut config,
                    &input["spec"],
                    &input["baseline_dns"],
                    input["factory"].as_str().unwrap_or(""),
                ) {
                    Ok(()) => serde_json::json!({"ok":true,"value":config}),
                    Err(error) => {
                        serde_json::json!({"ok":false,"status":error.status,"detail":error.detail})
                    }
                }
            }
            Err(_) => serde_json::json!({"ok":false}),
        };
        println!("{output}");
    }
}
