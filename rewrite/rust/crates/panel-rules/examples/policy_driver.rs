use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let output = match serde_json::from_str::<serde_json::Value>(&line) {
            Ok(input) => {
                let mut config = input["config"].clone();
                let result = match input["action"].as_str() {
                    Some("client-policy") => {
                        match serde_json::from_value(input["outbound"].clone()) {
                            Ok(outbound) => xcli_panel_rules::apply_client_policy(
                                &mut config,
                                input["ai_outbound"].as_str().unwrap_or(""),
                                &outbound,
                            ),
                            Err(_) => continue,
                        }
                    }
                    Some("google-policy") => xcli_panel_rules::apply_google_policy(&mut config),
                    _ => continue,
                };
                match result {
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
