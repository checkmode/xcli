use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let output = match serde_json::from_str::<serde_json::Value>(&line) {
            Ok(input) => {
                let user = serde_json::from_value(input["user"].clone());
                if let Ok(user) = user {
                    match xcli_panel_clash::build(
                        &input["settings"],
                        &user,
                        input["remote_nodes"]
                            .as_array()
                            .map(Vec::as_slice)
                            .unwrap_or(&[]),
                        input["dynamic_enabled"].as_bool().unwrap_or(false),
                        &input["policy"],
                    ) {
                        Ok(value) => match xcli_panel_clash::render(&value) {
                            Ok(rendered) => {
                                serde_json::json!({"ok":true,"value":value,"yaml":rendered})
                            }
                            Err(error) => {
                                serde_json::json!({"ok":false,"status":error.status,"detail":error.detail})
                            }
                        },
                        Err(error) => {
                            serde_json::json!({"ok":false,"status":error.status,"detail":error.detail})
                        }
                    }
                } else {
                    serde_json::json!({"ok":false})
                }
            }
            Err(_) => serde_json::json!({"ok":false}),
        };
        println!("{output}");
    }
}
