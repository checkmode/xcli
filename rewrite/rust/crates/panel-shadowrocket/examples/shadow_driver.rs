use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let output = match serde_json::from_str::<serde_json::Value>(&line) {
            Ok(input) => {
                match serde_json::from_value::<xcli_panel_shadowrocket::User>(input["user"].clone())
                {
                    Ok(user) => {
                        let setup = xcli_panel_shadowrocket::setup(
                            &input["settings"],
                            &user,
                            &input["policy"],
                        );
                        let profile = xcli_panel_shadowrocket::profile(
                            &input["settings"],
                            &user,
                            input["remote_nodes"]
                                .as_array()
                                .map(Vec::as_slice)
                                .unwrap_or(&[]),
                            input["dynamic_enabled"].as_bool().unwrap_or(false),
                            &input["policy"],
                        );
                        match (setup, profile) {
                            (Ok(setup), Ok(profile)) => {
                                serde_json::json!({"ok":true,"setup":setup,"status":200,"profile":profile})
                            }
                            (Ok(setup), Err(error)) => {
                                serde_json::json!({"ok":true,"setup":setup,"status":error.status,"detail":error.detail})
                            }
                            (Err(error), _) => {
                                serde_json::json!({"ok":false,"status":error.status,"detail":error.detail})
                            }
                        }
                    }
                    Err(_) => serde_json::json!({"ok":false}),
                }
            }
            Err(_) => serde_json::json!({"ok":false}),
        };
        println!("{output}");
    }
}
