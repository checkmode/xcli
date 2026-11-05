use std::io::{self, BufRead};
use std::path::Path;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        return;
    }
    let Ok(settings) = std::fs::read(&args[2])
        .and_then(|data| serde_json::from_slice(&data).map_err(std::io::Error::other))
    else {
        return;
    };
    let Ok(key) = std::fs::read(&args[3]).and_then(|key| {
        <[u8; 32]>::try_from(key).map_err(|_| std::io::Error::other("invalid key"))
    }) else {
        return;
    };
    let Ok(mut store) =
        xcli_panel_backup::BackupStore::open(Path::new(&args[1]), settings, key, "1.3.0".into())
    else {
        return;
    };
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let result = serde_json::from_str::<serde_json::Value>(&line)
            .ok()
            .map(|input| match input["action"].as_str() {
                Some("create") => store.create("manual", input["stamp"].as_i64().unwrap_or(0)),
                Some("inspect") => store.inspect(input["id"].as_str().unwrap_or("")),
                Some("list") => store.list().map(|items| serde_json::json!(items)),
                Some("restore-offline") => store.restore_with_flush(
                    input["id"].as_str().unwrap_or(""),
                    input["stamp"].as_i64().unwrap_or(0),
                    || Ok(()),
                ),
                _ => Err(xcli_panel_backup::BackupError::Invalid),
            });
        let output = match result {
            Some(Ok(value)) => serde_json::json!({"ok":true,"value":value}),
            Some(Err(error)) => serde_json::json!({"ok":false,"error":format!("{error:?}")}),
            None => serde_json::json!({"ok":false}),
        };
        println!("{output}");
    }
}
