//! Synthetic compatibility fixture. Never use this fixed key with real data.
use serde_json::json;
use std::path::Path;
use xcli_panel_import::queue::Queue;

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 4 {
        std::process::exit(2);
    }
    let result = Queue::open(
        Path::new(&args[1]),
        Path::new(&args[2]),
        Some(Path::new(&args[3])),
        [42; 32],
    )
    .and_then(|queue| queue.claim(1000));
    match result {
        Ok(Some(value)) => println!(
            "{}",
            json!({"claimed":true,"id":value.id(),"action":format!("{:?}",value.action())})
        ),
        Ok(None) => println!("{}", json!({"claimed":false})),
        Err(_) => println!("{}", json!({"error":true})),
    }
}
