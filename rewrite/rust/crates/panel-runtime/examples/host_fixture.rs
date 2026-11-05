//! Fixture-only host sampler for comparing disposable proc trees.
use std::path::Path;
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        std::process::exit(2);
    }
    let (mut host, ticks) = xcli_panel_runtime::sample(Path::new(&args[1]), Path::new(&args[2]));
    host["cpu_ticks"] = serde_json::json!(ticks);
    println!("{host}");
}
