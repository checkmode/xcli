//! Experimental one-shot disk probe. The supervising service enforces timeout.
use std::path::Path;
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 4
        || args[1] != "--experimental"
        || args[2] != "--path"
        || !Path::new(&args[3]).is_absolute()
    {
        std::process::exit(2);
    }
    match xcli_panel_runtime::disk_status(Path::new(&args[3])) {
        Some(value) => println!("{value}"),
        None => std::process::exit(1),
    }
}
