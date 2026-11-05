//! Creates only a disposable compatibility fixture; not an installer.
use std::path::PathBuf;
use xcli_panel_provision::initialize_new_file;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 2 {
        return Err("fixture database path required".into());
    }
    let path = PathBuf::from(&args[1]);
    initialize_new_file(&path, "fixture-password-123")
        .map_err(|_| "fixture initialization failed")?;
    Ok(())
}
