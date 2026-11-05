//! Fixture-only combined PEM publisher; not a renewal hook or installer.
use std::path::PathBuf;
use xcli_certificates::bundle::publish;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 4 {
        return Err("fixture arguments required".into());
    }
    let cert = std::fs::read(&args[1])?;
    let key = zeroize::Zeroizing::new(std::fs::read(&args[2])?);
    publish(&PathBuf::from(&args[3]), "localhost", &cert, &key)
        .map_err(|_| "fixture publication failed")?;
    Ok(())
}
