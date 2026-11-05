//! Synthetic Certbot hook fixture; not a production renewal executable.
use std::path::Path;
use xcli_certificates::{
    bundle::publish,
    renewal::{matches_lineage, read_pair},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 5 {
        return Err("fixture arguments required".into());
    }
    let root = Path::new(&args[1]);
    let renewed = Path::new(&args[2]);
    let target = Path::new(&args[3]);
    let lineage = args[4].to_str().ok_or("invalid fixture lineage")?;
    if !matches_lineage(root, lineage, Some(renewed)).map_err(|_| "invalid fixture lineage")? {
        return Ok(());
    }
    let pair = read_pair(root, lineage).map_err(|_| "fixture source unavailable")?;
    publish(target, "localhost", pair.certificate(), pair.private_key())
        .map_err(|_| "fixture publication failed")?;
    Ok(())
}
