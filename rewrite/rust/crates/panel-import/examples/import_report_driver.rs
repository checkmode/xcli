//! Disposable privilege-boundary fixture. Never use against production paths.
use std::path::Path;
use xcli_panel_import::report::{Phase, ReportChannel};
fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().expect("mode");
    let path = args.next().expect("path");
    let owner = args
        .next()
        .expect("owner")
        .parse::<u32>()
        .expect("owner UID");
    let group = args
        .next()
        .expect("group")
        .parse::<u32>()
        .expect("group GID");
    assert!(args.next().is_none());
    let channel =
        ReportChannel::open(Path::new(&path), owner, group).expect("fixture report channel");
    match mode.as_str() {
        "write" => channel
            .publish("", Phase::Idle, 1000, None)
            .expect("fixture publish"),
        "read" => println!("{}", channel.read(1000).expect("fixture read")),
        _ => panic!("unsupported fixture mode"),
    }
}
