//! Fixture-only driver for comparing two isolated test snapshots.
use rusqlite::{Connection, OpenFlags};
use xcli_panel_backup::migration::compare_snapshots;

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        std::process::exit(2);
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NOFOLLOW
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let result = (|| {
        let mut before = Connection::open_with_flags(&args[1], flags).ok()?;
        let mut after = Connection::open_with_flags(&args[2], flags).ok()?;
        Some(compare_snapshots(&mut before, &mut after))
    })();
    match result {
        Some(Ok(summary)) => println!("ok {} {}", summary.tables, summary.users),
        Some(Err(error)) => println!("error {error:?}"),
        None => println!("error Unavailable"),
    }
}
