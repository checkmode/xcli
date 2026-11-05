//! Offline checkpoint for a stopped panel and a still-running Xray core.
//! It records usage but does not stop or restart any service.
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use xcli_panel_controller::{checkpoint_before_restart, Core, SqliteStore};
use xcli_panel_xray::ManagedCore;

struct Args {
    db: PathBuf,
    binary: PathBuf,
    pid_file: PathBuf,
    api: String,
    interval: i64,
}
fn arguments() -> Result<Args, ()> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("--experimental") {
        return Err(());
    }
    let mut db = None;
    let mut binary = None;
    let mut pid_file = None;
    let mut api = None;
    let mut interval = None;
    while let Some(name) = args.next() {
        let value = args.next().ok_or(())?;
        let target = match name.as_str() {
            "--db" => &mut db,
            "--core-binary" => &mut binary,
            "--core-pid-file" => &mut pid_file,
            "--core-api" => &mut api,
            "--core-poll-seconds" => &mut interval,
            _ => return Err(()),
        };
        if target.replace(value).is_some() {
            return Err(());
        }
    }
    let interval = interval
        .unwrap_or_else(|| "5".into())
        .parse::<i64>()
        .map_err(|_| ())?;
    if !(1..=60).contains(&interval) {
        return Err(());
    }
    Ok(Args {
        db: PathBuf::from(db.ok_or(())?),
        binary: PathBuf::from(binary.ok_or(())?),
        pid_file: PathBuf::from(pid_file.ok_or(())?),
        api: api.ok_or(())?,
        interval,
    })
}
fn lock_controller(db: &Path) -> Result<File, ()> {
    let parent = db
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|_| ())?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent.join("controller.lock"))
        .map_err(|_| ())?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(());
    }
    Ok(file)
}
fn run() -> Result<String, ()> {
    let args = arguments()?;
    let _lock = lock_controller(&args.db)?;
    let mut core = ManagedCore::new(&args.api, &args.binary, &args.pid_file, BTreeSet::new())
        .map_err(|_| ())?;
    let mut store = SqliteStore::open(&args.db, args.interval, None).map_err(|_| ())?;
    let generation = core.generation().map_err(|_| ())?;
    let stamp = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ())?
            .as_secs(),
    )
    .map_err(|_| ())?;
    checkpoint_before_restart(&mut core, &mut store, &generation, stamp).map_err(|_| ())?;
    if core.generation().map_err(|_| ())? != generation {
        return Err(());
    }
    Ok(generation)
}
fn main() {
    match run() {
        Ok(generation) => println!("{}", serde_json::json!({"generation":generation})),
        Err(()) => {
            eprintln!("最终用量采样失败，未停止核心");
            std::process::exit(1);
        }
    }
}
