//! Disposable process fixture, restricted to a root-owned /var/lib test directory.
//! It is deliberately not a service installer or a production worker.
#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::fs::{self, OpenOptions};
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use xcli_panel_import::{
        journal::{Hooks, JournalError, Store},
        launcher::Launcher,
        queue::Queue,
        report::ReportChannel,
        runner::PreviewRunner,
    };
    use zeroize::Zeroizing;

    // Only for disposable files under the fixture root. Real service stop,
    // restart and health checks must be supplied by the installation.
    struct FixtureHooks;
    impl Hooks for FixtureHooks {
        fn validate(&mut self, _: &Path) -> Result<(), JournalError> {
            Ok(())
        }
        fn stop(&mut self) -> Result<(), JournalError> {
            Ok(())
        }
        fn start_and_check(&mut self) -> Result<(), JournalError> {
            Ok(())
        }
    }

    fn root_directory(path: &Path) -> Result<(), ()> {
        let meta = fs::symlink_metadata(path).map_err(|_| ())?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.uid() != 0
            || meta.mode() & 0o022 != 0
        {
            return Err(());
        }
        Ok(())
    }
    fn key(path: &Path) -> Result<Zeroizing<[u8; 32]>, ()> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| ())?;
        let meta = file.metadata().map_err(|_| ())?;
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.uid() != 0
            || meta.mode() & 0o077 != 0
            || meta.len() != 32
        {
            return Err(());
        }
        let mut value = Zeroizing::new([0; 32]);
        file.read_exact(value.as_mut()).map_err(|_| ())?;
        Ok(value)
    }
    pub async fn run() -> Result<(), ()> {
        let mut args = std::env::args().skip(1);
        let apply = match args.next().as_deref() {
            Some("--isolated-fixture") => false,
            Some("--isolated-apply") => true,
            _ => return Err(()),
        };
        if unsafe { libc::geteuid() } != 0 {
            return Err(());
        }
        let root = PathBuf::from(args.next().ok_or(())?);
        let panel_gid = args.next().ok_or(())?.parse::<u32>().map_err(|_| ())?;
        let probe_uid = args.next().ok_or(())?.parse::<u32>().map_err(|_| ())?;
        let probe_gid = args.next().ok_or(())?.parse::<u32>().map_err(|_| ())?;
        if args.next().is_some()
            || root.parent() != Some(Path::new("/var/lib"))
            || !root
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.starts_with("xcli-import-fixture-"))
            || fs::canonicalize(&root).ok().as_deref() != Some(root.as_path())
        {
            return Err(());
        }
        for path in [&root, &root.join("config"), &root.join("secret")] {
            root_directory(path)?;
        }
        let key = key(&root.join("secret/security.key"))?;
        let queue = Queue::open(&root.join("panel/inbox"), &root.join("state"), None, *key)
            .map_err(|_| ())?;
        let targets: BTreeMap<String, PathBuf> =
            ["settings", "core", "monitor", "nginx", "locations", "pool"]
                .into_iter()
                .map(|name| (name.to_owned(), root.join("config").join(name)))
                .collect();
        let store = Store::open(
            &root.join("journal"),
            &root.join("journal/update.lock"),
            targets,
        )
        .map_err(|_| ())?;
        let launcher = Launcher::isolated_fixture(&root, probe_uid, probe_gid).map_err(|_| ())?;
        let report =
            ReportChannel::open_trusted(&root.join("report"), panel_gid).map_err(|_| ())?;
        let worker = PreviewRunner::new(queue, store, launcher, report);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let mut task = tokio::task::spawn_blocking(move || {
            if apply {
                worker.run_with_hooks(worker_stop, Some(Box::new(FixtureHooks)))
            } else {
                worker.run(worker_stop)
            }
        });
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|_| ())?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .map_err(|_| ())?;
        tokio::select! {
            value = &mut task => value.map_err(|_| ())?.map_err(|_| ()),
            _ = term.recv() => { stop.store(true, Ordering::Release); task.await.map_err(|_| ())?.map_err(|_| ()) },
            _ = interrupt.recv() => { stop.store(true, Ordering::Release); task.await.map_err(|_| ())?.map_err(|_| ()) },
        }
    }
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if linux::run().await.is_err() {
        eprintln!("isolated import fixture unavailable");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("isolated import fixture requires Linux");
    std::process::exit(1);
}
