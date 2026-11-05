//! Experimental fixed-proxy worker. It is not installed by the legacy installer.
#[cfg(target_os = "linux")]
mod linux {
    use serde::Deserialize;
    use std::collections::BTreeMap;
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use xcli_panel_import::{
        journal::Store,
        launcher::Launcher,
        queue::Queue,
        report::ReportChannel,
        runner::PreviewRunner,
        systemd::{Options, ServiceHooks},
        validate::{Validated, Validator},
    };
    use zeroize::Zeroizing;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        mode: String,
        key: PathBuf,
        inbox: PathBuf,
        state: PathBuf,
        journal: PathBuf,
        update_lock: PathBuf,
        legacy_processed: Option<PathBuf>,
        report_directory: PathBuf,
        panel_uid: u32,
        panel_gid: u32,
        probe_uid: u32,
        probe_gid: u32,
        targets: BTreeMap<String, PathBuf>,
        database: PathBuf,
        core_pid_file: PathBuf,
        core_api: String,
        panel_port: u16,
        monitor_report: PathBuf,
        core_unit: String,
        panel_unit: String,
        monitor_unit: String,
    }
    fn open_private(path: &Path, limit: u64) -> Result<std::fs::File, ()> {
        if !path.is_absolute() {
            return Err(());
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| ())?;
        let meta = file.metadata().map_err(|_| ())?;
        if !meta.is_file() || meta.nlink() != 1 || meta.len() > limit || meta.mode() & 0o022 != 0 {
            return Err(());
        }
        Ok(file)
    }
    fn read_config(path: &Path) -> Result<Config, ()> {
        let file = open_private(path, 32768)?;
        if file.metadata().map_err(|_| ())?.uid() != 0 {
            return Err(());
        }
        let mut bytes = Vec::new();
        file.take(32769).read_to_end(&mut bytes).map_err(|_| ())?;
        if bytes.len() > 32768 {
            return Err(());
        }
        serde_json::from_slice(&bytes).map_err(|_| ())
    }
    fn read_key(path: &Path, panel_uid: u32) -> Result<Zeroizing<[u8; 32]>, ()> {
        let mut file = open_private(path, 32)?;
        let meta = file.metadata().map_err(|_| ())?;
        if meta.len() != 32 || meta.mode() & 0o007 != 0 || ![0, panel_uid].contains(&meta.uid()) {
            return Err(());
        }
        let mut key = Zeroizing::new([0; 32]);
        file.read_exact(key.as_mut()).map_err(|_| ())?;
        Ok(key)
    }
    pub async fn run() -> Result<(), ()> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(());
        }
        unsafe {
            libc::umask(0o077);
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                return Err(());
            }
        }
        let mut args = std::env::args().skip(1);
        if args.next().as_deref() != Some("--experimental")
            || args.next().as_deref() != Some("--config")
        {
            return Err(());
        }
        let path = PathBuf::from(args.next().ok_or(())?);
        if args.next().is_some() {
            return Err(());
        }
        let config = read_config(&path)?;
        if !["preview", "apply"].contains(&config.mode.as_str())
            || config.panel_uid == 0
            || config.panel_gid == 0
            || config.probe_uid == 0
            || config.probe_gid == 0
        {
            return Err(());
        }
        let key = read_key(&config.key, config.panel_uid)?;
        let queue = Queue::open(
            &config.inbox,
            &config.state,
            config.legacy_processed.as_deref(),
            *key,
        )
        .map_err(|_| ())?;
        let settings = config.targets.get("settings").ok_or(())?.to_owned();
        let store =
            Store::open(&config.journal, &config.update_lock, config.targets).map_err(|_| ())?;
        let launcher = Launcher::production(config.probe_uid, config.probe_gid).map_err(|_| ())?;
        let report = ReportChannel::open_trusted(&config.report_directory, config.panel_gid)
            .map_err(|_| ())?;
        let hooks = if config.mode == "apply" {
            let options = Options {
                systemctl: "/usr/bin/systemctl".into(),
                nginx: "/usr/sbin/nginx".into(),
                checkpoint: "/usr/local/lib/xcli/xcli-panel-checkpoint".into(),
                database: config.database,
                core_binary: "/usr/local/lib/xcli/xray".into(),
                core_pid_file: config.core_pid_file,
                core_api: config.core_api,
                panel_uid: config.panel_uid,
                panel_gid: config.panel_gid,
                panel_port: config.panel_port,
                settings,
                monitor_report: config.monitor_report,
                core_unit: config.core_unit,
                panel_unit: config.panel_unit,
                monitor_unit: config.monitor_unit,
                health_timeout: Duration::from_secs(150),
            };
            Some(Validated {
                validator: Validator::production().map_err(|_| ())?,
                inner: ServiceHooks::new(options).map_err(|_| ())?,
            })
        } else {
            None
        };
        let worker = PreviewRunner::new(queue, store, launcher, report);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let mut task = tokio::task::spawn_blocking(move || match hooks {
            Some(hooks) => worker.run_with_hooks(worker_stop, Some(Box::new(hooks))),
            None => worker.run(worker_stop),
        });
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|_| ())?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .map_err(|_| ())?;
        tokio::select! {
            result = &mut task => result.map_err(|_| ())?.map_err(|_| ()),
            _ = term.recv() => { stop.store(true, Ordering::Release); task.await.map_err(|_| ())?.map_err(|_| ()) },
            _ = interrupt.recv() => { stop.store(true, Ordering::Release); task.await.map_err(|_| ())?.map_err(|_| ()) },
        }
    }
}
#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if linux::run().await.is_err() {
        eprintln!("固定代理服务不可用，请检查服务配置");
        std::process::exit(1);
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("固定代理服务需要 Linux");
    std::process::exit(1);
}
