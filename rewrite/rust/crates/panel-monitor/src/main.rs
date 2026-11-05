//! Experimental monitor service. It is not installed or enabled by default.
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use xcli_panel_monitor::{
    report::Scope,
    runner::Runner,
    service::{RunChecks, Service},
    store::Store,
    Config, Invalid,
};
use zeroize::Zeroizing;

struct Arguments {
    config: PathBuf,
    state: PathBuf,
    interval: u64,
    scope: Scope,
    once: bool,
}
fn arguments<I: Iterator<Item = String>>(mut input: I) -> Result<Arguments, Invalid> {
    let (mut config, mut state, mut interval, mut scope) = (None, None, None, None);
    let (mut once, mut experimental) = (false, false);
    while let Some(arg) = input.next() {
        match arg.as_str() {
            "--experimental" if !experimental => experimental = true,
            "--once" if !once => once = true,
            "--config" if config.is_none() => {
                config = Some(PathBuf::from(input.next().ok_or(Invalid)?))
            }
            "--state-dir" if state.is_none() => {
                state = Some(PathBuf::from(input.next().ok_or(Invalid)?))
            }
            "--interval" if interval.is_none() => {
                interval = Some(
                    input
                        .next()
                        .ok_or(Invalid)?
                        .parse::<u64>()
                        .map_err(|_| Invalid)?,
                )
            }
            "--scope" if scope.is_none() => {
                scope = Some(match input.next().as_deref() {
                    Some("server") => Scope::Server,
                    Some("external") => Scope::External,
                    _ => return Err(Invalid),
                })
            }
            _ => return Err(Invalid),
        }
    }
    let config = config.filter(|path| path.is_absolute()).ok_or(Invalid)?;
    let state = state.filter(|path| path.is_absolute()).ok_or(Invalid)?;
    let interval = interval.unwrap_or(60);
    if !experimental || !(30..=3600).contains(&interval) {
        return Err(Invalid);
    }
    Ok(Arguments {
        config,
        state,
        interval,
        scope: scope.unwrap_or(Scope::Server),
        once,
    })
}
fn config(path: &Path) -> Result<Config, Invalid> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Invalid)?;
    let meta = file.metadata().map_err(|_| Invalid)?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.mode() & 0o027 != 0
        || meta.len() > 1_048_576
        || !(meta.uid() == 0 || meta.uid() == unsafe { libc::geteuid() })
    {
        return Err(Invalid);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(1_048_577)
        .read_to_end(&mut bytes)
        .map_err(|_| Invalid)?;
    Config::parse(&bytes)
}
fn now() -> Result<i64, Invalid> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_secs()).ok())
        .ok_or(Invalid)
}
async fn run(args: Arguments) -> Result<u8, Invalid> {
    let runner = Runner::production()?;
    run_with(args, runner).await
}
async fn run_with<R: RunChecks + 'static>(args: Arguments, runner: R) -> Result<u8, Invalid> {
    let cfg = config(&args.config)?;
    let store = Store::open(&args.state)?;
    let service = Arc::new(Mutex::new(Service::new(cfg, runner, store, args.scope)?));
    let stop = Arc::new(AtomicBool::new(false));
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| Invalid)?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| Invalid)?;
    loop {
        let started = Instant::now();
        let service = service.clone();
        let signal = stop.clone();
        let mut task = tokio::task::spawn_blocking(move || {
            service
                .lock()
                .map_err(|_| Invalid)?
                .cycle_with_clock(&signal, now)
        });
        let result = tokio::select! {
            value=&mut task=>Some(value),
            _=term.recv()=>None,
            _=interrupt.recv()=>None,
        };
        let Some(result) = result else {
            stop.store(true, Ordering::Release);
            let _ = task.await;
            return Ok(0);
        };
        match result {
            Ok(Ok(report)) => {
                if args.once {
                    println!(
                        "{}",
                        serde_json::to_string(report.as_value()).map_err(|_| Invalid)?
                    );
                    return Ok(if report.as_value()["status"] == "healthy" {
                        0
                    } else {
                        1
                    });
                }
            }
            _ => {
                if args.once {
                    return Err(Invalid);
                }
                eprintln!("探测周期未完成，保留上次报告");
            }
        }
        let delay = Duration::from_secs(args.interval)
            .saturating_sub(started.elapsed())
            .max(Duration::from_secs(5));
        tokio::select! {
            _=tokio::time::sleep(delay)=>(),
            _=term.recv()=>{stop.store(true,Ordering::Release);return Ok(0)},
            _=interrupt.recv()=>{stop.store(true,Ordering::Release);return Ok(0)},
        }
    }
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> ExitCode {
    let args = std::env::args_os()
        .skip(1)
        .map(|value| value.into_string().map_err(|_| Invalid))
        .collect::<Result<Vec<_>, _>>();
    let result = match args.and_then(|values| arguments(values.into_iter())) {
        Ok(args) => run(args).await,
        Err(error) => Err(error),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(_) => {
            eprintln!("监测服务未启动或周期失败，请检查配置和权限");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(values: &[&str]) -> Result<Arguments, Invalid> {
        arguments(values.iter().map(|value| value.to_string()))
    }
    #[test]
    fn requires_explicit_experimental_mode_and_valid_bounded_paths() {
        assert!(parse(&[
            "--config",
            "/etc/xcli/monitor.json",
            "--state-dir",
            "/var/lib/xcli-monitor"
        ])
        .is_err());
        assert!(parse(&[
            "--experimental",
            "--config",
            "relative",
            "--state-dir",
            "/var/lib/xcli-monitor"
        ])
        .is_err());
        assert!(parse(&[
            "--experimental",
            "--config",
            "/etc/xcli/monitor.json",
            "--state-dir",
            "/var/lib/xcli-monitor",
            "--interval",
            "1"
        ])
        .is_err());
        assert!(parse(&[
            "--experimental",
            "--config",
            "/etc/xcli/monitor.json",
            "--state-dir",
            "/var/lib/xcli-monitor",
            "--interval",
            "60",
            "--scope",
            "server",
            "--once"
        ])
        .is_ok());
    }

    struct FixtureRunner {
        marker: PathBuf,
        slow: bool,
    }
    impl RunChecks for FixtureRunner {
        fn run(
            &self,
            config: &Config,
            stop: &AtomicBool,
        ) -> Result<Vec<xcli_panel_monitor::report::Observation>, Invalid> {
            use xcli_panel_monitor::report::{Dns, Https, Observation, Outcome};
            std::fs::write(&self.marker, "started").map_err(|_| Invalid)?;
            if self.slow {
                let deadline = Instant::now() + Duration::from_secs(5);
                while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(20));
                }
                return Err(Invalid);
            }
            Ok(config
                .kinds()
                .iter()
                .map(|kind| Observation {
                    kind: kind.clone(),
                    finished_at: None,
                    outcome: Outcome::Measured {
                        https: Https::Ok(1),
                        dns: Dns::Ok(2),
                    },
                })
                .collect())
        }
    }
    #[test]
    fn service_child_fixture() {
        let (Ok(base), Ok(mode)) = (
            std::env::var("XCLI_TEST_MONITOR_DIR"),
            std::env::var("XCLI_TEST_MONITOR_MODE"),
        ) else {
            return;
        };
        let base = PathBuf::from(base);
        let args = Arguments {
            config: base.join("config.json"),
            state: base.join("state"),
            interval: 30,
            scope: Scope::Server,
            once: false,
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        assert_eq!(
            runtime.block_on(run_with(
                args,
                FixtureRunner {
                    marker: base.join("started"),
                    slow: mode == "slow"
                }
            )),
            Ok(0)
        );
    }
    #[test]
    fn service_handles_sigterm_without_losing_last_report() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Child, Command, Stdio};
        struct Process(Child);
        impl Drop for Process {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let value = serde_json::json!({"domain":"panel.example.com","public_ip":"8.8.8.8","reality_sni":"example.com",
            "reality_public":"fixture-public-key","short_id":"0123456789abcdef",
            "uuid":"11111111-2222-3333-4444-555555555555","ws_path":"/connect/fixture"});
        let path = dir.path().join("config.json");
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let spawn = |mode: &str| {
            Process(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "tests::service_child_fixture",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env("XCLI_TEST_MONITOR_DIR", dir.path())
                    .env("XCLI_TEST_MONITOR_MODE", mode)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            )
        };
        let wait_for = |path: &Path| {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !path.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(path.exists());
        };
        let stop = |child: &mut Process| {
            assert_eq!(unsafe { libc::kill(child.0.id() as i32, libc::SIGTERM) }, 0);
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        let mut child = spawn("normal");
        wait_for(&state.join("report.json"));
        stop(&mut child);
        drop(child);
        let original = std::fs::read(state.join("report.json")).unwrap();
        std::fs::remove_file(dir.path().join("started")).unwrap();
        let mut child = spawn("slow");
        wait_for(&dir.path().join("started"));
        stop(&mut child);
        drop(child);
        assert_eq!(std::fs::read(state.join("report.json")).unwrap(), original);
        assert!(Store::open(&state).is_ok());
    }
}
