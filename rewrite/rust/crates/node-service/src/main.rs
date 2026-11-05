//! Experimental independent-node process. No installer or production deployment.
use serde::Deserialize;
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use xcli_node_controller::{Clock, Controller};
use xcli_node_ledger::Ledger;
use xcli_node_transport::Transport;
use xcli_node_xray::XrayCore;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    node_id: String,
    token: String,
    panel: String,
}

#[derive(Clone)]
struct SystemClock(Instant);
impl Clock for SystemClock {
    fn wall_seconds(&self) -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(f64::NAN, |v| v.as_secs_f64())
    }
    fn monotonic(&self) -> Duration {
        self.0.elapsed()
    }
}

struct Arguments {
    config: PathBuf,
    state: PathBuf,
    core: PathBuf,
    xray: PathBuf,
    api: String,
}
fn arguments() -> Result<Arguments, &'static str> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("--experimental") {
        return Err("测试服务需要 --experimental");
    }
    let mut config = None;
    let mut state = None;
    let mut core = None;
    let mut xray = None;
    let mut api = None;
    while let Some(name) = args.next() {
        let value = args.next().ok_or("缺少参数")?;
        let target = match name.as_str() {
            "--config" => &mut config,
            "--state" => &mut state,
            "--core-config" => &mut core,
            "--xray" => &mut xray,
            "--api" => &mut api,
            _ => return Err("未知参数"),
        };
        if target.replace(PathBuf::from(value)).is_some() {
            return Err("参数重复");
        }
    }
    Ok(Arguments {
        config: config.ok_or("缺少配置")?,
        state: state.ok_or("缺少状态目录")?,
        core: core.ok_or("缺少核心配置")?,
        xray: xray.ok_or("缺少核心程序")?,
        api: api
            .unwrap_or_else(|| PathBuf::from("127.0.0.1:10085"))
            .into_os_string()
            .into_string()
            .map_err(|_| "核心地址无效")?,
    })
}

/// Protects against two Rust test processes using the same state. The legacy
/// agent does not use this lock: the deployment must stop it first.
fn lock_state(state: &Path) -> Result<File, &'static str> {
    fs::create_dir_all(state).map_err(|_| "状态目录不可用")?;
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(state.join("agent.lock"))
        .map_err(|_| "节点锁不可用")?;
    // SAFETY: the file descriptor remains open in the returned File for the process lifetime.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("节点状态已被其他进程占用");
    }
    Ok(file)
}

fn run() -> Result<(), &'static str> {
    // SAFETY: called once before creating threads or writing new files.
    unsafe {
        libc::umask(0o077);
    }
    let args = arguments()?;
    let config: Config =
        serde_json::from_slice(&fs::read(&args.config).map_err(|_| "节点配置不可用")?)
            .map_err(|_| "节点配置无效")?;
    let _lock = lock_state(&args.state)?;
    let ledger = Ledger::open(&args.state.join("traffic.sqlite")).map_err(|_| "节点账本不可用")?;
    let transport = Transport::new(&config.panel, &config.node_id, &config.token)
        .map_err(|_| "节点连接配置无效")?;
    let core = XrayCore::new(&args.xray, &args.core, &args.api).map_err(|_| "节点核心配置无效")?;
    let killer = core.kill_handle();
    let controller = Controller::new(ledger, core);
    let deadline = controller.deadline_handle();
    let controller = Arc::new(Mutex::new(controller));
    let stop = Arc::new(AtomicBool::new(false));
    let supervisor_done = Arc::new(AtomicBool::new(false));
    let signal = stop.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::SeqCst))
        .map_err(|_| "信号处理不可用")?;
    let clock = SystemClock(Instant::now());
    let deadline_clock = clock.clone();
    let deadline_stop = supervisor_done.clone();
    let deadline_killer = killer.clone();
    let supervisor = thread::spawn(move || {
        while !deadline_stop.load(Ordering::SeqCst) {
            if deadline
                .get()
                .is_some_and(|v| deadline_clock.monotonic() >= v)
            {
                let _ = deadline_killer.terminate();
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
    let sampler_controller = controller.clone();
    let sampler_clock = clock.clone();
    let sampler_stop = stop.clone();
    let sampler_killer = killer.clone();
    let sampler = thread::spawn(move || {
        let mut last_failure: Option<Instant> = None;
        while !sampler_stop.load(Ordering::SeqCst) {
            match sampler_controller.try_lock() {
                Ok(mut controller) => {
                    if controller.watchdog(sampler_clock.monotonic()).is_err()
                        && last_failure
                            .is_none_or(|stamp| stamp.elapsed() >= Duration::from_secs(60))
                    {
                        eprintln!("节点采样或授权撤销失败，核心已停止；请检查账本和服务状态");
                        last_failure = Some(Instant::now());
                    }
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    let _ = sampler_killer.terminate();
                    sampler_stop.store(true, Ordering::SeqCst);
                }
                Err(std::sync::TryLockError::WouldBlock) => {}
            }
            thread::sleep(Duration::from_secs(1));
        }
    });
    let mut last_warning: Option<Instant> = None;
    while !stop.load(Ordering::SeqCst) {
        let request = match controller.lock() {
            Ok(mut controller) => controller.prepare(),
            Err(_) => {
                let _ = killer.terminate();
                stop.store(true, Ordering::SeqCst);
                break;
            }
        };
        let result = match request {
            Ok(request) => match transport.exchange(&request.payload) {
                Ok(response) => match controller.lock() {
                    Ok(mut controller) => controller.complete(request, &response, &clock).is_ok(),
                    Err(_) => {
                        let _ = killer.terminate();
                        stop.store(true, Ordering::SeqCst);
                        false
                    }
                },
                Err(_) => false,
            },
            Err(_) => false,
        };
        if !result && last_warning.is_none_or(|v| v.elapsed() >= Duration::from_secs(60)) {
            eprintln!("节点同步暂不可用；授权到期后停止接入");
            last_warning = Some(Instant::now());
        }
        for _ in 0..50 {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
    // Keep the independent supervisor alive until sampling and shutdown finish.
    let sampler_failed = sampler.join().is_err();
    let shutdown = match controller.lock() {
        Ok(mut controller) => controller.stop().map_err(|_| "节点关闭前用量采集失败"),
        Err(_) => {
            let _ = killer.terminate();
            Err("节点关闭前用量采集不可用")
        }
    };
    supervisor_done.store(true, Ordering::SeqCst);
    let supervisor_failed = supervisor.join().is_err();
    if sampler_failed || supervisor_failed {
        return Err("节点监督线程异常");
    }
    shutdown
}

fn main() {
    if let Err(message) = run() {
        eprintln!("节点测试服务失败：{message}");
        std::process::exit(1);
    }
}
