//! Bounded subprocess wrapper for webhook delivery.
use crate::webhook::{Config, Delivery};
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const ERROR: &str = "连接失败、超时、证书不受信任或目标不是公网地址";
fn failed(status: u16) -> Delivery {
    Delivery {
        status,
        error: Some(ERROR.into()),
    }
}
struct Guard {
    child: Child,
    reaped: bool,
}
impl Drop for Guard {
    fn drop(&mut self) {
        if !self.reaped {
            // SAFETY: pre_exec creates a private process group before exec.
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGKILL);
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
fn trusted_binary(path: &Path) -> Result<PathBuf, ()> {
    if !path.is_absolute() {
        return Err(());
    }
    for (index, item) in path.ancestors().enumerate() {
        let meta = fs::symlink_metadata(item).map_err(|_| ())?;
        let link = meta.file_type().is_symlink();
        if meta.uid() != 0
            || !link && meta.mode() & 0o022 != 0
            || index == 0 && !(meta.is_file() || link)
            || index != 0 && !(meta.is_dir() || link)
        {
            return Err(());
        }
    }
    let path = fs::canonicalize(path).map_err(|_| ())?;
    for (index, item) in path.ancestors().enumerate() {
        let meta = fs::symlink_metadata(item).map_err(|_| ())?;
        if meta.uid() != 0
            || meta.mode() & 0o022 != 0
            || index == 0 && (!meta.is_file() || meta.nlink() != 1)
            || index != 0 && !meta.is_dir()
        {
            return Err(());
        }
    }
    Ok(path)
}
#[derive(Serialize)]
struct Wire<'a> {
    url: &'a str,
    bearer: &'a str,
    signing: &'a str,
    payload: &'a Value,
    timestamp: i64,
}

pub struct Sender {
    binary: PathBuf,
    timeout: Duration,
}
#[derive(Debug)]
pub struct SenderError;
impl Sender {
    /// The sender is installed under a fixed, root-owned path and is never
    /// chosen from a web request. The parent and child both run non-root.
    pub fn production() -> Result<Self, SenderError> {
        if unsafe { libc::geteuid() } == 0 {
            return Err(SenderError);
        }
        Ok(Self {
            binary: trusted_binary(Path::new("/usr/local/lib/xcli/xcli-webhook-sender"))
                .map_err(|_| SenderError)?,
            timeout: Duration::from_secs(12),
        })
    }
    fn send(
        &self,
        config: &Config,
        payload: &Value,
        timestamp: i64,
        stop: &AtomicBool,
    ) -> Result<Delivery, ()> {
        if timestamp < 0 || stop.load(Ordering::Acquire) {
            return Err(());
        }
        let bytes = Zeroizing::new(
            serde_json::to_vec(&Wire {
                url: &config.url,
                bearer: &config.bearer,
                signing: &config.signing,
                payload,
                timestamp,
            })
            .map_err(|_| ())?,
        );
        if bytes.len() > 32_768 {
            return Err(());
        }
        let parent = unsafe { libc::getpid() };
        let mut command = Command::new(&self.binary);
        command
            .arg("--experimental")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/nonexistent");
        // SAFETY: only async-signal-safe system calls are used after fork.
        unsafe {
            command.pre_exec(move || {
                let limits = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setpgid(0, 0) != 0 || libc::setrlimit(libc::RLIMIT_CORE, &limits) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                #[cfg(target_os = "linux")]
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::getppid() != parent
                {
                    return Err(std::io::Error::last_os_error());
                }
                #[cfg(not(target_os = "linux"))]
                let _ = parent;
                Ok(())
            });
        }
        let child = command.spawn().map_err(|_| ())?;
        let mut guard = Guard {
            child,
            reaped: false,
        };
        let deadline = Instant::now() + self.timeout;
        let mut stdin = guard.child.stdin.take().ok_or(())?;
        let fd = stdin.as_raw_fd();
        // SAFETY: fd belongs to the open child stdin. Flags are read and set
        // without altering ownership, allowing the deadline to bound writes.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(());
        }
        let mut offset = 0;
        while offset < bytes.len() {
            if stop.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err(());
            }
            match stdin.write(&bytes[offset..]) {
                Ok(0) => return Err(()),
                Ok(count) => offset += count,
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(_) => return Err(()),
            }
        }
        drop(stdin);
        loop {
            if stop.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err(());
            }
            match guard.child.try_wait().map_err(|_| ())? {
                Some(status) => {
                    guard.reaped = true;
                    if !status.success() {
                        return Err(());
                    }
                    break;
                }
                None => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        let mut stdout = guard.child.stdout.take().ok_or(())?;
        let fd = stdout.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(());
        }
        let mut output = Vec::new();
        match stdout.by_ref().take(1025).read_to_end(&mut output) {
            Ok(_) if output.len() <= 1024 => {}
            _ => return Err(()),
        }
        let value: Value = serde_json::from_slice(&output).map_err(|_| ())?;
        let status = value["status"].as_u64().filter(|v| *v <= 599).ok_or(())? as u16;
        let error = value["error"].as_bool().ok_or(())?;
        if !error && !(200..300).contains(&status) {
            return Err(());
        }
        Ok(if error {
            failed(status)
        } else {
            Delivery {
                status,
                error: None,
            }
        })
    }
    pub(crate) fn deliver(
        &self,
        config: &Config,
        payload: &Value,
        timestamp: i64,
        stop: &AtomicBool,
    ) -> Delivery {
        self.send(config, payload, timestamp, stop)
            .unwrap_or_else(|_| failed(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn config() -> Config {
        Config {
            url: Zeroizing::new("https://example.com/path?synthetic-secret".into()),
            bearer: Zeroizing::new("synthetic-bearer".into()),
            signing: Zeroizing::new("synthetic-signing".into()),
        }
    }
    fn script(dir: &Path, name: &str, content: &str, timeout: Duration) -> Sender {
        let path = dir.join(name);
        fs::write(&path, content).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Sender {
            binary: path,
            timeout,
        }
    }
    #[test]
    fn subprocess_result_is_bounded_and_stop_cancels_a_hung_child() {
        let dir = tempfile::tempdir().unwrap();
        let ok = script(
            dir.path(),
            "ok",
            "#!/bin/sh\ncat >/dev/null\nprintf '{\"status\":204,\"error\":false}'\n",
            Duration::from_secs(3),
        );
        let stop = AtomicBool::new(false);
        let payload = serde_json::json!({"id":"synthetic-id"});
        assert_eq!(
            ok.deliver(&config(), &payload, 100, &stop),
            Delivery {
                status: 204,
                error: None
            }
        );
        let bad = script(
            dir.path(),
            "bad",
            "#!/bin/sh\ncat >/dev/null\nprintf 'unexpected response'\n",
            Duration::from_secs(3),
        );
        assert_eq!(bad.deliver(&config(), &payload, 100, &stop).status, 0);
        let slow = script(
            dir.path(),
            "slow",
            "#!/bin/sh\nsleep 30\n",
            Duration::from_millis(250),
        );
        let start = Instant::now();
        assert_eq!(slow.deliver(&config(), &payload, 100, &stop).status, 0);
        assert!(start.elapsed() < Duration::from_secs(3));
        let slow = script(
            dir.path(),
            "cancel",
            "#!/bin/sh\nsleep 30\n",
            Duration::from_secs(5),
        );
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(100));
                stop.store(true, Ordering::Release);
            });
            let start = Instant::now();
            assert_eq!(slow.deliver(&config(), &payload, 100, &stop).status, 0);
            assert!(start.elapsed() < Duration::from_secs(3));
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parent_death_fixture() {
        let Ok(path) = std::env::var("XCLI_SENDER_PARENT_FIXTURE") else {
            return;
        };
        let sender = Sender {
            binary: PathBuf::from(path),
            timeout: Duration::from_secs(30),
        };
        let _ = sender.deliver(
            &config(),
            &serde_json::json!({"id":"fixture-id"}),
            100,
            &AtomicBool::new(false),
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sender_process_exits_when_parent_is_killed() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("child.pid");
        let name = pid_file.to_str().unwrap();
        assert!(name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"/._-".contains(&c)));
        let sender = script(
            dir.path(),
            "child",
            &format!("#!/bin/sh\nprintf '%s' \"$$\" > '{name}'\nexec sleep 60\n"),
            Duration::from_secs(30),
        );
        let mut parent = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sender::tests::parent_death_fixture",
                "--nocapture",
            ])
            .env("XCLI_SENDER_PARENT_FIXTURE", &sender.binary)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let pid = loop {
            if let Ok(value) = fs::read_to_string(&pid_file) {
                if let Ok(pid) = value.parse::<i32>() {
                    break pid;
                }
            }
            if Instant::now() >= deadline {
                let _ = parent.kill();
                let _ = parent.wait();
                panic!("test child did not start");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        parent.kill().unwrap();
        parent.wait().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let stat = fs::read_to_string(format!("/proc/{pid}/stat"));
            if stat.as_ref().is_err()
                || stat
                    .as_ref()
                    .ok()
                    .and_then(|line| line.rsplit_once(')'))
                    .and_then(|(_, tail)| tail.split_whitespace().next())
                    == Some("Z")
            {
                break;
            }
            if Instant::now() >= deadline {
                unsafe { libc::kill(pid, libc::SIGKILL) };
                panic!("sender survived its parent");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
