//! Nonblocking supervision of an external disk-sampling subprocess.
//!
//! A wedged filesystem probe is killed after its deadline; no replacement is
//! started until the previous child is reaped. A kernel task in uninterruptible
//! sleep may remain alive until the filesystem returns. The parent never waits
//! for that task when reporting status or shutting down.
use serde_json::Value;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const MAX_OUTPUT: u64 = 4096;
const INTERVAL: Duration = Duration::from_secs(30);
const DEADLINE: Duration = Duration::from_secs(2);
const MAX_AGE: Duration = Duration::from_secs(45);

pub struct DiskProbe {
    program: PathBuf,
    target: PathBuf,
    child: Option<Child>,
    deadline: Option<Instant>,
    killed: bool,
    next: Instant,
    last: Option<(Instant, Value)>,
}
fn trusted_program(path: &Path) -> bool {
    if !path.is_absolute() || std::fs::canonicalize(path).ok().as_deref() != Some(path) {
        return false;
    }
    let uid = unsafe { libc::geteuid() };
    for (index, item) in path.ancestors().enumerate() {
        let Ok(meta) = std::fs::symlink_metadata(item) else {
            return false;
        };
        if meta.uid() != 0 && meta.uid() != uid {
            return false;
        }
        if index == 0 {
            if !meta.file_type().is_file()
                || meta.mode() & 0o6022 != 0
                || meta.mode() & 0o111 == 0
                || meta.nlink() != 1
            {
                return false;
            }
        } else if !meta.file_type().is_dir()
            || meta.mode() & 0o022 != 0 && meta.mode() & libc::S_ISVTX == 0
        {
            // In a trusted sticky directory such as /tmp, another user cannot
            // rename or unlink a child owned by root or the service. Every
            // child in the chain is independently checked above.
            return false;
        }
    }
    true
}
fn valid(value: &Value, target: &Path) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.len() != 4 || object.get("path").and_then(Value::as_str) != target.to_str() {
        return false;
    }
    let (Some(total), Some(used), Some(available)) = (
        object.get("total").and_then(Value::as_u64),
        object.get("used").and_then(Value::as_u64),
        object.get("available").and_then(Value::as_u64),
    ) else {
        return false;
    };
    total > 0 && used <= total && available <= total
}
fn read_output(child: &mut Child) -> Option<Value> {
    let output = child.stdout.take()?;
    // Never wait for an inherited pipe held open by an unrelated descendant.
    let flags = unsafe { libc::fcntl(output.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(output.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return None;
    }
    let mut bytes = Vec::new();
    output.take(MAX_OUTPUT + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_OUTPUT {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}
impl DiskProbe {
    /// The caller must keep the service-owned path stable and ensure the
    /// target is the intended state filesystem. Neither path is set by HTTP.
    pub fn new(program: &Path, target: &Path) -> std::result::Result<Self, &'static str> {
        if !trusted_program(program)
            || !target.is_absolute()
            || target.to_str().is_none()
            || target.as_os_str().len() > 4096
        {
            return Err("磁盘采样配置无效");
        }
        Ok(Self {
            program: program.to_owned(),
            target: target.to_owned(),
            child: None,
            deadline: None,
            killed: false,
            next: Instant::now(),
            last: None,
        })
    }
    /// Poll without waiting for I/O or process exit. Returns only a recent,
    /// structurally validated measurement for the configured filesystem.
    pub fn poll(&mut self, now: Instant) -> Option<Value> {
        if let Some(child) = self.child.as_mut() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if status.success() && !self.killed {
                        self.last = read_output(child)
                            .filter(|value| valid(value, &self.target))
                            .map(|value| (now, value));
                    } else {
                        self.last = None;
                    }
                    self.child = None;
                    self.deadline = None;
                    self.killed = false;
                }
                Ok(None)
                    if !self.killed && self.deadline.is_some_and(|deadline| now >= deadline) =>
                {
                    // The child is still unreaped, so its PID cannot yet be reused.
                    unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                    let _ = child.kill();
                    self.killed = true;
                    self.last = None;
                }
                Err(_) => {
                    self.last = None;
                }
                _ => (),
            }
        }
        if self.child.is_none() && now >= self.next {
            self.next = now + INTERVAL;
            if trusted_program(&self.program) {
                let mut command = Command::new(&self.program);
                command
                    .arg("--experimental")
                    .arg("--path")
                    .arg(&self.target)
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .current_dir("/")
                    .process_group(0)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null());
                #[cfg(target_os = "linux")]
                // SAFETY: this closure performs only an async-signal-safe
                // syscall between fork and exec; it captures no references.
                unsafe {
                    command.pre_exec(|| {
                        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                match command.spawn() {
                    Ok(child) => {
                        self.child = Some(child);
                        self.deadline = Some(now + DEADLINE);
                        self.killed = false;
                    }
                    Err(_) => self.last = None,
                }
            } else {
                self.last = None;
            }
        }
        self.last
            .as_ref()
            .filter(|(stamp, _)| now.saturating_duration_since(*stamp) <= MAX_AGE)
            .map(|(_, value)| value.clone())
    }
}
impl Drop for DiskProbe {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if matches!(child.try_wait(), Ok(None)) {
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                let _ = child.kill();
                // A filesystem task may remain in uninterruptible sleep. A
                // detached reaper prevents shutdown from waiting for it and
                // collects it if the kernel eventually completes the I/O.
                let _ = std::thread::Builder::new()
                    .name("xcli-disk-reaper".into())
                    .spawn(move || {
                        let _ = child.wait();
                    });
            }
        }
    }
}
