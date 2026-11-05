//! Experimental service switch for a fixed-proxy transaction. Installation
//! supplies trusted paths and unit names; HTTP requests cannot change them.
use crate::journal::{Hooks, JournalError};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, JournalError>;

/// All values must come from the administrator-controlled service unit.
pub struct Options {
    pub systemctl: PathBuf,
    pub nginx: PathBuf,
    pub checkpoint: PathBuf,
    pub database: PathBuf,
    pub core_binary: PathBuf,
    pub core_pid_file: PathBuf,
    pub core_api: String,
    pub panel_uid: u32,
    pub panel_gid: u32,
    pub panel_port: u16,
    pub settings: PathBuf,
    pub monitor_report: PathBuf,
    pub core_unit: String,
    pub panel_unit: String,
    pub monitor_unit: String,
    pub health_timeout: Duration,
}

pub struct ServiceHooks {
    options: Options,
}
fn unit(value: &str) -> bool {
    value.ends_with(".service")
        && value.len() <= 128
        && value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"@_.-".contains(&v))
}
impl ServiceHooks {
    pub fn new(options: Options) -> Result<Self> {
        let paths = [
            &options.systemctl,
            &options.nginx,
            &options.checkpoint,
            &options.database,
            &options.core_binary,
            &options.core_pid_file,
            &options.settings,
            &options.monitor_report,
        ];
        let address = options
            .core_api
            .parse::<SocketAddr>()
            .map_err(|_| JournalError::Invalid)?;
        if paths.iter().any(|path| !path.is_absolute())
            || options.panel_uid == 0
            || options.panel_gid == 0
            || options.panel_port == 0
            || !address.ip().is_loopback()
            || address.port() == 0
            || ![
                &options.core_unit,
                &options.panel_unit,
                &options.monitor_unit,
            ]
            .into_iter()
            .all(|value| unit(value))
            || options.core_unit == options.panel_unit
            || options.core_unit == options.monitor_unit
            || options.panel_unit == options.monitor_unit
            || options.health_timeout.is_zero()
            || options.health_timeout > Duration::from_secs(180)
        {
            return Err(JournalError::Invalid);
        }
        Ok(Self { options })
    }
    fn command(
        &self,
        program: &Path,
        args: &[OsString],
        identity: Option<(u32, u32)>,
    ) -> Result<i32> {
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .process_group(0);
        if let Some((uid, gid)) = identity {
            // SAFETY: the closure performs only libc calls between fork and exec.
            unsafe {
                command.pre_exec(move || {
                    if libc::setgroups(0, std::ptr::null()) != 0
                        || libc::setresgid(gid, gid, gid) != 0
                        || libc::setresuid(uid, uid, uid) != 0
                        || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let mut child = command.spawn().map_err(|_| JournalError::Unavailable)?;
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return status.code().ok_or(JournalError::Unavailable),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                _ => {
                    unsafe {
                        libc::kill(-(child.id() as i32), libc::SIGKILL);
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(JournalError::Unavailable);
                }
            }
        }
    }
    fn systemctl(&self, args: &[&str]) -> Result<i32> {
        self.command(
            &self.options.systemctl,
            &args.iter().map(OsString::from).collect::<Vec<_>>(),
            None,
        )
    }
    fn require_systemctl(&self, args: &[&str]) -> Result<()> {
        if self.systemctl(args)? == 0 {
            Ok(())
        } else {
            Err(JournalError::Unavailable)
        }
    }
    fn checkpoint(&self) -> Result<()> {
        let o = &self.options;
        let args = vec![
            "--experimental".into(),
            "--db".into(),
            o.database.as_os_str().into(),
            "--core-binary".into(),
            o.core_binary.as_os_str().into(),
            "--core-pid-file".into(),
            o.core_pid_file.as_os_str().into(),
            "--core-api".into(),
            o.core_api.as_str().into(),
        ];
        if self.command(&o.checkpoint, &args, Some((o.panel_uid, o.panel_gid)))? == 0 {
            Ok(())
        } else {
            Err(JournalError::Unavailable)
        }
    }
    fn restart_dependents(&self) {
        let _ = self.systemctl(&[
            "start",
            &self.options.panel_unit,
            &self.options.monitor_unit,
        ]);
    }
    fn ready(&self) -> bool {
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, self.options.panel_port));
        let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_secs(1)) else {
            return false;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
        if stream
            .write_all(
                b"GET /internal/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .is_err()
        {
            return false;
        }
        let mut response = Vec::new();
        stream.take(1024).read_to_end(&mut response).is_ok()
            && response.starts_with(b"HTTP/1.1 200 ")
    }
    fn monitor_updated(&self, since: i64) -> bool {
        let Ok(bytes) = std::fs::read(&self.options.settings) else {
            return false;
        };
        if bytes.len() > 1024 * 1024 {
            return false;
        }
        let Ok(settings) = serde_json::from_slice(&bytes) else {
            return false;
        };
        let Ok(expected) = xcli_panel_monitor::status::expected(&settings) else {
            return false;
        };
        let Ok(now) = timestamp() else {
            return false;
        };
        let report = xcli_panel_monitor::status::read(&self.options.monitor_report, &expected, now);
        // A previously failing, unrelated residential exit must not undo an
        // otherwise valid import. The candidate itself was probed before
        // apply; the panel continues to expose each exit's latest result.
        report["scope"] == "server"
            && matches!(
                report["status"].as_str(),
                Some("healthy" | "failed" | "unknown")
            )
            && report["updated"]
                .as_i64()
                .is_some_and(|updated| updated > since)
    }
}
fn timestamp() -> Result<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JournalError::Unavailable)?
            .as_secs(),
    )
    .map_err(|_| JournalError::Unavailable)
}
impl Hooks for ServiceHooks {
    // Compose this hook with `Validated` to validate staged Xray/Nginx config.
    fn validate(&mut self, _: &Path) -> Result<()> {
        Ok(())
    }
    fn stop(&mut self) -> Result<()> {
        let o = &self.options;
        if self
            .require_systemctl(&["stop", &o.monitor_unit, &o.panel_unit])
            .is_err()
        {
            self.restart_dependents();
            return Err(JournalError::Unavailable);
        }
        match self.systemctl(&["is-active", "--quiet", &o.core_unit]) {
            Ok(0) => {
                if self.checkpoint().is_err() {
                    self.restart_dependents();
                    return Err(JournalError::Unavailable);
                }
            }
            Ok(3) => (),
            _ => {
                self.restart_dependents();
                return Err(JournalError::Unavailable);
            }
        }
        if self.require_systemctl(&["stop", &o.core_unit]).is_err() {
            self.restart_dependents();
            return Err(JournalError::Unavailable);
        }
        Ok(())
    }
    fn start_and_check(&mut self) -> Result<()> {
        let o = &self.options;
        let since = timestamp()?;
        self.require_systemctl(&["start", &o.core_unit])?;
        self.require_systemctl(&["start", &o.panel_unit])?;
        if self.command(&o.nginx, &["-t".into()], None)? != 0 {
            return Err(JournalError::Unavailable);
        }
        self.require_systemctl(&["reload", "nginx.service"])?;
        self.require_systemctl(&["start", &o.monitor_unit])?;
        let deadline = Instant::now() + o.health_timeout;
        while Instant::now() < deadline {
            if self.ready() && self.monitor_updated(since) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        Err(JournalError::Unavailable)
    }
}
