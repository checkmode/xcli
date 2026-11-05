//! Pin and verify the supervised Xray process before revoking connections.
use std::path::{Path, PathBuf};
use xcli_panel_controller::Error;

pub struct ProcessIdentity {
    binary: PathBuf,
    pid_file: PathBuf,
}

impl ProcessIdentity {
    pub fn new(binary: &Path, pid_file: &Path) -> Result<Self, Error> {
        let binary = std::fs::canonicalize(binary).map_err(|_| Error::CoreUnavailable)?;
        if !binary.is_file() || !pid_file.is_absolute() {
            return Err(Error::InvalidState);
        }
        Ok(Self {
            binary,
            pid_file: pid_file.to_owned(),
        })
    }

    #[cfg(target_os = "linux")]
    pub fn generation(&self) -> Result<String, Error> {
        use std::os::unix::ffi::OsStrExt;
        let cgroup = known_core_cgroup(&self.pid_file);
        let ids = read_limited(&self.pid_file, 65536)?;
        let ids = std::str::from_utf8(&ids).map_err(|_| Error::CoreUnavailable)?;
        for pid in ids
            .split_whitespace()
            .filter_map(|part| part.parse::<i32>().ok())
            .filter(|pid| *pid > 1)
        {
            let proc = PathBuf::from("/proc").join(pid.to_string());
            match std::fs::canonicalize(proc.join("exe")) {
                Ok(executable) if executable == self.binary => {}
                Err(error)
                    if error.kind() == std::io::ErrorKind::PermissionDenied && cgroup.is_some() =>
                {
                    if read_limited(&proc.join("cgroup"), 8192).ok().as_deref() != cgroup {
                        continue;
                    }
                    let command = match read_limited(&proc.join("cmdline"), 65536) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let program = command
                        .split(|byte| *byte == 0)
                        .next()
                        .map(|bytes| Path::new(std::ffi::OsStr::from_bytes(bytes)));
                    if program
                        .and_then(|path| std::fs::canonicalize(path).ok())
                        .as_ref()
                        != Some(&self.binary)
                    {
                        continue;
                    }
                    let status = match read_limited(&proc.join("status"), 16384) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let Ok(status) = std::str::from_utf8(&status) else {
                        continue;
                    };
                    // SAFETY: getuid takes no arguments and has no memory side effects.
                    let uid = unsafe { libc::getuid() };
                    let values = status
                        .lines()
                        .find_map(|line| line.strip_prefix("Uid:"))
                        .map(|line| {
                            line.split_whitespace()
                                .take(4)
                                .filter_map(|part| part.parse::<libc::uid_t>().ok())
                                .collect::<Vec<_>>()
                        });
                    if !values.is_some_and(|values| {
                        values.len() == 4 && values.into_iter().all(|value| value == uid)
                    }) {
                        continue;
                    }
                }
                _ => continue,
            }
            let stat = read_limited(&proc.join("stat"), 8192)?;
            let stat = std::str::from_utf8(&stat).map_err(|_| Error::CoreUnavailable)?;
            let end = stat.rfind(')').ok_or(Error::CoreUnavailable)?;
            let start = stat
                .get(end + 1..)
                .ok_or(Error::CoreUnavailable)?
                .split_whitespace()
                .nth(19)
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or(Error::CoreUnavailable)?;
            return Ok(format!("{pid}:{start}"));
        }
        Err(Error::CoreUnavailable)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn generation(&self) -> Result<String, Error> {
        let _ = (&self.binary, &self.pid_file);
        Err(Error::CoreUnavailable)
    }

    #[cfg(target_os = "linux")]
    pub fn restart(&self, expected: &str) -> Result<(), Error> {
        use std::os::fd::{FromRawFd, OwnedFd};
        if self.generation()? != expected {
            return Err(Error::CoreChanged);
        }
        let pid = expected
            .split_once(':')
            .and_then(|(pid, _)| pid.parse::<i32>().ok())
            .filter(|pid| *pid > 1)
            .ok_or(Error::InvalidState)?;
        // SAFETY: pidfd_open takes an integer PID and flags; the returned fd is
        // owned exactly once and closed by OwnedFd on every path.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
        if fd < 0 {
            return Err(Error::CoreUnavailable);
        }
        // SAFETY: fd is the successful, uniquely owned result of pidfd_open.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        if self.generation()? != expected {
            return Err(Error::CoreChanged);
        }
        // SAFETY: the pidfd pins the checked process; null siginfo is allowed.
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                std::os::fd::AsRawFd::as_raw_fd(&owned),
                libc::SIGTERM,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        } < 0
        {
            return Err(Error::CoreUnavailable);
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    pub fn restart(&self, _: &str) -> Result<(), Error> {
        Err(Error::CoreUnavailable)
    }
}

#[cfg(target_os = "linux")]
fn known_core_cgroup(path: &Path) -> Option<&'static [u8]> {
    match path.to_str()? {
        "/sys/fs/cgroup/system.slice/xray-gateway-core.service/cgroup.procs" => {
            Some(b"0::/system.slice/xray-gateway-core.service\n")
        }
        "/sys/fs/cgroup/system.slice/xcli-core.service/cgroup.procs" => {
            Some(b"0::/system.slice/xcli-core.service\n")
        }
        _ => None,
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn supports_existing_and_new_core_service_names() {
        for name in ["xray-gateway-core.service", "xcli-core.service"] {
            let path = format!("/sys/fs/cgroup/system.slice/{name}/cgroup.procs");
            assert_eq!(
                known_core_cgroup(Path::new(&path)),
                Some(format!("0::/system.slice/{name}\n").as_bytes())
            );
        }
        assert!(known_core_cgroup(Path::new("/tmp/cgroup.procs")).is_none());
    }
}

#[cfg(target_os = "linux")]
fn read_limited(path: &Path, maximum: usize) -> Result<Vec<u8>, Error> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|_| Error::CoreUnavailable)?;
    let mut data = Vec::new();
    file.take((maximum + 1) as u64)
        .read_to_end(&mut data)
        .map_err(|_| Error::CoreUnavailable)?;
    if data.len() > maximum {
        return Err(Error::CoreUnavailable);
    }
    Ok(data)
}
