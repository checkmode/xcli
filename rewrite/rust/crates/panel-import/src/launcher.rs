//! Experimental root-to-unprivileged probe launcher for Linux. The production
//! service and installer are not yet connected to this component.
use crate::probe::{ProbeError, ProbeResult, Protocol};
use crate::vmess::{SecretJson, VmessProxy};
use crate::vmess_probe::VmessProbeResult;
use crate::{public_ipv4, Proxy};
use serde_json::json;
use std::fs;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const BINARY: &str = "/usr/local/lib/xcli/xcli-import-probe";
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
struct Slot;
impl Slot {
    fn acquire() -> Result<Self, ProbeError> {
        let mut current = ACTIVE.load(Ordering::Acquire);
        loop {
            if current >= 4 {
                return Err(ProbeError::Unavailable);
            }
            match ACTIVE.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(Self),
                Err(observed) => current = observed,
            }
        }
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::AcqRel);
    }
}
struct ChildGuard {
    child: Child,
    reaped: bool,
}
impl ChildGuard {
    fn stop(&mut self) {
        if !self.reaped {
            // SAFETY: the child created its own process group before exec.
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGKILL);
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.reaped = true;
        }
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.stop();
    }
}
pub(crate) fn trusted_binary(path: &Path) -> Result<PathBuf, ProbeError> {
    if !path.is_absolute() {
        return Err(ProbeError::Unavailable);
    }
    // Check the configured path as well as the resolved target: an
    // unprivileged writer must not choose what the fixed path resolves to.
    for (index, item) in path.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(item).map_err(|_| ProbeError::Unavailable)?;
        let symlink = metadata.file_type().is_symlink();
        if metadata.uid() != 0
            || !symlink && metadata.mode() & 0o022 != 0
            || index == 0 && !(metadata.is_file() || symlink)
            || index != 0 && !(metadata.is_dir() || symlink)
        {
            return Err(ProbeError::Unavailable);
        }
    }
    let binary = fs::canonicalize(path).map_err(|_| ProbeError::Unavailable)?;
    for (index, item) in binary.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(item).map_err(|_| ProbeError::Unavailable)?;
        if metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || index == 0 && (!metadata.is_file() || metadata.nlink() != 1)
            || index != 0 && !metadata.is_dir()
        {
            return Err(ProbeError::Unavailable);
        }
    }
    Ok(binary)
}
pub struct Launcher {
    binary: PathBuf,
    uid: u32,
    gid: u32,
}
impl Launcher {
    #[cfg(test)]
    pub(crate) fn fixture(binary: PathBuf, uid: u32, gid: u32) -> Self {
        Self { binary, uid, gid }
    }
    /// The executable is a fixed, root-owned installation path, never a path
    /// supplied by the web request. The target account must have no privilege.
    pub fn production(uid: u32, gid: u32) -> Result<Self, ProbeError> {
        if unsafe { libc::geteuid() } != 0 || uid == 0 || gid == 0 {
            return Err(ProbeError::Unavailable);
        }
        Ok(Self {
            binary: trusted_binary(Path::new(BINARY))?,
            uid,
            gid,
        })
    }
    /// Test-only layout under a root-owned /var/lib fixture. It cannot choose a
    /// helper from the panel's writable directory or from a production path.
    pub fn isolated_fixture(root: &Path, uid: u32, gid: u32) -> Result<Self, ProbeError> {
        if unsafe { libc::geteuid() } != 0
            || uid == 0
            || gid == 0
            || root.parent() != Some(Path::new("/var/lib"))
            || !root
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.starts_with("xcli-import-fixture-"))
            || fs::canonicalize(root).ok().as_deref() != Some(root)
        {
            return Err(ProbeError::Unavailable);
        }
        Ok(Self {
            binary: trusted_binary(&root.join("bin/xcli-import-probe"))?,
            uid,
            gid,
        })
    }
    pub fn fixed(&self, proxy: &Proxy, protocol: Protocol) -> Result<ProbeResult, ProbeError> {
        self.fixed_cancellable(proxy, protocol, None)
    }
    pub(crate) fn fixed_cancellable(
        &self,
        proxy: &Proxy,
        protocol: Protocol,
        stop: Option<&AtomicBool>,
    ) -> Result<ProbeResult, ProbeError> {
        if !public_ipv4(proxy.address) || proxy.port == 0 {
            return Err(ProbeError::InvalidExit);
        }
        let request = SecretJson::new(json!({"kind":"fixed","protocol":protocol.name(),"fields":{
            "address":proxy.address.to_string(),"port":proxy.port,"username":proxy.username(),"password":proxy.password()}}));
        let output = self.run(&request, Duration::from_secs(80), stop)?;
        parse(&output, false).map(|(result, _)| result)
    }
    pub fn vmess(&self, proxy: &VmessProxy) -> Result<VmessProbeResult, ProbeError> {
        self.vmess_cancellable(proxy, None)
    }
    pub(crate) fn vmess_cancellable(
        &self,
        proxy: &VmessProxy,
        stop: Option<&AtomicBool>,
    ) -> Result<VmessProbeResult, ProbeError> {
        let record = proxy.record();
        let request =
            SecretJson::new(json!({"kind":"vmess","protocol":"vmess","fields":record.as_value()}));
        let output = self.run(&request, Duration::from_secs(80), stop)?;
        let (observed, server_ip) = parse(&output, true)?;
        let server_ip = server_ip.ok_or(ProbeError::Unavailable)?;
        if proxy
            .address()
            .parse::<Ipv4Addr>()
            .is_ok_and(|ip| ip != server_ip)
        {
            return Err(ProbeError::InvalidExit);
        }
        Ok(VmessProbeResult {
            server_ip,
            observed,
        })
    }
    fn run(
        &self,
        request: &SecretJson,
        timeout: Duration,
        stop: Option<&AtomicBool>,
    ) -> Result<Zeroizing<Vec<u8>>, ProbeError> {
        if stop.is_some_and(|stop| stop.load(Ordering::Acquire)) {
            return Err(ProbeError::Unavailable);
        }
        let _slot = Slot::acquire()?;
        let mut bytes = Zeroizing::new(
            serde_json::to_vec(request.as_value()).map_err(|_| ProbeError::Unavailable)?,
        );
        if bytes.len() >= 20_000 {
            return Err(ProbeError::Unavailable);
        }
        bytes.push(b'\n');
        let uid = self.uid;
        let gid = self.gid;
        let parent = unsafe { libc::getpid() };
        let mut command = Command::new(&self.binary);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .current_dir("/")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/nonexistent");
        // SAFETY: only async-signal-safe syscalls and stack values are used
        // between fork and exec. No request data is put in arguments or env.
        unsafe {
            command.pre_exec(move || {
                let nofile = libc::rlimit { rlim_cur: 64, rlim_max: 64 };
                let core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                if libc::setpgid(0, 0) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) != 0
                    || libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0
                    || libc::setrlimit(libc::RLIMIT_NOFILE, &nofile) != 0
                    || libc::setrlimit(libc::RLIMIT_CORE, &core) != 0
                    || libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setresgid(gid, gid, gid) != 0
                    || libc::setresuid(uid, uid, uid) != 0
                    || libc::getuid() != uid || libc::geteuid() != uid
                    || libc::getgid() != gid || libc::getegid() != gid
                    || libc::getgroups(0, std::ptr::null_mut()) != 0
                    // Changing UID/GID clears PDEATHSIG, so set it only after
                    // the privilege drop and then recheck the parent race.
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::getppid() != parent {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = ChildGuard {
            child: command.spawn().map_err(|_| ProbeError::Unavailable)?,
            reaped: false,
        };
        let mut input = child.child.stdin.take().ok_or(ProbeError::Unavailable)?;
        let output = child.child.stdout.take().ok_or(ProbeError::Unavailable)?;
        let writer = std::thread::spawn(move || input.write_all(&bytes).is_ok());
        let reader = std::thread::spawn(move || {
            let mut bytes = Zeroizing::new(Vec::new());
            let ok = output.take(8193).read_to_end(&mut bytes).is_ok();
            (ok, bytes)
        });
        let deadline = Instant::now() + timeout;
        let status = loop {
            match child.child.try_wait() {
                Ok(Some(status)) => {
                    child.reaped = true;
                    break Some(status);
                }
                Ok(None)
                    if Instant::now() < deadline
                        && !stop.is_some_and(|stop| stop.load(Ordering::Acquire)) =>
                {
                    std::thread::sleep(Duration::from_millis(20))
                }
                _ => {
                    child.stop();
                    break None;
                }
            }
        };
        let wrote = writer.join().unwrap_or(false);
        let (read, bytes) = reader.join().map_err(|_| ProbeError::Unavailable)?;
        if status.is_none()
            && Instant::now() >= deadline
            && !stop.is_some_and(|stop| stop.load(Ordering::Acquire))
        {
            return Err(ProbeError::Timeout);
        }
        if !status.is_some_and(|value| value.success()) || !wrote || !read || bytes.len() > 8192 {
            return Err(ProbeError::Unavailable);
        }
        Ok(bytes)
    }
}
fn parse(bytes: &[u8], vmess: bool) -> Result<(ProbeResult, Option<Ipv4Addr>), ProbeError> {
    let protected = SecretJson::parse(bytes).map_err(|_| ProbeError::Unavailable)?;
    let value = protected.as_value();
    let map = value.as_object().ok_or(ProbeError::Unavailable)?;
    if value["ok"] == false && map.len() == 2 && map.contains_key("reason") {
        return Err(value["reason"]
            .as_str()
            .and_then(ProbeError::from_code)
            .unwrap_or(ProbeError::Unavailable));
    }
    let fields: &[&str] = if vmess {
        &[
            "ok",
            "exit_ip",
            "country",
            "https_ms",
            "doh_ms",
            "server_ip",
        ]
    } else {
        &["ok", "exit_ip", "country", "https_ms", "doh_ms"]
    };
    if map.len() != fields.len()
        || fields.iter().any(|field| !map.contains_key(*field))
        || value["ok"] != true
    {
        return Err(ProbeError::Unavailable);
    }
    let ip = |name: &str| {
        value[name]
            .as_str()
            .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
            .filter(|ip| public_ipv4(*ip))
            .ok_or(ProbeError::InvalidExit)
    };
    let exit_ip = ip("exit_ip")?;
    let server_ip = if vmess { Some(ip("server_ip")?) } else { None };
    let country = value["country"]
        .as_str()
        .filter(|country| country.len() == 2 && country.bytes().all(|c| c.is_ascii_uppercase()))
        .ok_or(ProbeError::InvalidExit)?
        .to_owned();
    let millis = |name: &str| {
        value[name]
            .as_u64()
            .filter(|value| *value <= 120_000)
            .ok_or(ProbeError::Unavailable)
    };
    Ok((
        ProbeResult {
            exit_ip,
            country,
            https_ms: millis("https_ms")?,
            doh_ms: millis("doh_ms")?,
        },
        server_ip,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn response_parser_rejects_private_extra_or_invalid_values() {
        let good = br#"{"ok":true,"exit_ip":"8.8.8.8","country":"US","https_ms":1,"doh_ms":2}"#;
        assert_eq!(parse(good, false).unwrap().0.exit_ip.to_string(), "8.8.8.8");
        assert!(matches!(
            parse(br#"{"ok":false,"reason":"invalid_dns"}"#, false),
            Err(ProbeError::InvalidDns)
        ));
        assert!(matches!(
            parse(br#"{"ok":false,"reason":"timeout"}"#, false),
            Err(ProbeError::Timeout)
        ));
        assert!(matches!(
            parse(br#"{"ok":false,"reason":"synthetic-secret"}"#, false),
            Err(ProbeError::Unavailable)
        ));
        for input in [
            br#"{"ok":true,"exit_ip":"127.0.0.1","country":"US","https_ms":1,"doh_ms":2}"#
                .as_slice(),
            br#"{"ok":true,"exit_ip":"8.8.8.8","country":"us","https_ms":1,"doh_ms":2}"#.as_slice(),
            br#"{"ok":true,"exit_ip":"8.8.8.8","country":"US","https_ms":1,"doh_ms":2,"extra":1}"#
                .as_slice(),
            br#"{"ok":false}"#.as_slice(),
        ] {
            assert!(parse(input, false).is_err());
        }
        assert!(parse(good, true).is_err());
    }

    // Deliberately opt in only in an isolated root test environment.
    #[test]
    fn launcher_drops_privileges_and_times_out_a_process_group() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let (Ok(uid), Ok(gid)) = (
            std::env::var("XCLI_TEST_PROBE_UID"),
            std::env::var("XCLI_TEST_PROBE_GID"),
        ) else {
            return;
        };
        let uid = uid.parse::<u32>().unwrap();
        let gid = gid.parse::<u32>().unwrap();
        assert_ne!(uid, 0);
        assert_ne!(gid, 0);
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let script = directory.path().join("probe");
        fs::write(
            &script,
            format!(
                r##"#!/bin/sh
IFS= read -r data || exit 2
[ "$(id -u)" = "{uid}" ] || exit 3
[ "$(id -g)" = "{gid}" ] || exit 4
[ "$(id -G)" = "{gid}" ] || exit 5
[ "$(awk '/^NoNewPrivs:/ {{print $2}}' /proc/self/status)" = 1 ] || exit 6
[ "$(awk '/^CapEff:/ {{print $2}}' /proc/self/status)" = 0000000000000000 ] || exit 7
[ "$HOME" = /nonexistent ] || exit 8
[ "$#" = 0 ] || exit 9
case "$data" in *'"password":"synthetic-only-password"'*) ;; *) exit 10;; esac
printf '%s\n' '{{"ok":true,"exit_ip":"8.8.8.8","country":"US","https_ms":1,"doh_ms":2}}'
"##
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(trusted_binary(&script).is_err()); // /tmp is not a trusted installation path.
        let launcher = Launcher {
            binary: script.clone(),
            uid,
            gid,
        };
        let proxy = crate::parse_fixed("1.1.1.1:80:fixture:synthetic-only-password").unwrap();
        let result = launcher.fixed(&proxy[0], Protocol::Socks).unwrap();
        assert_eq!(result.exit_ip.to_string(), "8.8.8.8");
        fs::write(&script, "#!/bin/sh\nIFS= read -r data\nsleep 10\n").unwrap();
        let request = SecretJson::new(json!({"fixture":"synthetic"}));
        let started = Instant::now();
        assert!(matches!(
            launcher.run(&request, Duration::from_millis(250), None),
            Err(ProbeError::Timeout)
        ));
        assert!(started.elapsed() < Duration::from_secs(3));
        let marker_dir = directory.path().join("cancel");
        fs::create_dir(&marker_dir).unwrap();
        fs::set_permissions(&marker_dir, fs::Permissions::from_mode(0o777)).unwrap();
        let marker = marker_dir.join("pids");
        let name = marker.to_str().unwrap();
        assert!(!name.contains('\''));
        fs::write(&script,format!("#!/bin/sh\nIFS= read -r data\nsleep 60 &\nchild=$!\nprintf '%s %s' \"$$\" \"$child\" > '{name}'\nwait\n")).unwrap();
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            struct CancelOnDrop<'a>(&'a AtomicBool);
            impl Drop for CancelOnDrop<'_> {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Release);
                }
            }
            let _cancel_on_panic = CancelOnDrop(&stop);
            let task = scope.spawn(|| launcher.run(&request, Duration::from_secs(60), Some(&stop)));
            let deadline = Instant::now() + Duration::from_secs(5);
            while !marker.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            let pids: Vec<u32> = fs::read_to_string(&marker)
                .unwrap()
                .split_whitespace()
                .map(|value| value.parse().unwrap())
                .collect();
            assert_eq!(pids.len(), 2);
            let started = Instant::now();
            stop.store(true, Ordering::Release);
            assert!(matches!(task.join().unwrap(), Err(ProbeError::Unavailable)));
            assert!(started.elapsed() < Duration::from_secs(3));
            for pid in pids {
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    let active = fs::read_to_string(format!("/proc/{pid}/status"))
                        .ok()
                        .is_some_and(|value| {
                            !value
                                .lines()
                                .any(|line| line.starts_with("State:") && line.contains('Z'))
                        });
                    if !active {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "cancelled probe process remained active"
                    );
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        });
        if let Ok(actual) = std::env::var("XCLI_TEST_IMPORT_HELPER") {
            let helper = Launcher {
                binary: PathBuf::from(&actual),
                uid,
                gid,
            };
            let invalid = SecretJson::new(json!({"kind":"fixed","protocol":"socks","fields":{
                "address":"127.0.0.1","port":1080,"username":"fixture","password":"synthetic-only-password"}}));
            let output = helper.run(&invalid, Duration::from_secs(5), None).unwrap();
            assert_eq!(output.as_slice(), b"{\"ok\":false}\n");
            let root = Command::new(actual)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output()
                .unwrap();
            assert!(!root.status.success());
            assert!(root.stdout.is_empty());
        }
    }

    #[test]
    fn root_parent_death_fixture() {
        let (Ok(path), Ok(uid), Ok(gid)) = (
            std::env::var("XCLI_TEST_PROBE_FIXTURE"),
            std::env::var("XCLI_TEST_PROBE_UID"),
            std::env::var("XCLI_TEST_PROBE_GID"),
        ) else {
            return;
        };
        let launcher = Launcher {
            binary: PathBuf::from(path),
            uid: uid.parse().unwrap(),
            gid: gid.parse().unwrap(),
        };
        let input = SecretJson::new(json!({"fixture":"synthetic"}));
        let _ = launcher.run(&input, Duration::from_secs(60), None);
    }

    #[test]
    fn privilege_dropped_helper_dies_with_its_parent() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let (Ok(uid), Ok(gid)) = (
            std::env::var("XCLI_TEST_PROBE_UID"),
            std::env::var("XCLI_TEST_PROBE_GID"),
        ) else {
            return;
        };
        assert_ne!(uid, "0");
        assert_ne!(gid, "0");
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let marker = dir.path().join("pid");
        let name = marker.to_str().unwrap();
        assert!(!name.contains('\''));
        let script = dir.path().join("probe");
        fs::write(
            &script,
            format!("#!/bin/sh\nprintf '%s' \"$$\" > '{name}'\nexec sleep 60\n"),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        struct Process(std::process::Child);
        impl Drop for Process {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut parent = Process(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "launcher::tests::root_parent_death_fixture",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("XCLI_TEST_PROBE_FIXTURE", &script)
                .env("XCLI_TEST_PROBE_UID", uid)
                .env("XCLI_TEST_PROBE_GID", gid)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !marker.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let pid: u32 = fs::read_to_string(&marker).unwrap().parse().unwrap();
        parent.0.kill().unwrap();
        parent.0.wait().unwrap();
        let status = format!("/proc/{pid}/status");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let active = fs::read_to_string(&status).ok().is_some_and(|value| {
                !value
                    .lines()
                    .any(|line| line.starts_with("State:") && line.contains('Z'))
            });
            if !active {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "probe remained active after its parent exited"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
