//! Experimental validation of staged configuration; no service is started.
use crate::journal::{atomic, check_private_dir, private_meta, read, Hooks, JournalError};
use crate::launcher::trusted_binary;
use std::ffi::OsString;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const INCLUDE: &str = "include /etc/nginx/xcli-import-locations.conf;";
const MAX_FILE: u64 = 4 * 1024 * 1024;
type Result<T> = std::result::Result<T, JournalError>;

pub struct Validator {
    xray: PathBuf,
    nginx: PathBuf,
}
/// Compose validation with the caller's quiesce and health-check hooks.
pub struct Validated<H> {
    pub validator: Validator,
    pub inner: H,
}
impl<H: Hooks> Hooks for Validated<H> {
    fn validate(&mut self, stage: &Path) -> Result<()> {
        self.validator.validate(stage)?;
        self.inner.validate(stage)
    }
    fn stop(&mut self) -> Result<()> {
        self.inner.stop()
    }
    fn start_and_check(&mut self) -> Result<()> {
        self.inner.start_and_check()
    }
    fn after_write(&mut self, key: &str) -> Result<()> {
        self.inner.after_write(key)
    }
}
impl Validator {
    pub fn production() -> Result<Self> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(JournalError::Unavailable);
        }
        Ok(Self {
            xray: trusted_binary(Path::new("/usr/local/lib/xcli/xray"))
                .map_err(|_| JournalError::Unavailable)?,
            nginx: trusted_binary(Path::new("/usr/sbin/nginx"))
                .map_err(|_| JournalError::Unavailable)?,
        })
    }
    /// Called by a transaction hook on the private stage directory before any
    /// writers are stopped or production files are replaced.
    pub fn validate(&self, stage: &Path) -> Result<()> {
        check_private_dir(stage)?;
        let stage = fs::canonicalize(stage).map_err(|_| JournalError::Unavailable)?;
        stage
            .to_str()
            .filter(|path| {
                path.starts_with('/')
                    && path
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"/._-".contains(&c))
            })
            .ok_or(JournalError::Invalid)?;
        let core = stage.join("new.core");
        let nginx = read(&stage.join("new.nginx"), MAX_FILE)?.ok_or(JournalError::Invalid)?;
        let locations =
            read(&stage.join("new.locations"), MAX_FILE)?.ok_or(JournalError::Invalid)?;
        let core_state = read(&core, MAX_FILE)?.ok_or(JournalError::Invalid)?;
        for file in [&nginx, &locations, &core_state] {
            if file.meta.uid != unsafe { libc::geteuid() } || file.meta.mode & 0o077 != 0 {
                return Err(JournalError::Unavailable);
            }
        }
        let text = std::str::from_utf8(&nginx.data).map_err(|_| JournalError::Invalid)?;
        let count = text.matches(INCLUDE).count();
        if count == 0 && !locations.data.is_empty() {
            return Err(JournalError::Invalid);
        }
        let replacement = format!("include {};", stage.join("new.locations").display());
        let candidate = Zeroizing::new(if count > 0 {
            text.replace(INCLUDE, &replacement)
        } else {
            text.to_owned()
        });
        let test_core = stage.join("validator.core.json");
        let test_nginx = stage.join("validator.nginx");
        if read(&test_core, MAX_FILE)?.is_some() || read(&test_nginx, MAX_FILE)?.is_some() {
            return Err(JournalError::Conflict);
        }
        struct Scratch(Vec<PathBuf>);
        impl Drop for Scratch {
            fn drop(&mut self) {
                for file in &self.0 {
                    let _ = fs::remove_file(file);
                }
            }
        }
        let mut scratch = Scratch(Vec::new());
        // Xray's config loader still requires the .json suffix even when the
        // format is explicitly set, so validate a private staged copy.
        atomic(&test_core, &core_state.data, &private_meta())?;
        scratch.0.push(test_core.clone());
        atomic(&test_nginx, candidate.as_bytes(), &private_meta())?;
        scratch.0.push(test_nginx.clone());
        run(
            &self.xray,
            &[
                "run".into(),
                "-test".into(),
                "-format".into(),
                "json".into(),
                "-config".into(),
                test_core.into_os_string(),
            ],
            Duration::from_secs(30),
        )?;
        run(
            &self.nginx,
            &["-t".into(), "-c".into(), test_nginx.into_os_string()],
            Duration::from_secs(30),
        )
    }
}
fn run(binary: &Path, args: &[OsString], timeout: Duration) -> Result<()> {
    let parent = unsafe { libc::getpid() };
    let mut command = Command::new(binary);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent");
    // SAFETY: only async-signal-safe syscalls and stack values are used here.
    unsafe {
        command.pre_exec(move || {
            let core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setpgid(0, 0) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::setrlimit(libc::RLIMIT_CORE, &core) != 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                || libc::getppid() != parent
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|_| JournalError::Unavailable)?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err(JournalError::Invalid)
                }
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                // SAFETY: the child successfully created a dedicated process group.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn put(dir: &Path, name: &str, bytes: &[u8]) {
        fs::write(dir.join(name), bytes).unwrap();
        fs::set_permissions(dir.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[test]
    fn staged_validator_uses_real_xray_and_nginx_when_available() {
        let (Ok(xray), Ok(nginx)) = (
            std::env::var("XCLI_TEST_XRAY"),
            std::env::var("XCLI_TEST_NGINX"),
        ) else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let core=br#"{"inbounds":[{"listen":"127.0.0.1","port":12080,"protocol":"socks","settings":{"auth":"noauth","udp":false}}],"outbounds":[{"protocol":"freedom"}]}"#;
        let config=format!("error_log {}/error.log;\npid {}/nginx.pid;\nevents {{}}\nhttp {{ access_log off; server {{ listen 127.0.0.1:18090; {INCLUDE} }} }}\n",dir.path().display(),dir.path().display());
        put(dir.path(), "new.core", core);
        put(dir.path(), "new.nginx", config.as_bytes());
        put(
            dir.path(),
            "new.locations",
            b"location = /fixture { proxy_pass http://127.0.0.1:10450; }",
        );
        let validator = Validator {
            xray: xray.into(),
            nginx: nginx.into(),
        };
        assert!(check_private_dir(dir.path()).is_ok());
        assert!(read(&dir.path().join("new.core"), MAX_FILE)
            .unwrap()
            .is_some());
        let manual = dir.path().join("manual.conf");
        fs::write(
            &manual,
            config.replace(
                INCLUDE,
                &format!("include {};", dir.path().join("new.locations").display()),
            ),
        )
        .unwrap();
        let output = Command::new(&validator.nginx)
            .args(["-t", "-c"])
            .arg(&manual)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "synthetic Nginx configuration rejected: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        fs::remove_file(manual).unwrap();
        assert_eq!(validator.validate(dir.path()), Ok(()));
        assert!(!dir.path().join("validator.nginx").exists());
        assert!(!dir.path().join("validator.core.json").exists());
        assert_eq!(
            fs::read(dir.path().join("new.nginx")).unwrap(),
            config.as_bytes()
        );
        // The same imported locations can be used by two distinct TLS sites.
        // Validate both references against the staged file, not the live one.
        let two_sites = format!(
            "error_log {}/error.log;\npid {}/nginx.pid;\nevents {{}}\nhttp {{ access_log off; server {{ listen 127.0.0.1:18090; {INCLUDE} }} server {{ listen 127.0.0.1:18091; {INCLUDE} }} }}\n",
            dir.path().display(),
            dir.path().display()
        );
        put(dir.path(), "new.nginx", two_sites.as_bytes());
        assert_eq!(validator.validate(dir.path()), Ok(()));
        put(dir.path(), "new.core", b"{broken");
        assert_eq!(validator.validate(dir.path()), Err(JournalError::Invalid));
        assert!(!dir.path().join("validator.nginx").exists());
        assert!(!dir.path().join("validator.core.json").exists());
        put(dir.path(), "new.core", core);
        put(dir.path(), "new.locations", b"bad directive here;");
        assert_eq!(validator.validate(dir.path()), Err(JournalError::Invalid));
        assert!(!dir.path().join("validator.nginx").exists());
        put(
            dir.path(),
            "new.nginx",
            format!("{config}\n{INCLUDE}").as_bytes(),
        );
        assert_eq!(validator.validate(dir.path()), Err(JournalError::Invalid));
    }
    #[test]
    fn validator_times_out_and_reaps_a_stalled_process() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("stall");
        fs::write(&script, b"#!/bin/sh\nexec sleep 10\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let started = Instant::now();
        assert_eq!(
            run(&script, &[], Duration::from_millis(200)),
            Err(JournalError::Unavailable)
        );
        assert!(started.elapsed() < Duration::from_secs(3));
    }
    #[test]
    fn real_validator_precedes_any_transaction_stop() {
        use crate::config::{add_fixed, Verified};
        use crate::journal::{Candidate, Store};
        use crate::probe::{ProbeResult, Protocol};
        use serde_json::json;
        use std::collections::BTreeMap;
        let (Ok(xray), Ok(nginx)) = (
            std::env::var("XCLI_TEST_XRAY"),
            std::env::var("XCLI_TEST_NGINX"),
        ) else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("journal");
        let etc = dir.path().join("etc");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&etc).unwrap();
        fs::set_permissions(&etc, fs::Permissions::from_mode(0o700)).unwrap();
        let settings =
            json!({"public_ip":"8.8.8.8","ws_path":"/connect/fixture","residential_exits":[]});
        let core = json!({"inbounds":[{"tag":"reality","listen":"127.0.0.1","port":12080,"protocol":"socks","settings":{"auth":"noauth","udp":false}}],
            "outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"blocked","protocol":"blackhole"}],
            "routing":{"rules":[{"inboundTag":["reality"],"outboundTag":"direct"}]}});
        let monitor = json!({"residential_exits":[]});
        let config=format!("error_log {}/error.log;\npid {}/nginx.pid;\nevents {{}}\nhttp {{ access_log off; map $http_upgrade $connection_upgrade {{ default upgrade; \"\" close; }} server {{ listen 127.0.0.1:18090; location = /connect/fixture {{ return 204; }} }} }}\n",dir.path().display(),dir.path().display());
        for (key, value) in [
            ("settings", serde_json::to_vec(&settings).unwrap()),
            ("core", serde_json::to_vec(&core).unwrap()),
            ("monitor", serde_json::to_vec(&monitor).unwrap()),
            ("nginx", config.into_bytes()),
        ] {
            put(&etc, key, &value);
        }
        let keys = ["settings", "core", "monitor", "nginx", "locations", "pool"];
        let paths: BTreeMap<_, _> = keys
            .iter()
            .map(|key| (key.to_string(), etc.join(key)))
            .collect();
        let store = Store::open(&root, &root.join("update.lock"), paths).unwrap();
        let (files, snapshot) = store.load().unwrap();
        let proxy = crate::parse_fixed("1.1.1.1:80:fixture:synthetic-password").unwrap();
        let probe = ProbeResult {
            exit_ip: "8.8.8.8".parse().unwrap(),
            country: "US".into(),
            https_ms: 1,
            doh_ms: 1,
        };
        let input = [Verified {
            proxy: &proxy[0],
            protocol: Protocol::Socks,
            result: &probe,
        }];
        let (files, _) = add_fixed(files, &input, "fixture").unwrap();
        struct FakeHooks {
            stopped: usize,
            started: usize,
        }
        impl Hooks for FakeHooks {
            fn validate(&mut self, _: &Path) -> Result<()> {
                Ok(())
            }
            fn stop(&mut self) -> Result<()> {
                self.stopped += 1;
                Ok(())
            }
            fn start_and_check(&mut self) -> Result<()> {
                self.started += 1;
                Ok(())
            }
        }
        let mut hooks = Validated {
            validator: Validator {
                xray: xray.into(),
                nginx: nginx.into(),
            },
            inner: FakeHooks {
                stopped: 0,
                started: 0,
            },
        };
        store
            .apply(
                &snapshot,
                &Candidate::from_files(&files).unwrap(),
                &mut hooks,
            )
            .unwrap();
        assert_eq!((hooks.inner.stopped, hooks.inner.started), (1, 1));
        let snapshot = store.snapshot().unwrap();
        let mut invalid: BTreeMap<_, _> = keys
            .iter()
            .map(|key| (key.to_string(), fs::read(etc.join(key)).unwrap()))
            .collect();
        invalid.insert("core".into(), b"{broken".to_vec());
        assert_eq!(
            store.apply(&snapshot, &Candidate::new(invalid).unwrap(), &mut hooks),
            Err(JournalError::Invalid)
        );
        assert_eq!((hooks.inner.stopped, hooks.inner.started), (1, 1));
        assert_eq!(store.snapshot().unwrap(), snapshot);
    }
}
