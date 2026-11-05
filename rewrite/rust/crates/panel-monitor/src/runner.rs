//! Experimental bounded self-test runner, not a production daemon.
use crate::report::{Dns, Observation, Outcome};
use crate::{requests, udp, Config, Invalid, SocksAuth};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

trait Probes: Sync {
    fn check(&self, port: u16, auth: &SocksAuth, expected: Ipv4Addr, residential: bool) -> Outcome;
}
struct PublicProbes;
impl Probes for PublicProbes {
    fn check(&self, port: u16, auth: &SocksAuth, expected: Ipv4Addr, residential: bool) -> Outcome {
        let https = requests::https(port, auth, expected);
        let dns = if residential {
            requests::doh(port, auth)
        } else {
            udp::dns(port, auth).map_or(Dns::Failed, Dns::Ok)
        };
        Outcome::Measured { https, dns }
    }
}
struct Process {
    child: Child,
    reaped: bool,
}
impl Process {
    fn exited(&mut self) -> Result<bool, Invalid> {
        if self.child.try_wait().map_err(|_| Invalid)?.is_some() {
            self.reaped = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
fn trusted_binary(path: &Path) -> Result<PathBuf, Invalid> {
    if !path.is_absolute() {
        return Err(Invalid);
    }
    for (index, item) in path.ancestors().enumerate() {
        let meta = std::fs::symlink_metadata(item).map_err(|_| Invalid)?;
        let link = meta.file_type().is_symlink();
        if meta.uid() != 0
            || !link && meta.mode() & 0o022 != 0
            || index == 0 && !(meta.is_file() || link)
            || index != 0 && !(meta.is_dir() || link)
        {
            return Err(Invalid);
        }
    }
    let path = std::fs::canonicalize(path).map_err(|_| Invalid)?;
    for (index, item) in path.ancestors().enumerate() {
        let meta = std::fs::symlink_metadata(item).map_err(|_| Invalid)?;
        if meta.uid() != 0
            || meta.mode() & 0o022 != 0
            || index == 0 && (!meta.is_file() || meta.nlink() != 1)
            || index != 0 && !meta.is_dir()
        {
            return Err(Invalid);
        }
    }
    Ok(path)
}
pub struct Runner {
    xray: PathBuf,
}
impl Runner {
    /// The installed binary is fixed and root-owned. The daemon itself must
    /// run as an unprivileged, resource-limited account.
    pub fn production() -> Result<Self, Invalid> {
        if unsafe { libc::geteuid() } == 0 {
            return Err(Invalid);
        }
        Ok(Self {
            xray: trusted_binary(Path::new("/usr/local/lib/xcli/xray"))?,
        })
    }
    pub fn run_once(
        &self,
        config: &Config,
        stop: &AtomicBool,
    ) -> Result<Vec<Observation>, Invalid> {
        self.run_with(config, stop, &PublicProbes)
    }
    fn run_with(
        &self,
        config: &Config,
        stop: &AtomicBool,
        probes: &dyn Probes,
    ) -> Result<Vec<Observation>, Invalid> {
        let mut observations = Vec::new();
        for chunk in config.kinds().chunks(4) {
            if stop.load(Ordering::Acquire) {
                return Err(Invalid);
            }
            let batch = std::thread::scope(|scope| {
                let tasks: Vec<_> = chunk
                    .iter()
                    .map(|kind| {
                        scope.spawn(move || {
                            let outcome = self
                                .one(config, kind, probes)
                                .unwrap_or(Outcome::ClientUnavailable);
                            Observation {
                                kind: kind.clone(),
                                outcome,
                                finished_at: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .ok()
                                    .and_then(|value| i64::try_from(value.as_secs()).ok()),
                            }
                        })
                    })
                    .collect();
                tasks
                    .into_iter()
                    .map(|task| task.join().map_err(|_| Invalid))
                    .collect::<Result<Vec<_>, _>>()
            })?;
            observations.extend(batch);
        }
        if stop.load(Ordering::Acquire) {
            return Err(Invalid);
        }
        Ok(observations)
    }
    fn one(&self, config: &Config, kind: &str, probes: &dyn Probes) -> Result<Outcome, Invalid> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| Invalid)?;
        let port = listener.local_addr().map_err(|_| Invalid)?.port();
        drop(listener);
        let auth = SocksAuth::random()?;
        let settings = config.client_secured(kind, port, &auth)?;
        let data = Zeroizing::new(serde_json::to_vec(settings.as_value()).map_err(|_| Invalid)?);
        let mut command = Command::new(&self.xray);
        command
            .args(["run", "-config", "stdin:"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/nonexistent")
            .env("GOMAXPROCS", "2");
        #[cfg(target_os = "linux")]
        {
            let parent = unsafe { libc::getpid() };
            // SAFETY: only async-signal-safe system calls are used after fork.
            unsafe {
                command.pre_exec(move || {
                    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                        || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                        || libc::getppid() != parent
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let mut child = Process {
            child: command.spawn().map_err(|_| Invalid)?,
            reaped: false,
        };
        child
            .child
            .stdin
            .take()
            .ok_or(Invalid)?
            .write_all(&data)
            .map_err(|_| Invalid)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while !authenticated(port, &auth) {
            if child.exited()? || Instant::now() >= deadline {
                return Err(Invalid);
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        Ok(probes.check(
            port,
            &auth,
            config.expected_exit(kind)?,
            config.residential(kind),
        ))
    }
}
fn authenticated(port: u16, auth: &SocksAuth) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(
        &(Ipv4Addr::LOCALHOST, port).into(),
        Duration::from_millis(200),
    ) else {
        return false;
    };
    if stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .is_err()
        || stream
            .set_write_timeout(Some(Duration::from_millis(200)))
            .is_err()
    {
        return false;
    }
    if stream.write_all(&[5, 1, 2]).is_err() {
        return false;
    }
    let mut response = [0u8; 2];
    if stream.read_exact(&mut response).is_err() || response != [5, 2] {
        return false;
    }
    let user = auth.username.as_bytes();
    let password = auth.password.as_bytes();
    if user.is_empty() || user.len() > 255 || password.is_empty() || password.len() > 255 {
        return false;
    }
    let mut data = Zeroizing::new(Vec::with_capacity(user.len() + password.len() + 3));
    data.extend_from_slice(&[1, user.len() as u8]);
    data.extend_from_slice(user);
    data.push(password.len() as u8);
    data.extend_from_slice(password);
    stream.write_all(&data).is_ok()
        && stream.read_exact(&mut response).is_ok()
        && response == [1, 0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Dns, Https};
    use serde_json::json;
    use std::sync::{atomic::AtomicUsize, Mutex};
    struct FakeProbes {
        active: AtomicUsize,
        peak: AtomicUsize,
        ports: Mutex<Vec<u16>>,
    }
    impl Probes for FakeProbes {
        fn check(&self, port: u16, auth: &SocksAuth, expected: Ipv4Addr, _: bool) -> Outcome {
            assert!(authenticated(port, auth));
            assert!([Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(1, 1, 1, 1)].contains(&expected));
            self.ports.lock().unwrap().push(port);
            let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
            self.peak.fetch_max(active, Ordering::AcqRel);
            std::thread::sleep(Duration::from_millis(100));
            self.active.fetch_sub(1, Ordering::AcqRel);
            Outcome::Measured {
                https: Https::Ok(1),
                dns: Dns::Ok(2),
            }
        }
    }
    #[test]
    fn real_xray_runner_bounds_concurrency_authenticates_and_reaps_children() {
        let Ok(xray) = std::env::var("XCLI_TEST_XRAY") else {
            return;
        };
        let key = Command::new(&xray).arg("x25519").output().unwrap();
        assert!(key.status.success());
        let text = String::from_utf8(key.stdout).unwrap();
        let public = text
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| ["Password (PublicKey)", "Password", "PublicKey"].contains(name))
            .map(|(_, value)| value.trim())
            .unwrap();
        let exits: Vec<_> = (27..33)
            .map(|number| {
                json!({"tag":format!("residential-{number:02}"),"exit_ip":"1.1.1.1",
            "ws_path":format!("/connect/fixture/residential-{number:02}")})
            })
            .collect();
        let settings = json!({"domain":"panel.example.com","public_ip":"8.8.8.8","reality_sni":"example.com",
            "reality_public":public,"short_id":"0123456789abcdef","uuid":"11111111-2222-3333-4444-555555555555",
            "ws_path":"/connect/fixture","residential_exits":exits});
        let config = Config::parse(&serde_json::to_vec(&settings).unwrap()).unwrap();
        let runner = Runner { xray: xray.into() };
        let stop = AtomicBool::new(false);
        let probes = FakeProbes {
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            ports: Mutex::new(Vec::new()),
        };
        let result = runner.run_with(&config, &stop, &probes).unwrap();
        assert_eq!(result.len(), 8);
        assert!(result.iter().all(|item| matches!(
            item.outcome,
            Outcome::Measured {
                https: Https::Ok(_),
                dns: Dns::Ok(_)
            }
        )));
        assert!((2..=4).contains(&probes.peak.load(Ordering::Acquire)));
        assert!(probes
            .ports
            .lock()
            .unwrap()
            .iter()
            .all(|port| TcpStream::connect((Ipv4Addr::LOCALHOST, *port)).is_err()));
        stop.store(true, Ordering::Release);
        assert!(runner.run_with(&config, &stop, &probes).is_err());
        stop.store(false, Ordering::Release);
        let missing = Runner {
            xray: PathBuf::from("/nonexistent/xcli-test-xray"),
        };
        let failed = missing.run_with(&config, &stop, &probes).unwrap();
        assert!(failed
            .iter()
            .all(|item| matches!(item.outcome, Outcome::ClientUnavailable)));
    }
}
