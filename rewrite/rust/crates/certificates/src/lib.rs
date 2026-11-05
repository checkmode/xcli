//! Experimental certificate/key validation and single-file publication.
//! This does not choose production paths or replace renewal hooks.
pub mod bundle;
pub mod renewal;

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const CERT_LIMIT: usize = 256 * 1024;
const KEY_LIMIT: usize = 64 * 1024;
const OUTPUT_LIMIT: usize = 16 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    Invalid,
    Unavailable,
}
type Result<T> = std::result::Result<T, VerifyError>;
#[derive(Clone, Copy)]
enum Identity {
    Current,
    #[cfg(target_os = "linux")]
    Dropped {
        uid: u32,
        gid: u32,
    },
}

fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.is_ascii()
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

struct Process(Child);
impl Process {
    fn kill_group(&mut self) {
        // The child runs in its own process group. This also releases pipes
        // retained by normal descendants of a stuck validator.
        unsafe { libc::kill(-(self.0.id() as i32), libc::SIGKILL) };
        let _ = self.0.kill();
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            self.kill_group();
            let _ = self.0.wait();
        }
    }
}
#[cfg(all(test, target_os = "linux"))]
fn command(binary: &Path, args: &[&str], input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    command_with(binary, args, input, Identity::Current)
}
fn command_with(
    binary: &Path,
    args: &[&str],
    input: &[u8],
    identity: Identity,
) -> Result<Zeroizing<Vec<u8>>> {
    if !binary.is_absolute() {
        return Err(VerifyError::Unavailable);
    }
    let mut command = Command::new(binary);
    command
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(target_os = "linux")]
    if let Identity::Dropped { uid, gid } = identity {
        if unsafe { libc::geteuid() } != 0 || uid == 0 || gid == 0 {
            return Err(VerifyError::Unavailable);
        }
        // SAFETY: only async-signal-safe system calls run between fork and
        // exec. The validator receives key bytes only after privilege drop.
        unsafe {
            command.pre_exec(move || {
                let core = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) != 0
                    || libc::prctl(
                        libc::PR_CAP_AMBIENT,
                        libc::PR_CAP_AMBIENT_CLEAR_ALL,
                        0,
                        0,
                        0,
                    ) != 0
                    || libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setresgid(gid, gid, gid) != 0
                    || libc::setresuid(uid, uid, uid) != 0
                    || libc::geteuid() != uid
                    || libc::getegid() != gid
                    || libc::getgroups(0, std::ptr::null_mut()) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = identity;
    let mut child = Process(command.spawn().map_err(|_| VerifyError::Unavailable)?);
    let mut stdin = child.0.stdin.take().ok_or(VerifyError::Unavailable)?;
    let stdout = child.0.stdout.take().ok_or(VerifyError::Unavailable)?;
    let data = Zeroizing::new(input.to_vec());
    let (write_tx, write_rx) = mpsc::sync_channel(1);
    let (read_tx, read_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = write_tx.send(stdin.write_all(&data).is_ok());
    });
    std::thread::spawn(move || {
        let mut bytes = Zeroizing::new(Vec::new());
        let read = stdout
            .take((OUTPUT_LIMIT + 1) as u64)
            .read_to_end(&mut bytes);
        let _ = read_tx.send((read.is_ok(), bytes));
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    // Do not reap the group leader until both pipes close. While its PID is
    // still reserved, a timeout can safely signal its process group even if a
    // descendant inherited a pipe after the validator itself exited.
    let wrote = write_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    let read = read_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    let (Ok(wrote), Ok((read, bytes))) = (wrote, read) else {
        child.kill_group();
        let _ = child.0.wait();
        return Err(VerifyError::Unavailable);
    };
    let status = loop {
        match child.0.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                child.kill_group();
                let _ = child.0.wait();
                break None;
            }
        }
    };
    if !wrote || !read || bytes.len() > OUTPUT_LIMIT || status.is_none() {
        return Err(VerifyError::Unavailable);
    }
    if !status.is_some_and(|value| value.success()) {
        return Err(VerifyError::Invalid);
    }
    Ok(bytes)
}

/// Check a certificate's hostname, at least 24 hours of validity, and the
/// matching private key. The caller provides already-read, bounded bytes; the
/// private key is passed over a pipe and never appears in argv or log output.
/// Production integration must still pin trusted source paths, protect memory
/// and publish both files with a verified crash/reload strategy.
pub fn validate(domain: &str, certificate: &[u8], private_key: &[u8]) -> Result<()> {
    #[cfg(target_os = "linux")]
    if unsafe { libc::geteuid() } == 0 {
        return Err(VerifyError::Unavailable);
    }
    validate_with(
        Path::new("/usr/bin/openssl"),
        domain,
        certificate,
        private_key,
        Identity::Current,
    )
}
/// A privileged Linux caller must choose a dedicated unprivileged identity;
/// supplemental groups are cleared before the validator sees the key.
#[cfg(target_os = "linux")]
pub fn validate_dropped(
    domain: &str,
    certificate: &[u8],
    private_key: &[u8],
    uid: u32,
    gid: u32,
) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 || uid == 0 || gid == 0 {
        return Err(VerifyError::Unavailable);
    }
    validate_with(
        Path::new("/usr/bin/openssl"),
        domain,
        certificate,
        private_key,
        Identity::Dropped { uid, gid },
    )
}
fn validate_with(
    binary: &Path,
    domain: &str,
    certificate: &[u8],
    private_key: &[u8],
    identity: Identity,
) -> Result<()> {
    if !valid_domain(domain)
        || certificate.is_empty()
        || certificate.len() > CERT_LIMIT
        || private_key.is_empty()
        || private_key.len() > KEY_LIMIT
    {
        return Err(VerifyError::Invalid);
    }
    let hostname = command_with(
        binary,
        &["x509", "-noout", "-checkhost", domain],
        certificate,
        identity,
    )?;
    if hostname.trim_ascii() != format!("Hostname {domain} does match certificate").as_bytes() {
        return Err(VerifyError::Invalid);
    }
    command_with(
        binary,
        &["x509", "-noout", "-checkend", "86400"],
        certificate,
        identity,
    )?;
    let cert_public = command_with(
        binary,
        &["x509", "-pubkey", "-noout"],
        certificate,
        identity,
    )?;
    let key_public = command_with(
        binary,
        &["pkey", "-pubout", "-passin", "pass:"],
        private_key,
        identity,
    )?;
    if cert_public.is_empty() || cert_public.trim_ascii() != key_public.trim_ascii() {
        return Err(VerifyError::Invalid);
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn generate(path: &Path, name: &str, days: &str) -> (Vec<u8>, Vec<u8>) {
        let cert = path.join(format!("{name}.pem"));
        let key = path.join(format!("{name}.key"));
        let status = Command::new("/usr/bin/openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                days,
                "-subj",
                "/CN=panel.example.com",
                "-addext",
                "subjectAltName=DNS:panel.example.com",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        (fs::read(cert).unwrap(), fs::read(key).unwrap())
    }
    #[test]
    fn accepts_ecdsa_wildcard_and_rejects_the_wrong_host() {
        let directory = tempfile::tempdir().unwrap();
        let cert = directory.path().join("ecdsa.pem");
        let key = directory.path().join("ecdsa.key");
        let status = Command::new("/usr/bin/openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-days",
                "2",
                "-subj",
                "/CN=*.example.com",
                "-addext",
                "subjectAltName=DNS:*.example.com",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let cert = fs::read(cert).unwrap();
        let key = fs::read(key).unwrap();
        assert_eq!(validate("hk.example.com", &cert, &key), Ok(()));
        assert_eq!(
            validate("sub.hk.example.com", &cert, &key),
            Err(VerifyError::Invalid)
        );
    }
    #[test]
    fn accepts_only_matching_unexpired_certificate_and_key() {
        let directory = tempfile::tempdir().unwrap();
        let (cert, key) = generate(directory.path(), "valid", "2");
        let (_, other_key) = generate(directory.path(), "other", "2");
        let (short_lived, short_lived_key) = generate(directory.path(), "short-lived", "1");
        assert_eq!(validate("panel.example.com", &cert, &key), Ok(()));
        assert_eq!(
            validate("wrong.example.com", &cert, &key),
            Err(VerifyError::Invalid)
        );
        assert_eq!(
            validate("panel.example.com", &cert, &other_key),
            Err(VerifyError::Invalid)
        );
        assert_eq!(
            validate("panel.example.com", &short_lived, &short_lived_key),
            Err(VerifyError::Invalid)
        );
        assert_eq!(
            validate("panel.example.com", &cert, b"synthetic-secret"),
            Err(VerifyError::Invalid)
        );
        assert_eq!(
            validate("-invalid.example.com", &cert, &key),
            Err(VerifyError::Invalid)
        );
        assert_eq!(
            validate("panel.example.com", &vec![0; CERT_LIMIT + 1], &key),
            Err(VerifyError::Invalid)
        );
    }
    #[test]
    fn unavailable_validator_is_bounded_and_does_not_expose_input() {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("validator");
        fs::write(&script, b"#!/bin/sh\nexec sleep 60\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let started = Instant::now();
        assert_eq!(
            command(&script, &[], b"synthetic-only-key"),
            Err(VerifyError::Unavailable)
        );
        assert!(started.elapsed() < Duration::from_secs(7));
        fs::write(&script, b"#!/bin/sh\nhead -c 20000 /dev/zero\n").unwrap();
        assert_eq!(
            command(&script, &[], b"synthetic-only-key"),
            Err(VerifyError::Unavailable)
        );
        let marker = directory.path().join("child-pid");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nsleep 60 &\nprintf '%s' \"$!\" > '{}'\nexit 0\n",
                marker.display()
            ),
        )
        .unwrap();
        let started = Instant::now();
        assert_eq!(
            command(&script, &[], b"synthetic-only-key"),
            Err(VerifyError::Unavailable)
        );
        assert!(started.elapsed() < Duration::from_secs(7));
        let pid: u32 = fs::read_to_string(marker).unwrap().parse().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let status = fs::read_to_string(format!("/proc/{pid}/stat"));
            if status.is_err()
                || status.as_ref().is_ok_and(|value| {
                    value
                        .rsplit(')')
                        .next()
                        .is_some_and(|rest| rest.trim_start().starts_with('Z'))
                })
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "validator descendant remained running"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    #[test]
    fn private_input_is_not_in_validator_arguments_or_environment() {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("validator");
        let marker = directory.path().join("observed");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\ncat /proc/$$/cmdline > '{}'\nenv >> '{}'\ncat >/dev/null\nprintf ok\n",
                marker.display(),
                marker.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let result = command(&script, &["public-argument"], b"synthetic-only-private-key").unwrap();
        assert_eq!(result.as_slice(), b"ok");
        let observed = fs::read(marker).unwrap();
        assert!(!observed
            .windows(26)
            .any(|part| part == b"synthetic-only-private-key"));
    }
    #[test]
    #[ignore = "requires root and an explicitly supplied unprivileged fixture account"]
    fn root_validation_drops_identity_groups_and_capabilities() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let uid: u32 = std::env::var("XCLI_TEST_CERT_UID")
            .unwrap()
            .parse()
            .unwrap();
        let gid: u32 = std::env::var("XCLI_TEST_CERT_GID")
            .unwrap()
            .parse()
            .unwrap();
        assert_ne!(uid, 0);
        assert_ne!(gid, 0);
        let identity = Identity::Dropped { uid, gid };
        let status = command_with(
            Path::new("/usr/bin/sh"),
            &["-c", "cat /proc/self/status"],
            b"",
            identity,
        )
        .unwrap();
        let text = std::str::from_utf8(&status).unwrap();
        let field = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(name))
                .unwrap()
                .trim()
        };
        let uid_text = uid.to_string();
        let gid_text = gid.to_string();
        assert!(field("Uid:")
            .split_whitespace()
            .all(|value| value == uid_text));
        assert!(field("Gid:")
            .split_whitespace()
            .all(|value| value == gid_text));
        assert!(field("Groups:").is_empty());
        assert_eq!(u64::from_str_radix(field("CapEff:"), 16).unwrap(), 0);
        assert_eq!(field("NoNewPrivs:"), "1");
        let directory = tempfile::tempdir().unwrap();
        let (cert, key) = generate(directory.path(), "root-fixture", "2");
        assert_eq!(
            validate("panel.example.com", &cert, &key),
            Err(VerifyError::Unavailable)
        );
        assert_eq!(
            validate_dropped("panel.example.com", &cert, &key, uid, gid),
            Ok(())
        );
        assert_eq!(
            validate_dropped("panel.example.com", &cert, &key, 0, gid),
            Err(VerifyError::Unavailable)
        );
    }
}
