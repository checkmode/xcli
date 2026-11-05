//! Experimental Certbot lineage selection and bounded key reading.
//!
//! Only paths under a caller-supplied, trusted Certbot tree are read. A real
//! deployment must keep all ancestor directories stable, run only one writer,
//! and separately verify certificate use by the target service.
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const CERT_LIMIT: u64 = 256 * 1024;
const KEY_LIMIT: u64 = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum RenewalError {
    Invalid,
    Unavailable,
}
type Result<T> = std::result::Result<T, RenewalError>;

/// Kept out of Debug output. The private key is cleared when dropped.
pub struct Pair {
    certificate: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>,
}
impl Pair {
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.is_ascii()
        && !name.starts_with('.')
        && !name.ends_with('.')
        && !name.contains("..")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
}
fn live_path(root: &Path, lineage: &str) -> Result<PathBuf> {
    if !root.is_absolute() || !valid_name(lineage) {
        return Err(RenewalError::Invalid);
    }
    Ok(root.join("live").join(lineage))
}

/// Certbot invokes global deploy hooks for unrelated certificates. A missing
/// lineage is rejected; callers handling a manual request must select it
/// explicitly instead of treating a missing environment variable as a match.
pub fn matches_lineage(root: &Path, lineage: &str, renewed: Option<&Path>) -> Result<bool> {
    let expected = live_path(root, lineage)?;
    let renewed = renewed.ok_or(RenewalError::Invalid)?;
    if !renewed.is_absolute() {
        return Err(RenewalError::Invalid);
    }
    Ok(renewed == expected)
}

fn trusted_directory(path: &Path, uid: u32) -> Result<()> {
    let meta = fs::symlink_metadata(path).map_err(|_| RenewalError::Unavailable)?;
    if !meta.file_type().is_dir() || meta.uid() != uid || meta.mode() & 0o022 != 0 {
        return Err(RenewalError::Unavailable);
    }
    Ok(())
}
fn archive_name(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|name| name.strip_suffix(".pem"))
        .is_some_and(|number| {
            !number.is_empty() && number.len() <= 12 && number.bytes().all(|v| v.is_ascii_digit())
        })
}
fn read_file(path: &Path, limit: u64, uid: u32, private: bool) -> Result<Zeroizing<Vec<u8>>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| RenewalError::Unavailable)?;
    let meta = file.metadata().map_err(|_| RenewalError::Unavailable)?;
    if !meta.is_file()
        || meta.uid() != uid
        || meta.nlink() != 1
        || meta.mode() & 0o022 != 0
        || (private && meta.mode() & 0o077 != 0)
        || meta.len() == 0
        || meta.len() > limit
    {
        return Err(RenewalError::Unavailable);
    }
    let mut data = Zeroizing::new(Vec::new());
    file.take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|_| RenewalError::Unavailable)?;
    if data.is_empty() || data.len() as u64 > limit {
        return Err(RenewalError::Unavailable);
    }
    Ok(data)
}

/// Read the current `fullchain` and private-key symlinks from a trusted
/// Certbot tree, restricted to their own archive directory. The pair can
/// change between the two reads; callers must validate that it matches before
/// publishing and treat validation failure as retryable.
pub fn read_pair(root: &Path, lineage: &str) -> Result<Pair> {
    let live = live_path(root, lineage)?;
    let uid = unsafe { libc::geteuid() };
    let archive = root.join("archive").join(lineage);
    for dir in [
        root.to_path_buf(),
        root.join("live"),
        live.clone(),
        root.join("archive"),
        archive.clone(),
    ] {
        trusted_directory(&dir, uid)?;
    }
    let archive = fs::canonicalize(archive).map_err(|_| RenewalError::Unavailable)?;
    let cert =
        fs::canonicalize(live.join("fullchain.pem")).map_err(|_| RenewalError::Unavailable)?;
    let key = fs::canonicalize(live.join("privkey.pem")).map_err(|_| RenewalError::Unavailable)?;
    for (path, prefix) in [(&cert, "fullchain"), (&key, "privkey")] {
        if path.parent() != Some(archive.as_path())
            || !path
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|name| archive_name(name, prefix))
        {
            return Err(RenewalError::Unavailable);
        }
    }
    let certificate = read_file(&cert, CERT_LIMIT, uid, false)?;
    let private_key = read_file(&key, KEY_LIMIT, uid, true)?;
    Ok(Pair {
        certificate: certificate.to_vec(),
        private_key,
    })
}
