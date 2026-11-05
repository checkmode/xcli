//! Experimental atomic publication of one combined PEM file.
//!
//! A caller must use a stable, trusted parent directory, ensure every writer
//! observes this lock, configure both Xray certificate and key paths to this
//! same file, and coordinate core startup with renewal. This does not modify
//! configuration, install a hook, or prove the new certificate is in use.
use super::{validate, VerifyError};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub enum PublishError {
    Invalid,
    Unavailable,
    /// The rename may have happened, but directory durability was not proven.
    Uncertain,
}
type Result<T> = std::result::Result<T, PublishError>;

fn validation_error(error: VerifyError) -> PublishError {
    match error {
        VerifyError::Invalid => PublishError::Invalid,
        VerifyError::Unavailable => PublishError::Unavailable,
    }
}

fn random_name() -> Result<CString> {
    let mut random = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .map_err(|_| PublishError::Unavailable)?;
    let mut name = String::from(".xcli-tls-");
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut name, "{byte:02x}").map_err(|_| PublishError::Unavailable)?;
    }
    CString::new(name).map_err(|_| PublishError::Unavailable)
}

fn name(target: &Path) -> Result<CString> {
    let name = target
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(PublishError::Invalid)?;
    if name.is_empty()
        || name.len() > 128
        || name.starts_with('.')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    {
        return Err(PublishError::Invalid);
    }
    CString::new(name).map_err(|_| PublishError::Invalid)
}

fn open_at(dir: &File, name: &CString, flags: libc::c_int, mode: libc::mode_t) -> Result<File> {
    // SAFETY: the directory descriptor and NUL-terminated name are valid;
    // the returned owned descriptor is checked before constructing File.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(PublishError::Unavailable);
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn valid_old_target(dir: &File, target: &CString, uid: u32) -> Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat points to writable memory and target is NUL terminated.
    let result = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            target.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(PublishError::Unavailable)
        };
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_nlink != 1
        || stat.st_uid != uid
        || stat.st_mode & 0o022 != 0
    {
        return Err(PublishError::Unavailable);
    }
    Ok(())
}

fn atomic(target: &Path, certificate: &[u8], private_key: &[u8], group: u32) -> Result<()> {
    let target_name = name(target)?;
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
        .map_err(|_| PublishError::Unavailable)?;
    let metadata = dir.metadata().map_err(|_| PublishError::Unavailable)?;
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
        || (uid == 0 && group == 0)
    {
        return Err(PublishError::Unavailable);
    }
    let lock_name = CString::new(".xcli-cert.lock").map_err(|_| PublishError::Unavailable)?;
    let lock = open_at(
        &dir,
        &lock_name,
        libc::O_CREAT | libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0o600,
    )?;
    let info = lock.metadata().map_err(|_| PublishError::Unavailable)?;
    if !info.is_file()
        || info.uid() != uid
        || info.nlink() != 1
        || info.mode() & 0o077 != 0
        || unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
    {
        return Err(PublishError::Unavailable);
    }
    valid_old_target(&dir, &target_name, uid)?;
    let temp_name = random_name()?;
    let mut temp = open_at(
        &dir,
        &temp_name,
        libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )?;
    let mut data = Zeroizing::new(Vec::with_capacity(
        certificate.len() + private_key.len() + 2,
    ));
    data.extend_from_slice(certificate);
    if !data.ends_with(b"\n") {
        data.push(b'\n');
    }
    data.extend_from_slice(private_key);
    if !data.ends_with(b"\n") {
        data.push(b'\n');
    }
    let mut renamed = false;
    let result = (|| {
        temp.write_all(&data)
            .map_err(|_| PublishError::Unavailable)?;
        if uid == 0 && unsafe { libc::fchown(temp.as_raw_fd(), uid, group) } != 0 {
            return Err(PublishError::Unavailable);
        }
        if uid != 0 && group != unsafe { libc::getegid() } {
            return Err(PublishError::Unavailable);
        }
        if unsafe { libc::fchmod(temp.as_raw_fd(), 0o640) } != 0 {
            return Err(PublishError::Unavailable);
        }
        temp.sync_all().map_err(|_| PublishError::Unavailable)?;
        if unsafe {
            libc::renameat(
                dir.as_raw_fd(),
                temp_name.as_ptr(),
                dir.as_raw_fd(),
                target_name.as_ptr(),
            )
        } != 0
        {
            return Err(PublishError::Unavailable);
        }
        renamed = true;
        dir.sync_all().map_err(|_| PublishError::Uncertain)?;
        Ok(())
    })();
    if !renamed {
        // SAFETY: unlink only the random name this call created in the pinned directory.
        unsafe { libc::unlinkat(dir.as_raw_fd(), temp_name.as_ptr(), 0) };
    }
    result
}

/// Validate and atomically publish a combined certificate and key as a
/// non-root caller. Existing targets are never truncated in place. This does
/// not serialize legacy writers or make two independent path reads atomic.
pub fn publish(target: &Path, domain: &str, certificate: &[u8], private_key: &[u8]) -> Result<()> {
    validate(domain, certificate, private_key).map_err(validation_error)?;
    atomic(target, certificate, private_key, unsafe { libc::getegid() })
}

/// A root caller must supply both the validator's non-root identity and the
/// group that may read the resulting 0640 bundle.
#[cfg(target_os = "linux")]
pub fn publish_dropped(
    target: &Path,
    domain: &str,
    certificate: &[u8],
    private_key: &[u8],
    uid: u32,
    gid: u32,
    output_group: u32,
) -> Result<()> {
    super::validate_dropped(domain, certificate, private_key, uid, gid)
        .map_err(validation_error)?;
    atomic(target, certificate, private_key, output_group)
}
