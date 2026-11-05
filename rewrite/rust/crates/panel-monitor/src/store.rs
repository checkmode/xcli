//! Experimental atomic monitor report storage. No credentials are written.
use crate::report::Report;
use crate::{Invalid, Sensitive};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const LIMIT: u64 = 64 * 1024;
pub struct Store {
    directory: PathBuf,
    _lock: File,
}
fn directory(path: &Path) -> Result<(), Invalid> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Invalid)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err(Invalid);
    }
    Ok(())
}
fn safe_file(path: &Path) -> Result<Option<File>, Invalid> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Invalid),
    };
    let metadata = file.metadata().map_err(|_| Invalid)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o027 != 0
        || metadata.len() > LIMIT
    {
        return Err(Invalid);
    }
    Ok(Some(file))
}
impl Store {
    /// The caller supplies an existing service-owned directory from trusted
    /// configuration. Holding this value excludes a second report writer.
    pub fn open(path: &Path) -> Result<Self, Invalid> {
        if !path.is_absolute() {
            return Err(Invalid);
        }
        directory(path)?;
        let directory = fs::canonicalize(path).map_err(|_| Invalid)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join("worker.lock"))
            .map_err(|_| Invalid)?;
        let meta = lock.metadata().map_err(|_| Invalid)?;
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o077 != 0
        {
            return Err(Invalid);
        }
        // SAFETY: the locked descriptor stays alive in Store until drop.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Invalid);
        }
        Ok(Self {
            directory,
            _lock: lock,
        })
    }
    pub fn load(&self) -> Result<Option<Sensitive>, Invalid> {
        directory(&self.directory)?;
        let Some(file) = safe_file(&self.directory.join("report.json"))? else {
            return Ok(None);
        };
        let mut data = Zeroizing::new(Vec::new());
        file.take(LIMIT + 1)
            .read_to_end(&mut data)
            .map_err(|_| Invalid)?;
        if data.len() as u64 > LIMIT {
            return Err(Invalid);
        }
        let value = Sensitive(serde_json::from_slice(&data).map_err(|_| Invalid)?);
        if !value.as_value().is_object() {
            return Err(Invalid);
        }
        Ok(Some(value))
    }
    pub fn save(&self, report: &Report) -> Result<(), Invalid> {
        directory(&self.directory)?;
        let _ = safe_file(&self.directory.join("report.json"))?;
        let mut data = Zeroizing::new(serde_json::to_vec(report.as_value()).map_err(|_| Invalid)?);
        data.push(b'\n');
        if data.len() as u64 > LIMIT {
            return Err(Invalid);
        }
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| Invalid)?;
        let temporary = self
            .directory
            .join(format!(".report-{}", hex::encode(random)));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .map_err(|_| Invalid)?;
        let result = (|| {
            // SAFETY: fchmod acts only on the newly created owned file.
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o640) } != 0 {
                return Err(Invalid);
            }
            if file.metadata().map_err(|_| Invalid)?.gid()
                != fs::metadata(&self.directory).map_err(|_| Invalid)?.gid()
            {
                return Err(Invalid);
            }
            file.write_all(&data)
                .and_then(|_| file.sync_all())
                .map_err(|_| Invalid)?;
            fs::rename(&temporary, self.directory.join("report.json")).map_err(|_| Invalid)?;
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&self.directory)
                .and_then(|file| file.sync_all())
                .map_err(|_| Invalid)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}
