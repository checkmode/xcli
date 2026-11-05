//! Experimental multi-file update journal. No production paths or commands
//! are selected here. A privileged caller must supply fixed paths, authenticate
//! the request, validate candidates, and implement service hooks.
use crate::vmess::SecretJson;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const KEYS: [&str; 6] = ["settings", "core", "monitor", "nginx", "locations", "pool"];
const LIMIT: u64 = 4 * 1024 * 1024;
#[derive(Debug, PartialEq, Eq)]
pub enum JournalError {
    Unavailable,
    Pending,
    Conflict,
    Invalid,
    RolledBack,
}
type Result<T> = std::result::Result<T, JournalError>;
#[derive(Clone)]
pub(crate) struct Meta {
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}
pub(crate) struct FileState {
    pub(crate) data: Zeroizing<Vec<u8>>,
    pub(crate) meta: Meta,
}
pub trait Hooks {
    /// Validate the complete staged candidate before stopping any service.
    fn validate(&mut self, staged: &Path) -> Result<()>;
    /// Durably flush affected local-core counters or prove the cores are
    /// stopped, preserve remote-node ledgers, then quiesce all local writers.
    fn stop(&mut self) -> Result<()>;
    /// Restart the core and panel and verify that monitoring has resumed.
    fn start_and_check(&mut self) -> Result<()>;
    fn after_write(&mut self, _key: &str) -> Result<()> {
        Ok(())
    }
}
pub struct Store {
    root: PathBuf,
    lock: PathBuf,
    targets: BTreeMap<String, PathBuf>,
}
pub struct Candidate(BTreeMap<String, Zeroizing<Vec<u8>>>);
impl Candidate {
    pub fn new(values: BTreeMap<String, Vec<u8>>) -> Result<Self> {
        let values: BTreeMap<_, _> = values
            .into_iter()
            .map(|(key, value)| (key, Zeroizing::new(value)))
            .collect();
        if values.len() != KEYS.len()
            || KEYS.iter().any(|key| {
                !values
                    .get(*key)
                    .is_some_and(|value| value.len() as u64 <= LIMIT)
            })
        {
            return Err(JournalError::Invalid);
        }
        Ok(Self(values))
    }
    pub fn from_files(files: &crate::config::Files) -> Result<Self> {
        let mut values = BTreeMap::new();
        for (key, value) in [
            ("settings", files.settings()),
            ("core", files.core()),
            ("monitor", files.monitor()),
            ("pool", files.pool()),
        ] {
            values.insert(
                key.to_owned(),
                Zeroizing::new(serde_json::to_vec(value).map_err(|_| JournalError::Invalid)?),
            );
        }
        values.insert(
            "nginx".into(),
            Zeroizing::new(files.nginx().as_bytes().to_vec()),
        );
        values.insert(
            "locations".into(),
            Zeroizing::new(files.locations().as_bytes().to_vec()),
        );
        if values.values().any(|value| value.len() as u64 > LIMIT) {
            return Err(JournalError::Invalid);
        }
        Ok(Self(values))
    }
}
fn digest(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}
fn signature(file: &FileState) -> String {
    format!(
        "{}:{:o}:{}:{}",
        digest(&file.data),
        file.meta.mode,
        file.meta.uid,
        file.meta.gid
    )
}
fn identifier(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| JournalError::Unavailable)?;
    Ok(hex::encode(bytes))
}
fn sync_dir(path: &Path) -> Result<()> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| JournalError::Unavailable)
}
pub(crate) fn read(path: &Path, limit: u64) -> Result<Option<FileState>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        _ => return Err(JournalError::Unavailable),
    };
    let info = file.metadata().map_err(|_| JournalError::Unavailable)?;
    if !info.is_file() || info.nlink() != 1 || info.len() > limit {
        return Err(JournalError::Unavailable);
    }
    let mut data = Zeroizing::new(Vec::new());
    file.take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|_| JournalError::Unavailable)?;
    if data.len() as u64 > limit {
        return Err(JournalError::Unavailable);
    }
    Ok(Some(FileState {
        data,
        meta: Meta {
            mode: info.mode() & 0o777,
            uid: info.uid(),
            gid: info.gid(),
        },
    }))
}
pub(crate) fn atomic(path: &Path, data: &[u8], meta: &Meta) -> Result<()> {
    let parent = path.parent().ok_or(JournalError::Unavailable)?;
    let name = path.file_name().ok_or(JournalError::Unavailable)?;
    let tmp = parent.join(format!(".xcli-{}", random_id()?));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)
        .map_err(|_| JournalError::Unavailable)?;
    let result = (|| {
        // SAFETY: fchmod/fchown operate on the fresh, exclusively opened file.
        if unsafe { libc::fchmod(file.as_raw_fd(), meta.mode as libc::mode_t) } != 0 {
            return Err(JournalError::Unavailable);
        }
        // Unprivileged fixture processes may retain only their own ownership.
        let current = unsafe { libc::geteuid() };
        if current == 0 {
            if unsafe { libc::fchown(file.as_raw_fd(), meta.uid, meta.gid) } != 0 {
                return Err(JournalError::Unavailable);
            }
        } else {
            let info = file.metadata().map_err(|_| JournalError::Unavailable)?;
            if info.uid() != meta.uid || info.gid() != meta.gid {
                return Err(JournalError::Unavailable);
            }
        }
        let mut file = file;
        file.write_all(data)
            .and_then(|_| file.sync_all())
            .map_err(|_| JournalError::Unavailable)?;
        fs::rename(&tmp, parent.join(name)).map_err(|_| JournalError::Unavailable)?;
        sync_dir(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}
pub(crate) fn private_meta() -> Meta {
    // SAFETY: getters read only the current process identity.
    Meta {
        mode: 0o600,
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
    }
}
fn private_dir(path: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => sync_dir(path.parent().ok_or(JournalError::Unavailable)?)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => return Err(JournalError::Unavailable),
    }
    check_private_dir(path)
}
pub(crate) fn check_private_dir(path: &Path) -> Result<()> {
    let info = fs::symlink_metadata(path).map_err(|_| JournalError::Unavailable)?;
    if !info.is_dir()
        || info.file_type().is_symlink()
        || info.mode() & 0o077 != 0
        || info.uid() != unsafe { libc::geteuid() }
    {
        return Err(JournalError::Unavailable);
    }
    Ok(())
}
pub(crate) fn lock(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| JournalError::Unavailable)?;
    let info = file.metadata().map_err(|_| JournalError::Unavailable)?;
    if !info.is_file()
        || info.nlink() != 1
        || info.mode() & 0o022 != 0
        || info.uid() != unsafe { libc::geteuid() }
    {
        return Err(JournalError::Unavailable);
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        // SAFETY: the descriptor remains open until the transaction is complete.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(file);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if error.kind() != std::io::ErrorKind::WouldBlock {
            return Err(JournalError::Unavailable);
        }
        if Instant::now() >= deadline {
            return Err(JournalError::Pending);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
impl Store {
    /// Only trusted service configuration may select these paths; never pass
    /// paths from an import request. This does not acquire the update lock.
    pub fn open(root: &Path, lock_path: &Path, targets: BTreeMap<String, PathBuf>) -> Result<Self> {
        let meta = fs::symlink_metadata(root).map_err(|_| JournalError::Unavailable)?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.mode() & 0o077 != 0
            || meta.uid() != unsafe { libc::geteuid() }
        {
            return Err(JournalError::Unavailable);
        }
        if !lock_path.is_absolute()
            || targets.len() != KEYS.len()
            || KEYS
                .iter()
                .any(|key| !targets.get(*key).is_some_and(|path| path.is_absolute()))
        {
            return Err(JournalError::Invalid);
        }
        let root = fs::canonicalize(root).map_err(|_| JournalError::Unavailable)?;
        let mut unique = std::collections::BTreeSet::new();
        let mut normalized = BTreeMap::new();
        for (key, path) in targets {
            let parent = path.parent().ok_or(JournalError::Invalid)?;
            let resolved = fs::canonicalize(parent)
                .map_err(|_| JournalError::Unavailable)?
                .join(path.file_name().ok_or(JournalError::Invalid)?);
            if resolved.starts_with(&root) || !unique.insert(resolved.clone()) {
                return Err(JournalError::Invalid);
            }
            normalized.insert(key, resolved);
        }
        let lock = fs::canonicalize(lock_path.parent().ok_or(JournalError::Invalid)?)
            .map_err(|_| JournalError::Unavailable)?
            .join(lock_path.file_name().ok_or(JournalError::Invalid)?);
        if unique.contains(&lock) {
            return Err(JournalError::Invalid);
        }
        Ok(Self {
            root,
            lock,
            targets: normalized,
        })
    }
    fn current(&self) -> Result<BTreeMap<String, Option<FileState>>> {
        let mut files = BTreeMap::new();
        for key in KEYS {
            let state = read(&self.targets[key], LIMIT)?;
            if state.is_none() && !["locations", "pool"].contains(&key) {
                return Err(JournalError::Unavailable);
            }
            files.insert(key.to_owned(), state);
        }
        Ok(files)
    }
    fn verify(&self, expected: &BTreeMap<String, String>) -> Result<()> {
        let actual: BTreeMap<_, _> = self
            .current()?
            .into_iter()
            .map(|(key, file)| {
                (
                    key,
                    file.map_or_else(String::new, |value| signature(&value)),
                )
            })
            .collect();
        if &actual == expected {
            Ok(())
        } else {
            Err(JournalError::Conflict)
        }
    }
    /// Hash the snapshot while holding the same update lock used for apply.
    /// Empty string denotes an absent optional file.
    pub fn snapshot(&self) -> Result<BTreeMap<String, String>> {
        let _guard = lock(&self.lock)?;
        if read(&self.root.join("transaction.json"), 4096)?.is_some() {
            return Err(JournalError::Pending);
        }
        Ok(self
            .current()?
            .into_iter()
            .map(|(key, value)| (key, value.map_or_else(String::new, |file| signature(&file))))
            .collect())
    }
    /// Load a coherent configuration snapshot under the update lock. The
    /// returned signatures must be supplied unchanged when applying a preview.
    pub fn load(&self) -> Result<(crate::config::Files, BTreeMap<String, String>)> {
        let _guard = lock(&self.lock)?;
        if read(&self.root.join("transaction.json"), 4096)?.is_some() {
            return Err(JournalError::Pending);
        }
        let current = self.current()?;
        let signatures: BTreeMap<_, _> = current
            .iter()
            .map(|(key, file)| {
                (
                    key.clone(),
                    file.as_ref().map_or_else(String::new, signature),
                )
            })
            .collect();
        self.verify(&signatures)?;
        let parse = |key: &str| -> Result<SecretJson> {
            let data = &current[key].as_ref().ok_or(JournalError::Unavailable)?.data;
            Ok(SecretJson::new(
                serde_json::from_slice(data).map_err(|_| JournalError::Invalid)?,
            ))
        };
        let mut settings = parse("settings")?;
        let mut core = parse("core")?;
        let mut monitor = parse("monitor")?;
        let mut pool = if current["pool"].is_some() {
            Some(parse("pool")?)
        } else {
            None
        };
        let string = |key: &str| -> Result<Option<Zeroizing<String>>> {
            current[key]
                .as_ref()
                .map(|file| {
                    std::str::from_utf8(&file.data)
                        .map(|value| Zeroizing::new(value.to_owned()))
                        .map_err(|_| JournalError::Invalid)
                })
                .transpose()
        };
        let mut nginx = string("nginx")?.ok_or(JournalError::Unavailable)?;
        let mut locations = string("locations")?;
        self.verify(&signatures)?;
        let files = crate::config::Files::new(
            std::mem::take(settings.value_mut()),
            std::mem::take(core.value_mut()),
            std::mem::take(monitor.value_mut()),
            std::mem::take(&mut *nginx),
            locations.as_mut().map(|value| std::mem::take(&mut **value)),
            pool.as_mut().map(|value| std::mem::take(value.value_mut())),
        )
        .map_err(|_| JournalError::Invalid)?;
        Ok((files, signatures))
    }
    /// Prepare only the Brutal sender rate, retaining every other file byte
    /// for the existing journal's validation, checkpoint and rollback path.
    pub fn brutal_rate_candidate(
        &self,
        rate: u64,
    ) -> Result<(Option<Candidate>, BTreeMap<String, String>)> {
        if !(1..=1000).contains(&rate) {
            return Err(JournalError::Invalid);
        }
        let _guard = lock(&self.lock)?;
        if read(&self.root.join("transaction.json"), 4096)?.is_some() {
            return Err(JournalError::Pending);
        }
        let current = self.current()?;
        let signatures = current.iter().map(|(key, file)| {
            (key.clone(), file.as_ref().map_or_else(String::new, signature))
        }).collect();
        let bytes = |key: &str| current[key].as_ref().map(|v| v.data.as_slice()).ok_or(JournalError::Unavailable);
        let mut settings: Value = serde_json::from_slice(bytes("settings")?).map_err(|_| JournalError::Invalid)?;
        let mut core: Value = serde_json::from_slice(bytes("core")?).map_err(|_| JournalError::Invalid)?;
        let old = settings.get("hysteria2_brutal_mbps").map_or(Some(40), Value::as_u64)
            .filter(|v| (1..=1000).contains(v)).ok_or(JournalError::Invalid)?;
        let port = settings.get("hysteria2_brutal_port").and_then(Value::as_u64)
            .filter(|v| (1024..=65535).contains(v)).ok_or(JournalError::Invalid)?;
        let entries = core.get_mut("inbounds").and_then(Value::as_array_mut).ok_or(JournalError::Invalid)?;
        let mut matches = entries.iter_mut().filter(|v| v.get("tag").and_then(Value::as_str) == Some("hysteria2-brutal"));
        let inbound = matches.next().ok_or(JournalError::Invalid)?;
        if matches.next().is_some() || inbound.get("port").and_then(Value::as_u64) != Some(port)
            || inbound.get("protocol").and_then(Value::as_str) != Some("hysteria") {
            return Err(JournalError::Invalid);
        }
        let params = inbound.pointer_mut("/streamSettings/finalmask/quicParams")
            .and_then(Value::as_object_mut).ok_or(JournalError::Invalid)?;
        if params.get("congestion").and_then(Value::as_str) != Some("force-brutal")
            || !params.get("brutalUp").and_then(Value::as_str)
                .is_some_and(|v| v.trim().eq_ignore_ascii_case(&format!("{old} mbps"))) {
            return Err(JournalError::Conflict);
        }
        if rate == old {
            return Ok((None, signatures));
        }
        params.insert("brutalUp".into(), json!(format!("{rate} mbps")));
        settings.as_object_mut().ok_or(JournalError::Invalid)?
            .insert("hysteria2_brutal_mbps".into(), json!(rate));
        let mut values: BTreeMap<String, Vec<u8>> = current.iter().map(|(key, value)| {
            (key.clone(), value.as_ref().map_or_else(Vec::new, |file| file.data.to_vec()))
        }).collect();
        values.insert("settings".into(), serde_json::to_vec_pretty(&settings).map_err(|_| JournalError::Invalid)?);
        values.insert("core".into(), serde_json::to_vec_pretty(&core).map_err(|_| JournalError::Invalid)?);
        Ok((Some(Candidate::new(values)?), signatures))
    }
    fn write_manifest(&self, backup: &Path, manifest: &Value) -> Result<()> {
        let bytes =
            Zeroizing::new(serde_json::to_vec(manifest).map_err(|_| JournalError::Unavailable)?);
        atomic(&backup.join("manifest.json"), &bytes, &private_meta())
    }
    fn clear_pointer(&self) -> Result<()> {
        fs::remove_file(self.root.join("transaction.json"))
            .map_err(|_| JournalError::Unavailable)?;
        sync_dir(&self.root)
    }
    /// Stage and apply a full candidate with a verified before-image. Hooks
    /// must quiesce writers and prove the restarted system before returning.
    pub fn apply(
        &self,
        expected: &BTreeMap<String, String>,
        candidate: &Candidate,
        hooks: &mut dyn Hooks,
    ) -> Result<()> {
        let _guard = lock(&self.lock)?;
        if read(&self.root.join("transaction.json"), 4096)?.is_some() {
            return Err(JournalError::Pending);
        }
        let current = self.current()?;
        let actual: BTreeMap<_, _> = current
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    value.as_ref().map_or_else(String::new, signature),
                )
            })
            .collect();
        if &actual != expected {
            return Err(JournalError::Conflict);
        }
        let backups = self.root.join("backups");
        private_dir(&backups)?;
        let id = random_id()?;
        let backup = backups.join(&id);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&backup)
            .map_err(|_| JournalError::Unavailable)?;
        sync_dir(&backups)?;
        let mut files = json!({});
        for key in KEYS {
            let existing = current.get(key).ok_or(JournalError::Invalid)?;
            let data = candidate.0.get(key).ok_or(JournalError::Invalid)?;
            if let Some(file) = existing {
                atomic(
                    &backup.join(format!("old.{key}")),
                    &file.data,
                    &private_meta(),
                )?;
            }
            atomic(&backup.join(format!("new.{key}")), data, &private_meta())?;
            let meta = existing
                .as_ref()
                .map(|file| file.meta.clone())
                .unwrap_or_else(|| {
                    let mut meta = private_meta();
                    if key == "locations" {
                        meta.mode = 0o644;
                    }
                    meta
                });
            files[key] = json!({"old":existing.as_ref().map_or_else(String::new,|file|digest(&file.data)),"new":digest(data),"present":existing.is_some(),
                "mode":meta.mode,"uid":meta.uid,"gid":meta.gid});
        }
        let mut manifest = json!({"version":1,"id":id,"phase":"prepared","files":files});
        self.write_manifest(&backup, &manifest)?;
        hooks.validate(&backup)?;
        for key in KEYS {
            let staged =
                read(&backup.join(format!("new.{key}")), LIMIT)?.ok_or(JournalError::Invalid)?;
            if digest(&staged.data) != digest(&candidate.0[key]) {
                return Err(JournalError::Conflict);
            }
        }
        let fresh = self.current()?;
        let hashes: BTreeMap<_, _> = fresh
            .into_iter()
            .map(|(key, value)| (key, value.map_or_else(String::new, |file| signature(&file))))
            .collect();
        if &hashes != expected {
            return Err(JournalError::Conflict);
        }
        atomic(
            &self.root.join("transaction.json"),
            serde_json::to_vec(&json!({ "id": id }))
                .map_err(|_| JournalError::Unavailable)?
                .as_slice(),
            &private_meta(),
        )?;
        manifest["phase"] = json!("applying");
        if self.write_manifest(&backup, &manifest).is_err() {
            return Err(JournalError::Unavailable);
        }
        let applied = (|| {
            hooks.stop()?;
            // A writer may have changed the files while services were stopping.
            // Cooperating writers must also hold the shared update lock.
            let mut expected_files = expected.clone();
            self.verify(&expected_files)?;
            for key in KEYS {
                // A rate-only update retains absent optional files as absent.
                if current[key].is_none() && candidate.0[key].is_empty()
                    && ["locations", "pool"].contains(&key) {
                    continue;
                }
                let info = manifest["files"][key]
                    .as_object()
                    .ok_or(JournalError::Invalid)?;
                let meta = Meta {
                    mode: u32::try_from(info["mode"].as_u64().ok_or(JournalError::Invalid)?)
                        .map_err(|_| JournalError::Invalid)?,
                    uid: u32::try_from(info["uid"].as_u64().ok_or(JournalError::Invalid)?)
                        .map_err(|_| JournalError::Invalid)?,
                    gid: u32::try_from(info["gid"].as_u64().ok_or(JournalError::Invalid)?)
                        .map_err(|_| JournalError::Invalid)?,
                };
                self.verify(&expected_files)?;
                atomic(&self.targets[key], candidate.0[key].as_slice(), &meta)?;
                expected_files.insert(
                    key.to_owned(),
                    format!(
                        "{}:{:o}:{}:{}",
                        digest(&candidate.0[key]),
                        meta.mode,
                        meta.uid,
                        meta.gid
                    ),
                );
                hooks.after_write(key)?;
            }
            self.verify(&expected_files)?;
            hooks.start_and_check()
        })();
        if applied.is_err() {
            return self.fail_and_rollback(&id, &manifest, hooks);
        }
        manifest["phase"] = json!("committed");
        if self.write_manifest(&backup, &manifest).is_err() {
            return Err(JournalError::Unavailable);
        }
        self.clear_pointer()
    }
    fn fail_and_rollback(&self, id: &str, manifest: &Value, hooks: &mut dyn Hooks) -> Result<()> {
        self.rollback_locked(id, manifest, hooks)?;
        Err(JournalError::RolledBack)
    }
    fn rollback_locked(&self, id: &str, manifest: &Value, hooks: &mut dyn Hooks) -> Result<()> {
        if !identifier(id) || manifest["id"] != id || manifest["version"] != 1 {
            return Err(JournalError::Invalid);
        }
        let backup = self.root.join("backups").join(id);
        check_private_dir(&self.root.join("backups"))?;
        check_private_dir(&backup)?;
        let records = manifest
            .get("files")
            .and_then(Value::as_object)
            .ok_or(JournalError::Invalid)?;
        if records.len() != KEYS.len() {
            return Err(JournalError::Invalid);
        }
        let current = self.current()?;
        let mut old_files = BTreeMap::new();
        let mut metas = BTreeMap::new();
        for key in KEYS {
            let row = records
                .get(key)
                .and_then(Value::as_object)
                .ok_or(JournalError::Invalid)?;
            let old = row
                .get("old")
                .and_then(Value::as_str)
                .ok_or(JournalError::Invalid)?;
            let new = row
                .get("new")
                .and_then(Value::as_str)
                .ok_or(JournalError::Invalid)?;
            let present = row
                .get("present")
                .and_then(Value::as_bool)
                .ok_or(JournalError::Invalid)?;
            if (present && !valid_digest(old))
                || (!present && !old.is_empty())
                || !valid_digest(new)
            {
                return Err(JournalError::Invalid);
            }
            let mode = row
                .get("mode")
                .and_then(Value::as_u64)
                .and_then(|v| u32::try_from(v).ok())
                .filter(|v| *v <= 0o777)
                .ok_or(JournalError::Invalid)?;
            let uid = row
                .get("uid")
                .and_then(Value::as_u64)
                .and_then(|v| u32::try_from(v).ok())
                .ok_or(JournalError::Invalid)?;
            let gid = row
                .get("gid")
                .and_then(Value::as_u64)
                .and_then(|v| u32::try_from(v).ok())
                .ok_or(JournalError::Invalid)?;
            let observed = current[key]
                .as_ref()
                .map_or_else(String::new, |file| digest(&file.data));
            if observed != old && observed != new {
                return Err(JournalError::Conflict);
            }
            if current[key].as_ref().is_some_and(|file| {
                file.meta.mode != mode || file.meta.uid != uid || file.meta.gid != gid
            }) {
                return Err(JournalError::Conflict);
            }
            let old_file = read(&backup.join(format!("old.{key}")), LIMIT)?;
            if present {
                if old_file
                    .as_ref()
                    .is_none_or(|file| digest(&file.data) != old)
                {
                    return Err(JournalError::Invalid);
                }
            } else if old_file.is_some() {
                return Err(JournalError::Invalid);
            }
            old_files.insert(key, old_file);
            metas.insert(key, Meta { mode, uid, gid });
        }
        let mut expected_files: BTreeMap<_, _> = current
            .into_iter()
            .map(|(key, file)| {
                (
                    key,
                    file.map_or_else(String::new, |value| signature(&value)),
                )
            })
            .collect();
        hooks.stop()?;
        self.verify(&expected_files)?;
        for key in KEYS {
            self.verify(&expected_files)?;
            match &old_files[key] {
                Some(file) => atomic(&self.targets[key], &file.data, &metas[key])?,
                None => match fs::remove_file(&self.targets[key]) {
                    Ok(()) => sync_dir(
                        self.targets[key]
                            .parent()
                            .ok_or(JournalError::Unavailable)?,
                    )?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                    Err(_) => return Err(JournalError::Unavailable),
                },
            }
            expected_files.insert(
                key.to_owned(),
                old_files[key].as_ref().map_or_else(String::new, |file| {
                    format!(
                        "{}:{:o}:{}:{}",
                        digest(&file.data),
                        metas[key].mode,
                        metas[key].uid,
                        metas[key].gid
                    )
                }),
            );
        }
        self.verify(&expected_files)?;
        hooks.start_and_check()?;
        let mut finished = manifest.clone();
        finished["phase"] = json!("rolled_back");
        self.write_manifest(&backup, &finished)?;
        self.clear_pointer()
    }
    /// A pending journal is completed only when all current file hashes still
    /// match the recorded before or after images. Conflicts require review.
    pub fn recover(&self, hooks: &mut dyn Hooks) -> Result<bool> {
        let _guard = lock(&self.lock)?;
        let Some(pointer) = read(&self.root.join("transaction.json"), 4096)? else {
            return Ok(false);
        };
        let pointer: Value =
            serde_json::from_slice(&pointer.data).map_err(|_| JournalError::Invalid)?;
        let id = pointer
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| identifier(id))
            .ok_or(JournalError::Invalid)?;
        check_private_dir(&self.root.join("backups"))?;
        check_private_dir(&self.root.join("backups").join(id))?;
        let manifest = read(
            &self.root.join("backups").join(id).join("manifest.json"),
            65536,
        )?
        .ok_or(JournalError::Invalid)?;
        let manifest: Value =
            serde_json::from_slice(&manifest.data).map_err(|_| JournalError::Invalid)?;
        if manifest["id"] != id || manifest["version"] != 1 {
            return Err(JournalError::Invalid);
        }
        match manifest["phase"].as_str() {
            Some("prepared" | "applying") => self.rollback_locked(id, &manifest, hooks)?,
            Some("committed" | "rolled_back") => self.clear_pointer()?,
            _ => return Err(JournalError::Invalid),
        }
        Ok(true)
    }
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    struct Fixture {
        _dir: tempfile::TempDir,
        store: Store,
        paths: BTreeMap<String, PathBuf>,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("journal");
            let target = dir.path().join("etc");
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            fs::create_dir(&target).unwrap();
            let mut paths = BTreeMap::new();
            for key in KEYS {
                let path = target.join(key);
                if !["locations", "pool"].contains(&key) {
                    fs::write(&path, format!("old-{key}")).unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                }
                paths.insert(key.to_owned(), path);
            }
            let store = Store::open(&root, &root.join("update.lock"), paths.clone()).unwrap();
            Self {
                _dir: dir,
                store,
                paths,
            }
        }
        fn candidate(&self) -> Candidate {
            Candidate::new(
                KEYS.iter()
                    .map(|key| (key.to_string(), format!("new-{key}").into_bytes()))
                    .collect(),
            )
            .unwrap()
        }
        fn old(&self) {
            for key in KEYS {
                if ["locations", "pool"].contains(&key) {
                    assert!(!self.paths[key].exists());
                } else {
                    assert_eq!(
                        fs::read_to_string(&self.paths[key]).unwrap(),
                        format!("old-{key}")
                    );
                    assert_eq!(
                        fs::metadata(&self.paths[key]).unwrap().mode() & 0o777,
                        0o600
                    );
                }
            }
        }
    }
    #[derive(Default)]
    struct FakeHooks {
        stops: usize,
        starts: usize,
        fail: Option<&'static str>,
        conflict: Option<PathBuf>,
        conflict_on_stop: Option<(usize, PathBuf)>,
        panic_at: Option<&'static str>,
        tamper: bool,
    }
    impl Hooks for FakeHooks {
        fn validate(&mut self, path: &Path) -> Result<()> {
            if self.tamper {
                fs::write(path.join("new.core"), "tampered").unwrap();
            }
            Ok(())
        }
        fn stop(&mut self) -> Result<()> {
            self.stops += 1;
            if let Some((number, path)) = &self.conflict_on_stop {
                if *number == self.stops {
                    fs::write(path, "external-change").unwrap();
                }
            }
            Ok(())
        }
        fn start_and_check(&mut self) -> Result<()> {
            self.starts += 1;
            Ok(())
        }
        fn after_write(&mut self, key: &str) -> Result<()> {
            if self.panic_at == Some(key) {
                panic!("synthetic interrupted transaction");
            }
            if self.fail == Some(key) {
                if let Some(path) = &self.conflict {
                    fs::write(path, "external-change").unwrap();
                }
                return Err(JournalError::Unavailable);
            }
            Ok(())
        }
    }
    fn brutal_fixture() -> Fixture {
        let fixture = Fixture::new();
        fs::write(&fixture.paths["settings"], br#"{"hysteria2_port":443,"hysteria2_brutal_port":8443,"preserved":"yes"}"#).unwrap();
        fs::write(&fixture.paths["core"], br#"{"inbounds":[{"tag":"hysteria2","port":443,"protocol":"hysteria","streamSettings":{"finalmask":{"quicParams":{"congestion":"bbr"}}}},{"tag":"hysteria2-brutal","port":8443,"protocol":"hysteria","streamSettings":{"finalmask":{"quicParams":{"congestion":"force-brutal","brutalUp":"40 mbps"}}}}],"routing":{"preserved":true}}"#).unwrap();
        fixture
    }
    #[test]
    fn brutal_rate_changes_only_its_fields_and_preserves_absent_files() {
        let fixture = brutal_fixture();
        let before_core: Value = serde_json::from_slice(&fs::read(&fixture.paths["core"]).unwrap()).unwrap();
        let (candidate, expected) = fixture.store.brutal_rate_candidate(60).unwrap();
        let mut hooks = FakeHooks::default();
        fixture.store.apply(&expected, &candidate.unwrap(), &mut hooks).unwrap();
        let after_core: Value = serde_json::from_slice(&fs::read(&fixture.paths["core"]).unwrap()).unwrap();
        let settings: Value = serde_json::from_slice(&fs::read(&fixture.paths["settings"]).unwrap()).unwrap();
        assert_eq!(settings["hysteria2_brutal_mbps"], 60);
        assert_eq!(settings["preserved"], "yes");
        assert_eq!(before_core["inbounds"][0], after_core["inbounds"][0]);
        assert_eq!(before_core["routing"], after_core["routing"]);
        assert_eq!(after_core["inbounds"][1]["streamSettings"]["finalmask"]["quicParams"]["brutalUp"], "60 mbps");
        assert!(!fixture.paths["locations"].exists() && !fixture.paths["pool"].exists());
        assert_eq!(fs::read_to_string(&fixture.paths["monitor"]).unwrap(), "old-monitor");
        assert_eq!((hooks.stops, hooks.starts), (1, 1));
        assert!(fixture.store.brutal_rate_candidate(60).unwrap().0.is_none());
        assert!(fixture.store.brutal_rate_candidate(0).is_err());
        assert!(fixture.store.brutal_rate_candidate(1001).is_err());
    }
    #[test]
    fn failed_brutal_rate_change_restores_original_and_refuses_external_edits() {
        let fixture = brutal_fixture();
        let before_settings = fs::read(&fixture.paths["settings"]).unwrap();
        let before_core = fs::read(&fixture.paths["core"]).unwrap();
        let (candidate, expected) = fixture.store.brutal_rate_candidate(60).unwrap();
        let mut hooks = FakeHooks { fail: Some("core"), ..Default::default() };
        assert_eq!(fixture.store.apply(&expected, &candidate.unwrap(), &mut hooks), Err(JournalError::RolledBack));
        assert_eq!(fs::read(&fixture.paths["settings"]).unwrap(), before_settings);
        assert_eq!(fs::read(&fixture.paths["core"]).unwrap(), before_core);
        assert!(!fixture.paths["locations"].exists() && !fixture.paths["pool"].exists());
        let mut core: Value = serde_json::from_slice(&before_core).unwrap();
        core["inbounds"][1]["streamSettings"]["finalmask"]["quicParams"]["brutalUp"] = json!("70 mbps");
        fs::write(&fixture.paths["core"], serde_json::to_vec(&core).unwrap()).unwrap();
        assert!(matches!(fixture.store.brutal_rate_candidate(80), Err(JournalError::Conflict)));
    }
    #[test]
    fn commits_all_files_and_preserves_existing_permissions() {
        let fixture = Fixture::new();
        let expected = fixture.store.snapshot().unwrap();
        let mut hooks = FakeHooks::default();
        fixture
            .store
            .apply(&expected, &fixture.candidate(), &mut hooks)
            .unwrap();
        for key in KEYS {
            assert_eq!(
                fs::read_to_string(&fixture.paths[key]).unwrap(),
                format!("new-{key}")
            );
        }
        assert_eq!(
            fs::metadata(&fixture.paths["settings"]).unwrap().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&fixture.paths["locations"]).unwrap().mode() & 0o777,
            0o644
        );
        assert_eq!((hooks.stops, hooks.starts), (1, 1));
        assert!(!fixture.store.root.join("transaction.json").exists());
        let backup = fs::read_dir(fixture.store.root.join("backups"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let manifest = fs::read_to_string(backup.join("manifest.json")).unwrap();
        assert!(manifest.contains("committed"));
        assert!(!manifest.contains("new-core"));
    }
    #[test]
    fn failed_write_rolls_back_without_removing_unrelated_state() {
        let fixture = Fixture::new();
        let expected = fixture.store.snapshot().unwrap();
        let other = fixture.paths["core"].parent().unwrap().join("unrelated");
        fs::write(&other, "untouched").unwrap();
        let mut hooks = FakeHooks {
            fail: Some("monitor"),
            ..FakeHooks::default()
        };
        assert_eq!(
            fixture
                .store
                .apply(&expected, &fixture.candidate(), &mut hooks),
            Err(JournalError::RolledBack)
        );
        fixture.old();
        assert_eq!(fs::read_to_string(other).unwrap(), "untouched");
        assert_eq!((hooks.stops, hooks.starts), (2, 1));
        assert!(!fixture.store.root.join("transaction.json").exists());
    }
    #[test]
    fn changed_before_image_and_staged_candidate_are_never_applied() {
        let fixture = Fixture::new();
        let expected = fixture.store.snapshot().unwrap();
        fs::write(&fixture.paths["settings"], "external-change").unwrap();
        let mut hooks = FakeHooks::default();
        assert_eq!(
            fixture
                .store
                .apply(&expected, &fixture.candidate(), &mut hooks),
            Err(JournalError::Conflict)
        );
        assert_eq!((hooks.stops, hooks.starts), (0, 0));
        fs::write(&fixture.paths["settings"], "old-settings").unwrap();
        let expected = fixture.store.snapshot().unwrap();
        let mut hooks = FakeHooks {
            tamper: true,
            ..FakeHooks::default()
        };
        assert_eq!(
            fixture
                .store
                .apply(&expected, &fixture.candidate(), &mut hooks),
            Err(JournalError::Conflict)
        );
        fixture.old();
        assert!(!fixture.store.root.join("transaction.json").exists());
    }
    #[test]
    fn changes_while_stopping_are_never_overwritten_during_apply_or_recovery() {
        for at_stop in [1, 2] {
            let fixture = Fixture::new();
            let expected = fixture.store.snapshot().unwrap();
            let path = fixture.paths[if at_stop == 1 { "core" } else { "settings" }].clone();
            let mut hooks = FakeHooks {
                fail: (at_stop == 2).then_some("core"),
                conflict_on_stop: Some((at_stop, path.clone())),
                ..FakeHooks::default()
            };
            assert_eq!(
                fixture
                    .store
                    .apply(&expected, &fixture.candidate(), &mut hooks),
                Err(JournalError::Conflict)
            );
            assert_eq!(fs::read_to_string(&path).unwrap(), "external-change");
            assert!(fixture.store.root.join("transaction.json").exists());
            if at_stop == 1 {
                assert_eq!(
                    fs::read_to_string(&fixture.paths["settings"]).unwrap(),
                    "old-settings"
                );
                fs::write(&path, "old-core").unwrap();
            } else {
                fs::write(&path, "new-settings").unwrap();
            }
            assert!(fixture.store.recover(&mut FakeHooks::default()).unwrap());
            fixture.old();
        }
    }
    #[test]
    fn snapshot_waits_for_an_existing_update_lock() {
        let fixture = Fixture::new();
        let guard = lock(&fixture.store.lock).unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                sent.send(fixture.store.snapshot()).unwrap();
            });
            assert!(matches!(
                received.recv_timeout(Duration::from_millis(100)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ));
            drop(guard);
            assert!(received
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .is_ok());
        });
    }
    #[test]
    fn hardlinked_targets_are_rejected_without_changing_either_link() {
        let fixture = Fixture::new();
        let linked = fixture.paths["core"].parent().unwrap().join("hardlink");
        fs::hard_link(&fixture.paths["core"], &linked).unwrap();
        assert!(matches!(
            fixture.store.snapshot(),
            Err(JournalError::Unavailable)
        ));
        assert_eq!(fs::read_to_string(&linked).unwrap(), "old-core");
        assert_eq!(
            fs::read_to_string(&fixture.paths["core"]).unwrap(),
            "old-core"
        );
    }
    #[test]
    fn candidate_builder_and_journal_apply_the_same_synthetic_files() {
        use crate::config::{add_fixed, Verified};
        use crate::probe::{ProbeResult, Protocol};
        let fixture = Fixture::new();
        let settings =
            json!({"public_ip":"8.8.8.8","ws_path":"/connect/fixture","residential_exits":[]});
        let core = json!({"inbounds":[{"tag":"reality","port":10443}],"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[{"inboundTag":["reality"],"outboundTag":"direct"}]}});
        let monitor = json!({"residential_exits":[]});
        let nginx = "location = /connect/fixture {}";
        for (key, value) in [
            ("settings", serde_json::to_vec(&settings).unwrap()),
            ("core", serde_json::to_vec(&core).unwrap()),
            ("monitor", serde_json::to_vec(&monitor).unwrap()),
            ("nginx", nginx.as_bytes().to_vec()),
        ] {
            fs::write(&fixture.paths[key], value).unwrap();
        }
        let (files, expected) = fixture.store.load().unwrap();
        assert_eq!(expected, fixture.store.snapshot().unwrap());
        let proxies = crate::parse_fixed("1.1.1.1:80:fixture:synthetic-password").unwrap();
        let probe = ProbeResult {
            exit_ip: "1.1.1.1".parse().unwrap(),
            country: "US".into(),
            https_ms: 1,
            doh_ms: 1,
        };
        let input = [Verified {
            proxy: &proxies[0],
            protocol: Protocol::Socks,
            result: &probe,
        }];
        let (files, entries) = add_fixed(files, &input, "fixture").unwrap();
        let candidate = Candidate::from_files(&files).unwrap();
        fixture
            .store
            .apply(&expected, &candidate, &mut FakeHooks::default())
            .unwrap();
        let current: Value =
            serde_json::from_slice(&fs::read(&fixture.paths["core"]).unwrap()).unwrap();
        assert_eq!(current, *files.core());
        assert_eq!(current["inbounds"][0], core["inbounds"][0]);
        assert_eq!(entries[0]["tag"], "residential-27");
        assert!(fixture.paths["locations"].exists());
    }
    #[test]
    fn coherent_load_rejects_corruption_and_pending_recovery() {
        let fixture = Fixture::new();
        fs::write(&fixture.paths["settings"], "{broken").unwrap();
        assert!(matches!(fixture.store.load(), Err(JournalError::Invalid)));
        fs::write(fixture.store.root.join("transaction.json"), "{}").unwrap();
        assert!(matches!(fixture.store.load(), Err(JournalError::Pending)));
    }
    #[test]
    fn conflict_during_rollback_retains_the_journal_until_explicit_recovery() {
        let fixture = Fixture::new();
        let expected = fixture.store.snapshot().unwrap();
        let mut hooks = FakeHooks {
            fail: Some("core"),
            conflict: Some(fixture.paths["core"].clone()),
            ..FakeHooks::default()
        };
        assert_eq!(
            fixture
                .store
                .apply(&expected, &fixture.candidate(), &mut hooks),
            Err(JournalError::Conflict)
        );
        assert_eq!(
            fs::read_to_string(&fixture.paths["core"]).unwrap(),
            "external-change"
        );
        assert!(fixture.store.root.join("transaction.json").exists());
        assert!(matches!(
            fixture.store.snapshot(),
            Err(JournalError::Pending)
        ));
        fs::write(&fixture.paths["core"], "new-core").unwrap();
        let mut recovery = FakeHooks::default();
        assert!(fixture.store.recover(&mut recovery).unwrap());
        fixture.old();
        assert!(!fixture.store.recover(&mut recovery).unwrap());
    }
    #[test]
    fn interrupted_update_recovers_and_symlink_tampering_fails_closed() {
        let fixture = Fixture::new();
        let expected = fixture.store.snapshot().unwrap();
        let mut hooks = FakeHooks {
            panic_at: Some("core"),
            ..FakeHooks::default()
        };
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fixture
                .store
                .apply(&expected, &fixture.candidate(), &mut hooks)
        }));
        assert!(interrupted.is_err());
        assert!(fixture.store.root.join("transaction.json").exists());
        fs::remove_file(&fixture.paths["core"]).unwrap();
        symlink(&fixture.paths["settings"], &fixture.paths["core"]).unwrap();
        let mut recovery = FakeHooks::default();
        assert_eq!(
            fixture.store.recover(&mut recovery),
            Err(JournalError::Unavailable)
        );
        fs::remove_file(&fixture.paths["core"]).unwrap();
        fs::write(&fixture.paths["core"], "new-core").unwrap();
        fs::set_permissions(&fixture.paths["core"], fs::Permissions::from_mode(0o600)).unwrap();
        assert!(fixture.store.recover(&mut recovery).unwrap());
        fixture.old();
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn killed_process_fixture() {
        let Some(base) = std::env::var_os("XCLI_TEST_JOURNAL_ROOT") else {
            return;
        };
        let base = PathBuf::from(base);
        let root = base.join("journal");
        let target = base.join("etc");
        let paths = KEYS
            .iter()
            .map(|key| (key.to_string(), target.join(key)))
            .collect();
        let store = Store::open(&root, &root.join("update.lock"), paths).unwrap();
        struct Pause;
        impl Hooks for Pause {
            fn validate(&mut self, _: &Path) -> Result<()> {
                Ok(())
            }
            fn stop(&mut self) -> Result<()> {
                Ok(())
            }
            fn start_and_check(&mut self) -> Result<()> {
                Ok(())
            }
            fn after_write(&mut self, key: &str) -> Result<()> {
                if key == "core" {
                    println!("XCLI_JOURNAL_PAUSED");
                    std::io::stdout().flush().unwrap();
                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
                Ok(())
            }
        }
        let expected = store.snapshot().unwrap();
        let candidate = Candidate::new(
            KEYS.iter()
                .map(|key| (key.to_string(), format!("new-{key}").into_bytes()))
                .collect(),
        )
        .unwrap();
        let _ = store.apply(&expected, &candidate, &mut Pause);
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn recovery_after_sigkill_restores_each_before_image() {
        use std::io::{BufRead, BufReader};
        use std::process::{Child, Command, Stdio};
        struct Process(Child);
        impl Drop for Process {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let fixture = Fixture::new();
        let mut process = Process(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "journal::tests::killed_process_fixture",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("XCLI_TEST_JOURNAL_ROOT", fixture._dir.path())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let output = process.0.stdout.take().unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(output)
                .lines()
                .map_while(std::result::Result::ok)
            {
                if line.contains("XCLI_JOURNAL_PAUSED") {
                    let _ = sent.send(());
                    break;
                }
            }
        });
        received.recv_timeout(Duration::from_secs(10)).unwrap();
        drop(process);
        reader.join().unwrap();
        assert!(fixture.store.root.join("transaction.json").exists());
        let mut hooks = FakeHooks::default();
        assert!(fixture.store.recover(&mut hooks).unwrap());
        fixture.old();
        assert!(!fixture.store.root.join("transaction.json").exists());
    }
}
