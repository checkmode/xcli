//! Experimental encrypted legacy backup reading and creation. Restoring a live
//! system and coordinating cores are not implemented by this component.

pub mod migration;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use subtle::ConstantTimeEq;
use xcli_auth_compat::{open_xgb1, seal_xgb1};
use zeroize::{Zeroize, Zeroizing};

const MAX_ENCRYPTED: u64 = 64 * 1024 * 1024;
const MAX_DATABASE: u64 = 40 * 1024 * 1024;
const CONTEXT: &[u8] = b"xcli:backup:v1";
#[derive(Debug, PartialEq, Eq)]
pub enum BackupError {
    NotFound,
    Invalid,
    DifferentServer,
    Unavailable,
}
type Result<T> = std::result::Result<T, BackupError>;
fn valid_id(id: &str) -> bool {
    let Some((stamp, tail)) = id.split_once('-') else {
        return false;
    };
    let Some(random) = tail.strip_suffix(".xgb") else {
        return false;
    };
    (10..=12).contains(&stamp.len())
        && stamp.bytes().all(|c| c.is_ascii_digit())
        && random.len() == 32
        && random
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| BackupError::Unavailable)?;
    bytes[6] = (bytes[6] & 15) | 0x40;
    bytes[8] = (bytes[8] & 63) | 0x80;
    Ok(hex::encode(bytes))
}
fn retired_credentials() -> Result<(String, String)> {
    let id = random_id()?;
    let uuid = format!(
        "{}-{}-{}-{}-{}",
        &id[..8],
        &id[8..12],
        &id[12..16],
        &id[16..20],
        &id[20..]
    );
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| BackupError::Unavailable)?;
    Ok((uuid, URL_SAFE_NO_PAD.encode(bytes.as_ref())))
}
fn read_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| BackupError::NotFound)?;
    let metadata = file.metadata().map_err(|_| BackupError::Unavailable)?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(BackupError::Invalid);
    }
    let mut data = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|_| BackupError::Unavailable)?;
    if data.len() as u64 > limit {
        return Err(BackupError::Invalid);
    }
    Ok(data)
}
fn directory(path: &Path, create: bool) -> Result<PathBuf> {
    let mut created = false;
    if create {
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => created = true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(_) => return Err(BackupError::Unavailable),
        }
    }
    let meta = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            BackupError::NotFound
        } else {
            BackupError::Unavailable
        }
    })?;
    if !meta.file_type().is_dir() || meta.file_type().is_symlink() {
        return Err(BackupError::Unavailable);
    }
    if created {
        sync_directory(path.parent().ok_or(BackupError::Unavailable)?)?;
    }
    Ok(path.to_path_buf())
}
fn sync_directory(path: &Path) -> Result<()> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| BackupError::Unavailable)
}
fn summary(bundle: &Value, id: &str) -> Result<Value> {
    let get = |key: &str| bundle.get(key).cloned().ok_or(BackupError::Invalid);
    let domain = bundle
        .get("settings")
        .and_then(|v| v.get("domain"))
        .cloned()
        .ok_or(BackupError::Invalid)?;
    Ok(
        json!({"id":id,"created":get("created")?,"reason":get("reason")?,"users":get("users")?,"version":get("version")?,"domain":domain}),
    )
}
fn scrub(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(scrub),
        Value::Object(items) => items.values_mut().for_each(scrub),
        _ => (),
    }
}
struct SecretBundle(Value);
impl Drop for SecretBundle {
    fn drop(&mut self) {
        scrub(&mut self.0);
    }
}
// Credentials in these rows must not be logged.
struct SavedUser {
    id: String,
    name: String,
    uuid: String,
    token: String,
    enabled: i64,
    quota: i64,
    expires: i64,
    upload: i64,
    download: i64,
    created: i64,
    deleted: i64,
}
impl Drop for SavedUser {
    fn drop(&mut self) {
        self.id.zeroize();
        self.name.zeroize();
        self.uuid.zeroize();
        self.token.zeroize();
    }
}
struct RestorePlan {
    users: Vec<SavedUser>,
    rules: Option<String>,
}

// A rate change does not alter the server identity or the database restore
// contract; restore keeps the current server-side rate and configuration.
fn same_server_settings(current: &Value, saved: &Value) -> Result<bool> {
    let normalized = |value: &Value| -> Result<Zeroizing<Vec<u8>>> {
        let mut value = SecretBundle(value.clone());
        let object = value.0.as_object_mut().ok_or(BackupError::Invalid)?;
        if let Some(rate) = object.remove("hysteria2_brutal_mbps") {
            if !rate.as_u64().is_some_and(|v| (1..=1000).contains(&v)) {
                return Err(BackupError::Invalid);
            }
        }
        Ok(Zeroizing::new(serde_json::to_vec(&value.0).map_err(|_| BackupError::Invalid)?))
    };
    let a = Sha256::digest(normalized(current)?.as_slice());
    let b = Sha256::digest(normalized(saved)?.as_slice());
    Ok(bool::from(a.as_slice().ct_eq(b.as_slice())))
}
impl Drop for RestorePlan {
    fn drop(&mut self) {
        if let Some(value) = &mut self.rules {
            value.zeroize();
        }
    }
}

/// Uses a separate SQLite connection. The caller must hold the existing panel
/// mutation lock and must not run a legacy writer against the same state.
pub struct BackupStore {
    db: Connection,
    state: PathBuf,
    settings: Value,
    key: Zeroizing<[u8; 32]>,
    version: String,
    automatic: bool,
    interval: i64,
    retention: usize,
    retry_after: i64,
}
impl BackupStore {
    pub fn open(path: &Path, settings: Value, key: [u8; 32], version: String) -> Result<Self> {
        if fs::symlink_metadata(path)
            .map_err(|_| BackupError::Unavailable)?
            .file_type()
            .is_symlink()
        {
            return Err(BackupError::Unavailable);
        }
        let name = path.file_name().ok_or(BackupError::Unavailable)?;
        let parent = path
            .parent()
            .filter(|v| !v.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let state = fs::canonicalize(parent).map_err(|_| BackupError::Unavailable)?;
        let db = Connection::open_with_flags(
            state.join(name),
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| BackupError::Unavailable)?;
        db.busy_timeout(Duration::from_secs(15))
            .map_err(|_| BackupError::Unavailable)?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;")
            .map_err(|_| BackupError::Unavailable)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(|_| BackupError::Unavailable)?;
        if settings.get("domain").and_then(Value::as_str).is_none()
            || version.is_empty()
            || version.len() > 128
        {
            return Err(BackupError::Invalid);
        }
        Ok(Self {
            db,
            state,
            settings,
            key: Zeroizing::new(key),
            version,
            automatic: false,
            interval: 21_600,
            retention: 28,
            retry_after: 0,
        })
    }
    /// Configure the scheduler and retention bounds used by the legacy panel.
    /// Automatic backups remain disabled until explicitly enabled by a caller.
    pub fn configure(&mut self, automatic: bool, interval: i64, retention: usize) -> Result<()> {
        if !(60..=604_800).contains(&interval) || !(2..=365).contains(&retention) {
            return Err(BackupError::Invalid);
        }
        self.automatic = automatic;
        self.interval = interval;
        self.retention = retention;
        Ok(())
    }
    fn path(&self, id: &str) -> Result<PathBuf> {
        if !valid_id(id) {
            return Err(BackupError::NotFound);
        }
        Ok(directory(&self.state.join("backups"), false)?.join(id))
    }
    fn bundle(&self, id: &str) -> Result<SecretBundle> {
        let data = read_file(&self.path(id)?, MAX_ENCRYPTED)?;
        let plain =
            open_xgb1(&data, self.key.as_ref(), CONTEXT).map_err(|_| BackupError::Invalid)?;
        let value = SecretBundle(serde_json::from_slice(&plain).map_err(|_| BackupError::Invalid)?);
        if value.0.get("format").and_then(Value::as_i64) != Some(1)
            || value.0.get("application").and_then(Value::as_str) != Some("xcli")
        {
            return Err(BackupError::Invalid);
        }
        Ok(value)
    }
    pub fn download(&self, id: &str) -> Result<Vec<u8>> {
        read_file(&self.path(id)?, MAX_ENCRYPTED)
    }
    pub fn inspect(&self, id: &str) -> Result<Value> {
        let bundle = self.bundle(id)?;
        let mut result = summary(&bundle.0, id)?;
        result["same_server"] = json!(same_server_settings(&self.settings,
            bundle.0.get("settings").ok_or(BackupError::Invalid)?)?);
        result["preserves"] = json!([
            "当前管理员密码和二次验证",
            "当前流量累计下限",
            "当前服务器入口与证书"
        ]);
        Ok(result)
    }
    pub fn list(&self) -> Result<Vec<Value>> {
        let path = match directory(&self.state.join("backups"), false) {
            Ok(path) => path,
            Err(BackupError::NotFound) => return Ok(vec![]),
            Err(error) => return Err(error),
        };
        let mut entries = Vec::new();
        for entry in fs::read_dir(path).map_err(|_| BackupError::Unavailable)? {
            let entry = entry.map_err(|_| BackupError::Unavailable)?;
            let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !id.ends_with(".xgb") {
                continue;
            }
            let meta = fs::symlink_metadata(entry.path()).map_err(|_| BackupError::Unavailable)?;
            let time = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            let item = match self.bundle(&id).and_then(|bundle| summary(&bundle.0, &id)) {
                Ok(mut value) => {
                    value["bytes"] = json!(meta.len());
                    value["valid"] = json!(true);
                    value
                }
                Err(_) => json!({"id":id,"valid":false,"created":0,"reason":"校验失败"}),
            };
            entries.push((time, item));
        }
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.0));
        Ok(entries.into_iter().map(|(_, value)| value).collect())
    }
    pub fn status(&self) -> Result<Value> {
        let previous: Option<String> = self
            .db
            .query_row(
                "SELECT value FROM metadata WHERE key='last_backup'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| BackupError::Unavailable)?;
        let last = previous.map_or(Ok(0), |value| {
            value.parse::<i64>().map_err(|_| BackupError::Invalid)
        })?;
        let error: Option<String> = self
            .db
            .query_row(
                "SELECT value FROM metadata WHERE key='backup_error'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| BackupError::Unavailable)?;
        let failed = error.as_ref().is_some_and(|value| !value.is_empty());
        Ok(
            json!({"automatic":self.automatic,"interval":self.interval,"retention":self.retention,"retention_enforced":true,"last_backup":last,
            "next_backup":if !self.automatic { 0 } else if failed { self.retry_after } else { last.saturating_add(self.interval) },
            "error":error.unwrap_or_default(),"backups":self.list()?}),
        )
    }
    // Invalid or unreadable files are never deleted by retention. Only backups
    // authenticated with this server's key count toward the retention limit.
    fn prune(&self, protected: &str) -> Result<()> {
        let entries = self.list()?;
        if !entries
            .iter()
            .any(|item| item["id"] == protected && item["valid"] == true)
        {
            return Err(BackupError::Unavailable);
        }
        let mut kept = 1usize;
        let mut deleted = false;
        for entry in entries {
            if entry.get("valid").and_then(Value::as_bool) != Some(true) {
                continue;
            }
            let id = entry
                .get("id")
                .and_then(Value::as_str)
                .ok_or(BackupError::Invalid)?;
            if id == protected {
                continue;
            }
            kept += 1;
            if kept > self.retention {
                fs::remove_file(self.path(id)?).map_err(|_| BackupError::Unavailable)?;
                deleted = true;
            }
        }
        if deleted {
            sync_directory(&self.state.join("backups"))?;
        }
        Ok(())
    }

    /// The caller must hold the same mutation lock as manual backups and core
    /// updates. Retrying failures is deliberately rate-limited.
    pub fn scheduled(&mut self, stamp: i64) -> Result<bool> {
        if !self.automatic || stamp < self.retry_after {
            return Ok(false);
        }
        let last: Option<String> = self
            .db
            .query_row(
                "SELECT value FROM metadata WHERE key='last_backup'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| BackupError::Unavailable)?;
        let last = last.map_or(Ok(0), |value| {
            value.parse::<i64>().map_err(|_| BackupError::Invalid)
        })?;
        let failed: bool = self
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM metadata WHERE key='backup_error' AND value<>'')",
                [],
                |row| row.get(0),
            )
            .map_err(|_| BackupError::Unavailable)?;
        if !failed && stamp.saturating_sub(last) < self.interval {
            return Ok(false);
        }
        match self.create("automatic", stamp) {
            Ok(_) => {
                self.retry_after = 0;
                Ok(true)
            }
            Err(error) => {
                self.retry_after = stamp.saturating_add(300);
                let _ = self.db.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES('backup_error','自动备份失败；5 分钟后重试')", []);
                Err(error)
            }
        }
    }
    pub fn create(&mut self, reason: &str, stamp: i64) -> Result<Value> {
        if !["manual", "automatic", "before-restore"].contains(&reason)
            || !(1_000_000_000..=999_999_999_999).contains(&stamp)
        {
            return Err(BackupError::Invalid);
        }
        let dir = directory(&self.state.join("backups"), true)?;
        let pages: i64 = self
            .db
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .map_err(|_| BackupError::Unavailable)?;
        let page_size: i64 = self
            .db
            .query_row("PRAGMA page_size", [], |row| row.get(0))
            .map_err(|_| BackupError::Unavailable)?;
        if pages <= 0
            || page_size <= 0
            || pages
                .checked_mul(page_size)
                .is_none_or(|size| size > MAX_DATABASE as i64)
        {
            return Err(BackupError::Invalid);
        }
        // An on-disk SQLite snapshot can leave plaintext -wal/-shm files after
        // a crash. Keep the consistent snapshot entirely in memory instead.
        let mut copy = Connection::open_in_memory().map_err(|_| BackupError::Unavailable)?;
        copy.execute_batch("PRAGMA temp_store=MEMORY; PRAGMA trusted_schema=OFF;")
            .map_err(|_| BackupError::Unavailable)?;
        {
            let backup = rusqlite::backup::Backup::new(&self.db, &mut copy)
                .map_err(|_| BackupError::Unavailable)?;
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                match backup.step(256).map_err(|_| BackupError::Unavailable)? {
                    rusqlite::backup::StepResult::Done => break,
                    rusqlite::backup::StepResult::More => (),
                    _ => std::thread::sleep(Duration::from_millis(10)),
                }
                if Instant::now() >= deadline {
                    return Err(BackupError::Unavailable);
                }
            }
        }
        let check: String = copy
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(|_| BackupError::Invalid)?;
        if check != "ok" {
            return Err(BackupError::Invalid);
        }
        let users: i64 = copy
            .query_row("SELECT COUNT(*) FROM users WHERE deleted=0", [], |row| {
                row.get(0)
            })
            .map_err(|_| BackupError::Unavailable)?;
        let serialized = copy
            .serialize(rusqlite::MAIN_DB)
            .map_err(|_| BackupError::Unavailable)?;
        if serialized.len() as u64 > MAX_DATABASE {
            return Err(BackupError::Invalid);
        }
        let raw = Zeroizing::new(serialized.to_vec());
        drop(serialized);
        drop(copy);
        let id = format!("{stamp}-{}.xgb", random_id()?);
        let mut bundle = SecretBundle(
            json!({"format":1,"application":"xcli","version":self.version,"created":stamp,"reason":reason,"users":users,
            "settings":self.settings,"database":STANDARD.encode(raw.as_slice())}),
        );
        let serialized =
            Zeroizing::new(serde_json::to_vec(&bundle.0).map_err(|_| BackupError::Unavailable)?);
        let encrypted = seal_xgb1(&serialized, self.key.as_ref(), CONTEXT)
            .map_err(|_| BackupError::Unavailable)?;
        if let Some(Value::String(value)) = bundle.0.get_mut("database") {
            value.zeroize();
        }
        bundle.0["database"] = Value::Null;
        let path = dir.join(&id);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|_| BackupError::Unavailable)?;
        if file
            .write_all(&encrypted)
            .and_then(|_| file.sync_all())
            .is_err()
        {
            let _ = fs::remove_file(path);
            return Err(BackupError::Unavailable);
        }
        sync_directory(&dir)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| BackupError::Unavailable)?;
        tx.execute(
            "INSERT OR REPLACE INTO metadata(key,value) VALUES('last_backup',?)",
            [stamp.to_string()],
        )
        .map_err(|_| BackupError::Unavailable)?;
        tx.execute("DELETE FROM metadata WHERE key='backup_error'", [])
            .map_err(|_| BackupError::Unavailable)?;
        tx.execute(
            "INSERT INTO events(ts,action,detail) VALUES(?,'backup_created',?)",
            rusqlite::params![stamp, id],
        )
        .map_err(|_| BackupError::Unavailable)?;
        tx.execute(
            "DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM events)",
            [],
        )
        .map_err(|_| BackupError::Unavailable)?;
        tx.commit().map_err(|_| BackupError::Unavailable)?;
        self.prune(&id)?;
        summary(&bundle.0, &id)
    }

    fn restore_plan(&self, id: &str) -> Result<RestorePlan> {
        let bundle = self.bundle(id)?;
        if !same_server_settings(&self.settings, bundle.0.get("settings").ok_or(BackupError::Invalid)?)? {
            return Err(BackupError::DifferentServer);
        }
        let encoded = bundle
            .0
            .get("database")
            .and_then(Value::as_str)
            .ok_or(BackupError::Invalid)?;
        if encoded.len() > (MAX_DATABASE as usize).div_ceil(3) * 4 {
            return Err(BackupError::Invalid);
        }
        let decoded = Zeroizing::new(STANDARD.decode(encoded).map_err(|_| BackupError::Invalid)?);
        if decoded.len() as u64 > MAX_DATABASE
            || decoded.len() < 100
            || !decoded.starts_with(b"SQLite format 3\0")
            || ![1, 2].contains(&decoded[18])
            || ![1, 2].contains(&decoded[19])
        {
            return Err(BackupError::Invalid);
        }
        let logical_size = decoded.len();
        let mut bytes = Zeroizing::new(vec![0u8; logical_size + 20]);
        bytes[..logical_size].copy_from_slice(&decoded);
        drop(decoded);
        // SQLite cannot deserialize WAL-mode images. The backup API has
        // already merged WAL pages into this snapshot. Normalize its in-memory
        // header as documented, and retain 20 bytes of padding for malformed
        // authenticated images; the encrypted backup file is never modified.
        // https://www.sqlite.org/c3ref/deserialize.html
        bytes[18] = 1;
        bytes[19] = 1;
        let copy = Connection::open_in_memory().map_err(|_| BackupError::Unavailable)?;
        // SAFETY: `bytes` outlives `copy` (including every early return), its
        // storage is not reallocated or mutated until the connection is closed,
        // and READONLY prevents SQLite from modifying or freeing this buffer.
        // The logical length is distinct from the allocated padded capacity.
        let status = unsafe {
            rusqlite::ffi::sqlite3_deserialize(
                copy.handle(),
                rusqlite::MAIN_DB.as_ptr(),
                bytes.as_mut_ptr(),
                logical_size as i64,
                bytes.len() as i64,
                rusqlite::ffi::SQLITE_DESERIALIZE_READONLY,
            )
        };
        if status != rusqlite::ffi::SQLITE_OK {
            return Err(BackupError::Invalid);
        }
        copy.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY;")
            .map_err(|_| BackupError::Invalid)?;
        let check: String = copy
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(|_| BackupError::Invalid)?;
        if check != "ok" {
            return Err(BackupError::Invalid);
        }
        let mut users = Vec::new();
        {
            let mut statement=copy.prepare("SELECT id,name,uuid,token,enabled,quota,expires,upload,download,created,deleted FROM users").map_err(|_|BackupError::Invalid)?;
            let mut rows = statement.query([]).map_err(|_| BackupError::Invalid)?;
            while let Some(row) = rows.next().map_err(|_| BackupError::Invalid)? {
                if users.len() >= 100_000 {
                    return Err(BackupError::Invalid);
                }
                let user = SavedUser {
                    id: row.get(0).map_err(|_| BackupError::Invalid)?,
                    name: row.get(1).map_err(|_| BackupError::Invalid)?,
                    uuid: row.get(2).map_err(|_| BackupError::Invalid)?,
                    token: row.get(3).map_err(|_| BackupError::Invalid)?,
                    enabled: i64::from(
                        row.get::<_, i64>(4).map_err(|_| BackupError::Invalid)? != 0,
                    ),
                    quota: row.get(5).map_err(|_| BackupError::Invalid)?,
                    expires: row.get(6).map_err(|_| BackupError::Invalid)?,
                    upload: row.get(7).map_err(|_| BackupError::Invalid)?,
                    download: row.get(8).map_err(|_| BackupError::Invalid)?,
                    created: row.get(9).map_err(|_| BackupError::Invalid)?,
                    deleted: i64::from(
                        row.get::<_, i64>(10).map_err(|_| BackupError::Invalid)? != 0,
                    ),
                };
                if user.quota < 0
                    || user.expires < 0
                    || user.upload < 0
                    || user.download < 0
                    || user.created < 0
                {
                    return Err(BackupError::Invalid);
                }
                users.push(user);
            }
        }
        let rules: Option<String> = copy
            .query_row(
                "SELECT value FROM metadata WHERE key='rule_templates_v1'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| BackupError::Invalid)?;
        if rules.as_ref().is_some_and(|value| {
            value.len() > 1024 * 1024 || serde_json::from_str::<Value>(value).is_err()
        }) {
            return Err(BackupError::Invalid);
        }
        Ok(RestorePlan { users, rules })
    }

    /// The caller must hold the panel's
    /// mutation lock and provide a flush callback that durably samples all
    /// current core traffic or verifies that every core is stopped. It must
    /// also authenticate and authorize the administrator before calling this.
    pub fn restore_with_flush<F>(&mut self, id: &str, stamp: i64, flush: F) -> Result<Value>
    where
        F: FnOnce() -> Result<()>,
    {
        let plan = self.restore_plan(id)?;
        flush()?;
        let safety_backup = self.create("before-restore", stamp)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| BackupError::Unavailable)?;
        let mut usage = BTreeMap::new();
        let saved_ids: BTreeSet<_> = plan.users.iter().map(|user| user.id.as_str()).collect();
        let mut retired = Vec::new();
        {
            let mut query = tx
                .prepare("SELECT id,name,quota,expires,upload,download,created FROM users")
                .map_err(|_| BackupError::Unavailable)?;
            let mut rows = query.query([]).map_err(|_| BackupError::Unavailable)?;
            while let Some(row) = rows.next().map_err(|_| BackupError::Unavailable)? {
                let id: String = row.get(0).map_err(|_| BackupError::Unavailable)?;
                let upload: i64 = row.get(4).map_err(|_| BackupError::Unavailable)?;
                let download: i64 = row.get(5).map_err(|_| BackupError::Unavailable)?;
                if upload < 0 || download < 0 {
                    return Err(BackupError::Invalid);
                }
                if !saved_ids.contains(id.as_str()) {
                    // Keep removed users as disabled tombstones. A remote node
                    // may still report previously unacknowledged usage for them.
                    let (uuid, token) = retired_credentials()?;
                    retired.push(SavedUser {
                        id: id.clone(),
                        name: row.get(1).map_err(|_| BackupError::Unavailable)?,
                        uuid,
                        token,
                        enabled: 0,
                        quota: row.get(2).map_err(|_| BackupError::Unavailable)?,
                        expires: row.get(3).map_err(|_| BackupError::Unavailable)?,
                        upload,
                        download,
                        created: row.get(6).map_err(|_| BackupError::Unavailable)?,
                        deleted: 1,
                    });
                }
                usage.insert(id, (upload, download));
            }
        }
        tx.execute("DELETE FROM users", [])
            .map_err(|_| BackupError::Unavailable)?;
        for user in &plan.users {
            let previous = usage.get(&user.id).copied().unwrap_or((0, 0));
            tx.execute("INSERT INTO users(id,name,uuid,token,enabled,quota,expires,upload,download,created,deleted) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                rusqlite::params![user.id,user.name,user.uuid,user.token,user.enabled,user.quota,user.expires,
                    user.upload.max(previous.0),user.download.max(previous.1),user.created,user.deleted]).map_err(|_|BackupError::Unavailable)?;
        }
        for user in &retired {
            tx.execute("INSERT INTO users(id,name,uuid,token,enabled,quota,expires,upload,download,created,deleted) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                rusqlite::params![user.id,user.name,user.uuid,user.token,user.enabled,user.quota,user.expires,
                    user.upload,user.download,user.created,user.deleted]).map_err(|_|BackupError::Unavailable)?;
        }
        if let Some(rules) = &plan.rules {
            tx.execute(
                "INSERT OR REPLACE INTO metadata(key,value) VALUES('rule_templates_v1',?)",
                [rules],
            )
            .map_err(|_| BackupError::Unavailable)?;
        } else {
            tx.execute("DELETE FROM metadata WHERE key='rule_templates_v1'", [])
                .map_err(|_| BackupError::Unavailable)?;
        }
        for sql in [
            "DELETE FROM sessions",
            "DELETE FROM mfa_sessions",
            "DELETE FROM device_activity",
            "DELETE FROM metadata WHERE key='activity_sample'",
        ] {
            tx.execute(sql, []).map_err(|_| BackupError::Unavailable)?;
        }
        tx.execute(
            "INSERT INTO events(ts,action,detail) VALUES(?,'backup_restored',?)",
            rusqlite::params![stamp, id],
        )
        .map_err(|_| BackupError::Unavailable)?;
        tx.execute(
            "DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM events)",
            [],
        )
        .map_err(|_| BackupError::Unavailable)?;
        tx.commit().map_err(|_| BackupError::Unavailable)?;
        Ok(safety_backup)
    }
}
