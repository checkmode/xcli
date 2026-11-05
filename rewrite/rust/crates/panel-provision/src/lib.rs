//! Experimental initialization of an empty, isolated panel database.
//!
//! Supports an empty SQLite connection or exclusive creation of a new private
//! database file. Callers remain responsible for trusted ancestor directories,
//! key material, TLS, service ownership, upgrades and production installation.
//! It refuses every nonempty schema and never restores or overwrites old data.
use rusqlite::{params, Connection, TransactionBehavior};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use xcli_auth_compat::hash_password;

#[derive(Debug, PartialEq, Eq)]
pub enum ProvisionError {
    InvalidPassword,
    AlreadyInitialized,
    Unavailable,
}
type Result<T> = std::result::Result<T, ProvisionError>;

// Schema is intentionally compatible with the existing C++ panel's initial
// database. The operations history migration is complete because a fresh
// database has no historical samples to import.
const SCHEMA: &str = r#"
    CREATE TABLE admin(id INTEGER PRIMARY KEY CHECK(id=1), password TEXT NOT NULL);
    CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT NOT NULL,uuid TEXT NOT NULL UNIQUE,
      token TEXT NOT NULL UNIQUE,enabled INTEGER NOT NULL DEFAULT 1,quota INTEGER NOT NULL DEFAULT 0,
      expires INTEGER NOT NULL DEFAULT 0,upload INTEGER NOT NULL DEFAULT 0,download INTEGER NOT NULL DEFAULT 0,
      created INTEGER NOT NULL,deleted INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE sessions(hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
    CREATE TABLE counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL,generation TEXT NOT NULL);
    CREATE TABLE samples(ts INTEGER NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL);
    CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);
    CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
    CREATE TABLE mfa(id INTEGER PRIMARY KEY CHECK(id=1),enabled INTEGER NOT NULL DEFAULT 0,
      secret TEXT NOT NULL DEFAULT '',last_step INTEGER NOT NULL DEFAULT -1,
      pending TEXT NOT NULL DEFAULT '',pending_expires INTEGER NOT NULL DEFAULT 0,pending_session TEXT NOT NULL DEFAULT '');
    INSERT INTO mfa(id) VALUES(1);
    CREATE TABLE mfa_sessions(hash TEXT PRIMARY KEY);
    CREATE TABLE recovery_codes(hash TEXT PRIMARY KEY,used INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE device_activity(user_id TEXT NOT NULL,transport TEXT NOT NULL,
      last_seen INTEGER NOT NULL DEFAULT 0,sampled INTEGER NOT NULL DEFAULT 0,
      upload_delta INTEGER NOT NULL DEFAULT 0,download_delta INTEGER NOT NULL DEFAULT 0,
      interval_seconds INTEGER NOT NULL DEFAULT 5,PRIMARY KEY(user_id,transport));
    CREATE INDEX samples_ts ON samples(ts);
    CREATE TABLE traffic_history(ts INTEGER PRIMARY KEY,upload INTEGER NOT NULL,download INTEGER NOT NULL);
    CREATE TABLE probe_history(ts INTEGER NOT NULL,transport TEXT NOT NULL,status TEXT NOT NULL,
      https_ms REAL,udp_ms REAL,PRIMARY KEY(ts,transport));
    CREATE TABLE notification_config(id INTEGER PRIMARY KEY CHECK(id=1),enabled INTEGER NOT NULL DEFAULT 0,
      url TEXT NOT NULL DEFAULT '',bearer TEXT NOT NULL DEFAULT '',signing TEXT NOT NULL DEFAULT '',
      generation TEXT NOT NULL DEFAULT '',failures INTEGER NOT NULL DEFAULT 3,recoveries INTEGER NOT NULL DEFAULT 2);
    INSERT INTO notification_config(id) VALUES(1);
    CREATE TABLE alarm_state(service TEXT PRIMARY KEY,bad INTEGER NOT NULL DEFAULT 0,
      good INTEGER NOT NULL DEFAULT 0,firing INTEGER NOT NULL DEFAULT 0,since INTEGER NOT NULL DEFAULT 0,
      last_sample INTEGER NOT NULL DEFAULT 0,last_seen INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE notifications(id TEXT PRIMARY KEY,created INTEGER NOT NULL,service TEXT NOT NULL,
      kind TEXT NOT NULL,payload TEXT NOT NULL,generation TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',
      attempts INTEGER NOT NULL DEFAULT 0,next_attempt INTEGER NOT NULL DEFAULT 0,
      delivered INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '',http_status INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX notification_pending ON notifications(status,next_attempt);
    INSERT INTO metadata(key,value) VALUES('operations_history_imported','1');
"#;

/// Initialize only a freshly created SQLite connection. Schema creation and
/// the legacy-compatible administrator hash are committed in one transaction.
/// The caller owns password acquisition and zeroization. This function never
/// returns or prints the password or hash.
pub fn initialize_empty(db: &mut Connection, password: &str) -> Result<()> {
    if !(16..=256).contains(&password.chars().count()) {
        return Err(ProvisionError::InvalidPassword);
    }
    let hash = hash_password(password).map_err(|_| ProvisionError::Unavailable)?;
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ProvisionError::Unavailable)?;
    let objects: i64 = tx
        .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
        .map_err(|_| ProvisionError::Unavailable)?;
    if objects != 0 {
        return Err(ProvisionError::AlreadyInitialized);
    }
    tx.execute_batch(SCHEMA)
        .map_err(|_| ProvisionError::Unavailable)?;
    tx.execute(
        "INSERT INTO admin(id,password) VALUES(1,?)",
        params![hash.as_str()],
    )
    .map_err(|_| ProvisionError::Unavailable)?;
    tx.commit().map_err(|_| ProvisionError::Unavailable)
}

/// Exclusively create a new 0600 database in a trusted, private parent
/// directory. The SQLite image is constructed entirely in memory, then written
/// and synced; an existing file is never opened for writing or replaced.
///
/// Callers must ensure all ancestors are trusted and stable, and must arrange
/// service ownership and durable key/credential storage separately. A crash
/// can leave an incomplete newly-created file; it is never silently reused or
/// overwritten. This is not an installer or upgrade operation.
pub fn initialize_new_file(path: &Path, password: &str) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if path.file_name().is_none() {
        return Err(ProvisionError::Unavailable);
    }
    let parent_meta = fs::symlink_metadata(parent).map_err(|_| ProvisionError::Unavailable)?;
    if !parent_meta.file_type().is_dir()
        || parent_meta.uid() != unsafe { libc::geteuid() }
        || parent_meta.mode() & 0o022 != 0
    {
        return Err(ProvisionError::Unavailable);
    }
    let mut db = Connection::open_in_memory().map_err(|_| ProvisionError::Unavailable)?;
    initialize_empty(&mut db, password)?;
    let image = db
        .serialize(rusqlite::MAIN_DB)
        .map_err(|_| ProvisionError::Unavailable)?;
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(ProvisionError::AlreadyInitialized)
        }
        Err(_) => return Err(ProvisionError::Unavailable),
    };
    let meta = file.metadata().map_err(|_| ProvisionError::Unavailable)?;
    let written = (|| {
        if !meta.is_file() || meta.nlink() != 1 || meta.uid() != unsafe { libc::geteuid() } {
            return Err(ProvisionError::Unavailable);
        }
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| ProvisionError::Unavailable)?;
        file.write_all(&image)
            .map_err(|_| ProvisionError::Unavailable)?;
        file.sync_all().map_err(|_| ProvisionError::Unavailable)?;
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| ProvisionError::Unavailable)?;
        Ok(())
    })();
    if written.is_err() {
        // The parent is required to be trusted. Never remove a path that no
        // longer names the inode created by this call.
        if fs::symlink_metadata(path).is_ok_and(|current| {
            current.file_type().is_file()
                && current.dev() == meta.dev()
                && current.ino() == meta.ino()
        }) {
            let _ = fs::remove_file(path);
        }
    }
    written
}
