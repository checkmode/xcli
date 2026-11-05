use super::{status, validate, ValidationError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rusqlite::config::DbConfig;
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::Serialize;
use serde_json::Value;
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    InvalidInput(ValidationError),
    NotFound,
    Limit,
    RemoteHistory,
    Unavailable,
}
type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct UserSummary {
    pub id: String,
    pub name: String,
    pub enabled: i64,
    pub quota: i64,
    pub expires: i64,
    pub upload: i64,
    pub download: i64,
    pub created: i64,
    pub status: &'static str,
}

#[derive(Serialize)]
pub struct AuditEvent {
    pub ts: i64,
    pub action: String,
    pub detail: String,
}

fn random_id() -> Result<String> {
    let mut bytes = Zeroizing::new([0u8; 16]);
    getrandom::fill(bytes.as_mut()).map_err(|_| StoreError::Unavailable)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(hex::encode(bytes.as_ref()))
}
fn random_uuid() -> Result<String> {
    let id = random_id()?;
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &id[..8],
        &id[8..12],
        &id[12..16],
        &id[16..20],
        &id[20..]
    ))
}
fn random_token() -> Result<String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| StoreError::Unavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes.as_ref()))
}
fn audit(tx: &Transaction<'_>, now: i64, action: &str, detail: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO events(ts,action,detail) VALUES(?,?,?)",
        params![now, action, detail],
    )
    .map_err(|_| StoreError::Unavailable)?;
    tx.execute(
        "DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM events)",
        [],
    )
    .map_err(|_| StoreError::Unavailable)?;
    Ok(())
}
fn existing_name(tx: &Transaction<'_>, id: &str) -> Result<String> {
    tx.query_row(
        "SELECT name FROM users WHERE id=? AND deleted=0",
        [id],
        |row| row.get(0),
    )
    .optional()
    .map_err(|_| StoreError::Unavailable)?
    .ok_or(StoreError::NotFound)
}

fn ensure_no_remote_history(tx: &Transaction<'_>, id: &str) -> Result<()> {
    let raw: Option<String> = tx
        .query_row(
            "SELECT value FROM metadata WHERE key='remote_nodes_v1'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| StoreError::Unavailable)?;
    let Some(raw) = raw else { return Ok(()) };
    if raw.len() > 16 * 1024 * 1024 {
        return Err(StoreError::Unavailable);
    }
    let value: Value = serde_json::from_str(&raw).map_err(|_| StoreError::Unavailable)?;
    let nodes = value
        .as_array()
        .filter(|nodes| nodes.len() <= 20)
        .ok_or(StoreError::Unavailable)?;
    let mut found = false;
    for node in nodes {
        let history = node
            .get("history")
            .and_then(Value::as_array)
            .filter(|history| history.len() <= 5000)
            .ok_or(StoreError::Unavailable)?;
        for value in history {
            let user = value
                .as_str()
                .filter(|user| {
                    user.len() == 32
                        && user
                            .bytes()
                            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                })
                .ok_or(StoreError::Unavailable)?;
            found |= user == id;
        }
    }
    if found {
        Err(StoreError::RemoteHistory)
    } else {
        Ok(())
    }
}

/// Existing database only; never use alongside another process writing the
/// production panel database. Session/CSRF checks are the caller's duty.
pub struct Repository {
    db: Connection,
}

impl Repository {
    pub fn open(path: &Path) -> Result<Self> {
        if std::fs::symlink_metadata(path)
            .map_err(|_| StoreError::Unavailable)?
            .file_type()
            .is_symlink()
        {
            return Err(StoreError::Unavailable);
        }
        let name = path.file_name().ok_or(StoreError::Unavailable)?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let resolved = std::fs::canonicalize(parent)
            .map_err(|_| StoreError::Unavailable)?
            .join(name);
        let db = Connection::open_with_flags(
            resolved,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| StoreError::Unavailable)?;
        db.busy_timeout(Duration::from_secs(15))
            .map_err(|_| StoreError::Unavailable)?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;")
            .map_err(|_| StoreError::Unavailable)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(|_| StoreError::Unavailable)?;
        Ok(Self { db })
    }

    pub fn list(&self, now: i64) -> Result<Vec<UserSummary>> {
        let mut statement = self.db.prepare("SELECT id,name,enabled,quota,expires,upload,download,created FROM users WHERE deleted=0 ORDER BY created")
            .map_err(|_| StoreError::Unavailable)?;
        let users = statement
            .query_map([], |row| {
                let enabled: i64 = row.get(2)?;
                let quota = row.get(3)?;
                let expires = row.get(4)?;
                let upload = row.get(5)?;
                let download = row.get(6)?;
                Ok(UserSummary {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    enabled: i64::from(enabled != 0),
                    quota,
                    expires,
                    upload,
                    download,
                    created: row.get(7)?,
                    status: status(enabled != 0, expires, quota, upload, download, now),
                })
            })
            .map_err(|_| StoreError::Unavailable)?;
        users
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| StoreError::Unavailable)
    }

    /// Admin-only callers may show the same bounded recent audit as the
    /// legacy overview. Event details can contain IPs and must not be logged.
    pub fn recent_events(&self) -> Result<Vec<AuditEvent>> {
        let mut statement = self
            .db
            .prepare("SELECT ts,action,detail FROM events ORDER BY id DESC LIMIT 30")
            .map_err(|_| StoreError::Unavailable)?;
        let mut rows = statement.query([]).map_err(|_| StoreError::Unavailable)?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(|_| StoreError::Unavailable)? {
            let event = AuditEvent {
                ts: row.get(0).map_err(|_| StoreError::Unavailable)?,
                action: row.get(1).map_err(|_| StoreError::Unavailable)?,
                detail: row.get(2).map_err(|_| StoreError::Unavailable)?,
            };
            if event.ts < 0 || event.action.len() > 256 || event.detail.len() > 4096 {
                return Err(StoreError::Unavailable);
            }
            result.push(event);
        }
        Ok(result)
    }

    /// Read local sampled activity only. These records identify an account
    /// and transport, not individual physical devices or remote-node activity.
    pub fn activity(&self, now: i64) -> Result<Value> {
        if now < 0 {
            return Err(StoreError::Unavailable);
        }
        let mut statement = self.db.prepare("SELECT user_id,transport,last_seen,sampled,upload_delta,download_delta,interval_seconds FROM device_activity WHERE user_id IN (SELECT id FROM users WHERE deleted=0) LIMIT 10001")
            .map_err(|_| StoreError::Unavailable)?;
        let mut rows = statement.query([]).map_err(|_| StoreError::Unavailable)?;
        let mut result = serde_json::Map::new();
        let mut count = 0;
        while let Some(row) = rows.next().map_err(|_| StoreError::Unavailable)? {
            count += 1;
            if count > 10000 {
                return Err(StoreError::Unavailable);
            }
            let id: String = row.get(0).map_err(|_| StoreError::Unavailable)?;
            let transport: String = row.get(1).map_err(|_| StoreError::Unavailable)?;
            let last: i64 = row.get(2).map_err(|_| StoreError::Unavailable)?;
            let sample: i64 = row.get(3).map_err(|_| StoreError::Unavailable)?;
            let up: i64 = row.get(4).map_err(|_| StoreError::Unavailable)?;
            let down: i64 = row.get(5).map_err(|_| StoreError::Unavailable)?;
            let interval: i64 = row.get(6).map_err(|_| StoreError::Unavailable)?;
            if id.len() != 32
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || transport.is_empty()
                || transport.len() > 64
                || transport.chars().any(char::is_control)
                || [last, sample, up, down].into_iter().any(|v| v < 0)
                || !(1..=300).contains(&interval)
            {
                return Err(StoreError::Unavailable);
            }
            let stale = now.saturating_sub(sample) > 30
                || sample > now.saturating_add(60)
                || last > now.saturating_add(60);
            let status = if stale {
                "unknown"
            } else if last == 0 {
                "never"
            } else if now.saturating_sub(last) <= 60 {
                "recent"
            } else {
                "idle"
            };
            let value = serde_json::json!({"user_id":id,"transport":transport,"last_seen":last,"sampled":sample,
                "upload_delta":up,"download_delta":down,"interval_seconds":interval,"status":status,
                "upload_rate":if stale {0.0} else {up as f64 / interval as f64},
                "download_rate":if stale {0.0} else {down as f64 / interval as f64}});
            let group = result.entry(id).or_insert_with(|| serde_json::json!({}));
            group
                .as_object_mut()
                .ok_or(StoreError::Unavailable)?
                .insert(transport, value);
        }
        Ok(Value::Object(result))
    }

    pub fn create(&mut self, input: &Value, now: i64) -> Result<String> {
        let value = validate(input).map_err(StoreError::InvalidInput)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Unavailable)?;
        let count: i64 = tx
            .query_row("SELECT COUNT(*) FROM users WHERE deleted=0", [], |row| {
                row.get(0)
            })
            .map_err(|_| StoreError::Unavailable)?;
        if count >= 500 {
            return Err(StoreError::Limit);
        }
        let id = random_id()?;
        tx.execute("INSERT INTO users(id,name,uuid,token,enabled,quota,expires,created) VALUES(?,?,?,?,?,?,?,?)",
            params![id, value.name, random_uuid()?, random_token()?, i64::from(value.enabled), value.quota, value.expires, now])
            .map_err(|_| StoreError::Unavailable)?;
        audit(&tx, now, "user_created", &value.name)?;
        tx.commit().map_err(|_| StoreError::Unavailable)?;
        Ok(id)
    }

    pub fn update(&mut self, id: &str, input: &Value, now: i64) -> Result<()> {
        let value = validate(input).map_err(StoreError::InvalidInput)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Unavailable)?;
        existing_name(&tx, id)?;
        tx.execute(
            "UPDATE users SET name=?,enabled=?,quota=?,expires=? WHERE id=?",
            params![
                value.name,
                i64::from(value.enabled),
                value.quota,
                value.expires,
                id
            ],
        )
        .map_err(|_| StoreError::Unavailable)?;
        audit(&tx, now, "user_updated", &value.name)?;
        tx.commit().map_err(|_| StoreError::Unavailable)
    }

    pub fn delete(&mut self, id: &str, now: i64) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Unavailable)?;
        let name = existing_name(&tx, id)?;
        tx.execute(
            "UPDATE users SET deleted=1,enabled=0,token=? WHERE id=?",
            params![random_token()?, id],
        )
        .map_err(|_| StoreError::Unavailable)?;
        audit(&tx, now, "user_deleted", &name)?;
        tx.commit().map_err(|_| StoreError::Unavailable)
    }

    pub fn rotate(&mut self, id: &str, now: i64) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Unavailable)?;
        let name = existing_name(&tx, id)?;
        tx.execute(
            "UPDATE users SET uuid=?,token=? WHERE id=?",
            params![random_uuid()?, random_token()?, id],
        )
        .map_err(|_| StoreError::Unavailable)?;
        audit(&tx, now, "credentials_rotated", &name)?;
        tx.commit().map_err(|_| StoreError::Unavailable)
    }

    /// Check before contacting the core; the same check is repeated in the
    /// write transaction so a racing node grant cannot be silently ignored.
    pub fn ensure_resettable(&mut self, id: &str) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| StoreError::Unavailable)?;
        existing_name(&tx, id)?;
        ensure_no_remote_history(&tx, id)?;
        tx.commit().map_err(|_| StoreError::Unavailable)
    }

    /// Commit the sampled baseline and reset in one transaction. The caller
    /// must hold the panel mutation lock and verify the Xray generation both
    /// before and after the non-resetting counter read.
    pub fn reset_sampled(
        &mut self,
        id: &str,
        generation: &str,
        counters: &[xcli_panel_traffic::Counter],
        now: i64,
        poll_seconds: i64,
    ) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Unavailable)?;
        let name = existing_name(&tx, id)?;
        ensure_no_remote_history(&tx, id)?;
        xcli_panel_traffic::apply_in_transaction(&tx, generation, counters, now, poll_seconds)
            .map_err(|_| StoreError::Unavailable)?;
        tx.execute("UPDATE users SET upload=0,download=0 WHERE id=?", [id])
            .map_err(|_| StoreError::Unavailable)?;
        audit(&tx, now, "traffic_reset", &name)?;
        tx.commit().map_err(|_| StoreError::Unavailable)
    }
}
