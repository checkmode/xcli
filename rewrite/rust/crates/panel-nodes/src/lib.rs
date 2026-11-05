//! Experimental panel-side remote node synchronization.
//!
//! A caller must serialize this database writer with panel and core changes,
//! serve it only over the existing authenticated HTTPS boundary, and avoid
//! logging the Authorization header or returned user identities.
use rusqlite::config::DbConfig;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;
use subtle::ConstantTimeEq;
mod manage;
pub use manage::ManageError;

#[derive(Debug, PartialEq, Eq)]
pub enum SyncError {
    Unauthorized,
    InvalidInput,
    CounterRollback,
    Unavailable,
}
type Result<T> = std::result::Result<T, SyncError>;

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}
fn hash(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}
fn exact_shape(value: &Value, fields: &[&str]) -> bool {
    value.as_object().is_some_and(|map| {
        map.len() == fields.len() && fields.iter().all(|name| map.contains_key(*name))
    })
}
fn add(a: i64, b: i64) -> Result<i64> {
    if a < 0 || b < 0 {
        return Err(SyncError::InvalidInput);
    }
    a.checked_add(b).ok_or(SyncError::InvalidInput)
}
fn canonical_users(users: &[(String, String, i64)]) -> Result<String> {
    let mut result = String::from("[");
    for (index, (id, uuid, expires)) in users.iter().enumerate() {
        if index > 0 {
            result.push(',');
        }
        // The old panel uses ordered_json and inserts keys in this order.
        // The bytes, including order, are the basis of the revision hash.
        result.push_str("{\"id\":");
        result.push_str(&serde_json::to_string(id).map_err(|_| SyncError::Unavailable)?);
        result.push_str(",\"uuid\":");
        result.push_str(&serde_json::to_string(uuid).map_err(|_| SyncError::Unavailable)?);
        result.push_str(",\"expires\":");
        result.push_str(&expires.to_string());
        result.push('}');
    }
    result.push(']');
    Ok(result)
}

/// Existing database only. This type does not own the global mutation lock.
pub struct NodeSync {
    db: Connection,
}
impl NodeSync {
    pub fn open(path: &Path) -> Result<Self> {
        if std::fs::symlink_metadata(path)
            .map_err(|_| SyncError::Unavailable)?
            .file_type()
            .is_symlink()
        {
            return Err(SyncError::Unavailable);
        }
        let name = path.file_name().ok_or(SyncError::Unavailable)?;
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let resolved = std::fs::canonicalize(parent)
            .map_err(|_| SyncError::Unavailable)?
            .join(name);
        let db = Connection::open_with_flags(
            resolved,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| SyncError::Unavailable)?;
        db.busy_timeout(Duration::from_secs(15))
            .map_err(|_| SyncError::Unavailable)?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;")
            .map_err(|_| SyncError::Unavailable)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(|_| SyncError::Unavailable)?;
        Ok(Self { db })
    }

    pub fn sync(&mut self, authorization: &str, input: &Value, now: i64) -> Result<Value> {
        let (node_id, secret) = authorization
            .strip_prefix("Xcli-Node ")
            .and_then(|value| value.split_once('.'))
            .filter(|(id, key)| lowercase_hex(id, 32) && token(key))
            .ok_or(SyncError::Unauthorized)?;
        if now < 0 || !exact_shape(input, &["revision", "counters"]) {
            return Err(SyncError::InvalidInput);
        }
        let revision = input["revision"].as_str().ok_or(SyncError::InvalidInput)?;
        if !revision.is_empty() && !lowercase_hex(revision, 64) {
            return Err(SyncError::InvalidInput);
        }
        let reports = input["counters"]
            .as_array()
            .filter(|items| items.len() <= 100)
            .ok_or(SyncError::InvalidInput)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SyncError::Unavailable)?;
        let stored: Option<String> = tx
            .query_row(
                "SELECT value FROM metadata WHERE key='remote_nodes_v1'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| SyncError::Unavailable)?;
        let mut registry: Value = match stored {
            Some(value) => serde_json::from_str(&value).map_err(|_| SyncError::Unavailable)?,
            None => json!([]),
        };
        let nodes = registry
            .as_array_mut()
            .filter(|items| items.len() <= 20)
            .ok_or(SyncError::Unavailable)?;
        let node = nodes
            .iter_mut()
            .find(|node| node.get("id").and_then(Value::as_str) == Some(node_id))
            .ok_or(SyncError::Unauthorized)?;
        let expected = node
            .get("key_hash")
            .and_then(Value::as_str)
            .ok_or(SyncError::Unavailable)?;
        let supplied = hash(secret.as_bytes());
        if expected.len() != supplied.len()
            || !bool::from(expected.as_bytes().ct_eq(supplied.as_bytes()))
        {
            return Err(SyncError::Unauthorized);
        }
        let history: BTreeSet<String> = node
            .get("history")
            .and_then(Value::as_array)
            .ok_or(SyncError::Unavailable)?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(SyncError::Unavailable)
            })
            .collect::<Result<_>>()?;
        let mut seen = BTreeSet::new();
        let (mut upload, mut download) = (0, 0);
        let last = node
            .get_mut("counters")
            .and_then(Value::as_object_mut)
            .ok_or(SyncError::Unavailable)?;
        for entry in reports {
            if !exact_shape(entry, &["id", "upload", "download"]) {
                return Err(SyncError::InvalidInput);
            }
            let id = entry["id"]
                .as_str()
                .filter(|value| lowercase_hex(value, 32))
                .ok_or(SyncError::InvalidInput)?;
            if !seen.insert(id.to_owned()) || !history.contains(id) {
                return Err(SyncError::InvalidInput);
            }
            let up = entry["upload"]
                .as_i64()
                .filter(|value| *value >= 0)
                .ok_or(SyncError::InvalidInput)?;
            let down = entry["download"]
                .as_i64()
                .filter(|value| *value >= 0)
                .ok_or(SyncError::InvalidInput)?;
            let (old_up, old_down) = match last.get(id) {
                Some(value) => (
                    value
                        .get("upload")
                        .and_then(Value::as_i64)
                        .ok_or(SyncError::Unavailable)?,
                    value
                        .get("download")
                        .and_then(Value::as_i64)
                        .ok_or(SyncError::Unavailable)?,
                ),
                None => (0, 0),
            };
            if old_up < 0 || old_down < 0 {
                return Err(SyncError::Unavailable);
            }
            if up < old_up || down < old_down {
                return Err(SyncError::CounterRollback);
            }
            let (du, dd) = (up - old_up, down - old_down);
            let user: Option<(i64, i64)> = tx
                .query_row(
                    "SELECT upload,download FROM users WHERE id=?",
                    [id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|_| SyncError::Unavailable)?;
            if let Some((current_up, current_down)) = user {
                tx.execute(
                    "UPDATE users SET upload=?,download=? WHERE id=?",
                    params![add(current_up, du)?, add(current_down, dd)?, id],
                )
                .map_err(|_| SyncError::Unavailable)?;
                upload = add(upload, du)?;
                download = add(download, dd)?;
            }
            last.insert(id.to_owned(), json!({"upload":up,"download":down}));
        }
        if upload != 0 || download != 0 {
            let bucket = now / 60 * 60;
            let previous: Option<(i64, i64)> = tx
                .query_row(
                    "SELECT upload,download FROM traffic_history WHERE ts=?",
                    [bucket],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|_| SyncError::Unavailable)?;
            let (old_up, old_down) = previous.unwrap_or((0, 0));
            tx.execute(
                "INSERT OR REPLACE INTO traffic_history VALUES(?,?,?)",
                params![bucket, add(old_up, upload)?, add(old_down, download)?],
            )
            .map_err(|_| SyncError::Unavailable)?;
            tx.execute(
                "INSERT INTO samples VALUES(?,?,?)",
                params![now, upload, download],
            )
            .map_err(|_| SyncError::Unavailable)?;
        }
        let pending = node
            .get("pending_revision")
            .and_then(Value::as_str)
            .ok_or(SyncError::Unavailable)?;
        if !revision.is_empty() && revision == pending {
            let pending_users = node
                .get("pending_users")
                .filter(|value| value.is_array())
                .ok_or(SyncError::Unavailable)?
                .clone();
            node["applied_revision"] = json!(revision);
            node["applied_users"] = pending_users;
        }
        node["last_seen"] = json!(now);
        let enabled = node
            .get("enabled")
            .and_then(Value::as_bool)
            .ok_or(SyncError::Unavailable)?;
        let selected = node
            .get("users")
            .and_then(Value::as_array)
            .ok_or(SyncError::Unavailable)?;
        let mut desired = Vec::new();
        if enabled {
            for selected_id in selected {
                let id = selected_id.as_str().ok_or(SyncError::Unavailable)?;
                let user:Option<(String,i64,i64,i64,i64,i64)>=tx.query_row(
                    "SELECT uuid,enabled,quota,expires,upload,download FROM users WHERE id=? AND deleted=0",[id],
                    |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)))
                    .optional().map_err(|_|SyncError::Unavailable)?;
                if let Some((uuid, enabled, quota, expires, up, down)) = user {
                    if xcli_panel_users::status(enabled != 0, expires, quota, up, down, now)
                        == "active"
                    {
                        desired.push((id.to_owned(), uuid, expires));
                    }
                }
            }
        }
        let revision = hash(canonical_users(&desired)?.as_bytes());
        let users = Value::Array(
            desired
                .into_iter()
                .map(|(id, uuid, expires)| json!({"id":id,"uuid":uuid,"expires":expires}))
                .collect(),
        );
        node["pending_revision"] = json!(revision);
        node["pending_users"] = users.clone();
        tx.execute(
            "INSERT OR REPLACE INTO metadata(key,value) VALUES('remote_nodes_v1',?)",
            [serde_json::to_string(&registry).map_err(|_| SyncError::Unavailable)?],
        )
        .map_err(|_| SyncError::Unavailable)?;
        tx.commit().map_err(|_| SyncError::Unavailable)?;
        Ok(
            json!({"revision":revision,"users":users,"lease_seconds":30,"issued_at":now,"ack":input["counters"]}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn revision_uses_legacy_ordered_json_bytes() {
        let users = vec![(
            "11111111111111111111111111111111".to_owned(),
            "01234567-89ab-4def-8123-456789abcdef".to_owned(),
            0,
        )];
        assert_eq!(
            hash(canonical_users(&users).unwrap().as_bytes()),
            "dbc0806f3c75333713a1fbe79bb0cc310a3713e5e788c25abd79a52f39d60abb"
        );
    }
}
