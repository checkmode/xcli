use super::{build, Error, Links, User};
use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use xcli_auth_compat::open_xgb1;
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    NotFound,
    Inactive,
    Unavailable,
}
type Result<T> = std::result::Result<T, StoreError>;
struct Record {
    id: String,
    user: User,
}

/// Contains a user's UUID and must never be logged.
pub struct ClashInput {
    pub user_id: String,
    pub name: String,
    pub uuid: String,
    pub token: String,
    pub settings: Value,
    pub remote_nodes: Vec<Value>,
    pub dynamic_enabled: bool,
    pub userinfo: String,
}

/// A reader of an existing legacy database. The caller must authorize admin
/// access, avoid logging link values, and serialize it with panel mutations.
pub struct SubscriptionStore {
    db: Connection,
    settings: Value,
    state: PathBuf,
    key: Zeroizing<[u8; 32]>,
}
impl SubscriptionStore {
    pub fn open(path: &Path, settings: Value, key: [u8; 32]) -> Result<Self> {
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
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let state = std::fs::canonicalize(parent).map_err(|_| StoreError::Unavailable)?;
        let db = Connection::open_with_flags(
            state.join(name),
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| StoreError::Unavailable)?;
        db.busy_timeout(Duration::from_secs(15))
            .map_err(|_| StoreError::Unavailable)?;
        db.execute_batch("PRAGMA trusted_schema=OFF;")
            .map_err(|_| StoreError::Unavailable)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(|_| StoreError::Unavailable)?;
        Ok(Self {
            db,
            settings,
            state,
            key: Zeroizing::new(key),
        })
    }
    fn dynamic_enabled(&self) -> bool {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.state.join("webshare/config.xgb"));
        let Ok(file) = file else { return false };
        if !file
            .metadata()
            .is_ok_and(|value| value.is_file() && value.len() <= 16384)
        {
            return false;
        }
        let mut ciphertext = Vec::new();
        if file.take(16385).read_to_end(&mut ciphertext).is_err() || ciphertext.len() > 16384 {
            return false;
        }
        let Ok(plaintext) = open_xgb1(&ciphertext, self.key.as_ref(), b"xcli:webshare:config:v1")
        else {
            return false;
        };
        serde_json::from_slice::<Value>(&plaintext)
            .ok()
            .and_then(|value| value.get("enabled").and_then(Value::as_bool))
            .unwrap_or(false)
    }
    fn lookup(tx: &Transaction<'_>, value: &str, by_token: bool) -> Result<Record> {
        let sql = if by_token {
            "SELECT id,name,uuid,token,enabled,deleted,quota,expires,upload,download FROM users WHERE token=? AND deleted=0"
        } else {
            "SELECT id,name,uuid,token,enabled,deleted,quota,expires,upload,download FROM users WHERE id=? AND deleted=0"
        };
        tx.query_row(sql, [value], |row| {
            Ok(Record {
                id: row.get(0)?,
                user: User {
                    name: row.get(1)?,
                    uuid: row.get(2)?,
                    token: row.get(3)?,
                    enabled: row.get::<_, i64>(4)? != 0,
                    deleted: row.get::<_, i64>(5)? != 0,
                    quota: row.get(6)?,
                    expires: row.get(7)?,
                    upload: row.get(8)?,
                    download: row.get(9)?,
                },
            })
        })
        .optional()
        .map_err(|_| StoreError::Unavailable)?
        .ok_or(StoreError::NotFound)
    }
    fn remote(tx: &Transaction<'_>, record: &Record) -> Result<Vec<Value>> {
        let raw: Option<String> = tx
            .query_row(
                "SELECT value FROM metadata WHERE key='remote_nodes_v1'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StoreError::Unavailable)?;
        let Some(raw) = raw else { return Ok(vec![]) };
        let registry: Value = serde_json::from_str(&raw).map_err(|_| StoreError::Unavailable)?;
        let nodes = registry
            .as_array()
            .filter(|items| items.len() <= 20)
            .ok_or(StoreError::Unavailable)?;
        let mut result = Vec::new();
        for node in nodes {
            if !node
                .get("enabled")
                .and_then(Value::as_bool)
                .ok_or(StoreError::Unavailable)?
            {
                continue;
            }
            let users = node
                .get("users")
                .and_then(Value::as_array)
                .ok_or(StoreError::Unavailable)?;
            if !users.iter().any(|value| value.as_str() == Some(&record.id)) {
                continue;
            }
            let applied = node
                .get("applied_users")
                .and_then(Value::as_array)
                .ok_or(StoreError::Unavailable)?;
            let mut matches = false;
            for value in applied {
                let id = value
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or(StoreError::Unavailable)?;
                let uuid = value
                    .get("uuid")
                    .and_then(Value::as_str)
                    .ok_or(StoreError::Unavailable)?;
                if id == record.id && uuid == record.user.uuid {
                    matches = true;
                }
            }
            if matches {
                result.push(node.clone());
            }
        }
        Ok(result)
    }
    fn resolve(&mut self, value: &str, by_token: bool) -> Result<(User, Links)> {
        let dynamic = self.dynamic_enabled();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| StoreError::Unavailable)?;
        let record = Self::lookup(&tx, value, by_token)?;
        let remote = Self::remote(&tx, &record)?;
        let links = build(&self.settings, &record.user, &remote, dynamic)
            .map_err(|_| StoreError::Unavailable)?;
        tx.commit().map_err(|_| StoreError::Unavailable)?;
        Ok((record.user, links))
    }
    pub fn links_for_id(&mut self, id: &str) -> Result<Vec<(String, String)>> {
        self.resolve(id, false).map(|(_, links)| links.entries)
    }
    /// Read only the identity needed to generate a diagnostic; never log the token.
    /// Callers must hold the panel mutation lock throughout the diagnostic.
    pub fn diagnostic_user(
        &mut self,
        id: &str,
        now: i64,
    ) -> Result<(Zeroizing<String>, &'static str)> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| StoreError::Unavailable)?;
        let record = Self::lookup(&tx, id, false)?;
        let user = &record.user;
        let status = xcli_panel_users::status(
            user.enabled,
            user.expires,
            user.quota,
            user.upload,
            user.download,
            now,
        );
        tx.commit().map_err(|_| StoreError::Unavailable)?;
        Ok((Zeroizing::new(record.user.token), status))
    }
    pub fn clash_input(&mut self, token: &str, now: i64) -> Result<ClashInput> {
        if token.len() != 43
            || !token
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(StoreError::NotFound);
        }
        self.profile_input(token, true, Some(now))
    }
    /// Used for pre-publication validation, including disabled or expired
    /// accounts. The caller must hold the panel mutation lock.
    pub fn template_input(&mut self, user_id: &str) -> Result<ClashInput> {
        self.profile_input(user_id, false, None)
    }
    /// Internal configuration for constructing an administrator's option
    /// catalog. The settings may contain secrets and must never be returned or
    /// logged directly.
    pub fn template_context(&self) -> (Value, bool) {
        (self.settings.clone(), self.dynamic_enabled())
    }
    fn profile_input(
        &mut self,
        value: &str,
        by_token: bool,
        now: Option<i64>,
    ) -> Result<ClashInput> {
        let dynamic_enabled = self.dynamic_enabled();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| StoreError::Unavailable)?;
        let record = Self::lookup(&tx, value, by_token)?;
        let user = &record.user;
        if now.is_some_and(|timestamp| {
            user.deleted
                || xcli_panel_users::status(
                    user.enabled,
                    user.expires,
                    user.quota,
                    user.upload,
                    user.download,
                    timestamp,
                ) != "active"
        }) {
            return Err(StoreError::Inactive);
        }
        let remote_nodes = Self::remote(&tx, &record)?;
        let userinfo = format!(
            "upload={}; download={}; total={}; expire={}",
            user.upload, user.download, user.quota, user.expires
        );
        tx.commit().map_err(|_| StoreError::Unavailable)?;
        Ok(ClashInput {
            user_id: record.id,
            name: record.user.name,
            uuid: record.user.uuid,
            token: record.user.token,
            settings: self.settings.clone(),
            remote_nodes,
            dynamic_enabled,
            userinfo,
        })
    }
    pub fn generic(&mut self, token: &str, now: i64) -> Result<(String, String)> {
        if token.len() != 43
            || !token
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(StoreError::NotFound);
        }
        let (user, links) = self.resolve(token, true)?;
        links
            .generic_subscription(&user, now)
            .map_err(|error| match error {
                Error::Inactive => StoreError::Inactive,
                Error::InvalidConfiguration => StoreError::Unavailable,
            })
    }
}
