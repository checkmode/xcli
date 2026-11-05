use super::{Error, Result, Store, User};
use rusqlite::config::DbConfig;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use std::path::Path;
use std::time::Duration;
use xcli_panel_traffic::{apply_in_transaction, Counter};

/// Isolated storage adapter. Callers must ensure a single controller and
/// serialize it with all session, user, node and core mutations.
pub struct SqliteStore {
    db: Connection,
    poll_seconds: i64,
    probe: Option<User>,
}

impl SqliteStore {
    pub fn open(path: &Path, poll_seconds: i64, probe: Option<User>) -> Result<Self> {
        if !(1..=60).contains(&poll_seconds) {
            return Err(Error::InvalidState);
        }
        if std::fs::symlink_metadata(path)
            .map_err(|_| Error::StorageUnavailable)?
            .file_type()
            .is_symlink()
        {
            return Err(Error::StorageUnavailable);
        }
        let name = path.file_name().ok_or(Error::StorageUnavailable)?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let resolved = std::fs::canonicalize(parent)
            .map_err(|_| Error::StorageUnavailable)?
            .join(name);
        let db = Connection::open_with_flags(
            resolved,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| Error::StorageUnavailable)?;
        db.busy_timeout(Duration::from_secs(15))
            .map_err(|_| Error::StorageUnavailable)?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;")
            .map_err(|_| Error::StorageUnavailable)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(|_| Error::StorageUnavailable)?;
        Ok(Self {
            db,
            poll_seconds,
            probe,
        })
    }
}

impl Store for SqliteStore {
    fn commit_sample_and_load(
        &mut self,
        generation: &str,
        counters: &[Counter],
        now: i64,
    ) -> Result<Vec<User>> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::StorageUnavailable)?;
        apply_in_transaction(&tx, generation, counters, now, self.poll_seconds)
            .map_err(|_| Error::StorageUnavailable)?;
        let mut users = {
            let mut statement = tx
                .prepare("SELECT id,uuid,enabled,deleted,quota,expires,upload,download FROM users")
                .map_err(|_| Error::StorageUnavailable)?;
            let result = statement
                .query_map([], |row| {
                    Ok(User {
                        id: row.get(0)?,
                        uuid: row.get(1)?,
                        enabled: row.get::<_, i64>(2)? != 0,
                        deleted: row.get::<_, i64>(3)? != 0,
                        quota: row.get(4)?,
                        expires: row.get(5)?,
                        upload: row.get(6)?,
                        download: row.get(7)?,
                    })
                })
                .map_err(|_| Error::StorageUnavailable)?;
            result
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| Error::StorageUnavailable)?
        };
        if let Some(probe) = self.probe.clone() {
            users.push(probe);
        }
        tx.commit().map_err(|_| Error::StorageUnavailable)?;
        Ok(users)
    }
    fn record_restart(&mut self, now: i64) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::StorageUnavailable)?;
        tx.execute(
            "INSERT INTO events(ts,action,detail) VALUES(?,?,?)",
            params![
                now,
                "core_restart",
                "凭据撤销、停用、到期或配额触发；现有连接将重新建立"
            ],
        )
        .map_err(|_| Error::StorageUnavailable)?;
        tx.execute(
            "DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM events)",
            [],
        )
        .map_err(|_| Error::StorageUnavailable)?;
        tx.commit().map_err(|_| Error::StorageUnavailable)
    }
}
