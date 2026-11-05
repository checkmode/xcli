//! Idempotent event storage for the encrypted Webshare write journal.
use crate::{AuditRecord, Auditor, Error};
use rusqlite::config::DbConfig;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use std::path::Path;
use std::time::Duration;

pub struct SqliteAuditor {
    db: Connection,
}
impl SqliteAuditor {
    /// Open an existing panel database while the panel owns its controller
    /// lock. The caller must serialize this with other panel mutations.
    pub fn open(path: &Path) -> Result<Self, Error> {
        if std::fs::symlink_metadata(path)
            .map_err(|_| Error::Unavailable)?
            .file_type()
            .is_symlink()
        {
            return Err(Error::Unavailable);
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let resolved = std::fs::canonicalize(parent)
            .map_err(|_| Error::Unavailable)?
            .join(path.file_name().ok_or(Error::Unavailable)?);
        let db = Connection::open_with_flags(
            resolved,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| Error::Unavailable)?;
        db.busy_timeout(Duration::from_secs(15))
            .map_err(|_| Error::Unavailable)?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;")
            .map_err(|_| Error::Unavailable)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(|_| Error::Unavailable)?;
        db.prepare("SELECT id,ts,action,detail FROM events LIMIT 0")
            .map_err(|_| Error::Unavailable)?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS xcli_webshare_audit_ops (id TEXT PRIMARY KEY) WITHOUT ROWID;")
            .map_err(|_| Error::Unavailable)?;
        Ok(Self { db })
    }
}
impl Auditor for SqliteAuditor {
    fn record(&mut self, record: &AuditRecord) -> Result<(), Error> {
        if record.timestamp < 0
            || record.id.len() != 32
            || !record.id.bytes().all(|c| c.is_ascii_hexdigit())
            || !matches!(
                (record.action, record.detail),
                (
                    "webshare_configured",
                    "动态住宅池已请求启用" | "Webshare 配置已保存"
                ) | (
                    "webshare_requested",
                    "请求同步 Webshare" | "请求更换动态住宅会话"
                )
            )
        {
            return Err(Error::Unavailable);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Unavailable)?;
        let inserted = tx
            .execute(
                "INSERT OR IGNORE INTO xcli_webshare_audit_ops(id) VALUES(?)",
                [&record.id],
            )
            .map_err(|_| Error::Unavailable)?;
        if inserted == 1 {
            tx.execute(
                "INSERT INTO events(ts,action,detail) VALUES(?,?,?)",
                params![record.timestamp, record.action, record.detail],
            )
            .map_err(|_| Error::Unavailable)?;
            tx.execute(
                "DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM events)",
                [],
            )
            .map_err(|_| Error::Unavailable)?;
        }
        tx.commit().map_err(|_| Error::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Control;
    use serde_json::json;

    struct FailAfterCommit<'a>(&'a mut SqliteAuditor);
    impl Auditor for FailAfterCommit<'_> {
        fn record(&mut self, record: &AuditRecord) -> Result<(), Error> {
            self.0.record(record)?;
            Err(Error::Unavailable)
        }
    }
    #[test]
    fn sqlite_failure_rolls_back_marker_and_recovery_deduplicates_committed_event() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);\
            CREATE TRIGGER reject_webshare BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
        let control = Control::open(dir.path(), json!({}), [4; 32]).unwrap();
        let mut audit = SqliteAuditor::open(&path).unwrap();
        assert_eq!(
            control.configure_audited(
                &json!({"api_key":"synthetic-api-key-for-test"}),
                1000,
                &mut audit
            ),
            Err(Error::Unavailable)
        );
        let count: i64 = db
            .query_row("SELECT count(*) FROM xcli_webshare_audit_ops", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
        db.execute_batch("DROP TRIGGER reject_webshare").unwrap();
        assert_eq!(
            control.recover(&mut FailAfterCommit(&mut audit)),
            Err(Error::Unavailable)
        );
        control.recover(&mut audit).unwrap();
        let count: i64 = db
            .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
        let secret = b"synthetic-api-key-for-test";
        assert!(!std::fs::read(path)
            .unwrap()
            .windows(secret.len())
            .any(|bytes| bytes == secret));
    }
}
