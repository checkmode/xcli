//! Idempotent audit for import-request publication and crash recovery.
use super::{AuditRecord, Auditor, PublishError, Result};
use rusqlite::config::DbConfig;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use std::path::Path;
use std::time::Duration;

pub struct SqliteAuditor {
    db: Connection,
}
impl SqliteAuditor {
    /// The panel must own the database lock and serialize all mutations.
    pub fn open(path: &Path) -> Result<Self> {
        if std::fs::symlink_metadata(path)
            .map_err(|_| PublishError::Unavailable)?
            .file_type()
            .is_symlink()
        {
            return Err(PublishError::Unavailable);
        }
        let name = path.file_name().ok_or(PublishError::Unavailable)?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let path = std::fs::canonicalize(parent)
            .map_err(|_| PublishError::Unavailable)?
            .join(name);
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| PublishError::Unavailable)?;
        db.busy_timeout(Duration::from_secs(15))
            .map_err(|_| PublishError::Unavailable)?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;")
            .map_err(|_| PublishError::Unavailable)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(|_| PublishError::Unavailable)?;
        db.prepare("SELECT id,ts,action,detail FROM events LIMIT 0")
            .map_err(|_| PublishError::Unavailable)?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS xcli_import_audit_ops (id TEXT PRIMARY KEY,ts INTEGER NOT NULL) WITHOUT ROWID;")
            .map_err(|_| PublishError::Unavailable)?;
        Ok(Self { db })
    }
}
fn detail_allowed(detail: &str) -> bool {
    if ["请求检测固定代理", "确认应用代理变更"].contains(&detail) {
        return true;
    }
    let Some(tail) = detail.strip_prefix("请求管理代理 ") else {
        return false;
    };
    let Some((action, tag)) = tail.split_once(' ') else {
        return false;
    };
    ["edit", "enable", "disable", "delete", "restore"].contains(&action)
        && tag.len() == 14
        && tag.starts_with("residential-")
        && tag[12..].bytes().all(|b| b.is_ascii_digit())
}
impl Auditor for SqliteAuditor {
    fn record(&mut self, event: &AuditRecord) -> Result<()> {
        if !super::identifier(&event.id) || event.timestamp < 0 || !detail_allowed(&event.detail) {
            return Err(PublishError::Invalid);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| PublishError::Unavailable)?;
        let inserted = tx
            .execute(
                "INSERT OR IGNORE INTO xcli_import_audit_ops(id,ts) VALUES(?,?)",
                params![event.id, event.timestamp],
            )
            .map_err(|_| PublishError::Unavailable)?;
        if inserted == 1 {
            tx.execute(
                "INSERT INTO events(ts,action,detail) VALUES(?,'proxy_import_requested',?)",
                params![event.timestamp, event.detail],
            )
            .map_err(|_| PublishError::Unavailable)?;
            tx.execute(
                "DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM events)",
                [],
            )
            .map_err(|_| PublishError::Unavailable)?;
        }
        tx.execute(
            "DELETE FROM xcli_import_audit_ops WHERE ts<?",
            [event.timestamp.saturating_sub(30 * 86400)],
        )
        .map_err(|_| PublishError::Unavailable)?;
        tx.commit().map_err(|_| PublishError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publisher::Publisher;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Barrier};

    struct FailAfterCommit<'a>(&'a mut SqliteAuditor);
    impl Auditor for FailAfterCommit<'_> {
        fn record(&mut self, event: &AuditRecord) -> Result<()> {
            self.0.record(event)?;
            Err(PublishError::Unavailable)
        }
    }
    #[test]
    fn audit_failure_recovery_is_durable_and_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        std::fs::create_dir(&inbox).unwrap();
        std::fs::set_permissions(&inbox, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("gateway.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);
            CREATE TRIGGER reject_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
        let key = [42u8; 32];
        let publisher = Publisher::open(&inbox, key).unwrap();
        let mut audit = SqliteAuditor::open(&path).unwrap();
        let prepared = crate::request::prepare(
            &json!({"action":"preview","protocol":"socks","label":"fixture",
            "text":"1.1.1.1:80:synthetic-user:synthetic-password"}),
            1000,
            &key,
            0,
        )
        .unwrap();
        assert_eq!(
            publisher.submit(
                &prepared,
                &json!({"status":"idle","updated":1000,"id":""}),
                1000,
                &mut audit
            ),
            Err(PublishError::Unavailable)
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM xcli_import_audit_ops", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        db.execute_batch("DROP TRIGGER reject_event").unwrap();
        assert_eq!(
            publisher.recover(1000, &mut FailAfterCommit(&mut audit)),
            Err(PublishError::Unavailable)
        );
        publisher.recover(1000, &mut audit).unwrap();
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM events WHERE action='proxy_import_requested'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM xcli_import_audit_ops", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert!(!std::fs::read(path)
            .unwrap()
            .windows(18)
            .any(|part| part == b"synthetic-password"));
    }

    #[test]
    fn concurrent_publishers_never_overwrite_an_unacknowledged_request() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        std::fs::create_dir(&inbox).unwrap();
        std::fs::set_permissions(&inbox, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("gateway.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);").unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let barrier = barrier.clone();
                let path = path.clone();
                let inbox = inbox.clone();
                std::thread::spawn(move || {
                    let key = [42u8; 32];
                    let publisher = Publisher::open(&inbox, key).unwrap();
                    let mut audit = SqliteAuditor::open(&path).unwrap();
                    let prepared = crate::request::prepare(
                        &json!({"action":"preview","protocol":"socks","label":"fixture",
                    "text":"1.1.1.1:80:synthetic-user:synthetic-password"}),
                        1000,
                        &key,
                        0,
                    )
                    .unwrap();
                    barrier.wait();
                    publisher.submit(
                        &prepared,
                        &json!({"status":"idle","updated":1000,"id":""}),
                        1000,
                        &mut audit,
                    )
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(PublishError::Busy))
                .count(),
            1
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM events WHERE action='proxy_import_requested'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    }
}
