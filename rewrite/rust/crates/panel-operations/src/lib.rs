//! Experimental, legacy-compatible history sampling and queries.
//!
//! The owning panel must authorize reads and serialize collection against
//! mutations. The webhook transport is separate and is not yet scheduled by
//! the panel; these components do not control Xray.
pub mod alarm;
pub mod notifications;
pub mod sender;
pub mod webhook;
use rusqlite::{params, Connection, OpenFlags, Transaction, TransactionBehavior};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Unavailable,
}
type Result<T> = std::result::Result<T, Error>;
const RETENTION: i64 = 30 * 86_400;

fn open_db(path: &Path) -> Result<Connection> {
    if std::fs::symlink_metadata(path)
        .map_err(|_| Error::Unavailable)?
        .file_type()
        .is_symlink()
    {
        return Err(Error::Unavailable);
    }
    let name = path.file_name().ok_or(Error::Unavailable)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let resolved = std::fs::canonicalize(parent)
        .map_err(|_| Error::Unavailable)?
        .join(name);
    let db = Connection::open_with_flags(
        resolved,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| Error::Unavailable)?;
    db.busy_timeout(Duration::from_secs(15))
        .map_err(|_| Error::Unavailable)?;
    db.execute_batch("PRAGMA trusted_schema=OFF;")
        .map_err(|_| Error::Unavailable)?;
    Ok(db)
}

pub struct History {
    db: Connection,
    transports: Vec<String>,
}
impl History {
    pub fn open(path: &Path, transports: Vec<String>) -> Result<Self> {
        if transports.len() > 44
            || transports.iter().any(|value| !valid_transport(value))
            || transports.iter().collect::<BTreeSet<_>>().len() != transports.len()
        {
            return Err(Error::Invalid);
        }
        let db = open_db(path)?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS traffic_history(ts INTEGER PRIMARY KEY,upload INTEGER NOT NULL,download INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS probe_history(ts INTEGER NOT NULL,transport TEXT NOT NULL,status TEXT NOT NULL,
                https_ms REAL,udp_ms REAL,PRIMARY KEY(ts,transport));")
            .map_err(|_| Error::Unavailable)?;
        Ok(Self { db, transports })
    }

    /// Store one sanitized monitor observation. Re-reading one report never
    /// creates extra healthy/failure samples. A stale or unavailable report
    /// contributes at most one unknown sample per minute and transport.
    pub fn collect(&mut self, report: &Value, now: i64) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Unavailable)?;
        record_history(&tx, &self.transports, report, now)?;
        tx.commit().map_err(|_| Error::Unavailable)
    }

    /// Return the legacy bucket and summary shape, preserving missing buckets
    /// rather than fabricating zeroes for periods without data.
    pub fn query(&mut self, range: &str, now: i64) -> Result<Value> {
        let (duration, bucket) = match range {
            "1h" => (3600, 60),
            "24h" => (86_400, 300),
            "7d" => (7 * 86_400, 1800),
            "30d" => (RETENTION, 7200),
            _ => return Err(Error::Invalid),
        };
        if now < 0 {
            return Err(Error::Invalid);
        }
        let start = (now - duration) / bucket * bucket;
        let tx = self.db.transaction().map_err(|_| Error::Unavailable)?;
        let traffic = {
            let mut statement = tx.prepare("SELECT (ts/?1)*?1,SUM(upload),SUM(download),COUNT(*) FROM traffic_history WHERE ts>=?2 AND ts<=?3 GROUP BY ts/?1 ORDER BY ts/?1").map_err(|_| Error::Unavailable)?;
            let rows = statement.query_map(params![bucket,start,now], |row| Ok(json!({"ts":row.get::<_,i64>(0)?,"upload":row.get::<_,i64>(1)?,"download":row.get::<_,i64>(2)?,"minutes":row.get::<_,i64>(3)?}))).map_err(|_| Error::Unavailable)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| Error::Unavailable)?
        };
        let probes = {
            let mut statement = tx.prepare("SELECT (ts/?1)*?1,transport,SUM(status='healthy'),SUM(status='failed'),SUM(status='unknown'),AVG(https_ms),AVG(udp_ms) FROM probe_history WHERE ts>=?2 AND ts<=?3 GROUP BY ts/?1,transport ORDER BY ts/?1,transport").map_err(|_| Error::Unavailable)?;
            let rows = statement.query_map(params![bucket,start,now], |row| Ok(json!({"ts":row.get::<_,i64>(0)?,"transport":row.get::<_,String>(1)?,"healthy":row.get::<_,i64>(2)?,"failed":row.get::<_,i64>(3)?,"unknown":row.get::<_,i64>(4)?,"https_ms":row.get::<_,Option<f64>>(5)?,"udp_ms":row.get::<_,Option<f64>>(6)?}))).map_err(|_| Error::Unavailable)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| Error::Unavailable)?
        };
        let summary = {
            let mut statement = tx.prepare("SELECT transport,SUM(status='healthy'),SUM(status='failed'),SUM(status='unknown'),AVG(https_ms),AVG(udp_ms) FROM probe_history WHERE ts>=?1 AND ts<=?2 GROUP BY transport").map_err(|_| Error::Unavailable)?;
            let rows = statement.query_map(params![start,now], |row| {
                let healthy=row.get::<_,i64>(1)?; let failed=row.get::<_,i64>(2)?;
                let total=healthy.checked_add(failed).ok_or(rusqlite::Error::IntegralValueOutOfRange(1,healthy))?;
                Ok(json!({"transport":row.get::<_,String>(0)?,"healthy":healthy,"failed":failed,"unknown":row.get::<_,i64>(3)?,"https_ms":row.get::<_,Option<f64>>(4)?,"udp_ms":row.get::<_,Option<f64>>(5)?,"success_percent":if total>0 {Some(100.0 * healthy as f64 / total as f64)} else {None}}))
            }).map_err(|_| Error::Unavailable)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| Error::Unavailable)?
        };
        let first: Option<i64> = tx
            .query_row("SELECT MIN(ts) FROM probe_history", [], |row| row.get(0))
            .map_err(|_| Error::Unavailable)?;
        tx.commit().map_err(|_| Error::Unavailable)?;
        Ok(
            json!({"range":range,"start":start,"end":now,"bucket_seconds":bucket,"retention_days":30,
            "transports":self.transports,"first_probe":first,"traffic":traffic,"probes":probes,"summary":summary}),
        )
    }
}
fn record_history(
    tx: &Transaction<'_>,
    transports: &[String],
    report: &Value,
    now: i64,
) -> Result<()> {
    if now < 0 || !report.is_object() {
        return Err(Error::Invalid);
    }
    let state = report["status"].as_str().unwrap_or("unknown");
    let updated = report["updated"].as_i64().unwrap_or(-1);
    let rows = report["checks"].as_array();
    let fresh = updated >= 0
        && matches!(state, "healthy" | "failed")
        && (-60..=180).contains(&now.saturating_sub(updated));
    for transport in transports {
        let found = rows
            .and_then(|rows| {
                let mut matches = rows
                    .iter()
                    .filter(|row| row["transport"].as_str() == Some(transport));
                let first = matches.next()?;
                if matches.next().is_none() {
                    Some(first)
                } else {
                    None
                }
            })
            .filter(|row| fresh && matches!(row["status"].as_str(), Some("healthy" | "failed")));
        let sampled = if found.is_some() {
            updated
        } else {
            now / 60 * 60
        };
        let status = found
            .and_then(|row| row["status"].as_str())
            .unwrap_or("unknown");
        let metric = |key: &str| {
            found
                .and_then(|row| row[key].as_f64())
                .filter(|n| n.is_finite() && (0.0..=300_000.0).contains(n))
        };
        tx.execute("INSERT OR IGNORE INTO probe_history(ts,transport,status,https_ms,udp_ms) VALUES(?,?,?,?,?)",
            params![sampled,transport,status,metric("https_ms"),metric("udp_ms")]).map_err(|_|Error::Unavailable)?;
    }
    tx.execute(
        "DELETE FROM traffic_history WHERE ts<?",
        [now.saturating_sub(RETENTION)],
    )
    .map_err(|_| Error::Unavailable)?;
    tx.execute(
        "DELETE FROM probe_history WHERE ts<?",
        [now.saturating_sub(RETENTION)],
    )
    .map_err(|_| Error::Unavailable)?;
    Ok(())
}
fn valid_transport(tag: &str) -> bool {
    matches!(tag, "reality" | "websocket" | "hysteria2" | "vmess")
        || tag
            .strip_prefix("residential-")
            .is_some_and(|suffix| suffix.len() == 2 && suffix.bytes().all(|c| c.is_ascii_digit()))
}
