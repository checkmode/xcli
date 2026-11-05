//! Persistent accounting compatible with the existing XCLI node ledger.
//!
//! Only one node agent may own a ledger and control its Xray instance at a
//! time. Callers must serialize sampling and acknowledgement with that agent's
//! authorization and core lifecycle. This library does not implement the agent.

use regex::Regex;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

#[derive(Debug)]
pub enum LedgerError {
    Invalid(&'static str),
    Database(rusqlite::Error),
    Io(std::io::Error),
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => f.write_str(reason),
            Self::Database(_) => f.write_str("Accounting database error"),
            Self::Io(_) => f.write_str("Accounting file error"),
        }
    }
}
impl std::error::Error for LedgerError {}
impl From<rusqlite::Error> for LedgerError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value)
    }
}
impl From<std::io::Error> for LedgerError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

type Result<T> = std::result::Result<T, LedgerError>;

fn counter_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(
        r"\Auser>>>([0-9a-f]{32})\.[0-9a-f]{8}@(reality|websocket|hysteria2)>>>traffic>>>(uplink|downlink)\z"
    ).expect("static counter pattern"))
}

fn valid_user(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn counter_value(value: Option<&Value>) -> Result<i64> {
    match value {
        None => Ok(0),
        Some(Value::Number(number)) => number
            .as_i64()
            .filter(|n| *n >= 0)
            .ok_or(LedgerError::Invalid("Invalid counter value")),
        Some(Value::String(value)) => {
            let bytes = value.as_bytes();
            let canonical = !bytes.is_empty()
                && bytes.len() <= 19
                && bytes.iter().all(u8::is_ascii_digit)
                && (bytes.len() == 1 || bytes[0] != b'0');
            if !canonical {
                return Err(LedgerError::Invalid("Invalid counter value"));
            }
            value
                .parse::<i64>()
                .ok()
                .filter(|n| *n >= 0)
                .ok_or(LedgerError::Invalid("Invalid counter value"))
        }
        _ => Err(LedgerError::Invalid("Invalid counter value")),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub id: String,
    pub upload: i64,
    pub download: i64,
}

pub struct Ledger {
    db: Connection,
}

impl Ledger {
    /// Opens a legacy ledger in place. The caller must own the containing
    /// directory and ensure no other agent has the file open for writing.
    pub fn open(path: &Path) -> Result<Self> {
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(LedgerError::Invalid(
                    "Accounting database must not be a symlink",
                ))
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let name = path
            .file_name()
            .ok_or(LedgerError::Invalid("Invalid accounting database path"))?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let resolved = std::fs::canonicalize(parent)?.join(name);
        let db = Connection::open_with_flags(
            resolved,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        db.busy_timeout(Duration::from_secs(15))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS node_totals (
               user_id TEXT PRIMARY KEY, upload INTEGER NOT NULL DEFAULT 0,
               download INTEGER NOT NULL DEFAULT 0, ack_upload INTEGER NOT NULL DEFAULT 0,
               ack_download INTEGER NOT NULL DEFAULT 0, last_ack INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE IF NOT EXISTS node_counters (
               name TEXT PRIMARY KEY, generation TEXT NOT NULL, value INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS node_meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
             INSERT OR IGNORE INTO node_meta VALUES ('ack_sequence', 0);",
        )?;
        Ok(Self { db })
    }

    /// Atomically samples Xray's cumulative counters for one process generation.
    pub fn record(&mut self, generation: &str, counters: &Value) -> Result<()> {
        if generation.is_empty() || generation.chars().count() > 128 {
            return Err(LedgerError::Invalid("Invalid core generation"));
        }
        let entries = counters
            .as_array()
            .filter(|v| v.len() <= 10_000)
            .ok_or(LedgerError::Invalid("Invalid core counters"))?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut seen = HashSet::new();
        for entry in entries {
            let entry = entry
                .as_object()
                .filter(|v| {
                    (v.len() == 1 || v.len() == 2)
                        && v.contains_key("name")
                        && (v.len() == 1 || v.contains_key("value"))
                })
                .ok_or(LedgerError::Invalid("Invalid counter"))?;
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .filter(|v| v.chars().count() <= 200)
                .ok_or(LedgerError::Invalid("Invalid counter name"))?;
            let Some(caps) = counter_pattern().captures(name) else {
                continue;
            };
            if !seen.insert(name) {
                return Err(LedgerError::Invalid("Duplicate counter"));
            }
            let value = counter_value(entry.get("value"))?;
            let previous: Option<(String, i64)> = tx
                .query_row(
                    "SELECT generation,value FROM node_counters WHERE name=?",
                    [name],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let delta = match previous {
                Some((old_generation, old)) if old_generation == generation => value
                    .checked_sub(old)
                    .filter(|n| *n >= 0)
                    .ok_or(LedgerError::Invalid(
                        "Core counter decreased within one generation",
                    ))?,
                _ => value,
            };
            let uid = &caps[1];
            tx.execute(
                "INSERT OR IGNORE INTO node_totals(user_id) VALUES (?)",
                [uid],
            )?;
            let (select, update) = if &caps[3] == "uplink" {
                (
                    "SELECT upload FROM node_totals WHERE user_id=?",
                    "UPDATE node_totals SET upload=? WHERE user_id=?",
                )
            } else {
                (
                    "SELECT download FROM node_totals WHERE user_id=?",
                    "UPDATE node_totals SET download=? WHERE user_id=?",
                )
            };
            let old: i64 = tx.query_row(select, [uid], |row| row.get(0))?;
            let total = old
                .checked_add(delta)
                .ok_or(LedgerError::Invalid("Traffic total overflow"))?;
            tx.execute(update, params![total, uid])?;
            tx.execute("INSERT INTO node_counters VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET generation=excluded.generation,value=excluded.value",
                params![name, generation, value])?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn pending(&self, limit: usize) -> Result<Vec<Report>> {
        if !(1..=500).contains(&limit) {
            return Err(LedgerError::Invalid("Invalid report limit"));
        }
        let mut statement = self.db.prepare(
            "SELECT user_id,upload,download FROM node_totals WHERE upload!=ack_upload OR download!=ack_download ORDER BY last_ack,user_id LIMIT ?"
        )?;
        let rows = statement.query_map([limit as i64], |row| {
            Ok(Report {
                id: row.get(0)?,
                upload: row.get(1)?,
                download: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Atomically acknowledges cumulative totals, rejecting rollback and over-acknowledgement.
    pub fn acknowledge(&mut self, entries: &Value) -> Result<()> {
        let entries = entries
            .as_array()
            .filter(|v| v.len() <= 500)
            .ok_or(LedgerError::Invalid("Invalid accounting acknowledgement"))?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut sequence: i64 = tx.query_row(
            "SELECT value FROM node_meta WHERE key='ack_sequence'",
            [],
            |row| row.get(0),
        )?;
        for entry in entries {
            let entry = entry
                .as_object()
                .filter(|v| {
                    v.len() == 3
                        && v.contains_key("id")
                        && v.contains_key("upload")
                        && v.contains_key("download")
                })
                .ok_or(LedgerError::Invalid("Invalid accounting acknowledgement"))?;
            let uid = entry
                .get("id")
                .and_then(Value::as_str)
                .filter(|v| valid_user(v))
                .ok_or(LedgerError::Invalid("Invalid accounting acknowledgement"))?;
            let parse = |key: &str| {
                entry
                    .get(key)
                    .and_then(Value::as_i64)
                    .ok_or(LedgerError::Invalid("Invalid accounting acknowledgement"))
            };
            let up = parse("upload")?;
            let down = parse("download")?;
            let row: Option<(i64,i64,i64,i64)> = tx.query_row(
                "SELECT upload,download,ack_upload,ack_download FROM node_totals WHERE user_id=?", [uid],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
            ).optional()?;
            let (total_up, total_down, ack_up, ack_down) = row.ok_or(LedgerError::Invalid(
                "Acknowledgement does not match local accounting",
            ))?;
            if up < 0
                || down < 0
                || up > total_up
                || down > total_down
                || up < ack_up
                || down < ack_down
            {
                return Err(LedgerError::Invalid(
                    "Acknowledgement does not match local accounting",
                ));
            }
            sequence = sequence
                .checked_add(1)
                .ok_or(LedgerError::Invalid("Acknowledgement sequence overflow"))?;
            tx.execute(
                "UPDATE node_totals SET ack_upload=?,ack_download=?,last_ack=? WHERE user_id=?",
                params![up, down, sequence, uid],
            )?;
        }
        tx.execute(
            "UPDATE node_meta SET value=? WHERE key='ack_sequence'",
            [sequence],
        )?;
        tx.commit()?;
        Ok(())
    }
}
