//! Experimental legacy-compatible local Xray counter accounting.
//!
//! The caller must sample a verified core generation before and after reading
//! counters and serialize this transaction with user, quota and core changes.
//! This library does not control Xray, remote nodes or production scheduling.
use regex::Regex;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::sync::OnceLock;

#[derive(Debug)]
pub struct Counter {
    pub name: String,
    pub value: i64,
}
#[derive(Debug, PartialEq, Eq)]
pub enum AccountingError {
    InvalidInput,
    Unavailable,
}
type Result<T> = std::result::Result<T, AccountingError>;

fn add(a: i64, b: i64) -> Result<i64> {
    if a < 0 || b < 0 {
        return Err(AccountingError::Unavailable);
    }
    a.checked_add(b).ok_or(AccountingError::Unavailable)
}
fn format() -> &'static Regex {
    static FORMAT: OnceLock<Regex> = OnceLock::new();
    FORMAT.get_or_init(|| Regex::new(r"^user>>>([0-9a-f]{32})\.([0-9a-f]{8})@(reality|websocket|hysteria2|vmess|residential-[0-9]{2}(?:-hy2)?)>>>traffic>>>(uplink|downlink)$").expect("fixed regex"))
}

/// Atomically update legacy counters, usage, activity and history tables.
pub fn apply(
    db: &mut Connection,
    generation: &str,
    counters: &[Counter],
    now: i64,
    poll_seconds: i64,
) -> Result<(i64, i64)> {
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| AccountingError::Unavailable)?;
    let result = apply_in_transaction(&tx, generation, counters, now, poll_seconds)?;
    tx.commit().map_err(|_| AccountingError::Unavailable)?;
    Ok(result)
}

/// Account within a caller-owned transaction so user decisions use the same
/// snapshot. The caller must roll back the entire transaction on any error.
pub fn apply_in_transaction(
    tx: &Transaction<'_>,
    generation: &str,
    counters: &[Counter],
    now: i64,
    poll_seconds: i64,
) -> Result<(i64, i64)> {
    if generation.is_empty() || now < 0 || !(1..=60).contains(&poll_seconds) {
        return Err(AccountingError::InvalidInput);
    }
    let previous_sample: Option<String> = tx
        .query_row(
            "SELECT value FROM metadata WHERE key='activity_sample'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| AccountingError::Unavailable)?;
    let interval = match &previous_sample {
        Some(value) => now
            .saturating_sub(
                value
                    .parse::<i64>()
                    .map_err(|_| AccountingError::Unavailable)?,
            )
            .clamp(1, 300),
        None => poll_seconds,
    };
    tx.execute(
        "UPDATE device_activity SET upload_delta=0,download_delta=0,sampled=?,interval_seconds=?",
        params![now, interval],
    )
    .map_err(|_| AccountingError::Unavailable)?;
    let (mut up, mut down) = (0, 0);
    for counter in counters {
        let Some(found) = format().captures(&counter.name) else {
            continue;
        };
        if counter.value < 0 {
            continue;
        }
        let user_id = &found[1];
        let tag = &found[3];
        let uplink = &found[4] == "uplink";
        let previous: Option<(i64, String)> = tx
            .query_row(
                "SELECT value,generation FROM counters WHERE name=?",
                [&counter.name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| AccountingError::Unavailable)?;
        let delta = match &previous {
            Some((value, old_generation))
                if old_generation == generation && *value <= counter.value =>
            {
                counter
                    .value
                    .checked_sub(*value)
                    .ok_or(AccountingError::Unavailable)?
            }
            _ => counter.value,
        };
        tx.execute(
            "INSERT OR REPLACE INTO counters VALUES(?,?,?)",
            params![counter.name, counter.value, generation],
        )
        .map_err(|_| AccountingError::Unavailable)?;
        let select = if uplink {
            "SELECT upload FROM users WHERE id=?"
        } else {
            "SELECT download FROM users WHERE id=?"
        };
        let existing: Option<i64> = tx
            .query_row(select, [user_id], |row| row.get(0))
            .optional()
            .map_err(|_| AccountingError::Unavailable)?;
        if let Some(existing) = existing {
            let update = if uplink {
                "UPDATE users SET upload=? WHERE id=?"
            } else {
                "UPDATE users SET download=? WHERE id=?"
            };
            tx.execute(update, params![add(existing, delta)?, user_id])
                .map_err(|_| AccountingError::Unavailable)?;
            let activity_delta = if previous_sample.is_some() && previous.is_some() {
                delta
            } else {
                0
            };
            let transport = if tag.ends_with("-hy2") {
                "hysteria2"
            } else if tag.starts_with("residential-") {
                "websocket"
            } else {
                tag
            };
            tx.execute("INSERT OR IGNORE INTO device_activity(user_id,transport,sampled,interval_seconds) VALUES(?,?,?,?)",
                params![user_id,transport,now,interval]).map_err(|_| AccountingError::Unavailable)?;
            let activity = if uplink {
                "UPDATE device_activity SET upload_delta=upload_delta+?,last_seen=CASE WHEN ?>0 THEN ? ELSE last_seen END WHERE user_id=? AND transport=?"
            } else {
                "UPDATE device_activity SET download_delta=download_delta+?,last_seen=CASE WHEN ?>0 THEN ? ELSE last_seen END WHERE user_id=? AND transport=?"
            };
            tx.execute(
                activity,
                params![activity_delta, activity_delta, now, user_id, transport],
            )
            .map_err(|_| AccountingError::Unavailable)?;
        }
        if uplink {
            up = add(up, delta)?;
        } else {
            down = add(down, delta)?;
        }
    }
    tx.execute(
        "INSERT OR REPLACE INTO metadata VALUES('activity_sample',?)",
        [now.to_string()],
    )
    .map_err(|_| AccountingError::Unavailable)?;
    let bucket = now / 60 * 60;
    let previous_history: Option<(i64, i64)> = tx
        .query_row(
            "SELECT upload,download FROM traffic_history WHERE ts=?",
            [bucket],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| AccountingError::Unavailable)?;
    let (history_up, history_down) = match previous_history {
        Some((old_up, old_down)) => (add(old_up, up)?, add(old_down, down)?),
        None => (up, down),
    };
    tx.execute(
        "INSERT OR REPLACE INTO traffic_history VALUES(?,?,?)",
        params![bucket, history_up, history_down],
    )
    .map_err(|_| AccountingError::Unavailable)?;
    tx.execute("INSERT INTO samples VALUES(?,?,?)", params![now, up, down])
        .map_err(|_| AccountingError::Unavailable)?;
    tx.execute(
        "DELETE FROM samples WHERE ts<?",
        [now.saturating_sub(7 * 86400)],
    )
    .map_err(|_| AccountingError::Unavailable)?;
    Ok((up, down))
}
