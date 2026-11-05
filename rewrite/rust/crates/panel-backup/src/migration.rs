//! Experimental comparison of two detached SQLite snapshots before migration.
//!
//! This is deliberately strict: schema and all non-traffic rows must match,
//! and user upload/download counters may only increase. Callers must first
//! create independent, consistent SQLite backup copies, ensure those copies
//! cannot be modified during this check, and keep the originals protected.
//! This does not compare external files, prove final Xray accounting, perform
//! an upgrade, or authorize switching a production service.
use rusqlite::config::DbConfig;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, Transaction, TransactionBehavior};

const MAX_TABLES: usize = 128;
const MAX_COLUMNS: usize = 128;
const MAX_ROWS_PER_TABLE: i64 = 1_000_000;

#[derive(Debug, PartialEq, Eq)]
pub enum CompareError {
    Unavailable,
    UnsupportedSchema,
    SchemaChanged,
    DataChanged,
    UsageDecreased,
}

type Result<T> = std::result::Result<T, CompareError>;

#[derive(Debug, PartialEq, Eq)]
pub struct Comparison {
    pub tables: usize,
    pub users: u64,
}

fn quote_identifier(name: &str) -> Result<String> {
    if name.is_empty() || name.len() > 255 || name.contains('\0') {
        return Err(CompareError::UnsupportedSchema);
    }
    Ok(format!("\"{}\"", name.replace('"', "\"\"")))
}

fn prepare(db: &Connection) -> Result<()> {
    db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(|_| CompareError::Unavailable)?;
    db.pragma_update(None, "trusted_schema", "OFF")
        .map_err(|_| CompareError::Unavailable)?;
    // Rows may contain passwords or tokens. Never let SQLite spill the sort
    // or temporary indexes into a plaintext file.
    db.pragma_update(None, "temp_store", "MEMORY")
        .map_err(|_| CompareError::Unavailable)?;
    db.pragma_update(None, "query_only", "ON")
        .map_err(|_| CompareError::Unavailable)?;
    Ok(())
}

fn check_database(tx: &Transaction<'_>) -> Result<()> {
    let ok: String = tx
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|_| CompareError::Unavailable)?;
    if ok != "ok" {
        return Err(CompareError::Unavailable);
    }
    Ok(())
}

fn equal_value(a: ValueRef<'_>, b: ValueRef<'_>) -> bool {
    match (a, b) {
        (ValueRef::Null, ValueRef::Null) => true,
        (ValueRef::Integer(x), ValueRef::Integer(y)) => x == y,
        (ValueRef::Real(x), ValueRef::Real(y)) => x.to_bits() == y.to_bits(),
        (ValueRef::Text(x), ValueRef::Text(y)) | (ValueRef::Blob(x), ValueRef::Blob(y)) => x == y,
        _ => false,
    }
}

fn compare_query(left: &Transaction<'_>, right: &Transaction<'_>, sql: &str) -> Result<()> {
    let mut a = left.prepare(sql).map_err(|_| CompareError::Unavailable)?;
    let mut b = right.prepare(sql).map_err(|_| CompareError::Unavailable)?;
    let count = a.column_count();
    if count != b.column_count() {
        return Err(CompareError::DataChanged);
    }
    let mut rows_a = a.query([]).map_err(|_| CompareError::Unavailable)?;
    let mut rows_b = b.query([]).map_err(|_| CompareError::Unavailable)?;
    loop {
        let row_a = rows_a.next().map_err(|_| CompareError::Unavailable)?;
        let row_b = rows_b.next().map_err(|_| CompareError::Unavailable)?;
        match (row_a, row_b) {
            (None, None) => return Ok(()),
            (Some(x), Some(y)) => {
                for index in 0..count {
                    if !equal_value(
                        x.get_ref(index).map_err(|_| CompareError::Unavailable)?,
                        y.get_ref(index).map_err(|_| CompareError::Unavailable)?,
                    ) {
                        return Err(CompareError::DataChanged);
                    }
                }
            }
            _ => return Err(CompareError::DataChanged),
        }
    }
}

fn tables(tx: &Transaction<'_>) -> Result<Vec<String>> {
    let mut statement = tx
        .prepare("SELECT name, type FROM pragma_table_list WHERE schema='main' ORDER BY name COLLATE BINARY")
        .map_err(|_| CompareError::Unavailable)?;
    let mut rows = statement.query([]).map_err(|_| CompareError::Unavailable)?;
    let mut tables = Vec::new();
    while let Some(row) = rows.next().map_err(|_| CompareError::Unavailable)? {
        let name: String = row.get(0).map_err(|_| CompareError::Unavailable)?;
        let kind: String = row.get(1).map_err(|_| CompareError::Unavailable)?;
        if name.starts_with("sqlite_") && name != "sqlite_sequence" {
            continue;
        }
        if kind == "view" {
            continue;
        }
        if kind != "table" || tables.len() >= MAX_TABLES {
            return Err(CompareError::UnsupportedSchema);
        }
        quote_identifier(&name)?;
        tables.push(name);
    }
    if !tables.iter().any(|v| v == "users") {
        return Err(CompareError::UnsupportedSchema);
    }
    Ok(tables)
}

fn columns(tx: &Transaction<'_>, table: &str) -> Result<Vec<String>> {
    let mut statement = tx
        .prepare("SELECT name, hidden FROM pragma_table_xinfo(?1) ORDER BY cid")
        .map_err(|_| CompareError::Unavailable)?;
    let mut rows = statement
        .query([table])
        .map_err(|_| CompareError::Unavailable)?;
    let mut columns = Vec::new();
    while let Some(row) = rows.next().map_err(|_| CompareError::Unavailable)? {
        let name: String = row.get(0).map_err(|_| CompareError::Unavailable)?;
        let hidden: i64 = row.get(1).map_err(|_| CompareError::Unavailable)?;
        if hidden != 0 || columns.len() >= MAX_COLUMNS {
            return Err(CompareError::UnsupportedSchema);
        }
        quote_identifier(&name)?;
        columns.push(name);
    }
    if columns.is_empty() {
        return Err(CompareError::UnsupportedSchema);
    }
    Ok(columns)
}

fn count(tx: &Transaction<'_>, table: &str) -> Result<i64> {
    let sql = format!("SELECT count(*) FROM {}", quote_identifier(table)?);
    let count: i64 = tx
        .query_row(&sql, [], |row| row.get(0))
        .map_err(|_| CompareError::Unavailable)?;
    if !(0..=MAX_ROWS_PER_TABLE).contains(&count) {
        return Err(CompareError::UnsupportedSchema);
    }
    Ok(count)
}

fn compare_usage(left: &Transaction<'_>, right: &Transaction<'_>) -> Result<u64> {
    let sql = "SELECT id, upload, download FROM users ORDER BY id COLLATE BINARY";
    let mut a = left
        .prepare(sql)
        .map_err(|_| CompareError::UnsupportedSchema)?;
    let mut b = right
        .prepare(sql)
        .map_err(|_| CompareError::UnsupportedSchema)?;
    let mut rows_a = a.query([]).map_err(|_| CompareError::Unavailable)?;
    let mut rows_b = b.query([]).map_err(|_| CompareError::Unavailable)?;
    let mut users = 0;
    loop {
        let row_a = rows_a.next().map_err(|_| CompareError::Unavailable)?;
        let row_b = rows_b.next().map_err(|_| CompareError::Unavailable)?;
        match (row_a, row_b) {
            (None, None) => return Ok(users),
            (Some(x), Some(y)) => {
                if !equal_value(
                    x.get_ref(0).map_err(|_| CompareError::Unavailable)?,
                    y.get_ref(0).map_err(|_| CompareError::Unavailable)?,
                ) {
                    return Err(CompareError::DataChanged);
                }
                for index in 1..=2 {
                    let old = x
                        .get::<_, i64>(index)
                        .map_err(|_| CompareError::UnsupportedSchema)?;
                    let new = y
                        .get::<_, i64>(index)
                        .map_err(|_| CompareError::UnsupportedSchema)?;
                    if old < 0 || new < old {
                        return Err(CompareError::UsageDecreased);
                    }
                }
                users += 1;
            }
            _ => return Err(CompareError::DataChanged),
        }
    }
}

/// Compare dedicated connections to already-created, immutable SQLite backup
/// copies. Both connections are left query-only. No row contents or secrets are
/// returned. Strict schema equality intentionally blocks unknown migrations.
pub fn compare_snapshots(before: &mut Connection, after: &mut Connection) -> Result<Comparison> {
    prepare(before)?;
    prepare(after)?;
    let left = before
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|_| CompareError::Unavailable)?;
    let right = after
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|_| CompareError::Unavailable)?;
    check_database(&left)?;
    check_database(&right)?;
    let schema = "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type COLLATE BINARY,name COLLATE BINARY";
    compare_query(&left, &right, schema).map_err(|error| match error {
        CompareError::DataChanged => CompareError::SchemaChanged,
        other => other,
    })?;
    let table_names = tables(&left)?;
    if table_names != tables(&right)? {
        return Err(CompareError::SchemaChanged);
    }
    for table in &table_names {
        let cols = columns(&left, table)?;
        if cols != columns(&right, table)? {
            return Err(CompareError::SchemaChanged);
        }
        if count(&left, table)? != count(&right, table)? {
            return Err(CompareError::DataChanged);
        }
        let included: Vec<&str> = cols
            .iter()
            .map(String::as_str)
            .filter(|name| table != "users" || (*name != "upload" && *name != "download"))
            .collect();
        if included.is_empty()
            || (table == "users"
                && (!cols.iter().any(|c| c == "id")
                    || !cols.iter().any(|c| c == "upload")
                    || !cols.iter().any(|c| c == "download")))
        {
            return Err(CompareError::UnsupportedSchema);
        }
        let selected: Vec<String> = included
            .iter()
            .map(|c| quote_identifier(c))
            .collect::<Result<_>>()?;
        let order: Vec<String> = selected
            .iter()
            .flat_map(|c| {
                [
                    format!("typeof({c}) COLLATE BINARY"),
                    format!("CAST({c} AS BLOB)"),
                ]
            })
            .collect();
        let sql = format!(
            "SELECT {} FROM {} ORDER BY {}",
            selected.join(","),
            quote_identifier(table)?,
            order.join(",")
        );
        compare_query(&left, &right, &sql)?;
    }
    let users = compare_usage(&left, &right)?;
    Ok(Comparison {
        tables: table_names.len(),
        users,
    })
}
