//! Stable, compact client-facing names for fixed residential exits.
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

type Registry = BTreeMap<String, BTreeMap<String, u16>>;
const KEY: &str = "residential_client_names_v1";

pub fn country_label(country: &str) -> &str {
    match country {
        "US" => "美国",
        "JP" => "日本",
        "SG" => "新加坡",
        "ZZ" => "全球",
        "HK" => "香港",
        "TW" => "台湾",
        "KR" => "韩国",
        "TH" => "泰国",
        "MY" => "马来西亚",
        "IN" => "印度",
        "CA" => "加拿大",
        "GB" => "英国",
        "DE" => "德国",
        "FR" => "法国",
        "NL" => "荷兰",
        "AU" => "澳大利亚",
        _ => country,
    }
}

fn exits(settings: &Value) -> Result<&[Value], ()> {
    settings.get("residential_exits").map_or(Ok(&[]), |value| {
        value.as_array().map(Vec::as_slice).ok_or(())
    })
}
fn fields(exit: &Value) -> Result<(&str, &str), ()> {
    let tag = exit.get("tag").and_then(Value::as_str).ok_or(())?;
    let country = exit.get("country").and_then(Value::as_str).ok_or(())?;
    if !tag
        .strip_prefix("residential-")
        .is_some_and(|n| n.len() == 2 && n.bytes().all(|b| b.is_ascii_digit()))
        || country.len() != 2
        || !country.bytes().all(|b| b.is_ascii_uppercase())
    {
        return Err(());
    }
    Ok((tag, country))
}
fn fixed(exit: &Value) -> Result<bool, ()> {
    exit.get("dynamic")
        .map_or(Ok(true), |v| v.as_bool().map(|v| !v).ok_or(()))
}
fn allocate(settings: &Value, registry: &mut Registry) -> Result<(), ()> {
    for (country, tags) in registry.iter() {
        if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(());
        }
        let mut used = BTreeSet::new();
        for (tag, number) in tags {
            if !tag
                .strip_prefix("residential-")
                .is_some_and(|n| n.len() == 2 && n.bytes().all(|b| b.is_ascii_digit()))
                || *number == 0
                || !used.insert(*number)
            {
                return Err(());
            }
        }
    }
    let mut pending = Vec::new();
    let mut seen = BTreeSet::new();
    for exit in exits(settings)? {
        let (tag, country) = fields(exit)?;
        if !seen.insert(tag.to_owned()) {
            return Err(());
        }
        if fixed(exit)? {
            pending.push((country.to_owned(), tag.to_owned()));
        }
    }
    pending.sort();
    for (country, tag) in pending {
        let entries = registry.entry(country).or_default();
        if entries.contains_key(&tag) {
            continue;
        }
        let used: BTreeSet<u16> = entries.values().copied().collect();
        let number = (1..=u16::MAX).find(|n| !used.contains(n)).ok_or(())?;
        entries.insert(tag, number);
    }
    Ok(())
}

/// Return the same fixed exit names to every subscription renderer. For
/// standalone rendering without a panel database, allocate in stable tag order.
pub fn names(settings: &Value) -> Result<BTreeMap<String, String>, ()> {
    let mut registry = settings
        .get("residential_name_registry")
        .map_or(Ok(Registry::new()), |v| {
            serde_json::from_value(v.clone()).map_err(|_| ())
        })?;
    allocate(settings, &mut registry)?;
    let mut result = BTreeMap::new();
    for exit in exits(settings)? {
        if !fixed(exit)? {
            continue;
        }
        let (tag, country) = fields(exit)?;
        let number = registry.get(country).and_then(|v| v.get(tag)).ok_or(())?;
        result.insert(
            tag.to_owned(),
            format!("{}{:02}", country_label(country), number),
        );
    }
    Ok(result)
}

/// Reserve country-local numbers in the panel database. The registry keeps
/// disabled/deleted tags, so another exit never inherits their displayed name.
/// Only the in-memory subscription settings receive the registry.
pub fn attach_registry(path: &Path, settings: &mut Value) -> Result<(), ()> {
    exits(settings)?;
    if std::fs::symlink_metadata(path)
        .map_err(|_| ())?
        .file_type()
        .is_symlink()
    {
        return Err(());
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let path = std::fs::canonicalize(parent)
        .map_err(|_| ())?
        .join(path.file_name().ok_or(())?);
    let mut db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| ())?;
    db.busy_timeout(Duration::from_secs(15)).map_err(|_| ())?;
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ())?;
    let raw: Option<String> = tx
        .query_row("SELECT value FROM metadata WHERE key=?", [KEY], |row| {
            row.get(0)
        })
        .optional()
        .map_err(|_| ())?;
    if raw.as_ref().is_some_and(|value| value.len() > 65536) {
        return Err(());
    }
    let mut registry: Registry = raw.as_deref().map_or(Ok(Registry::new()), |v| {
        serde_json::from_str(v).map_err(|_| ())
    })?;
    let before = registry.clone();
    allocate(settings, &mut registry)?;
    if before != registry {
        tx.execute(
            "INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)",
            (KEY, serde_json::to_string(&registry).map_err(|_| ())?),
        )
        .map_err(|_| ())?;
    }
    tx.commit().map_err(|_| ())?;
    settings
        .as_object_mut()
        .ok_or(())?
        .insert("residential_name_registry".into(), json!(registry));
    Ok(())
}

/// Look up an active or previously reserved name for the management list.
pub fn reserved_name(settings: &Value, tag: &str, country: &str) -> Option<String> {
    let number = settings
        .get("residential_name_registry")?
        .get(country)?
        .get(tag)?
        .as_u64()?;
    Some(format!("{}{:02}", country_label(country), number))
}
