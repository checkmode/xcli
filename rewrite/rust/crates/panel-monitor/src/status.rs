//! Safe, read-only view of the monitor report for the management API.
use crate::{tag, Invalid, Sensitive};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use zeroize::Zeroizing;

pub fn unavailable() -> Value {
    json!({"scope":"server","status":"unknown","message":"尚未收到服务器自检结果","updated":0,"checks":[]})
}
pub fn expected(settings: &Value) -> Result<Vec<String>, Invalid> {
    if !settings.is_object() {
        return Err(Invalid);
    }
    let mut result = vec!["reality".to_owned(), "websocket".to_owned()];
    if settings
        .get("hysteria2_port")
        .and_then(Value::as_u64)
        .is_some_and(|value| value > 0)
    {
        result.push("hysteria2".into());
    }
    if settings
        .get("hysteria2_brutal_port")
        .and_then(Value::as_u64)
        .is_some_and(|value| value > 0)
    {
        result.push("hysteria2-brutal".into());
    }
    if settings
        .get("vmess_ws_path")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
    {
        result.push("vmess".into());
    }
    if let Some(exits) = settings.get("residential_exits") {
        let exits = exits
            .as_array()
            .filter(|values| values.len() <= 40)
            .ok_or(Invalid)?;
        let mut seen = BTreeSet::new();
        for entry in exits {
            if entry.get("dynamic").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let name = entry
                .get("tag")
                .and_then(Value::as_str)
                .filter(|value| tag(value))
                .ok_or(Invalid)?;
            if !seen.insert(name.to_owned()) {
                return Err(Invalid);
            }
            result.push(name.to_owned());
        }
    }
    Ok(result)
}
fn sanitized_error(value: &Value) -> &str {
    let text = value.as_str().unwrap_or("");
    const ALLOWED: &[&str] = &[
        "",
        "Probe client unavailable",
        "HTTPS connection failed",
        "Unexpected egress IP",
        "HTTPS probe unavailable",
        "UDP DNS probe failed",
        "DoH probe failed",
        "HTTPS connection failed; UDP DNS probe failed",
        "HTTPS connection failed; DoH probe failed",
        "Unexpected egress IP; UDP DNS probe failed",
        "Unexpected egress IP; DoH probe failed",
        "HTTPS probe unavailable; UDP DNS probe failed",
        "HTTPS probe unavailable; DoH probe failed",
    ];
    if ALLOWED.contains(&text) {
        text
    } else {
        "探测异常"
    }
}
fn metric(value: &Value) -> Value {
    value
        .as_u64()
        .filter(|value| *value <= 120_000)
        .map_or(Value::Null, |value| json!(value))
}
/// Parse and filter an untrusted report, retaining legacy stale semantics.
pub fn view(bytes: &[u8], expected: &[String], now: i64) -> Value {
    if bytes.len() > 64 * 1024 || now < 0 {
        return unavailable();
    }
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return unavailable();
    };
    let value = Sensitive(value);
    let raw = value.as_value();
    let Some(updated) = raw
        .get("updated")
        .and_then(Value::as_i64)
        .filter(|value| *value >= 0)
    else {
        return unavailable();
    };
    if raw["schema"] != 1 {
        return unavailable();
    }
    let scope = match raw["scope"].as_str() {
        Some("server") => "server",
        Some("external") => "external",
        _ => return unavailable(),
    };
    let status = match raw["status"].as_str() {
        Some("healthy") => "healthy",
        Some("failed") => "failed",
        _ => return unavailable(),
    };
    let Some(rows) = raw["checks"].as_array().filter(|rows| rows.len() <= 45) else {
        return unavailable();
    };
    let allowed: BTreeSet<_> = expected.iter().map(String::as_str).collect();
    if allowed.is_empty() || allowed.len() != expected.len() || allowed.len() > 45 {
        return unavailable();
    }
    let mut seen = BTreeSet::new();
    let mut checks = Vec::new();
    for row in rows {
        let Some(kind) = row["transport"]
            .as_str()
            .filter(|value| allowed.contains(*value))
        else {
            continue;
        };
        if !seen.insert(kind.to_owned()) {
            return unavailable();
        }
        let mut state = match row["status"].as_str() {
            Some("healthy") => "healthy",
            Some("failed") => "failed",
            _ => "unknown",
        };
        let last = row["last_success"]
            .as_i64()
            .filter(|stamp| *stamp >= 0 && *stamp <= now.saturating_add(60))
            .unwrap_or(0);
        let https = metric(&row["https_ms"]);
        let udp = metric(&row["udp_ms"]);
        let doh = metric(&row["doh_ms"]);
        let residential = tag(kind);
        let error = sanitized_error(&row["error"]);
        if state == "healthy"
            && (!error.is_empty()
                || https.is_null()
                || if residential {
                    doh.is_null()
                } else {
                    udp.is_null()
                })
        {
            state = "unknown";
        }
        checks.push(
            json!({"transport":kind,"status":state,"https_ms":https,"udp_ms":udp,
            "doh_ms":doh,"udp_supported":!residential,"last_success":last,"error":error}),
        );
    }
    let age = now.saturating_sub(updated);
    let stale = !(-60..=180).contains(&age);
    let mut output = json!({"scope":scope,"updated":updated,"status":status,"checks":checks});
    if stale {
        output["status"] = json!("stale");
        output["message"] = json!("自检结果已过期，请检查探测服务");
    } else if expected.iter().any(|kind| !seen.contains(kind))
        || status == "healthy"
            && output["checks"]
                .as_array()
                .is_some_and(|checks| checks.iter().any(|check| check["status"] != "healthy"))
    {
        output["status"] = json!("unknown");
        output["message"] = json!("等待全部入口的自检结果");
    }
    output
}
/// Pin the trusted directory while opening the fixed report filename. Report
/// contents are still treated as untrusted and filtered by `view`.
pub fn read(path: &Path, expected: &[String], now: i64) -> Value {
    if !path.is_absolute() || path.file_name().and_then(|name| name.to_str()) != Some("report.json")
    {
        return unavailable();
    }
    let Some(parent) = path.parent() else {
        return unavailable();
    };
    let Ok(dir) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
    else {
        return unavailable();
    };
    let Ok(owner) = dir.metadata() else {
        return unavailable();
    };
    if !owner.is_dir() || owner.mode() & 0o022 != 0 {
        return unavailable();
    }
    let name = std::ffi::CString::new("report.json").unwrap();
    // SAFETY: dir is open, and name is a fixed NUL-terminated filename.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return unavailable();
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let Ok(meta) = file.metadata() else {
        return unavailable();
    };
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != owner.uid()
        || meta.gid() != owner.gid()
        || meta.mode() & 0o027 != 0
        || meta.len() > 64 * 1024
    {
        return unavailable();
    }
    let mut bytes = Zeroizing::new(Vec::new());
    if file.take(64 * 1024 + 1).read_to_end(&mut bytes).is_err() {
        return unavailable();
    }
    view(&bytes, expected, now)
}
