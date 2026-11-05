//! Experimental read-only Linux host sampling. Missing or invalid metrics are
//! returned as null; this does not infer process ownership or public reachability.
pub mod disk_probe;

use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

fn text(path: &Path, limit: usize) -> Option<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut bytes).ok()?;
    if bytes.len() > limit {
        return None;
    }
    String::from_utf8(bytes).ok()
}
fn finite(value: &str) -> Option<f64> {
    let number: f64 = value.parse().ok()?;
    (number.is_finite() && number >= 0.0).then_some(number)
}
fn memory(input: &str, total: &str, available: &str) -> Option<Value> {
    let mut total_bytes = None;
    let mut available_bytes = None;
    for line in input.lines() {
        let mut fields = line.split_whitespace();
        let (Some(name), Some(number), Some("kB")) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let value = number
            .parse::<u64>()
            .ok()
            .and_then(|number| number.checked_mul(1024));
        if name == total {
            total_bytes = value;
        }
        if name == available {
            available_bytes = value;
        }
    }
    let total = total_bytes?;
    let available = available_bytes?;
    Some(json!({"total":total, "used":total.saturating_sub(available)}))
}
fn cpu(input: &str) -> Option<(u64, u64)> {
    let line = input
        .lines()
        .find(|line| line.split_whitespace().next() == Some("cpu"))?;
    let values: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .take(8)
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()
        .ok()?;
    if values.len() < 4 {
        return None;
    }
    let total = values
        .iter()
        .try_fold(0u64, |sum, value| sum.checked_add(*value))?;
    let idle = values[3].checked_add(values.get(4).copied().unwrap_or(0))?;
    (idle <= total).then_some((total, idle))
}
#[cfg(target_os = "linux")]
fn disk(path: &Path) -> Option<Value> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let path_text = path.to_str()?;
    let name = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut data = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: the C path is NUL terminated and data points to writable memory.
    if unsafe { libc::statvfs(name.as_ptr(), data.as_mut_ptr()) } != 0 {
        return None;
    }
    let data = unsafe { data.assume_init() };
    let total = data.f_blocks.checked_mul(data.f_frsize)?;
    let used = data
        .f_blocks
        .checked_sub(data.f_bfree)?
        .checked_mul(data.f_frsize)?;
    let available = data.f_bavail.checked_mul(data.f_frsize)?;
    Some(json!({"path":path_text, "total":total, "used":used, "available":available}))
}
#[cfg(not(target_os = "linux"))]
fn disk(_: &Path) -> Option<Value> {
    None
}

/// A caller must isolate and bound this operation because a remote filesystem
/// may not respond to statvfs.
pub fn disk_status(path: &Path) -> Option<Value> {
    disk(path)
}

/// The returned counter tuple is deliberately separate from JSON. Callers can
/// calculate CPU utilization across two samples from the same boot.
pub fn sample(proc_root: &Path, disk_path: &Path) -> (Value, Option<(u64, u64)>) {
    sample_inner(proc_root, Some(disk_path))
}

/// Sampling only kernel procfs avoids blocking a long-lived service on a
/// potentially remote or unresponsive filesystem. Disk sampling requires a
/// separately bounded worker before it can be used in production.
pub fn sample_without_disk(proc_root: &Path) -> (Value, Option<(u64, u64)>) {
    sample_inner(proc_root, None)
}

fn sample_inner(proc_root: &Path, disk_path: Option<&Path>) -> (Value, Option<(u64, u64)>) {
    let uptime = text(&proc_root.join("uptime"), 1024)
        .and_then(|value| finite(value.split_whitespace().next()?));
    let load = text(&proc_root.join("loadavg"), 1024).and_then(|value| {
        let values: Vec<f64> = value
            .split_whitespace()
            .take(3)
            .map(finite)
            .collect::<Option<_>>()?;
        (values.len() == 3).then_some(values)
    });
    let meminfo = text(&proc_root.join("meminfo"), 65536);
    let mem = meminfo
        .as_deref()
        .and_then(|value| memory(value, "MemTotal:", "MemAvailable:"));
    let swap = meminfo
        .as_deref()
        .and_then(|value| memory(value, "SwapTotal:", "SwapFree:"));
    let stat = text(&proc_root.join("stat"), 65536);
    let counters = stat.as_deref().and_then(cpu);
    let booted = stat.as_deref().and_then(|value| {
        value.lines().find_map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next()? != "btime" {
                return None;
            }
            fields.next()?.parse::<u64>().ok()
        })
    });
    (
        json!({"uptime_seconds":uptime, "memory":mem, "swap":swap, "disk":disk_path.and_then(disk),
            "load":load, "booted_at":booted}),
        counters,
    )
}

/// Calculate CPU use from monotonically advancing, checked aggregate ticks.
pub fn cpu_percent(previous: Option<(u64, u64)>, current: Option<(u64, u64)>) -> Option<f64> {
    let (old_total, old_idle) = previous?;
    let (total, idle) = current?;
    let delta = total.checked_sub(old_total)?;
    let idle_delta = idle.checked_sub(old_idle)?;
    if delta == 0 || idle_delta > delta {
        return None;
    }
    Some((100.0 * (1.0 - idle_delta as f64 / delta as f64)).clamp(0.0, 100.0))
}
