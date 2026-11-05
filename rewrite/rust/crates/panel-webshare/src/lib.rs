//! Experimental compatibility for the encrypted Webshare control files.
//! This is not a residential gateway or a production service. The caller must
//! authenticate, hold the panel mutation lock, and coordinate durable audit
//! and worker state before exposing these writes in a production deployment.
use serde_json::{json, Map, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use xcli_auth_compat::{open_xgb1, seal_xgb1};
use zeroize::{Zeroize, Zeroizing};

pub mod audit;
pub mod coordinator;
pub mod probe;
pub mod provider;
pub mod region;
pub mod relay;
pub mod runner;
pub mod sync;

const CONTEXT: &[u8] = b"xcli:webshare:config:v1";
const ACTIVE_CONTEXT: &[u8] = b"xcli:webshare:active:v1";
const PENDING_CONTEXT: &[u8] = b"xcli:webshare:pending:v1";
pub struct Region {
    pub country: &'static str,
    pub label: &'static str,
    pub group: &'static str,
    pub tag: &'static str,
    pub port: u16,
    pub socks_port: u16,
}
pub const REGIONS: [Region; 16] = [
    Region {
        country: "US",
        label: "美国",
        group: "北美",
        tag: "residential-11",
        port: 10110,
        socks_port: 10120,
    },
    Region {
        country: "JP",
        label: "日本",
        group: "亚洲",
        tag: "residential-12",
        port: 10111,
        socks_port: 10121,
    },
    Region {
        country: "SG",
        label: "新加坡",
        group: "亚洲",
        tag: "residential-13",
        port: 10112,
        socks_port: 10122,
    },
    Region {
        country: "ZZ",
        label: "全球",
        group: "全球",
        tag: "residential-14",
        port: 10113,
        socks_port: 10123,
    },
    Region {
        country: "HK",
        label: "香港",
        group: "亚洲",
        tag: "residential-15",
        port: 10200,
        socks_port: 10300,
    },
    Region {
        country: "TW",
        label: "台湾",
        group: "亚洲",
        tag: "residential-16",
        port: 10201,
        socks_port: 10301,
    },
    Region {
        country: "KR",
        label: "韩国",
        group: "亚洲",
        tag: "residential-17",
        port: 10202,
        socks_port: 10302,
    },
    Region {
        country: "TH",
        label: "泰国",
        group: "亚洲",
        tag: "residential-18",
        port: 10203,
        socks_port: 10303,
    },
    Region {
        country: "MY",
        label: "马来西亚",
        group: "亚洲",
        tag: "residential-19",
        port: 10204,
        socks_port: 10304,
    },
    Region {
        country: "IN",
        label: "印度",
        group: "亚洲",
        tag: "residential-20",
        port: 10205,
        socks_port: 10305,
    },
    Region {
        country: "CA",
        label: "加拿大",
        group: "北美",
        tag: "residential-21",
        port: 10206,
        socks_port: 10306,
    },
    Region {
        country: "GB",
        label: "英国",
        group: "欧洲",
        tag: "residential-22",
        port: 10207,
        socks_port: 10307,
    },
    Region {
        country: "DE",
        label: "德国",
        group: "欧洲",
        tag: "residential-23",
        port: 10208,
        socks_port: 10308,
    },
    Region {
        country: "FR",
        label: "法国",
        group: "欧洲",
        tag: "residential-24",
        port: 10209,
        socks_port: 10309,
    },
    Region {
        country: "NL",
        label: "荷兰",
        group: "欧洲",
        tag: "residential-25",
        port: 10210,
        socks_port: 10310,
    },
    Region {
        country: "AU",
        label: "澳大利亚",
        group: "大洋洲",
        tag: "residential-26",
        port: 10211,
        socks_port: 10311,
    },
];

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    Unavailable,
}
type Result<T> = std::result::Result<T, Error>;
pub struct AuditRecord {
    pub id: String,
    pub timestamp: i64,
    pub action: &'static str,
    pub detail: &'static str,
}
/// Implementations must atomically deduplicate the operation ID with the
/// audit entry, so recovery after a crash cannot insert the same event twice.
pub trait Auditor {
    fn record(&mut self, record: &AuditRecord) -> Result<()>;
}
fn exists_region(country: &str) -> bool {
    REGIONS.iter().any(|item| item.country == country)
}
fn scrub(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(scrub),
        Value::Object(values) => values.values_mut().for_each(scrub),
        _ => (),
    }
}
fn redact(value: &mut Value, secret: &str) {
    if secret.is_empty() {
        return;
    }
    match value {
        Value::String(text)
            if (secret.len() >= 4 && text.contains(secret)) || text.as_str() == secret =>
        {
            let replacement = text.replace(secret, "[已隐藏]");
            text.zeroize();
            *text = replacement;
        }
        Value::Array(values) => values.iter_mut().for_each(|value| redact(value, secret)),
        Value::Object(values) => values.values_mut().for_each(|value| redact(value, secret)),
        _ => (),
    }
}
#[derive(Clone)]
struct Secret(Value);
impl Drop for Secret {
    fn drop(&mut self) {
        scrub(&mut self.0);
    }
}
/// Contains provider credentials and session identities; never log or expose it
/// in an HTTP response. Drops clear strings owned by the snapshot.
pub struct ActiveSnapshot(Secret);
impl ActiveSnapshot {
    pub fn from_value(value: Value, countries: &[&str], now: i64) -> Result<Self> {
        let mut state = Secret(value);
        if now < 0
            || countries.len() > REGIONS.len()
            || countries.iter().any(|country| !exists_region(country))
        {
            return Err(Error::Unavailable);
        }
        let active = state
            .0
            .get("active")
            .and_then(Value::as_object)
            .ok_or(Error::Unavailable)?;
        if !active.get("enabled").is_some_and(Value::is_boolean)
            || !active
                .get("plan_id")
                .and_then(Value::as_i64)
                .is_some_and(|id| (0..=2_147_483_647).contains(&id))
            || !state
                .0
                .get("processed_revision")
                .and_then(Value::as_str)
                .is_some_and(|value| value.len() <= 128)
            || !state
                .0
                .get("plans")
                .and_then(Value::as_array)
                .is_some_and(|items| items.len() <= 100)
        {
            return Err(Error::Unavailable);
        }
        if let Some(key) = active.get("api_key") {
            if !key
                .as_str()
                .is_some_and(|key| key.is_empty() || api_key(key))
            {
                return Err(Error::Unavailable);
            }
        }
        if let Some(credentials) = active.get("credentials") {
            let object = credentials.as_object().ok_or(Error::Unavailable)?;
            let base = object
                .get("base")
                .and_then(Value::as_str)
                .ok_or(Error::Unavailable)?;
            let password = object
                .get("password")
                .and_then(Value::as_str)
                .ok_or(Error::Unavailable)?;
            if base.is_empty()
                || base.len() > 64
                || !base
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                || password.is_empty()
                || password.len() > 255
                || password.chars().any(|value| (value as u32) < 32)
            {
                return Err(Error::Unavailable);
            }
        }
        let pools = state
            .0
            .get_mut("pools")
            .and_then(Value::as_object_mut)
            .ok_or(Error::Unavailable)?;
        let mut normalized = Secret(json!({}));
        for country in countries {
            if normalized.0.get(*country).is_some() {
                continue;
            }
            let mut sessions = Secret(json!([]));
            if let Some(saved) = pools.get(*country) {
                let saved = saved
                    .as_array()
                    .filter(|items| items.len() <= 16)
                    .ok_or(Error::Unavailable)?;
                for item in saved {
                    let username = item
                        .get("username")
                        .and_then(Value::as_str)
                        .ok_or(Error::Unavailable)?;
                    let expires = item
                        .get("expires_at")
                        .and_then(Value::as_i64)
                        .ok_or(Error::Unavailable)?;
                    if username.is_empty()
                        || username.len() > 255
                        || !username.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
                        })
                        || expires < 0
                    {
                        return Err(Error::Unavailable);
                    }
                    if expires > now {
                        sessions
                            .0
                            .as_array_mut()
                            .ok_or(Error::Unavailable)?
                            .push(item.clone());
                    }
                }
            }
            normalized.0[*country] = std::mem::take(&mut sessions.0);
        }
        for value in pools.values_mut() {
            scrub(value);
        }
        *pools = std::mem::take(normalized.0.as_object_mut().ok_or(Error::Unavailable)?);
        Ok(Self(state))
    }
    pub fn as_value(&self) -> &Value {
        &self.0 .0
    }
}
fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| Error::Unavailable)?;
    Ok(hex::encode(bytes))
}
fn read_file(path: &Path, limit: u64) -> Result<Option<Vec<u8>>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::Unavailable),
    };
    let metadata = file.metadata().map_err(|_| Error::Unavailable)?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(Error::Unavailable);
    }
    let mut content = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut content)
        .map_err(|_| Error::Unavailable)?;
    if content.len() as u64 > limit {
        return Err(Error::Unavailable);
    }
    Ok(Some(content))
}
fn sync_dir(path: &Path) -> Result<()> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| Error::Unavailable)
}
fn permitted_fields<'a>(input: &'a Value, allowed: &[&str]) -> Result<&'a Map<String, Value>> {
    let map = input
        .as_object()
        .ok_or(Error::Invalid("请求必须是 JSON 对象"))?;
    if map.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(Error::Invalid("包含不支持的字段"));
    }
    Ok(map)
}
fn bool_field(value: &Value) -> Result<bool> {
    value.as_bool().ok_or(Error::Invalid("请输入有效布尔值"))
}
fn api_key(value: &str) -> bool {
    (16..=256).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}
fn short(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}
fn integer(value: &Value) -> bool {
    value.is_i64() || value.is_u64()
}
fn copy_ints(source: &Value, target: &mut Value, keys: &[&str]) {
    for key in keys {
        if let Some(value) = source.get(key).filter(|value| integer(value)) {
            target[*key] = value.clone();
        }
    }
}
fn copy_strings(source: &Value, target: &mut Value, keys: &[&str], limit: usize) {
    for key in keys {
        if let Some(value) = source.get(key).and_then(Value::as_str) {
            target[*key] = json!(short(value, limit));
        }
    }
}

/// Reads and writes only a named state's Webshare subdirectory. Credentials
/// and the unredacted configuration must never be logged or returned to users.
pub struct Control {
    state: PathBuf,
    settings: Value,
    key: Zeroizing<[u8; 32]>,
}
impl Control {
    pub fn open(state: &Path, settings: Value, key: [u8; 32]) -> Result<Self> {
        let meta = fs::symlink_metadata(state).map_err(|_| Error::Unavailable)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(Error::Unavailable);
        }
        let state = fs::canonicalize(state).map_err(|_| Error::Unavailable)?;
        if !settings.is_object() {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            state,
            settings,
            key: Zeroizing::new(key),
        })
    }
    fn directory(&self, create: bool) -> Result<PathBuf> {
        let path = self.state.join("webshare");
        if create {
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => sync_dir(&self.state)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(_) => return Err(Error::Unavailable),
            }
        }
        self.existing_directory()?.ok_or(Error::Unavailable)
    }
    fn existing_directory(&self) -> Result<Option<PathBuf>> {
        let path = self.state.join("webshare");
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Error::Unavailable),
        };
        if !meta.is_dir() || meta.file_type().is_symlink() || meta.mode() & 0o077 != 0 {
            return Err(Error::Unavailable);
        }
        Ok(Some(path))
    }
    fn lock_file(&self, name: &str) -> Result<File> {
        let dir = self.directory(true)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(dir.join(name))
            .map_err(|_| Error::Unavailable)?;
        let metadata = file.metadata().map_err(|_| Error::Unavailable)?;
        if !metadata.is_file() || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(Error::Unavailable);
        }
        Ok(file)
    }
    /// Exclusive lease for one new worker; retain the returned file until all
    /// listeners stop. The old Python worker does not honor this lease.
    pub fn worker_lease(&self) -> Result<File> {
        let file = self.lock_file("worker.lock")?;
        // SAFETY: the descriptor remains open in the returned File.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error::Unavailable);
        }
        Ok(file)
    }
    /// Serialize all new control writers and worker commits across processes.
    /// Legacy C++/Python processes do not honor this lock and must be stopped.
    fn lock(&self) -> Result<File> {
        let file = self.lock_file("control.lock")?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            // SAFETY: the descriptor owns the lock until it is dropped.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(file);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() != std::io::ErrorKind::WouldBlock || Instant::now() >= deadline {
                return Err(Error::Unavailable);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn pending_exists(&self) -> Result<bool> {
        let Some(dir) = self.existing_directory()? else {
            return Ok(false);
        };
        match fs::symlink_metadata(dir.join("pending.xgb")) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
            Ok(_) => Err(Error::Unavailable),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(Error::Unavailable),
        }
    }
    fn config(&self) -> Result<Secret> {
        if self.pending_exists()? {
            return Err(Error::Unavailable);
        }
        self.config_unchecked()
    }
    fn config_unchecked(&self) -> Result<Secret> {
        let Some(dir) = self.existing_directory()? else {
            return Ok(Secret(
                json!({"api_key":"","plan_id":0,"enabled":false,"revision":""}),
            ));
        };
        let path = dir.join("config.xgb");
        let data = match read_file(&path, 16 * 1024)? {
            Some(value) => value,
            None => {
                return Ok(Secret(
                    json!({"api_key":"","plan_id":0,"enabled":false,"revision":""}),
                ))
            }
        };
        let plain = open_xgb1(&data, self.key.as_ref(), CONTEXT).map_err(|_| Error::Unavailable)?;
        let config = Secret(serde_json::from_slice(&plain).map_err(|_| Error::Unavailable)?);
        let key = config
            .0
            .get("api_key")
            .and_then(Value::as_str)
            .ok_or(Error::Unavailable)?;
        let plan = config
            .0
            .get("plan_id")
            .and_then(Value::as_i64)
            .ok_or(Error::Unavailable)?;
        if (!key.is_empty() && !api_key(key))
            || !(0..=2_147_483_647).contains(&plan)
            || !config.0.get("enabled").is_some_and(Value::is_boolean)
            || !config.0.get("revision").is_some_and(Value::is_string)
        {
            return Err(Error::Unavailable);
        }
        Ok(config)
    }
    fn write_secret(
        &self,
        name: &str,
        context: &[u8],
        maximum: usize,
        config: &Secret,
    ) -> Result<()> {
        let plaintext =
            Zeroizing::new(serde_json::to_vec(&config.0).map_err(|_| Error::Unavailable)?);
        let encrypted =
            seal_xgb1(&plaintext, self.key.as_ref(), context).map_err(|_| Error::Unavailable)?;
        if encrypted.len() > maximum {
            return Err(Error::Unavailable);
        }
        self.write_atomic(name, &encrypted)
    }
    fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let dir = self.directory(true)?;
        let temporary = dir.join(format!(".state-{}", random_id()?));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .map_err(|_| Error::Unavailable)?;
        let result = file
            .write_all(bytes)
            .and_then(|_| file.sync_all())
            .and_then(|_| fs::rename(&temporary, dir.join(name)));
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(Error::Unavailable);
        }
        sync_dir(&dir)
    }
    pub(crate) fn write_report(&self, value: &Value) -> Result<()> {
        let bytes = serde_json::to_vec(value).map_err(|_| Error::Unavailable)?;
        if bytes.len() > 65536 {
            return Err(Error::Unavailable);
        }
        self.write_atomic("report.json", &bytes)
    }
    fn write(&self, config: &Secret) -> Result<()> {
        self.write_secret("config.xgb", CONTEXT, 16 * 1024, config)
    }
    pub fn load_active(&self, countries: &[&str], now: i64) -> Result<Option<ActiveSnapshot>> {
        let Some(dir) = self.existing_directory()? else {
            return Ok(None);
        };
        let Some(data) = read_file(&dir.join("active.xgb"), 2 * 1024 * 1024)? else {
            return Ok(None);
        };
        let plain =
            open_xgb1(&data, self.key.as_ref(), ACTIVE_CONTEXT).map_err(|_| Error::Unavailable)?;
        let value = serde_json::from_slice(&plain).map_err(|_| Error::Unavailable)?;
        ActiveSnapshot::from_value(value, countries, now).map(Some)
    }
    pub fn save_active(&self, snapshot: &ActiveSnapshot) -> Result<()> {
        self.write_secret("active.xgb", ACTIVE_CONTEXT, 2 * 1024 * 1024, &snapshot.0)
    }
    fn report(&self, now: i64) -> Value {
        let fallback = || json!({"updated":0,"status":"unknown","message":"等待池管理服务","plans":[],"pools":[],"events":[]});
        let Ok(Some(dir)) = self.existing_directory() else {
            return fallback();
        };
        let Some(data) = read_file(&dir.join("report.json"), 65536).ok().flatten() else {
            return fallback();
        };
        let data = Zeroizing::new(data);
        let Ok(source) = serde_json::from_slice::<Value>(&data) else {
            return fallback();
        };
        let source = Secret(source);
        let source = &source.0;
        if !source.is_object() {
            return fallback();
        }
        let mut out = json!({"updated":0,"status":"unconfigured","message":"填写 API Key 后读取可用套餐","plans":[],"pools":[],"events":[]});
        copy_ints(
            source,
            &mut out,
            &[
                "updated",
                "last_sync",
                "last_attempt",
                "next_sync",
                "active_plan_id",
                "usage_updated",
                "requests_total",
                "requests_successful",
                "requests_failed",
            ],
        );
        copy_strings(
            source,
            &mut out,
            &["status", "message", "revision", "sync_error", "usage_error"],
            256,
        );
        if let Some(value) = source
            .get("bandwidth_total")
            .filter(|value| value.is_number())
        {
            out["bandwidth_total"] = value.clone();
        }
        if let Some(value) = source.get("enabled").and_then(Value::as_bool) {
            out["active_enabled"] = json!(value);
        }
        if let Some(plans) = source.get("plans").and_then(Value::as_array) {
            for plan in plans
                .iter()
                .filter(|plan| plan.get("id").is_some_and(integer))
                .take(100)
            {
                let mut item = json!({"id":plan["id"]});
                copy_strings(
                    plan,
                    &mut item,
                    &["label", "status", "pool_filter", "proxy_subtype"],
                    100,
                );
                if let Some(value) = plan
                    .get("bandwidth_limit")
                    .filter(|value| value.is_number())
                {
                    item["bandwidth_limit"] = value.clone();
                }
                if let Some(value) = plan.get("eligible").and_then(Value::as_bool) {
                    item["eligible"] = json!(value);
                }
                out["plans"].as_array_mut().unwrap().push(item);
            }
        }
        if let Some(pools) = source.get("pools").and_then(Value::as_array) {
            for pool in pools
                .iter()
                .filter(|pool| {
                    pool.get("country")
                        .and_then(Value::as_str)
                        .is_some_and(exists_region)
                })
                .take(REGIONS.len())
            {
                let mut item = json!({"country":pool["country"]});
                copy_strings(
                    pool,
                    &mut item,
                    &["label", "status", "error", "exit_ip", "exit_country"],
                    256,
                );
                copy_ints(
                    pool,
                    &mut item,
                    &[
                        "last_success",
                        "selected_at",
                        "expires_at",
                        "standby",
                        "ready_standby",
                        "failures",
                        "https_ms",
                        "doh_ms",
                        "probe_interval",
                        "failovers",
                    ],
                );
                out["pools"].as_array_mut().unwrap().push(item);
            }
        }
        if let Some(events) = source.get("events").and_then(Value::as_array) {
            for event in events
                .iter()
                .filter(|event| {
                    event
                        .get("country")
                        .and_then(Value::as_str)
                        .is_some_and(exists_region)
                })
                .take(20)
            {
                out["events"].as_array_mut().unwrap().push(json!({"country":event["country"],"ts":event.get("ts").and_then(Value::as_i64).unwrap_or(0),
                    "reason":short(event.get("reason").and_then(Value::as_str).unwrap_or(""),120)}));
            }
        }
        if now.saturating_sub(out["updated"].as_i64().unwrap_or(0)) > 30 {
            out["status"] = json!("stale");
            out["message"] = json!("池管理服务状态已过期，请检查服务");
        }
        out
    }
    pub fn status(&self, now: i64) -> Result<Value> {
        let config = self.config()?;
        let mut status = self.report(now);
        status["key_saved"] = json!(!config.0["api_key"].as_str().unwrap_or("").is_empty());
        status["plan_id"] = config.0["plan_id"].clone();
        status["enabled"] = config.0["enabled"].clone();
        status["requested_revision"] = config.0["revision"].clone();
        let exits = self
            .settings
            .get("residential_exits")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        status["installed"] = json!(exits
            .iter()
            .any(|exit| exit.get("dynamic").and_then(Value::as_bool) == Some(true)));
        let mut regions = Vec::new();
        for region in &REGIONS {
            for exit in exits {
                if exit.get("dynamic").and_then(Value::as_bool) == Some(true)
                    && exit.get("country").and_then(Value::as_str) == Some(region.country)
                {
                    regions.push(
                        json!({"country":region.country,"label":region.label,"group":region.group}),
                    );
                }
            }
        }
        status["regions"] = json!(regions);
        redact(&mut status, config.0["api_key"].as_str().unwrap_or(""));
        Ok(status)
    }
    fn prepare_configure(&self, input: &Value, now: i64) -> Result<(Secret, &'static str)> {
        if now < 0 {
            return Err(Error::Invalid("时间无效"));
        }
        let map = permitted_fields(input, &["api_key", "plan_id", "enabled", "clear_key"])?;
        let mut config = self.config()?;
        if let Some(value) = map.get("api_key") {
            let key = value.as_str().ok_or(Error::Invalid("API Key 格式不正确"))?;
            if !key.is_empty() {
                if !api_key(key) {
                    return Err(Error::Invalid("API Key 格式不正确"));
                }
                scrub(&mut config.0["api_key"]);
                config.0["api_key"] = json!(key);
            }
        }
        if let Some(value) = map.get("clear_key") {
            if bool_field(value)? {
                scrub(&mut config.0["api_key"]);
                config.0["api_key"] = json!("");
                config.0["enabled"] = json!(false);
                config.0["plan_id"] = json!(0);
            }
        }
        if let Some(value) = map.get("plan_id") {
            let id = value
                .as_i64()
                .filter(|number| (0..=2_147_483_647).contains(number))
                .ok_or(Error::Invalid("请输入有效整数"))?;
            if id != 0
                && !self.report(now)["plans"].as_array().is_some_and(|plans| {
                    plans.iter().any(|plan| {
                        plan["id"].as_i64() == Some(id) && plan["eligible"].as_bool() == Some(true)
                    })
                })
            {
                return Err(Error::Invalid("请先读取套餐，再选择可用的动态住宅套餐"));
            }
            config.0["plan_id"] = json!(id);
        }
        if let Some(value) = map.get("enabled") {
            config.0["enabled"] = json!(bool_field(value)?);
        }
        let enabled = config.0["enabled"].as_bool().ok_or(Error::Unavailable)?;
        if enabled
            && (config.0["api_key"].as_str().unwrap_or("").is_empty()
                || config.0["plan_id"].as_i64() == Some(0))
        {
            return Err(Error::Invalid("启用前请填写 API Key 并选择套餐"));
        }
        config.0["revision"] = json!(random_id()?);
        config.0["requested_at"] = json!(now);
        if let Some(map) = config.0.as_object_mut() {
            map.remove("action");
            map.remove("country");
        }
        Ok((
            config,
            if enabled {
                "动态住宅池已请求启用"
            } else {
                "Webshare 配置已保存"
            },
        ))
    }
    fn prepare_request(&self, input: &Value, now: i64) -> Result<(Secret, &'static str)> {
        if now < 0 {
            return Err(Error::Invalid("时间无效"));
        }
        let map = permitted_fields(input, &["action", "country"])?;
        let action = map
            .get("action")
            .and_then(Value::as_str)
            .ok_or(Error::Invalid("缺少必要字段"))?;
        if !["sync", "rotate"].contains(&action) {
            return Err(Error::Invalid("不支持此操作"));
        }
        let mut config = self.config()?;
        if config.0["api_key"].as_str().unwrap_or("").is_empty() {
            return Err(Error::Invalid("请先保存 API Key"));
        }
        if action == "rotate" {
            let country = map.get("country").and_then(Value::as_str).unwrap_or("");
            if !exists_region(country) || config.0["enabled"].as_bool() != Some(true) {
                return Err(Error::Invalid("请先启用对应地区的动态池"));
            }
            config.0["country"] = json!(country);
        }
        config.0["action"] = json!(action);
        config.0["revision"] = json!(random_id()?);
        config.0["requested_at"] = json!(now);
        Ok((
            config,
            if action == "sync" {
                "请求同步 Webshare"
            } else {
                "请求更换动态住宅会话"
            },
        ))
    }
    /// Unaudited compatibility helper for isolated fixtures only.
    pub fn configure(&self, input: &Value, now: i64) -> Result<&'static str> {
        let _guard = self.lock()?;
        let (config, detail) = self.prepare_configure(input, now)?;
        self.write(&config)?;
        Ok(detail)
    }
    /// Unaudited compatibility helper for isolated fixtures only.
    pub fn request(&self, input: &Value, now: i64) -> Result<&'static str> {
        let _guard = self.lock()?;
        let (config, detail) = self.prepare_request(input, now)?;
        self.write(&config)?;
        Ok(detail)
    }
    fn recover_locked(&self, auditor: &mut dyn Auditor) -> Result<()> {
        let Some(dir) = self.existing_directory()? else {
            return Ok(());
        };
        let path = dir.join("pending.xgb");
        let Some(encrypted) = read_file(&path, 32 * 1024)? else {
            return Ok(());
        };
        let plaintext = open_xgb1(&encrypted, self.key.as_ref(), PENDING_CONTEXT)
            .map_err(|_| Error::Unavailable)?;
        let journal =
            Secret(serde_json::from_slice::<Value>(&plaintext).map_err(|_| Error::Unavailable)?);
        let id = journal.0["id"]
            .as_str()
            .filter(|id| id.len() == 32 && id.bytes().all(|v| v.is_ascii_hexdigit()))
            .ok_or(Error::Unavailable)?;
        let timestamp = journal.0["timestamp"]
            .as_i64()
            .filter(|value| *value >= 0)
            .ok_or(Error::Unavailable)?;
        let (action, detail) = match (journal.0["action"].as_str(), journal.0["detail"].as_str()) {
            (Some("webshare_configured"), Some("动态住宅池已请求启用")) => {
                ("webshare_configured", "动态住宅池已请求启用")
            }
            (Some("webshare_configured"), Some("Webshare 配置已保存")) => {
                ("webshare_configured", "Webshare 配置已保存")
            }
            (Some("webshare_requested"), Some("请求同步 Webshare")) => {
                ("webshare_requested", "请求同步 Webshare")
            }
            (Some("webshare_requested"), Some("请求更换动态住宅会话")) => {
                ("webshare_requested", "请求更换动态住宅会话")
            }
            _ => return Err(Error::Unavailable),
        };
        let previous = journal.0["previous_revision"]
            .as_str()
            .filter(|value| value.len() <= 128)
            .ok_or(Error::Unavailable)?;
        let next = Secret(journal.0.get("config").cloned().ok_or(Error::Unavailable)?);
        let desired = sync::Desired::from_value(&next.0).map_err(|_| Error::Unavailable)?;
        let current = self.config_unchecked()?;
        let current_revision = current.0["revision"].as_str().ok_or(Error::Unavailable)?;
        if current_revision == previous && current_revision != desired.revision {
            self.write(&next)?;
        } else if current_revision != desired.revision || current.0 != next.0 {
            return Err(Error::Unavailable);
        }
        auditor.record(&AuditRecord {
            id: id.to_owned(),
            timestamp,
            action,
            detail,
        })?;
        fs::remove_file(&path).map_err(|_| Error::Unavailable)?;
        sync_dir(&dir)
    }
    /// Finish any durable pending write before accepting new control changes.
    pub fn recover(&self, auditor: &mut dyn Auditor) -> Result<()> {
        if !self.pending_exists()? {
            return Ok(());
        }
        let _guard = self.lock()?;
        self.recover_locked(auditor)
    }
    fn commit_audited(
        &self,
        previous: &str,
        config: &Secret,
        now: i64,
        action: &'static str,
        detail: &'static str,
        auditor: &mut dyn Auditor,
    ) -> Result<()> {
        let desired = sync::Desired::from_value(&config.0).map_err(|_| Error::Unavailable)?;
        if previous.len() > 128 || previous == desired.revision {
            return Err(Error::Unavailable);
        }
        let journal = Secret(json!({"id":random_id()?,"timestamp":now,"action":action,
            "detail":detail,"previous_revision":previous,"config":config.0}));
        self.write_secret("pending.xgb", PENDING_CONTEXT, 32 * 1024, &journal)?;
        self.recover_locked(auditor)
    }
    pub fn configure_audited(
        &self,
        input: &Value,
        now: i64,
        auditor: &mut dyn Auditor,
    ) -> Result<&'static str> {
        let _guard = self.lock()?;
        self.recover_locked(auditor)?;
        let previous = self.config()?;
        let revision = previous.0["revision"].as_str().ok_or(Error::Unavailable)?;
        let (config, detail) = self.prepare_configure(input, now)?;
        self.commit_audited(
            revision,
            &config,
            now,
            "webshare_configured",
            detail,
            auditor,
        )?;
        Ok(detail)
    }
    pub fn request_audited(
        &self,
        input: &Value,
        now: i64,
        auditor: &mut dyn Auditor,
    ) -> Result<&'static str> {
        let _guard = self.lock()?;
        self.recover_locked(auditor)?;
        let previous = self.config()?;
        let revision = previous.0["revision"].as_str().ok_or(Error::Unavailable)?;
        let (config, detail) = self.prepare_request(input, now)?;
        self.commit_audited(
            revision,
            &config,
            now,
            "webshare_requested",
            detail,
            auditor,
        )?;
        Ok(detail)
    }
}

#[cfg(test)]
mod audit_recovery_tests {
    use super::*;

    #[derive(Default)]
    struct Audit(Vec<String>);
    impl Auditor for Audit {
        fn record(&mut self, record: &AuditRecord) -> Result<()> {
            if !self.0.contains(&record.id) {
                self.0.push(record.id.clone());
            }
            Ok(())
        }
    }
    fn stage(control: &Control) {
        let (next, detail) = control
            .prepare_configure(&json!({"api_key":"synthetic-api-key-for-test"}), 1000)
            .unwrap();
        let journal = Secret(
            json!({"id":"0123456789abcdef0123456789abcdef","timestamp":1000,
            "action":"webshare_configured","detail":detail,"previous_revision":"","config":next.0.clone()}),
        );
        control
            .write_secret("pending.xgb", PENDING_CONTEXT, 32 * 1024, &journal)
            .unwrap();
    }
    #[test]
    fn recovery_completes_a_journal_written_before_the_configuration() {
        let state = tempfile::tempdir().unwrap();
        let control = Control::open(state.path(), json!({}), [9; 32]).unwrap();
        stage(&control);
        assert_eq!(control.config_unchecked().unwrap().0["revision"], "");
        assert_eq!(control.status(1000), Err(Error::Unavailable));
        let mut audit = Audit::default();
        control.recover(&mut audit).unwrap();
        assert_eq!(control.status(1000).unwrap()["key_saved"], true);
        assert_eq!(audit.0.len(), 1);
    }
    #[test]
    fn recovery_never_overwrites_an_unrelated_newer_configuration() {
        let state = tempfile::tempdir().unwrap();
        let control = Control::open(state.path(), json!({}), [9; 32]).unwrap();
        stage(&control);
        let unrelated = Secret(json!({"api_key":"another-synthetic-key","plan_id":0,
            "enabled":false,"revision":"unrelated"}));
        control.write(&unrelated).unwrap();
        let mut audit = Audit::default();
        assert_eq!(control.recover(&mut audit), Err(Error::Unavailable));
        assert_eq!(
            control.config_unchecked().unwrap().0["revision"],
            "unrelated"
        );
        assert!(audit.0.is_empty());
    }
}
