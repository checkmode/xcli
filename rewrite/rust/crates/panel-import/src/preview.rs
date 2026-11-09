//! Experimental two-step import coordinator. It is not an HTTP endpoint or a
//! production worker; service hooks must still validate and safely switch.
use crate::config::{
    add_fixed, add_vmess, enable_all_residential_hysteria, enable_residential_hysteria,
    enable_vmess, manage as manage_candidate, Files, Manage, Verified, VerifiedVmess,
};
use crate::journal::{Candidate, Hooks, JournalError, Store};
use crate::launcher::Launcher;
use crate::probe::{ProbeResult, Protocol};
use crate::vmess::{parse_links, SecretJson, VmessProxy};
use crate::{parse_fixed, Proxy};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub enum PreviewError {
    Invalid,
    Probe,
    Conflict,
    Expired,
    Unavailable,
}
impl From<JournalError> for PreviewError {
    fn from(value: JournalError) -> Self {
        match value {
            JournalError::Conflict | JournalError::Pending => Self::Conflict,
            JournalError::Invalid => Self::Invalid,
            JournalError::Unavailable | JournalError::RolledBack => Self::Unavailable,
        }
    }
}
pub struct Ready {
    id: String,
    deadline: Instant,
    snapshot: BTreeMap<String, String>,
    candidate: Candidate,
    entries: Vec<Value>,
}
impl Ready {
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Entries contain public labels and exit metadata, not upstream credentials.
    pub fn entries(&self) -> &[Value] {
        &self.entries
    }
    /// Consumes the preview even on failure. Callers must authorize the request
    /// and protect this value behind a single-owner operation slot.
    pub fn confirm(
        self,
        id: &str,
        store: &Store,
        hooks: &mut dyn Hooks,
    ) -> Result<(), PreviewError> {
        if id != self.id {
            return Err(PreviewError::Invalid);
        }
        if Instant::now() >= self.deadline {
            return Err(PreviewError::Expired);
        }
        store
            .apply(&self.snapshot, &self.candidate, hooks)
            .map_err(Into::into)
    }
}
fn check_label(label: &str) -> Result<(), PreviewError> {
    if label.is_empty() || label.chars().count() > 30 || label.chars().any(|c| c < ' ') {
        Err(PreviewError::Invalid)
    } else {
        Ok(())
    }
}
pub(crate) fn ready(
    store: &Store,
    snapshot: BTreeMap<String, String>,
    files: crate::config::Files,
    entries: Vec<Value>,
) -> Result<Ready, PreviewError> {
    if store.snapshot()? != snapshot {
        return Err(PreviewError::Conflict);
    }
    let candidate = Candidate::from_files(&files)?;
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|_| PreviewError::Unavailable)?;
    Ok(Ready {
        id: hex::encode(random),
        deadline: Instant::now() + Duration::from_secs(900),
        snapshot,
        candidate,
        entries,
    })
}
/// Probes are paired with the exact in-memory credentials used to build the
/// candidate. A changed on-disk snapshot invalidates the whole preview.
pub fn fixed(
    store: &Store,
    launcher: &Launcher,
    text: &str,
    protocol: Protocol,
    label: &str,
) -> Result<Ready, PreviewError> {
    fixed_cancellable(store, launcher, text, protocol, label, None)
}
pub(crate) fn fixed_cancellable(
    store: &Store,
    launcher: &Launcher,
    text: &str,
    protocol: Protocol,
    label: &str,
    stop: Option<&AtomicBool>,
) -> Result<Ready, PreviewError> {
    if stop.is_some_and(|stop| stop.load(Ordering::Acquire)) {
        return Err(PreviewError::Probe);
    }
    check_label(label)?;
    let proxies = parse_fixed(text).map_err(|_| PreviewError::Invalid)?;
    let (files, snapshot) = store.load()?;
    let mut results = Vec::new();
    for chunk in proxies.chunks(4) {
        let batch = std::thread::scope(|scope| {
            let tasks: Vec<_> = chunk
                .iter()
                .map(|proxy| scope.spawn(move || launcher.fixed_cancellable(proxy, protocol, stop)))
                .collect();
            tasks
                .into_iter()
                .map(|task| {
                    task.join()
                        .map_err(|_| PreviewError::Probe)?
                        .map_err(|_| PreviewError::Probe)
                })
                .collect::<Result<Vec<_>, _>>()
        })?;
        results.extend(batch);
    }
    if stop.is_some_and(|stop| stop.load(Ordering::Acquire)) {
        return Err(PreviewError::Probe);
    }
    let verified: Vec<_> = proxies
        .iter()
        .zip(&results)
        .map(|(proxy, result)| Verified {
            proxy,
            protocol,
            result,
        })
        .collect();
    let (files, entries) = add_fixed(files, &verified, label).map_err(|_| PreviewError::Invalid)?;
    ready(store, snapshot, files, entries)
}
pub fn vmess(
    store: &Store,
    launcher: &Launcher,
    text: &str,
    label: &str,
) -> Result<Ready, PreviewError> {
    vmess_cancellable(store, launcher, text, label, None)
}
pub(crate) fn vmess_cancellable(
    store: &Store,
    launcher: &Launcher,
    text: &str,
    label: &str,
    stop: Option<&AtomicBool>,
) -> Result<Ready, PreviewError> {
    if stop.is_some_and(|stop| stop.load(Ordering::Acquire)) {
        return Err(PreviewError::Probe);
    }
    check_label(label)?;
    let proxies = parse_links(text).map_err(|_| PreviewError::Invalid)?;
    let (files, snapshot) = store.load()?;
    let mut results = Vec::new();
    for chunk in proxies.chunks(4) {
        let batch = std::thread::scope(|scope| {
            let tasks: Vec<_> = chunk
                .iter()
                .map(|proxy| scope.spawn(move || launcher.vmess_cancellable(proxy, stop)))
                .collect();
            tasks
                .into_iter()
                .map(|task| {
                    task.join()
                        .map_err(|_| PreviewError::Probe)?
                        .map_err(|_| PreviewError::Probe)
                })
                .collect::<Result<Vec<_>, _>>()
        })?;
        results.extend(batch);
    }
    if stop.is_some_and(|stop| stop.load(Ordering::Acquire)) {
        return Err(PreviewError::Probe);
    }
    let verified: Vec<_> = proxies
        .iter()
        .zip(&results)
        .map(|(proxy, result)| VerifiedVmess { proxy, result })
        .collect();
    let (files, entries) = add_vmess(files, &verified, label).map_err(|_| PreviewError::Invalid)?;
    ready(store, snapshot, files, entries)
}

#[derive(Clone, Copy)]
pub enum Operation<'a> {
    Disable,
    Delete { now: u64 },
    Restore,
    Enable,
    Edit { changes: &'a Value },
}
enum ManagedProxy {
    Fixed(Proxy, Protocol),
    Vmess(VmessProxy),
}
fn proxy_from_candidate(files: &Files, tag: &str) -> Result<ManagedProxy, PreviewError> {
    let pool = files.pool()["proxies"]
        .as_array()
        .ok_or(PreviewError::Invalid)?;
    let target = pool
        .iter()
        .find(|entry| entry["tag"] == tag)
        .ok_or(PreviewError::Invalid)?;
    match target["protocol"].as_str() {
        Some("socks" | "http") => {
            let protocol = if target["protocol"] == "socks" {
                Protocol::Socks
            } else {
                Protocol::Http
            };
            let address = target["address"].as_str().ok_or(PreviewError::Invalid)?;
            let port = target["port"].as_u64().ok_or(PreviewError::Invalid)?;
            let user = target["username"].as_str().ok_or(PreviewError::Invalid)?;
            let password = target["password"].as_str().ok_or(PreviewError::Invalid)?;
            let text = Zeroizing::new(format!("{address}:{port}:{user}:{password}"));
            let mut proxies = parse_fixed(&text).map_err(|_| PreviewError::Invalid)?;
            if proxies.len() != 1
                || proxies[0].username() != user
                || proxies[0].password() != password
            {
                return Err(PreviewError::Invalid);
            }
            Ok(ManagedProxy::Fixed(proxies.remove(0), protocol))
        }
        Some("vmess") => {
            let mut record = SecretJson::new(json!({}));
            for key in [
                "address",
                "port",
                "uuid",
                "security",
                "network",
                "tls",
                "server_name",
                "host",
                "path",
                "alpn",
                "fingerprint",
            ] {
                record.value_mut()[key] = target.get(key).ok_or(PreviewError::Invalid)?.clone();
            }
            Ok(ManagedProxy::Vmess(
                VmessProxy::from_record(record.as_value()).map_err(|_| PreviewError::Invalid)?,
            ))
        }
        _ => Err(PreviewError::Invalid),
    }
}
fn with_result<'a>(
    operation: Operation<'a>,
    result: &'a ProbeResult,
    server_ip: Option<Ipv4Addr>,
) -> Manage<'a> {
    match operation {
        Operation::Enable => Manage::Enable { result, server_ip },
        Operation::Edit { changes } => Manage::Edit {
            changes,
            result,
            server_ip,
        },
        Operation::Disable => Manage::Disable,
        Operation::Delete { now } => Manage::Delete { now },
        Operation::Restore => Manage::Restore,
    }
}
/// Management previews probe changed/enabled credentials, then rebuild the
/// candidate from the same unchanged snapshot using that exact probe result.
pub fn manage(
    store: &Store,
    launcher: &Launcher,
    tag: &str,
    operation: Operation<'_>,
) -> Result<Ready, PreviewError> {
    manage_cancellable(store, launcher, tag, operation, None)
}
/// Build one atomic candidate for the whole selection. A failed item leaves
/// the original files untouched and no partial preview is returned.
pub(crate) fn delete_many_cancellable(
    store: &Store,
    tags: &[String],
    now: u64,
    stop: Option<&AtomicBool>,
) -> Result<Ready, PreviewError> {
    let mut unique = BTreeSet::new();
    if now == 0
        || tags.is_empty()
        || tags.len() > 40
        || tags.iter().any(|tag| {
            tag.len() != 14
                || !tag.starts_with("residential-")
                || !tag[12..].bytes().all(|b| b.is_ascii_digit())
                || !unique.insert(tag)
        })
    {
        return Err(PreviewError::Invalid);
    }
    let (mut files, snapshot) = store.load()?;
    let mut rows = Vec::with_capacity(tags.len());
    for tag in tags {
        if stop.is_some_and(|stop| stop.load(Ordering::Acquire)) {
            return Err(PreviewError::Probe);
        }
        let item = files.pool()["proxies"]
            .as_array()
            .and_then(|items| items.iter().find(|item| item["tag"] == *tag))
            .ok_or(PreviewError::Invalid)?;
        let entry = item
            .get("entry")
            .or_else(|| {
                files.settings()["residential_exits"]
                    .as_array()
                    .and_then(|items| items.iter().find(|entry| entry["tag"] == *tag))
            })
            .ok_or(PreviewError::Invalid)?;
        rows.push(json!({"tag":tag,"label":entry["label"].as_str().unwrap_or(""),
            "exit_ip":entry["exit_ip"].as_str().unwrap_or(""),"country":entry["country"].as_str().unwrap_or("")}));
        files = manage_candidate(files, tag, Manage::Delete { now })
            .map_err(|_| PreviewError::Invalid)?
            .0;
    }
    ready(store, snapshot, files, rows)
}
pub(crate) fn manage_cancellable(
    store: &Store,
    launcher: &Launcher,
    tag: &str,
    operation: Operation<'_>,
    stop: Option<&AtomicBool>,
) -> Result<Ready, PreviewError> {
    if stop.is_some_and(|stop| stop.load(Ordering::Acquire)) {
        return Err(PreviewError::Probe);
    }
    let (files, snapshot) = store.load()?;
    let placeholder = ProbeResult {
        exit_ip: Ipv4Addr::new(8, 8, 8, 8),
        country: "US".into(),
        https_ms: 0,
        doh_ms: 0,
    };
    if !matches!(operation, Operation::Enable | Operation::Edit { .. }) {
        let (files, entries) =
            manage_candidate(files, tag, with_result(operation, &placeholder, None))
                .map_err(|_| PreviewError::Invalid)?;
        return ready(store, snapshot, files, entries);
    }
    let target = files.pool()["proxies"]
        .as_array()
        .and_then(|items| items.iter().find(|item| item["tag"] == tag))
        .ok_or(PreviewError::Invalid)?;
    let changes = match operation {
        Operation::Edit { changes } => Some(changes),
        _ => None,
    };
    let protocol = changes
        .and_then(|value| value.get("protocol"))
        .and_then(Value::as_str)
        .or_else(|| target["protocol"].as_str())
        .ok_or(PreviewError::Invalid)?;
    let address = changes
        .and_then(|value| value.get("address"))
        .and_then(Value::as_str)
        .or_else(|| target["address"].as_str())
        .ok_or(PreviewError::Invalid)?;
    let temporary_ip = (protocol == "vmess").then(|| {
        address
            .parse::<Ipv4Addr>()
            .unwrap_or(Ipv4Addr::new(8, 8, 4, 4))
    });
    let (draft, _) = manage_candidate(
        files,
        tag,
        with_result(operation, &placeholder, temporary_ip),
    )
    .map_err(|_| PreviewError::Invalid)?;
    let (result, server_ip) = match proxy_from_candidate(&draft, tag)? {
        ManagedProxy::Fixed(proxy, protocol) => (
            launcher
                .fixed_cancellable(&proxy, protocol, stop)
                .map_err(|_| PreviewError::Probe)?,
            None,
        ),
        ManagedProxy::Vmess(proxy) => {
            let result = launcher
                .vmess_cancellable(&proxy, stop)
                .map_err(|_| PreviewError::Probe)?;
            (result.observed, Some(result.server_ip))
        }
    };
    if stop.is_some_and(|stop| stop.load(Ordering::Acquire)) {
        return Err(PreviewError::Probe);
    }
    drop(draft);
    let (files, current) = store.load()?;
    if current != snapshot {
        return Err(PreviewError::Conflict);
    }
    let (files, entries) = manage_candidate(files, tag, with_result(operation, &result, server_ip))
        .map_err(|_| PreviewError::Invalid)?;
    ready(store, snapshot, files, entries)
}

pub enum Entrance<'a> {
    Vmess,
    ResidentialHysteria { tag: &'a str },
    AllResidentialHysteria,
}
pub fn entrance(store: &Store, operation: Entrance<'_>) -> Result<Ready, PreviewError> {
    let (files, snapshot) = store.load()?;
    let (files, entries) = match operation {
        Entrance::Vmess => enable_vmess(files),
        Entrance::ResidentialHysteria { tag } => enable_residential_hysteria(files, tag),
        Entrance::AllResidentialHysteria => enable_all_residential_hysteria(files),
    }
    .map_err(|_| PreviewError::Invalid)?;
    ready(store, snapshot, files, entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde_json::json;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    struct HooksFixture;
    impl Hooks for HooksFixture {
        fn validate(&mut self, _: &Path) -> Result<(), JournalError> {
            Ok(())
        }
        fn stop(&mut self) -> Result<(), JournalError> {
            Ok(())
        }
        fn start_and_check(&mut self) -> Result<(), JournalError> {
            Ok(())
        }
    }
    #[test]
    fn preview_is_bound_to_probe_snapshot_and_one_confirmation() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let (Ok(uid), Ok(gid)) = (
            std::env::var("XCLI_TEST_PROBE_UID"),
            std::env::var("XCLI_TEST_PROBE_GID"),
        ) else {
            return;
        };
        let uid = uid.parse::<u32>().unwrap();
        let gid = gid.parse::<u32>().unwrap();
        assert_ne!(uid, 0);
        assert_ne!(gid, 0);
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let journal = dir.path().join("journal");
        let etc = dir.path().join("etc");
        fs::create_dir(&journal).unwrap();
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&etc).unwrap();
        fs::set_permissions(&etc, fs::Permissions::from_mode(0o700)).unwrap();
        let settings =
            json!({"public_ip":"8.8.8.8","ws_path":"/connect/fixture","residential_exits":[]});
        let core = json!({"inbounds":[{"tag":"reality","port":10443}],
            "outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"blocked","protocol":"blackhole"}],
            "routing":{"rules":[{"inboundTag":["reality"],"outboundTag":"direct"}]}});
        let monitor = json!({"residential_exits":[]});
        for (key, value) in [
            ("settings", serde_json::to_vec(&settings).unwrap()),
            ("core", serde_json::to_vec(&core).unwrap()),
            ("monitor", serde_json::to_vec(&monitor).unwrap()),
            (
                "nginx",
                b"server { location = /connect/fixture {} }".to_vec(),
            ),
        ] {
            fs::write(etc.join(key), value).unwrap();
            fs::set_permissions(etc.join(key), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let paths: BTreeMap<String, PathBuf> =
            ["settings", "core", "monitor", "nginx", "locations", "pool"]
                .into_iter()
                .map(|key| (key.to_owned(), etc.join(key)))
                .collect();
        let store = Store::open(&journal, &journal.join("update.lock"), paths).unwrap();
        let user_data = etc.join("users-unrelated");
        fs::write(&user_data, "traffic-counter-123").unwrap();
        let script = dir.path().join("probe");
        fs::write(&script, r##"#!/bin/sh
IFS= read -r data || exit 2
case "$data" in
  *'"kind":"fixed"'*) case "$data" in *synthetic-one*|*synthetic-two*) ;; *) exit 3;; esac
    printf '%s\n' '{"ok":true,"exit_ip":"8.8.8.8","country":"US","https_ms":1,"doh_ms":2}';;
  *'"kind":"vmess"'*) case "$data" in *11111111-2222-3333-4444-555555555555*) ;; *) exit 4;; esac
    printf '%s\n' '{"ok":true,"exit_ip":"8.8.8.8","country":"US","https_ms":1,"doh_ms":2,"server_ip":"8.8.4.4"}';;
  *) exit 5;;
esac
"##).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let launcher = Launcher::fixture(script, uid, gid);
        let input = "1.1.1.1:80:fixture:synthetic-one\n8.8.8.8:81:fixture:synthetic-two";
        let first = fixed(&store, &launcher, input, Protocol::Socks, "fixture").unwrap();
        assert_eq!(first.entries().len(), 2);
        assert!(!serde_json::to_string(first.entries())
            .unwrap()
            .contains("synthetic-one"));
        assert_eq!(
            first.confirm("wrong", &store, &mut HooksFixture),
            Err(PreviewError::Invalid)
        );
        assert!(!etc.join("pool").exists());
        let stale = fixed(&store, &launcher, input, Protocol::Socks, "fixture").unwrap();
        let stale_id = stale.id().to_owned();
        fs::write(
            etc.join("settings"),
            serde_json::to_vec(&json!({"external":true})).unwrap(),
        )
        .unwrap();
        assert_eq!(
            stale.confirm(&stale_id, &store, &mut HooksFixture),
            Err(PreviewError::Conflict)
        );
        assert!(!etc.join("pool").exists());
        fs::write(etc.join("settings"), serde_json::to_vec(&settings).unwrap()).unwrap();
        let mut expired = fixed(&store, &launcher, input, Protocol::Socks, "fixture").unwrap();
        let expired_id = expired.id().to_owned();
        expired.deadline = Instant::now() - Duration::from_secs(1);
        assert_eq!(
            expired.confirm(&expired_id, &store, &mut HooksFixture),
            Err(PreviewError::Expired)
        );
        let prepared = fixed(&store, &launcher, input, Protocol::Socks, "fixture").unwrap();
        let id = prepared.id().to_owned();
        prepared.confirm(&id, &store, &mut HooksFixture).unwrap();
        assert_eq!(
            fs::read_to_string(&user_data).unwrap(),
            "traffic-counter-123"
        );
        let before = store.snapshot().unwrap();
        let invalid = vec!["residential-27".into(), "residential-99".into()];
        assert!(matches!(
            delete_many_cancellable(&store, &invalid, 1000, None),
            Err(PreviewError::Invalid)
        ));
        assert_eq!(store.snapshot().unwrap(), before);
        let duplicate = vec!["residential-27".into(), "residential-27".into()];
        assert!(matches!(
            delete_many_cancellable(&store, &duplicate, 1000, None),
            Err(PreviewError::Invalid)
        ));
        assert_eq!(store.snapshot().unwrap(), before);
        let batch_tags = vec!["residential-27".into(), "residential-28".into()];
        let batch = delete_many_cancellable(&store, &batch_tags, 1000, None).unwrap();
        assert_eq!(batch.entries().len(), 2);
        assert!(!serde_json::to_string(batch.entries())
            .unwrap()
            .contains("synthetic-"));
        assert_eq!(store.snapshot().unwrap(), before);
        let id = batch.id().to_owned();
        batch.confirm(&id, &store, &mut HooksFixture).unwrap();
        let pool: Value = serde_json::from_slice(&fs::read(etc.join("pool")).unwrap()).unwrap();
        assert!(pool["proxies"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["deleted_at"] == 1000 && item["enabled"] == false));
        let settings_after: Value =
            serde_json::from_slice(&fs::read(etc.join("settings")).unwrap()).unwrap();
        assert!(settings_after["residential_exits"]
            .as_array()
            .unwrap()
            .is_empty());
        for name in ["core", "monitor", "locations"] {
            let content = fs::read_to_string(etc.join(name)).unwrap();
            for tag in &batch_tags {
                assert!(!content.contains(tag), "deleted tag remains in {name}");
            }
        }
        for tag in &batch_tags {
            for action in [Operation::Restore, Operation::Enable] {
                let restore = manage(&store, &launcher, tag, action).unwrap();
                let id = restore.id().to_owned();
                restore.confirm(&id, &store, &mut HooksFixture).unwrap();
            }
        }

        let saved: Value = serde_json::from_slice(&fs::read(etc.join("core")).unwrap()).unwrap();
        assert_eq!(saved["inbounds"][0], core["inbounds"][0]);
        assert_eq!(
            saved["outbounds"][2]["settings"]["servers"][0]["users"][0]["pass"],
            "synthetic-one"
        );
        let changes = json!({"password":"synthetic-two","label":"edited"});
        let edit = manage(
            &store,
            &launcher,
            "residential-27",
            Operation::Edit { changes: &changes },
        )
        .unwrap();
        let id = edit.id().to_owned();
        edit.confirm(&id, &store, &mut HooksFixture).unwrap();
        let pool: Value = serde_json::from_slice(&fs::read(etc.join("pool")).unwrap()).unwrap();
        assert_eq!(pool["proxies"][0]["password"], "synthetic-two");
        for operation in [
            Operation::Disable,
            Operation::Enable,
            Operation::Delete { now: 1700000000 },
            Operation::Restore,
            Operation::Enable,
        ] {
            let prepared = manage(&store, &launcher, "residential-27", operation).unwrap();
            let id = prepared.id().to_owned();
            prepared.confirm(&id, &store, &mut HooksFixture).unwrap();
        }
        let pool: Value = serde_json::from_slice(&fs::read(etc.join("pool")).unwrap()).unwrap();
        assert_eq!(pool["proxies"][0]["enabled"], true);
        assert_eq!(pool["proxies"][0]["deleted_at"], 0);
        let share = json!({"v":"2","add":"proxy.example.com","port":"443","id":"11111111-2222-3333-4444-555555555555", "net":"ws","path":"/fixture"});
        let link = format!(
            "vmess://{}",
            STANDARD.encode(serde_json::to_vec(&share).unwrap())
        );
        let prepared = vmess(&store, &launcher, &link, "fixture").unwrap();
        let id = prepared.id().to_owned();
        prepared.confirm(&id, &store, &mut HooksFixture).unwrap();
        let saved: Value = serde_json::from_slice(&fs::read(etc.join("core")).unwrap()).unwrap();
        assert_eq!(
            saved["outbounds"][4]["settings"]["vnext"][0]["address"],
            "8.8.4.4"
        );
        let changes = json!({"path":"/edited"});
        let edit = manage(
            &store,
            &launcher,
            "residential-29",
            Operation::Edit { changes: &changes },
        )
        .unwrap();
        let id = edit.id().to_owned();
        edit.confirm(&id, &store, &mut HooksFixture).unwrap();
        let pool: Value = serde_json::from_slice(&fs::read(etc.join("pool")).unwrap()).unwrap();
        assert_eq!(pool["proxies"][2]["path"], "/edited");
        assert_eq!(pool["proxies"][2]["server_ip"], "8.8.4.4");
        let prepared = entrance(&store, Entrance::Vmess).unwrap();
        let id = prepared.id().to_owned();
        prepared.confirm(&id, &store, &mut HooksFixture).unwrap();
        let mut new_settings: Value =
            serde_json::from_slice(&fs::read(etc.join("settings")).unwrap()).unwrap();
        let mut new_core: Value =
            serde_json::from_slice(&fs::read(etc.join("core")).unwrap()).unwrap();
        assert!(new_core["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["tag"] == "vmess"));
        new_settings["hysteria2_port"] = json!(1443);
        new_core["inbounds"]
            .as_array_mut()
            .unwrap()
            .push(json!({"tag":"hysteria2","port":1443,"protocol":"hysteria"}));
        fs::write(
            etc.join("settings"),
            serde_json::to_vec(&new_settings).unwrap(),
        )
        .unwrap();
        fs::write(etc.join("core"), serde_json::to_vec(&new_core).unwrap()).unwrap();
        let prepared = entrance(&store, Entrance::AllResidentialHysteria).unwrap();
        let id = prepared.id().to_owned();
        prepared.confirm(&id, &store, &mut HooksFixture).unwrap();
        let pool: Value = serde_json::from_slice(&fs::read(etc.join("pool")).unwrap()).unwrap();
        assert!(pool["proxies"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["entry"]["hysteria2"] == true));
        assert_eq!(
            fs::read_to_string(&user_data).unwrap(),
            "traffic-counter-123"
        );
        // Consume encrypted legacy-format requests in order. A mismatched
        // confirmation consumes the preview; a fresh preview may be applied
        // once with fixture hooks. No real service is stopped by this test.
        let inbox = dir.path().join("inbox");
        let queue_state = dir.path().join("queue-state");
        for path in [&inbox, &queue_state] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = [42u8; 32];
        let queue = crate::queue::Queue::open(&inbox, &queue_state, None, key).unwrap();
        let claim = |payload: Value| {
            let plain = Zeroizing::new(serde_json::to_vec(&payload).unwrap());
            let cipher =
                xcli_auth_compat::seal_xgb1(&plain, &key, b"xcli:proxy-import:request:v1").unwrap();
            fs::write(inbox.join("request.xgb"), cipher).unwrap();
            fs::set_permissions(inbox.join("request.xgb"), fs::Permissions::from_mode(0o600))
                .unwrap();
            queue.claim(1000).unwrap().unwrap()
        };
        let mut coordinator = crate::coordinator::Coordinator::default();
        let a = "a".repeat(32);
        let manage_request = claim(json!({"id":a,"requested_at":1000,"action":"manage",
            "operation":"disable","tag":"residential-27"}));
        let report = coordinator
            .handle(&manage_request, &store, &launcher, &mut HooksFixture, 1000)
            .unwrap();
        assert_eq!(report["status"], "ready");
        assert!(!report.to_string().contains("synthetic-one"));
        assert!(queue.claim(1000).unwrap().is_none());
        let wrong = claim(
            json!({"id":"b".repeat(32),"requested_at":1000,"action":"apply","preview_id":"f".repeat(32)}),
        );
        assert_eq!(
            coordinator.handle(&wrong, &store, &launcher, &mut HooksFixture, 1000),
            Err(PreviewError::Invalid)
        );
        let consumed =
            claim(json!({"id":"c".repeat(32),"requested_at":1000,"action":"apply","preview_id":a}));
        assert_eq!(
            coordinator.handle(&consumed, &store, &launcher, &mut HooksFixture, 1000),
            Err(PreviewError::Expired)
        );
        let d = "d".repeat(32);
        let fresh = claim(json!({"id":d,"requested_at":1000,"action":"manage",
            "operation":"disable","tag":"residential-27"}));
        assert_eq!(
            coordinator
                .handle(&fresh, &store, &launcher, &mut HooksFixture, 1000)
                .unwrap()["status"],
            "ready"
        );
        let apply =
            claim(json!({"id":"e".repeat(32),"requested_at":1000,"action":"apply","preview_id":d}));
        assert_eq!(
            coordinator
                .handle(&apply, &store, &launcher, &mut HooksFixture, 1000)
                .unwrap()["status"],
            "complete"
        );
        let pool: Value = serde_json::from_slice(&fs::read(etc.join("pool")).unwrap()).unwrap();
        assert_eq!(pool["proxies"][0]["enabled"], false);
        let before_batch = store.snapshot().unwrap();
        let batch_id = "1".repeat(32);
        let batch = claim(json!({"id":batch_id,"requested_at":1000,"action":"manage",
            "operation":"delete","tags":["residential-27","residential-28"]}));
        let batch_report = coordinator
            .handle(&batch, &store, &launcher, &mut HooksFixture, 1000)
            .unwrap();
        assert_eq!(batch_report["status"], "ready");
        assert_eq!(batch_report["rows"].as_array().unwrap().len(), 2);
        assert_eq!(store.snapshot().unwrap(), before_batch);
        let confirm = claim(
            json!({"id":"2".repeat(32),"requested_at":1000,"action":"apply","preview_id":batch_id}),
        );
        assert_eq!(
            coordinator
                .handle(&confirm, &store, &launcher, &mut HooksFixture, 1000)
                .unwrap()["status"],
            "complete"
        );
        let pool: Value = serde_json::from_slice(&fs::read(etc.join("pool")).unwrap()).unwrap();
        assert!(pool["proxies"]
            .as_array()
            .unwrap()
            .iter()
            .take(2)
            .all(|item| item["deleted_at"] == 1000));
        for tag in ["residential-27", "residential-28"] {
            let restore = manage(&store, &launcher, tag, Operation::Restore).unwrap();
            let id = restore.id().to_owned();
            restore.confirm(&id, &store, &mut HooksFixture).unwrap();
        }
        let enable = manage(&store, &launcher, "residential-28", Operation::Enable).unwrap();
        let id = enable.id().to_owned();
        enable.confirm(&id, &store, &mut HooksFixture).unwrap();
        assert_eq!(
            fs::read_to_string(&user_data).unwrap(),
            "traffic-counter-123"
        );
        let prepared = crate::request::prepare(
            &json!({"action":"preview","protocol":"socks","label":"fixture",
            "text":"9.9.9.9:82:fixture:synthetic-two"}),
            1000,
            &key,
            3,
        )
        .unwrap();
        let f = prepared.id().to_owned();
        let db_path = dir.path().join("audit.sqlite");
        let db = rusqlite::Connection::open(&db_path).unwrap();
        db.execute_batch("CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);").unwrap();
        let mut audit = crate::publisher::audit::SqliteAuditor::open(&db_path).unwrap();
        let publisher = crate::publisher::Publisher::open(&inbox, key).unwrap();
        publisher
            .submit(
                &prepared,
                &json!({"status":"complete","updated":1000,"id":"2".repeat(32)}),
                1000,
                &mut audit,
            )
            .unwrap();
        let add = queue.claim(1000).unwrap().unwrap();
        let report = coordinator
            .handle(&add, &store, &launcher, &mut HooksFixture, 1000)
            .unwrap();
        assert_eq!(report["status"], "ready");
        assert_eq!(report["rows"].as_array().unwrap().len(), 1);
        assert!(!report.to_string().contains("synthetic-two"));
        let prepared =
            crate::request::prepare(&json!({"action":"apply","preview_id":f}), 1000, &key, 3)
                .unwrap();
        publisher
            .submit(
                &prepared,
                &json!({"status":"ready","updated":1000,"id":f,"expires":1900}),
                1000,
                &mut audit,
            )
            .unwrap();
        let add_apply = queue.claim(1000).unwrap().unwrap();
        assert_eq!(
            coordinator
                .handle(&add_apply, &store, &launcher, &mut HooksFixture, 1000)
                .unwrap()["status"],
            "complete"
        );
        let pool: Value = serde_json::from_slice(&fs::read(etc.join("pool")).unwrap()).unwrap();
        assert_eq!(pool["proxies"].as_array().unwrap().len(), 4);
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM events WHERE action='proxy_import_requested'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            2
        );

        // A preview-only worker maintains a trusted heartbeat, consumes the
        // encrypted queue and refuses apply before any configuration write.
        let worker_inbox = dir.path().join("worker-inbox");
        let worker_state = dir.path().join("worker-state");
        for path in [&worker_inbox, &worker_state] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let report_dir = dir.path().join("worker-report");
        fs::create_dir(&report_dir).unwrap();
        fs::set_permissions(&report_dir, fs::Permissions::from_mode(0o750)).unwrap();
        let owner = unsafe { libc::geteuid() };
        let group = unsafe { libc::getegid() };
        let writer = crate::report::ReportChannel::open(&report_dir, owner, group).unwrap();
        let reader = crate::report::ReportChannel::open(&report_dir, owner, group).unwrap();
        let worker_queue =
            crate::queue::Queue::open(&worker_inbox, &worker_state, None, key).unwrap();
        let worker_publisher = crate::publisher::Publisher::open(&worker_inbox, key).unwrap();
        let before_core = fs::read(etc.join("core")).unwrap();
        let before_pool = fs::read(etc.join("pool")).unwrap();
        let worker = crate::runner::PreviewRunner::new(worker_queue, store, launcher, writer);
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let signal = stop.clone();
        let thread = std::thread::spawn(move || worker.run(signal));
        let mut cancel_started = None;
        let mut cancelled_id = String::new();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let now = || {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
            };
            let wait = |wanted: &str| {
                let deadline = Instant::now() + Duration::from_secs(15);
                loop {
                    if let Ok(value) = reader.read(now()) {
                        if value["status"] == wanted {
                            break value;
                        }
                    }
                    assert!(
                        Instant::now() < deadline,
                        "worker status did not become {wanted}"
                    );
                    std::thread::sleep(Duration::from_millis(50));
                }
            };
            let idle = wait("idle");
            let rival = crate::queue::Queue::open(&worker_inbox, &worker_state, None, key).unwrap();
            assert!(
                rival.worker_lock().is_err(),
                "two workers acquired the same state lock"
            );
            let preview = crate::request::prepare(
                &json!({"action":"preview","protocol":"socks","label":"fixture",
                "text":"9.9.9.9:84:fixture:synthetic-one"}),
                now(),
                &key,
                4,
            )
            .unwrap();
            worker_publisher
                .submit(&preview, &idle, now(), &mut audit)
                .unwrap();
            let ready = wait("ready");
            assert_eq!(ready["id"], preview.id());
            assert_eq!(ready["rows"].as_array().unwrap().len(), 1);
            assert_eq!(ready["rows"][0]["exit_ip"], "8.8.8.8");
            assert!(!ready.to_string().contains("synthetic-one"));
            assert!(!fs::read_to_string(report_dir.join("report.json"))
                .unwrap()
                .contains("synthetic-one"));
            let apply = crate::request::prepare(
                &json!({"action":"apply","preview_id":preview.id()}),
                now(),
                &key,
                4,
            )
            .unwrap();
            worker_publisher
                .submit(&apply, &ready, now(), &mut audit)
                .unwrap();
            let failed = wait("failed");
            assert_eq!(failed["id"], apply.id());
            assert_eq!(failed["reason"], "apply_disabled");
            assert!(failed.get("rows").is_none());
            assert_eq!(fs::read(etc.join("core")).unwrap(), before_core);
            assert_eq!(fs::read(etc.join("pool")).unwrap(), before_pool);
            fs::write(dir.path().join("probe"), b"#!/bin/sh\nexit 1\n").unwrap();
            let bad = crate::request::prepare(
                &json!({"action":"preview","protocol":"socks","label":"fixture",
                "text":"9.9.9.9:86:fixture:synthetic-one"}),
                now(),
                &key,
                4,
            )
            .unwrap();
            worker_publisher
                .submit(&bad, &failed, now(), &mut audit)
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let failed = loop {
                if let Ok(value) = reader.read(now()) {
                    if value["status"] == "failed" && value["id"] == bad.id() {
                        break value;
                    }
                }
                assert!(Instant::now() < deadline, "failed probe was not reported");
                std::thread::sleep(Duration::from_millis(20));
            };
            assert_eq!(failed["reason"], "probe");
            assert!(!failed.to_string().contains("synthetic-one"));
            let marker_dir = dir.path().join("worker-cancel");
            fs::create_dir(&marker_dir).unwrap();
            fs::set_permissions(&marker_dir, fs::Permissions::from_mode(0o777)).unwrap();
            let marker = marker_dir.join("started");
            let name = marker.to_str().unwrap();
            assert!(!name.contains('\''));
            fs::write(
                dir.path().join("probe"),
                format!("#!/bin/sh\nIFS= read -r data\nprintf started > '{name}'\nexec sleep 60\n"),
            )
            .unwrap();
            let slow = crate::request::prepare(
                &json!({"action":"preview","protocol":"socks","label":"fixture",
                "text":"9.9.9.9:85:fixture:synthetic-one"}),
                now(),
                &key,
                4,
            )
            .unwrap();
            cancelled_id = slow.id().to_owned();
            worker_publisher
                .submit(&slow, &failed, now(), &mut audit)
                .unwrap();
            let verifying = wait("verifying");
            assert_eq!(verifying["id"], slow.id());
            let deadline = Instant::now() + Duration::from_secs(5);
            while !marker.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(marker.exists(), "slow fixture probe did not start");
            cancel_started = Some(Instant::now());
            stop.store(true, std::sync::atomic::Ordering::Release);
        }));
        stop.store(true, std::sync::atomic::Ordering::Release);
        assert!(thread.join().unwrap().is_ok());
        if let Err(error) = outcome {
            std::panic::resume_unwind(error);
        }
        assert!(cancel_started.unwrap().elapsed() < Duration::from_secs(3));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let stopped = reader.read(now).unwrap();
        assert_eq!(stopped["status"], "unavailable");
        assert_eq!(stopped["id"], cancelled_id);
        let paths: BTreeMap<String, PathBuf> =
            ["settings", "core", "monitor", "nginx", "locations", "pool"]
                .into_iter()
                .map(|key| (key.to_owned(), etc.join(key)))
                .collect();
        let store = Store::open(&journal, &journal.join("update.lock"), paths).unwrap();
        let launcher = Launcher::fixture(dir.path().join("probe"), uid, gid);
        let queue = crate::queue::Queue::open(&worker_inbox, &worker_state, None, key).unwrap();
        let writer = crate::report::ReportChannel::open(&report_dir, owner, group).unwrap();
        let worker = crate::runner::PreviewRunner::new(queue, store, launcher, writer);
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let signal = stop.clone();
        let thread = std::thread::spawn(move || worker.run(signal));
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut restarted = None;
        while Instant::now() < deadline {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            if let Ok(value) = reader.read(now) {
                if value["status"] == "failed" {
                    restarted = Some(value);
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        stop.store(true, std::sync::atomic::Ordering::Release);
        assert!(thread.join().unwrap().is_ok());
        let restarted = restarted.unwrap();
        assert_eq!(restarted["id"], cancelled_id);
        assert_eq!(restarted["reason"], "interrupted");
    }
}
