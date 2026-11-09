//! Per-item probe progress and an in-memory, selection-bound import preview.
//! Credentials and verified results never enter the public status channel.
use crate::config::{add_fixed, add_vmess, import_inventory, Verified, VerifiedVmess};
use crate::journal::{Hooks, Store};
use crate::launcher::Launcher;
use crate::preview::{self, PreviewError};
use crate::probe::{ProbeError, ProbeResult, Protocol};
use crate::vmess::{parse_links, VmessProxy};
use crate::vmess_probe::VmessProbeResult;
use crate::{parse_fixed, ImportError, Proxy};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

enum Input {
    Fixed(Proxy, Protocol),
    Vmess(VmessProxy),
}
impl Input {
    fn peer(&self) -> (String, u16) {
        match self {
            Self::Fixed(proxy, _) => (proxy.address.to_string(), proxy.port),
            Self::Vmess(proxy) => (proxy.address().to_owned(), proxy.port()),
        }
    }
    fn probe(&self, launcher: &Launcher, stop: Option<&AtomicBool>) -> Result<Outcome, ProbeError> {
        match self {
            Self::Fixed(proxy, protocol) => launcher
                .fixed_cancellable(proxy, *protocol, stop)
                .map(Outcome::Fixed),
            Self::Vmess(proxy) => launcher.vmess_cancellable(proxy, stop).map(Outcome::Vmess),
        }
    }
}
enum Outcome {
    Fixed(ProbeResult),
    Vmess(VmessProbeResult),
}
impl Outcome {
    fn observed(&self) -> &ProbeResult {
        match self {
            Self::Fixed(result) => result,
            Self::Vmess(result) => &result.observed,
        }
    }
}
fn input_error(error: ImportError, protocol: &str) -> &'static str {
    if protocol == "vmess" {
        return "invalid_link";
    }
    match error.0 {
        "每行格式应为 HOST:PORT:USER:PASS" => "invalid_format",
        "仅支持公网 IPv4 地址" => "invalid_address",
        "代理端口不正确" => "invalid_port",
        "账号或密码格式不正确" => "invalid_credentials",
        _ => "invalid_format",
    }
}
fn parse_input(line: &str, protocol: &str) -> Result<Input, ImportError> {
    match protocol {
        "socks" | "http" => {
            let mut proxies = parse_fixed(line)?;
            if proxies.len() != 1 {
                return Err(ImportError("每行格式应为 HOST:PORT:USER:PASS"));
            }
            Ok(Input::Fixed(
                proxies.remove(0),
                if protocol == "socks" {
                    Protocol::Socks
                } else {
                    Protocol::Http
                },
            ))
        }
        "vmess" => {
            let mut proxies = parse_links(line)?;
            if proxies.len() != 1 {
                return Err(ImportError("VMess 链接无效"));
            }
            Ok(Input::Vmess(proxies.remove(0)))
        }
        _ => Err(ImportError("不支持的代理协议")),
    }
}

pub(crate) struct BatchReady {
    deadline: Instant,
    snapshot: BTreeMap<String, String>,
    label: String,
    inputs: Vec<Option<Input>>,
    outcomes: Vec<Option<Outcome>>,
    rows: Vec<Value>,
    available: usize,
}
impl BatchReady {
    pub(crate) fn rows(&self) -> &[Value] {
        &self.rows
    }
    pub(crate) fn available(&self) -> usize {
        self.available
    }
    pub(crate) fn confirm(
        self,
        selected: &[usize],
        store: &Store,
        hooks: &mut dyn Hooks,
    ) -> Result<Vec<Value>, PreviewError> {
        if Instant::now() >= self.deadline {
            return Err(PreviewError::Expired);
        }
        if selected.is_empty() || selected.len() > self.available || selected.len() > 20 {
            return Err(PreviewError::Invalid);
        }
        let indices: BTreeSet<_> = selected.iter().copied().collect();
        if indices.len() != selected.len()
            || indices.iter().any(|index| {
                *index == 0 || *index > self.inputs.len() || self.outcomes[*index - 1].is_none()
            })
        {
            return Err(PreviewError::Invalid);
        }
        let (files, snapshot) = store.load()?;
        if snapshot != self.snapshot {
            return Err(PreviewError::Conflict);
        }
        let fixed = matches!(
            self.inputs[indices
                .iter()
                .next()
                .copied()
                .ok_or(PreviewError::Invalid)?
                - 1],
            Some(Input::Fixed(_, _))
        );
        let (files, entries) = if fixed {
            let mut verified = Vec::new();
            for index in &indices {
                match (&self.inputs[*index - 1], &self.outcomes[*index - 1]) {
                    (Some(Input::Fixed(proxy, protocol)), Some(Outcome::Fixed(result))) => verified
                        .push(Verified {
                            proxy,
                            protocol: *protocol,
                            result,
                        }),
                    _ => return Err(PreviewError::Invalid),
                }
            }
            add_fixed(files, &verified, &self.label).map_err(|_| PreviewError::Invalid)?
        } else {
            let mut verified = Vec::new();
            for index in &indices {
                match (&self.inputs[*index - 1], &self.outcomes[*index - 1]) {
                    (Some(Input::Vmess(proxy)), Some(Outcome::Vmess(result))) => {
                        verified.push(VerifiedVmess { proxy, result })
                    }
                    _ => return Err(PreviewError::Invalid),
                }
            }
            add_vmess(files, &verified, &self.label).map_err(|_| PreviewError::Invalid)?
        };
        let ready = preview::ready(store, snapshot, files, entries)?;
        let entries = ready.entries().to_vec();
        let id = ready.id().to_owned();
        ready.confirm(&id, store, hooks)?;
        Ok(entries)
    }
}

pub(crate) fn detect(
    store: &Store,
    launcher: &Launcher,
    protocol: &str,
    label: &str,
    text: &str,
    stop: Option<&AtomicBool>,
    publish: &dyn Fn(&[Value], usize) -> Result<(), PreviewError>,
) -> Result<BatchReady, PreviewError> {
    detect_with(
        store,
        protocol,
        label,
        text,
        stop,
        publish,
        &|input, stop| input.probe(launcher, stop),
    )
}

fn detect_with(
    store: &Store,
    protocol: &str,
    label: &str,
    text: &str,
    stop: Option<&AtomicBool>,
    publish: &dyn Fn(&[Value], usize) -> Result<(), PreviewError>,
    probe: &(dyn Fn(&Input, Option<&AtomicBool>) -> Result<Outcome, ProbeError> + Sync),
) -> Result<BatchReady, PreviewError> {
    if stop.is_some_and(|stop| stop.load(Ordering::Acquire))
        || !["socks", "http", "vmess"].contains(&protocol)
        || label.is_empty()
        || label.chars().count() > 30
        || label.chars().any(|c| c < ' ')
        || text.is_empty()
        || text.len() > 12_000
    {
        return Err(PreviewError::Invalid);
    }
    let lines: Vec<_> = text
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .collect();
    if !(1..=20).contains(&lines.len()) {
        return Err(PreviewError::Invalid);
    }
    let (files, snapshot) = store.load()?;
    let (mut peers, available) = import_inventory(&files).map_err(|_| PreviewError::Invalid)?;
    drop(files);
    let mut rows = Vec::with_capacity(lines.len());
    let mut inputs = Vec::with_capacity(lines.len());
    let mut outcomes: Vec<Option<Outcome>> = (0..lines.len()).map(|_| None).collect();
    for (position, (line_number, line)) in lines.iter().enumerate() {
        let mut row = json!({"index":position + 1,"line":line_number + 1});
        let input = match parse_input(line, protocol) {
            Ok(input) => {
                let (address, port) = input.peer();
                row["address"] = json!(address);
                row["port"] = json!(port);
                if peers.insert((address, port)) {
                    row["state"] = json!("waiting");
                    Some(input)
                } else {
                    row["state"] = json!("failed");
                    row["reason"] = json!("duplicate");
                    None
                }
            }
            Err(error) => {
                row["state"] = json!("failed");
                row["reason"] = json!(input_error(error, protocol));
                None
            }
        };
        rows.push(row);
        inputs.push(input);
    }
    publish(&rows, available)?;
    let candidates: Vec<_> = (0..inputs.len())
        .filter(|index| inputs[*index].is_some())
        .collect();
    for chunk in candidates.chunks(4) {
        if stop.is_some_and(|stop| stop.load(Ordering::Acquire)) {
            return Err(PreviewError::Probe);
        }
        for index in chunk {
            rows[*index]["state"] = json!("testing");
        }
        publish(&rows, available)?;
        std::thread::scope(|scope| -> Result<(), PreviewError> {
            let (sender, receiver) = mpsc::channel();
            for index in chunk {
                let index = *index;
                let input = inputs[index].as_ref().ok_or(PreviewError::Invalid)?;
                let sender = sender.clone();
                scope.spawn(move || {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        probe(input, stop)
                    }))
                    .unwrap_or(Err(ProbeError::Unavailable));
                    let _ = sender.send((index, result));
                });
            }
            drop(sender);
            for (index, result) in receiver {
                match result {
                    Ok(result) => {
                        let observed = result.observed();
                        rows[index]["state"] = json!("success");
                        rows[index]["exit_ip"] = json!(observed.exit_ip.to_string());
                        rows[index]["country"] = json!(observed.country);
                        rows[index]["https_ms"] = json!(observed.https_ms);
                        rows[index]["doh_ms"] = json!(observed.doh_ms);
                        outcomes[index] = Some(result);
                    }
                    Err(error) => {
                        rows[index]["state"] = json!("failed");
                        rows[index]["reason"] = json!(error.code());
                    }
                }
                publish(&rows, available)?;
            }
            Ok(())
        })?;
        for index in chunk {
            if outcomes[*index].is_none() {
                inputs[*index] = None;
            }
        }
    }
    if stop.is_some_and(|stop| stop.load(Ordering::Acquire)) {
        return Err(PreviewError::Probe);
    }
    if store.snapshot()? != snapshot {
        return Err(PreviewError::Conflict);
    }
    Ok(BatchReady {
        deadline: Instant::now() + Duration::from_secs(900),
        snapshot,
        label: label.to_owned(),
        inputs,
        outcomes,
        rows,
        available,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::JournalError;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::fs;
    use std::net::Ipv4Addr;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    #[derive(Default)]
    pub(super) struct FixtureHooks {
        stops: usize,
    }
    impl Hooks for FixtureHooks {
        fn validate(&mut self, _: &Path) -> Result<(), JournalError> {
            Ok(())
        }
        fn stop(&mut self) -> Result<(), JournalError> {
            self.stops += 1;
            Ok(())
        }
        fn start_and_check(&mut self) -> Result<(), JournalError> {
            Ok(())
        }
    }
    pub(super) fn fixture() -> (tempfile::TempDir, Store, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("journal");
        let etc = dir.path().join("etc");
        fs::create_dir(&journal).unwrap();
        fs::create_dir(&etc).unwrap();
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&etc, fs::Permissions::from_mode(0o700)).unwrap();
        let settings =
            json!({"public_ip":"8.8.8.8","ws_path":"/connect/fixture","residential_exits":[]});
        let core = json!({"inbounds":[{"tag":"reality","port":10443}],
            "outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"blocked","protocol":"blackhole"}],
            "routing":{"rules":[{"inboundTag":["reality"],"outboundTag":"direct"}]}});
        let monitor = json!({"residential_exits":[]});
        for (name, contents) in [
            ("settings", serde_json::to_vec(&settings).unwrap()),
            ("core", serde_json::to_vec(&core).unwrap()),
            ("monitor", serde_json::to_vec(&monitor).unwrap()),
            (
                "nginx",
                b"server { location = /connect/fixture {} }".to_vec(),
            ),
        ] {
            fs::write(etc.join(name), contents).unwrap();
            fs::set_permissions(etc.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let paths: BTreeMap<String, PathBuf> =
            ["settings", "core", "monitor", "nginx", "locations", "pool"]
                .into_iter()
                .map(|key| (key.to_owned(), etc.join(key)))
                .collect();
        let store = Store::open(&journal, &journal.join("update.lock"), paths).unwrap();
        (dir, store, etc)
    }
    fn fake(input: &Input, _: Option<&AtomicBool>) -> Result<Outcome, ProbeError> {
        let (address, _) = input.peer();
        if address == "1.1.1.1" {
            std::thread::sleep(Duration::from_millis(200));
        }
        if address == "8.8.8.8" {
            return Err(ProbeError::InvalidDns);
        }
        let observed = ProbeResult {
            exit_ip: Ipv4Addr::new(8, 8, 4, 4),
            country: "US".into(),
            https_ms: 5,
            doh_ms: 7,
        };
        Ok(match input {
            Input::Fixed(_, _) => Outcome::Fixed(observed),
            Input::Vmess(_) => Outcome::Vmess(VmessProbeResult {
                server_ip: Ipv4Addr::new(8, 8, 4, 4),
                observed,
            }),
        })
    }
    #[test]
    fn mixed_progress_and_selected_apply_are_bound_to_the_original_snapshot() {
        let (_dir, store, etc) = fixture();
        let text="\n1.1.1.1:80:fixture:secret-one\n8.8.8.8:81:fixture:secret-two\nnot-a-proxy\n9.9.9.9:82:fixture:secret-three\n1.1.1.1:80:fixture:secret-duplicate\n127.0.0.1:83:u:secret-private";
        let events = Mutex::new(Vec::<Vec<Value>>::new());
        let publish = |rows: &[Value], available: usize| {
            assert_eq!(available, 40);
            events.lock().unwrap().push(rows.to_vec());
            Ok(())
        };
        let before = store.snapshot().unwrap();
        let batch = detect_with(&store, "socks", "fixture", text, None, &publish, &fake).unwrap();
        assert_eq!(batch.rows().len(), 6);
        assert_eq!(batch.rows()[0]["line"], 2);
        assert_eq!(batch.rows()[0]["state"], "success");
        assert_eq!(batch.rows()[1]["reason"], "invalid_dns");
        assert_eq!(batch.rows()[2]["reason"], "invalid_format");
        assert_eq!(batch.rows()[3]["state"], "success");
        assert_eq!(batch.rows()[4]["reason"], "duplicate");
        assert_eq!(batch.rows()[5]["reason"], "invalid_address");
        assert!(!serde_json::to_string(batch.rows())
            .unwrap()
            .contains("secret"));
        assert!(events
            .lock()
            .unwrap()
            .iter()
            .any(|rows| rows[3]["state"] == "success" && rows[0]["state"] == "testing"));
        assert_eq!(store.snapshot().unwrap(), before);
        assert!(matches!(
            batch.confirm(&[1, 2], &store, &mut FixtureHooks::default()),
            Err(PreviewError::Invalid)
        ));
        assert_eq!(store.snapshot().unwrap(), before);
        let batch = detect_with(
            &store,
            "socks",
            "fixture",
            text,
            None,
            &|_, _| Ok(()),
            &fake,
        )
        .unwrap();
        let mut hooks = FixtureHooks::default();
        let applied = batch.confirm(&[4], &store, &mut hooks).unwrap();
        assert_eq!(hooks.stops, 1);
        assert_eq!(applied.len(), 1);
        let pool: Value = serde_json::from_slice(&fs::read(etc.join("pool")).unwrap()).unwrap();
        assert_eq!(pool["proxies"].as_array().unwrap().len(), 1);
        assert_eq!(pool["proxies"][0]["address"], "9.9.9.9");
        let duplicate = detect_with(
            &store,
            "socks",
            "fixture",
            "9.9.9.9:82:fixture:secret-three",
            None,
            &|_, _| Ok(()),
            &fake,
        )
        .unwrap();
        assert_eq!(duplicate.rows()[0]["reason"], "duplicate");
        let stale = detect_with(
            &store,
            "socks",
            "fixture",
            "4.4.4.4:83:fixture:secret-four",
            None,
            &|_, _| Ok(()),
            &fake,
        )
        .unwrap();
        let mut settings: Value =
            serde_json::from_slice(&fs::read(etc.join("settings")).unwrap()).unwrap();
        settings["intervening"] = json!(true);
        fs::write(etc.join("settings"), serde_json::to_vec(&settings).unwrap()).unwrap();
        assert!(matches!(
            stale.confirm(&[1], &store, &mut FixtureHooks::default()),
            Err(PreviewError::Conflict)
        ));
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(etc.join("settings")).unwrap()).unwrap()
                ["intervening"],
            true
        );
        let share = json!({"v":"2","add":"proxy.example.com","port":"443","id":"11111111-2222-3333-4444-555555555555","net":"ws","path":"/fixture"});
        let link = format!(
            "vmess://{}",
            STANDARD.encode(serde_json::to_vec(&share).unwrap())
        );
        let mixed = format!("{link}\nnot-a-vmess-link");
        let vmess = detect_with(
            &store,
            "vmess",
            "fixture",
            &mixed,
            None,
            &|_, _| Ok(()),
            &fake,
        )
        .unwrap();
        assert_eq!(vmess.rows()[0]["state"], "success");
        assert_eq!(vmess.rows()[1]["reason"], "invalid_link");
        assert!(!serde_json::to_string(vmess.rows())
            .unwrap()
            .contains("11111111-2222"));
        assert_eq!(
            vmess
                .confirm(&[1], &store, &mut FixtureHooks::default())
                .unwrap()
                .len(),
            1
        );
        let pool: Value = serde_json::from_slice(&fs::read(etc.join("pool")).unwrap()).unwrap();
        assert_eq!(pool["proxies"][1]["protocol"], "vmess");
        let http = detect_with(
            &store,
            "http",
            "fixture",
            "4.4.4.4:84:fixture:secret-http",
            None,
            &|_, _| Ok(()),
            &fake,
        )
        .unwrap();
        assert_eq!(http.available(), 38);
        assert_eq!(http.rows()[0]["state"], "success");
        assert_eq!(
            http.confirm(&[1], &store, &mut FixtureHooks::default())
                .unwrap()
                .len(),
            1
        );
        let pool: Value = serde_json::from_slice(&fs::read(etc.join("pool")).unwrap()).unwrap();
        assert_eq!(pool["proxies"][2]["protocol"], "http");
        let mut core: Value = serde_json::from_slice(&fs::read(etc.join("core")).unwrap()).unwrap();
        for port in 10453..10550 {
            core["inbounds"]
                .as_array_mut()
                .unwrap()
                .push(json!({"tag":format!("reserved-{port}"),"port":port}));
        }
        fs::write(etc.join("core"), serde_json::to_vec(&core).unwrap()).unwrap();
        let full = detect_with(
            &store,
            "socks",
            "fixture",
            "4.4.4.4:85:u:p",
            None,
            &|_, _| Ok(()),
            &fake,
        )
        .unwrap();
        assert_eq!(full.available(), 0);
        assert!(matches!(
            full.confirm(&[1], &store, &mut FixtureHooks::default()),
            Err(PreviewError::Invalid)
        ));
    }
}

#[cfg(test)]
mod worker_tests {
    use super::tests::{fixture, FixtureHooks};
    use super::*;
    use crate::publisher::{AuditRecord, Auditor, PublishError, Publisher};
    use crate::queue::Queue;
    use crate::report::ReportChannel;
    use crate::request;
    use crate::runner::PreviewRunner;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Audit;
    impl Auditor for Audit {
        fn record(&mut self, _: &AuditRecord) -> Result<(), PublishError> {
            Ok(())
        }
    }
    #[test]
    fn worker_reports_each_probe_and_applies_only_checked_successes() {
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
        let (dir, store, etc) = fixture();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let script = dir.path().join("probe");
        fs::write(&script,r##"#!/bin/sh
IFS= read -r data || exit 2
case "$data" in
 *bad-secret*) printf '%s\n' '{"ok":false,"reason":"invalid_dns"}';;
 *slow-secret*) sleep 1; printf '%s\n' '{"ok":true,"exit_ip":"8.8.8.8","country":"US","https_ms":10,"doh_ms":5}';;
 *) printf '%s\n' '{"ok":true,"exit_ip":"9.9.9.9","country":"US","https_ms":7,"doh_ms":3}';;
esac
"##).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let inbox = dir.path().join("inbox");
        let state = dir.path().join("state");
        let report_dir = dir.path().join("report");
        for path in [&inbox, &state, &report_dir] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let owner = unsafe { libc::geteuid() };
        let group = unsafe { libc::getegid() };
        let writer = ReportChannel::open(&report_dir, owner, group).unwrap();
        let reader = ReportChannel::open(&report_dir, owner, group).unwrap();
        let key = [42u8; 32];
        let queue = Queue::open(&inbox, &state, None, key).unwrap();
        let publisher = Publisher::open(&inbox, key).unwrap();
        let worker = PreviewRunner::new(queue, store, Launcher::fixture(script, uid, gid), writer);
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let task = std::thread::spawn(move || {
            worker.run_with_hooks(signal, Some(Box::new(FixtureHooks::default())))
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let now = || {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
            };
            let wait = |wanted: &str, wanted_id: Option<&str>| {
                let deadline = Instant::now() + Duration::from_secs(15);
                loop {
                    if let Ok(value) = reader.read(now()) {
                        if value["status"] == wanted && wanted_id.is_none_or(|id| value["id"] == id)
                        {
                            break value;
                        }
                    }
                    assert!(Instant::now() < deadline, "worker did not reach {wanted}");
                    std::thread::sleep(Duration::from_millis(30));
                }
            };
            let idle = wait("idle", None);
            let text="1.1.1.1:81:fixture:slow-secret\n8.8.8.8:82:fixture:bad-secret\n9.9.9.9:83:fixture:good-secret\ninvalid-row";
            let first = request::prepare(
                &json!({"action":"preview_batch","protocol":"socks","label":"fixture","text":text}),
                now(),
                &key,
                0,
            )
            .unwrap();
            publisher.submit(&first, &idle, now(), &mut Audit).unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let progress = reader.read(now()).unwrap();
                if progress["id"] == first.id()
                    && progress["status"] == "verifying"
                    && progress["rows"].as_array().is_some_and(|rows| {
                        rows.len() == 4
                            && rows[1]["state"] == "failed"
                            && rows[0]["state"] == "testing"
                    })
                {
                    assert_eq!(progress["rows"][1]["reason"], "invalid_dns");
                    assert!(!progress.to_string().contains("secret"));
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "per-item progress was not published"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            let ready = wait("ready", Some(first.id()));
            assert_eq!(ready["rows"][0]["state"], "success");
            assert_eq!(ready["rows"][1]["state"], "failed");
            assert_eq!(ready["rows"][3]["reason"], "invalid_format");
            assert_eq!(ready["available"], 40);
            assert!(!fs::read_to_string(report_dir.join("report.json"))
                .unwrap()
                .contains("secret"));
            let invalid = request::prepare(
                &json!({"action":"apply_batch","preview_id":first.id(),"selected":[2]}),
                now(),
                &key,
                0,
            )
            .unwrap();
            publisher
                .submit(&invalid, &ready, now(), &mut Audit)
                .unwrap();
            let failed = wait("failed", Some(invalid.id()));
            assert_eq!(failed["reason"], "invalid");
            assert!(!etc.join("pool").exists());
            let second = request::prepare(
                &json!({"action":"preview_batch","protocol":"socks","label":"fixture","text":text}),
                now(),
                &key,
                0,
            )
            .unwrap();
            publisher
                .submit(&second, &failed, now(), &mut Audit)
                .unwrap();
            let ready = wait("ready", Some(second.id()));
            let apply = request::prepare(
                &json!({"action":"apply_batch","preview_id":second.id(),"selected":[3]}),
                now(),
                &key,
                0,
            )
            .unwrap();
            publisher.submit(&apply, &ready, now(), &mut Audit).unwrap();
            let complete = wait("complete", Some(apply.id()));
            assert_eq!(complete["rows"].as_array().unwrap().len(), 1);
            assert_eq!(complete["rows"][0]["tag"], "residential-27");
            let pool: Value = serde_json::from_slice(&fs::read(etc.join("pool")).unwrap()).unwrap();
            assert_eq!(pool["proxies"].as_array().unwrap().len(), 1);
            assert_eq!(pool["proxies"][0]["address"], "9.9.9.9");
            let catalog = reader.read_catalog().unwrap();
            assert_eq!(catalog.len(), 1);
            assert_eq!(catalog[0]["address"], "9.9.9.9");
            assert!(!complete.to_string().contains("secret"));
        }));
        stop.store(true, Ordering::Release);
        assert!(task.join().unwrap().is_ok());
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
    }
}
