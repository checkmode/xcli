//! Local Xray process adapter for an independent node.
//!
//! The caller must supply an independent supervisor that uses KillHandle when
//! authorization expires. This library does not install or run a node service.
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;
use wait_timeout::ChildExt;
use xcli_node_controller::{Core, CoreError};
use xcli_node_protocol::User;

const TAGS: [&str; 3] = ["reality", "websocket", "hysteria2"];
const MAX_OUTPUT: usize = 4 * 1024 * 1024;

#[derive(Clone, Default)]
pub struct KillHandle(Arc<Mutex<Option<Child>>>);
impl KillHandle {
    /// Can be called while the controller is blocked in a different operation.
    pub fn terminate(&self) -> std::io::Result<()> {
        let mut slot = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(child) = slot.as_mut() {
            if child.try_wait()?.is_none() {
                child.kill()?;
            }
        }
        Ok(())
    }
}

pub struct XrayCore {
    binary: PathBuf,
    config_path: PathBuf,
    api: String,
    config: Value,
    process: KillHandle,
    generation: String,
    users: BTreeMap<String, User>,
}

impl XrayCore {
    pub fn new(
        binary: &Path,
        config_path: &Path,
        api: &str,
    ) -> std::result::Result<Self, &'static str> {
        let address: SocketAddr = api.parse().map_err(|_| "Invalid core management address")?;
        if !matches!(address, SocketAddr::V4(v4) if *v4.ip() == Ipv4Addr::LOCALHOST && v4.port() != 0)
        {
            return Err("Core management API must use IPv4 loopback");
        }
        let config: Value = serde_json::from_slice(
            &std::fs::read(config_path).map_err(|_| "Core configuration unavailable")?,
        )
        .map_err(|_| "Invalid core configuration")?;
        if config.pointer("/api/listen").and_then(Value::as_str) != Some(api) {
            return Err("Unexpected core management address");
        }
        let inbounds = config
            .get("inbounds")
            .and_then(Value::as_array)
            .ok_or("Invalid core inbounds")?;
        if inbounds.len() != TAGS.len() {
            return Err("Invalid core inbounds");
        }
        let mut tags = BTreeSet::new();
        for inbound in inbounds {
            let tag = inbound
                .get("tag")
                .and_then(Value::as_str)
                .ok_or("Invalid core inbound")?;
            let settings = inbound
                .get("settings")
                .and_then(Value::as_object)
                .ok_or("Invalid core inbound")?;
            if !tags.insert(tag)
                || ["clients", "users"].iter().any(|key| {
                    settings
                        .get(*key)
                        .is_some_and(|v| !v.as_array().is_some_and(Vec::is_empty))
                })
            {
                return Err("Persisted core configuration must not contain users");
            }
        }
        if tags != TAGS.into_iter().collect() {
            return Err("Unexpected core inbounds");
        }
        Ok(Self {
            binary: binary.to_owned(),
            config_path: config_path.to_owned(),
            api: api.to_owned(),
            config,
            process: KillHandle::default(),
            generation: String::new(),
            users: BTreeMap::new(),
        })
    }

    pub fn kill_handle(&self) -> KillHandle {
        self.process.clone()
    }

    fn command(
        &self,
        action: &str,
        args: &[String],
        input: Option<Vec<u8>>,
        timeout: Duration,
    ) -> std::result::Result<Vec<u8>, ()> {
        let mut child = Command::new(&self.binary)
            .arg("api")
            .arg(action)
            .arg(format!("--server={}", self.api))
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .map_err(|_| ())?;
        let mut stdout = child.stdout.take().ok_or(())?;
        let reader = thread::spawn(move || {
            let mut result = Vec::new();
            let mut chunk = [0u8; 8192];
            let mut overflow = false;
            loop {
                let n = stdout.read(&mut chunk).map_err(|_| ())?;
                if n == 0 {
                    break;
                }
                if result.len().saturating_add(n) > MAX_OUTPUT {
                    overflow = true;
                } else if !overflow {
                    result.extend_from_slice(&chunk[..n]);
                }
            }
            if overflow {
                Err(())
            } else {
                Ok(result)
            }
        });
        let writer = input.map(|data| {
            let mut stdin = child.stdin.take().expect("piped input");
            thread::spawn(move || stdin.write_all(&data).map_err(|_| ()))
        });
        let until = Instant::now() + timeout;
        let status = loop {
            let remaining = until.saturating_duration_since(Instant::now());
            let next = if remaining.is_zero() {
                None
            } else {
                match child.wait_timeout(remaining.min(Duration::from_millis(200))) {
                    Ok(Some(status)) => break status,
                    Ok(None) if self.alive() => Some(()),
                    _ => None,
                }
            };
            if next.is_none() {
                // SAFETY: the helper was started as leader of its own process
                // group and has not been reaped; never signal the Xray core.
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                if let Some(w) = writer {
                    let _ = w.join();
                }
                return Err(());
            }
        };
        let output = reader.join().map_err(|_| ())??;
        if let Some(writer) = writer {
            writer.join().map_err(|_| ())??;
        }
        if !status.success() {
            return Err(());
        }
        Ok(output)
    }

    fn alive(&self) -> bool {
        let mut slot = self.process.0.lock().unwrap_or_else(|p| p.into_inner());
        match slot.as_mut() {
            Some(child) => matches!(child.try_wait(), Ok(None)),
            None => false,
        }
    }
}

impl Core for XrayCore {
    fn running(&mut self) -> bool {
        self.alive()
    }

    fn start(&mut self) -> std::result::Result<(), CoreError> {
        if self.alive() {
            return Err(CoreError);
        }
        self.stop();
        {
            let mut slot = self.process.0.lock().unwrap_or_else(|p| p.into_inner());
            if slot.is_some() {
                return Err(CoreError);
            }
            *slot = Some(
                Command::new(&self.binary)
                    .arg("run")
                    .arg("-config")
                    .arg(&self.config_path)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .map_err(|_| ())?,
            );
        }
        self.generation = Uuid::new_v4().simple().to_string();
        self.users.clear();
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if !self.alive() {
                self.stop();
                return Err(CoreError);
            }
            if self
                .command(
                    "inboundusercount",
                    &["-tag=reality".into(), "--timeout=1".into()],
                    None,
                    Duration::from_secs(2),
                )
                .is_ok()
            {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(200));
        }
        self.stop();
        Err(CoreError)
    }

    fn stop(&mut self) {
        let _ = self.process.terminate();
        let mut slot = self.process.0.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(child) = slot.as_mut() {
            if matches!(child.wait_timeout(Duration::from_secs(8)), Ok(Some(_))) {
                *slot = None;
            }
        }
        self.users.clear();
        self.generation.clear();
    }

    fn generation(&self) -> &str {
        &self.generation
    }

    fn counters(&mut self) -> std::result::Result<Value, CoreError> {
        if !self.alive() {
            return Err(CoreError);
        }
        let output = self.command(
            "statsquery",
            &["-pattern=user>>>".into(), "--timeout=3".into()],
            None,
            Duration::from_secs(5),
        )?;
        let result: Value = serde_json::from_slice(&output).map_err(|_| ())?;
        let counters = result.get("stat").cloned().unwrap_or_else(|| json!([]));
        if !counters.is_array() {
            return Err(CoreError);
        }
        Ok(counters)
    }

    fn apply(&mut self, users: &BTreeMap<String, User>) -> std::result::Result<(), CoreError> {
        if !self.alive() {
            return Err(CoreError);
        }
        for (id, user) in users {
            let canonical = Uuid::parse_str(&user.uuid).map_err(|_| ())?.to_string();
            if id != &user.id
                || id.len() != 32
                || !id
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                || canonical != user.uuid
                || user.expires < 0
            {
                return Err(CoreError);
            }
        }
        let remove = self
            .users
            .iter()
            .any(|(id, old)| users.get(id).is_none_or(|new| old.uuid != new.uuid));
        if remove {
            self.stop();
            self.start()?;
        }
        let additions: Vec<&User> = users
            .iter()
            .filter(|(id, _)| !self.users.contains_key(*id))
            .map(|(_, user)| user)
            .collect();
        if additions.is_empty() {
            self.users = users.clone();
            return Ok(());
        }
        let mut inbounds = self.config["inbounds"].as_array().ok_or(())?.clone();
        for item in &mut inbounds {
            let tag = item["tag"].as_str().ok_or(())?.to_owned();
            let mut entries = Vec::new();
            for user in &additions {
                let prefix = user.uuid.get(..8).ok_or(())?;
                let email = format!("{}.{prefix}@{tag}", user.id);
                let mut entry = if tag == "hysteria2" {
                    json!({"email":email,"auth":user.uuid})
                } else {
                    json!({"email":email,"id":user.uuid})
                };
                if tag == "reality" {
                    entry["flow"] = json!("xtls-rprx-vision");
                }
                entries.push(entry);
            }
            item["settings"]["clients"] = json!(entries);
        }
        let input = serde_json::to_vec(&json!({ "inbounds": inbounds })).map_err(|_| ())?;
        let result = self.command(
            "adu",
            &["--timeout=30".into(), "stdin:".into()],
            Some(input),
            Duration::from_secs(35),
        );
        let expected = format!("Added {} user(s) in total.", additions.len() * TAGS.len());
        match result {
            Ok(output)
                if output
                    .windows(expected.len())
                    .any(|window| window == expected.as_bytes()) =>
            {
                self.users = users.clone();
                Ok(())
            }
            _ => {
                self.stop();
                Err(CoreError)
            }
        }
    }
}

impl Drop for XrayCore {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Value {
        json!({"api":{"listen":"127.0.0.1:10085"},"inbounds":[
            {"tag":"reality","settings":{"clients":[]}},
            {"tag":"websocket","settings":{"clients":[]}},
            {"tag":"hysteria2","settings":{"clients":[]}}
        ]})
    }

    #[test]
    fn accepts_only_the_local_api_and_empty_expected_inbounds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("core.json");
        let write =
            |data: &Value| std::fs::write(&path, serde_json::to_vec(data).unwrap()).unwrap();
        write(&config());
        assert!(XrayCore::new(Path::new("/unused"), &path, "127.0.0.1:10085").is_ok());
        assert!(XrayCore::new(Path::new("/unused"), &path, "0.0.0.0:10085").is_err());
        let mut with_users = config();
        with_users["inbounds"][0]["settings"]["clients"] = json!([{"id":"fixture"}]);
        write(&with_users);
        assert!(XrayCore::new(Path::new("/unused"), &path, "127.0.0.1:10085").is_err());
        let mut duplicate = config();
        duplicate["inbounds"][1]["tag"] = json!("reality");
        write(&duplicate);
        assert!(XrayCore::new(Path::new("/unused"), &path, "127.0.0.1:10085").is_err());
    }

    #[test]
    fn independent_kill_handle_terminates_the_owned_process() {
        let handle = KillHandle::default();
        *handle.0.lock().unwrap() = Some(
            Command::new("sleep")
                .arg("60")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        handle.terminate().unwrap();
        let mut slot = handle.0.lock().unwrap();
        assert!(slot
            .as_mut()
            .unwrap()
            .wait_timeout(Duration::from_secs(2))
            .unwrap()
            .is_some());
        *slot = None;
    }
}
