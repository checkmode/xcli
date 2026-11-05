//! Bounded, root-owned import-worker heartbeat shared with the panel.
//! This is a status channel, not proof that any configuration was applied.
use crate::journal::{atomic, read, Meta};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub enum ReportError {
    Invalid,
    Unavailable,
    Stale,
}
type Result<T> = std::result::Result<T, ReportError>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Verifying,
    Ready,
    Applying,
    Complete,
    Failed,
    Expired,
    Unavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureReason {
    Invalid,
    Probe,
    Conflict,
    Expired,
    Unavailable,
    ApplyDisabled,
    Interrupted,
}
impl FailureReason {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::Probe => "probe",
            Self::Conflict => "conflict",
            Self::Expired => "expired",
            Self::Unavailable => "unavailable",
            Self::ApplyDisabled => "apply_disabled",
            Self::Interrupted => "interrupted",
        }
    }
    pub(crate) fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "invalid" => Self::Invalid,
            "probe" => Self::Probe,
            "conflict" => Self::Conflict,
            "expired" => Self::Expired,
            "unavailable" => Self::Unavailable,
            "apply_disabled" => Self::ApplyDisabled,
            "interrupted" => Self::Interrupted,
            _ => return None,
        })
    }
}
impl Phase {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Verifying => "verifying",
            Self::Ready => "ready",
            Self::Applying => "applying",
            Self::Complete => "complete",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Unavailable => "unavailable",
        }
    }
    pub(crate) fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "idle" => Self::Idle,
            "verifying" => Self::Verifying,
            "ready" => Self::Ready,
            "applying" => Self::Applying,
            "complete" => Self::Complete,
            "failed" => Self::Failed,
            "expired" => Self::Expired,
            "unavailable" => Self::Unavailable,
            _ => return None,
        })
    }
}
fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn catalog_entries(items: &[Value]) -> Result<Vec<Value>> {
    if items.len() > 40 {
        return Err(ReportError::Invalid);
    }
    items
        .iter()
        .map(|item| {
            let mut row = serde_json::Map::new();
            for key in ["tag", "protocol", "address", "label", "country", "exit_ip"] {
                let text = item
                    .get(key)
                    .and_then(Value::as_str)
                    .filter(|v| v.len() <= 256 && !v.chars().any(char::is_control))
                    .ok_or(ReportError::Invalid)?;
                row.insert(key.into(), json!(text));
            }
            let port = item["port"]
                .as_u64()
                .filter(|v| (1..=65535).contains(v))
                .ok_or(ReportError::Invalid)?;
            let enabled = item["enabled"].as_bool().ok_or(ReportError::Invalid)?;
            let deleted = item["deleted_at"].as_u64().ok_or(ReportError::Invalid)?;
            row.insert("port".into(), json!(port));
            row.insert("enabled".into(), json!(enabled));
            row.insert("deleted_at".into(), json!(deleted));
            for key in [
                "network",
                "security",
                "server_name",
                "host",
                "path",
                "alpn",
                "fingerprint",
            ] {
                if let Some(value) = item.get(key).and_then(Value::as_str) {
                    let limit = if key == "path" { 1024 } else { 256 };
                    if value.len() > limit || value.chars().any(char::is_control) {
                        return Err(ReportError::Invalid);
                    }
                    row.insert(key.into(), json!(value));
                }
            }
            if let Some(tls) = item.get("tls").and_then(Value::as_bool) {
                row.insert("tls".into(), json!(tls));
            }
            Ok(Value::Object(row))
        })
        .collect()
}
/// Whitelist display fields on both sides of the privilege boundary. In
/// particular, upstream credentials, client entry paths and nested objects are
/// never copied from a candidate into the group-readable status file.
pub(crate) fn public_entries(entries: &[Value]) -> Vec<Value> {
    entries
        .iter()
        .take(40)
        .map(|entry| {
            let mut value = serde_json::Map::new();
            for key in ["tag", "label", "exit_ip", "country"] {
                if let Some(item) = entry
                    .get(key)
                    .and_then(Value::as_str)
                    .filter(|item| item.len() <= 256 && !item.chars().any(char::is_control))
                {
                    value.insert(key.to_owned(), json!(item));
                }
            }
            if let Some(port) = entry
                .get("port")
                .and_then(Value::as_u64)
                .filter(|port| *port <= 65535)
            {
                value.insert("port".into(), json!(port));
            }
            if let Some(hy2) = entry.get("hysteria2").and_then(Value::as_bool) {
                value.insert("hysteria2".into(), json!(hy2));
            }
            Value::Object(value)
        })
        .collect()
}
fn directory(path: &Path, owner: u32, group: u32) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(ReportError::Invalid);
    }
    let info = fs::symlink_metadata(path).map_err(|_| ReportError::Unavailable)?;
    if !info.is_dir()
        || info.file_type().is_symlink()
        || info.uid() != owner
        || info.gid() != group
        || info.mode() & 0o027 != 0
    {
        return Err(ReportError::Unavailable);
    }
    fs::canonicalize(path).map_err(|_| ReportError::Unavailable)
}
pub struct ReportChannel {
    directory: PathBuf,
    owner: u32,
    group: u32,
    trusted_ancestors: bool,
}
impl ReportChannel {
    /// Production must pass the root worker's UID and the panel's read group.
    /// The directory must be owned by the worker and not group/world writable.
    /// The trusted installation path and its ancestors must not be writable by
    /// the panel; this method must never receive a path from an HTTP request.
    pub fn open(path: &Path, owner: u32, group: u32) -> Result<Self> {
        Ok(Self {
            directory: directory(path, owner, group)?,
            owner,
            group,
            trusted_ancestors: false,
        })
    }
    /// The panel uses this stricter variant for a root-worker report. Every
    /// ancestor must be a root-owned directory that the panel cannot replace.
    /// Installation chooses the path; it is never supplied by a web request.
    pub fn open_trusted(path: &Path, group: u32) -> Result<Self> {
        if group == 0 || !path.is_absolute() {
            return Err(ReportError::Invalid);
        }
        Self::verify_ancestors(path)?;
        let mut channel = Self::open(path, 0, group)?;
        channel.trusted_ancestors = true;
        channel.verify_directory()?;
        Ok(channel)
    }
    fn verify_ancestors(path: &Path) -> Result<()> {
        for ancestor in path.ancestors() {
            let meta = fs::symlink_metadata(ancestor).map_err(|_| ReportError::Unavailable)?;
            if !meta.is_dir()
                || meta.file_type().is_symlink()
                || meta.uid() != 0
                || meta.mode() & 0o022 != 0
            {
                return Err(ReportError::Unavailable);
            }
        }
        Ok(())
    }
    fn verify_directory(&self) -> Result<()> {
        if self.trusted_ancestors {
            Self::verify_ancestors(&self.directory)?;
        }
        if directory(&self.directory, self.owner, self.group)? != self.directory {
            return Err(ReportError::Unavailable);
        }
        Ok(())
    }
    pub fn publish_catalog(&self, items: &[Value]) -> Result<()> {
        if unsafe { libc::geteuid() } != self.owner {
            return Err(ReportError::Unavailable);
        }
        self.verify_directory()?;
        let bytes = serde_json::to_vec(&json!({"items":catalog_entries(items)?}))
            .map_err(|_| ReportError::Unavailable)?;
        if bytes.len() > 32768 {
            return Err(ReportError::Invalid);
        }
        atomic(
            &self.directory.join("catalog.json"),
            &bytes,
            &Meta {
                mode: 0o640,
                uid: self.owner,
                gid: self.group,
            },
        )
        .map_err(|_| ReportError::Unavailable)
    }
    pub fn read_catalog(&self) -> Result<Vec<Value>> {
        self.verify_directory()?;
        let file = read(&self.directory.join("catalog.json"), 32768)
            .map_err(|_| ReportError::Unavailable)?
            .ok_or(ReportError::Unavailable)?;
        if file.meta.uid != self.owner || file.meta.gid != self.group || file.meta.mode & 0o027 != 0
        {
            return Err(ReportError::Unavailable);
        }
        let value: Value =
            serde_json::from_slice(&file.data).map_err(|_| ReportError::Unavailable)?;
        catalog_entries(value["items"].as_array().ok_or(ReportError::Unavailable)?)
    }
    /// Only the owning worker may publish. Non-ready states carry no preview.
    pub fn publish(&self, id: &str, phase: Phase, now: i64, expires: Option<i64>) -> Result<()> {
        self.publish_inner(id, phase, now, expires, None, None)
    }
    /// Publish a ready preview with only bounded display fields. The preview
    /// expires with the in-memory candidate and is never a confirmation.
    pub fn publish_preview(&self, id: &str, now: i64, expires: i64, rows: &[Value]) -> Result<()> {
        if rows.len() > 40 || rows.iter().any(|row| !row.is_object()) {
            return Err(ReportError::Invalid);
        }
        self.publish_inner(id, Phase::Ready, now, Some(expires), Some(rows), None)
    }
    /// Publish only a fixed diagnostic category, never an upstream error text.
    pub fn publish_failure(&self, id: &str, now: i64, reason: FailureReason) -> Result<()> {
        self.publish_inner(id, Phase::Failed, now, None, None, Some(reason))
    }
    fn publish_inner(
        &self,
        id: &str,
        phase: Phase,
        now: i64,
        expires: Option<i64>,
        rows: Option<&[Value]>,
        reason: Option<FailureReason>,
    ) -> Result<()> {
        if unsafe { libc::geteuid() } != self.owner {
            return Err(ReportError::Unavailable);
        }
        if now < 0
            || !(id.is_empty() && matches!(phase, Phase::Idle | Phase::Unavailable) || valid_id(id))
            || expires.is_some_and(|expires| expires < 0 || expires > now.saturating_add(960))
            || matches!(phase, Phase::Ready) && expires.is_none()
        {
            return Err(ReportError::Invalid);
        }
        self.verify_directory()?;
        let mut value = json!({"schema":1,"id":id,"status":phase.name(),"updated":now});
        if let Some(expires) = expires {
            value["expires"] = json!(expires);
        }
        if let Some(rows) = rows {
            value["rows"] = json!(public_entries(rows));
        }
        if let Some(reason) = reason {
            value["reason"] = json!(reason.name());
        }
        let bytes = serde_json::to_vec(&value).map_err(|_| ReportError::Unavailable)?;
        if bytes.len() > 32768 {
            return Err(ReportError::Invalid);
        }
        atomic(
            &self.directory.join("report.json"),
            &bytes,
            &Meta {
                mode: 0o640,
                uid: self.owner,
                gid: self.group,
            },
        )
        .map_err(|_| ReportError::Unavailable)
    }
    /// Return only known fields from a fresh, regular file. Missing or stale
    /// heartbeats are not interpreted as idle or healthy.
    fn read_internal(&self, now: Option<i64>) -> Result<Value> {
        self.verify_directory()?;
        let file = read(&self.directory.join("report.json"), 32768)
            .map_err(|_| ReportError::Unavailable)?
            .ok_or(ReportError::Unavailable)?;
        if file.meta.uid != self.owner || file.meta.gid != self.group || file.meta.mode & 0o027 != 0
        {
            return Err(ReportError::Unavailable);
        }
        let value: Value =
            serde_json::from_slice(&file.data).map_err(|_| ReportError::Unavailable)?;
        let id = value["id"].as_str().ok_or(ReportError::Unavailable)?;
        let phase = value["status"]
            .as_str()
            .and_then(Phase::parse)
            .ok_or(ReportError::Unavailable)?;
        let updated = value["updated"]
            .as_i64()
            .filter(|v| *v >= 0)
            .ok_or(ReportError::Unavailable)?;
        if value["schema"] != 1
            || !(id.is_empty() && matches!(phase, Phase::Idle | Phase::Unavailable) || valid_id(id))
        {
            return Err(ReportError::Unavailable);
        }
        if let Some(now) = now {
            if now.saturating_sub(updated) > 30 || updated > now.saturating_add(60) {
                return Err(ReportError::Stale);
            }
        }
        let expires = match value.get("expires") {
            Some(value) => Some(
                value
                    .as_i64()
                    .filter(|v| *v >= 0 && *v <= updated.saturating_add(960))
                    .ok_or(ReportError::Unavailable)?,
            ),
            None => None,
        };
        if matches!(phase, Phase::Ready) && expires.is_none() {
            return Err(ReportError::Unavailable);
        }
        let status = if matches!(phase, Phase::Ready)
            && now.is_some_and(|now| expires.is_some_and(|expires| expires <= now))
        {
            "expired"
        } else {
            phase.name()
        };
        let mut result = json!({"id":id,"status":status,"updated":updated});
        if let Some(expires) = expires {
            result["expires"] = json!(expires);
        }
        if let Some(rows) = value.get("rows") {
            let rows = rows
                .as_array()
                .filter(|rows| rows.len() <= 40 && rows.iter().all(Value::is_object))
                .filter(|_| phase == Phase::Ready)
                .ok_or(ReportError::Unavailable)?;
            if status == "ready" {
                result["rows"] = json!(public_entries(rows));
            }
        }
        if let Some(reason) = value.get("reason") {
            let reason = reason
                .as_str()
                .and_then(FailureReason::parse)
                .filter(|_| phase == Phase::Failed)
                .ok_or(ReportError::Unavailable)?;
            result["reason"] = json!(reason.name());
        }
        Ok(result)
    }
    pub fn read(&self, now: i64) -> Result<Value> {
        if now < 0 {
            return Err(ReportError::Invalid);
        }
        self.read_internal(Some(now))
    }
    /// An in-memory preview never survives process restart. A missing report
    /// initializes idle; malformed or unsafe files are not overwritten.
    pub fn restart(&self, now: i64) -> Result<Value> {
        if now < 0 || unsafe { libc::geteuid() } != self.owner {
            return Err(ReportError::Unavailable);
        }
        self.verify_directory()?;
        let path = self.directory.join("report.json");
        let previous = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(ReportError::Unavailable),
            Ok(_) => Some(self.read_internal(None)?),
        };
        let (id, phase, reason) = if let Some(value) = previous.as_ref() {
            let id = value["id"].as_str().ok_or(ReportError::Unavailable)?;
            let phase = Phase::parse(value["status"].as_str().ok_or(ReportError::Unavailable)?)
                .ok_or(ReportError::Unavailable)?;
            match phase {
                Phase::Ready | Phase::Verifying | Phase::Applying => {
                    (id, Phase::Failed, Some(FailureReason::Interrupted))
                }
                Phase::Unavailable if valid_id(id) => {
                    (id, Phase::Failed, Some(FailureReason::Interrupted))
                }
                Phase::Failed => (
                    id,
                    phase,
                    value["reason"].as_str().and_then(FailureReason::parse),
                ),
                other => (id, other, None),
            }
        } else {
            ("", Phase::Idle, None)
        };
        if let Some(reason) = reason {
            self.publish_failure(id, now, reason)?;
        } else {
            self.publish(id, phase, now, None)?;
        }
        self.read(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn fixture() -> (tempfile::TempDir, PathBuf, u32, u32) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o750)).unwrap();
        (dir, path, unsafe { libc::geteuid() }, unsafe {
            libc::getegid()
        })
    }
    #[test]
    fn fresh_ready_report_expires_and_stale_or_future_reports_fail_closed() {
        let (_dir, path, uid, gid) = fixture();
        let channel = ReportChannel::open(&path, uid, gid).unwrap();
        let id = "a".repeat(32);
        channel
            .publish(&id, Phase::Ready, 1000, Some(1050))
            .unwrap();
        assert_eq!(
            channel.read(1001).unwrap(),
            json!({"id":id,"status":"ready","updated":1000,"expires":1050})
        );
        assert_eq!(channel.read(1031), Err(ReportError::Stale));
        channel
            .publish(&id, Phase::Ready, 1040, Some(1050))
            .unwrap();
        assert_eq!(channel.read(1050).unwrap()["status"], "expired");
        assert_eq!(channel.read(970), Err(ReportError::Stale));
        assert!(channel
            .publish("bad", Phase::Ready, 1000, Some(1100))
            .is_err());
        assert!(channel.publish(&id, Phase::Ready, 1000, None).is_err());
    }
    #[test]
    fn preview_rows_are_bounded_filtered_and_disappear_when_expired_or_restarted() {
        let (_dir, path, uid, gid) = fixture();
        let channel = ReportChannel::open(&path, uid, gid).unwrap();
        let id = "a".repeat(32);
        let rows = vec![json!({
            "tag":"residential-27", "label":"fixture · US", "exit_ip":"8.8.8.8",
            "country":"US", "port":10450, "hysteria2":true,
            "username":"synthetic-user", "password":"synthetic-password",
            "ws_path":"/synthetic-secret", "nested":{"password":"synthetic-secret"}
        })];
        channel.publish_preview(&id, 1000, 1050, &rows).unwrap();
        let report = channel.read(1001).unwrap();
        assert_eq!(report["rows"][0]["tag"], "residential-27");
        assert_eq!(report["rows"][0]["label"], "fixture · US");
        assert_eq!(report["rows"][0]["port"], 10450);
        let file = fs::read_to_string(path.join("report.json")).unwrap();
        assert!(!file.contains("synthetic"));
        channel.publish_preview(&id, 1040, 1050, &rows).unwrap();
        let expired = channel.read(1050).unwrap();
        assert_eq!(expired["status"], "expired");
        assert!(expired.get("rows").is_none());
        let restarted = channel.restart(1051).unwrap();
        assert_eq!(restarted["status"], "failed");
        assert!(restarted.get("rows").is_none());
        assert!(!fs::read_to_string(path.join("report.json"))
            .unwrap()
            .contains("residential-27"));
        assert!(channel
            .publish_preview(&id, 1000, 1050, &vec![json!({}); 41])
            .is_err());
        assert!(channel
            .publish_preview(&id, 1000, 1050, &[json!("bad")])
            .is_err());
        let escaped = "\"".repeat(256);
        let large =
            vec![json!({"tag":escaped,"label":escaped,"exit_ip":escaped,"country":escaped}); 40];
        assert!(channel.publish_preview(&id, 1000, 1050, &large).is_err());
    }
    #[test]
    fn reader_filters_unrecognized_fields_even_from_a_trusted_report() {
        let (_dir, path, uid, gid) = fixture();
        let channel = ReportChannel::open(&path, uid, gid).unwrap();
        let id = "a".repeat(32);
        channel
            .publish_preview(&id, 1000, 1050, &[json!({"tag":"safe"})])
            .unwrap();
        let mut value: Value =
            serde_json::from_slice(&fs::read(path.join("report.json")).unwrap()).unwrap();
        value["rows"][0]["password"] = json!("synthetic-secret");
        fs::write(
            path.join("report.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        let report = channel.read(1001).unwrap();
        assert_eq!(report["rows"][0]["tag"], "safe");
        assert!(!report.to_string().contains("synthetic-secret"));
        value["status"] = json!("failed");
        fs::write(
            path.join("report.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        assert_eq!(channel.read(1001), Err(ReportError::Unavailable));
    }
    #[test]
    fn failure_exposes_only_fixed_categories_and_survives_restart() {
        let (_dir, path, uid, gid) = fixture();
        let channel = ReportChannel::open(&path, uid, gid).unwrap();
        let id = "a".repeat(32);
        channel
            .publish_failure(&id, 1000, FailureReason::Probe)
            .unwrap();
        assert_eq!(channel.read(1001).unwrap()["reason"], "probe");
        assert_eq!(channel.restart(1002).unwrap()["reason"], "probe");
        let mut value: Value =
            serde_json::from_slice(&fs::read(path.join("report.json")).unwrap()).unwrap();
        value["reason"] = json!("synthetic-secret");
        fs::write(
            path.join("report.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        assert_eq!(channel.read(1002), Err(ReportError::Unavailable));
        value["reason"] = json!("probe");
        value["status"] = json!("idle");
        fs::write(
            path.join("report.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        assert_eq!(channel.read(1002), Err(ReportError::Unavailable));
    }
    #[test]
    fn refuses_links_writable_or_malformed_reports_and_filters_unknown_fields() {
        let (dir, path, uid, gid) = fixture();
        let channel = ReportChannel::open(&path, uid, gid).unwrap();
        channel.publish("", Phase::Idle, 1000, None).unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"{}").unwrap();
        fs::remove_file(path.join("report.json")).unwrap();
        symlink(&target, path.join("report.json")).unwrap();
        assert_eq!(channel.read(1000), Err(ReportError::Unavailable));
        fs::remove_file(path.join("report.json")).unwrap();
        fs::hard_link(&target, path.join("report.json")).unwrap();
        assert_eq!(channel.read(1000), Err(ReportError::Unavailable));
        fs::remove_file(path.join("report.json")).unwrap();
        fs::write(path.join("report.json"),serde_json::to_vec(&json!({"schema":1,"id":"","status":"idle","updated":1000,"password":"synthetic-secret"})).unwrap()).unwrap();
        fs::set_permissions(path.join("report.json"), fs::Permissions::from_mode(0o640)).unwrap();
        assert!(!channel
            .read(1000)
            .unwrap()
            .to_string()
            .contains("synthetic-secret"));
        fs::set_permissions(path.join("report.json"), fs::Permissions::from_mode(0o660)).unwrap();
        assert_eq!(channel.read(1000), Err(ReportError::Unavailable));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(channel.read(1000), Err(ReportError::Unavailable));
    }

    #[test]
    fn trusted_heartbeat_gates_publication_and_expired_preview() {
        struct Audit;
        impl crate::publisher::Auditor for Audit {
            fn record(
                &mut self,
                _: &crate::publisher::AuditRecord,
            ) -> std::result::Result<(), crate::publisher::PublishError> {
                Ok(())
            }
        }
        let (dir, path, uid, gid) = fixture();
        let channel = ReportChannel::open(&path, uid, gid).unwrap();
        let inbox = dir.path().join("inbox");
        fs::create_dir(&inbox).unwrap();
        fs::set_permissions(&inbox, fs::Permissions::from_mode(0o700)).unwrap();
        let key = [42u8; 32];
        let publisher = crate::publisher::Publisher::open(&inbox, key).unwrap();
        let request = crate::request::prepare(
            &json!({"action":"preview","protocol":"socks","label":"fixture",
            "text":"1.1.1.1:80:synthetic-user:synthetic-password"}),
            1000,
            &key,
            0,
        )
        .unwrap();
        channel.publish("", Phase::Idle, 1000, None).unwrap();
        publisher
            .submit(&request, &channel.read(1000).unwrap(), 1000, &mut Audit)
            .unwrap();
        channel
            .publish(request.id(), Phase::Ready, 1001, Some(1020))
            .unwrap();
        let apply = crate::request::prepare(
            &json!({"action":"apply","preview_id":request.id()}),
            1020,
            &key,
            0,
        )
        .unwrap();
        assert_eq!(
            publisher.submit(&apply, &channel.read(1020).unwrap(), 1020, &mut Audit),
            Err(crate::publisher::PublishError::Busy)
        );
        let fresh = crate::request::prepare(
            &json!({"action":"apply","preview_id":request.id()}),
            1010,
            &key,
            0,
        )
        .unwrap();
        publisher
            .submit(&fresh, &channel.read(1010).unwrap(), 1010, &mut Audit)
            .unwrap();
        assert!(!fs::read_to_string(path.join("report.json"))
            .unwrap()
            .contains("synthetic-password"));
    }

    #[test]
    fn restart_never_revives_an_in_memory_preview() {
        let (_dir, path, uid, gid) = fixture();
        let channel = ReportChannel::open(&path, uid, gid).unwrap();
        assert_eq!(channel.restart(1000).unwrap()["status"], "idle");
        let id = "a".repeat(32);
        for phase in [Phase::Ready, Phase::Verifying, Phase::Applying] {
            channel
                .publish(
                    &id,
                    phase,
                    1000,
                    if matches!(phase, Phase::Ready) {
                        Some(1100)
                    } else {
                        None
                    },
                )
                .unwrap();
            let restarted = channel.restart(5000).unwrap();
            assert_eq!(restarted["status"], "failed");
            assert_eq!(restarted["reason"], "interrupted");
            assert_eq!(restarted["id"], id);
            assert!(restarted.get("expires").is_none());
        }
        channel.publish(&id, Phase::Complete, 1000, None).unwrap();
        assert_eq!(channel.restart(5000).unwrap()["status"], "complete");
        channel
            .publish(&id, Phase::Unavailable, 1000, None)
            .unwrap();
        let restarted = channel.restart(5000).unwrap();
        assert_eq!(restarted["status"], "failed");
        assert_eq!(restarted["id"], id);
        fs::write(path.join("report.json"), b"malformed").unwrap();
        assert_eq!(channel.restart(5000), Err(ReportError::Unavailable));
        assert_eq!(fs::read(path.join("report.json")).unwrap(), b"malformed");
    }
}
