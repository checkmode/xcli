//! Experimental crash-recoverable publication of encrypted import requests.
//! The caller must authenticate the administrator, own the panel mutation
//! lock and supply a trusted, fresh worker report. No services are started here.
use crate::journal::{atomic, check_private_dir, lock, private_meta, read};
use crate::request::Prepared;
use crate::vmess::SecretJson;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use xcli_auth_compat::{open_xgb1, seal_xgb1};
use zeroize::Zeroizing;
pub mod audit;

const REQUEST_CONTEXT: &[u8] = b"xcli:proxy-import:request:v1";
const INTENT_CONTEXT: &[u8] = b"xcli:proxy-import:publication:v1";
const TTL: i64 = 900;

#[derive(Debug, PartialEq, Eq)]
pub enum PublishError {
    Invalid,
    Busy,
    Unavailable,
    Expired,
}
type Result<T> = std::result::Result<T, PublishError>;

pub struct AuditRecord {
    pub id: String,
    pub timestamp: i64,
    pub detail: String,
}
/// Implementations must deduplicate the same request ID transactionally.
pub trait Auditor {
    fn record(&mut self, event: &AuditRecord) -> Result<()>;
}

pub struct Publisher {
    directory: PathBuf,
    key: Zeroizing<[u8; 32]>,
}

fn identifier(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn digest(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}
fn private_read(path: &Path, limit: u64) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let value = read(path, limit).map_err(|_| PublishError::Unavailable)?;
    if value.as_ref().is_some_and(|file| {
        file.meta.uid != unsafe { libc::geteuid() } || file.meta.mode & 0o077 != 0
    }) {
        return Err(PublishError::Unavailable);
    }
    Ok(value.map(|file| file.data))
}
fn sync_directory(path: &Path) -> Result<()> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| PublishError::Unavailable)
}
fn decoded(cipher: &[u8], key: &[u8]) -> Result<SecretJson> {
    if cipher.len() > 20000 {
        return Err(PublishError::Invalid);
    }
    let plain = open_xgb1(cipher, key, REQUEST_CONTEXT).map_err(|_| PublishError::Invalid)?;
    let payload = SecretJson::parse(&plain).map_err(|_| PublishError::Invalid)?;
    let value = payload.as_value();
    if !value["id"].as_str().is_some_and(identifier)
        || value["requested_at"].as_i64().is_none_or(|n| n < 0)
    {
        return Err(PublishError::Invalid);
    }
    match value["action"].as_str() {
        Some("preview" | "manage" | "apply" | "brutal_rate") => Ok(payload),
        _ => Err(PublishError::Invalid),
    }
}
fn audit(value: &Value) -> Result<AuditRecord> {
    let id = value["id"]
        .as_str()
        .filter(|s| identifier(s))
        .ok_or(PublishError::Invalid)?
        .to_owned();
    let timestamp = value["requested_at"]
        .as_i64()
        .filter(|n| *n >= 0)
        .ok_or(PublishError::Invalid)?;
    let detail = match value["action"].as_str() {
        Some("preview") => "请求检测固定代理".to_owned(),
        Some("apply") => "确认应用代理变更".to_owned(),
        Some("brutal_rate") => {
            let rate = value["mbps"].as_u64().filter(|v| (1..=1000).contains(v)).ok_or(PublishError::Invalid)?;
            format!("请求调整 Brutal 速率至 {rate} Mbps")
        },
        Some("manage") => {
            let action = value["operation"]
                .as_str()
                .filter(|s| ["edit", "enable", "disable", "delete", "restore"].contains(s))
                .ok_or(PublishError::Invalid)?;
            let tag = value["tag"]
                .as_str()
                .filter(|s| {
                    s.len() == 14
                        && s.starts_with("residential-")
                        && s[12..].bytes().all(|b| b.is_ascii_digit())
                })
                .ok_or(PublishError::Invalid)?;
            format!("请求管理代理 {action} {tag}")
        }
        _ => return Err(PublishError::Invalid),
    };
    Ok(AuditRecord {
        id,
        timestamp,
        detail,
    })
}

impl Publisher {
    pub fn open(directory: &Path, key: [u8; 32]) -> Result<Self> {
        if !directory.is_absolute() {
            return Err(PublishError::Invalid);
        }
        check_private_dir(directory).map_err(|_| PublishError::Unavailable)?;
        Ok(Self {
            directory: fs::canonicalize(directory).map_err(|_| PublishError::Unavailable)?,
            key: Zeroizing::new(key),
        })
    }
    fn current(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        private_read(&self.directory.join("request.xgb"), 20000)
    }
    fn lock(&self) -> Result<std::fs::File> {
        check_private_dir(&self.directory).map_err(|_| PublishError::Unavailable)?;
        lock(&self.directory.join("publisher.lock")).map_err(|_| PublishError::Busy)
    }
    fn recover_locked(
        &self,
        now: i64,
        auditor: &mut dyn Auditor,
        preview_only: bool,
    ) -> Result<()> {
        let Some(cipher) = private_read(&self.directory.join("pending-publication.xgb"), 40000)?
        else {
            return Ok(());
        };
        let plain = open_xgb1(&cipher, self.key.as_ref(), INTENT_CONTEXT)
            .map_err(|_| PublishError::Unavailable)?;
        let intent = SecretJson::parse(&plain).map_err(|_| PublishError::Unavailable)?;
        let expected = intent.as_value()["previous"]
            .as_str()
            .filter(|s| s.is_empty() || s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or(PublishError::Unavailable)?;
        let encoded = intent.as_value()["request"]
            .as_str()
            .filter(|s| s.len() <= 28000)
            .ok_or(PublishError::Unavailable)?;
        let desired = Zeroizing::new(
            STANDARD
                .decode(encoded)
                .map_err(|_| PublishError::Unavailable)?,
        );
        let request =
            decoded(&desired, self.key.as_ref()).map_err(|_| PublishError::Unavailable)?;
        if preview_only && ["apply", "brutal_rate"].iter().any(|v| request.as_value()["action"] == *v) {
            return Err(PublishError::Unavailable);
        }
        let event = audit(request.as_value()).map_err(|_| PublishError::Unavailable)?;
        if intent.as_value()["id"].as_str() != Some(&event.id) {
            return Err(PublishError::Unavailable);
        }
        let current = self.current()?;
        let actual = current
            .as_deref()
            .map_or_else(String::new, |data| digest(data));
        let target = digest(&desired);
        if actual != target {
            if actual != expected {
                return Err(PublishError::Unavailable);
            }
            if now < event.timestamp {
                return Err(PublishError::Unavailable);
            }
            if now.saturating_sub(event.timestamp) > TTL {
                return Err(PublishError::Expired);
            }
            atomic(
                &self.directory.join("request.xgb"),
                &desired,
                &private_meta(),
            )
            .map_err(|_| PublishError::Unavailable)?;
        }
        auditor.record(&event)?;
        fs::remove_file(self.directory.join("pending-publication.xgb"))
            .map_err(|_| PublishError::Unavailable)?;
        sync_directory(&self.directory)
    }
    /// Recover a previously staged publication without overwriting unrelated
    /// state. An expired unsubmitted intent remains blocked for manual review.
    pub fn recover(&self, now: i64, auditor: &mut dyn Auditor) -> Result<()> {
        if now < 0 {
            return Err(PublishError::Invalid);
        }
        let _guard = self.lock()?;
        self.recover_locked(now, auditor, false)
    }
    /// `report` must be obtained from the privileged worker through a trusted
    /// read-only path, never from a browser request. The legacy panel and this
    /// publisher cannot write the same inbox concurrently.
    pub fn submit(
        &self,
        prepared: &Prepared,
        report: &Value,
        now: i64,
        auditor: &mut dyn Auditor,
    ) -> Result<()> {
        self.submit_inner(prepared, report, now, auditor, false)
    }
    /// The experimental HTTP interface cannot publish or recover an apply
    /// request. An older pending apply remains untouched for manual review.
    pub fn submit_preview_only(
        &self,
        prepared: &Prepared,
        report: &Value,
        now: i64,
        auditor: &mut dyn Auditor,
    ) -> Result<()> {
        self.submit_inner(prepared, report, now, auditor, true)
    }
    fn submit_inner(
        &self,
        prepared: &Prepared,
        report: &Value,
        now: i64,
        auditor: &mut dyn Auditor,
        preview_only: bool,
    ) -> Result<()> {
        if now < 0 {
            return Err(PublishError::Invalid);
        }
        let _guard = self.lock()?;
        let value = decoded(prepared.encrypted(), self.key.as_ref())?;
        if preview_only && ["apply", "brutal_rate"].iter().any(|v| value.as_value()["action"] == *v) {
            return Err(PublishError::Invalid);
        }
        self.recover_locked(now, auditor, preview_only)?;
        let status = report["status"].as_str().ok_or(PublishError::Unavailable)?;
        let updated = report["updated"]
            .as_i64()
            .filter(|v| *v >= 0)
            .ok_or(PublishError::Unavailable)?;
        if now.saturating_sub(updated) > 30 || updated > now.saturating_add(60) {
            return Err(PublishError::Unavailable);
        }
        if matches!(status, "verifying" | "applying") {
            return Err(PublishError::Busy);
        }
        if !["idle", "ready", "complete", "failed", "expired"].contains(&status) {
            return Err(PublishError::Unavailable);
        }
        let event = audit(value.as_value())?;
        if event.id != prepared.id()
            || event.timestamp > now
            || now.saturating_sub(event.timestamp) > TTL
        {
            return Err(PublishError::Invalid);
        }
        if value.as_value()["action"] == "apply"
            && (status != "ready"
                || value.as_value()["preview_id"] != report["id"]
                || report["expires"].as_i64().is_none_or(|v| v <= now))
        {
            return Err(PublishError::Busy);
        }
        let current = self.current()?;
        if let Some(existing) = &current {
            let previous =
                decoded(existing, self.key.as_ref()).map_err(|_| PublishError::Unavailable)?;
            let previous_id = previous.as_value()["id"]
                .as_str()
                .ok_or(PublishError::Unavailable)?;
            let timestamp = previous.as_value()["requested_at"]
                .as_i64()
                .ok_or(PublishError::Unavailable)?;
            if previous_id != report["id"].as_str().unwrap_or("")
                && now.saturating_sub(timestamp) <= TTL
            {
                return Err(PublishError::Busy);
            }
        }
        let previous = current
            .as_deref()
            .map_or_else(String::new, |data| digest(data));
        let intent = SecretJson::new(
            json!({"id":event.id,"previous":previous,"request":STANDARD.encode(prepared.encrypted())}),
        );
        let plaintext = Zeroizing::new(
            serde_json::to_vec(intent.as_value()).map_err(|_| PublishError::Unavailable)?,
        );
        let ciphertext = Zeroizing::new(
            seal_xgb1(&plaintext, self.key.as_ref(), INTENT_CONTEXT)
                .map_err(|_| PublishError::Unavailable)?,
        );
        if ciphertext.len() > 40000 {
            return Err(PublishError::Invalid);
        }
        atomic(
            &self.directory.join("pending-publication.xgb"),
            &ciphertext,
            &private_meta(),
        )
        .map_err(|_| PublishError::Unavailable)?;
        self.recover_locked(now, auditor, preview_only)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[derive(Default)]
    struct Audit {
        ids: BTreeSet<String>,
        fail_before: bool,
        fail_after: bool,
    }
    impl Auditor for Audit {
        fn record(&mut self, record: &AuditRecord) -> Result<()> {
            if self.fail_before {
                return Err(PublishError::Unavailable);
            }
            self.ids.insert(record.id.clone());
            if self.fail_after {
                return Err(PublishError::Unavailable);
            }
            Ok(())
        }
    }
    fn prepared(key: &[u8; 32], now: i64) -> Prepared {
        crate::request::prepare(
            &json!({"action":"preview","protocol":"socks","label":"fixture",
            "text":"1.1.1.1:80:synthetic-user:synthetic-password"}),
            now,
            key,
            0,
        )
        .unwrap()
    }
    fn fixture() -> (tempfile::TempDir, PathBuf, [u8; 32]) {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        fs::create_dir(&inbox).unwrap();
        fs::set_permissions(&inbox, fs::Permissions::from_mode(0o700)).unwrap();
        (dir, inbox, [42; 32])
    }
    #[test]
    fn preview_only_never_publishes_a_new_or_recovered_apply() {
        let (_dir, inbox, key) = fixture();
        let publisher = Publisher::open(&inbox, key).unwrap();
        let apply = crate::request::prepare(
            &json!({"action":"apply","preview_id":"a".repeat(32)}),
            1000,
            &key,
            0,
        )
        .unwrap();
        let ready = json!({"status":"ready","updated":1000,"id":"a".repeat(32),"expires":1100});
        let mut audit = Audit::default();
        assert_eq!(
            publisher.submit_preview_only(&apply, &ready, 1000, &mut audit),
            Err(PublishError::Invalid)
        );
        assert!(!inbox.join("request.xgb").exists());
        let intent =
            json!({"id":apply.id(),"previous":"","request":STANDARD.encode(apply.encrypted())});
        let cipher =
            seal_xgb1(&serde_json::to_vec(&intent).unwrap(), &key, INTENT_CONTEXT).unwrap();
        atomic(
            &inbox.join("pending-publication.xgb"),
            &cipher,
            &private_meta(),
        )
        .unwrap();
        let preview = prepared(&key, 1000);
        assert_eq!(
            publisher.submit_preview_only(&preview, &ready, 1000, &mut audit),
            Err(PublishError::Unavailable)
        );
        assert_eq!(
            fs::read(inbox.join("pending-publication.xgb")).unwrap(),
            cipher
        );
        assert!(!inbox.join("request.xgb").exists());
        assert!(audit.ids.is_empty());
    }
    #[test]
    fn recover_completes_audited_publication_without_duplicates_or_secrets() {
        let (_dir, inbox, key) = fixture();
        let publisher = Publisher::open(&inbox, key).unwrap();
        let first = prepared(&key, 1000);
        let mut audit = Audit {
            fail_before: true,
            ..Default::default()
        };
        assert_eq!(
            publisher.submit(
                &first,
                &json!({"status":"idle","updated":1000,"id":""}),
                1000,
                &mut audit
            ),
            Err(PublishError::Unavailable)
        );
        for name in ["request.xgb", "pending-publication.xgb"] {
            let path = inbox.join(name);
            let bytes = fs::read(&path).unwrap();
            assert!(!bytes
                .windows(18)
                .any(|value| value == b"synthetic-password"));
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        audit.fail_before = false;
        publisher.recover(1000, &mut audit).unwrap();
        assert!(!inbox.join("pending-publication.xgb").exists());
        assert_eq!(audit.ids.len(), 1);
        publisher.recover(1000, &mut audit).unwrap();
        assert_eq!(audit.ids.len(), 1);
        let next = prepared(&key, 1001);
        assert_eq!(
            publisher.submit(
                &next,
                &json!({"status":"idle","updated":1001,"id":""}),
                1001,
                &mut audit
            ),
            Err(PublishError::Busy)
        );
        let apply = crate::request::prepare(
            &json!({"action":"apply","preview_id":first.id()}),
            1001,
            &key,
            0,
        )
        .unwrap();
        let ready = json!({"status":"ready","updated":1001,"id":first.id(),"expires":1900});
        audit.fail_after = true;
        assert_eq!(
            publisher.submit(&apply, &ready, 1001, &mut audit),
            Err(PublishError::Unavailable)
        );
        assert_eq!(audit.ids.len(), 2);
        audit.fail_after = false;
        publisher.recover(1001, &mut audit).unwrap();
        assert_eq!(audit.ids.len(), 2);
        assert_eq!(
            decoded(&fs::read(inbox.join("request.xgb")).unwrap(), &key)
                .unwrap()
                .as_value()["id"],
            apply.id()
        );
    }
    #[test]
    fn rejects_stale_or_busy_reports_and_preserves_unrelated_replacements() {
        let (_dir, inbox, key) = fixture();
        let publisher = Publisher::open(&inbox, key).unwrap();
        let mut audit = Audit::default();
        let first = prepared(&key, 1000);
        assert_eq!(
            publisher.submit(
                &first,
                &json!({"status":"idle","updated":969}),
                1000,
                &mut audit
            ),
            Err(PublishError::Unavailable)
        );
        assert_eq!(
            publisher.submit(
                &first,
                &json!({"status":"verifying","updated":1000}),
                1000,
                &mut audit
            ),
            Err(PublishError::Busy)
        );
        publisher
            .submit(
                &first,
                &json!({"status":"idle","updated":1000,"id":""}),
                1000,
                &mut audit,
            )
            .unwrap();
        let second = prepared(&key, 1001);
        audit.fail_before = true;
        assert_eq!(
            publisher.submit(
                &second,
                &json!({"status":"complete","updated":1001,"id":first.id()}),
                1001,
                &mut audit
            ),
            Err(PublishError::Unavailable)
        );
        let unrelated = prepared(&key, 1002);
        atomic(
            &inbox.join("request.xgb"),
            unrelated.encrypted(),
            &private_meta(),
        )
        .unwrap();
        audit.fail_before = false;
        assert_eq!(
            publisher.recover(1002, &mut audit),
            Err(PublishError::Unavailable)
        );
        assert_eq!(
            fs::read(inbox.join("request.xgb")).unwrap(),
            unrelated.encrypted()
        );
        assert!(inbox.join("pending-publication.xgb").exists());
    }
    #[test]
    fn rejects_symlinks_hardlinks_and_expired_unpublished_intents() {
        let (dir, inbox, key) = fixture();
        let publisher = Publisher::open(&inbox, key).unwrap();
        let mut audit = Audit::default();
        let first = prepared(&key, 1000);
        let target = dir.path().join("target");
        fs::write(&target, first.encrypted()).unwrap();
        symlink(&target, inbox.join("request.xgb")).unwrap();
        assert_eq!(
            publisher.submit(
                &first,
                &json!({"status":"idle","updated":1000}),
                1000,
                &mut audit
            ),
            Err(PublishError::Unavailable)
        );
        fs::remove_file(inbox.join("request.xgb")).unwrap();
        fs::hard_link(&target, inbox.join("request.xgb")).unwrap();
        assert_eq!(
            publisher.submit(
                &first,
                &json!({"status":"idle","updated":1000}),
                1000,
                &mut audit
            ),
            Err(PublishError::Unavailable)
        );
        fs::remove_file(inbox.join("request.xgb")).unwrap();
        let intent = SecretJson::new(
            json!({"id":first.id(),"previous":"","request":STANDARD.encode(first.encrypted())}),
        );
        let plain = Zeroizing::new(serde_json::to_vec(intent.as_value()).unwrap());
        let cipher = seal_xgb1(&plain, &key, INTENT_CONTEXT).unwrap();
        atomic(
            &inbox.join("pending-publication.xgb"),
            &cipher,
            &private_meta(),
        )
        .unwrap();
        assert_eq!(
            publisher.recover(2000, &mut audit),
            Err(PublishError::Expired)
        );
        assert!(!inbox.join("request.xgb").exists());
        assert!(inbox.join("pending-publication.xgb").exists());
    }
}
