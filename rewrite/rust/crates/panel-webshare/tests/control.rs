use serde_json::{json, Value};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use xcli_auth_compat::open_xgb1;
use xcli_panel_webshare::{ActiveSnapshot, AuditRecord, Auditor, Control, Error, REGIONS};

#[derive(Default)]
struct FixtureAudit {
    operations: std::collections::BTreeSet<String>,
    fail_before: bool,
    fail_after: bool,
}
impl Auditor for FixtureAudit {
    fn record(&mut self, record: &AuditRecord) -> Result<(), Error> {
        if self.fail_before {
            return Err(Error::Unavailable);
        }
        self.operations.insert(record.id.clone());
        if self.fail_after {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
}

fn config(root: &std::path::Path, key: &[u8; 32]) -> Value {
    let encrypted = std::fs::read(root.join("webshare/config.xgb")).unwrap();
    assert!(encrypted.starts_with(b"XGB1"));
    let data = open_xgb1(&encrypted, key, b"xcli:webshare:config:v1").unwrap();
    serde_json::from_slice(&data).unwrap()
}

#[test]
fn configuration_is_encrypted_and_status_only_exposes_approved_fields() {
    let dir = tempfile::tempdir().unwrap();
    let key = [7; 32];
    let settings = json!({"residential_exits":[{"dynamic":true,"country":"US"},{"dynamic":true,"country":"JP"}]});
    let control = Control::open(dir.path(), settings, key).unwrap();
    let status = control.status(1_700_000_000).unwrap();
    assert_eq!(status["key_saved"], false);
    assert_eq!(status["status"], "unknown");
    assert_eq!(status["regions"].as_array().unwrap().len(), 2);
    let secret = "synthetic-api-token-123456";
    assert!(matches!(
        control.configure(&json!({"api_key":"short"}), 1_700_000_000),
        Err(Error::Invalid(_))
    ));
    control
        .configure(&json!({ "api_key": secret }), 1_700_000_000)
        .unwrap();
    assert_eq!(config(dir.path(), &key)["api_key"], secret);
    let encrypted = std::fs::read(dir.path().join("webshare/config.xgb")).unwrap();
    assert!(!encrypted
        .windows(secret.len())
        .any(|window| window == secret.as_bytes()));
    assert_eq!(
        std::fs::metadata(dir.path().join("webshare"))
            .unwrap()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(dir.path().join("webshare/config.xgb"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    assert!(matches!(
        control.configure(&json!({"enabled":true}), 1_700_000_001),
        Err(Error::Invalid(_))
    ));
    let report = json!({"updated":1_700_000_000,"status":"healthy","api_key":secret,
        "plans":[{"id":17,"eligible":true,"label":"住宅","password":secret}],
        "pools":[{"country":"US","exit_ip":"8.8.8.8","username":secret},{"country":"XX","username":secret}],
        "events":[{"country":"US","ts":1_700_000_000,"reason":"ready","private":secret}]});
    std::fs::write(
        dir.path().join("webshare/report.json"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    let status = control.status(1_700_000_001).unwrap();
    assert!(status["key_saved"].as_bool().unwrap());
    assert!(!status.to_string().contains(secret));
    assert_eq!(status["plans"].as_array().unwrap().len(), 1);
    assert_eq!(status["pools"].as_array().unwrap().len(), 1);
    assert!(matches!(
        control.configure(&json!({"plan_id":18,"enabled":true}), 1_700_000_001),
        Err(Error::Invalid(_))
    ));
    control
        .configure(&json!({"plan_id":17,"enabled":true}), 1_700_000_001)
        .unwrap();
    assert_eq!(control.status(1_700_000_001).unwrap()["enabled"], true);
    control
        .request(&json!({"action":"rotate","country":"US"}), 1_700_000_002)
        .unwrap();
    let pending = config(dir.path(), &key);
    assert_eq!(pending["country"], "US");
    assert_eq!(pending["action"], "rotate");
    control
        .configure(&json!({"clear_key":true}), 1_700_000_003)
        .unwrap();
    let pending = config(dir.path(), &key);
    assert_eq!(pending["api_key"], "");
    assert_eq!(pending["plan_id"], 0);
    assert_eq!(pending["enabled"], false);
    assert!(pending.get("action").is_none());
    assert!(pending.get("country").is_none());
    assert_eq!(control.status(1_700_000_100).unwrap()["status"], "stale");
}

#[test]
fn bad_key_tampering_and_unsafe_directory_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let key = [3; 32];
    let control = Control::open(dir.path(), json!({}), key).unwrap();
    control
        .configure(
            &json!({"api_key":"synthetic-api-key-for-test"}),
            1_700_000_000,
        )
        .unwrap();
    let wrong = Control::open(dir.path(), json!({}), [4; 32]).unwrap();
    assert_eq!(wrong.status(1_700_000_000), Err(Error::Unavailable));
    let path = dir.path().join("webshare/config.xgb");
    let original = std::fs::read(&path).unwrap();
    let mut corrupt = original.clone();
    corrupt[20] ^= 1;
    std::fs::write(&path, corrupt).unwrap();
    assert_eq!(control.status(1_700_000_000), Err(Error::Unavailable));
    assert_eq!(
        control.configure(&json!({"clear_key":true}), 1_700_000_001),
        Err(Error::Unavailable)
    );
    std::fs::write(&path, original).unwrap();
    std::fs::set_permissions(
        dir.path().join("webshare"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert_eq!(control.status(1_700_000_000), Err(Error::Unavailable));
    std::fs::set_permissions(
        dir.path().join("webshare"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::remove_file(&path).unwrap();
    symlink("/etc/passwd", &path).unwrap();
    assert_eq!(control.status(1_700_000_000), Err(Error::Unavailable));
}

#[test]
fn symlinked_state_directory_is_never_followed() {
    let state = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), state.path().join("webshare")).unwrap();
    let control = Control::open(state.path(), json!({}), [0; 32]).unwrap();
    assert_eq!(control.status(1_700_000_000), Err(Error::Unavailable));
    assert_eq!(
        control.configure(
            &json!({"api_key":"synthetic-api-key-for-test"}),
            1_700_000_000
        ),
        Err(Error::Unavailable)
    );
    assert!(!outside.path().join("config.xgb").exists());
}

#[test]
fn symlinked_control_lock_is_never_followed() {
    let state = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let directory = state.path().join("webshare");
    std::fs::DirBuilder::new().create(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = outside.path().join("target");
    std::fs::write(&target, b"fixture").unwrap();
    symlink(&target, directory.join("control.lock")).unwrap();
    let control = Control::open(state.path(), json!({}), [0; 32]).unwrap();
    assert_eq!(
        control.configure(&json!({"api_key":"synthetic-api-key-for-test"}), 1000),
        Err(Error::Unavailable)
    );
    assert_eq!(std::fs::read(target).unwrap(), b"fixture");
}

#[test]
fn worker_lease_excludes_another_worker_until_released() {
    let state = tempfile::tempdir().unwrap();
    let first = Control::open(state.path(), json!({}), [0; 32]).unwrap();
    let second = Control::open(state.path(), json!({}), [0; 32]).unwrap();
    let lease = first.worker_lease().unwrap();
    assert!(matches!(second.worker_lease(), Err(Error::Unavailable)));
    drop(lease);
    assert!(second.worker_lease().is_ok());
}

#[test]
fn recovery_without_a_pending_operation_does_not_create_a_state_directory() {
    let state = tempfile::tempdir().unwrap();
    let control = Control::open(state.path(), json!({}), [0; 32]).unwrap();
    control.recover(&mut FixtureAudit::default()).unwrap();
    assert!(!state.path().join("webshare").exists());
}

#[test]
fn audited_configuration_recovers_after_failures_without_duplicate_events() {
    let state = tempfile::tempdir().unwrap();
    let control = Control::open(state.path(), json!({}), [8; 32]).unwrap();
    let mut audit = FixtureAudit {
        fail_before: true,
        ..FixtureAudit::default()
    };
    let secret = "synthetic-api-key-for-test";
    assert_eq!(
        control.configure_audited(&json!({ "api_key": secret }), 1000, &mut audit),
        Err(Error::Unavailable)
    );
    let pending = state.path().join("webshare/pending.xgb");
    let data = std::fs::read(&pending).unwrap();
    assert!(!data
        .windows(secret.len())
        .any(|value| value == secret.as_bytes()));
    assert_eq!(control.status(1000), Err(Error::Unavailable));
    assert_eq!(
        control.configure(&json!({"clear_key":true}), 1000),
        Err(Error::Unavailable)
    );
    audit.fail_before = false;
    control.recover(&mut audit).unwrap();
    assert_eq!(control.status(1000).unwrap()["key_saved"], true);
    assert_eq!(audit.operations.len(), 1);
    assert!(!pending.exists());
    audit.fail_after = true;
    assert_eq!(
        control.request_audited(&json!({"action":"sync"}), 1001, &mut audit),
        Err(Error::Unavailable)
    );
    assert_eq!(audit.operations.len(), 2);
    assert_eq!(control.status(1001), Err(Error::Unavailable));
    audit.fail_after = false;
    control.recover(&mut audit).unwrap();
    control.recover(&mut audit).unwrap();
    assert_eq!(audit.operations.len(), 2);
    assert!(!pending.exists());
}

#[test]
fn registry_has_stable_unique_countries_and_ports() {
    let mut countries = std::collections::BTreeSet::new();
    let mut ports = std::collections::BTreeSet::new();
    for region in &REGIONS {
        assert!(countries.insert(region.country));
        assert!(ports.insert(region.socks_port));
    }
    assert_eq!(REGIONS.len(), 16);
    assert_eq!(REGIONS[0].tag, "residential-11");
    assert_eq!(REGIONS[0].socks_port, 10120);
}

#[test]
fn encrypted_active_snapshot_retains_credentials_and_discards_expired_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let key = [5; 32];
    let control = Control::open(dir.path(), json!({}), key).unwrap();
    assert!(control.load_active(&["US", "JP"], 1000).unwrap().is_none());
    let state = json!({"active":{"enabled":true,"plan_id":17,"api_key":"synthetic-api-key-for-test",
        "credentials":{"base":"fixture","password":"synthetic-password"}},"processed_revision":"revision","plans":[{"id":17}],
        "pools":{"US":[{"username":"fixture-us-1","expires_at":999},{"username":"fixture-us-2","expires_at":2000,"last_success":990}],
            "JP":[{"username":"fixture-jp-3","expires_at":2500}],"HK":[{"username":"fixture-hk-4","expires_at":2500}]}});
    let snapshot = ActiveSnapshot::from_value(state, &["US", "JP"], 1000).unwrap();
    assert_eq!(
        snapshot.as_value()["pools"]["US"].as_array().unwrap().len(),
        1
    );
    assert!(snapshot.as_value()["pools"].get("HK").is_none());
    control.save_active(&snapshot).unwrap();
    let encrypted = std::fs::read(dir.path().join("webshare/active.xgb")).unwrap();
    assert!(encrypted.starts_with(b"XGB1"));
    assert!(!encrypted
        .windows(18)
        .any(|bytes| bytes == b"synthetic-password"));
    let loaded = control.load_active(&["US", "JP"], 1000).unwrap().unwrap();
    assert_eq!(loaded.as_value(), snapshot.as_value());
    let wrong = Control::open(dir.path(), json!({}), [6; 32]).unwrap();
    assert!(matches!(
        wrong.load_active(&["US"], 1000),
        Err(Error::Unavailable)
    ));
    assert!(matches!(
        ActiveSnapshot::from_value(json!({}), &["US"], 1000),
        Err(Error::Unavailable)
    ));
}
