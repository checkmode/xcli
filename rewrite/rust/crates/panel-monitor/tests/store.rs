use serde_json::json;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use xcli_panel_monitor::report::{aggregate, Dns, Https, Observation, Outcome, Scope};
use xcli_panel_monitor::{store::Store, Config};

fn fixture() -> Config {
    let input = json!({"domain":"panel.example.com","public_ip":"8.8.8.8","reality_sni":"example.com",
        "reality_public":"fixture-public-key","short_id":"0123456789abcdef",
        "uuid":"11111111-2222-3333-4444-555555555555","ws_path":"/connect/fixture"});
    Config::parse(&serde_json::to_vec(&input).unwrap()).unwrap()
}
fn observations() -> Vec<Observation> {
    ["reality", "websocket"]
        .into_iter()
        .map(|kind| Observation {
            kind: kind.into(),
            finished_at: None,
            outcome: Outcome::Measured {
                https: Https::Ok(1),
                dns: Dns::Ok(2),
            },
        })
        .collect()
}
#[test]
fn report_is_atomic_private_and_recovers_success_history() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let store = Store::open(dir.path()).unwrap();
    assert!(Store::open(dir.path()).is_err());
    assert!(store.load().unwrap().is_none());
    let cfg = fixture();
    let report = aggregate(&cfg, Scope::Server, 100, observations(), None).unwrap();
    store.save(&report).unwrap();
    let path = dir.path().join("report.json");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o640
    );
    let loaded = store.load().unwrap().unwrap();
    assert_eq!(loaded.as_value(), report.as_value());
    assert!(!fs::read_to_string(&path)
        .unwrap()
        .contains("11111111-2222-3333-4444-555555555555"));
    let failures = ["reality", "websocket"]
        .into_iter()
        .map(|kind| Observation {
            kind: kind.into(),
            finished_at: None,
            outcome: Outcome::ClientUnavailable,
        })
        .collect();
    let next = aggregate(&cfg, Scope::Server, 110, failures, Some(loaded.as_value())).unwrap();
    store.save(&next).unwrap();
    assert_eq!(
        store.load().unwrap().unwrap().as_value()["checks"][0]["last_success"],
        100
    );
    drop(store);
    assert!(Store::open(dir.path()).is_ok());
}
#[test]
fn symlinks_and_hardlinks_never_replace_unrelated_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let store = Store::open(dir.path()).unwrap();
    let target = dir.path().join("unrelated");
    fs::write(&target, "untouched").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    let path = dir.path().join("report.json");
    let cfg = fixture();
    let report = aggregate(&cfg, Scope::Server, 100, observations(), None).unwrap();
    symlink(&target, &path).unwrap();
    assert!(store.load().is_err());
    assert!(store.save(&report).is_err());
    fs::remove_file(&path).unwrap();
    fs::hard_link(&target, &path).unwrap();
    assert!(store.load().is_err());
    assert!(store.save(&report).is_err());
    assert_eq!(fs::read_to_string(target).unwrap(), "untouched");
}
