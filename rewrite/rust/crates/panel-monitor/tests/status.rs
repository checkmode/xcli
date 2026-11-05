use serde_json::json;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use xcli_panel_monitor::status::{expected, read, view};

#[test]
fn filters_secrets_and_detects_stale_or_incomplete_reports() {
    let settings = json!({"hysteria2_port":443,"residential_exits":[{"tag":"residential-27"},{"tag":"residential-11","dynamic":true}]});
    let tags = expected(&settings).unwrap();
    assert!(!tags.iter().any(|tag| tag == "residential-11"));
    let row = |kind| {
        json!({"transport":kind,"status":"healthy","https_ms":5,"udp_ms":4,"doh_ms":null,
        "udp_supported":true,"last_success":100,"error":"synthetic-secret","unexpected":"synthetic-secret"})
    };
    let report = json!({"schema":1,"scope":"server","updated":100,"status":"healthy","checks":[
        row("reality"),row("websocket"),row("hysteria2"),row("residential-27")],"password":"synthetic-secret"});
    let bytes = serde_json::to_vec(&report).unwrap();
    let result = view(&bytes, &tags, 120);
    assert_eq!(result["status"], "unknown");
    assert_eq!(result["checks"][0]["error"], "探测异常");
    assert!(!serde_json::to_string(&result)
        .unwrap()
        .contains("synthetic-secret"));
    let mut healthy = report.clone();
    for row in healthy["checks"].as_array_mut().unwrap() {
        row["error"] = json!("");
    }
    healthy["checks"][3]["doh_ms"] = json!(4);
    assert_eq!(
        view(&serde_json::to_vec(&healthy).unwrap(), &tags, 120)["status"],
        "healthy"
    );
    assert_eq!(view(&bytes, &tags, 300)["status"], "stale");
    let mut incomplete = report.clone();
    incomplete["checks"].as_array_mut().unwrap().pop();
    assert_eq!(
        view(&serde_json::to_vec(&incomplete).unwrap(), &tags, 120)["status"],
        "unknown"
    );
    let mut duplicated = report;
    duplicated["checks"]
        .as_array_mut()
        .unwrap()
        .push(row("reality"));
    assert_eq!(
        view(&serde_json::to_vec(&duplicated).unwrap(), &tags, 120)["status"],
        "unknown"
    );
}
#[test]
fn refuses_symlinked_or_hardlinked_report_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let target = dir.path().join("unrelated");
    fs::write(&target, b"synthetic").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    let path = dir.path().join("report.json");
    let tags = expected(&json!({})).unwrap();
    symlink(&target, &path).unwrap();
    assert_eq!(read(&path, &tags, 100)["status"], "unknown");
    fs::remove_file(&path).unwrap();
    fs::hard_link(&target, &path).unwrap();
    assert_eq!(read(&path, &tags, 100)["status"], "unknown");
    assert_eq!(fs::read(target).unwrap(), b"synthetic");
}
