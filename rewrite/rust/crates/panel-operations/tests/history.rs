use rusqlite::{params, Connection};
use serde_json::json;
use xcli_panel_operations::{Error, History};

#[test]
fn history_preserves_existing_data_deduplicates_reports_and_excludes_unknown_from_success_rate() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("panel.sqlite");
    Connection::open(&path).unwrap();
    let mut history = History::open(&path, vec!["reality".into(), "websocket".into()]).unwrap();
    let db = Connection::open(&path).unwrap();
    let now = 2_000_100i64;
    db.execute(
        "INSERT INTO traffic_history VALUES(?,?,?)",
        params![now - 60, 11, 22],
    )
    .unwrap();
    db.execute(
        "INSERT INTO probe_history VALUES(?,?,?,?,?)",
        params![now - 70, "reality", "failed", None::<f64>, None::<f64>],
    )
    .unwrap();
    db.execute(
        "INSERT INTO probe_history VALUES(?,?,?,?,?)",
        params![
            now - 30 * 86400 - 1,
            "reality",
            "failed",
            None::<f64>,
            None::<f64>
        ],
    )
    .unwrap();
    let report = json!({"status":"healthy","updated":now-10,"checks":[
        {"transport":"reality","status":"healthy","https_ms":20,"udp_ms":30,"credential":"never-store"},
        {"transport":"websocket","status":"healthy","https_ms":40,"udp_ms":50}]});
    history.collect(&report, now).unwrap();
    history.collect(&report, now + 10).unwrap();
    let count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM probe_history WHERE ts=?",
            [now - 10],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 2,
        "polling the same report must not multiply observations"
    );
    history.collect(&report, now + 240).unwrap();
    let result = history.query("1h", now + 240).unwrap();
    let reality = result["summary"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["transport"] == "reality")
        .unwrap();
    assert_eq!(
        (
            reality["healthy"].as_i64(),
            reality["failed"].as_i64(),
            reality["unknown"].as_i64()
        ),
        (Some(1), Some(1), Some(1))
    );
    assert_eq!(reality["success_percent"], 50.0);
    assert_eq!(result["traffic"][0]["upload"], 11);
    assert_eq!(result["traffic"][0]["download"], 22);
    assert!(!result.to_string().contains("never-store"));
    let old: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM probe_history WHERE ts<?",
            [now - 30 * 86400],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(old, 0);
    assert_eq!(history.query("invalid", now), Err(Error::Invalid));
}

#[test]
fn duplicate_or_missing_transports_are_unknown_and_future_reports_are_not_recorded_as_healthy() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("panel.sqlite");
    Connection::open(&path).unwrap();
    assert!(matches!(
        History::open(&path, vec!["reality".into(), "reality".into()]),
        Err(Error::Invalid)
    ));
    assert!(matches!(
        History::open(&path, vec!["untrusted".into()]),
        Err(Error::Invalid)
    ));
    let mut history = History::open(&path, vec!["reality".into(), "websocket".into()]).unwrap();
    let now = 2_000_100;
    let duplicate = json!({"status":"healthy","updated":now,"checks":[
        {"transport":"reality","status":"healthy","https_ms":1,"udp_ms":1},
        {"transport":"reality","status":"healthy","https_ms":1,"udp_ms":1}]});
    history.collect(&duplicate, now).unwrap();
    let future = json!({"status":"healthy","updated":now+301,"checks":[
        {"transport":"reality","status":"healthy","https_ms":1,"udp_ms":1}]});
    history.collect(&future, now + 60).unwrap();
    let result = history.query("1h", now + 60).unwrap();
    assert!(result["summary"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["healthy"] == 0
            && row["failed"] == 0
            && row["unknown"] == 2
            && row["success_percent"].is_null()));
}
