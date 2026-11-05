use rusqlite::{params, Connection};
use serde_json::json;
use xcli_panel_users::{Repository, StoreError};

#[test]
fn activity_distinguishes_fresh_stale_future_and_deleted_users() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("activity.sqlite");
    let db = Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE users(id TEXT PRIMARY KEY,deleted INTEGER NOT NULL);
        CREATE TABLE device_activity(user_id TEXT NOT NULL,transport TEXT NOT NULL,last_seen INTEGER NOT NULL,
        sampled INTEGER NOT NULL,upload_delta INTEGER NOT NULL,download_delta INTEGER NOT NULL,interval_seconds INTEGER NOT NULL,
        PRIMARY KEY(user_id,transport));").unwrap();
    let id = "a".repeat(32);
    let deleted = "b".repeat(32);
    db.execute("INSERT INTO users VALUES(?,0)", [&id]).unwrap();
    db.execute("INSERT INTO users VALUES(?,1)", [&deleted])
        .unwrap();
    for (user, transport, last, sample, up, down) in [
        (&id, "websocket", 990, 995, 100, 50),
        (&id, "reality", 900, 995, 0, 5),
        (&id, "hysteria2", 0, 995, 0, 0),
        (&id, "stale", 990, 969, 100, 200),
        (&id, "future", 990, 1061, 100, 200),
        (&deleted, "websocket", 990, 995, 100, 100),
    ] {
        db.execute(
            "INSERT INTO device_activity VALUES(?,?,?,?,?,?,5)",
            params![user, transport, last, sample, up, down],
        )
        .unwrap();
    }
    let users = Repository::open(&path).unwrap();
    let value = users.activity(1000).unwrap();
    assert_eq!(value[&id]["websocket"]["status"], "recent");
    assert_eq!(value[&id]["websocket"]["upload_rate"], json!(20.0));
    assert_eq!(value[&id]["reality"]["status"], "idle");
    assert_eq!(value[&id]["hysteria2"]["status"], "never");
    for transport in ["stale", "future"] {
        assert_eq!(value[&id][transport]["status"], "unknown");
        assert_eq!(value[&id][transport]["upload_rate"], json!(0.0));
    }
    assert!(value.get(&deleted).is_none());
    db.execute(
        "UPDATE device_activity SET interval_seconds=0 WHERE user_id=? AND transport='websocket'",
        [&id],
    )
    .unwrap();
    assert_eq!(users.activity(1000), Err(StoreError::Unavailable));
}
