use rusqlite::{params, Connection};
use serde_json::json;
use xcli_panel_traffic::{apply, Counter};
use xcli_panel_users::{Repository, StoreError};

fn database(path: &std::path::Path) {
    Connection::open(path).unwrap().execute_batch("CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT NOT NULL,uuid TEXT NOT NULL UNIQUE,
      token TEXT NOT NULL UNIQUE,enabled INTEGER NOT NULL DEFAULT 1,quota INTEGER NOT NULL DEFAULT 0,
      expires INTEGER NOT NULL DEFAULT 0,upload INTEGER NOT NULL DEFAULT 0,download INTEGER NOT NULL DEFAULT 0,
      created INTEGER NOT NULL,deleted INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);
      CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
      CREATE TABLE counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL,generation TEXT NOT NULL);
      CREATE TABLE device_activity(user_id TEXT NOT NULL,transport TEXT NOT NULL,last_seen INTEGER NOT NULL DEFAULT 0,
        sampled INTEGER NOT NULL DEFAULT 0,upload_delta INTEGER NOT NULL DEFAULT 0,download_delta INTEGER NOT NULL DEFAULT 0,
        interval_seconds INTEGER NOT NULL DEFAULT 5,PRIMARY KEY(user_id,transport));
      CREATE TABLE traffic_history(ts INTEGER PRIMARY KEY,upload INTEGER NOT NULL,download INTEGER NOT NULL);
      CREATE TABLE samples(ts INTEGER NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL);").unwrap();
}
fn counters(id: &str, up: i64, down: i64) -> Vec<Counter> {
    [("uplink", up), ("downlink", down)]
        .into_iter()
        .map(|(direction, value)| Counter {
            name: format!("user>>>{id}.12345678@websocket>>>traffic>>>{direction}"),
            value,
        })
        .collect()
}

#[test]
fn reset_persists_the_counter_baseline_and_counts_only_new_traffic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    database(&path);
    let mut users = Repository::open(&path).unwrap();
    let id = users.create(&json!({"name":"fixture"}), 1).unwrap();
    let other = users.create(&json!({"name":"other"}), 1).unwrap();
    let mut db = Connection::open(&path).unwrap();
    db.execute("UPDATE users SET upload=5,download=7 WHERE id=?", [&id])
        .unwrap();
    db.execute("UPDATE users SET upload=7,download=9 WHERE id=?", [&other])
        .unwrap();
    users.ensure_resettable(&id).unwrap();
    let mut first_sample = counters(&id, 10, 20);
    first_sample.extend(counters(&other, 11, 21));
    users
        .reset_sampled(&id, "1:20", &first_sample, 100, 5)
        .unwrap();
    let read_usage = |db: &Connection| -> (i64, i64) {
        db.query_row(
            "SELECT upload,download FROM users WHERE id=?",
            [&id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
    };
    assert_eq!(read_usage(&db), (0, 0));
    let read_other = |db: &Connection| -> (i64, i64) {
        db.query_row(
            "SELECT upload,download FROM users WHERE id=?",
            [&other],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
    };
    assert_eq!(read_other(&db), (18, 30));
    let mut second_sample = counters(&id, 13, 27);
    second_sample.extend(counters(&other, 15, 26));
    apply(&mut db, "1:20", &second_sample, 105, 5).unwrap();
    assert_eq!(read_usage(&db), (3, 7));
    assert_eq!(read_other(&db), (22, 35));
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM events WHERE action='traffic_reset'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}

#[test]
fn remote_history_corruption_and_failed_audit_never_clear_or_partially_account() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    database(&path);
    let mut users = Repository::open(&path).unwrap();
    let id = users.create(&json!({"name":"fixture"}), 1).unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute("UPDATE users SET upload=5,download=7 WHERE id=?", [&id])
        .unwrap();
    for (metadata, expected) in [
        (
            json!([{ "history": [id] }]).to_string(),
            StoreError::RemoteHistory,
        ),
        (
            json!([{ "history": null }]).to_string(),
            StoreError::Unavailable,
        ),
        ("invalid-json".to_owned(), StoreError::Unavailable),
    ] {
        db.execute(
            "INSERT OR REPLACE INTO metadata VALUES('remote_nodes_v1',?)",
            [metadata],
        )
        .unwrap();
        assert_eq!(users.ensure_resettable(&id), Err(expected));
        assert!(users
            .reset_sampled(&id, "1:20", &counters(&id, 10, 20), 100, 5)
            .is_err());
    }
    db.execute("DELETE FROM metadata WHERE key='remote_nodes_v1'", [])
        .unwrap();
    db.execute_batch("CREATE TRIGGER deny_reset BEFORE INSERT ON events WHEN NEW.action='traffic_reset' BEGIN SELECT RAISE(FAIL,'denied'); END;").unwrap();
    assert_eq!(
        users.reset_sampled(&id, "1:20", &counters(&id, 10, 20), 100, 5),
        Err(StoreError::Unavailable)
    );
    assert_eq!(
        db.query_row(
            "SELECT upload,download FROM users WHERE id=?",
            params![id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        )
        .unwrap(),
        (5, 7)
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM counters", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM traffic_history", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
