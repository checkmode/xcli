use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::{Arc, Barrier};
use xcli_panel_nodes::{NodeSync, SyncError};

const NODE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ONE: &str = "11111111111111111111111111111111";
const TWO: &str = "22222222222222222222222222222222";
const UUID: &str = "01234567-89ab-4def-8123-456789abcdef";
const UUID_TWO: &str = "11234567-89ab-4def-8123-456789abcdef";
fn key() -> String {
    "Z".repeat(43)
}
fn auth() -> String {
    format!("Xcli-Node {NODE}.{}", key())
}
fn fixture(path: &Path) {
    let db = Connection::open(path).unwrap();
    db.execute_batch("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE users(id TEXT PRIMARY KEY,uuid TEXT NOT NULL,enabled INTEGER NOT NULL,deleted INTEGER NOT NULL,
            quota INTEGER NOT NULL,expires INTEGER NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL);
        CREATE TABLE traffic_history(ts INTEGER PRIMARY KEY,upload INTEGER NOT NULL,download INTEGER NOT NULL);
        CREATE TABLE samples(ts INTEGER NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL);").unwrap();
    db.execute(
        "INSERT INTO users VALUES(?,?,1,0,0,0,0,0)",
        params![ONE, UUID],
    )
    .unwrap();
    db.execute(
        "INSERT INTO users VALUES(?,?,1,0,0,0,0,0)",
        params![TWO, UUID_TWO],
    )
    .unwrap();
    let node = json!({"id":NODE,"key_hash":hex::encode(Sha256::digest(key().as_bytes())),"name":"fixture","enabled":true,
        "users":[ONE,TWO],"history":[ONE,TWO],"last_seen":0,"pending_revision":"","applied_revision":"",
        "pending_users":[],"applied_users":[],"counters":{}});
    db.execute(
        "INSERT INTO metadata VALUES('remote_nodes_v1',?)",
        [json!([node]).to_string()],
    )
    .unwrap();
}
fn usage(path: &Path, id: &str) -> (i64, i64) {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT upload,download FROM users WHERE id=?",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}
fn registry(path: &Path) -> Value {
    let data: String = Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT value FROM metadata WHERE key='remote_nodes_v1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    serde_json::from_str(&data).unwrap()
}

#[test]
fn grants_acknowledge_idempotently_and_revoke_on_quota() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    fixture(&path);
    let mut sync = NodeSync::open(&path).unwrap();
    let first = sync
        .sync(&auth(), &json!({"revision":"","counters":[]}), 1000)
        .unwrap();
    assert_eq!(first["users"].as_array().unwrap().len(), 2);
    assert_eq!(first["lease_seconds"], 30);
    let rev = first["revision"].as_str().unwrap();
    assert_eq!(rev.len(), 64);
    let payload = json!({"revision":rev,"counters":[{"id":ONE,"upload":100,"download":200}]});
    let second = sync.sync(&auth(), &payload, 1001).unwrap();
    assert_eq!(second["ack"], payload["counters"]);
    assert_eq!(registry(&path)[0]["applied_revision"], rev);
    assert_eq!(usage(&path, ONE), (100, 200));
    sync.sync(&auth(), &payload, 1002).unwrap();
    assert_eq!(usage(&path, ONE), (100, 200));
    let db = Connection::open(&path).unwrap();
    db.execute("UPDATE users SET quota=350 WHERE id=?", [ONE])
        .unwrap();
    drop(db);
    let next = sync
        .sync(
            &auth(),
            &json!({"revision":rev,"counters":[{"id":ONE,"upload":150,"download":200}]}),
            1003,
        )
        .unwrap();
    assert_eq!(usage(&path, ONE), (150, 200));
    assert_eq!(next["users"].as_array().unwrap().len(), 1);
    assert_eq!(next["users"][0]["id"], TWO);
    assert_ne!(next["revision"], rev);
}

#[test]
fn failures_and_partial_reports_roll_back_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    fixture(&path);
    let mut sync = NodeSync::open(&path).unwrap();
    let before = registry(&path);
    assert_eq!(
        sync.sync("Xcli-Node bad", &json!({"revision":"","counters":[]}), 1000),
        Err(SyncError::Unauthorized)
    );
    let bad = json!({"revision":"","counters":[{"id":ONE,"upload":10,"download":20},{"id":"f".repeat(32),"upload":1,"download":1}]});
    assert_eq!(sync.sync(&auth(), &bad, 1000), Err(SyncError::InvalidInput));
    assert_eq!(usage(&path, ONE), (0, 0));
    assert_eq!(registry(&path), before);
    let duplicate = json!({"revision":"","counters":[{"id":ONE,"upload":10,"download":20},{"id":ONE,"upload":10,"download":20}]});
    assert_eq!(
        sync.sync(&auth(), &duplicate, 1000),
        Err(SyncError::InvalidInput)
    );
    sync.sync(
        &auth(),
        &json!({"revision":"","counters":[{"id":ONE,"upload":10,"download":20}]}),
        1000,
    )
    .unwrap();
    let before = registry(&path);
    assert_eq!(
        sync.sync(
            &auth(),
            &json!({"revision":"","counters":[{"id":ONE,"upload":9,"download":20}]}),
            1001
        ),
        Err(SyncError::CounterRollback)
    );
    assert_eq!(registry(&path), before);
    assert_eq!(usage(&path, ONE), (10, 20));
}

#[test]
fn late_reports_for_a_removed_user_do_not_block_other_users() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    fixture(&path);
    let db = Connection::open(&path).unwrap();
    db.execute("DELETE FROM users WHERE id=?", [ONE]).unwrap();
    drop(db);
    let mut sync = NodeSync::open(&path).unwrap();
    let reports =
        json!([{"id":ONE,"upload":100,"download":200},{"id":TWO,"upload":3,"download":4}]);
    let reply = sync
        .sync(&auth(), &json!({"revision":"","counters":reports}), 1000)
        .unwrap();
    assert_eq!(reply["ack"].as_array().unwrap().len(), 2);
    assert_eq!(usage(&path, TWO), (3, 4));
    assert_eq!(registry(&path)[0]["counters"][ONE]["upload"], 100);
}

#[test]
fn concurrent_duplicate_reports_are_counted_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    fixture(&path);
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut sync = NodeSync::open(&path).unwrap();
                barrier.wait();
                sync.sync(
                    &auth(),
                    &json!({"revision":"","counters":[{"id":ONE,"upload":100,"download":200}]}),
                    1000,
                )
                .is_ok()
            })
        })
        .collect();
    assert!(workers.into_iter().all(|worker| worker.join().unwrap()));
    assert_eq!(usage(&path, ONE), (100, 200));
}
