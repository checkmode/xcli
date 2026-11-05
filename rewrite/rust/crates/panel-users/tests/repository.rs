use rusqlite::{params, Connection};
use serde_json::json;
use std::path::Path;
use std::sync::{Arc, Barrier};
use xcli_panel_users::{Repository, StoreError};

fn fixture(path: &Path) {
    let db = Connection::open(path).unwrap();
    db.execute_batch("CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT NOT NULL,uuid TEXT NOT NULL UNIQUE,
        token TEXT NOT NULL UNIQUE,enabled INTEGER NOT NULL DEFAULT 1,quota INTEGER NOT NULL DEFAULT 0,
        expires INTEGER NOT NULL DEFAULT 0,upload INTEGER NOT NULL DEFAULT 0,download INTEGER NOT NULL DEFAULT 0,
        created INTEGER NOT NULL,deleted INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);").unwrap();
}

fn credentials(path: &Path, id: &str) -> (String, String, i64, i64) {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT uuid,token,enabled,deleted FROM users WHERE id=?",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap()
}

#[test]
fn create_update_rotate_and_delete_are_transactional() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.sqlite");
    fixture(&path);
    let mut store = Repository::open(&path).unwrap();
    let id = store
        .create(&json!({"name":"  测试  ","quota":100}), 100)
        .unwrap();
    assert_eq!(id.len(), 32);
    let before = credentials(&path, &id);
    assert_eq!(before.0.len(), 36);
    assert_eq!(before.1.len(), 43);
    assert_eq!(store.list(101).unwrap()[0].name, "测试");
    store
        .update(&id, &json!({"name":"new","enabled":false,"quota":500}), 102)
        .unwrap();
    let listed = store.list(103).unwrap();
    assert_eq!(listed[0].status, "disabled");
    assert_eq!(listed[0].quota, 500);
    store.rotate(&id, 104).unwrap();
    let rotated = credentials(&path, &id);
    assert_ne!(before.0, rotated.0);
    assert_ne!(before.1, rotated.1);
    store.delete(&id, 105).unwrap();
    let deleted = credentials(&path, &id);
    assert_eq!(deleted.0, rotated.0);
    assert_ne!(deleted.1, rotated.1);
    assert_eq!((deleted.2, deleted.3), (0, 1));
    assert!(store.list(106).unwrap().is_empty());
    assert_eq!(store.rotate(&id, 106), Err(StoreError::NotFound));
    let db = Connection::open(path).unwrap();
    let actions = db
        .prepare("SELECT action FROM events ORDER BY id")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        actions,
        vec![
            "user_created",
            "user_updated",
            "credentials_rotated",
            "user_deleted"
        ]
    );
}

#[test]
fn failed_audit_rolls_back_user_creation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.sqlite");
    fixture(&path);
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TRIGGER deny_event BEFORE INSERT ON events BEGIN SELECT RAISE(FAIL,'denied'); END;",
    )
    .unwrap();
    drop(db);
    let mut store = Repository::open(&path).unwrap();
    assert_eq!(
        store.create(&json!({"name":"test"}), 1),
        Err(StoreError::Unavailable)
    );
    assert!(store.list(1).unwrap().is_empty());
}

#[test]
fn concurrent_creates_cannot_exceed_limit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.sqlite");
    fixture(&path);
    let mut db = Connection::open(&path).unwrap();
    let tx = db.transaction().unwrap();
    for i in 0..499 {
        tx.execute(
            "INSERT INTO users(id,name,uuid,token,created) VALUES(?,?,?,?,0)",
            params![
                format!("{i:032x}"),
                "fixture",
                format!("uuid-{i}"),
                format!("token-{i}")
            ],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    drop(db);
    let gate = Arc::new(Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let path = path.clone();
            let gate = gate.clone();
            std::thread::spawn(move || {
                let mut store = Repository::open(&path).unwrap();
                gate.wait();
                store.create(&json!({"name":"new"}), 1)
            })
        })
        .collect();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == Err(StoreError::Limit))
            .count(),
        1
    );
    assert_eq!(Repository::open(&path).unwrap().list(1).unwrap().len(), 500);
}

#[cfg(unix)]
#[test]
fn rejects_symlink_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.sqlite");
    fixture(&path);
    let link = dir.path().join("link.sqlite");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(matches!(
        Repository::open(&link),
        Err(StoreError::Unavailable)
    ));
}
