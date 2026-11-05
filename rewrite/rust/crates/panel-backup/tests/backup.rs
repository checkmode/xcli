use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::Connection;
use serde_json::{json, Value};
use xcli_auth_compat::open_xgb1;
use xcli_panel_backup::{BackupError, BackupStore};

fn fixture(path: &std::path::Path) {
    let db = Connection::open(path).unwrap();
    db.execute_batch("PRAGMA journal_mode=WAL;
    CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT NOT NULL,uuid TEXT NOT NULL UNIQUE,token TEXT NOT NULL UNIQUE,
      enabled INTEGER NOT NULL,quota INTEGER NOT NULL,expires INTEGER NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL,created INTEGER NOT NULL,deleted INTEGER NOT NULL);
    CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);
    CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL);CREATE TABLE sessions(hash TEXT PRIMARY KEY);
    CREATE TABLE mfa_sessions(hash TEXT PRIMARY KEY);CREATE TABLE device_activity(user_id TEXT NOT NULL,transport TEXT NOT NULL);
    INSERT INTO admin VALUES(1,'current-password-hash');INSERT INTO sessions VALUES('session');INSERT INTO mfa_sessions VALUES('session');
    INSERT INTO users VALUES('active','测试用户','uuid-old','token-old',1,0,0,123,456,10,0);
    INSERT INTO users VALUES('deleted','删除','uuid-del','token-del',0,0,0,0,0,11,1);").unwrap();
}

#[test]
fn offline_restore_keeps_current_credentials_and_usage_floors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.sqlite");
    fixture(&path);
    let settings = json!({"domain":"example.test"});
    let mut store = BackupStore::open(&path, settings.clone(), [7; 32], "1.3.0".into()).unwrap();
    let id = store.create("manual", 1_700_000_000).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let db = Connection::open(&path).unwrap();
    db.execute_batch("UPDATE users SET name='changed',uuid='uuid-new',token='token-new',upload=999,download=200 WHERE id='active';
        UPDATE admin SET password='new-admin-hash';INSERT INTO metadata VALUES('activity_sample','1');
        INSERT INTO device_activity VALUES('active','websocket');
        INSERT INTO users VALUES('later','later user','later-uuid','later-token',1,0,0,50,60,12,0);").unwrap();
    let safety = store
        .restore_with_flush(&id, 1_700_000_001, || Ok(()))
        .unwrap();
    assert_eq!(safety["reason"], "before-restore");
    let restored: (String, String, i64, i64) = db
        .query_row(
            "SELECT name,uuid,upload,download FROM users WHERE id='active'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(restored, ("测试用户".into(), "uuid-old".into(), 999, 456));
    let retired: (i64, i64, i64, i64, String, String) = db
        .query_row(
            "SELECT enabled,deleted,upload,download,uuid,token FROM users WHERE id='later'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!((retired.0, retired.1, retired.2, retired.3), (0, 1, 50, 60));
    assert_ne!(retired.4, "later-uuid");
    assert_ne!(retired.5, "later-token");
    assert_eq!(
        db.query_row("SELECT password FROM admin WHERE id=1", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "new-admin-hash"
    );
    for table in ["sessions", "mfa_sessions", "device_activity"] {
        assert_eq!(
            db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM metadata WHERE key='activity_sample'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    let mut different = BackupStore::open(
        &path,
        json!({"domain":"other.test"}),
        [7; 32],
        "1.3.0".into(),
    )
    .unwrap();
    assert!(!different.inspect(&id).unwrap()["same_server"]
        .as_bool()
        .unwrap());
    let called = std::cell::Cell::new(false);
    assert_eq!(
        different.restore_with_flush(&id, 1_700_000_002, || {
            called.set(true);
            Ok(())
        }),
        Err(BackupError::DifferentServer)
    );
    assert!(!called.get());
}

#[test]
fn changing_brutal_rate_keeps_existing_backups_restorable_without_changing_current_settings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.sqlite");
    fixture(&path);
    let settings = json!({"domain":"example.test","hysteria2_brutal_port":8443});
    let mut before = BackupStore::open(&path, settings.clone(), [7; 32], "1.3.0".into()).unwrap();
    let id = before.create("manual", 1_700_000_000).unwrap()["id"].as_str().unwrap().to_owned();
    let mut current = settings;
    current["hysteria2_brutal_mbps"] = json!(60);
    let mut after = BackupStore::open(&path, current, [7; 32], "1.3.0".into()).unwrap();
    assert_eq!(after.inspect(&id).unwrap()["same_server"], true);
    after.restore_with_flush(&id, 1_700_000_001, || Ok(())).unwrap();
}

#[test]
fn restore_does_not_mutate_state_when_flush_or_transaction_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.sqlite");
    fixture(&path);
    let mut store = BackupStore::open(
        &path,
        json!({"domain":"example.test"}),
        [7; 32],
        "1.3.0".into(),
    )
    .unwrap();
    let id = store.create("manual", 1_700_000_000).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let db = Connection::open(&path).unwrap();
    db.execute("UPDATE users SET upload=999 WHERE id='active'", [])
        .unwrap();
    assert_eq!(
        store.restore_with_flush(&id, 1_700_000_001, || Err(BackupError::Unavailable)),
        Err(BackupError::Unavailable)
    );
    db.execute_batch("CREATE TRIGGER reject_restore BEFORE DELETE ON users BEGIN SELECT RAISE(FAIL,'fail'); END;").unwrap();
    assert_eq!(
        store.restore_with_flush(&id, 1_700_000_002, || Ok(())),
        Err(BackupError::Unavailable)
    );
    assert_eq!(
        db.query_row("SELECT upload FROM users WHERE id='active'", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        999
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM sessions", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(store.list().unwrap().len(), 2);
}

#[test]
fn encrypted_snapshot_can_be_inspected_and_contains_consistent_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.sqlite");
    fixture(&path);
    let settings = json!({"domain":"example.test","origin":"https://example.test"});
    let mut store = BackupStore::open(&path, settings.clone(), [7; 32], "1.3.0".into()).unwrap();
    let created = store.create("manual", 1_700_000_000).unwrap();
    let id = created["id"].as_str().unwrap();
    assert_eq!(created["users"], 1);
    assert_eq!(store.inspect(id).unwrap()["same_server"], true);
    let encrypted = store.download(id).unwrap();
    let plaintext = open_xgb1(&encrypted, &[7; 32], b"xcli:backup:v1").unwrap();
    let bundle: Value = serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(bundle["settings"], settings);
    let restored = dir.path().join("snapshot.sqlite");
    std::fs::write(
        &restored,
        STANDARD
            .decode(bundle["database"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let db = Connection::open(&restored).unwrap();
    assert_eq!(
        db.query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    let usage: (i64, i64) = db
        .query_row(
            "SELECT upload,download FROM users WHERE id='active'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(usage, (123, 456));
    assert_eq!(store.list().unwrap().len(), 1);
    assert!(std::fs::read_dir(dir.path().join("backups"))
        .unwrap()
        .all(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".xgb")));
    assert_eq!(store.inspect("../bad.xgb"), Err(BackupError::NotFound));
}

#[test]
fn tampered_and_wrong_key_backups_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.sqlite");
    fixture(&path);
    let settings = json!({"domain":"example.test"});
    let mut store = BackupStore::open(&path, settings.clone(), [7; 32], "1.3.0".into()).unwrap();
    let id = store.create("manual", 1_700_000_000).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let wrong = BackupStore::open(&path, settings, [8; 32], "1.3.0".into()).unwrap();
    assert_eq!(wrong.inspect(&id), Err(BackupError::Invalid));
    let file = dir.path().join("backups").join(&id);
    let mut bytes = std::fs::read(&file).unwrap();
    bytes[20] ^= 1;
    std::fs::write(file, bytes).unwrap();
    assert_eq!(store.inspect(&id), Err(BackupError::Invalid));
    assert_eq!(store.list().unwrap()[0]["valid"], false);
}

#[test]
fn automatic_backups_keep_recent_valid_files_and_ignore_corrupt_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.sqlite");
    fixture(&path);
    let mut store = BackupStore::open(
        &path,
        json!({"domain":"example.test"}),
        [7; 32],
        "1.3.0".into(),
    )
    .unwrap();
    assert_eq!(store.configure(true, 59, 2), Err(BackupError::Invalid));
    assert_eq!(store.configure(true, 60, 1), Err(BackupError::Invalid));
    store.configure(true, 60, 2).unwrap();
    assert!(store.scheduled(1_700_000_000).unwrap());
    assert!(!store.scheduled(1_700_000_059).unwrap());
    let invalid = dir
        .path()
        .join("backups/1700000001-00000000000000000000000000000000.xgb");
    std::fs::write(&invalid, b"invalid and retained").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    assert!(store.scheduled(1_700_000_060).unwrap());
    std::thread::sleep(std::time::Duration::from_millis(5));
    assert!(store.scheduled(1_700_000_120).unwrap());
    let entries = store.list().unwrap();
    assert_eq!(entries.iter().filter(|v| v["valid"] == true).count(), 2);
    assert_eq!(entries.iter().filter(|v| v["valid"] == false).count(), 1);
    assert!(invalid.exists());
    let status = store.status().unwrap();
    assert_eq!(status["automatic"], true);
    assert_eq!(status["retention_enforced"], true);
    assert_eq!(status["next_backup"], 1_700_000_180);
}

#[test]
fn automatic_backup_failure_records_error_and_retries_after_five_minutes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.sqlite");
    fixture(&path);
    let mut store = BackupStore::open(
        &path,
        json!({"domain":"example.test"}),
        [7; 32],
        "1.3.0".into(),
    )
    .unwrap();
    store.configure(true, 60, 2).unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TRIGGER reject_event BEFORE INSERT ON events BEGIN SELECT RAISE(FAIL,'fail'); END;",
    )
    .unwrap();
    assert_eq!(
        store.scheduled(1_700_000_000),
        Err(BackupError::Unavailable)
    );
    assert!(!store.status().unwrap()["error"]
        .as_str()
        .unwrap()
        .is_empty());
    db.execute_batch("DROP TRIGGER reject_event;").unwrap();
    assert!(!store.scheduled(1_700_000_299).unwrap());
    assert!(store.scheduled(1_700_000_300).unwrap());
    assert_eq!(store.status().unwrap()["error"], "");
}
