use rusqlite::Connection;
use std::time::Duration;
use xcli_panel_auth::AdminAuth;
use xcli_panel_provision::{initialize_empty, ProvisionError};

#[test]
fn fresh_database_supports_legacy_compatible_admin_login() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fresh.sqlite");
    let mut db = Connection::open(&path).unwrap();
    initialize_empty(&mut db, "synthetic-password-123").unwrap();
    assert_eq!(
        db.query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM users", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row(
            "SELECT value FROM metadata WHERE key='operations_history_imported'",
            [],
            |row| row.get::<_, String>(0)
        )
        .unwrap(),
        "1"
    );
    let stored: String = db
        .query_row("SELECT password FROM admin", [], |row| row.get(0))
        .unwrap();
    assert_ne!(stored, "synthetic-password-123");
    drop(db);
    let mut auth = AdminAuth::open(&path, [9; 32]).unwrap();
    assert!(auth
        .login(
            "admin",
            "wrong-password",
            "",
            "127.0.0.1",
            100,
            Duration::ZERO
        )
        .is_err());
    assert!(auth
        .login(
            "admin",
            "synthetic-password-123",
            "",
            "127.0.0.1",
            101,
            Duration::from_secs(1)
        )
        .is_ok());
}

#[test]
fn refuses_existing_data_and_weak_password_without_changing_schema() {
    let mut db = Connection::open_in_memory().unwrap();
    assert_eq!(
        initialize_empty(&mut db, "short"),
        Err(ProvisionError::InvalidPassword)
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM sqlite_schema", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    db.execute_batch("CREATE TABLE existing(value TEXT); INSERT INTO existing VALUES('keep')")
        .unwrap();
    assert_eq!(
        initialize_empty(&mut db, "synthetic-password-123"),
        Err(ProvisionError::AlreadyInitialized)
    );
    assert_eq!(
        db.query_row("SELECT value FROM existing", [], |row| row
            .get::<_, String>(0))
            .unwrap(),
        "keep"
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name='admin'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn read_only_failure_never_leaves_partial_schema() {
    let mut db = Connection::open_in_memory().unwrap();
    db.pragma_update(None, "query_only", "ON").unwrap();
    assert_eq!(
        initialize_empty(&mut db, "synthetic-password-123"),
        Err(ProvisionError::Unavailable)
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM sqlite_schema", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn new_file_is_private_exclusive_and_never_replaces_existing_data() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fresh.sqlite");
    xcli_panel_provision::initialize_new_file(&path, "synthetic-password-123").unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let before = std::fs::read(&path).unwrap();
    assert_eq!(
        xcli_panel_provision::initialize_new_file(&path, "another-password-123"),
        Err(ProvisionError::AlreadyInitialized)
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let link = dir.path().join("existing-link");
    symlink(&path, &link).unwrap();
    assert_eq!(
        xcli_panel_provision::initialize_new_file(&link, "another-password-123"),
        Err(ProvisionError::AlreadyInitialized)
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let insecure = dir.path().join("insecure");
    std::fs::create_dir(&insecure).unwrap();
    std::fs::set_permissions(&insecure, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        xcli_panel_provision::initialize_new_file(
            &insecure.join("bad.sqlite"),
            "synthetic-password-123"
        ),
        Err(ProvisionError::Unavailable)
    );
    assert!(!insecure.join("bad.sqlite").exists());
}
