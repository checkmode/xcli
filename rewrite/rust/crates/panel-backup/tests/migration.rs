use rusqlite::{backup::Backup, Connection};
use xcli_panel_backup::migration::{compare_snapshots, CompareError, Comparison};

fn fixture() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT NOT NULL,uuid TEXT NOT NULL UNIQUE,
            token TEXT NOT NULL UNIQUE,enabled INTEGER NOT NULL,quota INTEGER NOT NULL,
            expires INTEGER NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL,
            created INTEGER NOT NULL,deleted INTEGER NOT NULL);
         CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL);
         CREATE TABLE mfa(id INTEGER PRIMARY KEY,secret TEXT NOT NULL);
         CREATE TABLE recovery_codes(hash TEXT PRIMARY KEY,used INTEGER NOT NULL);
         CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
         CREATE TABLE audit(id INTEGER PRIMARY KEY AUTOINCREMENT,entry TEXT NOT NULL);
         CREATE TABLE history(value BLOB);
         INSERT INTO users VALUES('a','Alice','uuid-a','token-a',1,123,0,50,80,1,0),
                                 ('b','Bob','uuid-b','token-b',0,0,0,20,0,2,1);
         INSERT INTO admin VALUES(1,'password-hash');
         INSERT INTO mfa VALUES(1,'encrypted-secret');
         INSERT INTO recovery_codes VALUES('recovery-hash',0);
         INSERT INTO metadata VALUES('remote_nodes_v1','synthetic-node-secret-and-counters'),
                                    ('rules_v1','synthetic-policy');
         INSERT INTO audit(entry) VALUES('hello');
         INSERT INTO history VALUES(x'00ff'),(NULL),('text'),(1),(1.25),('text');",
    )
    .unwrap();
    db
}

fn copy(db: &Connection) -> Connection {
    let mut dest = Connection::open_in_memory().unwrap();
    let backup = Backup::new(db, &mut dest).unwrap();
    backup.step(-1).unwrap();
    drop(backup);
    dest
}

#[test]
fn consistent_snapshot_compares_all_rows_and_allows_only_increasing_user_usage() {
    let original = fixture();
    let mut before = copy(&original);
    let mut after = copy(&original);
    after
        .execute(
            "UPDATE users SET upload=upload+1, download=download+2 WHERE id='a'",
            [],
        )
        .unwrap();
    assert_eq!(
        compare_snapshots(&mut before, &mut after),
        Ok(Comparison {
            tables: 8,
            users: 2
        })
    );
    assert!(
        after.execute("UPDATE users SET upload=0", []).is_err(),
        "comparison connections must remain read-only"
    );
}

#[test]
fn rejects_identity_auth_rules_nodes_and_history_changes_without_returning_values() {
    for sql in [
        "UPDATE users SET token='different-secret' WHERE id='a'",
        "UPDATE users SET uuid='different' WHERE id='a'",
        "UPDATE users SET name='another-name' WHERE id='a'",
        "DELETE FROM users WHERE id='b'",
        "UPDATE admin SET password='different-secret'",
        "UPDATE mfa SET secret='different-secret'",
        "UPDATE recovery_codes SET used=1",
        "UPDATE metadata SET value='different-node' WHERE key='remote_nodes_v1'",
        "UPDATE metadata SET value='different-rule' WHERE key='rules_v1'",
        "DELETE FROM history WHERE rowid=(SELECT MIN(rowid) FROM history WHERE value='text')",
        "UPDATE sqlite_sequence SET seq=0 WHERE name='audit'",
    ] {
        let original = fixture();
        let mut before = copy(&original);
        let mut after = copy(&original);
        after.execute(sql, []).unwrap();
        assert_eq!(
            compare_snapshots(&mut before, &mut after),
            Err(CompareError::DataChanged),
            "{sql}"
        );
    }
}

#[test]
fn rejects_regressed_or_invalid_usage_and_changed_schema() {
    for sql in [
        "UPDATE users SET upload=49 WHERE id='a'",
        "UPDATE users SET download=-1 WHERE id='b'",
    ] {
        let original = fixture();
        let mut before = copy(&original);
        let mut after = copy(&original);
        after.execute(sql, []).unwrap();
        assert_eq!(
            compare_snapshots(&mut before, &mut after),
            Err(CompareError::UsageDecreased)
        );
    }
    let original = fixture();
    let mut before = copy(&original);
    let mut after = copy(&original);
    after
        .execute("ALTER TABLE users ADD COLUMN unexpected TEXT", [])
        .unwrap();
    assert_eq!(
        compare_snapshots(&mut before, &mut after),
        Err(CompareError::SchemaChanged)
    );
}

#[test]
fn rejects_unsupported_virtual_or_generated_columns() {
    let original = fixture();
    original
        .execute_batch(
            "CREATE TABLE computed(a INTEGER, b INTEGER GENERATED ALWAYS AS (a + 1) VIRTUAL);",
        )
        .unwrap();
    let mut before = copy(&original);
    let mut after = copy(&original);
    assert_eq!(
        compare_snapshots(&mut before, &mut after),
        Err(CompareError::UnsupportedSchema)
    );
}

#[test]
fn handles_identifier_escaping_and_duplicate_rows() {
    let original = fixture();
    original.execute_batch("CREATE TABLE \"odd\"\"table\"(\"odd\"\"column\" BLOB); INSERT INTO \"odd\"\"table\" VALUES('x'),('x'),('y');").unwrap();
    let mut before = copy(&original);
    let mut after = copy(&original);
    assert!(compare_snapshots(&mut before, &mut after).is_ok());
    let mut before = copy(&original);
    let mut after = copy(&original);
    after
        .execute(
            "UPDATE \"odd\"\"table\" SET \"odd\"\"column\"='y' WHERE rowid=1",
            [],
        )
        .unwrap();
    assert_eq!(
        compare_snapshots(&mut before, &mut after),
        Err(CompareError::DataChanged)
    );
}
