use rusqlite::{params, Connection};
use xcli_panel_traffic::{apply, apply_in_transaction, AccountingError, Counter};

const USER: &str = "0123456789abcdef0123456789abcdef";
const OTHER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn db() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE users(id TEXT PRIMARY KEY,upload INTEGER NOT NULL DEFAULT 0,download INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL,generation TEXT NOT NULL);
        CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE device_activity(user_id TEXT NOT NULL,transport TEXT NOT NULL,last_seen INTEGER NOT NULL DEFAULT 0,
            sampled INTEGER NOT NULL DEFAULT 0,upload_delta INTEGER NOT NULL DEFAULT 0,download_delta INTEGER NOT NULL DEFAULT 0,
            interval_seconds INTEGER NOT NULL DEFAULT 5,PRIMARY KEY(user_id,transport));
        CREATE TABLE samples(ts INTEGER NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL);
        CREATE TABLE traffic_history(ts INTEGER PRIMARY KEY,upload INTEGER NOT NULL,download INTEGER NOT NULL);").unwrap();
    db.execute("INSERT INTO users(id) VALUES(?)", [USER])
        .unwrap();
    db
}
fn counter(id: &str, tag: &str, direction: &str, value: i64) -> Counter {
    Counter {
        name: format!("user>>>{id}.abcdef01@{tag}>>>traffic>>>{direction}"),
        value,
    }
}
fn usage(db: &Connection) -> (i64, i64) {
    db.query_row(
        "SELECT upload,download FROM users WHERE id=?",
        [USER],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .unwrap()
}

#[test]
fn cumulative_and_generation_changes_do_not_double_count() {
    let mut db = db();
    let batch = |up, down| {
        vec![
            counter(USER, "reality", "uplink", up),
            counter(USER, "reality", "downlink", down),
        ]
    };
    assert_eq!(
        apply(&mut db, "1:10", &batch(100, 200), 1000, 5).unwrap(),
        (100, 200)
    );
    assert_eq!(usage(&db), (100, 200));
    let activity: (i64, i64, i64) = db
        .query_row(
            "SELECT upload_delta,download_delta,last_seen FROM device_activity",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(activity, (0, 0, 0));
    assert_eq!(
        apply(&mut db, "1:10", &batch(100, 200), 1005, 5).unwrap(),
        (0, 0)
    );
    assert_eq!(
        apply(&mut db, "1:10", &batch(180, 250), 1010, 5).unwrap(),
        (80, 50)
    );
    assert_eq!(usage(&db), (180, 250));
    let activity: (i64, i64, i64) = db
        .query_row(
            "SELECT upload_delta,download_delta,last_seen FROM device_activity",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(activity, (80, 50, 1010));
    assert_eq!(
        apply(&mut db, "2:11", &batch(250, 1), 1015, 5).unwrap(),
        (250, 1)
    );
    assert_eq!(usage(&db), (430, 251));
    let history: (i64, i64) = db
        .query_row(
            "SELECT SUM(upload),SUM(download) FROM traffic_history",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(history, (430, 251));
}

#[test]
fn ignores_invalid_counters_and_maps_residential_activity() {
    let mut db = db();
    let mut batch = vec![
        counter(USER, "residential-01", "uplink", 3),
        counter(USER, "residential-01-hy2", "downlink", 5),
        counter(OTHER, "vmess", "uplink", 7),
        counter(USER, "websocket", "uplink", -1),
        counter(USER, "unknown", "uplink", 999),
    ];
    batch.push(Counter {
        name: "user>>>bad".into(),
        value: 100,
    });
    assert_eq!(apply(&mut db, "core", &batch, 1000, 5).unwrap(), (10, 5));
    assert_eq!(usage(&db), (3, 5));
    batch[0].value = 13;
    batch[1].value = 25;
    batch[2].value = 7;
    assert_eq!(apply(&mut db, "core", &batch, 1005, 5).unwrap(), (10, 20));
    let entries = db
        .prepare(
            "SELECT transport,upload_delta,download_delta FROM device_activity ORDER BY transport",
        )
        .unwrap()
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        entries,
        vec![("hysteria2".into(), 0, 20), ("websocket".into(), 10, 0)]
    );
}

#[test]
fn optional_brutal_entry_counts_toward_the_same_user_and_hysteria_activity() {
    let mut db = db();
    let sample = vec![
        counter(USER, "hysteria2", "downlink", 100),
        counter(USER, "hysteria2-brutal", "downlink", 200),
    ];
    assert_eq!(apply(&mut db, "core", &sample, 1000, 5).unwrap(), (0, 300));
    assert_eq!(usage(&db), (0, 300));
    assert_eq!(apply(&mut db, "core", &sample, 1005, 5).unwrap(), (0, 0));
    let second = vec![
        counter(USER, "hysteria2", "downlink", 130),
        counter(USER, "hysteria2-brutal", "downlink", 270),
    ];
    assert_eq!(apply(&mut db, "core", &second, 1010, 5).unwrap(), (0, 100));
    assert_eq!(usage(&db), (0, 400));
    let activity: (String, i64) = db
        .query_row(
            "SELECT transport,download_delta FROM device_activity",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(activity, ("hysteria2".into(), 100));
}

#[test]
fn overflow_or_bad_state_rolls_back_the_entire_sample() {
    let mut db = db();
    db.execute(
        "UPDATE users SET upload=? WHERE id=?",
        params![i64::MAX, USER],
    )
    .unwrap();
    assert_eq!(
        apply(
            &mut db,
            "core",
            &[counter(USER, "reality", "uplink", 1)],
            1000,
            5
        ),
        Err(AccountingError::Unavailable)
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM counters", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM metadata", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    db.execute("UPDATE users SET upload=0 WHERE id=?", [USER])
        .unwrap();
    db.execute(
        "INSERT INTO metadata VALUES('activity_sample','broken')",
        [],
    )
    .unwrap();
    assert_eq!(
        apply(
            &mut db,
            "core",
            &[counter(USER, "reality", "uplink", 1)],
            1000,
            5
        ),
        Err(AccountingError::Unavailable)
    );
    assert_eq!(usage(&db), (0, 0));
    assert_eq!(
        db.query_row("SELECT count(*) FROM samples", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn counter_reset_counts_new_value_and_preserves_history() {
    let mut db = db();
    assert_eq!(
        apply(
            &mut db,
            "core",
            &[counter(USER, "reality", "uplink", 100)],
            1000,
            5
        )
        .unwrap(),
        (100, 0)
    );
    assert_eq!(
        apply(
            &mut db,
            "core",
            &[counter(USER, "reality", "uplink", 5)],
            1005,
            5
        )
        .unwrap(),
        (5, 0)
    );
    assert_eq!(usage(&db), (105, 0));
    assert_eq!(
        db.query_row("SELECT upload FROM traffic_history", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        105
    );
}

#[test]
fn caller_can_atomically_combine_accounting_with_user_changes() {
    let mut db = db();
    {
        let tx = db.transaction().unwrap();
        tx.execute("UPDATE users SET upload=20 WHERE id=?", [USER])
            .unwrap();
        apply_in_transaction(
            &tx,
            "core",
            &[counter(USER, "reality", "uplink", 5)],
            1000,
            5,
        )
        .unwrap();
        assert_eq!(
            tx.query_row("SELECT upload FROM users WHERE id=?", [USER], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            25
        );
        // The caller aborts its larger unit of work, including the sample.
    }
    assert_eq!(usage(&db), (0, 0));
    assert_eq!(
        db.query_row("SELECT count(*) FROM counters", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}
