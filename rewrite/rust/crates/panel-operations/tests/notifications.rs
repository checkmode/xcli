use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{params, Connection};
use std::collections::BTreeMap;
use xcli_auth_compat::seal_xgb1;
use xcli_panel_operations::{
    alarm::Transition, notifications::Notifications, webhook::Delivery, Error,
};

fn setup() -> (tempfile::TempDir, Connection, Notifications) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("panel.sqlite");
    let db = Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);").unwrap();
    let key = [7; 32];
    let notify = Notifications::open(
        &path,
        key,
        "fixture.example",
        BTreeMap::from([("reality".into(), "REALITY 入口".into())]),
    )
    .unwrap();
    let seal = |field: &str, text: &str| {
        STANDARD.encode(
            seal_xgb1(
                text.as_bytes(),
                &key,
                format!("xcli:webhook:{field}:v1").as_bytes(),
            )
            .unwrap(),
        )
    };
    db.execute("UPDATE notification_config SET enabled=1,url=?,bearer=?,signing=?,generation='generation-1',failures=2,recoveries=2 WHERE id=1",
        params![seal("url","https://example.com/synthetic-path"),seal("bearer","fixture-bearer"),seal("signing","fixture-signing-secret")]).unwrap();
    (dir, db, notify)
}
#[test]
fn alarm_outbox_is_atomic_deduplicated_and_supersedes_obsolete_faults() {
    let (_dir, db, mut notify) = setup();
    let view = notify.status().unwrap();
    assert_eq!(view["destination"], "example.com");
    assert_eq!(view["configured"], true);
    assert_eq!(view["has_bearer"], true);
    assert_eq!(view["has_signing_secret"], true);
    assert!(!view.to_string().contains("synthetic-path"));
    assert!(!view.to_string().contains("fixture-bearer"));
    assert_eq!(notify.observe("reality", true, 1, 100).unwrap(), None);
    assert_eq!(notify.observe("reality", true, 1, 120).unwrap(), None);
    assert_eq!(
        notify.observe("reality", true, 2, 160).unwrap(),
        Some(Transition::Fault { started: 100 })
    );
    let fault = notify.next(160).unwrap().unwrap();
    let fault_id = fault.id().to_owned();
    let raw: String = db
        .query_row(
            "SELECT payload FROM notifications WHERE id=?",
            [&fault_id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!raw.contains("fixture-bearer"));
    assert!(!raw.contains("synthetic-path"));
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(value["event"], "fault");
    assert_eq!(value["duration_seconds"], 60);
    let fail = Delivery {
        status: 503,
        error: Some("untrusted external response".into()),
    };
    assert!(notify.finish(&fault, &fail, 160).unwrap());
    db.execute(
        "UPDATE notifications SET last_error='synthetic-private-secret' WHERE id=?",
        [&fault_id],
    )
    .unwrap();
    assert!(!notify
        .status()
        .unwrap()
        .to_string()
        .contains("synthetic-private-secret"));
    assert!(!notify.finish(&fault, &fail, 160).unwrap());
    assert!(notify.next(189).unwrap().is_none());
    let retry = notify.next(190).unwrap().unwrap();
    assert_eq!(retry.id(), fault_id);
    db.execute(
        "UPDATE notification_config SET generation='generation-2' WHERE id=1",
        [],
    )
    .unwrap();
    assert!(
        !notify.finish(&retry, &fail, 190).unwrap(),
        "old destination must not update a new generation"
    );
    db.execute(
        "UPDATE notification_config SET generation='generation-1' WHERE id=1",
        [],
    )
    .unwrap();
    assert_eq!(notify.observe("reality", false, 3, 220).unwrap(), None);
    assert_eq!(
        notify.observe("reality", false, 4, 280).unwrap(),
        Some(Transition::Recovery { started: 100 })
    );
    let old: String = db
        .query_row(
            "SELECT status FROM notifications WHERE id=?",
            [fault_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(old, "superseded");
    let recovery = notify.next(280).unwrap().unwrap();
    let ok = Delivery {
        status: 204,
        error: None,
    };
    assert!(notify.finish(&recovery, &ok, 280).unwrap());
    assert!(notify.next(281).unwrap().is_none());
    let events: Vec<String> = db
        .prepare("SELECT action FROM events ORDER BY id")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(events, ["fault_detected", "fault_recovered"]);
    assert_eq!(
        notify.observe("unknown-service", true, 1, 100),
        Err(Error::Invalid)
    );
}
#[test]
fn retry_limit_and_authentication_fail_closed() {
    let (_dir, db, mut notify) = setup();
    notify.observe("backup", true, 1, 100).unwrap();
    let mut now = 100;
    let delays = [Some(30), Some(120), Some(600), Some(1800), Some(3600), None];
    for delay in delays {
        let pending = notify.next(now).unwrap().unwrap();
        assert!(notify
            .finish(
                &pending,
                &Delivery {
                    status: 0,
                    error: Some("failed".into())
                },
                now
            )
            .unwrap());
        if let Some(delay) = delay {
            now += delay;
        }
    }
    assert!(notify.next(now + 1).unwrap().is_none());
    let (status, attempts): (String, i64) = db
        .query_row("SELECT status,attempts FROM notifications", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((status.as_str(), attempts), ("failed", 6));
    notify.observe("backup", false, 2, now + 60).unwrap();
    db.execute(
        "UPDATE notification_config SET bearer='tampered' WHERE id=1",
        [],
    )
    .unwrap();
    assert!(matches!(notify.next(now + 60), Err(Error::Unavailable)));
}

#[test]
fn configuration_reencrypts_preserves_existing_and_invalidates_stale_queue_atomically() {
    use serde_json::json;
    use xcli_panel_operations::notifications::ConfigureError;
    let (_dir, mut db, mut notify) = setup();
    notify.observe("reality", true, 1, 100).unwrap();
    notify.observe("reality", true, 2, 160).unwrap();
    let first = notify.next(160).unwrap().unwrap();
    let first_id = first.id().to_owned();
    {
        let tx = db.transaction().unwrap();
        let error = notify.configure(
            &tx,
            &json!({"enabled":true,"url":"https://127.0.0.1/private"}),
            170,
        );
        assert!(matches!(error, Err(ConfigureError::Invalid(_))));
    }
    let status: String = db
        .query_row(
            "SELECT status FROM notifications WHERE id=?",
            [&first_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status, "pending");
    {
        let tx = db.transaction().unwrap();
        notify.configure(&tx,&json!({"enabled":true,"url":"https://new.example.net/hook?token=new-synthetic-secret","failures":4,"recoveries":3}),180).unwrap();
        tx.commit().unwrap();
    }
    let status: String = db
        .query_row(
            "SELECT status FROM notifications WHERE id=?",
            [first_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status, "cancelled");
    let view = notify.status().unwrap();
    assert_eq!(view["destination"], "new.example.net");
    assert_eq!(view["has_bearer"], true);
    assert_eq!(view["has_signing_secret"], true);
    assert_eq!(view["failures"], 4);
    assert_eq!(view["recoveries"], 3);
    assert!(!view.to_string().contains("new-synthetic-secret"));
    assert!(
        notify.next(180).unwrap().is_some(),
        "a firing alarm must be requeued for the new destination"
    );
    let stored: String = db
        .query_row("SELECT url FROM notification_config WHERE id=1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(!stored.contains("new-synthetic-secret"));
    {
        let tx = db.transaction().unwrap();
        notify
            .configure(&tx, &json!({"clear_url":true}), 200)
            .unwrap();
        tx.commit().unwrap();
    }
    let view = notify.status().unwrap();
    assert_eq!(view["enabled"], false);
    assert_eq!(view["configured"], false);
    assert_eq!(view["has_bearer"], false);
    assert_eq!(view["has_signing_secret"], false);
    assert!(notify.next(200).unwrap().is_none());
}

#[test]
fn monitor_collection_is_atomic_and_unknown_never_clears_an_active_fault() {
    use serde_json::json;
    let (dir, db, mut notify) = setup();
    let _history = xcli_panel_operations::History::open(
        &dir.path().join("panel.sqlite"),
        vec!["reality".into()],
    )
    .unwrap();
    let report = |stamp, state| json!({"status":state,"updated":stamp,"checks":[{"transport":"reality","status":state}]});
    notify
        .collect_with_history(&report(600, "failed"), 600)
        .unwrap();
    notify
        .collect_with_history(&report(600, "failed"), 610)
        .unwrap();
    let bad: i64 = db
        .query_row(
            "SELECT bad FROM alarm_state WHERE service='reality'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(bad, 1);
    db.execute_batch("CREATE TRIGGER reject_fault BEFORE INSERT ON events WHEN NEW.action='fault_detected' BEGIN SELECT RAISE(ABORT,'reject'); END;").unwrap();
    assert_eq!(
        notify.collect_with_history(&report(660, "failed"), 660),
        Err(Error::Unavailable)
    );
    let state: (i64, i64) = db
        .query_row(
            "SELECT bad,last_sample FROM alarm_state WHERE service='reality'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, (1, 600));
    let probe_sample: i64 = db
        .query_row(
            "SELECT last_sample FROM alarm_state WHERE service='probe'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        probe_sample, 10,
        "earlier sensor update must roll back with the failed event"
    );
    let history_rows: i64 = db
        .query_row("SELECT COUNT(*) FROM probe_history WHERE ts=660", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(
        history_rows, 0,
        "history and notification state must roll back together"
    );
    db.execute_batch("DROP TRIGGER reject_fault;").unwrap();
    notify
        .collect_with_history(&report(660, "failed"), 660)
        .unwrap();
    let firing: i64 = db
        .query_row(
            "SELECT firing FROM alarm_state WHERE service='reality'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(firing, 1);
    notify
        .collect_with_history(&report(660, "failed"), 900)
        .unwrap();
    notify
        .collect_with_history(&report(660, "failed"), 960)
        .unwrap();
    let states: Vec<(String, i64)> = db
        .prepare("SELECT service,firing FROM alarm_state ORDER BY service")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(states, [("probe".into(), 1), ("reality".into(), 1)]);
    notify
        .collect_with_history(&report(1020, "healthy"), 1020)
        .unwrap();
    notify
        .collect_with_history(&report(1080, "healthy"), 1080)
        .unwrap();
    let active: i64 = db
        .query_row("SELECT COUNT(*) FROM alarm_state WHERE firing=1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(active, 0);
    let recoveries: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM notifications WHERE kind='recovery'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(recoveries, 2);
}

#[test]
fn explicit_test_is_rate_limited_and_works_when_alerts_are_disabled() {
    use xcli_panel_operations::notifications::EnqueueError;
    let (_dir, db, mut notify) = setup();
    db.execute("UPDATE notification_config SET enabled=0 WHERE id=1", [])
        .unwrap();
    let id = notify.enqueue_test(100).unwrap();
    assert_eq!(notify.enqueue_test(129), Err(EnqueueError::RateLimited));
    let pending = notify.next(100).unwrap().unwrap();
    assert_eq!(pending.id(), id);
    let event: String = db
        .query_row("SELECT payload FROM notifications WHERE id=?", [id], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&event).unwrap()["event"],
        "test"
    );
    assert!(notify.enqueue_test(130).is_ok());
    db.execute("UPDATE notification_config SET url='' WHERE id=1", [])
        .unwrap();
    assert_eq!(notify.enqueue_test(200), Err(EnqueueError::NotConfigured));
}

#[test]
fn core_and_backup_observations_raise_and_recover_without_a_monitor_report() {
    use xcli_panel_operations::notifications::BackupObservation;
    let (_dir, db, mut notify) = setup();
    db.execute_batch("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);")
        .unwrap();
    let backup = Some(BackupObservation {
        started: 600,
        interval: 60,
    });
    notify
        .collect_runtime(None, Some(true), backup, 600)
        .unwrap();
    db.execute(
        "INSERT INTO metadata VALUES('backup_error','synthetic failure')",
        [],
    )
    .unwrap();
    notify
        .collect_runtime(None, Some(false), backup, 660)
        .unwrap();
    notify
        .collect_runtime(None, Some(false), backup, 720)
        .unwrap();
    let firing: Vec<String> = db
        .prepare("SELECT service FROM alarm_state WHERE firing=1 ORDER BY service")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(firing, ["backup", "core"]);
    db.execute("DELETE FROM metadata WHERE key='backup_error'", [])
        .unwrap();
    db.execute("INSERT INTO metadata VALUES('last_backup','780')", [])
        .unwrap();
    notify
        .collect_runtime(None, Some(true), backup, 780)
        .unwrap();
    notify
        .collect_runtime(None, Some(true), backup, 840)
        .unwrap();
    let firing: i64 = db
        .query_row("SELECT COUNT(*) FROM alarm_state WHERE firing=1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(firing, 0);
    let recoveries: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM notifications WHERE kind='recovery'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(recoveries, 2);
}
