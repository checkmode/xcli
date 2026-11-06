use rusqlite::Connection;
use serde_json::json;
use std::sync::{Arc, Barrier};
use xcli_panel_rules::{RuleEditor, RuleStore, RuleStoreError};

fn fixture(path: &std::path::Path) {
    let db = Connection::open(path).unwrap();
    db.execute_batch("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT NOT NULL,deleted INTEGER NOT NULL,created INTEGER NOT NULL);
        CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);").unwrap();
}
fn spec(rules: &str) -> serde_json::Value {
    json!({"base":"standard","ai_outbound":"proxy","rules":rules})
}

#[test]
fn drafts_do_not_change_published_content_and_stale_updates_fail() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.sqlite");
    fixture(&path);
    let mut editor = RuleEditor::open(&path).unwrap();
    let mut reader = RuleStore::open(&path, json!({})).unwrap();
    let created = editor
        .create(&json!({"name":"  草稿  ","spec":spec("")}), 100)
        .unwrap();
    let id = created["id"].as_str().unwrap();
    assert_eq!(created["revision"], 1);
    assert_eq!(editor.update(id,&json!({"name":"编辑","spec":spec("DOMAIN,example.com,DIRECT"),"expected_revision":1}),101).unwrap()["revision"],2);
    assert!(matches!(
        editor.update(
            id,
            &json!({"name":"过期","spec":spec(""),"expected_revision":1}),
            102
        ),
        Err(RuleStoreError::Conflict(_))
    ));
    editor.update("standard",&json!({"name":"标准编辑","spec":spec("DOMAIN,example.com,DIRECT"),"expected_revision":1}),103).unwrap();
    let catalog = reader.catalog().unwrap();
    let builtin = &catalog["templates"][0];
    assert_eq!(builtin["spec"]["rules"], "DOMAIN,example.com,DIRECT");
    assert_eq!(builtin["published_spec"]["rules"], "");
    let custom = &catalog["templates"][2];
    assert_eq!(custom["name"], "编辑");
    assert!(custom["published_spec"].is_null());
    let db = Connection::open(&path).unwrap();
    let actions: Vec<String> = db
        .prepare("SELECT action FROM events ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        actions,
        vec![
            "rule_template_created",
            "rule_template_saved",
            "rule_template_saved"
        ]
    );
}

#[test]
fn failed_audit_rolls_back_and_concurrent_updates_have_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.sqlite");
    fixture(&path);
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TRIGGER deny_audit BEFORE INSERT ON events BEGIN SELECT RAISE(FAIL,'fail'); END;",
    )
    .unwrap();
    let mut editor = RuleEditor::open(&path).unwrap();
    assert_eq!(
        editor.create(&json!({"name":"草稿","spec":spec("")}), 100),
        Err(RuleStoreError::Unavailable)
    );
    let count: i64 = db
        .query_row("SELECT count(*) FROM metadata", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
    db.execute_batch("DROP TRIGGER deny_audit;").unwrap();
    drop(db);
    let id = editor
        .create(&json!({"name":"草稿","spec":spec("")}), 101)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for name in ["并发一", "并发二"] {
        let path = path.clone();
        let id = id.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            let mut editor = RuleEditor::open(&path).unwrap();
            barrier.wait();
            editor.update(
                &id,
                &json!({"name":name,"spec":spec(""),"expected_revision":1}),
                102,
            )
        }));
    }
    barrier.wait();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(RuleStoreError::Conflict(_))))
            .count(),
        1
    );
}

#[test]
fn publish_and_assignment_validate_before_commit_and_reset_is_reversible() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.sqlite");
    fixture(&path);
    let db = Connection::open(&path).unwrap();
    db.execute("INSERT INTO users VALUES('u','测试用户',0,1)", [])
        .unwrap();
    let mut editor = RuleEditor::open(&path).unwrap();
    let mut reader = RuleStore::open(&path, json!({})).unwrap();
    let id = editor
        .create(&json!({"name":"自定义","spec":spec("")}), 100)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        editor.assign("u", &json!({ "template_id": id }), 101, |_, _| Ok(())),
        Err(RuleStoreError::Unpublished)
    );
    assert_eq!(
        editor
            .publish(&id, &json!({"expected_revision":1}), 102, |_, _| Ok(()))
            .unwrap()["affected_users"],
        0
    );
    let fail = |_: &str, _: &serde_json::Value| Err(RuleStoreError::Invalid("校验失败".into()));
    assert!(editor
        .assign("u", &json!({ "template_id": id }), 103, fail)
        .is_err());
    assert_eq!(
        reader.catalog().unwrap()["users"][0]["template_id"],
        "legacy"
    );
    editor
        .assign("u", &json!({ "template_id": id }), 104, |_, _| Ok(()))
        .unwrap();
    editor
        .update(
            &id,
            &json!({"name":"草稿","spec":spec("DOMAIN,example.com,DIRECT"),"expected_revision":1}),
            105,
        )
        .unwrap();
    assert!(editor
        .publish(&id, &json!({"expected_revision":2}), 106, fail)
        .is_err());
    assert_eq!(reader.effective("u").unwrap()["rules"], "");
    assert_eq!(
        editor
            .publish(&id, &json!({"expected_revision":2}), 107, |_, _| Ok(()))
            .unwrap()["affected_users"],
        1
    );
    assert_eq!(
        reader.effective("u").unwrap()["rules"],
        "DOMAIN,example.com,DIRECT"
    );
    editor
        .assign("u", &json!({"template_id":"standard"}), 108, |_, _| Ok(()))
        .unwrap();
    editor.update("standard",&json!({"name":"已修改","spec":spec("DOMAIN,example.com,DIRECT"),"expected_revision":1}),109).unwrap();
    assert_eq!(
        editor
            .reset("standard", &json!({"expected_revision":2}), 110, |_, _| Ok(
                ()
            ))
            .unwrap()["revision"],
        3
    );
    let reset = reader.catalog().unwrap();
    assert!(reset["templates"][0]["can_undo_reset"].as_bool().unwrap());
    assert_eq!(
        editor
            .undo_reset("standard", &json!({"expected_revision":3}), 111, |_, _| Ok(
                ()
            ))
            .unwrap()["revision"],
        4
    );
    let restored = reader.catalog().unwrap();
    assert_eq!(
        restored["templates"][0]["spec"]["rules"],
        "DOMAIN,example.com,DIRECT"
    );
    assert_eq!(restored["templates"][0]["published_spec"]["rules"], "");
    assert_eq!(restored["templates"][0]["published_revision"], 3);
}

#[test]
fn group_defaults_stay_in_draft_until_publish_and_survive_reset_undo() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.sqlite");
    fixture(&path);
    let db = Connection::open(&path).unwrap();
    db.execute("INSERT INTO users VALUES('u','测试用户',0,1)", [])
        .unwrap();
    let mut editor = RuleEditor::open(&path).unwrap();
    let mut reader = RuleStore::open(&path, json!({})).unwrap();
    editor
        .assign("u", &json!({"template_id":"independent"}), 100, |_, _| {
            Ok(())
        })
        .unwrap();
    let mut draft = reader.catalog().unwrap()["templates"][1]["spec"].clone();
    draft["group_defaults"] =
        json!({"独立 · AI":"node:residential-41","独立 · Google":"selector:自动选择"});
    editor
        .update(
            "independent",
            &json!({"name":"独立服务分组","spec":draft,"expected_revision":1}),
            101,
        )
        .unwrap();
    assert!(reader
        .effective("u")
        .unwrap()
        .get("group_defaults")
        .is_none());
    assert!(editor
        .publish(
            "independent",
            &json!({"expected_revision":2}),
            102,
            |_, policy| {
                assert_eq!(policy["group_defaults"]["独立 · AI"], "node:residential-41");
                Err(RuleStoreError::Invalid("不可用".into()))
            }
        )
        .is_err());
    assert!(reader
        .effective("u")
        .unwrap()
        .get("group_defaults")
        .is_none());
    editor
        .publish(
            "independent",
            &json!({"expected_revision":2}),
            103,
            |_, _| Ok(()),
        )
        .unwrap();
    assert_eq!(
        reader.effective("u").unwrap()["group_defaults"]["独立 · Google"],
        "selector:自动选择"
    );
    editor
        .reset(
            "independent",
            &json!({"expected_revision":2}),
            104,
            |_, _| Ok(()),
        )
        .unwrap();
    assert!(reader
        .effective("u")
        .unwrap()
        .get("group_defaults")
        .is_none());
    editor
        .undo_reset(
            "independent",
            &json!({"expected_revision":3}),
            105,
            |_, _| Ok(()),
        )
        .unwrap();
    assert_eq!(
        reader.effective("u").unwrap()["group_defaults"]["独立 · AI"],
        "node:residential-41"
    );
}
