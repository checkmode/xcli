use rusqlite::{params, Connection};
use serde_json::json;
use xcli_panel_rules::{factory_spec, RuleStore, RuleStoreError};

#[test]
fn catalog_and_effective_policy_preserve_published_state_and_assignments() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.sqlite");
    let db = Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT NOT NULL,deleted INTEGER NOT NULL,created INTEGER NOT NULL);
        INSERT INTO users VALUES('legacy','旧用户',0,1);INSERT INTO users VALUES('assigned','新用户',0,2);
        INSERT INTO users VALUES('deleted','已删除',1,3);").unwrap();
    let settings = json!({"client_policies":{"legacy":{"ai_outbound":"residential-01"}}});
    let mut store = RuleStore::open(&path, settings).unwrap();
    let first = store.catalog().unwrap();
    assert_eq!(first["templates"].as_array().unwrap().len(), 2);
    assert_eq!(first["users"].as_array().unwrap().len(), 2);
    assert_eq!(
        store.effective("legacy").unwrap(),
        json!({"base":"independent","ai_outbound":"residential-01","rules":"","managed":false})
    );
    assert_eq!(
        store.effective("assigned").unwrap(),
        json!({"base":"standard","ai_outbound":"proxy","rules":"","managed":false})
    );
    let id = "a".repeat(32);
    let draft =
        json!({"base":"standard","ai_outbound":"proxy","rules":"DOMAIN,example.com,DIRECT"});
    let mut registry = json!({"version":1,"templates":{},"assignments":{"assigned":id}});
    registry["templates"][&id] = json!({"name":"测试","draft":draft,"revision":2,"published":null,"published_revision":0,"published_at":0});
    db.execute(
        "INSERT INTO metadata VALUES('rule_templates_v1',?)",
        params![registry.to_string()],
    )
    .unwrap();
    assert_eq!(
        store.effective("assigned"),
        Err(RuleStoreError::Unpublished)
    );
    registry["templates"][&id]["published"] = factory_spec("standard").unwrap();
    registry["templates"][&id]["published_revision"] = json!(1);
    db.execute(
        "UPDATE metadata SET value=? WHERE key='rule_templates_v1'",
        params![registry.to_string()],
    )
    .unwrap();
    assert_eq!(
        store.effective("assigned").unwrap(),
        json!({"base":"standard","ai_outbound":"proxy","rules":"","managed":true})
    );
    let catalog = store.catalog().unwrap();
    let template = &catalog["templates"][2];
    assert_eq!(template["spec"]["rules"], "DOMAIN,example.com,DIRECT");
    assert_eq!(template["published_spec"]["rules"], "");
    assert_eq!(catalog["users"][1]["template_id"], id);
    registry["assignments"]["assigned"] = json!("standard");
    registry["builtins"] = json!({"standard":{}});
    db.execute(
        "UPDATE metadata SET value=? WHERE key='rule_templates_v1'",
        params![registry.to_string()],
    )
    .unwrap();
    assert_eq!(
        store.effective("assigned"),
        Err(RuleStoreError::Unavailable)
    );
    db.execute(
        "UPDATE metadata SET value='not json' WHERE key='rule_templates_v1'",
        [],
    )
    .unwrap();
    assert_eq!(store.catalog(), Err(RuleStoreError::Unavailable));
}
