use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::path::Path;
use xcli_panel_nodes::{ManageError, NodeSync};

const ONE: &str = "11111111111111111111111111111111";
const TWO: &str = "22222222222222222222222222222222";
const NODE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn registration(id: &str) -> Value {
    json!({"version":1,"id":id,"key":"Z".repeat(43),"public_ip":"8.8.8.8","domain":"node.example.com",
        "public_port":443,"reality_sni":"www.bing.com","reality_public":"Y".repeat(43),"short_id":"0123456789abcdef",
        "ws_path":format!("/connect/{}","b".repeat(24)),"hysteria2_port":443})
}
fn fixture(path: &Path) {
    let db = Connection::open(path).unwrap();
    db.execute_batch("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE users(id TEXT PRIMARY KEY,deleted INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);").unwrap();
    db.execute("INSERT INTO users(id) VALUES(?)", [ONE])
        .unwrap();
    db.execute("INSERT INTO users(id) VALUES(?)", [TWO])
        .unwrap();
}
fn registry(path: &Path) -> Value {
    let db = Connection::open(path).unwrap();
    let raw: String = db
        .query_row(
            "SELECT value FROM metadata WHERE key='remote_nodes_v1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    serde_json::from_str(&raw).unwrap()
}

#[test]
fn registration_selection_history_and_display_match_legacy_contract() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    fixture(&path);
    let mut nodes = NodeSync::open(&path).unwrap();
    assert_eq!(nodes.list().unwrap()["nodes"], json!([]));
    let input = json!({"name":"  节点  ","registration":registration(NODE),"users":[TWO,ONE]});
    let output = nodes.add(&input, 1000).unwrap();
    assert_eq!(output["name"], "节点");
    assert_eq!(output["users"], json!([ONE, TWO]));
    assert!(output.get("key_hash").is_none());
    assert!(!output.to_string().contains(&"Z".repeat(43)));
    let stored = registry(&path);
    assert_ne!(stored[0]["key_hash"], "Z".repeat(43));
    assert_eq!(stored[0]["history"], json!([ONE, TWO]));
    assert_eq!(nodes.add(&input, 1001), Err(ManageError::Conflict));
    let same_prefix = format!("{}{}", &NODE[..8], "b".repeat(24));
    assert_eq!(
        nodes.add(
            &json!({"name":"duplicate","registration":registration(&same_prefix),"users":[]}),
            1001
        ),
        Err(ManageError::Conflict)
    );
    let packed = STANDARD.encode(hex::decode(ONE).unwrap());
    let updated = nodes
        .update(
            NODE,
            &json!({"name":"new","users":packed,"enabled":false}),
            1002,
        )
        .unwrap();
    assert_eq!(updated["users"], json!([ONE]));
    assert_eq!(updated["enabled"], false);
    assert_eq!(registry(&path)[0]["history"], json!([ONE, TWO]));
    let db = Connection::open(&path).unwrap();
    let actions = db
        .prepare("SELECT action FROM events ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(actions, vec!["node_added", "node_updated"]);
}

#[test]
fn rejects_private_addresses_bad_registration_and_unknown_users() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    fixture(&path);
    let mut nodes = NodeSync::open(&path).unwrap();
    for address in [
        "127.0.0.1",
        "10.0.0.1",
        "100.64.0.1",
        "172.16.0.1",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
    ] {
        let mut item = registration(NODE);
        item["public_ip"] = json!(address);
        assert_eq!(
            nodes.add(&json!({"name":"test","registration":item,"users":[]}), 1000),
            Err(ManageError::InvalidInput)
        );
    }
    for domain in [
        "-host.example".to_owned(),
        "host-.example".to_owned(),
        "host..example".to_owned(),
        "UPPER.example".to_owned(),
        "a".repeat(64) + ".com",
    ] {
        let mut item = registration(NODE);
        item["domain"] = json!(domain);
        assert_eq!(
            nodes.add(&json!({"name":"test","registration":item,"users":[]}), 1000),
            Err(ManageError::InvalidInput)
        );
    }
    assert_eq!(
        nodes.add(
            &json!({"name":"test","registration":registration(NODE),"users":[ONE,ONE]}),
            1000
        ),
        Err(ManageError::InvalidInput)
    );
    assert_eq!(
        nodes.add(
            &json!({"name":"test","registration":registration(NODE),"users":["f".repeat(32)]}),
            1000
        ),
        Err(ManageError::InvalidInput)
    );
    assert_eq!(
        nodes.add(
            &json!({"name":"bad,name","registration":registration(NODE),"users":[]}),
            1000
        ),
        Err(ManageError::InvalidInput)
    );
    assert_eq!(nodes.list().unwrap()["nodes"], json!([]));
}

#[test]
fn audit_failure_rolls_back_registration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    fixture(&path);
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TRIGGER deny_event BEFORE INSERT ON events BEGIN SELECT RAISE(FAIL,'denied'); END;",
    )
    .unwrap();
    drop(db);
    let mut nodes = NodeSync::open(&path).unwrap();
    assert_eq!(
        nodes.add(
            &json!({"name":"test","registration":registration(NODE),"users":[ONE]}),
            1000
        ),
        Err(ManageError::Unavailable)
    );
    assert_eq!(nodes.list().unwrap()["nodes"], json!([]));
}

#[test]
fn deleted_users_cannot_be_selected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    fixture(&path);
    let db = Connection::open(&path).unwrap();
    db.execute("UPDATE users SET deleted=1 WHERE id=?", params![ONE])
        .unwrap();
    drop(db);
    let mut nodes = NodeSync::open(&path).unwrap();
    assert_eq!(
        nodes.add(
            &json!({"name":"test","registration":registration(NODE),"users":[ONE]}),
            1000
        ),
        Err(ManageError::InvalidInput)
    );
}
