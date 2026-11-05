use aes_gcm::{aead::AeadInPlace, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::path::Path;
use xcli_panel_subscription::{StoreError, SubscriptionStore};

const ID: &str = "11111111111111111111111111111111";
const UUID: &str = "01234567-89ab-4def-8123-456789abcdef";
fn token() -> String {
    "X".repeat(43)
}
fn settings() -> Value {
    json!({"origin":"https://panel.example","domain":"panel.example","public_ip":"8.8.8.8",
    "reality_sni":"www.bing.com","reality_public":"Y".repeat(43),"short_id":"0123456789abcdef","ws_path":"/connect/test",
    "hysteria2_port":443,"residential_exits":[{"tag":"residential-11","label":"动态 US","exit_ip":"",
        "ws_path":"/connect/test/residential-11","dynamic":true}]})
}
fn fixture(path: &Path) {
    let db = Connection::open(path).unwrap();
    db.execute_batch("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT NOT NULL,uuid TEXT NOT NULL,token TEXT NOT NULL,enabled INTEGER NOT NULL,
            deleted INTEGER NOT NULL,quota INTEGER NOT NULL,expires INTEGER NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL);").unwrap();
    db.execute(
        "INSERT INTO users VALUES(?,?,?, ?,1,0,1000,0,10,20)",
        params![ID, "fixture", UUID, token()],
    )
    .unwrap();
    let node = json!({"id":"a".repeat(32),"name":"remote","enabled":true,"users":[ID],"applied_users":[],"endpoint":{
        "public_ip":"8.8.4.4","domain":"node.example","public_port":443,"reality_sni":"www.bing.com",
        "reality_public":"Y".repeat(43),"short_id":"0123456789abcdef","ws_path":"/connect/test","hysteria2_port":443}});
    db.execute(
        "INSERT INTO metadata VALUES('remote_nodes_v1',?)",
        [json!([node]).to_string()],
    )
    .unwrap();
}
fn body(store: &mut SubscriptionStore) -> String {
    String::from_utf8(
        STANDARD
            .decode(store.generic(&token(), 100).unwrap().0)
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn includes_only_remote_nodes_with_applied_current_grants() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.sqlite");
    fixture(&path);
    let mut store = SubscriptionStore::open(&path, settings(), [1; 32]).unwrap();
    assert!(!body(&mut store).contains("8.8.4.4"));
    let db = Connection::open(&path).unwrap();
    let raw: String = db
        .query_row(
            "SELECT value FROM metadata WHERE key='remote_nodes_v1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut nodes: Value = serde_json::from_str(&raw).unwrap();
    nodes[0]["applied_users"] = json!([{"id":ID,"uuid":UUID,"expires":0}]);
    db.execute(
        "UPDATE metadata SET value=? WHERE key='remote_nodes_v1'",
        [nodes.to_string()],
    )
    .unwrap();
    drop(db);
    assert_eq!(body(&mut store).matches("8.8.4.4").count(), 3);
    assert!(matches!(
        store.generic("invalid", 100),
        Err(StoreError::NotFound)
    ));
    let db = Connection::open(&path).unwrap();
    db.execute("UPDATE users SET enabled=0 WHERE id=?", [ID])
        .unwrap();
    drop(db);
    assert!(matches!(
        store.generic(&token(), 100),
        Err(StoreError::Inactive)
    ));
    assert!(store.links_for_id(ID).is_ok());
}

#[test]
fn encrypted_dynamic_configuration_is_read_and_tampering_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.sqlite");
    fixture(&path);
    let mut store = SubscriptionStore::open(&path, settings(), [1; 32]).unwrap();
    assert!(!body(&mut store).contains("residential-11"));
    let webshare = dir.path().join("webshare");
    std::fs::create_dir(&webshare).unwrap();
    let cipher = Aes256Gcm::new_from_slice(&[1; 32]).unwrap();
    let nonce = [7u8; 12];
    let mut data = br#"{"enabled":true}"#.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            b"xcli:webshare:config:v1",
            &mut data,
        )
        .unwrap();
    let mut frame = b"XGB1".to_vec();
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&tag);
    frame.extend_from_slice(&data);
    std::fs::write(webshare.join("config.xgb"), &frame).unwrap();
    assert!(body(&mut store).contains("residential-11"));
    frame[20] ^= 1;
    std::fs::write(webshare.join("config.xgb"), frame).unwrap();
    assert!(!body(&mut store).contains("residential-11"));
}
