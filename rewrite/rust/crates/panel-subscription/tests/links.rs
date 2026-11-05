use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::json;
use xcli_panel_subscription::{build, Error, User};

fn user() -> User {
    User {
        name: "测试 / A".into(),
        uuid: "01234567-89ab-4def-8123-456789abcdef".into(),
        token: "X".repeat(43),
        enabled: true,
        deleted: false,
        quota: 1000,
        expires: 0,
        upload: 10,
        download: 20,
    }
}
fn settings() -> serde_json::Value {
    json!({"origin":"https://panel.example.com","domain":"panel.example.com","public_ip":"8.8.8.8",
    "reality_sni":"www.bing.com","reality_public":"Y".repeat(43),"short_id":"0123456789abcdef","ws_path":"/connect/test",
    "hysteria2_port":443,"vmess_ws_path":"/connect/test/vmess","node_address_ip":true,
    "residential_exits":[{"tag":"residential-01","label":"住宅 HK","exit_ip":"1.1.1.1","ws_path":"/connect/test/residential-01","hysteria2":true},
        {"tag":"residential-02","label":"动态 US","exit_ip":"","ws_path":"/connect/test/residential-02","dynamic":true}]})
}

#[test]
fn quotes_names_and_preserves_generic_subscription_order() {
    let user = user();
    let links = build(&settings(), &user, &[], false).unwrap();
    assert!(links
        .get("reality")
        .unwrap()
        .contains("#%E6%B5%8B%E8%AF%95%20/%20A%20%C2%B7%20REALITY"));
    assert!(links.get("websocket").unwrap().contains("@8.8.8.8:443?"));
    assert!(links.get("residential-02").is_none());
    let vmess = links
        .get("vmess")
        .unwrap()
        .strip_prefix("vmess://")
        .unwrap();
    let decoded = String::from_utf8(STANDARD.decode(vmess).unwrap()).unwrap();
    assert!(decoded.starts_with("{\"v\":\"2\",\"ps\":"));
    let (body, info) = links.generic_subscription(&user, 100).unwrap();
    let body = String::from_utf8(STANDARD.decode(body).unwrap()).unwrap();
    let lines: Vec<_> = body.lines().collect();
    assert_eq!(
        lines,
        vec![
            links.get("reality").unwrap(),
            links.get("websocket").unwrap(),
            links.get("hysteria2").unwrap(),
            links.get("vmess").unwrap(),
            links.get("residential-01").unwrap(),
            links.get("residential-01-hy2").unwrap()
        ]
    );
    assert_eq!(info, "upload=10; download=20; total=1000; expire=0");
}

#[test]
fn disables_expired_and_exhausted_subscriptions() {
    let mut user = user();
    let links = build(&settings(), &user, &[], true).unwrap();
    assert!(links.get("residential-02").is_some());
    user.expires = 100;
    assert_eq!(links.generic_subscription(&user, 100), Err(Error::Inactive));
    user.expires = 0;
    user.quota = 30;
    assert_eq!(links.generic_subscription(&user, 100), Err(Error::Inactive));
    user.quota = 0;
    user.deleted = true;
    assert_eq!(links.generic_subscription(&user, 100), Err(Error::Inactive));
}
