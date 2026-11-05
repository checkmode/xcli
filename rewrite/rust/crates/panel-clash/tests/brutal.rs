use serde_json::{json, Value};
use xcli_panel_clash::{build, User};

fn settings() -> Value {
    json!({"public_ip":"8.8.8.8","domain":"panel.example.com","public_port":443,
        "hysteria2_port":443,"ws_path":"/connect/test","reality_sni":"www.example.com",
        "reality_public":"Y".repeat(43),"short_id":"0123456789abcdef"})
}

#[test]
fn optional_brutal_node_does_not_change_existing_node_or_default() {
    let user = User {
        id: "a".repeat(32),
        uuid: "01234567-89ab-4def-8123-456789abcdef".into(),
    };
    let original = build(&settings(), &user, &[], false, &json!({})).unwrap();
    let mut enabled = settings();
    enabled["hysteria2_brutal_port"] = json!(8443);
    let updated = build(&enabled, &user, &[], false, &json!({})).unwrap();
    let find = |config: &Value, name: &str| {
        config["proxies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|node| node["name"] == name)
            .unwrap()
            .clone()
    };
    assert_eq!(find(&original, "Hysteria 2"), find(&updated, "Hysteria 2"));
    let fast = find(&updated, "Hysteria 2 Brutal 40 Mbps");
    let neutral = find(&updated, "Hysteria 2 Brutal");
    assert_eq!(fast["port"], 8443);
    assert_eq!(fast["down"], "40 Mbps");
    assert_eq!(fast["password"], user.uuid);
    assert_eq!(neutral["down"], "40 Mbps");
    let mut adjusted = enabled.clone();
    adjusted["hysteria2_brutal_mbps"] = json!(60);
    let adjusted = build(&adjusted, &user, &[], false, &json!({})).unwrap();
    assert_eq!(find(&adjusted, "Hysteria 2 Brutal 40 Mbps")["down"], "60 Mbps");
    assert_eq!(find(&adjusted, "Hysteria 2 Brutal")["down"], "60 Mbps");
    assert_eq!(find(&adjusted, "Hysteria 2"), find(&original, "Hysteria 2"));
    assert_eq!(
        original["proxy-groups"][0]["proxies"][0],
        updated["proxy-groups"][0]["proxies"][0]
    );
    assert!(updated["proxy-groups"][0]["proxies"]
        .as_array()
        .unwrap()
        .iter()
        .any(|name| name == "Hysteria 2 Brutal 40 Mbps"));
    enabled["client_policies"] = json!({(user.id.clone()): {"ai_outbound":"proxy"}});
    let independent = build(&enabled, &user, &[], false, &json!({})).unwrap();
    let groups = independent["proxy-groups"].as_array().unwrap();
    let members = |name: &str| {
        groups.iter().find(|g| g["name"] == name).unwrap()["proxies"]
            .as_array()
            .unwrap()
    };
    assert!(members("PROXY")
        .iter()
        .any(|name| name == "Hysteria 2 Brutal 40 Mbps"));
    for group in ["独立 · AI", "独立 · YouTube", "独立 · Google"] {
        assert_eq!(members(group)[0], "故障转移");
        assert!(members(group)
            .iter()
            .any(|name| name == "Hysteria 2 Brutal 40 Mbps"));
    }
    assert!(!members("故障转移")
        .iter()
        .any(|name| name == "Hysteria 2 Brutal 40 Mbps"));
    assert!(!members("自动选择")
        .iter()
        .any(|name| name == "Hysteria 2 Brutal 40 Mbps"));
    for group in ["PROXY", "独立 · AI", "独立 · YouTube", "独立 · Google"] {
        assert!(members(group).iter().any(|name| name == "Hysteria 2 Brutal"));
    }
    for group in ["故障转移", "自动选择"] {
        assert!(!members(group).iter().any(|name| name == "Hysteria 2 Brutal"));
    }
    enabled["hysteria2_brutal_port"] = json!(443);
    assert!(build(&enabled, &user, &[], false, &json!({})).is_err());
}
