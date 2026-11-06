use serde_json::{json, Value};
use xcli_panel_clash::{build, template_group_catalog, User};
use xcli_panel_rules::factory_independent_rules;

fn settings() -> Value {
    json!({"public_ip":"8.8.8.8","domain":"panel.example.com","public_port":443,"hysteria2_port":8443,
    "ws_path":"/connect/test","reality_sni":"www.example.com","reality_public":"public","short_id":"0123456789abcdef",
    "residential_exits":[
        {"tag":"residential-41","label":"住宅 US","exit_ip":"8.8.4.4","country":"US","ws_path":"/connect/test/residential-41","hysteria2":true},
        {"tag":"residential-42","label":"动态 US","exit_ip":"","country":"US","ws_path":"/connect/test/residential-42","dynamic":true}
    ]})
}
fn user() -> User {
    User {
        id: "a".repeat(32),
        uuid: "01234567-89ab-4def-8123-456789abcdef".into(),
    }
}
fn first<'a>(config: &'a Value, name: &str) -> &'a str {
    config["proxy-groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap()["proxies"][0]
        .as_str()
        .unwrap()
}

#[test]
fn legacy_ai_is_preserved_and_per_group_defaults_only_reorder_requested_groups() {
    let base = json!({"base":"independent","ai_outbound":"residential-41","rules":factory_independent_rules(),"managed":true,
        "groups":[{"name":"工作","default":"PROXY"}]});
    let old = build(&settings(), &user(), &[], false, &base).unwrap();
    assert_eq!(first(&old, "独立 · AI"), "住宅 US · 8.8.4.4");
    assert_eq!(first(&old, "独立 · Google"), "故障转移");
    let mut policy = base.clone();
    policy["group_defaults"] = json!({"独立 · AI":"node:reality","独立 · Google":"selector:自动选择",
        "独立 · STUN":"node:hysteria2","工作":"node:residential-41"});
    let updated = build(&settings(), &user(), &[], false, &policy).unwrap();
    assert_eq!(first(&updated, "独立 · AI"), "REALITY");
    assert_eq!(first(&updated, "独立 · Google"), "自动选择");
    assert_eq!(first(&updated, "独立 · STUN"), "Hysteria 2");
    assert_eq!(first(&updated, "工作"), "住宅 US · 8.8.4.4");
    assert_eq!(
        first(&updated, "独立 · Telegram"),
        first(&old, "独立 · Telegram")
    );
    assert_eq!(updated["rules"], old["rules"]);
    assert_eq!(updated["proxies"], old["proxies"]);
    assert_eq!(updated["dns"], old["dns"]);
    assert_eq!(first(&updated, "oracle-cloud"), "DIRECT");
}

#[test]
fn unavailable_or_ineligible_nodes_do_not_silently_fall_back() {
    let policy = json!({"base":"independent","ai_outbound":"proxy","rules":"","managed":true,
        "group_defaults":{"独立 · Google":"node:residential-42","独立 · STUN":"node:residential-41"}});
    let config = build(&settings(), &user(), &[], false, &policy).unwrap();
    assert_eq!(first(&config, "独立 · Google"), "REJECT");
    assert_eq!(first(&config, "独立 · STUN"), "REJECT");
    assert_eq!(first(&config, "独立 · AI"), "故障转移");
}

#[test]
fn catalog_lists_actual_configured_nodes_and_allowed_group_policies() {
    let catalog = template_group_catalog(&settings(), &[], false).unwrap();
    let options = catalog["independent"]["独立 · Google"]["options"]
        .as_array()
        .unwrap();
    assert!(options
        .iter()
        .any(|option| option["value"] == "node:residential-41"));
    assert!(options.iter().any(|option| option["value"] == "country:US"));
    assert!(options
        .iter()
        .any(|option| option["value"] == "selector:自动选择"));
    assert!(!options
        .iter()
        .any(|option| option["value"] == "node:residential-42"));
    let stun = catalog["independent"]["独立 · STUN"]["options"]
        .as_array()
        .unwrap();
    assert!(!stun
        .iter()
        .any(|option| option["value"] == "node:residential-41"));
    assert_eq!(
        catalog["independent"]["独立 · AI"]["default"],
        "selector:故障转移"
    );
    assert_eq!(catalog["standard"]["PROXY"]["default"], "node:websocket");
    assert!(catalog["independent"].get("oracle-cloud").is_none());
    let enabled = template_group_catalog(&settings(), &[], true).unwrap();
    assert!(enabled["independent"]["独立 · AI"]["options"]
        .as_array()
        .unwrap()
        .iter()
        .any(|option| option["value"] == "node:residential-42"));
    let text = serde_json::to_string(&catalog).unwrap();
    assert!(!text.contains("00000000-0000-4000-8000-000000000000"));
}

#[test]
fn remote_node_choice_is_stable_and_missing_user_grants_are_rejected() {
    let id = "b".repeat(32);
    let remote = json!({"id":id,"name":"洛杉矶","endpoint":{"public_ip":"1.1.1.1","domain":"node.example.com",
        "public_port":443,"hysteria2_port":8443,"reality_sni":"www.example.com","reality_public":"public",
        "short_id":"0123456789abcdef","ws_path":"/connect/node"}});
    let choice = format!("node:remote-{}-hysteria2", "b".repeat(32));
    let catalog = template_group_catalog(&settings(), &[remote.clone()], false).unwrap();
    assert!(catalog["independent"]["独立 · Google"]["options"]
        .as_array()
        .unwrap()
        .iter()
        .any(|option| option["value"] == choice));
    let policy = json!({"base":"independent","ai_outbound":"proxy","rules":"","managed":true,
        "group_defaults":{"独立 · Google":choice}});
    let granted = build(&settings(), &user(), &[remote], false, &policy).unwrap();
    assert_eq!(
        first(&granted, "独立 · Google"),
        "节点 bbbbbbbb · 洛杉矶 · Hysteria 2"
    );
    let not_granted = build(&settings(), &user(), &[], false, &policy).unwrap();
    assert_eq!(first(&not_granted, "独立 · Google"), "REJECT");
}

#[test]
fn group_order_changes_display_only_and_preserves_other_configuration() {
    let base = json!({"base":"independent","ai_outbound":"proxy","rules":"","managed":true});
    let old = build(&settings(), &user(), &[], false, &base).unwrap();
    let mut reordered = base.clone();
    reordered["group_order"] = json!(["独立 · Google", "DIRECT", "独立 · AI", "PROXY", "oracle-cloud"]);
    let new = build(&settings(), &user(), &[], false, &reordered).unwrap();
    for key in ["rules", "dns", "proxies", "rule-providers"] {
        assert_eq!(new[key], old[key], "{key}");
    }
    let names: Vec<&str> = new["proxy-groups"].as_array().unwrap().iter()
        .map(|group| group["name"].as_str().unwrap()).collect();
    let position = |name| names.iter().position(|item| *item == name).unwrap();
    assert!(position("独立 · Google") < position("独立 · AI"));
    assert!(position("独立 · AI") < position("PROXY"));
    assert!(position("PROXY") < position("oracle-cloud"));
    assert_eq!(first(&new, "oracle-cloud"), "DIRECT");
}
