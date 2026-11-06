use serde_json::{json, Value};
use xcli_panel_rules::factory_independent_rules;
use xcli_panel_shadowrocket::{profile, setup, User};

fn settings() -> Value {
    json!({"public_ip":"8.8.8.8","domain":"panel.example.com","origin":"https://panel.example.com",
        "public_port":443,"hysteria2_port":8443,"ws_path":"/connect/test","reality_sni":"www.example.com",
        "reality_public":"public","short_id":"0123456789abcdef",
        "residential_exits":[{"tag":"residential-41","label":"住宅 US","exit_ip":"8.8.4.4","country":"US",
            "ws_path":"/connect/test/residential-41","hysteria2":true}]})
}
fn user() -> User {
    User {
        id: "a".repeat(32),
        name: "test".into(),
        uuid: "01234567-89ab-4def-8123-456789abcdef".into(),
        token: "x".repeat(43),
    }
}

#[test]
fn independent_group_defaults_are_reflected_in_shadowrocket_groups() {
    let policy = json!({"base":"independent","ai_outbound":"proxy","rules":factory_independent_rules(),"managed":true,
        "group_defaults":{"独立 · AI":"node:residential-41","独立 · Google":"node:reality"}});
    let config = profile(&settings(), &user(), &[], false, &policy).unwrap();
    assert!(config.contains("XCLI-独立 · AI = select,XCLI-住宅 US · 8.8.4.4,"));
    assert!(config.contains("XCLI-独立 · Google = select,test · REALITY,"));
    assert!(config.contains("XCLI-住宅 US · 8.8.4.4 = select,"));
}

#[test]
fn standard_template_with_only_group_defaults_generates_a_shadowrocket_profile() {
    let policy = json!({"base":"standard","ai_outbound":"proxy","rules":"","managed":true,
        "group_defaults":{"PROXY":"node:reality"}});
    assert_eq!(
        setup(&settings(), &user(), &policy).unwrap()["service_routing"],
        true
    );
    let config = profile(&settings(), &user(), &[], false, &policy).unwrap();
    assert!(config.contains("XCLI-PROXY = select,test · REALITY,"));
}
