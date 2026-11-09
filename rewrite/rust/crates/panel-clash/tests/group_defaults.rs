use serde_json::{json, Value};
use xcli_panel_clash::{build, template_group_catalog, template_group_catalogs, User};
use xcli_panel_rules::{factory_independent_rules, factory_spec};

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

fn members<'a>(config: &'a Value, name: &str) -> &'a Vec<Value> {
    config["proxy-groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap()["proxies"]
        .as_array()
        .unwrap()
}

#[test]
fn published_factory_rules_and_custom_group_are_rendered_for_clash() {
    let mut policy = factory_spec("independent").unwrap();
    policy["managed"] = json!(true);
    let config = build(&settings(), &user(), &[], false, &policy).unwrap();
    assert!(members(&config, "独立 · Stripe").contains(&json!("美国01")));
    let rules = config["rules"].as_array().unwrap();
    assert!(rules.contains(&json!("DOMAIN-SUFFIX,stripe.com,独立 · Stripe")));
    assert!(rules.contains(&json!("DOMAIN-SUFFIX,aliyun.com,DIRECT")));
    let groups = config["proxy-groups"].as_array().unwrap();
    let position = |name: &str| groups.iter().position(|g| g["name"] == name).unwrap();
    assert!(position("独立 · AI") < position("独立 · Google"));
    assert!(position("独立 · Google") < position("独立 · Stripe"));
    assert!(groups.iter().any(|g| g["name"] == "独立 · EaseLian"));
}

#[test]
fn independent_and_custom_groups_can_select_distinct_exits_in_the_same_country() {
    let mut settings = settings();
    settings["residential_exits"] = json!([
        {"tag":"residential-41","label":"新加坡 A","exit_ip":"8.8.4.4","country":"SG",
         "ws_path":"/connect/test/residential-41","hysteria2":true},
        {"tag":"residential-42","label":"新加坡 B","exit_ip":"1.1.1.1","country":"SG",
         "ws_path":"/connect/test/residential-42","hysteria2":true},
        {"tag":"residential-43","label":"新加坡动态","exit_ip":"","country":"SG",
         "ws_path":"/connect/test/residential-43","dynamic":true}
    ]);
    let a = "新加坡01";
    let b = "新加坡02";
    let mut policy = json!({"base":"independent","ai_outbound":"proxy",
        "rules":factory_independent_rules(),"managed":true,
        "groups":[{"name":"工作","default":"PROXY"}]});
    let initial = build(&settings, &user(), &[], false, &policy).unwrap();
    for group in ["PROXY", "独立 · AI", "独立 · Google", "独立 · Telegram", "其他流量", "工作"] {
        let nodes = members(&initial, group);
        for node in [a, b] {
            assert_eq!(nodes.iter().filter(|value| *value == node).count(), 1, "{group}");
        }
        assert!(!nodes.contains(&json!("新加坡动态")));
        assert!(!nodes.contains(&json!(format!("{a} · Hysteria2"))));
        assert!(!nodes.contains(&json!(format!("{a} · HTTPS"))));
    }
    for group in ["独立 · AI", "独立 · Google"] {
        assert_eq!(first(&initial, group), "故障转移");
        assert!(!members(&initial, group).contains(&json!("住宅分组 · 新加坡")));
        assert!(members(&initial, group).contains(&json!("DIRECT")));
    }
    assert_eq!(initial["proxy-groups"].as_array().unwrap().iter()
        .find(|g| g["name"] == "住宅分组 · 新加坡").unwrap()["hidden"], true);
    assert!(!members(&initial, "独立 · STUN").contains(&json!(a)));
    assert!(!members(&initial, "独立 · STUN").contains(&json!(b)));
    for group in ["故障转移", "自动选择"] {
        assert!(!members(&initial, group).contains(&json!(a)));
        assert!(!members(&initial, group).contains(&json!(b)));
    }
    assert_eq!(initial["dns"]["nameserver-policy"]["+.openai.com"][0],
        "https://1.1.1.1/dns-query#独立 · AI");
    assert_eq!(initial["dns"]["direct-nameserver-follow-policy"], false);

    policy["group_defaults"] = json!({"独立 · AI":"node:residential-41",
        "独立 · Google":"node:residential-42"});
    let configured = build(&settings, &user(), &[], false, &policy).unwrap();
    assert_eq!(first(&configured, "独立 · AI"), a);
    assert_eq!(first(&configured, "独立 · Google"), b);
    for (group, node) in [("独立 · AI", a), ("独立 · Google", b)] {
        assert_eq!(members(&configured, group).iter().filter(|value| *value == node).count(), 1);
    }
    assert_eq!(configured["rules"], initial["rules"]);
    assert_eq!(configured["dns"], initial["dns"]);
    assert_eq!(configured["proxies"], initial["proxies"]);

    policy["group_defaults"] = json!({"独立 · AI":"country:SG"});
    let migrated = build(&settings, &user(), &[], false, &policy).unwrap();
    assert_eq!(first(&migrated, "独立 · AI"), a);
    assert!(!members(&migrated, "独立 · AI").contains(&json!("住宅分组 · 新加坡")));
    policy["group_defaults"]["PROXY"] = json!("selector:直连");
    let direct = build(&settings, &user(), &[], false, &policy).unwrap();
    assert_eq!(first(&direct, "PROXY"), "DIRECT");

    policy["rules"] = json!("DOMAIN,example.com,独立 · AI");
    let custom = build(&settings, &user(), &[], false, &policy).unwrap();
    assert_eq!(custom["dns"]["nameserver-policy"]["example.com"][0],
        "https://1.1.1.1/dns-query#独立 · AI");

    let enabled = build(&settings, &user(), &[], true, &policy).unwrap();
    assert!(members(&enabled, "独立 · AI").contains(&json!("新加坡动态")));
    assert_eq!(first(&enabled, "独立 · AI"), "新加坡动态");

    settings["client_policies"] = json!({(user().id): {"ai_outbound":"proxy"}});
    let legacy = json!({"base":"independent","ai_outbound":"proxy","rules":"","managed":false});
    let legacy_config = build(&settings, &user(), &[], false, &legacy).unwrap();
    for group in ["独立 · AI", "独立 · Google"] {
        assert!(members(&legacy_config, group).contains(&json!(a)));
        assert!(members(&legacy_config, group).contains(&json!(b)));
        assert_eq!(first(&legacy_config, group), "故障转移");
    }
}

#[test]
fn legacy_ai_is_preserved_and_per_group_defaults_only_reorder_requested_groups() {
    let base = json!({"base":"independent","ai_outbound":"residential-41","rules":factory_independent_rules(),"managed":true,
        "groups":[{"name":"工作","default":"PROXY"}]});
    let old = build(&settings(), &user(), &[], false, &base).unwrap();
    assert_eq!(first(&old, "独立 · AI"), "美国01");
    assert_eq!(first(&old, "独立 · Google"), "故障转移");
    let mut policy = base.clone();
    policy["group_defaults"] = json!({"独立 · AI":"node:reality","独立 · Google":"selector:自动选择",
        "独立 · STUN":"node:hysteria2","工作":"node:residential-41"});
    let updated = build(&settings(), &user(), &[], false, &policy).unwrap();
    assert_eq!(first(&updated, "独立 · AI"), "REALITY");
    assert_eq!(first(&updated, "独立 · Google"), "自动选择");
    assert_eq!(first(&updated, "独立 · STUN"), "Hysteria 2");
    assert_eq!(first(&updated, "工作"), "美国01");
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
fn fixed_exit_defaults_to_automatic_fallback_for_both_base_templates() {
    for base in ["standard", "independent"] {
        let policy = json!({"base":base,"ai_outbound":"proxy","rules":"","managed":true});
        let config = build(&settings(), &user(), &[], false, &policy).unwrap();
        let groups = config["proxy-groups"].as_array().unwrap();
        let fallback = groups.iter().find(|g| g["name"] == "美国01").unwrap();
        assert_eq!(fallback["type"], "fallback");
        assert_eq!(fallback["proxies"], json!(["美国01 · Hysteria2","美国01 · HTTPS"]));
        assert_eq!(fallback["hidden"], true);
        assert_eq!(fallback["lazy"], false);
        assert_eq!(fallback["expected-status"], "204");
        assert_eq!(fallback["interval"], 120);
    }
}

#[test]
fn compact_fallback_does_not_create_an_extra_group_and_preserves_dynamic_groups() {
    let mut values = settings();
    values["residential_exits"][1]["hysteria2"] = json!(true);
    let policy = json!({"base":"independent","ai_outbound":"proxy","rules":"","managed":true,
        "groups":[{"name":"美国01 · 自动","default":"PROXY"}]});
    let config = build(&values, &user(), &[], true, &policy).unwrap();
    let groups = config["proxy-groups"].as_array().unwrap();
    let fixed = groups.iter().find(|g| g["name"] == "美国01").unwrap();
    assert_eq!(fixed["type"], "fallback");
    assert!(groups.iter().any(|g| g["name"] == "美国01 · 自动" && g["type"] == "select"));
    let dynamic = groups.iter().find(|g| g["name"] == "动态 US").unwrap();
    assert_eq!(dynamic["type"], "select");
    assert_eq!(dynamic["proxies"], json!(["动态 US · HTTPS", "动态 US · Hysteria2"]));
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
    reordered["group_order"] = json!([
        "独立 · Google",
        "DIRECT",
        "独立 · AI",
        "PROXY",
        "oracle-cloud"
    ]);
    let new = build(&settings(), &user(), &[], false, &reordered).unwrap();
    for key in ["rules", "dns", "proxies", "rule-providers"] {
        assert_eq!(new[key], old[key], "{key}");
    }
    let names: Vec<&str> = new["proxy-groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|group| group["name"].as_str().unwrap())
        .collect();
    let position = |name| names.iter().position(|item| *item == name).unwrap();
    assert!(position("独立 · Google") < position("独立 · AI"));
    assert!(position("独立 · AI") < position("PROXY"));
    assert!(position("PROXY") < position("oracle-cloud"));
    assert_eq!(first(&new, "oracle-cloud"), "DIRECT");
}

#[test]
fn visible_generated_groups_can_be_catalogued_and_reordered() {
    let mut values = settings();
    values["residential_exits"][1]["hysteria2"] = json!(true);
    let (_, catalog) = template_group_catalogs(&values, &[], true).unwrap();
    let ids = |base: &str| catalog[base].as_array().unwrap().iter()
        .map(|item| item["value"].as_str().unwrap().to_owned()).collect::<Vec<_>>();
    let independent = ids("independent");
    for group in ["PROXY", "直连", "故障转移", "自动选择", "独立 · AI", "#node:residential-42", "__custom__", "oracle-cloud"] {
        assert!(independent.contains(&group.to_owned()), "{group}");
    }
    assert!(!independent.contains(&"#country:US".to_owned()));
    assert!(!independent.contains(&"#node:residential-41".to_owned()));
    assert!(ids("standard").contains(&"#country:US".to_owned()));

    let mut policy = json!({"base":"independent","ai_outbound":"proxy","rules":"","managed":true,
        "group_order":["自动选择","独立 · AI","故障转移","#node:residential-42","直连","PROXY"]});
    let mut original_policy = policy.clone();
    original_policy.as_object_mut().unwrap().remove("group_order");
    let original = build(&values, &user(), &[], true, &original_policy).unwrap();
    let actual = build(&values, &user(), &[], true, &policy).unwrap();
    for key in ["rules", "dns", "proxies", "rule-providers"] {
        assert_eq!(actual[key], original[key], "{key}");
    }
    let positions = |config: &Value, names: &[&str]| names.iter().map(|name|
        config["proxy-groups"].as_array().unwrap().iter().position(|g| g["name"] == *name).unwrap()
    ).collect::<Vec<_>>();
    let independent_positions = positions(&actual, &["自动选择", "独立 · AI", "故障转移", "动态 US", "直连", "PROXY"]);
    assert!(independent_positions.windows(2).all(|v| v[0] < v[1]));
    policy["base"] = json!("standard");
    policy["group_order"] = json!(["#country:US", "#node:residential-42", "PROXY", "STUN"]);
    let standard = build(&values, &user(), &[], true, &policy).unwrap();
    let standard_positions = positions(&standard, &["住宅分组 · 美国", "动态 US", "PROXY", "STUN"]);
    assert!(standard_positions.windows(2).all(|v| v[0] < v[1]));

    let existing_custom = json!({"base":"independent","ai_outbound":"proxy","rules":"","managed":true,
        "groups":[{"name":"country:US","default":"PROXY"}],"group_order":["country:US","PROXY"]});
    let config = build(&values, &user(), &[], false, &existing_custom).unwrap();
    let custom_positions = positions(&config, &["country:US", "PROXY"]);
    assert!(custom_positions[0] < custom_positions[1]);
}

#[test]
fn builtin_names_update_groups_rules_and_dns_without_changing_priority() {
    let policy = json!({"base":"independent","ai_outbound":"proxy","managed":true,
        "rules":"DOMAIN,api.example.com,独立 · AI\nDOMAIN-SUFFIX,example.com,独立 · Google\n",
        "group_order":["独立 · Google","独立 · AI","PROXY"],
        "group_defaults":{"独立 · AI":"node:reality"},
        "group_names":{"独立 · AI":"人工智能","独立 · Google":"谷歌","PROXY":"默认代理"}});
    let config = build(&settings(), &user(), &[], false, &policy).unwrap();
    assert_eq!(first(&config, "人工智能"), "REALITY");
    let groups = config["proxy-groups"].as_array().unwrap();
    let position = |name| {
        groups
            .iter()
            .position(|group| group["name"] == name)
            .unwrap()
    };
    assert!(position("谷歌") < position("人工智能") && position("人工智能") < position("默认代理"));
    let rules = config["rules"].as_array().unwrap();
    let ai = rules
        .iter()
        .position(|rule| rule == "DOMAIN,api.example.com,人工智能")
        .unwrap();
    let google = rules
        .iter()
        .position(|rule| rule == "DOMAIN-SUFFIX,example.com,谷歌")
        .unwrap();
    assert!(ai < google);
    let dns = serde_json::to_string(&config["dns"]).unwrap();
    assert!(dns.contains("#人工智能") && dns.contains("#默认代理"));
    assert!(!dns.contains("#独立 · AI") && !dns.contains("#PROXY"));
    let mut collision = policy.clone();
    collision["group_names"]["独立 · AI"] = json!("REALITY");
    assert!(build(&settings(), &user(), &[], false, &collision).is_err());
}
