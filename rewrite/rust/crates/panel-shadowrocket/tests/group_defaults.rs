use serde_json::{json, Value};
use xcli_panel_rules::{factory_independent_rules, factory_spec};
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
fn published_factory_rules_and_custom_group_are_rendered_for_shadowrocket() {
    let mut policy = factory_spec("independent").unwrap();
    policy["managed"] = json!(true);
    let config = profile(&settings(), &user(), &[], false, &policy).unwrap();
    assert!(config.contains("XCLI-独立 · Stripe = select,"));
    assert!(config.contains("DOMAIN-SUFFIX,stripe.com,XCLI-独立 · Stripe\n"));
    assert!(config.contains("DOMAIN-SUFFIX,aliyun.com,DIRECT\n"));
    assert!(config.find("XCLI-独立 · AI = select,").unwrap()
        < config.find("XCLI-独立 · Google = select,").unwrap());
    assert!(config.find("XCLI-独立 · Google = select,").unwrap()
        < config.find("XCLI-独立 · Stripe = select,").unwrap());
    assert!(config.contains("XCLI-独立 · EaseLian = select,"));
}

#[test]
fn independent_group_defaults_are_reflected_in_shadowrocket_groups() {
    let policy = json!({"base":"independent","ai_outbound":"proxy","rules":factory_independent_rules(),"managed":true,
        "group_defaults":{"独立 · AI":"node:residential-41","独立 · Google":"node:reality"}});
    let config = profile(&settings(), &user(), &[], false, &policy).unwrap();
    assert!(config.contains("XCLI-独立 · AI = select,XCLI-美国01,"));
    assert!(config.contains("XCLI-独立 · Google = select,test · REALITY,"));
    assert!(config.contains("XCLI-美国01 = fallback,test · 美国01,test · 美国01 · HTTPS,interval=120,timeout=5,url=https://www.gstatic.com/generate_204,hidden=1"));
}

#[test]
fn each_independent_group_lists_the_same_country_exits_separately() {
    let mut settings = settings();
    settings["residential_exits"] = json!([
        {"tag":"residential-41","label":"新加坡 A","exit_ip":"8.8.4.4","country":"SG",
         "ws_path":"/connect/test/residential-41","hysteria2":true},
        {"tag":"residential-42","label":"新加坡 B","exit_ip":"1.1.1.1","country":"SG",
         "ws_path":"/connect/test/residential-42","hysteria2":true},
        {"tag":"residential-43","label":"新加坡 C","exit_ip":"9.9.9.9","country":"SG",
         "ws_path":"/connect/test/residential-43","hysteria2":false}
    ]);
    let policy = json!({"base":"independent","ai_outbound":"proxy",
        "rules":factory_independent_rules(),"managed":true,
        "groups":[{"name":"工作","default":"PROXY"}],
        "group_defaults":{"独立 · AI":"node:residential-41",
                          "独立 · Google":"node:residential-42"}});
    let config = profile(&settings, &user(), &[], false, &policy).unwrap();
    for name in ["XCLI-独立 · AI", "XCLI-独立 · Google", "XCLI-工作"] {
        let line = config.lines().find(|line| line.starts_with(&format!("{name} = select,"))).unwrap();
        for node in ["XCLI-新加坡01", "XCLI-新加坡02", "test · 新加坡03"] {
            assert_eq!(line.split(',').filter(|part| *part == node).count(), 1, "{name}");
        }
    }
    assert!(config.contains("XCLI-独立 · AI = select,XCLI-新加坡01,"));
    assert!(config.contains("XCLI-独立 · Google = select,XCLI-新加坡02,"));
    assert!(config.contains("XCLI-住宅分组 · 新加坡 = select,XCLI-新加坡01,XCLI-新加坡02,test · 新加坡03,hidden=1"));
    for node in ["新加坡01", "新加坡02"] {
        assert!(config.contains(&format!("XCLI-{node} = fallback,test · {node},test · {node} · HTTPS,")));
    }
    let subscription_user = xcli_panel_subscription::User {
        name: "test".into(), uuid: user().uuid, token: user().token,
        enabled: true, deleted: false, quota: 0, expires: 0, upload: 0, download: 0,
    };
    let links = xcli_panel_subscription::build(&settings, &subscription_user, &[], false).unwrap();
    fn fragment(link: &str) -> String {
        let text = link.split_once('#').unwrap().1.as_bytes();
        let mut output = Vec::new();
        let mut i = 0;
        while i < text.len() {
            if text[i] == b'%' {
                output.push(u8::from_str_radix(std::str::from_utf8(&text[i+1..i+3]).unwrap(), 16).unwrap());
                i += 3;
            } else { output.push(text[i]); i += 1; }
        }
        String::from_utf8(output).unwrap()
    }
    for (tag, label) in [("residential-41", "新加坡01"), ("residential-42", "新加坡02")] {
        assert_eq!(fragment(links.get(&format!("{tag}-hy2")).unwrap()), format!("test · {label}"));
        assert_eq!(fragment(links.get(tag).unwrap()), format!("test · {label} · HTTPS"));
    }
    assert_eq!(fragment(links.get("residential-43").unwrap()), "test · 新加坡03");
    let stun = config.lines().find(|line| line.starts_with("XCLI-独立 · STUN = select,")).unwrap();
    assert!(!stun.contains("新加坡01"));
    assert!(!stun.contains("新加坡02"));
}

#[test]
fn legacy_standard_users_get_a_profile_when_fixed_failover_exists() {
    let policy = json!({"base":"standard","ai_outbound":"proxy","rules":"","managed":false});
    let mut values = settings();
    values["shadowrocket_base_profiles"] = json!({(user().id):"[General]\ninclude = default.conf\n[Rule]\nDOMAIN,custom.example,DIRECT\nFINAL,PROXY\n"});
    assert_eq!(setup(&values, &user(), &policy).unwrap()["service_routing"], true);
    let config = profile(&values, &user(), &[], false, &policy).unwrap();
    assert!(config.contains("DOMAIN,custom.example,DIRECT"));
    assert!(config.contains("XCLI-美国01 = fallback,"));
    values["residential_exits"][0]["hysteria2"] = json!(false);
    assert_eq!(setup(&values, &user(), &policy).unwrap()["service_routing"], false);
}

#[test]
fn existing_custom_base_references_follow_the_renamed_fixed_exit() {
    let mut values = settings();
    values["shadowrocket_base_profiles"] = json!({(user().id):
        "[General]\ninclude = default.conf\n[Proxy Group]\n工作 = select,test · 住宅 US · 8.8.4.4,test · 住宅 US · 8.8.4.4 · HTTPS\n[Rule]\nDOMAIN,one.example,test · 住宅 US · 8.8.4.4 # keep\nDOMAIN,two.example,XCLI-住宅 US · 8.8.4.4\nFINAL,PROXY\n"});
    let policy = json!({"base":"standard","ai_outbound":"proxy","rules":"","managed":false});
    let config = profile(&values, &user(), &[], false, &policy).unwrap();
    assert!(config.contains("工作 = select,test · 美国01,test · 美国01 · HTTPS\n"));
    assert!(config.contains("DOMAIN,one.example,test · 美国01 # keep\n"));
    assert!(config.contains("DOMAIN,two.example,XCLI-美国01\n"));
    assert!(!config.contains("test · 住宅 US · 8.8.4.4"));

    values["residential_exits"][0]["label"] = json!("住宅 #1");
    values["shadowrocket_base_profiles"] = json!({(user().id):
        "[General]\ninclude = default.conf\n[Rule]\nDOMAIN,one.example,test · 住宅 #1 · 8.8.4.4 # keep\nFINAL,PROXY\n"});
    let config = profile(&values, &user(), &[], false, &policy).unwrap();
    assert!(config.contains("DOMAIN,one.example,test · 美国01 # keep\n"));
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

#[test]
fn group_display_order_is_shared_with_shadowrocket() {
    let policy = json!({"base":"independent","ai_outbound":"proxy","rules":factory_independent_rules(),"managed":true,
        "group_order":["独立 · Google","独立 · AI","PROXY"]});
    let config = profile(&settings(), &user(), &[], false, &policy).unwrap();
    let google = config.find("XCLI-独立 · Google = select,").unwrap();
    let ai = config.find("XCLI-独立 · AI = select,").unwrap();
    let proxy = config.find("XCLI-PROXY = select,").unwrap();
    assert!(google < ai && ai < proxy);
}

#[test]
fn system_domain_edits_are_included_in_shadowrocket() {
    let rows = xcli_panel_clash::system_rules_preview("panel.example.com", "independent").unwrap();
    let row = rows
        .iter()
        .find(|row| {
            row["kind"] == "DOMAIN-SUFFIX"
                && row["value"] == "google.com"
                && row["target"] == "独立 · Google"
        })
        .unwrap();
    let mut policy = json!({"base":"independent","ai_outbound":"proxy","rules":"","managed":true,"system_overrides":{}});
    policy["system_overrides"][row["id"].as_str().unwrap()] =
        json!({"kind":"DOMAIN-SUFFIX","value":"google.com","target":"DIRECT","option":""});
    let config = profile(&settings(), &user(), &[], false, &policy).unwrap();
    assert!(config.contains("DOMAIN-SUFFIX,google.com,DIRECT\n"));
}

#[test]
fn changed_geo_rules_are_converted_for_shadowrocket_and_keep_custom_base_rules() {
    let rows = xcli_panel_clash::system_rules_preview("panel.example.com", "standard").unwrap();
    let cn = rows
        .iter()
        .find(|row| row["kind"] == "GEOSITE" && row["value"] == "cn")
        .unwrap();
    let fallback = rows.iter().find(|row| row["kind"] == "MATCH").unwrap();
    let mut policy = json!({"base":"standard","ai_outbound":"proxy","rules":"","managed":true,"system_overrides":{}});
    policy["system_overrides"][cn["id"].as_str().unwrap()] =
        json!({"kind":"GEOSITE","value":"cn","target":"PROXY","option":""});
    policy["system_overrides"][fallback["id"].as_str().unwrap()] =
        json!({"kind":"MATCH","value":"全部剩余流量","target":"DIRECT","option":""});
    let mut values = settings();
    values["shadowrocket_base_profiles"] = json!({(user().id):"[General]\ninclude = default.conf\n[Rule]\nDOMAIN,custom.example,DIRECT\nGEOIP,CN,DIRECT\nFINAL,PROXY\n"});
    let config = profile(&values, &user(), &[], false, &policy).unwrap();
    let custom = config.find("DOMAIN,custom.example,DIRECT").unwrap();
    let converted = config
        .find("RULE-SET,https://panel.example.com/api/geosite/cn.list,XCLI-PROXY")
        .unwrap();
    let geoip = config.find("GEOIP,CN,DIRECT").unwrap();
    assert!(custom < converted && converted < geoip);
    assert!(config.contains(
        "RULE-SET,https://panel.example.com/api/geosite/geolocation-%21cn.list,XCLI-PROXY"
    ));
    assert!(config.contains("FINAL,DIRECT\n"));
}

#[test]
fn template_rule_priority_is_preserved_in_clash_and_shadowrocket() {
    let policy = json!({"base":"independent","ai_outbound":"proxy","rules":"DOMAIN-SUFFIX,example.com,独立 · Google\nDOMAIN,api.example.com,独立 · AI\n","managed":true});
    let clash_user = xcli_panel_clash::User {
        id: user().id,
        uuid: user().uuid,
    };
    let clash = xcli_panel_clash::build(&settings(), &clash_user, &[], false, &policy).unwrap();
    let rules = clash["rules"].as_array().unwrap();
    let broad = rules
        .iter()
        .position(|r| r == "DOMAIN-SUFFIX,example.com,独立 · Google")
        .unwrap();
    let specific = rules
        .iter()
        .position(|r| r == "DOMAIN,api.example.com,独立 · AI")
        .unwrap();
    assert!(broad < specific);
    let shadow = profile(&settings(), &user(), &[], false, &policy).unwrap();
    assert!(
        shadow
            .find("DOMAIN-SUFFIX,example.com,XCLI-独立 · Google")
            .unwrap()
            < shadow
                .find("DOMAIN,api.example.com,XCLI-独立 · AI")
                .unwrap()
    );
    let mut reversed = policy.clone();
    reversed["rules"] =
        json!("DOMAIN,api.example.com,独立 · AI\nDOMAIN-SUFFIX,example.com,独立 · Google\n");
    let clash = xcli_panel_clash::build(&settings(), &clash_user, &[], false, &reversed).unwrap();
    let rules = clash["rules"].as_array().unwrap();
    assert!(
        rules
            .iter()
            .position(|r| r == "DOMAIN,api.example.com,独立 · AI")
            .unwrap()
            < rules
                .iter()
                .position(|r| r == "DOMAIN-SUFFIX,example.com,独立 · Google")
                .unwrap()
    );
    let shadow = profile(&settings(), &user(), &[], false, &reversed).unwrap();
    assert!(
        shadow
            .find("DOMAIN,api.example.com,XCLI-独立 · AI")
            .unwrap()
            < shadow
                .find("DOMAIN-SUFFIX,example.com,XCLI-独立 · Google")
                .unwrap()
    );
}

#[test]
fn renamed_groups_update_shadowrocket_rules_and_legacy_fallbacks() {
    let policy = json!({"base":"independent","ai_outbound":"proxy","managed":true,
        "rules":"DOMAIN,api.example.com,独立 · AI\n",
        "group_names":{"独立 · AI":"人工智能","独立 · Google":"谷歌","PROXY":"默认代理","其他流量":"其他"}});
    let mut values = settings();
    values["shadowrocket_base_profiles"] = json!({(user().id):"[General]\ninclude = default.conf\n[Proxy Group]\nExisting = select,XCLI-独立 · AI\n[Rule]\nDOMAIN,legacy.example,XCLI-独立 · AI\nDOMAIN-KEYWORD,google,PROXY\nFINAL,PROXY\n"});
    let config = profile(&values, &user(), &[], false, &policy).unwrap();
    assert!(config.contains("XCLI-人工智能 = select,"));
    assert!(config.contains("XCLI-谷歌 = select,"));
    assert!(config.contains("DOMAIN,api.example.com,XCLI-人工智能"));
    assert!(config.contains("DOMAIN,legacy.example,XCLI-人工智能"));
    assert!(config.contains("Existing = select,XCLI-人工智能"));
    assert!(config.contains("DOMAIN-KEYWORD,google,XCLI-谷歌"));
    assert!(config.contains("FINAL,XCLI-其他"));
    assert!(!config.contains("XCLI-独立 · AI = select,"));
}

#[test]
fn renaming_only_the_standard_proxy_enables_a_matching_profile() {
    let policy = json!({"base":"standard","ai_outbound":"proxy","rules":"","managed":true,
        "group_names":{"PROXY":"默认代理"}});
    assert_eq!(
        setup(&settings(), &user(), &policy).unwrap()["service_routing"],
        true
    );
    let config = profile(&settings(), &user(), &[], false, &policy).unwrap();
    assert!(config.contains("XCLI-默认代理 = select,"));
    assert!(config.contains("FINAL,XCLI-默认代理"));
    assert!(!config.contains("XCLI-PROXY = select,"));
}
