use serde_json::json;
use std::collections::BTreeSet;
use xcli_panel_rules::{parse_rules, validate};

#[test]
fn preserves_rule_order_and_resolution_semantics() {
    let rules = parse_rules("# note\nDOMAIN-SUFFIX,google.com,独立 · Google\nIP-CIDR,192.0.2.0/24,PROXY\nIP-CIDR6,2001:db8::/32,DIRECT,resolve\nGEOIP,CN,DIRECT,no-resolve", "independent", &BTreeSet::new()).unwrap();
    assert_eq!(rules.len(), 4);
    assert_eq!(rules[0].target, "独立 · Google");
    assert!(rules[1].no_resolve && !rules[1].explicit_resolution);
    assert!(!rules[2].no_resolve && rules[2].explicit_resolution);
    assert!(rules[3].no_resolve && rules[3].explicit_resolution);
}

#[test]
fn groups_validate_targets_and_do_not_collide_with_builtins() {
    let value = json!({"base":"independent", "ai_outbound":"proxy", "rules":"DOMAIN,example.com,工作",
        "groups":[{"name":"工作","default":"故障转移"}]});
    assert_eq!(validate(&value).unwrap(), value);
    let mut invalid = value.clone();
    invalid["groups"][0]["name"] = json!("独立 · Google");
    assert!(validate(&invalid).is_err());
    let invalid =
        json!({"base":"standard", "ai_outbound":"proxy", "rules":"DOMAIN,example.com,工作"});
    assert!(validate(&invalid).is_err());
}

#[test]
fn validation_reports_the_original_line_number() {
    let input = json!({"base":"standard","ai_outbound":"proxy","rules":"# header\n\nDOMAIN,GOOGLE.COM,PROXY"});
    assert_eq!(
        validate(&input).unwrap_err().0,
        "第 3 行：域名规则需要小写英文域名"
    );
}

#[test]
fn group_defaults_extend_old_specs_without_accepting_unknown_groups_or_selectors() {
    let old = json!({"base":"independent","ai_outbound":"residential-41","rules":""});
    assert_eq!(validate(&old).unwrap(), old);
    let spec = json!({"base":"independent","ai_outbound":"residential-41","rules":"DOMAIN,example.com,工作",
        "groups":[{"name":"工作","default":"PROXY"}],
        "group_defaults":{"独立 · AI":"node:residential-41","独立 · Google":"selector:自动选择","工作":"country:US"}});
    assert_eq!(validate(&spec).unwrap(), spec);
    for (group, choice) in [
        ("DIRECT", "node:reality"),
        ("oracle-cloud", "node:reality"),
        ("独立 · AI", "node:../bad"),
        ("独立 · AI", "selector:other"),
    ] {
        let mut bad = old.clone();
        bad["group_defaults"] = json!({group:choice});
        assert!(validate(&bad).is_err(), "{group} {choice}");
    }
    let mut standard = old.clone();
    standard["base"] = json!("standard");
    standard["group_defaults"] = json!({"独立 · AI":"node:reality"});
    assert!(validate(&standard).is_err());
}
