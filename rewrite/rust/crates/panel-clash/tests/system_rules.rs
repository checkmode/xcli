use serde_json::{json, Value};
use xcli_panel_clash::{build, system_rules_preview, User};

#[test]
fn system_preview_expands_real_providers_without_template_rules_or_credentials() {
    let independent = system_rules_preview("panel.example.com", "independent").unwrap();
    let has = |kind: &str, value: &str, target: &str| {
        independent
            .iter()
            .any(|r| r["kind"] == kind && r["value"] == value && r["target"] == target)
    };
    assert!(has("DOMAIN-SUFFIX", "google.com", "独立 · Google"));
    assert!(has("DOMAIN-SUFFIX", "oraclecloud.com", "oracle-cloud"));
    assert!(has("DOMAIN", "panel.example.com", "DIRECT"));
    assert!(!has("DOMAIN-SUFFIX", "openai.com", "独立 · AI"));
    assert!(independent.iter().any(|r| r["target"] == "独立 · STUN"
        && r["value"].as_str().unwrap().contains("stun.l.google.com")));
    let serialized = serde_json::to_string(&independent).unwrap();
    let identifiers: std::collections::BTreeSet<_> = independent
        .iter()
        .map(|row| row["id"].as_str().unwrap())
        .collect();
    assert_eq!(identifiers.len(), independent.len());
    assert!(!serialized.contains("00000000-0000-4000-8000-000000000000"));
    assert!(!serialized.contains("192.0.2.1"));

    let standard = system_rules_preview("panel.example.com", "standard").unwrap();
    assert!(!standard.iter().any(|r| r["target"] == "独立 · Google"));
    assert!(standard.iter().any(|r| r["target"] == "STUN"));
    assert!(system_rules_preview("panel.example.com", "unknown").is_err());
}

fn settings() -> Value {
    json!({"public_ip":"8.8.8.8","domain":"panel.example.com","public_port":443,"hysteria2_port":8443,
        "ws_path":"/connect/test","reality_sni":"www.example.com","reality_public":"public","short_id":"0123456789abcdef"})
}
fn user() -> User {
    User {
        id: "a".repeat(32),
        uuid: "01234567-89ab-4def-8123-456789abcdef".into(),
    }
}
fn edit(row: &Value, target: &str) -> Value {
    json!({"kind":row["kind"],"value":row["value"],"target":target,"option":row["option"]})
}

#[test]
fn system_overrides_change_the_original_rule_and_dns_without_reordering_others() {
    let rows = system_rules_preview("panel.example.com", "independent").unwrap();
    let google = rows
        .iter()
        .find(|r| {
            r["kind"] == "DOMAIN-SUFFIX"
                && r["value"] == "google.com"
                && r["target"] == "独立 · Google"
        })
        .unwrap();
    let oracle = rows
        .iter()
        .find(|r| r["kind"] == "DOMAIN-SUFFIX" && r["value"] == "oraclecloud.com")
        .unwrap();
    let mut policy = json!({"base":"independent","ai_outbound":"proxy","rules":"","managed":true,"system_overrides":{}});
    policy["system_overrides"][google["id"].as_str().unwrap()] = edit(google, "DIRECT");
    policy["system_overrides"][oracle["id"].as_str().unwrap()] = edit(oracle, "PROXY");
    let config = build(&settings(), &user(), &[], false, &policy).unwrap();
    let rules = config["rules"].as_array().unwrap();
    assert!(rules.contains(&json!("DOMAIN-SUFFIX,google.com,DIRECT")));
    assert!(rules.contains(&json!("DOMAIN-SUFFIX,oraclecloud.com,PROXY")));
    assert!(config["dns"]["nameserver-policy"]["+.google.com"][0]
        .as_str()
        .unwrap()
        .ends_with("#DIRECT"));
    assert!(config["dns"]["nameserver-policy"]["+.oraclecloud.com"][0]
        .as_str()
        .unwrap()
        .ends_with("#PROXY"));
    assert!(
        !config["rule-providers"]["xcli-oracle-cloud-dns-edited"]["payload"]
            .as_array()
            .unwrap()
            .contains(&json!("DOMAIN-SUFFIX,oraclecloud.com"))
    );
    let original = build(
        &settings(),
        &user(),
        &[],
        false,
        &json!({"base":"independent","ai_outbound":"proxy","rules":"","managed":true}),
    )
    .unwrap();
    assert!(original["rules"]
        .as_array()
        .unwrap()
        .contains(&json!("RULE-SET,xcli-oracle-cloud,oracle-cloud")));
    assert!(
        rows.iter()
            .find(|r| r["value"] == "oraclecloud.com")
            .unwrap()["after_template"]
            == false
    );
    assert!(google["after_template"] == true);
}

#[test]
fn editing_system_suffix_keeps_earlier_specific_dns_policy() {
    let rows = system_rules_preview("panel.example.com", "independent").unwrap();
    let google = rows
        .iter()
        .find(|row| {
            row["kind"] == "DOMAIN-SUFFIX"
                && row["value"] == "google.com"
                && row["target"] == "独立 · Google"
        })
        .unwrap();
    let mut policy = json!({"base":"independent","ai_outbound":"proxy","rules":"DOMAIN,api.google.com,独立 · AI\n","managed":true,"system_overrides":{}});
    policy["system_overrides"][google["id"].as_str().unwrap()] = edit(google, "DIRECT");
    let config = build(&settings(), &user(), &[], false, &policy).unwrap();
    let dns = config["dns"]["nameserver-policy"].as_object().unwrap();
    let keys = dns.keys().collect::<Vec<_>>();
    assert!(
        keys.iter()
            .position(|key| key.as_str() == "api.google.com")
            .unwrap()
            < keys
                .iter()
                .position(|key| key.as_str() == "+.google.com")
                .unwrap()
    );
    assert!(dns["api.google.com"][0]
        .as_str()
        .unwrap()
        .ends_with("#独立 · AI"));
}

#[test]
fn system_override_can_be_restored_and_unknown_rules_are_rejected() {
    let rows = system_rules_preview("panel.example.com", "standard").unwrap();
    let row = rows
        .iter()
        .find(|r| r["kind"] == "IP-CIDR" && r["value"] == "10.0.0.0/8")
        .unwrap();
    let baseline = json!({"base":"standard","ai_outbound":"proxy","rules":"","managed":true});
    let original = build(&settings(), &user(), &[], false, &baseline).unwrap();
    let mut changed = baseline.clone();
    changed["system_overrides"] = json!({(row["id"].as_str().unwrap()):null});
    let edited = build(&settings(), &user(), &[], false, &changed).unwrap();
    assert!(!edited["rules"]
        .as_array()
        .unwrap()
        .contains(&json!("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve")));
    changed.as_object_mut().unwrap().remove("system_overrides");
    assert_eq!(
        build(&settings(), &user(), &[], false, &changed).unwrap(),
        original
    );
    changed["system_overrides"] = json!({("0".repeat(64)):null});
    assert!(build(&settings(), &user(), &[], false, &changed).is_err());
}
