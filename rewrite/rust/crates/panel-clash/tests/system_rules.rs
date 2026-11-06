use xcli_panel_clash::system_rules_preview;

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
    assert!(!serialized.contains("00000000-0000-4000-8000-000000000000"));
    assert!(!serialized.contains("192.0.2.1"));

    let standard = system_rules_preview("panel.example.com", "standard").unwrap();
    assert!(!standard.iter().any(|r| r["target"] == "独立 · Google"));
    assert!(standard.iter().any(|r| r["target"] == "STUN"));
    assert!(system_rules_preview("panel.example.com", "unknown").is_err());
}
