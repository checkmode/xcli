use serde_json::{json, Value};
use xcli_panel_monitor::report::{aggregate, Dns, Https, Observation, Outcome, Scope};
use xcli_panel_monitor::Config;

fn base() -> Value {
    json!({"domain":"panel.example.com","public_ip":"8.8.8.8","reality_sni":"example.com",
        "reality_public":"fixture-public-key","short_id":"0123456789abcdef",
        "uuid":"11111111-2222-3333-4444-555555555555","ws_path":"/connect/fixture","hysteria2_port":443})
}
fn parse(value: &Value) -> bool {
    Config::parse(&serde_json::to_vec(value).unwrap()).is_ok()
}

#[test]
fn rejects_malformed_credentials_inconsistent_exits_and_ports() {
    assert!(parse(&base()));
    for (key, value) in [
        ("uuid", json!("not-a-uuid")),
        ("public_ip", json!("bad")),
        ("domain", json!("example.com\nother")),
        ("public_port", json!(65536)),
        ("node_address_ip", json!(1)),
    ] {
        let mut config = base();
        config[key] = value;
        assert!(!parse(&config));
    }
    let mut config = base();
    config["hysteria2_port"] = json!(0);
    config["residential_exits"] =
        json!([{"tag":"residential-27","exit_ip":"1.1.1.1","hysteria2":true}]);
    assert!(!parse(&config));
    config["hysteria2_port"] = json!(443);
    let duplicate = config["residential_exits"][0].clone();
    config["residential_exits"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    assert!(!parse(&config));
}

#[test]
fn report_retains_success_history_and_separates_udp_from_residential_doh() {
    let mut input = base();
    input["hysteria2_port"] = json!(0);
    input["residential_exits"] = json!([{"tag":"residential-27","exit_ip":"1.1.1.1","ws_path":"/connect/fixture/residential-27"}]);
    let config = Config::parse(&serde_json::to_vec(&input).unwrap()).unwrap();
    let previous = json!({"checks":[{"transport":"websocket","last_success":80},{"transport":"residential-27","last_success":90},
        {"transport":"unrelated","last_success":99}]});
    let observations = vec![
        Observation {
            kind: "residential-27".into(),
            finished_at: None,
            outcome: Outcome::Measured {
                https: Https::Ok(10),
                dns: Dns::Failed,
            },
        },
        Observation {
            kind: "reality".into(),
            finished_at: Some(99),
            outcome: Outcome::Measured {
                https: Https::Ok(1),
                dns: Dns::Ok(2),
            },
        },
        Observation {
            kind: "websocket".into(),
            finished_at: None,
            outcome: Outcome::ClientUnavailable,
        },
    ];
    let report = aggregate(&config, Scope::Server, 100, observations, Some(&previous)).unwrap();
    let report = report.as_value();
    assert_eq!(report["status"], "failed");
    assert_eq!(report["checks"][0]["last_success"], 99);
    assert_eq!(report["checks"][0]["udp_ms"], 2);
    assert_eq!(report["checks"][1]["last_success"], 80);
    assert_eq!(report["checks"][2]["last_success"], 90);
    assert_eq!(report["checks"][2]["https_ms"], 10);
    assert_eq!(report["checks"][2]["doh_ms"], Value::Null);
    assert_eq!(report["checks"][2]["udp_supported"], false);
    assert_eq!(report["checks"][2]["error"], "DoH probe failed");
    assert!(!serde_json::to_string(&report)
        .unwrap()
        .contains("11111111-2222-3333-4444-555555555555"));
    let duplicate = vec![
        Observation {
            kind: "reality".into(),
            finished_at: None,
            outcome: Outcome::ClientUnavailable,
        },
        Observation {
            kind: "reality".into(),
            finished_at: None,
            outcome: Outcome::ClientUnavailable,
        },
        Observation {
            kind: "residential-27".into(),
            finished_at: None,
            outcome: Outcome::ClientUnavailable,
        },
    ];
    assert!(aggregate(&config, Scope::Server, 100, duplicate, None).is_err());
}
