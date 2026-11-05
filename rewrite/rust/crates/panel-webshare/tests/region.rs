use serde_json::json;
use std::net::IpAddr;
use xcli_panel_webshare::probe::{ProbeError, ProbeResult};
use xcli_panel_webshare::region::{maintain, Maintenance, RegionError, Session};

fn entry(name: &str, ip: &str, last_checked: i64) -> Session {
    let mut session = Session::new(name.into(), 10_000).unwrap();
    session.exit_ip = Some(ip.parse().unwrap());
    session.exit_country = "US".into();
    session.last_success = 1900;
    session.last_checked = last_checked;
    session.https_ms = 10;
    session
}
fn probe(ip: &str, now: i64) -> ProbeResult {
    ProbeResult {
        exit_ip: ip.parse::<IpAddr>().unwrap(),
        exit_country: "US".into(),
        https_ms: 12,
        doh_ms: 8,
        last_success: now,
    }
}
fn inputs<'a>(before: &'a [Session], now: i64) -> Maintenance<'a> {
    Maintenance {
        epoch: 7,
        country: "US",
        before,
        now,
        last_used: now,
        cooldown: 10_000,
        forced: false,
    }
}

#[test]
fn sticky_session_survives_two_failures_then_promotes_backup() {
    let mut sessions = vec![
        entry("active", "8.8.8.1", 1),
        entry("backup", "8.8.8.2", 1999),
    ];
    for (index, now) in [2000, 2031, 2062].into_iter().enumerate() {
        let output = maintain(
            inputs(&sessions, now),
            |name| {
                if name == "active" {
                    Err(ProbeError::Unavailable)
                } else {
                    Ok(probe("8.8.8.2", now))
                }
            },
            || Err(RegionError::InvalidInput),
        )
        .unwrap()
        .finish(7, true, Some("active"))
        .unwrap();
        sessions = output.sessions;
        if index < 2 {
            assert_eq!(sessions[0].username(), "active");
            assert_eq!(sessions[0].failures, (index + 1) as u8);
        } else {
            assert_eq!(sessions[0].username(), "backup");
            assert_eq!(output.reason, Some("出口故障切换"));
        }
    }
}

#[test]
fn forced_rotation_and_concurrent_promotion_keep_correct_primary() {
    let sessions = vec![
        entry("active", "8.8.8.1", 1999),
        entry("backup", "8.8.8.2", 1999),
    ];
    let mut input = inputs(&sessions, 2000);
    input.forced = true;
    let output = maintain(
        input,
        |_| Err(ProbeError::Unavailable),
        || Err(RegionError::InvalidInput),
    )
    .unwrap()
    .finish(7, true, Some("active"))
    .unwrap();
    assert_eq!(output.sessions[0].username(), "backup");
    assert_eq!(output.reason, Some("手动更换会话"));
    let pending = maintain(
        inputs(&sessions, 2000),
        |_| Err(ProbeError::Unavailable),
        || Err(RegionError::InvalidInput),
    )
    .unwrap();
    let output = pending.finish(7, true, Some("backup")).unwrap();
    assert_eq!(output.sessions[0].username(), "backup");
    assert_eq!(output.reason, None);
    let pending = maintain(
        inputs(&sessions, 2000),
        |_| Err(ProbeError::Unavailable),
        || Err(RegionError::InvalidInput),
    )
    .unwrap();
    assert!(pending.finish(8, true, Some("active")).is_none());
    let pending = maintain(
        inputs(&sessions, 2000),
        |_| Err(ProbeError::Unavailable),
        || Err(RegionError::InvalidInput),
    )
    .unwrap();
    assert!(pending.finish(7, false, Some("active")).is_none());
}

#[test]
fn creates_at_most_two_unique_exits_and_backs_off_on_duplicates() {
    let mut input = inputs(&[], 2000);
    input.cooldown = 0;
    let mut serial = 0;
    let pending = maintain(
        input,
        |_| Ok(probe("8.8.8.8", 2000)),
        || {
            serial += 1;
            Session::new(format!("fixture-us-{serial}"), 3000)
        },
    )
    .unwrap();
    let result = pending.finish(7, true, None).unwrap();
    assert_eq!(serial, 2);
    assert_eq!(result.sessions.len(), 1);
    assert_eq!(result.cooldown, 2060);
    assert_eq!(result.reason, Some("首次选定出口"));
}

#[test]
fn active_countries_probe_more_often_than_idle_countries() {
    let sessions = vec![
        entry("active", "8.8.8.1", 1800),
        entry("backup", "8.8.8.2", 1800),
    ];
    let mut names = Vec::new();
    let pending = maintain(
        inputs(&sessions, 2000),
        |name| {
            names.push(name.to_owned());
            Ok(probe("8.8.8.1", 2000))
        },
        || Err(RegionError::InvalidInput),
    )
    .unwrap();
    assert_eq!(names, vec!["active"]);
    assert!(pending.finish(7, true, None).is_some());
    let mut idle = inputs(&sessions, 2000);
    idle.last_used = 1000;
    let mut names = Vec::new();
    let pending = maintain(
        idle,
        |name| {
            names.push(name.to_owned());
            Ok(probe("8.8.8.1", 2000))
        },
        || Err(RegionError::InvalidInput),
    )
    .unwrap();
    assert!(names.is_empty());
    assert!(pending.finish(7, true, None).is_some());
}

#[test]
fn legacy_session_restores_probe_baseline_and_rejects_bad_state() {
    let value = json!({"username":"fixture-us-1","expires_at":3000,"exit_ip":"8.8.8.8","exit_country":"US","last_success":1900,"https_ms":12,"doh_ms":8});
    let session = Session::from_value(&value).unwrap();
    assert_eq!(session.last_checked, 1900);
    assert_eq!(session.failures, 0);
    let reloaded = Session::from_value(&session.to_value()).unwrap();
    assert_eq!(reloaded.username(), session.username());
    assert_eq!(reloaded.exit_ip, session.exit_ip);
    assert!(
        Session::from_value(&json!({"username":"fixture","expires_at":3000,"failures":-1}))
            .is_err()
    );
    assert!(Session::from_value(
        &json!({"username":"fixture","expires_at":3000,"exit_ip":"127.0.0.1","last_success":100})
    )
    .is_err());
}
