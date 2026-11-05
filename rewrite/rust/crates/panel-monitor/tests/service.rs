use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use xcli_panel_monitor::{
    report::{Dns, Https, Observation, Outcome, Scope},
    service::{RunChecks, Service},
    store::Store,
    Config, Invalid,
};

struct Fake(Arc<AtomicUsize>);
impl RunChecks for Fake {
    fn run(&self, config: &Config, _: &AtomicBool) -> Result<Vec<Observation>, Invalid> {
        let mode = self.0.load(Ordering::Acquire);
        if mode == 2 {
            return Err(Invalid);
        }
        Ok(config
            .kinds()
            .iter()
            .map(|kind| Observation {
                kind: kind.clone(),
                finished_at: None,
                outcome: if mode == 1 && kind == "websocket" {
                    Outcome::ClientUnavailable
                } else {
                    Outcome::Measured {
                        https: Https::Ok(1),
                        dns: Dns::Ok(2),
                    }
                },
            })
            .collect())
    }
}
fn config() -> Config {
    let value = json!({"domain":"panel.example.com","public_ip":"8.8.8.8","reality_sni":"example.com",
        "reality_public":"fixture-public-key","short_id":"0123456789abcdef",
        "uuid":"11111111-2222-3333-4444-555555555555","ws_path":"/connect/fixture"});
    Config::parse(&serde_json::to_vec(&value).unwrap()).unwrap()
}
#[test]
fn cycles_save_status_keep_history_and_leave_report_on_cancel_or_error() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mode = Arc::new(AtomicUsize::new(0));
    let stop = AtomicBool::new(false);
    let mut service = Service::new(
        config(),
        Fake(mode.clone()),
        Store::open(dir.path()).unwrap(),
        Scope::Server,
    )
    .unwrap();
    assert_eq!(
        service.cycle(100, &stop).unwrap().as_value()["status"],
        "healthy"
    );
    let original = fs::read(dir.path().join("report.json")).unwrap();
    mode.store(2, Ordering::Release);
    assert!(service.cycle(105, &stop).is_err());
    assert_eq!(fs::read(dir.path().join("report.json")).unwrap(), original);
    mode.store(1, Ordering::Release);
    stop.store(true, Ordering::Release);
    assert!(service.cycle(106, &stop).is_err());
    assert_eq!(fs::read(dir.path().join("report.json")).unwrap(), original);
    stop.store(false, Ordering::Release);
    drop(service);
    let mut service = Service::new(
        config(),
        Fake(mode),
        Store::open(dir.path()).unwrap(),
        Scope::Server,
    )
    .unwrap();
    let report = service.cycle(110, &stop).unwrap();
    assert_eq!(report.as_value()["status"], "failed");
    assert_eq!(report.as_value()["checks"][1]["last_success"], 100);
}
