use serde_json::json;
use tempfile::tempdir;
use xcli_node_ledger::Ledger;

const USER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn counter(direction: &str, value: serde_json::Value) -> serde_json::Value {
    json!({"name":format!("user>>>{USER}.01234567@reality>>>traffic>>>{direction}"),"value":value})
}

#[test]
fn sampling_acknowledgement_and_restart_keep_cumulative_totals() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("traffic.sqlite");
    let mut ledger = Ledger::open(&path).unwrap();
    ledger
        .record(
            "first",
            &json!([
                counter("uplink", json!("80")),
                counter("downlink", json!(15))
            ]),
        )
        .unwrap();
    ledger
        .acknowledge(&json!([{"id":USER,"upload":80,"download":10}]))
        .unwrap();
    drop(ledger);
    let mut ledger = Ledger::open(&path).unwrap();
    assert_eq!(ledger.pending(100).unwrap()[0].download, 15);
    ledger
        .record("second", &json!([counter("uplink", json!(7))]))
        .unwrap();
    assert_eq!(ledger.pending(100).unwrap()[0].upload, 87);
    ledger
        .acknowledge(&json!([{"id":USER,"upload":87,"download":15}]))
        .unwrap();
    assert!(ledger.pending(100).unwrap().is_empty());
}

#[test]
fn invalid_batches_are_atomic() {
    let dir = tempdir().unwrap();
    let mut ledger = Ledger::open(&dir.path().join("traffic.sqlite")).unwrap();
    ledger
        .record("gen", &json!([counter("uplink", json!(10))]))
        .unwrap();
    let before = ledger.pending(100).unwrap();
    assert!(ledger
        .record(
            "gen",
            &json!([counter("downlink", json!(99)), counter("uplink", json!(9))])
        )
        .is_err());
    assert_eq!(ledger.pending(100).unwrap(), before);
    assert!(ledger
        .record(
            "gen",
            &json!([counter("uplink", json!(11)), counter("uplink", json!(12))])
        )
        .is_err());
    assert_eq!(ledger.pending(100).unwrap(), before);
    assert!(ledger
        .acknowledge(
            &json!([{"id":USER,"upload":10,"download":0}, {"id":USER,"upload":11,"download":0}])
        )
        .is_err());
    assert_eq!(ledger.pending(100).unwrap(), before);
}

#[test]
fn value_and_acknowledgement_validation() {
    let dir = tempdir().unwrap();
    let mut ledger = Ledger::open(&dir.path().join("traffic.sqlite")).unwrap();
    for bad in [
        json!(-1),
        json!("01"),
        json!(true),
        json!(1.5),
        json!("9223372036854775808"),
    ] {
        assert!(ledger
            .record("gen", &json!([counter("uplink", bad)]))
            .is_err());
    }
    ledger
        .record("gen", &json!([counter("uplink", json!(10))]))
        .unwrap();
    assert!(ledger
        .acknowledge(&json!([{"id":USER,"upload":11,"download":0}]))
        .is_err());
    ledger
        .acknowledge(&json!([{"id":USER,"upload":7,"download":0}]))
        .unwrap();
    assert!(ledger
        .acknowledge(&json!([{"id":USER,"upload":6,"download":0}]))
        .is_err());
    assert!(ledger.pending(0).is_err());
    assert!(ledger.pending(501).is_err());
}

#[cfg(unix)]
#[test]
fn rejects_symbolic_link_database() {
    let dir = tempdir().unwrap();
    let link = dir.path().join("link.sqlite");
    std::os::unix::fs::symlink(dir.path().join("target.sqlite"), &link).unwrap();
    assert!(Ledger::open(&link).is_err());
}
