use serde_json::{json, Value};
use xcli_node_protocol::validate_response;

const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";
fn response() -> Value {
    json!({"revision":"f".repeat(64), "users":[{"id":ID,"uuid":UUID,"expires":0}],
        "lease_seconds":30, "issued_at":1000, "ack":[]})
}

#[test]
fn accepts_valid_grant_and_rechecks_elapsed_lease() {
    let grant = validate_response(&response(), &json!([]), 1005.0).unwrap();
    assert_eq!(grant.users.len(), 1);
    assert_eq!(grant.remaining_at(1005.0).unwrap(), 25.0);
    assert_eq!(grant.remaining_at(1029.5).unwrap(), 0.5);
    assert!(grant.remaining_at(1030.0).is_err());
}

#[test]
fn rejects_unsafe_or_stale_responses() {
    let mut bad = response();
    bad["issued_at"] = json!(969);
    assert!(validate_response(&bad, &json!([]), 1000.0).is_err());
    let mut bad = response();
    bad["lease_seconds"] = json!(9);
    assert!(validate_response(&bad, &json!([]), 1000.0).is_err());
    let mut bad = response();
    bad["users"][0]["uuid"] = json!(UUID.to_uppercase());
    assert!(validate_response(&bad, &json!([]), 1000.0).is_err());
    let mut bad = response();
    bad["users"][0]["extra"] = json!(true);
    assert!(validate_response(&bad, &json!([]), 1000.0).is_err());
    let mut bad = response();
    bad["users"] = json!([{"id":ID,"uuid":UUID,"expires":0},{"id":ID,"uuid":UUID,"expires":0}]);
    assert!(validate_response(&bad, &json!([]), 1000.0).is_err());
    assert!(validate_response(
        &response(),
        &json!([{"id":ID,"upload":1,"download":0}]),
        1000.0
    )
    .is_err());
    assert!(validate_response(&response(), &json!([]), f64::NAN).is_err());
}

#[test]
fn ignores_expired_users_and_rejects_lease_expired_in_transit() {
    let mut expiring = response();
    expiring["users"][0]["expires"] = json!(1000);
    assert!(validate_response(&expiring, &json!([]), 1000.0)
        .unwrap()
        .users
        .is_empty());
    let mut late = response();
    late["lease_seconds"] = json!(10);
    assert!(validate_response(&late, &json!([]), 1010.0).is_err());
}
