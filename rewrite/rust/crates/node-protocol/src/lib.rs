//! Validation of the existing panel-to-node synchronization response.
//!
//! This is a protocol component, not a running node agent. The agent must
//! enforce the monotonic lease deadline independently of network and core I/O.

use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError(&'static str);
impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ProtocolError {}
type Result<T> = std::result::Result<T, ProtocolError>;

fn pattern() -> &'static Regex {
    static REVISION: OnceLock<Regex> = OnceLock::new();
    REVISION.get_or_init(|| Regex::new(r"\A[0-9a-f]{64}\z").expect("static revision pattern"))
}
fn canonical_uuid() -> &'static Regex {
    static UUID: OnceLock<Regex> = OnceLock::new();
    UUID.get_or_init(|| {
        Regex::new(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z")
            .expect("static UUID pattern")
    })
}
fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct User {
    pub id: String,
    pub uuid: String,
    pub expires: i64,
}

#[derive(Clone, PartialEq)]
pub struct Grant {
    pub revision: String,
    pub users: BTreeMap<String, User>,
    issued_at: i64,
    lease_seconds: i64,
}

impl Grant {
    /// Call before and after applying a grant; use the result to set a
    /// monotonic deadline, never a fresh full lease after a slow operation.
    pub fn remaining_at(&self, now: f64) -> Result<f64> {
        if !now.is_finite() {
            return Err(ProtocolError("Invalid clock"));
        }
        let remaining = self.lease_seconds as f64 - (now - self.issued_at as f64).max(0.0);
        if remaining <= 0.0 {
            return Err(ProtocolError("Panel access lease expired"));
        }
        Ok(remaining)
    }
}

pub fn validate_response(response: &Value, pending: &Value, now: f64) -> Result<Grant> {
    if !now.is_finite() {
        return Err(ProtocolError("Invalid clock"));
    }
    let data = response
        .as_object()
        .filter(|v| {
            v.len() == 5
                && ["revision", "users", "lease_seconds", "issued_at", "ack"]
                    .iter()
                    .all(|key| v.contains_key(*key))
        })
        .ok_or(ProtocolError("Invalid panel response"))?;
    let revision = data["revision"]
        .as_str()
        .filter(|v| pattern().is_match(v))
        .ok_or(ProtocolError("Invalid configuration revision"))?;
    let lease_seconds = data["lease_seconds"]
        .as_i64()
        .filter(|v| (10..=60).contains(v))
        .ok_or(ProtocolError("Invalid access lease"))?;
    let issued_at = data["issued_at"]
        .as_i64()
        .filter(|v| (now - *v as f64).abs() <= 30.0)
        .ok_or(ProtocolError(
            "Expired panel response or unsynchronized clock",
        ))?;
    let entries = data["users"]
        .as_array()
        .filter(|v| v.len() <= 500)
        .ok_or(ProtocolError("Invalid user list"))?;
    let mut users = BTreeMap::new();
    for item in entries {
        let item = item
            .as_object()
            .filter(|v| {
                v.len() == 3
                    && ["id", "uuid", "expires"]
                        .iter()
                        .all(|key| v.contains_key(*key))
            })
            .ok_or(ProtocolError("Invalid user"))?;
        let id = item["id"]
            .as_str()
            .filter(|v| valid_id(v) && !users.contains_key(*v))
            .ok_or(ProtocolError("Invalid user"))?;
        let uuid = item["uuid"]
            .as_str()
            .filter(|v| canonical_uuid().is_match(v))
            .ok_or(ProtocolError("Invalid user credential"))?;
        let expires = item["expires"]
            .as_i64()
            .filter(|v| *v >= 0)
            .ok_or(ProtocolError("Invalid user"))?;
        if expires == 0 || expires > now.trunc() as i64 {
            users.insert(
                id.to_owned(),
                User {
                    id: id.to_owned(),
                    uuid: uuid.to_owned(),
                    expires,
                },
            );
        }
    }
    if data["ack"] != *pending {
        return Err(ProtocolError(
            "Panel acknowledgement differs from submitted accounting",
        ));
    }
    let grant = Grant {
        revision: revision.to_owned(),
        users,
        issued_at,
        lease_seconds,
    };
    grant.remaining_at(now)?;
    Ok(grant)
}
