//! Experimental, credential-free aggregation for monitor observations.
use crate::{Config, Invalid};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy)]
pub enum Scope {
    Server,
    External,
}
pub enum Https {
    Ok(u64),
    ConnectionFailed,
    UnexpectedEgress,
    Unavailable,
}
pub enum Dns {
    Ok(u64),
    Failed,
}
pub enum Outcome {
    ClientUnavailable,
    Measured { https: Https, dns: Dns },
}
pub struct Observation {
    pub kind: String,
    pub outcome: Outcome,
    pub finished_at: Option<i64>,
}
pub struct Report(Value);
impl Report {
    pub fn as_value(&self) -> &Value {
        &self.0
    }
}

/// Preserve only prior success timestamps for known transports. All output
/// strings are fixed by this module, never taken from proxy credentials.
pub fn aggregate(
    config: &Config,
    scope: Scope,
    now: i64,
    observations: Vec<Observation>,
    previous: Option<&Value>,
) -> Result<Report, Invalid> {
    if now < 0 || observations.len() != config.kinds().len() {
        return Err(Invalid);
    }
    let expected: BTreeSet<_> = config.kinds().iter().map(String::as_str).collect();
    let mut old = BTreeMap::new();
    if let Some(rows) = previous
        .and_then(|value| value.get("checks"))
        .and_then(Value::as_array)
    {
        if rows.len() > 44 {
            return Err(Invalid);
        }
        for row in rows {
            if let (Some(kind), Some(timestamp)) = (
                row.get("transport").and_then(Value::as_str),
                row.get("last_success").and_then(Value::as_i64),
            ) {
                if expected.contains(kind) && (0..=now).contains(&timestamp) {
                    old.insert(kind.to_owned(), timestamp);
                }
            }
        }
    }
    let mut values = BTreeMap::new();
    for observation in observations {
        if !expected.contains(observation.kind.as_str())
            || values
                .insert(
                    observation.kind.clone(),
                    (observation.outcome, observation.finished_at),
                )
                .is_some()
        {
            return Err(Invalid);
        }
    }
    let mut checks = Vec::new();
    for kind in config.kinds() {
        let residential = config.residential(kind);
        let (outcome, finished_at) = values.remove(kind).ok_or(Invalid)?;
        let finished_at = finished_at.unwrap_or(now);
        if !(0..=now).contains(&finished_at) {
            return Err(Invalid);
        }
        let (https_ms, dns_ms, error) = match outcome {
            Outcome::ClientUnavailable => (None, None, "Probe client unavailable".to_owned()),
            Outcome::Measured { https, dns } => {
                let mut errors = Vec::new();
                let https_ms = match https {
                    Https::Ok(ms) if ms <= 120_000 => Some(ms),
                    Https::Ok(_) => return Err(Invalid),
                    Https::ConnectionFailed => {
                        errors.push("HTTPS connection failed");
                        None
                    }
                    Https::UnexpectedEgress => {
                        errors.push("Unexpected egress IP");
                        None
                    }
                    Https::Unavailable => {
                        errors.push("HTTPS probe unavailable");
                        None
                    }
                };
                let dns_ms = match dns {
                    Dns::Ok(ms) if ms <= 120_000 => Some(ms),
                    Dns::Ok(_) => return Err(Invalid),
                    Dns::Failed => {
                        errors.push(if residential {
                            "DoH probe failed"
                        } else {
                            "UDP DNS probe failed"
                        });
                        None
                    }
                };
                (https_ms, dns_ms, errors.join("; "))
            }
        };
        let healthy = error.is_empty();
        checks.push(json!({"transport":kind,"status":if healthy {"healthy"} else {"failed"},"https_ms":https_ms,
            "udp_ms":if residential {None} else {dns_ms},"doh_ms":if residential {dns_ms} else {None},
            "error":error,"last_success":if healthy {finished_at} else {*old.get(kind).unwrap_or(&0)},"udp_supported":!residential}));
    }
    let healthy = checks.iter().all(|check| check["status"] == "healthy");
    Ok(Report(
        json!({"schema":1,"scope":match scope {Scope::Server=>"server",Scope::External=>"external"},
        "updated":now,"status":if healthy {"healthy"} else {"failed"},"checks":checks}),
    ))
}
