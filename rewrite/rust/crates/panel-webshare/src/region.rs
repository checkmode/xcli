//! Pure per-region session maintenance. Networking and persistence are owned
//! by the caller; pending results must be committed only to the same epoch.
use crate::probe::{ProbeError, ProbeResult};
use serde_json::{json, Value};
use std::net::IpAddr;
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub enum RegionError {
    InvalidInput,
}
fn optional_i64(value: &Value, key: &str, default: i64) -> Result<i64, RegionError> {
    match value.get(key) {
        None => Ok(default),
        Some(value) => value.as_i64().ok_or(RegionError::InvalidInput),
    }
}
fn optional_u64(value: &Value, key: &str, default: u64) -> Result<u64, RegionError> {
    match value.get(key) {
        None => Ok(default),
        Some(value) => value.as_u64().ok_or(RegionError::InvalidInput),
    }
}
#[derive(Clone)]
pub struct Session {
    username: Zeroizing<String>,
    pub expires_at: i64,
    pub exit_ip: Option<IpAddr>,
    pub exit_country: String,
    pub last_success: i64,
    pub last_checked: i64,
    pub failures: u8,
    pub retry_after: i64,
    pub selected_at: i64,
    pub https_ms: u64,
    pub doh_ms: u64,
}
impl Session {
    pub fn new(username: String, expires_at: i64) -> Result<Self, RegionError> {
        let username = Zeroizing::new(username);
        if username.is_empty()
            || username.len() > 255
            || !username
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
            || expires_at < 0
        {
            return Err(RegionError::InvalidInput);
        }
        Ok(Self {
            username,
            expires_at,
            exit_ip: None,
            exit_country: String::new(),
            last_success: 0,
            last_checked: 0,
            failures: 0,
            retry_after: 0,
            selected_at: 0,
            https_ms: 0,
            doh_ms: 0,
        })
    }
    pub fn username(&self) -> &str {
        &self.username
    }
    /// Input and output contain the provider session identifier and must not
    /// be logged. Missing optional values use the legacy worker's defaults.
    pub fn from_value(value: &Value) -> Result<Self, RegionError> {
        let username = value
            .get("username")
            .and_then(Value::as_str)
            .ok_or(RegionError::InvalidInput)?;
        let expires = value
            .get("expires_at")
            .and_then(Value::as_i64)
            .ok_or(RegionError::InvalidInput)?;
        let mut session = Self::new(username.to_owned(), expires)?;
        session.exit_ip = match value.get("exit_ip") {
            None => None,
            Some(Value::String(ip)) => Some(ip.parse().map_err(|_| RegionError::InvalidInput)?),
            _ => return Err(RegionError::InvalidInput),
        };
        session.exit_country = match value.get("exit_country") {
            None => String::new(),
            Some(Value::String(country)) => country.clone(),
            _ => return Err(RegionError::InvalidInput),
        };
        session.last_success = optional_i64(value, "last_success", 0)?;
        session.last_checked = optional_i64(value, "last_checked", session.last_success)?;
        session.failures = u8::try_from(optional_u64(value, "failures", 0)?)
            .map_err(|_| RegionError::InvalidInput)?;
        session.retry_after = optional_i64(value, "retry_after", 0)?;
        session.selected_at = optional_i64(value, "selected_at", 0)?;
        session.https_ms = optional_u64(value, "https_ms", 0)?;
        session.doh_ms = optional_u64(value, "doh_ms", 0)?;
        if !session.valid() {
            return Err(RegionError::InvalidInput);
        }
        Ok(session)
    }
    pub fn to_value(&self) -> Value {
        let mut value = json!({"username":self.username.as_str(),"expires_at":self.expires_at,"exit_country":self.exit_country,
            "last_success":self.last_success,"last_checked":self.last_checked,"failures":self.failures,"retry_after":self.retry_after,
            "selected_at":self.selected_at,"https_ms":self.https_ms,"doh_ms":self.doh_ms});
        if let Some(ip) = self.exit_ip {
            value["exit_ip"] = json!(ip.to_string());
        }
        value
    }
    pub fn fresh(&self, now: i64) -> bool {
        self.last_success > now.saturating_sub(1200) && self.expires_at > now && self.failures < 3
    }
    pub fn relay_session(&self) -> crate::relay::Session {
        let mut session = crate::relay::Session::new(
            self.username.to_string(),
            self.expires_at,
            self.last_success,
        );
        session.failures = self.failures;
        session.retry_after = self.retry_after;
        session.last_checked = self.last_checked;
        session
    }
    fn valid(&self) -> bool {
        self.expires_at >= 0
            && self.last_success >= 0
            && self.last_checked >= 0
            && self.retry_after >= 0
            && self.selected_at >= 0
            && self.exit_country.len() <= 16
            && self.exit_ip.is_none_or(crate::relay::public_ip)
            && (self.last_success == 0 || self.exit_ip.is_some())
            && self
                .exit_country
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
    }
    fn observed(&mut self, result: ProbeResult, country: &str, now: i64) -> bool {
        if !crate::relay::public_ip(result.exit_ip)
            || result.last_success < 0
            || result.exit_country.len() > 16
            || !result
                .exit_country
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
            || (country != "ZZ" && result.exit_country != country)
        {
            return false;
        }
        self.exit_ip = Some(result.exit_ip);
        self.exit_country = result.exit_country;
        self.last_success = result.last_success;
        self.last_checked = now;
        self.failures = 0;
        self.retry_after = 0;
        self.https_ms = result.https_ms;
        self.doh_ms = result.doh_ms;
        true
    }
}
pub struct Pending {
    epoch: u64,
    now: i64,
    forced: bool,
    previous: Option<Session>,
    sessions: Vec<Session>,
    cooldown: i64,
}
pub struct Outcome {
    pub sessions: Vec<Session>,
    pub cooldown: i64,
    pub reason: Option<&'static str>,
}
pub struct Maintenance<'a> {
    pub epoch: u64,
    pub country: &'a str,
    pub before: &'a [Session],
    pub now: i64,
    pub last_used: i64,
    pub cooldown: i64,
    pub forced: bool,
}
impl Pending {
    /// A stale probe must never overwrite a newer account, pool or shutdown.
    /// `current_primary` is read after probe completion so an in-flight
    /// connection failover is not overwritten by a slow maintenance pass.
    pub fn finish(
        mut self,
        current_epoch: u64,
        enabled: bool,
        current_primary: Option<&str>,
    ) -> Option<Outcome> {
        if self.epoch != current_epoch || !enabled {
            return None;
        }
        let mut previous = self.previous;
        if let (Some(old), Some(current)) = (&previous, current_primary) {
            if current != old.username() {
                if let Some(promoted) = self
                    .sessions
                    .iter()
                    .find(|session| session.username() == current)
                {
                    previous = Some(promoted.clone());
                }
            }
        }
        let preserve = previous.as_ref().filter(|old| {
            !self.forced
                && self
                    .sessions
                    .iter()
                    .any(|item| item.username() == old.username() && item.failures < 3)
        });
        self.sessions.sort_by_key(|session| {
            (
                preserve.is_some_and(|old| session.username() != old.username()),
                session.failures,
                session.https_ms,
            )
        });
        let mut reason = None;
        if let Some(first) = self.sessions.first_mut() {
            if previous
                .as_ref()
                .is_none_or(|old| old.username() != first.username())
            {
                first.selected_at = self.now;
                reason = Some(if self.forced {
                    "手动更换会话"
                } else if previous.is_none() {
                    "首次选定出口"
                } else if previous
                    .as_ref()
                    .is_some_and(|old| old.expires_at <= self.now)
                {
                    "会话到期"
                } else {
                    "出口故障切换"
                });
            } else if previous
                .as_ref()
                .is_some_and(|old| old.exit_ip != first.exit_ip)
            {
                reason = Some("供应商调整了当前会话的出口 IP");
            }
        }
        Some(Outcome {
            sessions: self.sessions,
            cooldown: self.cooldown,
            reason,
        })
    }
}

/// Run a single region's maintenance off the async reactor. `probe` and `make`
/// are bounded by the caller; at most two new candidates are requested. This
/// stage never mutates the live pool and cannot itself switch a connection.
pub fn maintain<F, G>(
    input: Maintenance<'_>,
    mut probe: F,
    mut make: G,
) -> Result<Pending, RegionError>
where
    F: FnMut(&str) -> Result<ProbeResult, ProbeError>,
    G: FnMut() -> Result<Session, RegionError>,
{
    let Maintenance {
        epoch,
        country,
        before,
        now,
        last_used,
        mut cooldown,
        forced,
    } = input;
    if !crate::REGIONS
        .iter()
        .any(|region| region.country == country)
        || now < 0
        || last_used < 0
        || cooldown < 0
        || before.len() > 4
        || before.iter().any(|session| !session.valid())
    {
        return Err(RegionError::InvalidInput);
    }
    let previous = before.first().cloned();
    let mut sessions: Vec<_> = before
        .iter()
        .filter(|session| {
            session.expires_at > now
                && !(forced
                    && previous
                        .as_ref()
                        .is_some_and(|old| old.username() == session.username()))
        })
        .cloned()
        .collect();
    let active_interval = if last_used > now.saturating_sub(300) {
        120
    } else {
        900
    };
    sessions = sessions
        .into_iter()
        .enumerate()
        .filter_map(|(index, mut session)| {
            let interval = if session.failures > 0 {
                30
            } else if index == 0 {
                active_interval
            } else {
                900
            };
            if session.last_checked <= now.saturating_sub(interval) {
                let result = probe(session.username());
                if !result.is_ok_and(|value| session.observed(value, country, now)) {
                    session.failures = session.failures.saturating_add(1);
                    session.last_checked = now;
                    if session.failures >= 3 {
                        return None;
                    }
                }
            }
            Some(session)
        })
        .collect();
    if sessions.len() >= 4 {
        if let Some(index) = sessions
            .iter()
            .enumerate()
            .skip(1)
            .find_map(|(index, session)| {
                (session.expires_at <= now.saturating_add(180)).then_some(index)
            })
        {
            sessions.remove(index);
        }
    }
    if sessions.len() < 4 && now >= cooldown {
        for _ in 0..(4 - sessions.len()).min(2) {
            let candidate = make();
            let Ok(mut candidate) = candidate else {
                cooldown = now.saturating_add(60);
                continue;
            };
            if !candidate.valid()
                || candidate.expires_at <= now
                || sessions
                    .iter()
                    .any(|item| item.username() == candidate.username())
            {
                cooldown = now.saturating_add(60);
                continue;
            }
            let result = probe(candidate.username());
            if !result.is_ok_and(|value| candidate.observed(value, country, now)) {
                cooldown = now.saturating_add(60);
                continue;
            }
            if sessions
                .iter()
                .any(|item| item.exit_ip == candidate.exit_ip)
            {
                cooldown = now.saturating_add(60);
                continue;
            }
            sessions.push(candidate);
        }
    }
    Ok(Pending {
        epoch,
        now,
        forced,
        previous,
        sessions,
        cooldown,
    })
}
