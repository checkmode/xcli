//! Experimental coordination of desired configuration, provider sync and
//! region pools. Networking runs outside this state machine. It is not wired
//! to a production process or a panel API yet.
use crate::provider::{session_username, Provider};
use crate::region::{maintain, Maintenance, Pending, RegionError, Session};
use crate::relay::{InvalidPool, Pool};
use crate::sync::{cached_rotation, synchronize, Active, Decision, Desired, SyncError};
use crate::{ActiveSnapshot, Control, Secret, REGIONS};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub enum CoreError {
    InvalidState,
    Storage,
    Pool,
    Entropy,
}
#[derive(Debug, PartialEq, Eq)]
pub enum SyncEffect {
    Applied,
    Stale,
    InvalidPlan,
}
struct RegionState {
    sessions: Vec<Session>,
    pool: Pool,
    online: bool,
    cooldown: i64,
    forced: bool,
    rotation_serial: u64,
    reported_failovers: u64,
}
#[derive(Clone, Default)]
pub struct ReportInfo {
    pub last_sync: i64,
    pub last_attempt: i64,
    pub next_sync: i64,
    pub sync_error: &'static str,
    pub usage_error: &'static str,
    pub usage: Value,
}
pub struct Coordinator {
    control: Arc<Control>,
    regions: BTreeMap<String, RegionState>,
    active: Active,
    desired: Option<Desired>,
    plans: Vec<Value>,
    processed_revision: String,
    epoch: u64,
    sync_serial: u64,
    events: VecDeque<Value>,
}
#[derive(Clone)]
pub struct SyncJob {
    desired: Desired,
    current: Active,
    control: Arc<Control>,
    serial: u64,
}
impl SyncJob {
    pub fn run<P: Provider + ?Sized>(&self, provider: &P) -> Result<Decision, SyncError> {
        synchronize(provider, &self.desired, &self.current, || {
            let value = self.control.config().map_err(|_| SyncError::InvalidState)?;
            value
                .0
                .get("revision")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(SyncError::InvalidState)
        })
    }
    pub fn wants_usage(&self) -> bool {
        self.desired.wants_usage()
    }
    pub fn run_usage<P: Provider + ?Sized>(
        &self,
        provider: &P,
        now: i64,
    ) -> Result<Value, crate::provider::ProviderError> {
        self.desired.usage(provider, now)
    }
}
pub struct RegionJob {
    epoch: u64,
    pool_generation: u64,
    rotation_serial: u64,
    country: String,
    sessions: Vec<Session>,
    last_used: i64,
    cooldown: i64,
    forced: bool,
    base: Zeroizing<String>,
    password: Zeroizing<String>,
}
pub struct RegionCompletion {
    epoch: u64,
    pool_generation: u64,
    rotation_serial: u64,
    country: String,
    pending: Pending,
}
impl RegionJob {
    pub fn run<F>(self, now: i64, mut probe: F) -> Result<RegionCompletion, CoreError>
    where
        F: FnMut(&str, &str, &str) -> Result<crate::probe::ProbeResult, crate::probe::ProbeError>,
    {
        let country = self.country.clone();
        let base = self.base.clone();
        let password = self.password.clone();
        let mut entropy_failed = false;
        let input = Maintenance {
            epoch: self.epoch,
            country: &country,
            before: &self.sessions,
            now,
            last_used: self.last_used,
            cooldown: self.cooldown,
            forced: self.forced,
        };
        let pending = maintain(
            input,
            |username| probe(username, &password, &country),
            || {
                let mut bytes = [0u8; 8];
                getrandom::fill(&mut bytes).map_err(|_| {
                    entropy_failed = true;
                    RegionError::InvalidInput
                })?;
                let identifier = u64::from_be_bytes(bytes) & ((1u64 << 48) - 1);
                let username = session_username(&base, &country, &identifier.to_string())
                    .map_err(|_| RegionError::InvalidInput)?;
                getrandom::fill(&mut bytes).map_err(|_| {
                    entropy_failed = true;
                    RegionError::InvalidInput
                })?;
                let jitter = (u64::from_be_bytes(bytes) % 600) as i64;
                Session::new(
                    username.to_string(),
                    now.saturating_add(1800).saturating_sub(jitter),
                )
            },
        )
        .map_err(|_| CoreError::InvalidState)?;
        if entropy_failed {
            return Err(CoreError::Entropy);
        }
        Ok(RegionCompletion {
            epoch: self.epoch,
            pool_generation: self.pool_generation,
            rotation_serial: self.rotation_serial,
            country,
            pending,
        })
    }
}
impl Coordinator {
    pub fn open(control: Arc<Control>, countries: &[&str], now: i64) -> Result<Self, CoreError> {
        let unique: BTreeSet<_> = countries.iter().copied().collect();
        if now < 0
            || countries.is_empty()
            || unique.len() != countries.len()
            || unique.len() > REGIONS.len()
            || unique
                .iter()
                .any(|country| !REGIONS.iter().any(|region| region.country == *country))
        {
            return Err(CoreError::InvalidState);
        }
        let snapshot = control
            .load_active(countries, now)
            .map_err(|_| CoreError::Storage)?;
        let active = match &snapshot {
            Some(value) => Active::from_snapshot(value).map_err(|_| CoreError::InvalidState)?,
            None => Active::empty(),
        };
        let plans = snapshot
            .as_ref()
            .and_then(|value| value.as_value().get("plans"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let processed_revision = snapshot
            .as_ref()
            .and_then(|value| value.as_value().get("processed_revision"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let limit = Arc::new(Semaphore::new(128));
        let mut regions = BTreeMap::new();
        for country in countries {
            let sessions = match snapshot
                .as_ref()
                .and_then(|value| value.as_value()["pools"].get(*country))
                .and_then(Value::as_array)
            {
                Some(values) => values
                    .iter()
                    .map(Session::from_value)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| CoreError::InvalidState)?,
                None => Vec::new(),
            };
            let forced = snapshot
                .as_ref()
                .and_then(|value| value.as_value().get("pending_rotations"))
                .and_then(Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(*country)));
            regions.insert(
                (*country).to_owned(),
                RegionState {
                    sessions,
                    pool: Pool::new(limit.clone()),
                    online: false,
                    cooldown: 0,
                    forced,
                    rotation_serial: u64::from(forced),
                    reported_failovers: 0,
                },
            );
        }
        Ok(Self {
            control,
            regions,
            active,
            desired: None,
            plans,
            processed_revision,
            epoch: 1,
            sync_serial: 0,
            events: VecDeque::new(),
        })
    }
    fn snapshot(
        &self,
        active: &Active,
        plans: &[Value],
        revision: &str,
        clear: bool,
        extra_rotation: Option<&str>,
        now: i64,
    ) -> Result<ActiveSnapshot, CoreError> {
        let mut bundle = Secret(
            json!({"active":{},"plans":plans,"processed_revision":revision,"pools":{},"pending_rotations":[]}),
        );
        let mut active = active.record();
        bundle.0["active"] = std::mem::take(&mut active.0);
        let mut pending = Vec::new();
        for (country, region) in &self.regions {
            let mut sessions = Secret(json!([]));
            if !clear {
                for session in &region.sessions {
                    sessions
                        .0
                        .as_array_mut()
                        .ok_or(CoreError::InvalidState)?
                        .push(session.to_value());
                }
            }
            bundle.0["pools"][country] = std::mem::take(&mut sessions.0);
            if (!clear && region.forced) || extra_rotation == Some(country.as_str()) {
                pending.push(country.clone());
            }
        }
        bundle.0["pending_rotations"] = json!(pending);
        let countries: Vec<&str> = self.regions.keys().map(String::as_str).collect();
        ActiveSnapshot::from_value(std::mem::take(&mut bundle.0), &countries, now)
            .map_err(|_| CoreError::InvalidState)
    }
    fn persist(&self, now: i64) -> Result<(), CoreError> {
        let snapshot = self.snapshot(
            &self.active,
            &self.plans,
            &self.processed_revision,
            false,
            None,
            now,
        )?;
        self.control
            .save_active(&snapshot)
            .map_err(|_| CoreError::Storage)
    }
    fn set_online(&mut self, online: bool, replace: bool) -> Result<(), CoreError> {
        let available = online && self.active.enabled && self.active.credentials.is_some();
        if !replace
            && self
                .regions
                .values()
                .all(|region| region.online == available)
        {
            return Ok(());
        }
        self.epoch = self.epoch.checked_add(1).ok_or(CoreError::InvalidState)?;
        let password = self
            .active
            .credentials
            .as_ref()
            .map(|value| value.password.as_str())
            .unwrap_or("");
        for region in self.regions.values_mut() {
            let sessions = region.sessions.iter().map(Session::relay_session).collect();
            region
                .pool
                .replace(available, password.to_owned(), sessions)
                .map_err(|_| CoreError::Pool)?;
            region.online = available;
        }
        Ok(())
    }
    /// Re-read the atomic desired file. A missing key or corrupt configuration
    /// disables every relay before any other operation can proceed.
    pub fn refresh(&mut self, now: i64) -> Result<(), CoreError> {
        let control = self.control.clone();
        let _guard = match control.lock() {
            Ok(guard) => guard,
            Err(_) => {
                self.desired = None;
                self.set_online(false, false)?;
                return Err(CoreError::Storage);
            }
        };
        let config = match self.control.config() {
            Ok(value) => value,
            Err(_) => {
                self.desired = None;
                self.sync_serial = self
                    .sync_serial
                    .checked_add(1)
                    .ok_or(CoreError::InvalidState)?;
                self.set_online(false, false)?;
                return Err(CoreError::Storage);
            }
        };
        let desired = match Desired::from_value(&config.0) {
            Ok(value) => value,
            Err(_) => {
                self.desired = None;
                self.sync_serial = self
                    .sync_serial
                    .checked_add(1)
                    .ok_or(CoreError::InvalidState)?;
                self.set_online(false, false)?;
                return Err(CoreError::InvalidState);
            }
        };
        if self
            .desired
            .as_ref()
            .is_none_or(|previous| !previous.equivalent(&desired))
        {
            self.sync_serial = self
                .sync_serial
                .checked_add(1)
                .ok_or(CoreError::InvalidState)?;
        }
        if desired.key_is_empty() {
            self.set_online(false, false)?;
            let changed = !self.active.key_is_empty()
                || !self.plans.is_empty()
                || self.processed_revision != desired.revision
                || self
                    .regions
                    .values()
                    .any(|region| !region.sessions.is_empty() || region.forced);
            if !changed {
                self.desired = Some(desired);
                return Ok(());
            }
            self.active = Active::empty();
            self.plans.clear();
            self.processed_revision = desired.revision.clone();
            for region in self.regions.values_mut() {
                region.sessions.clear();
                region.forced = false;
            }
            self.set_online(false, true)?;
            self.desired = Some(desired);
            return self.persist(now);
        }
        self.set_online(desired.enabled, false)?;
        if let Some(country) = cached_rotation(&desired, &self.active, &self.processed_revision) {
            if !self.regions.contains_key(&country) {
                return Err(CoreError::InvalidState);
            }
            let previous = self.processed_revision.clone();
            let was_forced = self.regions[&country].forced;
            let old_serial = self.regions[&country].rotation_serial;
            self.processed_revision = desired.revision.clone();
            let region = self
                .regions
                .get_mut(&country)
                .ok_or(CoreError::InvalidState)?;
            region.forced = true;
            region.rotation_serial = region
                .rotation_serial
                .checked_add(1)
                .ok_or(CoreError::InvalidState)?;
            if let Err(error) = self.persist(now) {
                self.processed_revision = previous;
                let region = self
                    .regions
                    .get_mut(&country)
                    .ok_or(CoreError::InvalidState)?;
                region.forced = was_forced;
                region.rotation_serial = old_serial;
                return Err(error);
            }
        }
        self.desired = Some(desired);
        Ok(())
    }
    pub fn sync_job(&self) -> Option<SyncJob> {
        let desired = self
            .desired
            .as_ref()
            .filter(|value| !value.key_is_empty())?
            .clone();
        Some(SyncJob {
            desired,
            current: self.active.clone(),
            control: self.control.clone(),
            serial: self.sync_serial,
        })
    }
    /// Re-check the on-disk revision immediately before saving any result.
    pub fn commit_sync(
        &mut self,
        job: &SyncJob,
        decision: Decision,
        now: i64,
    ) -> Result<SyncEffect, CoreError> {
        let control = self.control.clone();
        let _guard = control.lock().map_err(|_| CoreError::Storage)?;
        let current = self.control.config().map_err(|_| CoreError::Storage)?;
        let latest = Desired::from_value(&current.0).map_err(|_| CoreError::InvalidState)?;
        if self.sync_serial != job.serial
            || self
                .desired
                .as_ref()
                .is_none_or(|desired| !desired.equivalent(&job.desired))
            || !latest.equivalent(&job.desired)
        {
            return Ok(SyncEffect::Stale);
        }
        match decision {
            Decision::Stale => Ok(SyncEffect::Stale),
            Decision::InvalidPlan { disable_current } => {
                self.sync_serial = self
                    .sync_serial
                    .checked_add(1)
                    .ok_or(CoreError::InvalidState)?;
                self.processed_revision = job.desired.revision.clone();
                if disable_current {
                    self.active.enabled = false;
                    self.set_online(false, false)?;
                    self.persist(now)?;
                }
                Ok(SyncEffect::InvalidPlan)
            }
            Decision::Applied {
                active,
                plans,
                revision,
                changed,
                rotate,
            } => {
                if revision != job.desired.revision {
                    return Err(CoreError::InvalidState);
                }
                if rotate
                    .as_ref()
                    .is_some_and(|country| !self.regions.contains_key(country))
                {
                    return Err(CoreError::InvalidState);
                }
                let snapshot =
                    self.snapshot(&active, &plans, &revision, changed, rotate.as_deref(), now)?;
                self.control
                    .save_active(&snapshot)
                    .map_err(|_| CoreError::Storage)?;
                self.active = *active;
                self.plans = plans;
                self.processed_revision = revision;
                if changed {
                    for region in self.regions.values_mut() {
                        region.sessions.clear();
                        region.forced = false;
                    }
                }
                if let Some(country) = rotate {
                    let region = self
                        .regions
                        .get_mut(&country)
                        .ok_or(CoreError::InvalidState)?;
                    region.forced = true;
                    region.rotation_serial = region
                        .rotation_serial
                        .checked_add(1)
                        .ok_or(CoreError::InvalidState)?;
                }
                self.set_online(latest.enabled, changed)?;
                self.sync_serial = self
                    .sync_serial
                    .checked_add(1)
                    .ok_or(CoreError::InvalidState)?;
                Ok(SyncEffect::Applied)
            }
        }
    }
    pub fn pool(&self, country: &str) -> Option<Pool> {
        self.regions.get(country).map(|region| region.pool.clone())
    }
    /// Records a failed attempt without replacing a working account. The
    /// scheduler uses this revision together with its retry deadline.
    pub fn failed_sync(&mut self, job: &SyncJob) -> Result<bool, CoreError> {
        let control = self.control.clone();
        let _guard = control.lock().map_err(|_| CoreError::Storage)?;
        let current = self.control.config().map_err(|_| CoreError::Storage)?;
        let latest = Desired::from_value(&current.0).map_err(|_| CoreError::InvalidState)?;
        if self.sync_serial != job.serial
            || self
                .desired
                .as_ref()
                .is_none_or(|value| !value.equivalent(&job.desired))
            || !latest.equivalent(&job.desired)
        {
            return Ok(false);
        }
        self.processed_revision = job.desired.revision.clone();
        self.sync_serial = self
            .sync_serial
            .checked_add(1)
            .ok_or(CoreError::InvalidState)?;
        Ok(true)
    }
    pub fn current_job(&self, job: &SyncJob) -> Result<bool, CoreError> {
        let _guard = self.control.lock().map_err(|_| CoreError::Storage)?;
        let latest = self.control.config().map_err(|_| CoreError::Storage)?;
        let latest = Desired::from_value(&latest.0).map_err(|_| CoreError::InvalidState)?;
        Ok(self.sync_serial == job.serial
            && self
                .desired
                .as_ref()
                .is_some_and(|value| value.equivalent(&job.desired))
            && latest.equivalent(&job.desired))
    }
    pub fn begin_region(&self, country: &str) -> Option<RegionJob> {
        let region = self.regions.get(country)?;
        if !region.online {
            return None;
        }
        let credentials = self.active.credentials.as_ref()?;
        Some(RegionJob {
            epoch: self.epoch,
            pool_generation: region.pool.generation().ok()?,
            rotation_serial: region.rotation_serial,
            country: country.to_owned(),
            sessions: region.sessions.clone(),
            last_used: region.pool.last_used(),
            cooldown: region.cooldown,
            forced: region.forced,
            base: credentials.base.clone(),
            password: credentials.password.clone(),
        })
    }
    pub fn commit_region(
        &mut self,
        completion: RegionCompletion,
        now: i64,
    ) -> Result<Option<&'static str>, CoreError> {
        if completion.epoch != self.epoch {
            return Ok(None);
        }
        let control = self.control.clone();
        let _guard = control.lock().map_err(|_| CoreError::Storage)?;
        let current = control.config().map_err(|_| CoreError::Storage)?;
        let latest = Desired::from_value(&current.0).map_err(|_| CoreError::InvalidState)?;
        if self
            .desired
            .as_ref()
            .is_none_or(|desired| !desired.equivalent(&latest))
        {
            return Ok(None);
        }
        let region = self
            .regions
            .get_mut(&completion.country)
            .ok_or(CoreError::InvalidState)?;
        if !region.online {
            return Ok(None);
        }
        if region.pool.generation().map_err(|_| CoreError::Pool)? != completion.pool_generation {
            return Ok(None);
        }
        let result = region
            .pool
            .commit_sessions(completion.pool_generation, |primary| {
                let outcome = completion
                    .pending
                    .finish(completion.epoch, true, primary)
                    .ok_or(InvalidPool)?;
                let sessions = outcome
                    .sessions
                    .iter()
                    .map(Session::relay_session)
                    .collect();
                Ok((sessions, outcome))
            });
        let outcome = match result {
            Ok(value) => value,
            Err(_)
                if region
                    .pool
                    .generation()
                    .is_ok_and(|value| value != completion.pool_generation) =>
            {
                return Ok(None)
            }
            Err(_) => return Err(CoreError::Pool),
        };
        region.sessions = outcome.sessions;
        region.cooldown = outcome.cooldown;
        let was_forced = region.forced;
        if region.rotation_serial == completion.rotation_serial {
            region.forced = false;
        }
        if let Err(error) = self.persist(now) {
            self.regions
                .get_mut(&completion.country)
                .ok_or(CoreError::InvalidState)?
                .forced = was_forced;
            return Err(error);
        }
        if let Some(reason) = outcome.reason {
            self.events
                .push_front(json!({"country":completion.country,"ts":now,"reason":reason}));
            self.events.truncate(20);
        }
        Ok(outcome.reason)
    }
    pub fn report(&mut self, now: i64, info: &ReportInfo) -> Result<(), CoreError> {
        if now < 0 {
            return Err(CoreError::InvalidState);
        }
        let enabled = self.regions.values().any(|region| region.online);
        let mut pools = Vec::new();
        let mut events = Vec::new();
        let mut healthy = 0usize;
        for (country, region) in &mut self.regions {
            let Some(metadata) = REGIONS.iter().find(|value| value.country == country) else {
                return Err(CoreError::InvalidState);
            };
            let name = region.pool.primary_name();
            let current = name
                .as_ref()
                .and_then(|name| {
                    region
                        .sessions
                        .iter()
                        .find(|item| item.username() == name.as_str())
                })
                .or_else(|| region.sessions.first());
            let live = current.is_some_and(|item| item.fresh(now));
            let status = if !enabled {
                "disabled"
            } else if live {
                healthy += 1;
                "healthy"
            } else {
                "unavailable"
            };
            let ready = region
                .sessions
                .iter()
                .filter(|item| {
                    current.is_none_or(|first| first.username() != item.username())
                        && item.fresh(now)
                        && item.retry_after <= now
                })
                .count();
            let interval = if region.pool.last_used() > now.saturating_sub(300) {
                120
            } else {
                900
            };
            let failures = current.map_or(3, |item| u64::from(item.failures));
            let failovers = region.pool.failovers();
            if failovers > region.reported_failovers {
                events.push(
                    json!({"country":country,"ts":now,"reason":"连接失败，已切换同国家备用出口"}),
                );
                region.reported_failovers = failovers;
            }
            let mut pool = json!({"country":country,"label":format!("动态住宅 · {}",metadata.label),"status":status,
                "standby":region.sessions.len().saturating_sub(1),"ready_standby":ready,"probe_interval":interval,
                "failovers":failovers,"failures":failures,"error":if live {""} else {"等待可用会话"}});
            if let Some(session) = current {
                if let Some(ip) = session.exit_ip {
                    pool["exit_ip"] = json!(ip.to_string());
                }
                pool["exit_country"] = json!(session.exit_country);
                pool["https_ms"] = json!(session.https_ms);
                pool["doh_ms"] = json!(session.doh_ms);
                pool["last_success"] = json!(session.last_success);
                pool["selected_at"] = json!(session.selected_at);
                pool["expires_at"] = json!(session.expires_at);
            }
            pools.push(pool);
        }
        for event in events {
            self.events.push_front(event);
        }
        self.events.truncate(20);
        let total = self.regions.len();
        let status = if enabled && healthy == total {
            "healthy"
        } else if enabled {
            "degraded"
        } else if self.active.key_is_empty() {
            "unconfigured"
        } else {
            "disabled"
        };
        let message = if enabled {
            format!("{healthy}/{total} 个国家/地区入口可用")
        } else {
            "选择套餐并启用动态住宅池".into()
        };
        let mut plans = Vec::new();
        for plan in self
            .plans
            .iter()
            .filter(|value| value.get("id").is_some_and(crate::integer))
            .take(100)
        {
            let mut item = json!({"id":plan["id"]});
            crate::copy_strings(
                plan,
                &mut item,
                &["label", "status", "pool_filter", "proxy_subtype"],
                100,
            );
            if let Some(value) = plan
                .get("bandwidth_limit")
                .filter(|value| value.is_number())
            {
                item["bandwidth_limit"] = value.clone();
            }
            if let Some(value) = plan.get("eligible").and_then(Value::as_bool) {
                item["eligible"] = json!(value);
            }
            plans.push(item);
        }
        let mut report = json!({"updated":now,"status":status,"message":message,"enabled":enabled,"active_plan_id":self.active.plan_id,
            "revision":self.processed_revision,"last_sync":info.last_sync,"last_attempt":info.last_attempt,"next_sync":info.next_sync,
            "sync_error":info.sync_error,"usage_error":info.usage_error,"plans":plans,"pools":pools,"events":self.events});
        for key in [
            "bandwidth_total",
            "requests_total",
            "requests_successful",
            "requests_failed",
            "usage_updated",
        ] {
            if let Some(value) = info.usage.get(key).filter(|value| crate::integer(value)) {
                report[key] = value.clone();
            }
        }
        self.active.redact(&mut report);
        if let Some(desired) = &self.desired {
            desired.redact(&mut report);
        }
        for region in self.regions.values() {
            for session in &region.sessions {
                crate::redact(&mut report, session.username());
            }
        }
        self.control
            .write_report(&report)
            .map_err(|_| CoreError::Storage)
    }
    pub fn shutdown(&mut self) -> Result<(), CoreError> {
        self.desired = None;
        self.set_online(false, false)
    }
    pub fn needs_sync(&self, now: i64, next_sync: i64) -> bool {
        self.desired.as_ref().is_some_and(|desired| {
            !desired.key_is_empty()
                && (desired.revision != self.processed_revision || now >= next_sync)
        })
    }
    pub fn desired_revision(&self) -> Option<&str> {
        self.desired
            .as_ref()
            .map(|desired| desired.revision.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::{ProbeError, ProbeResult};
    use crate::provider::{Endpoint, ProviderError, ProviderResponse};
    use std::os::unix::fs::PermissionsExt;

    struct Fake {
        password: &'static str,
        fail: bool,
    }
    impl Provider for Fake {
        fn fetch(
            &self,
            _key: &str,
            endpoint: Endpoint,
            _parameters: &[(&str, &str)],
        ) -> Result<ProviderResponse, ProviderError> {
            if self.fail {
                return Err(ProviderError::Unauthorized);
            }
            Ok(match endpoint {
                Endpoint::Plans => ProviderResponse::fixture(
                    json!({"results":[{"id":17,"status":"active","pool_filter":"residential"}],"next":null}),
                ),
                Endpoint::Proxies => ProviderResponse::fixture(
                    json!({"results":[{"username":"fixture-123","password":self.password}]}),
                ),
                _ => return Err(ProviderError::InvalidRequest),
            })
        }
    }
    fn setup(root: &std::path::Path, now: i64) -> Arc<Control> {
        let control = Arc::new(Control::open(root, json!({}), [7; 32]).unwrap());
        control
            .configure(&json!({"api_key":"synthetic-api-key-for-test"}), now)
            .unwrap();
        std::fs::write(
            root.join("webshare/report.json"),
            serde_json::to_vec(&json!({"updated":now,"plans":[{"id":17,"eligible":true}]}))
                .unwrap(),
        )
        .unwrap();
        control
            .configure(&json!({"plan_id":17,"enabled":true}), now)
            .unwrap();
        let snapshot=ActiveSnapshot::from_value(json!({"active":{"api_key":"synthetic-api-key-for-test","enabled":true,"plan_id":17,
            "credentials":{"base":"fixture","password":"synthetic-password"}},"processed_revision":"old","plans":[],
            "pools":{"US":[{"username":"fixture-us-1","expires_at":now+1800,"exit_ip":"8.8.8.1","exit_country":"US","last_success":now}],"JP":[]}}),&["US","JP"],now).unwrap();
        control.save_active(&snapshot).unwrap();
        control
    }
    #[test]
    fn sync_preserves_live_pool_on_failure_and_rejects_stale_or_duplicate_results() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let control = setup(dir.path(), now);
        let mut core = Coordinator::open(control.clone(), &["US", "JP"], now).unwrap();
        core.refresh(now).unwrap();
        assert!(core.begin_region("US").is_some());
        let failed = core.sync_job().unwrap();
        assert!(matches!(
            failed.run(&Fake {
                password: "synthetic-password",
                fail: true
            }),
            Err(SyncError::Provider(ProviderError::Unauthorized))
        ));
        assert_eq!(core.begin_region("US").unwrap().sessions.len(), 1);
        assert!(core.failed_sync(&failed).unwrap());
        assert!(!core.needs_sync(now, now + 300));
        assert!(core.needs_sync(now + 300, now + 300));
        let first = core.sync_job().unwrap();
        let duplicate = core.sync_job().unwrap();
        let a = first
            .run(&Fake {
                password: "synthetic-password",
                fail: false,
            })
            .unwrap();
        let b = duplicate
            .run(&Fake {
                password: "synthetic-password",
                fail: false,
            })
            .unwrap();
        assert_eq!(
            core.commit_sync(&first, a, now).unwrap(),
            SyncEffect::Applied
        );
        assert_eq!(
            core.commit_sync(&duplicate, b, now).unwrap(),
            SyncEffect::Stale
        );
        let old = core.sync_job().unwrap();
        let result = old
            .run(&Fake {
                password: "synthetic-password",
                fail: false,
            })
            .unwrap();
        control
            .configure(&json!({"enabled":false}), now + 1)
            .unwrap();
        core.refresh(now + 1).unwrap();
        assert!(core.begin_region("US").is_none());
        assert_eq!(
            core.commit_sync(&old, result, now + 1).unwrap(),
            SyncEffect::Stale
        );
    }
    #[test]
    fn stale_probe_does_not_commit_before_the_new_configuration_is_refreshed() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let control = setup(dir.path(), now);
        let mut core = Coordinator::open(control.clone(), &["US", "JP"], now).unwrap();
        core.refresh(now).unwrap();
        let usage_job = core.sync_job().unwrap();
        assert!(core.current_job(&usage_job).unwrap());
        let job = core.begin_region("US").unwrap();
        let completion = job
            .run(now, |_, _, _| Err(ProbeError::Unavailable))
            .unwrap();
        control
            .configure(&json!({"enabled":false}), now + 1)
            .unwrap();
        assert!(!core.current_job(&usage_job).unwrap());
        assert_eq!(core.commit_region(completion, now + 1).unwrap(), None);
        core.refresh(now + 1).unwrap();
        assert!(core.begin_region("US").is_none());
        let saved = control
            .load_active(&["US", "JP"], now + 1)
            .unwrap()
            .unwrap();
        assert_eq!(
            saved.as_value()["pools"]["US"][0]["username"],
            "fixture-us-1"
        );
    }
    #[test]
    fn independent_controls_serialize_configuration_updates() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let control = setup(dir.path(), now);
        let other = Arc::new(Control::open(dir.path(), json!({}), [7; 32]).unwrap());
        let guard = control.lock().unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let result = other.configure(&json!({"enabled":false}), now + 1);
            sent.send(result).unwrap();
        });
        assert!(matches!(
            received.recv_timeout(std::time::Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        drop(guard);
        assert!(received
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap()
            .is_ok());
        thread.join().unwrap();
        assert_eq!(control.status(now + 1).unwrap()["enabled"], false);
    }
    #[test]
    fn changed_credentials_are_saved_before_active_pool_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let control = setup(dir.path(), now);
        let mut core = Coordinator::open(control.clone(), &["US", "JP"], now).unwrap();
        core.refresh(now).unwrap();
        let job = core.sync_job().unwrap();
        let result = job
            .run(&Fake {
                password: "new-synthetic-password",
                fail: false,
            })
            .unwrap();
        let directory = dir.path().join("webshare");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert_eq!(core.commit_sync(&job, result, now), Err(CoreError::Storage));
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(core.begin_region("US").unwrap().sessions.len(), 1);
        let job = core.sync_job().unwrap();
        let result = job
            .run(&Fake {
                password: "new-synthetic-password",
                fail: false,
            })
            .unwrap();
        assert_eq!(
            core.commit_sync(&job, result, now).unwrap(),
            SyncEffect::Applied
        );
        assert!(core.begin_region("US").unwrap().sessions.is_empty());
        let saved = control.load_active(&["US", "JP"], now).unwrap().unwrap();
        assert_eq!(
            saved.as_value()["active"]["credentials"]["password"],
            "new-synthetic-password"
        );
        assert!(saved.as_value()["pools"]["US"]
            .as_array()
            .unwrap()
            .is_empty());
    }
    #[test]
    fn later_rotation_is_not_lost_when_an_older_probe_finishes() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let control = setup(dir.path(), now);
        let mut core = Coordinator::open(control.clone(), &["US", "JP"], now).unwrap();
        core.refresh(now).unwrap();
        control
            .request(&json!({"action":"rotate","country":"US"}), now)
            .unwrap();
        core.refresh(now).unwrap();
        let job = core.begin_region("US").unwrap();
        assert!(job.forced);
        let mut counter = 0u8;
        let completion = job
            .run(now, |_, _, _| {
                counter += 1;
                Ok(ProbeResult {
                    exit_ip: format!("8.8.4.{counter}").parse().unwrap(),
                    exit_country: "US".into(),
                    https_ms: 10,
                    doh_ms: 10,
                    last_success: now,
                })
            })
            .unwrap();
        control
            .request(&json!({"action":"rotate","country":"US"}), now + 1)
            .unwrap();
        core.refresh(now + 1).unwrap();
        core.commit_region(completion, now + 1).unwrap();
        assert!(core.begin_region("US").unwrap().forced);
        let saved = control
            .load_active(&["US", "JP"], now + 1)
            .unwrap()
            .unwrap();
        assert_eq!(saved.as_value()["pending_rotations"], json!(["US"]));
        let mut restarted = Coordinator::open(control, &["US", "JP"], now + 1).unwrap();
        restarted.refresh(now + 1).unwrap();
        assert!(restarted.begin_region("US").unwrap().forced);
    }
    #[test]
    fn failed_probe_does_not_replace_existing_session() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let control = setup(dir.path(), now);
        let mut core = Coordinator::open(control, &["US", "JP"], now).unwrap();
        core.refresh(now).unwrap();
        let job = core.begin_region("US").unwrap();
        let completion = job
            .run(now, |_, _, _| Err(ProbeError::Unavailable))
            .unwrap();
        core.commit_region(completion, now).unwrap();
        assert_eq!(
            core.begin_region("US").unwrap().sessions[0].username(),
            "fixture-us-1"
        );
    }
    #[test]
    fn report_exposes_health_but_never_credentials_from_source_data() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let control = setup(dir.path(), now);
        let mut core = Coordinator::open(control.clone(), &["US", "JP"], now).unwrap();
        core.refresh(now).unwrap();
        core.plans.push(json!({"id":17,"eligible":true,"label":"synthetic-password fixture-us-1 synthetic-api-key-for-test",
            "password":"synthetic-password"}));
        let info = ReportInfo {
            sync_error: "synthetic-password",
            usage: json!({"requests_total":5,"secret":"synthetic-password"}),
            ..ReportInfo::default()
        };
        core.report(now, &info).unwrap();
        let raw = std::fs::read_to_string(dir.path().join("webshare/report.json")).unwrap();
        assert!(!raw.contains("synthetic-password"));
        assert!(!raw.contains("synthetic-api-key-for-test"));
        assert!(!raw.contains("fixture-us-1"));
        let report: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(report["requests_total"], 5);
        assert_eq!(report["status"], "degraded");
        let status = control.status(now).unwrap();
        assert!(!status.to_string().contains("synthetic-password"));
    }
}
