//! A bounded provider synchronization decision. Callers must re-check the
//! configuration revision and apply the result under their own state lock.
use crate::provider::{credentials, plans, Credentials, Endpoint, Provider, ProviderError};
use crate::ActiveSnapshot;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub enum SyncError {
    InvalidState,
    Provider(ProviderError),
}
#[derive(Clone)]
pub struct Desired {
    raw: crate::Secret,
    key: Zeroizing<String>,
    pub plan_id: i64,
    pub enabled: bool,
    pub revision: String,
    action: Option<String>,
    country: Option<String>,
}
impl Desired {
    pub(crate) fn key_is_empty(&self) -> bool {
        self.key.is_empty()
    }
    pub(crate) fn wants_usage(&self) -> bool {
        !self.key.is_empty() && self.plan_id > 0
    }
    pub(crate) fn usage<P: Provider + ?Sized>(
        &self,
        provider: &P,
        now: i64,
    ) -> Result<Value, ProviderError> {
        if !self.wants_usage() || now < 0 {
            return Err(ProviderError::InvalidRequest);
        }
        let plan = self.plan_id.to_string();
        let from = utc(now.saturating_sub(86_400))?;
        let to = utc(now)?;
        let response = provider.fetch(
            &self.key,
            Endpoint::Usage,
            &[
                ("plan_id", &plan),
                ("timestamp__gte", &from),
                ("timestamp__lte", &to),
            ],
        )?;
        let mut result = crate::provider::usage(response.as_value());
        result["usage_updated"] = json!(now);
        Ok(result)
    }
    pub(crate) fn redact(&self, value: &mut Value) {
        crate::redact(value, &self.key);
    }
    pub(crate) fn equivalent(&self, other: &Self) -> bool {
        self.plan_id == other.plan_id
            && self.enabled == other.enabled
            && self.revision == other.revision
            && self.action == other.action
            && self.country == other.country
            && same(&self.key, &other.key)
    }
    pub fn from_value(value: &Value) -> Result<Self, SyncError> {
        let key = value
            .get("api_key")
            .and_then(Value::as_str)
            .ok_or(SyncError::InvalidState)?;
        let plan_id = value
            .get("plan_id")
            .and_then(Value::as_i64)
            .filter(|id| (0..=2_147_483_647).contains(id))
            .ok_or(SyncError::InvalidState)?;
        let enabled = value
            .get("enabled")
            .and_then(Value::as_bool)
            .ok_or(SyncError::InvalidState)?;
        let revision = value
            .get("revision")
            .and_then(Value::as_str)
            .filter(|value| value.len() <= 128)
            .ok_or(SyncError::InvalidState)?;
        if (!key.is_empty() && !crate::api_key(key))
            || (enabled && (key.is_empty() || plan_id == 0))
        {
            return Err(SyncError::InvalidState);
        }
        let action = match value.get("action") {
            None => None,
            Some(Value::String(value)) if ["sync", "rotate"].contains(&value.as_str()) => {
                Some(value.clone())
            }
            _ => return Err(SyncError::InvalidState),
        };
        let country = match value.get("country") {
            None => None,
            Some(Value::String(value)) if crate::REGIONS.iter().any(|r| r.country == value) => {
                Some(value.clone())
            }
            _ => return Err(SyncError::InvalidState),
        };
        if action.as_deref() == Some("rotate") && country.is_none() {
            return Err(SyncError::InvalidState);
        }
        Ok(Self {
            raw: crate::Secret(value.clone()),
            key: Zeroizing::new(key.to_owned()),
            plan_id,
            enabled,
            revision: revision.to_owned(),
            action,
            country,
        })
    }
}
fn utc(timestamp: i64) -> Result<String, ProviderError> {
    let raw = libc::time_t::try_from(timestamp).map_err(|_| ProviderError::InvalidRequest)?;
    let mut output = std::mem::MaybeUninit::<libc::tm>::uninit();
    // SAFETY: both pointers are valid for this call; gmtime_r initializes the
    // output on success and uses no shared timezone state.
    if unsafe { libc::gmtime_r(&raw, output.as_mut_ptr()) }.is_null() {
        return Err(ProviderError::InvalidRequest);
    }
    // SAFETY: gmtime_r returned a non-null pointer to the initialized output.
    let value = unsafe { output.assume_init() };
    let year = value
        .tm_year
        .checked_add(1900)
        .ok_or(ProviderError::InvalidRequest)?;
    if !(1..=9999).contains(&year) {
        return Err(ProviderError::InvalidRequest);
    }
    Ok(format!(
        "{year:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
        value.tm_mon + 1,
        value.tm_mday,
        value.tm_hour,
        value.tm_min,
        value.tm_sec
    ))
}
#[derive(Clone)]
pub struct Active {
    raw: crate::Secret,
    key: Zeroizing<String>,
    pub plan_id: i64,
    pub enabled: bool,
    pub credentials: Option<Credentials>,
}
impl Active {
    pub(crate) fn key_is_empty(&self) -> bool {
        self.key.is_empty()
    }
    pub(crate) fn redact(&self, value: &mut Value) {
        crate::redact(value, &self.key);
        if let Some(credentials) = &self.credentials {
            crate::redact(value, &credentials.base);
            crate::redact(value, &credentials.password);
        }
    }
    pub fn empty() -> Self {
        Self {
            raw: crate::Secret(json!({"enabled":false,"plan_id":0})),
            key: Zeroizing::new(String::new()),
            plan_id: 0,
            enabled: false,
            credentials: None,
        }
    }
    pub fn from_snapshot(snapshot: &ActiveSnapshot) -> Result<Self, SyncError> {
        let value = &snapshot.as_value()["active"];
        let key = value.get("api_key").and_then(Value::as_str).unwrap_or("");
        let plan_id = value
            .get("plan_id")
            .and_then(Value::as_i64)
            .ok_or(SyncError::InvalidState)?;
        let enabled = value
            .get("enabled")
            .and_then(Value::as_bool)
            .ok_or(SyncError::InvalidState)?;
        let credentials = match value.get("credentials") {
            None => None,
            Some(value) => Some(Credentials {
                base: Zeroizing::new(
                    value
                        .get("base")
                        .and_then(Value::as_str)
                        .ok_or(SyncError::InvalidState)?
                        .to_owned(),
                ),
                password: Zeroizing::new(
                    value
                        .get("password")
                        .and_then(Value::as_str)
                        .ok_or(SyncError::InvalidState)?
                        .to_owned(),
                ),
            }),
        };
        Ok(Self {
            raw: crate::Secret(value.clone()),
            key: Zeroizing::new(key.to_owned()),
            plan_id,
            enabled,
            credentials,
        })
    }
    pub(crate) fn record(&self) -> crate::Secret {
        let mut result = self.raw.clone();
        for key in ["api_key", "credentials"] {
            if let Some(value) = result.0.get_mut(key) {
                crate::scrub(value);
            }
        }
        result.0["api_key"] = json!(self.key.as_str());
        result.0["plan_id"] = json!(self.plan_id);
        result.0["enabled"] = json!(self.enabled);
        if let Some(credentials) = &self.credentials {
            result.0["credentials"] =
                json!({"base":credentials.base.as_str(),"password":credentials.password.as_str()});
        } else if let Some(value) = result.0.as_object_mut() {
            value.remove("credentials");
        }
        result
    }
}
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
fn same_credentials(a: Option<&Credentials>, b: Option<&Credentials>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => same(&a.base, &b.base) && same(&a.password, &b.password),
        _ => false,
    }
}
pub enum Decision {
    Applied {
        active: Box<Active>,
        plans: Vec<Value>,
        revision: String,
        changed: bool,
        rotate: Option<String>,
    },
    Stale,
    InvalidPlan {
        disable_current: bool,
    },
}
/// Rotation of a cached account need not contact the provider. The caller
/// still persists the revision and schedules a new region session.
pub fn cached_rotation(
    desired: &Desired,
    current: &Active,
    processed_revision: &str,
) -> Option<String> {
    if desired.action.as_deref() == Some("rotate")
        && desired.enabled
        && current.enabled
        && desired.revision != processed_revision
        && desired.plan_id == current.plan_id
        && same(&desired.key, &current.key)
    {
        desired.country.clone()
    } else {
        None
    }
}
fn has_next(value: &Value) -> Result<bool, SyncError> {
    match value.get("next") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => Ok(false),
        Some(Value::Bool(true)) => Ok(true),
        Some(Value::String(value)) => Ok(!value.is_empty()),
        _ => Err(SyncError::InvalidState),
    }
}
/// Fetch at most ten bounded plan pages, validate credentials, then re-read
/// the desired revision. Results carry secrets and must not be logged.
pub fn synchronize<P, F>(
    provider: &P,
    desired: &Desired,
    current: &Active,
    revision: F,
) -> Result<Decision, SyncError>
where
    P: Provider + ?Sized,
    F: FnOnce() -> Result<String, SyncError>,
{
    if desired.key.is_empty() {
        return Err(SyncError::InvalidState);
    }
    let mut available = Vec::new();
    let mut completed = false;
    for page in 1..=10 {
        let page = page.to_string();
        let response = provider
            .fetch(
                &desired.key,
                Endpoint::Plans,
                &[("page", &page), ("page_size", "100")],
            )
            .map_err(SyncError::Provider)?;
        available.extend(plans(response.as_value()).map_err(SyncError::Provider)?);
        if !has_next(response.as_value())? {
            completed = true;
            break;
        }
    }
    if !completed {
        return Err(SyncError::InvalidState);
    }
    let credentials = if desired.plan_id == 0 {
        None
    } else {
        if !available.iter().any(|plan| {
            plan["id"].as_i64() == Some(desired.plan_id) && plan["eligible"].as_bool() == Some(true)
        }) {
            if revision()? != desired.revision {
                return Ok(Decision::Stale);
            }
            return Ok(Decision::InvalidPlan {
                disable_current: desired.plan_id == current.plan_id
                    && same(&desired.key, &current.key),
            });
        }
        let plan_id = desired.plan_id.to_string();
        let response = provider
            .fetch(
                &desired.key,
                Endpoint::Proxies,
                &[
                    ("mode", "backbone"),
                    ("plan_id", &plan_id),
                    ("page", "1"),
                    ("page_size", "1"),
                ],
            )
            .map_err(SyncError::Provider)?;
        Some(credentials(response.as_value()).map_err(SyncError::Provider)?)
    };
    if revision()? != desired.revision {
        return Ok(Decision::Stale);
    }
    let changed = current.plan_id != desired.plan_id
        || !same_credentials(current.credentials.as_ref(), credentials.as_ref());
    let active = Active {
        raw: desired.raw.clone(),
        key: desired.key.clone(),
        plan_id: desired.plan_id,
        enabled: desired.enabled,
        credentials,
    };
    available.truncate(100);
    Ok(Decision::Applied {
        active: Box::new(active),
        plans: available,
        revision: desired.revision.clone(),
        changed,
        rotate: if desired.action.as_deref() == Some("rotate") {
            desired.country.clone()
        } else {
            None
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::ProviderResponse;
    use serde_json::json;
    use std::cell::Cell;
    #[test]
    fn usage_timestamps_are_utc_and_handle_leap_days() {
        assert_eq!(utc(0).unwrap(), "1970-01-01T00:00:00+00:00");
        assert_eq!(utc(-1).unwrap(), "1969-12-31T23:59:59+00:00");
        assert_eq!(utc(951_782_400).unwrap(), "2000-02-29T00:00:00+00:00");
    }
    struct Fake {
        mode: &'static str,
        calls: Cell<usize>,
    }
    impl Provider for Fake {
        fn fetch(
            &self,
            _key: &str,
            endpoint: Endpoint,
            _params: &[(&str, &str)],
        ) -> Result<ProviderResponse, ProviderError> {
            self.calls.set(self.calls.get() + 1);
            if self.mode == "bad-key" {
                return Err(ProviderError::Unauthorized);
            }
            Ok(match endpoint {
                Endpoint::Plans => ProviderResponse::fixture(
                    json!({"results":[{"id":17,"status":if self.mode=="invalid" {"cancelled"} else {"active"},"pool_filter":"residential"}],
                    "next":if self.mode=="endless" {json!("next")} else {Value::Null}}),
                ),
                Endpoint::Proxies => ProviderResponse::fixture(
                    json!({"results":[{"username":"fixture-123","password":"synthetic-password"}]}),
                ),
                _ => return Err(ProviderError::InvalidRequest),
            })
        }
    }
    fn desired(key: &str, revision: &str) -> Desired {
        Desired::from_value(&json!({"api_key":key,"plan_id":17,"enabled":true,"revision":revision}))
            .unwrap()
    }
    fn active(key: &str) -> Active {
        Active {
            raw: crate::Secret(json!({})),
            key: Zeroizing::new(key.into()),
            plan_id: 17,
            enabled: true,
            credentials: Some(Credentials {
                base: Zeroizing::new("fixture".into()),
                password: Zeroizing::new("synthetic-password".into()),
            }),
        }
    }
    #[test]
    fn keeps_working_state_on_failure_and_discards_stale_provider_results() {
        let desired = desired("synthetic-api-key-for-test", "revision");
        let current = active("synthetic-api-key-for-test");
        let provider = Fake {
            mode: "good",
            calls: Cell::new(0),
        };
        assert!(matches!(
            synchronize(&provider, &desired, &current, || Ok("newer".into())),
            Ok(Decision::Stale)
        ));
        let result = synchronize(&provider, &desired, &current, || Ok("revision".into())).unwrap();
        match result {
            Decision::Applied {
                changed,
                active,
                plans,
                ..
            } => {
                assert!(!changed);
                assert!(active.enabled);
                assert_eq!(plans.len(), 1);
            }
            _ => panic!("unexpected decision"),
        }
        let bad = Fake {
            mode: "bad-key",
            calls: Cell::new(0),
        };
        assert!(matches!(
            synchronize(&bad, &desired, &current, || Ok("revision".into())),
            Err(SyncError::Provider(ProviderError::Unauthorized))
        ));
        assert!(current.enabled);
    }
    #[test]
    fn invalid_selected_plan_disables_only_the_same_account_and_limits_pagination() {
        let provider = Fake {
            mode: "invalid",
            calls: Cell::new(0),
        };
        let current = active("synthetic-api-key-for-test");
        let same_key = desired("synthetic-api-key-for-test", "r");
        let new_key = desired("another-synthetic-api-key", "r");
        assert!(matches!(
            synchronize(&provider, &same_key, &current, || Ok("r".into())),
            Ok(Decision::InvalidPlan {
                disable_current: true
            })
        ));
        assert!(matches!(
            synchronize(&provider, &same_key, &current, || Ok("newer".into())),
            Ok(Decision::Stale)
        ));
        assert!(matches!(
            synchronize(&provider, &new_key, &current, || Ok("r".into())),
            Ok(Decision::InvalidPlan {
                disable_current: false
            })
        ));
        let endless = Fake {
            mode: "endless",
            calls: Cell::new(0),
        };
        assert!(matches!(
            synchronize(&endless, &same_key, &current, || Ok("r".into())),
            Err(SyncError::InvalidState)
        ));
        assert_eq!(endless.calls.get(), 10);
    }
    #[test]
    fn same_account_rotation_can_be_requested_without_a_provider_roundtrip() {
        let current = active("synthetic-api-key-for-test");
        let request=Desired::from_value(&json!({"api_key":"synthetic-api-key-for-test","plan_id":17,"enabled":true,"revision":"next","action":"rotate","country":"US"})).unwrap();
        assert_eq!(
            cached_rotation(&request, &current, "old").as_deref(),
            Some("US")
        );
        assert!(cached_rotation(&request, &current, "next").is_none());
    }
}
