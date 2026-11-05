//! Experimental panel-side core reconciliation policy.
//!
//! Concrete core identity validation, atomic SQLite accounting, user locking,
//! service supervision, and event persistence are the caller's responsibility.
//! This module has no production Xray adapter and is not a deployable service.
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use xcli_panel_traffic::Counter;
mod store;
pub use store::SqliteStore;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidState,
    CoreUnavailable,
    StorageUnavailable,
    CoreChanged,
}
type Result<T> = std::result::Result<T, Error>;

// No Debug implementation: a user's connection identity is sensitive.
#[derive(Clone)]
pub struct User {
    pub id: String,
    pub uuid: String,
    pub enabled: bool,
    pub deleted: bool,
    pub quota: i64,
    pub expires: i64,
    pub upload: i64,
    pub download: i64,
}
impl User {
    fn active(&self, now: i64) -> bool {
        !self.deleted
            && xcli_panel_users::status(
                self.enabled,
                self.expires,
                self.quota,
                self.upload,
                self.download,
                now,
            ) == "active"
    }
    pub fn email(&self, tag: &str) -> Result<String> {
        let id_ok = self.id == "health-probe"
            || (self.id.len() == 32
                && self
                    .id
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
        let bytes = self.uuid.as_bytes();
        if !id_ok
            || bytes.len() != 36
            || ![8, 13, 18, 23].into_iter().all(|i| bytes[i] == b'-')
            || bytes.iter().enumerate().any(|(i, c)| {
                ![8, 13, 18, 23].contains(&i) && !(c.is_ascii_digit() || (b'a'..=b'f').contains(c))
            })
        {
            return Err(Error::InvalidState);
        }
        Ok(format!("{}.{}@{}", self.id, &self.uuid[..8], tag))
    }
}

pub trait Core {
    fn generation(&mut self) -> Result<String>;
    fn counters(&mut self) -> Result<Vec<Counter>>;
    /// Keys are existing Xray e-mail identities; values are connection IDs.
    fn users(&mut self, tag: &str) -> Result<BTreeMap<String, String>>;
    fn add(&mut self, tag: &str, user: &User) -> Result<()>;
    /// Must verify and pin the expected generation before signalling the core.
    fn restart(&mut self, expected_generation: &str) -> Result<()>;
}
pub trait Store {
    /// Sample counters and load users in one committed transaction. Nothing
    /// outside the transaction may alter authorization or traffic concurrently.
    fn commit_sample_and_load(
        &mut self,
        generation: &str,
        counters: &[Counter],
        now: i64,
    ) -> Result<Vec<User>>;
    fn record_restart(&mut self, now: i64) -> Result<()>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Ready { added: usize },
    Restarting,
}

fn valid_tag(tag: &str) -> bool {
    static FORMAT: OnceLock<Regex> = OnceLock::new();
    FORMAT
        .get_or_init(|| {
            Regex::new(r"^(?:reality|websocket|hysteria2(?:-brutal)?|vmess|residential-[0-9]{2}(?:-hy2)?)$")
                .unwrap()
        })
        .is_match(tag)
}

pub fn validate_tags(tags: &[String]) -> bool {
    !tags.is_empty()
        && tags.len() <= 100
        && tags.iter().all(|tag| valid_tag(tag))
        && tags.iter().collect::<BTreeSet<_>>().len() == tags.len()
}

/// Commit a fresh non-resetting sample from the expected core before a
/// controlled restart. The caller must hold the same mutation lock as the
/// controller and ensure the core cannot be replaced concurrently. A signal
/// may only be sent after this returns successfully, and the core adapter must
/// still verify the identity when signalling it. Traffic between this sample
/// and process exit may not be accounted; abrupt crashes have other limits.
pub fn checkpoint_before_restart(
    core: &mut impl Core,
    store: &mut impl Store,
    expected_generation: &str,
    now: i64,
) -> Result<()> {
    if expected_generation.is_empty() || now < 0 {
        return Err(Error::InvalidState);
    }
    if core.generation()? != expected_generation {
        return Err(Error::CoreChanged);
    }
    let counters = core.counters()?;
    if core.generation()? != expected_generation {
        return Err(Error::CoreChanged);
    }
    store.commit_sample_and_load(expected_generation, &counters, now)?;
    Ok(())
}

/// The caller must run one poll at a time and serialize all access changes.
pub fn poll(
    core: &mut impl Core,
    store: &mut impl Store,
    tags: &[String],
    now: i64,
) -> Result<Outcome> {
    if now < 0 || !validate_tags(tags) {
        return Err(Error::InvalidState);
    }
    let generation = core.generation()?;
    if generation.is_empty() {
        return Err(Error::InvalidState);
    }
    let counters = core.counters()?;
    let mut current = BTreeMap::new();
    for tag in tags {
        current.insert(tag, core.users(tag)?);
    }
    if core.generation()? != generation {
        return Err(Error::CoreChanged);
    }
    let users = store.commit_sample_and_load(&generation, &counters, now)?;
    let mut revoke = false;
    let mut additions = Vec::new();
    for tag in tags {
        let mut desired = BTreeMap::new();
        for user in users.iter().filter(|user| user.active(now)) {
            let email = user.email(tag)?;
            if desired.insert(email, user).is_some() {
                return Err(Error::InvalidState);
            }
        }
        let actual = current.get(tag).ok_or(Error::InvalidState)?;
        for (email, uuid) in actual {
            if desired.get(email).is_none_or(|user| user.uuid != *uuid) {
                revoke = true;
            }
        }
        for (email, user) in desired {
            if !actual.contains_key(&email) {
                additions.push((tag, user));
            }
        }
    }
    if revoke {
        // Authorization was determined from an earlier sample. Refresh it as
        // close to the controlled restart as practical, then pin the same core
        // generation again when the adapter sends the restart signal.
        checkpoint_before_restart(core, store, &generation, now)?;
        core.restart(&generation)?;
        store.record_restart(now)?;
        Ok(Outcome::Restarting)
    } else {
        for (tag, user) in &additions {
            core.add(tag, user)?;
        }
        Ok(Outcome::Ready {
            added: additions.len(),
        })
    }
}
