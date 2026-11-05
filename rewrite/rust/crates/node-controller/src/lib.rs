//! Synchronous node reconciliation state machine.
//!
//! This does not run network or process I/O. A production driver must serialize
//! calls and independently stop Xray if a blocked call holds the controller
//! past its published monotonic deadline. No production node uses this yet.
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use xcli_node_ledger::Ledger;
use xcli_node_protocol::{validate_response, Grant, User};

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct ControllerError(&'static str);
impl fmt::Display for ControllerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ControllerError {}
type Result<T> = std::result::Result<T, ControllerError>;

#[derive(Debug, Clone, Copy)]
pub struct CoreError;
impl From<()> for CoreError {
    fn from(_: ()) -> Self {
        Self
    }
}

/// A caller must report errors without including credentials or configuration.
pub trait Core {
    fn running(&mut self) -> bool;
    fn start(&mut self) -> std::result::Result<(), CoreError>;
    fn stop(&mut self);
    fn generation(&self) -> &str;
    fn counters(&mut self) -> std::result::Result<Value, CoreError>;
    /// Removing users must terminate their established connections.
    fn apply(&mut self, users: &BTreeMap<String, User>) -> std::result::Result<(), CoreError>;
}

pub trait Clock {
    fn wall_seconds(&self) -> f64;
    /// Monotonic time relative to a stable process-local origin.
    fn monotonic(&self) -> Duration;
}

/// A request may contain user identifiers and must never be logged.
pub struct Prepared {
    serial: u64,
    generation: String,
    pub payload: Value,
}

/// Can be inspected by a supervisor without acquiring the controller lock.
#[derive(Clone, Default)]
pub struct DeadlineHandle(Arc<Mutex<Option<Duration>>>);
impl DeadlineHandle {
    pub fn get(&self) -> Option<Duration> {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    fn set(&self, value: Option<Duration>) {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
    }
}

pub struct Controller<C: Core> {
    ledger: Ledger,
    core: C,
    revision: String,
    serial: u64,
    in_flight: Option<u64>,
    deadline: DeadlineHandle,
    accounting_failed: bool,
}

impl<C: Core> Controller<C> {
    pub fn new(ledger: Ledger, core: C) -> Self {
        Self {
            ledger,
            core,
            revision: String::new(),
            serial: 0,
            in_flight: None,
            deadline: DeadlineHandle::default(),
            accounting_failed: false,
        }
    }

    /// The supervisor needs this deadline even while a network or core call is blocked.
    pub fn deadline_handle(&self) -> DeadlineHandle {
        self.deadline.clone()
    }

    fn fail_closed(&mut self) {
        // Signal the independent supervisor before an adapter's stop can block.
        self.deadline.set(Some(Duration::ZERO));
        self.core.stop();
        self.revision.clear();
        self.in_flight = None;
        self.deadline.set(None);
    }

    fn sample(&mut self) -> Result<()> {
        let result = self
            .core
            .counters()
            .map_err(|_| ControllerError("Core statistics unavailable"))
            .and_then(|counters| {
                self.ledger
                    .record(self.core.generation(), &counters)
                    .map_err(|_| ControllerError("Accounting failed"))
            });
        if result.is_err() {
            // A later healthy generation cannot recover counters from the
            // failed one. Keep the warning for this controller's lifetime.
            self.accounting_failed = true;
        }
        result
    }

    pub fn prepare(&mut self) -> Result<Prepared> {
        if !self.core.running() {
            self.fail_closed();
            if self.core.start().is_err() {
                self.fail_closed();
                return Err(ControllerError("Core start failed"));
            }
        }
        if !self.core.running() || self.core.generation().is_empty() {
            self.fail_closed();
            return Err(ControllerError("Core start failed"));
        }
        if self.sample().is_err() {
            self.fail_closed();
            return Err(ControllerError("Accounting failed"));
        }
        let pending = match self.ledger.pending(100) {
            Ok(value) => value,
            Err(_) => {
                self.fail_closed();
                return Err(ControllerError("Accounting failed"));
            }
        };
        self.serial = match self.serial.checked_add(1) {
            Some(value) => value,
            None => {
                self.fail_closed();
                return Err(ControllerError("Request sequence exhausted"));
            }
        };
        self.in_flight = Some(self.serial);
        Ok(Prepared {
            serial: self.serial,
            generation: self.core.generation().to_owned(),
            payload: json!({"revision":self.revision,"counters":pending}),
        })
    }

    fn deadline_for(grant: &Grant, clock: &impl Clock) -> Result<Option<Duration>> {
        let wall = clock.wall_seconds();
        let mut remaining = grant
            .remaining_at(wall)
            .map_err(|_| ControllerError("Access lease expired"))?;
        if grant.users.is_empty() {
            return Ok(None);
        }
        for user in grant.users.values().filter(|u| u.expires != 0) {
            remaining = remaining.min(user.expires as f64 - wall);
        }
        if !remaining.is_finite() || remaining <= 0.0 {
            return Err(ControllerError("Access lease expired"));
        }
        clock
            .monotonic()
            .checked_add(Duration::from_secs_f64(remaining))
            .map(Some)
            .ok_or(ControllerError("Invalid monotonic deadline"))
    }

    /// Call after the untrusted response is received, with the exact request
    /// that produced it. The clock is read again after core reconciliation.
    pub fn complete(
        &mut self,
        request: Prepared,
        response: &Value,
        clock: &impl Clock,
    ) -> Result<()> {
        if self.in_flight != Some(request.serial)
            || !self.core.running()
            || self.core.generation() != request.generation
        {
            return Err(ControllerError("Stale synchronization response"));
        }
        if self
            .deadline
            .get()
            .is_some_and(|deadline| clock.monotonic() >= deadline)
        {
            self.fail_closed();
            return Err(ControllerError("Access lease expired"));
        }
        self.in_flight = None;
        let grant = validate_response(response, &request.payload["counters"], clock.wall_seconds())
            .map_err(|_| ControllerError("Invalid synchronization response"))?;
        Self::deadline_for(&grant, clock)?;
        if self.sample().is_err() {
            self.fail_closed();
            return Err(ControllerError("Accounting failed"));
        }
        if self.ledger.acknowledge(&response["ack"]).is_err() {
            self.fail_closed();
            return Err(ControllerError("Accounting acknowledgement failed"));
        }
        let next_deadline = match Self::deadline_for(&grant, clock) {
            Ok(value) => value,
            Err(error) => {
                self.fail_closed();
                return Err(error);
            }
        };
        // Do not extend old authorization while removal or reconciliation is
        // still in progress. A supervisor can enforce this deadline separately.
        let until_applied = match (self.deadline.get(), next_deadline) {
            (Some(old), Some(new)) => Some(old.min(new)),
            (Some(old), None) => Some(old),
            (None, Some(new)) => Some(new),
            (None, None) => None,
        };
        self.deadline.set(until_applied);
        if self.core.apply(&grant.users).is_err() {
            self.fail_closed();
            return Err(ControllerError("Core reconciliation failed"));
        }
        if !self.core.running()
            || until_applied.is_some_and(|deadline| clock.monotonic() >= deadline)
        {
            self.fail_closed();
            return Err(ControllerError(
                "Access lease expired during reconciliation",
            ));
        }
        let after_apply = match Self::deadline_for(&grant, clock) {
            Ok(value) => value,
            Err(error) => {
                self.fail_closed();
                return Err(error);
            }
        };
        // Wall clock adjustments during application must not extend the grant.
        let deadline = match (next_deadline, after_apply) {
            (Some(first), Some(last)) => Some(first.min(last)),
            (_, value) => value,
        };
        self.deadline.set(deadline);
        self.revision = grant.revision;
        Ok(())
    }

    /// Sample and revoke on deadline. The external supervisor must also stop
    /// Xray when this method cannot run because another operation is blocked.
    pub fn watchdog(&mut self, monotonic_now: Duration) -> Result<()> {
        if !self.core.running() {
            self.fail_closed();
            return Ok(());
        }
        if self.sample().is_err() {
            self.fail_closed();
            return Err(ControllerError("Accounting failed"));
        }
        if self
            .deadline
            .get()
            .is_some_and(|deadline| monotonic_now >= deadline)
        {
            if self.core.apply(&BTreeMap::new()).is_err() {
                self.fail_closed();
                return Err(ControllerError("Core revocation failed"));
            }
            self.revision.clear();
            self.in_flight = None;
            self.deadline.set(None);
        }
        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        let result = if self.core.running() {
            self.sample()
        } else {
            Ok(())
        };
        self.fail_closed();
        if result.is_ok() && self.accounting_failed {
            Err(ControllerError("A previous accounting sample failed"))
        } else {
            result
        }
    }
}
