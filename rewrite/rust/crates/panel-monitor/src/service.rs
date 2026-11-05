//! One monitor cycle with durable, credential-free status reporting.
use crate::report::{aggregate, Observation, Report, Scope};
use crate::{runner, store, Config, Invalid, Sensitive};
use std::sync::atomic::{AtomicBool, Ordering};

pub trait RunChecks: Send + Sync {
    fn run(&self, config: &Config, stop: &AtomicBool) -> Result<Vec<Observation>, Invalid>;
}
impl RunChecks for runner::Runner {
    fn run(&self, config: &Config, stop: &AtomicBool) -> Result<Vec<Observation>, Invalid> {
        self.run_once(config, stop)
    }
}
pub struct Service<R> {
    config: Config,
    runner: R,
    store: store::Store,
    scope: Scope,
    previous: Option<Sensitive>,
}
impl<R: RunChecks> Service<R> {
    pub fn new(
        config: Config,
        runner: R,
        store: store::Store,
        scope: Scope,
    ) -> Result<Self, Invalid> {
        let previous = store.load()?;
        Ok(Self {
            config,
            runner,
            store,
            scope,
            previous,
        })
    }
    /// A failed or cancelled cycle never overwrites the previous report.
    pub fn cycle(&mut self, now: i64, stop: &AtomicBool) -> Result<Report, Invalid> {
        self.cycle_with_clock(stop, || Ok(now))
    }
    /// Read the report timestamp after all probes finish so long batches do
    /// not produce a report that is already stale when it is written.
    pub fn cycle_with_clock(
        &mut self,
        stop: &AtomicBool,
        clock: impl FnOnce() -> Result<i64, Invalid>,
    ) -> Result<Report, Invalid> {
        let observations = self.runner.run(&self.config, stop)?;
        if stop.load(Ordering::Acquire) {
            return Err(Invalid);
        }
        let now = clock()?;
        let report = aggregate(
            &self.config,
            self.scope,
            now,
            observations,
            self.previous.as_ref().map(Sensitive::as_value),
        )?;
        self.store.save(&report)?;
        self.previous = self.store.load()?;
        Ok(report)
    }
}
