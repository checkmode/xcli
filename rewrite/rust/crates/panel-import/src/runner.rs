//! Experimental import-worker loop. Changes remain disabled unless a caller
//! supplies service hooks. Real deployment has not yet been validated.
use crate::coordinator::Coordinator;
use crate::journal::{Hooks, JournalError, Store};
use crate::launcher::Launcher;
use crate::preview::PreviewError;
use crate::queue::{Action, Queue};
use crate::report::{FailureReason, Phase, ReportChannel};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, PartialEq, Eq)]
pub enum RunnerError {
    Unavailable,
}
type Result<T> = std::result::Result<T, RunnerError>;
fn timestamp() -> Result<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RunnerError::Unavailable)?
            .as_secs(),
    )
    .map_err(|_| RunnerError::Unavailable)
}
struct RefuseChanges;
impl Hooks for RefuseChanges {
    fn validate(&mut self, _: &Path) -> std::result::Result<(), JournalError> {
        Err(JournalError::Unavailable)
    }
    fn stop(&mut self) -> std::result::Result<(), JournalError> {
        Err(JournalError::Unavailable)
    }
    fn start_and_check(&mut self) -> std::result::Result<(), JournalError> {
        Err(JournalError::Unavailable)
    }
}
#[derive(Clone)]
struct State {
    id: String,
    phase: Phase,
    expires: Option<i64>,
    rows: Option<Vec<serde_json::Value>>,
    reason: Option<FailureReason>,
}
struct Shared {
    channel: ReportChannel,
    state: Mutex<State>,
    failed: AtomicBool,
}
impl Shared {
    fn publish(&self, state: &State) -> Result<()> {
        let now = timestamp()?;
        match (
            state.phase,
            state.expires,
            state.rows.as_deref(),
            state.reason,
        ) {
            (Phase::Ready, Some(expires), Some(rows), None) => {
                self.channel.publish_preview(&state.id, now, expires, rows)
            }
            (Phase::Failed, None, None, Some(reason)) => {
                self.channel.publish_failure(&state.id, now, reason)
            }
            (_, _, None, None) => self
                .channel
                .publish(&state.id, state.phase, now, state.expires),
            _ => return Err(RunnerError::Unavailable),
        }
        .map_err(|_| RunnerError::Unavailable)
    }
    fn transition(&self, state: State) -> Result<()> {
        let mut guard = self.state.lock().map_err(|_| RunnerError::Unavailable)?;
        self.publish(&state)?;
        *guard = state;
        Ok(())
    }
    fn heartbeat(&self) -> Result<()> {
        let guard = self.state.lock().map_err(|_| RunnerError::Unavailable)?;
        self.publish(&guard)
    }
    fn snapshot(&self) -> Result<State> {
        self.state
            .lock()
            .map(|value| value.clone())
            .map_err(|_| RunnerError::Unavailable)
    }
}
pub struct PreviewRunner {
    queue: Queue,
    store: Store,
    launcher: Launcher,
    channel: ReportChannel,
}
impl PreviewRunner {
    /// The caller supplies only trusted fixed paths and a dropped-privilege
    /// probe launcher. The runner acquires a single-worker process lock.
    pub fn new(queue: Queue, store: Store, launcher: Launcher, channel: ReportChannel) -> Self {
        Self {
            queue,
            store,
            launcher,
            channel,
        }
    }
    pub fn run(self, stop: Arc<AtomicBool>) -> Result<()> {
        self.run_with_hooks(stop, None)
    }
    /// Apply is experimental and requires the caller to provide working
    /// service coordination. With no hooks, the worker remains preview-only.
    pub fn run_with_hooks(
        self,
        stop: Arc<AtomicBool>,
        mut apply_hooks: Option<Box<dyn Hooks + Send>>,
    ) -> Result<()> {
        let _worker = self
            .queue
            .worker_lock()
            .map_err(|_| RunnerError::Unavailable)?;
        if let Some(hooks) = apply_hooks.as_mut() {
            self.store
                .recover(hooks.as_mut())
                .map_err(|_| RunnerError::Unavailable)?;
        }
        let initial = self
            .channel
            .restart(timestamp()?)
            .map_err(|_| RunnerError::Unavailable)?;
        let state = State {
            id: initial["id"]
                .as_str()
                .ok_or(RunnerError::Unavailable)?
                .to_owned(),
            phase: Phase::parse(initial["status"].as_str().ok_or(RunnerError::Unavailable)?)
                .ok_or(RunnerError::Unavailable)?,
            expires: initial.get("expires").and_then(serde_json::Value::as_i64),
            rows: None,
            reason: initial["reason"].as_str().and_then(FailureReason::parse),
        };
        let shared = Arc::new(Shared {
            channel: self.channel,
            state: Mutex::new(state),
            failed: AtomicBool::new(false),
        });
        let refresh_catalog = || {
            let (files, _) = self.store.load().map_err(|_| RunnerError::Unavailable)?;
            let items = crate::config::catalog(files).map_err(|_| RunnerError::Unavailable)?;
            shared
                .channel
                .publish_catalog(&items)
                .map_err(|_| RunnerError::Unavailable)
        };
        if refresh_catalog().is_err() {
            let _ = shared.transition(State {
                id: String::new(),
                phase: Phase::Unavailable,
                expires: None,
                rows: None,
                reason: None,
            });
            return Err(RunnerError::Unavailable);
        }
        let heartbeat_stop = Arc::new(AtomicBool::new(false));
        let heartbeat_signal = heartbeat_stop.clone();
        let heartbeat_state = shared.clone();
        let heartbeat_worker_stop = stop.clone();
        let heartbeat = std::thread::Builder::new()
            .name("xcli-import-heartbeat".into())
            .spawn(move || {
                while !heartbeat_signal.load(Ordering::Acquire) {
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while !heartbeat_signal.load(Ordering::Acquire) && Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    if !heartbeat_signal.load(Ordering::Acquire)
                        && heartbeat_state.heartbeat().is_err()
                    {
                        heartbeat_state.failed.store(true, Ordering::Release);
                        heartbeat_worker_stop.store(true, Ordering::Release);
                        break;
                    }
                }
            })
            .map_err(|_| RunnerError::Unavailable)?;
        let result = (|| {
            let mut coordinator = Coordinator::default();
            while !stop.load(Ordering::Acquire) {
                if shared.failed.load(Ordering::Acquire) {
                    return Err(RunnerError::Unavailable);
                }
                let now = timestamp()?;
                let current = shared.snapshot()?;
                if current.phase == Phase::Ready
                    && current.expires.is_some_and(|expires| expires <= now)
                {
                    coordinator.discard();
                    shared.transition(State {
                        id: current.id,
                        phase: Phase::Expired,
                        expires: None,
                        rows: None,
                        reason: None,
                    })?;
                }
                match self.queue.claim(now) {
                    Ok(Some(request)) => {
                        let id = request.id().to_owned();
                        let applying =
                            matches!(request.action(), Action::Apply | Action::BrutalRate);
                        if applying && apply_hooks.is_none() {
                            coordinator.discard();
                            shared.transition(State {
                                id,
                                phase: Phase::Failed,
                                expires: None,
                                rows: None,
                                reason: Some(FailureReason::ApplyDisabled),
                            })?;
                        } else {
                            shared.transition(State {
                                id: id.clone(),
                                phase: if applying {
                                    Phase::Applying
                                } else {
                                    Phase::Verifying
                                },
                                expires: None,
                                rows: None,
                                reason: None,
                            })?;
                            let mut refused = RefuseChanges;
                            let hooks: &mut dyn Hooks = match apply_hooks.as_mut() {
                                Some(hooks) => hooks.as_mut(),
                                None => &mut refused,
                            };
                            let result = coordinator.handle_cancellable(
                                &request,
                                &self.store,
                                &self.launcher,
                                hooks,
                                now,
                                Some(&stop),
                            );
                            if stop.load(Ordering::Acquire) {
                                coordinator.discard();
                                break;
                            }
                            match result {
                                Ok(_) if applying => {
                                    refresh_catalog()?;
                                    shared.transition(State {
                                        id,
                                        phase: Phase::Complete,
                                        expires: None,
                                        rows: None,
                                        reason: None,
                                    })?
                                }
                                Ok(result) => {
                                    let expires = timestamp()?
                                        .checked_add(900)
                                        .ok_or(RunnerError::Unavailable)?;
                                    let rows = result["rows"]
                                        .as_array()
                                        .ok_or(RunnerError::Unavailable)?
                                        .clone();
                                    shared.transition(State {
                                        id,
                                        phase: Phase::Ready,
                                        expires: Some(expires),
                                        rows: Some(rows),
                                        reason: None,
                                    })?;
                                }
                                Err(error) => shared.transition(State {
                                    id,
                                    phase: Phase::Failed,
                                    expires: None,
                                    rows: None,
                                    reason: Some(match error {
                                        PreviewError::Invalid => FailureReason::Invalid,
                                        PreviewError::Probe => FailureReason::Probe,
                                        PreviewError::Conflict => FailureReason::Conflict,
                                        PreviewError::Expired => FailureReason::Expired,
                                        PreviewError::Unavailable => FailureReason::Unavailable,
                                    }),
                                })?,
                            }
                        }
                    }
                    Ok(None) if current.phase == Phase::Unavailable => {
                        shared.transition(State {
                            id: String::new(),
                            phase: Phase::Idle,
                            expires: None,
                            rows: None,
                            reason: None,
                        })?;
                    }
                    Ok(None) => (),
                    Err(_) => {
                        if current.phase != Phase::Unavailable {
                            coordinator.discard();
                            shared.transition(State {
                                id: String::new(),
                                phase: Phase::Unavailable,
                                expires: None,
                                rows: None,
                                reason: None,
                            })?;
                        }
                    }
                }
                let deadline = Instant::now() + Duration::from_secs(1);
                while !stop.load(Ordering::Acquire)
                    && !shared.failed.load(Ordering::Acquire)
                    && Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            if shared.failed.load(Ordering::Acquire) {
                Err(RunnerError::Unavailable)
            } else {
                Ok(())
            }
        })();
        heartbeat_stop.store(true, Ordering::Release);
        if heartbeat.join().is_err() {
            return Err(RunnerError::Unavailable);
        }
        let stopped_id = shared.snapshot().map(|state| state.id).unwrap_or_default();
        let unavailable = shared.transition(State {
            id: stopped_id,
            phase: Phase::Unavailable,
            expires: None,
            rows: None,
            reason: None,
        });
        result.and(unavailable)
    }
}
