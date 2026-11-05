use super::*;
use std::cell::Cell;
use std::rc::Rc;
use tempfile::tempdir;

const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";

#[derive(Clone)]
struct ManualClock {
    wall: Rc<Cell<f64>>,
    mono: Rc<Cell<u64>>,
}
impl ManualClock {
    fn new() -> Self {
        Self {
            wall: Rc::new(Cell::new(1000.0)),
            mono: Rc::new(Cell::new(0)),
        }
    }
    fn advance(&self, seconds: u64) {
        self.wall.set(self.wall.get() + seconds as f64);
        self.mono.set(self.mono.get() + seconds);
    }
}
impl Clock for ManualClock {
    fn wall_seconds(&self) -> f64 {
        self.wall.get()
    }
    fn monotonic(&self) -> Duration {
        Duration::from_secs(self.mono.get())
    }
}

struct FakeCore {
    running: bool,
    generation: String,
    users: BTreeMap<String, User>,
    counters: Value,
    fail_sample: bool,
    fail_apply: bool,
    delay_on_apply: u64,
    clock: ManualClock,
    deadline: Option<DeadlineHandle>,
    observed: Option<Duration>,
}
impl Core for FakeCore {
    fn running(&mut self) -> bool {
        self.running
    }
    fn start(&mut self) -> std::result::Result<(), CoreError> {
        self.running = true;
        self.generation = "first".into();
        Ok(())
    }
    fn stop(&mut self) {
        self.running = false;
        self.users.clear();
        self.generation.clear();
    }
    fn generation(&self) -> &str {
        &self.generation
    }
    fn counters(&mut self) -> std::result::Result<Value, CoreError> {
        if self.fail_sample {
            Err(CoreError)
        } else {
            Ok(self.counters.clone())
        }
    }
    fn apply(&mut self, users: &BTreeMap<String, User>) -> std::result::Result<(), CoreError> {
        self.observed = self.deadline.as_ref().and_then(DeadlineHandle::get);
        self.clock.advance(self.delay_on_apply);
        if self.fail_apply {
            return Err(CoreError);
        }
        self.users = users.clone();
        Ok(())
    }
}
fn controller(clock: &ManualClock, path: &std::path::Path) -> Controller<FakeCore> {
    let core = FakeCore {
        running: false,
        generation: String::new(),
        users: BTreeMap::new(),
        counters: json!([]),
        fail_sample: false,
        fail_apply: false,
        delay_on_apply: 0,
        clock: clock.clone(),
        deadline: None,
        observed: None,
    };
    let mut agent = Controller::new(Ledger::open(path).unwrap(), core);
    agent.core.deadline = Some(agent.deadline_handle());
    agent
}
fn response(request: &Prepared, users: Value, issued: i64) -> Value {
    json!({"revision":"f".repeat(64),"users":users,"lease_seconds":30,"issued_at":issued,"ack":request.payload["counters"]})
}
fn users() -> Value {
    json!([{"id":ID,"uuid":UUID,"expires":0}])
}

#[test]
fn synchronizes_accounting_and_enforces_deadline() {
    let dir = tempdir().unwrap();
    let clock = ManualClock::new();
    let mut agent = controller(&clock, &dir.path().join("ledger.sqlite"));
    let request = agent.prepare().unwrap();
    let reply = response(&request, users(), 1000);
    agent.complete(request, &reply, &clock).unwrap();
    assert_eq!(agent.core.users.len(), 1);
    assert_eq!(agent.deadline_handle().get(), Some(Duration::from_secs(30)));
    agent.core.counters =
        json!([{"name":format!("user>>>{ID}.01234567@reality>>>traffic>>>uplink"),"value":"80"}]);
    let request = agent.prepare().unwrap();
    assert_eq!(
        request.payload["counters"],
        json!([{"id":ID,"upload":80,"download":0}])
    );
    let reply = response(&request, users(), 1000);
    agent.complete(request, &reply, &clock).unwrap();
    assert!(agent.ledger.pending(100).unwrap().is_empty());
    clock.advance(31);
    agent.watchdog(clock.monotonic()).unwrap();
    assert!(agent.core.users.is_empty());
    assert!(agent.deadline_handle().get().is_none());
}

#[test]
fn rejects_superseded_request_and_bad_ack_without_extending_old_lease() {
    let dir = tempdir().unwrap();
    let clock = ManualClock::new();
    let mut agent = controller(&clock, &dir.path().join("ledger.sqlite"));
    let first = agent.prepare().unwrap();
    let reply = response(&first, users(), 1000);
    agent.complete(first, &reply, &clock).unwrap();
    let stale = agent.prepare().unwrap();
    let stale_reply = response(&stale, users(), 1000);
    let current = agent.prepare().unwrap();
    assert!(agent.complete(stale, &stale_reply, &clock).is_err());
    let mut bad = response(&current, users(), 1000);
    bad["ack"] = json!([{"id":ID,"upload":1,"download":0}]);
    assert!(agent.complete(current, &bad, &clock).is_err());
    assert_eq!(agent.deadline_handle().get(), Some(Duration::from_secs(30)));
    assert_eq!(agent.core.users.len(), 1);
}

#[test]
fn keeps_previous_deadline_until_reconciliation_and_revocation_finish() {
    let dir = tempdir().unwrap();
    let clock = ManualClock::new();
    let mut agent = controller(&clock, &dir.path().join("ledger.sqlite"));
    let first = agent.prepare().unwrap();
    let reply = response(&first, users(), 1000);
    agent.complete(first, &reply, &clock).unwrap();
    clock.advance(1);
    let second = agent.prepare().unwrap();
    let reply = response(&second, users(), 1001);
    agent.complete(second, &reply, &clock).unwrap();
    assert_eq!(agent.core.observed, Some(Duration::from_secs(30)));
    assert_eq!(agent.deadline_handle().get(), Some(Duration::from_secs(31)));
    let third = agent.prepare().unwrap();
    let reply = response(&third, json!([]), 1001);
    agent.complete(third, &reply, &clock).unwrap();
    assert_eq!(agent.core.observed, Some(Duration::from_secs(31)));
    assert!(agent.deadline_handle().get().is_none());
}

#[test]
fn fails_closed_if_apply_exceeds_lease_or_sampling_fails() {
    let dir = tempdir().unwrap();
    let clock = ManualClock::new();
    let mut agent = controller(&clock, &dir.path().join("ledger.sqlite"));
    let request = agent.prepare().unwrap();
    let reply = response(&request, users(), 1000);
    agent.core.delay_on_apply = 31;
    assert!(agent.complete(request, &reply, &clock).is_err());
    assert!(!agent.core.running);
    assert!(agent.deadline_handle().get().is_none());
    agent.core.delay_on_apply = 0;
    let request = agent.prepare().unwrap();
    let reply = response(&request, users(), 1031);
    agent.complete(request, &reply, &clock).unwrap();
    agent.core.fail_sample = true;
    assert!(agent.watchdog(clock.monotonic()).is_err());
    assert!(!agent.core.running);
    assert!(agent.deadline_handle().get().is_none());
}

#[test]
fn shutdown_records_observed_usage_and_reports_sampling_failure() {
    let dir = tempdir().unwrap();
    let clock = ManualClock::new();
    let mut agent = controller(&clock, &dir.path().join("ledger.sqlite"));
    agent.prepare().unwrap();
    agent.core.counters =
        json!([{"name":format!("user>>>{ID}.01234567@reality>>>traffic>>>uplink"),"value":"80"}]);
    agent.stop().unwrap();
    assert!(!agent.core.running);
    assert_eq!(
        json!(agent.ledger.pending(100).unwrap()),
        json!([{"id":ID,"upload":80,"download":0}])
    );
    agent.prepare().unwrap();
    agent.core.fail_sample = true;
    assert!(agent.stop().is_err());
    assert!(!agent.core.running, "an unmonitored node must fail closed");
    assert_eq!(
        json!(agent.ledger.pending(100).unwrap()),
        json!([{"id":ID,"upload":80,"download":0}])
    );
    // A later successful sample of a new core cannot restore the missing
    // part of the old generation, so shutdown continues to report failure.
    agent.core.fail_sample = false;
    agent.prepare().unwrap();
    assert!(agent.stop().is_err());
}

#[test]
fn old_lease_cannot_be_extended_by_a_stalled_reconciliation() {
    let dir = tempdir().unwrap();
    let clock = ManualClock::new();
    let mut agent = controller(&clock, &dir.path().join("ledger.sqlite"));
    let first = agent.prepare().unwrap();
    let reply = response(&first, users(), 1000);
    agent.complete(first, &reply, &clock).unwrap();
    clock.advance(20);
    let next = agent.prepare().unwrap();
    let reply = response(&next, users(), 1020);
    agent.core.delay_on_apply = 11;
    assert!(agent.complete(next, &reply, &clock).is_err());
    assert_eq!(agent.core.observed, Some(Duration::from_secs(30)));
    assert!(!agent.core.running);
    assert!(agent.deadline_handle().get().is_none());
}
