use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;
use xcli_panel_controller::{poll, Core, Error, Outcome, SqliteStore, Store, User};
use xcli_panel_traffic::Counter;

type Trace = Rc<RefCell<Vec<String>>>;
const ID: &str = "0123456789abcdef0123456789abcdef";
const UUID: &str = "01234567-89ab-4def-8123-456789abcdef";

fn user() -> User {
    User {
        id: ID.into(),
        uuid: UUID.into(),
        enabled: true,
        deleted: false,
        quota: 0,
        expires: 0,
        upload: 0,
        download: 0,
    }
}
struct FakeCore {
    trace: Trace,
    current: BTreeMap<String, BTreeMap<String, String>>,
    generations: Vec<String>,
    fail_add: bool,
    counters: VecDeque<Vec<Counter>>,
    counter_calls: usize,
    fail_counter_call: Option<usize>,
}
impl Core for FakeCore {
    fn generation(&mut self) -> Result<String, Error> {
        self.trace.borrow_mut().push("generation".into());
        Ok(self.generations.remove(0))
    }
    fn counters(&mut self) -> Result<Vec<Counter>, Error> {
        self.trace.borrow_mut().push("counters".into());
        self.counter_calls += 1;
        if self.fail_counter_call == Some(self.counter_calls) {
            return Err(Error::CoreUnavailable);
        }
        Ok(self.counters.pop_front().unwrap_or_default())
    }
    fn users(&mut self, tag: &str) -> Result<BTreeMap<String, String>, Error> {
        self.trace.borrow_mut().push(format!("users:{tag}"));
        Ok(self.current.get(tag).cloned().unwrap_or_default())
    }
    fn add(&mut self, tag: &str, _: &User) -> Result<(), Error> {
        self.trace.borrow_mut().push(format!("add:{tag}"));
        if self.fail_add {
            Err(Error::CoreUnavailable)
        } else {
            Ok(())
        }
    }
    fn restart(&mut self, _: &str) -> Result<(), Error> {
        self.trace.borrow_mut().push("restart".into());
        Ok(())
    }
}
struct FakeStore {
    trace: Trace,
    users: Vec<User>,
    fail: bool,
    commits: usize,
    fail_commit: Option<usize>,
}
impl Store for FakeStore {
    fn commit_sample_and_load(
        &mut self,
        _: &str,
        _: &[Counter],
        _: i64,
    ) -> Result<Vec<User>, Error> {
        self.trace.borrow_mut().push("commit".into());
        self.commits += 1;
        if self.fail || self.fail_commit == Some(self.commits) {
            Err(Error::StorageUnavailable)
        } else {
            Ok(std::mem::take(&mut self.users))
        }
    }
    fn record_restart(&mut self, _: i64) -> Result<(), Error> {
        self.trace.borrow_mut().push("audit".into());
        Ok(())
    }
}
fn setup() -> (FakeCore, FakeStore, Trace) {
    let trace = Rc::new(RefCell::new(vec![]));
    (
        FakeCore {
            trace: trace.clone(),
            current: BTreeMap::new(),
            generations: vec!["42:1".into(); 4],
            fail_add: false,
            counters: VecDeque::new(),
            counter_calls: 0,
            fail_counter_call: None,
        },
        FakeStore {
            trace: trace.clone(),
            users: vec![user()],
            fail: false,
            commits: 0,
            fail_commit: None,
        },
        trace,
    )
}

#[test]
fn commits_sample_before_adding_new_users() {
    let (mut core, mut store, trace) = setup();
    assert_eq!(
        poll(
            &mut core,
            &mut store,
            &["reality".into(), "websocket".into()],
            100
        ),
        Ok(Outcome::Ready { added: 2 })
    );
    assert_eq!(
        *trace.borrow(),
        vec![
            "generation",
            "counters",
            "users:reality",
            "users:websocket",
            "generation",
            "commit",
            "add:reality",
            "add:websocket"
        ]
    );
}
#[test]
fn revoked_or_rotated_user_restarts_before_any_addition() {
    let (mut core, mut store, trace) = setup();
    core.current.insert(
        "reality".into(),
        BTreeMap::from([("retired-user".into(), "old-uuid".into())]),
    );
    assert_eq!(
        poll(
            &mut core,
            &mut store,
            &["reality".into(), "websocket".into()],
            100
        ),
        Ok(Outcome::Restarting)
    );
    assert_eq!(
        *trace.borrow(),
        vec![
            "generation",
            "counters",
            "users:reality",
            "users:websocket",
            "generation",
            "commit",
            "generation",
            "counters",
            "generation",
            "commit",
            "restart",
            "audit"
        ]
    );
}
#[test]
fn generation_change_or_failed_transaction_prevents_core_mutation() {
    let (mut core, mut store, trace) = setup();
    core.generations[1] = "43:2".into();
    assert_eq!(
        poll(&mut core, &mut store, &["reality".into()], 100),
        Err(Error::CoreChanged)
    );
    assert!(!trace
        .borrow()
        .iter()
        .any(|v| v == "commit" || v == "restart" || v.starts_with("add:")));
    let (mut core, mut store, trace) = setup();
    store.fail = true;
    assert_eq!(
        poll(&mut core, &mut store, &["reality".into()], 100),
        Err(Error::StorageUnavailable)
    );
    assert!(!trace
        .borrow()
        .iter()
        .any(|v| v == "restart" || v.starts_with("add:")));
}
#[test]
fn final_checkpoint_failure_never_signals_restart() {
    for failure in 0..3 {
        let (mut core, mut store, trace) = setup();
        core.current.insert(
            "reality".into(),
            BTreeMap::from([("retired-user".into(), "old-uuid".into())]),
        );
        match failure {
            0 => core.fail_counter_call = Some(2),
            1 => store.fail_commit = Some(2),
            _ => core.generations[3] = "43:2".into(),
        }
        assert!(poll(&mut core, &mut store, &["reality".into()], 100).is_err());
        assert!(trace.borrow().iter().any(|entry| entry == "commit"));
        assert!(!trace
            .borrow()
            .iter()
            .any(|entry| entry == "restart" || entry == "audit"));
    }
}

#[test]
fn quota_and_expiry_revoke_existing_access() {
    for expired in [false, true] {
        let (mut core, mut store, _) = setup();
        if expired {
            store.users[0].expires = 100;
        } else {
            store.users[0].quota = 10;
            store.users[0].upload = 6;
            store.users[0].download = 4;
        }
        core.current.insert(
            "reality".into(),
            BTreeMap::from([(format!("{ID}.01234567@reality"), UUID.into())]),
        );
        assert_eq!(
            poll(&mut core, &mut store, &["reality".into()], 100),
            Ok(Outcome::Restarting)
        );
    }
}
#[test]
fn invalid_configuration_and_failed_add_do_not_claim_success() {
    let (mut core, mut store, trace) = setup();
    assert_eq!(
        poll(&mut core, &mut store, &["wrong".into()], 100),
        Err(Error::InvalidState)
    );
    assert!(trace.borrow().is_empty());
    let (mut core, mut store, trace) = setup();
    core.fail_add = true;
    assert_eq!(
        poll(&mut core, &mut store, &["reality".into()], 100),
        Err(Error::CoreUnavailable)
    );
    assert!(trace.borrow().iter().any(|v| v == "commit"));
    assert!(!trace.borrow().iter().any(|v| v == "audit"));
}

#[test]
fn sqlite_sample_reaches_quota_before_revocation() {
    use rusqlite::{params, Connection};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.sqlite");
    let db = Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE users(id TEXT PRIMARY KEY,uuid TEXT NOT NULL,enabled INTEGER NOT NULL,deleted INTEGER NOT NULL,
        quota INTEGER NOT NULL,expires INTEGER NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL);
        CREATE TABLE counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL,generation TEXT NOT NULL);
        CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE device_activity(user_id TEXT NOT NULL,transport TEXT NOT NULL,last_seen INTEGER NOT NULL DEFAULT 0,
            sampled INTEGER NOT NULL DEFAULT 0,upload_delta INTEGER NOT NULL DEFAULT 0,download_delta INTEGER NOT NULL DEFAULT 0,
            interval_seconds INTEGER NOT NULL DEFAULT 5,PRIMARY KEY(user_id,transport));
        CREATE TABLE samples(ts INTEGER NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL);
        CREATE TABLE traffic_history(ts INTEGER PRIMARY KEY,upload INTEGER NOT NULL,download INTEGER NOT NULL);
        CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);").unwrap();
    db.execute(
        "INSERT INTO users VALUES(?,?,1,0,100,0,0,0)",
        params![ID, UUID],
    )
    .unwrap();
    let (mut core, _, trace) = setup();
    core.current.insert(
        "reality".into(),
        BTreeMap::from([(format!("{ID}.01234567@reality"), UUID.into())]),
    );
    core.counters = VecDeque::from([
        vec![Counter {
            name: format!("user>>>{ID}.01234567@reality>>>traffic>>>uplink"),
            value: 100,
        }],
        vec![Counter {
            name: format!("user>>>{ID}.01234567@reality>>>traffic>>>uplink"),
            value: 130,
        }],
    ]);
    let mut store = SqliteStore::open(&path, 5, None).unwrap();
    assert_eq!(
        poll(&mut core, &mut store, &["reality".into()], 1000),
        Ok(Outcome::Restarting)
    );
    assert_eq!(
        db.query_row("SELECT upload FROM users WHERE id=?", [ID], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        130
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM events WHERE action='core_restart'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert!(trace.borrow().iter().any(|item| item == "restart"));
}
