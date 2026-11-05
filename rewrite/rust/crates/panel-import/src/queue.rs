//! Experimental authenticated import inbox and durable replay guard.
//! The caller must still validate every action-specific field, audit the
//! request, separate probe privileges, and handle interrupted transactions.
use crate::journal::{atomic, check_private_dir, lock, private_meta, read};
use crate::vmess::SecretJson;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use xcli_auth_compat::open_xgb1;
use zeroize::Zeroizing;

const CONTEXT: &[u8] = b"xcli:proxy-import:request:v1";
const TTL: i64 = 900;
const MAX_RECORDS: usize = 4096;
const MAX_INBOX: u64 = 20_000;
const MAX_STATE: u64 = 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum QueueError {
    Unavailable,
    Invalid,
    ClockBackwards,
    Full,
}
type Result<T> = std::result::Result<T, QueueError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Preview,
    Manage,
    Apply,
}
pub struct Claimed {
    id: String,
    action: Action,
    payload: SecretJson,
}
impl Claimed {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn action(&self) -> Action {
        self.action
    }
    /// Sensitive fields are present. Never log or publish this value.
    pub fn payload(&self) -> &Value {
        self.payload.as_value()
    }
}
pub struct Queue {
    inbox: PathBuf,
    state: PathBuf,
    legacy: Option<PathBuf>,
    key: Zeroizing<[u8; 32]>,
}
fn id_valid(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn private_read(path: &Path, limit: u64) -> Result<Option<crate::journal::FileState>> {
    let file = read(path, limit).map_err(|_| QueueError::Unavailable)?;
    if file.as_ref().is_some_and(|file| {
        file.meta.uid != unsafe { libc::geteuid() } || file.meta.mode & 0o077 != 0
    }) {
        return Err(QueueError::Unavailable);
    }
    Ok(file)
}
fn incoming(directory: &Path) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let parent = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(QueueError::Unavailable),
    };
    let name = std::ffi::CString::new("request.xgb").map_err(|_| QueueError::Invalid)?;
    // SAFETY: the directory descriptor remains open and name is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(QueueError::Unavailable)
        };
    }
    // SAFETY: openat returned a new owned descriptor on success.
    let file = unsafe { File::from_raw_fd(fd) };
    let info = file.metadata().map_err(|_| QueueError::Unavailable)?;
    if !info.is_file() || info.nlink() != 1 || info.len() > MAX_INBOX {
        return Err(QueueError::Invalid);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_INBOX + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| QueueError::Unavailable)?;
    if bytes.len() as u64 > MAX_INBOX {
        return Err(QueueError::Invalid);
    }
    Ok(Some(bytes))
}
struct Replay {
    last: i64,
    entries: BTreeMap<String, i64>,
}
impl Replay {
    fn load(state: &Path, legacy: Option<&Path>, now: i64) -> Result<(Self, bool)> {
        if let Some(file) = private_read(&state.join("request-replay.json"), MAX_STATE)? {
            let value: Value =
                serde_json::from_slice(&file.data).map_err(|_| QueueError::Invalid)?;
            if value["version"] != 1 {
                return Err(QueueError::Invalid);
            }
            let last = value["last"]
                .as_i64()
                .filter(|v| *v >= 0)
                .ok_or(QueueError::Invalid)?;
            let max_expiry = last.checked_add(TTL + 1).ok_or(QueueError::Invalid)?;
            let rows = value["entries"]
                .as_array()
                .filter(|rows| rows.len() <= MAX_RECORDS)
                .ok_or(QueueError::Invalid)?;
            let mut entries = BTreeMap::new();
            for row in rows {
                let id = row["id"]
                    .as_str()
                    .filter(|id| id_valid(id))
                    .ok_or(QueueError::Invalid)?;
                let expiry = row["expires"]
                    .as_i64()
                    .filter(|expiry| *expiry >= 0 && *expiry <= max_expiry)
                    .ok_or(QueueError::Invalid)?;
                if entries.insert(id.to_owned(), expiry).is_some() {
                    return Err(QueueError::Invalid);
                }
            }
            return Ok((Self { last, entries }, true));
        }
        let mut entries = BTreeMap::new();
        if let Some(file) = legacy
            .map(|path| private_read(path, 8192))
            .transpose()?
            .flatten()
        {
            let ids: Vec<String> =
                serde_json::from_slice(&file.data).map_err(|_| QueueError::Invalid)?;
            if ids.len() > 64 {
                return Err(QueueError::Invalid);
            }
            let expiry = now.checked_add(TTL + 1).ok_or(QueueError::Invalid)?;
            for id in ids {
                if !id_valid(&id) || entries.insert(id, expiry).is_some() {
                    return Err(QueueError::Invalid);
                }
            }
        }
        Ok((Self { last: now, entries }, false))
    }
    fn save(&self, state: &Path) -> Result<()> {
        let rows: Vec<_> = self
            .entries
            .iter()
            .map(|(id, expires)| json!({"id":id,"expires":expires}))
            .collect();
        let data = Zeroizing::new(
            serde_json::to_vec(&json!({"version":1,"last":self.last,"entries":rows}))
                .map_err(|_| QueueError::Invalid)?,
        );
        if data.len() as u64 > MAX_STATE {
            return Err(QueueError::Full);
        }
        atomic(&state.join("request-replay.json"), &data, &private_meta())
            .map_err(|_| QueueError::Unavailable)
    }
}
impl Queue {
    /// Paths come from trusted service configuration, never from a request.
    /// The private state directory must already exist and be owned by the caller.
    pub fn open(inbox: &Path, state: &Path, legacy: Option<&Path>, key: [u8; 32]) -> Result<Self> {
        if !inbox.is_absolute() || !state.is_absolute() {
            return Err(QueueError::Invalid);
        }
        check_private_dir(state).map_err(|_| QueueError::Unavailable)?;
        let legacy = legacy
            .map(|path| {
                if !path.is_absolute() {
                    return Err(QueueError::Invalid);
                }
                let parent = fs::canonicalize(path.parent().ok_or(QueueError::Invalid)?)
                    .map_err(|_| QueueError::Unavailable)?;
                let info = fs::symlink_metadata(&parent).map_err(|_| QueueError::Unavailable)?;
                if !info.is_dir()
                    || info.uid() != unsafe { libc::geteuid() }
                    || info.mode() & 0o022 != 0
                {
                    return Err(QueueError::Unavailable);
                }
                Ok(parent.join(path.file_name().ok_or(QueueError::Invalid)?))
            })
            .transpose()?;
        Ok(Self {
            inbox: inbox.to_path_buf(),
            state: fs::canonicalize(state).map_err(|_| QueueError::Unavailable)?,
            legacy,
            key: Zeroizing::new(key),
        })
    }
    /// Held for the entire worker lifetime; separate from the short queue
    /// claim lock so two workers can never race their in-memory previews.
    #[cfg(target_os = "linux")]
    pub(crate) fn worker_lock(&self) -> Result<File> {
        check_private_dir(&self.state).map_err(|_| QueueError::Unavailable)?;
        lock(&self.state.join("worker.lock")).map_err(|_| QueueError::Unavailable)
    }
    /// Atomically claim a fresh authenticated request. A claimed request is
    /// recorded before it is returned; a crash requires a new request ID.
    pub fn claim(&self, now: i64) -> Result<Option<Claimed>> {
        if now < 0 {
            return Err(QueueError::Invalid);
        }
        check_private_dir(&self.state).map_err(|_| QueueError::Unavailable)?;
        let _guard = lock(&self.state.join("queue.lock")).map_err(|_| QueueError::Unavailable)?;
        let Some(encrypted) = incoming(&self.inbox)? else {
            return Ok(None);
        };
        let plaintext =
            open_xgb1(&encrypted, self.key.as_ref(), CONTEXT).map_err(|_| QueueError::Invalid)?;
        let payload =
            SecretJson::new(serde_json::from_slice(&plaintext).map_err(|_| QueueError::Invalid)?);
        let object = payload.as_value().as_object().ok_or(QueueError::Invalid)?;
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| id_valid(id))
            .ok_or(QueueError::Invalid)?
            .to_owned();
        let requested = object
            .get("requested_at")
            .and_then(Value::as_i64)
            .filter(|value| *value >= 0)
            .ok_or(QueueError::Invalid)?;
        let age = now
            .checked_sub(requested)
            .filter(|age| (0..=TTL).contains(age))
            .ok_or(QueueError::Invalid)?;
        let _ = age;
        let action = match object.get("action").and_then(Value::as_str) {
            Some("preview") => Action::Preview,
            Some("manage") => Action::Manage,
            Some("apply") => Action::Apply,
            _ => return Err(QueueError::Invalid),
        };
        let (mut replay, existed) = Replay::load(&self.state, self.legacy.as_deref(), now)?;
        if now < replay.last {
            return Err(QueueError::ClockBackwards);
        }
        replay.entries.retain(|_, expiry| *expiry > now);
        if replay.entries.contains_key(&id) {
            if !existed {
                replay.save(&self.state)?;
            }
            return Ok(None);
        }
        if replay.entries.len() >= MAX_RECORDS {
            return Err(QueueError::Full);
        }
        replay.entries.insert(
            id.clone(),
            requested.checked_add(TTL + 1).ok_or(QueueError::Invalid)?,
        );
        replay.last = now;
        replay.save(&self.state)?;
        Ok(Some(Claimed {
            id,
            action,
            payload,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use xcli_auth_compat::seal_xgb1;

    struct Fixture {
        _dir: tempfile::TempDir,
        inbox: PathBuf,
        state: PathBuf,
        legacy: PathBuf,
        key: [u8; 32],
    }
    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let inbox = dir.path().join("inbox");
            let state = dir.path().join("state");
            let legacy_dir = dir.path().join("legacy");
            for path in [&inbox, &state, &legacy_dir] {
                fs::create_dir(path).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self {
                _dir: dir,
                inbox,
                state,
                legacy: legacy_dir.join("processed.json"),
                key: [42; 32],
            }
        }
        fn queue(&self) -> Queue {
            Queue::open(&self.inbox, &self.state, Some(&self.legacy), self.key).unwrap()
        }
        fn request(&self, value: Value) {
            let plain = Zeroizing::new(serde_json::to_vec(&value).unwrap());
            let encrypted = seal_xgb1(&plain, &self.key, CONTEXT).unwrap();
            fs::write(self.inbox.join("request.xgb"), encrypted).unwrap();
        }
    }
    fn request(id: &str, at: i64) -> Value {
        json!({"id":id,"action":"preview","requested_at":at,"password":"synthetic-only-password"})
    }
    #[test]
    fn authenticated_requests_are_claimed_once_and_never_persist_credentials() {
        let fixture = Fixture::new();
        let first = "a".repeat(32);
        fixture.request(request(&first, 1000));
        let wrong = Queue::open(&fixture.inbox, &fixture.state, None, [7; 32]).unwrap();
        assert!(matches!(wrong.claim(1000), Err(QueueError::Invalid)));
        let queue = fixture.queue();
        let claimed = queue.claim(1000).unwrap().unwrap();
        assert_eq!(claimed.id(), first);
        assert_eq!(claimed.action(), Action::Preview);
        assert_eq!(claimed.payload()["password"], "synthetic-only-password");
        assert!(queue.claim(1000).unwrap().is_none());
        assert!(fixture.queue().claim(1001).unwrap().is_none());
        let state = fs::read_to_string(fixture.state.join("request-replay.json")).unwrap();
        assert!(!state.contains("synthetic-only-password"));
        assert_eq!(
            fs::metadata(fixture.state.join("request-replay.json"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        fixture.request(request(&"b".repeat(32), 998));
        assert!(matches!(queue.claim(999), Err(QueueError::ClockBackwards)));
        assert!(queue.claim(1001).unwrap().is_some());
        fixture.request(request(&"c".repeat(32), 1000));
        assert!(matches!(queue.claim(1901), Err(QueueError::Invalid)));
        assert!(matches!(queue.claim(999), Err(QueueError::Invalid)));
    }
    #[test]
    fn old_replay_ids_are_imported_and_corrupt_state_fails_closed() {
        let fixture = Fixture::new();
        let old = "d".repeat(32);
        fs::write(
            &fixture.legacy,
            serde_json::to_vec(&vec![old.clone()]).unwrap(),
        )
        .unwrap();
        fs::set_permissions(&fixture.legacy, fs::Permissions::from_mode(0o600)).unwrap();
        fixture.request(request(&old, 1000));
        assert!(fixture.queue().claim(1000).unwrap().is_none());
        assert!(fixture.state.join("request-replay.json").exists());
        fs::remove_file(&fixture.legacy).unwrap();
        assert!(fixture.queue().claim(1001).unwrap().is_none());
        fixture.request(request(&old, 1901));
        assert!(fixture.queue().claim(1901).unwrap().is_some());
        fs::write(fixture.state.join("request-replay.json"), "broken").unwrap();
        fixture.request(request(&"e".repeat(32), 1902));
        assert!(matches!(
            fixture.queue().claim(1902),
            Err(QueueError::Invalid)
        ));
    }
    #[test]
    fn concurrent_workers_cannot_claim_the_same_message() {
        let fixture = Fixture::new();
        fixture.request(request(&"f".repeat(32), 1000));
        let queue = fixture.queue();
        let results = std::thread::scope(|scope| {
            let tasks: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| queue.claim(1000).unwrap().is_some()))
                .collect();
            tasks
                .into_iter()
                .map(|task| task.join().unwrap())
                .filter(|claimed| *claimed)
                .count()
        });
        assert_eq!(results, 1);
    }
    #[test]
    fn unsafe_inbox_types_and_tampering_are_rejected() {
        let fixture = Fixture::new();
        let target = fixture._dir.path().join("outside");
        fs::write(&target, b"synthetic").unwrap();
        let inbox = fixture.inbox.join("request.xgb");
        symlink(&target, &inbox).unwrap();
        assert!(matches!(
            fixture.queue().claim(1000),
            Err(QueueError::Unavailable)
        ));
        fs::remove_file(&inbox).unwrap();
        fs::hard_link(&target, &inbox).unwrap();
        assert!(matches!(
            fixture.queue().claim(1000),
            Err(QueueError::Invalid)
        ));
        fs::remove_file(&inbox).unwrap();
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(inbox.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            fixture.queue().claim(1000),
            Err(QueueError::Invalid)
        ));
        fs::remove_file(&inbox).unwrap();
        fixture.request(request(&"a".repeat(32), 1000));
        let mut bytes = fs::read(&inbox).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&inbox, bytes).unwrap();
        assert!(matches!(
            fixture.queue().claim(1000),
            Err(QueueError::Invalid)
        ));
    }
    #[test]
    fn full_replay_guard_refuses_new_requests_without_evicting_live_ids() {
        let fixture = Fixture::new();
        let entries = (0..MAX_RECORDS)
            .map(|number| (format!("{number:032x}"), 1001))
            .collect();
        Replay {
            last: 1000,
            entries,
        }
        .save(&fixture.state)
        .unwrap();
        fixture.request(request(&"a".repeat(32), 1000));
        assert!(matches!(fixture.queue().claim(1000), Err(QueueError::Full)));
    }
}
