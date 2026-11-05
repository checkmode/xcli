//! Experimental SOCKS relay with a fixed provider destination and loopback
//! fixtures. Session management, installation and process ownership are not wired.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{watch, Semaphore};
use tokio::time::timeout;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Session {
    username: Zeroizing<String>,
    pub expires_at: i64,
    pub last_success: i64,
    pub failures: u8,
    pub retry_after: i64,
    pub last_checked: i64,
}
impl Session {
    pub fn new(username: String, expires_at: i64, last_success: i64) -> Self {
        Self {
            username: Zeroizing::new(username),
            expires_at,
            last_success,
            failures: 0,
            retry_after: 0,
            last_checked: 0,
        }
    }
    fn fresh(&self, now: i64) -> bool {
        self.last_success > now.saturating_sub(1_200) && self.expires_at > now && self.failures < 3
    }
}
struct State {
    generation: u64,
    enabled: bool,
    password: Zeroizing<String>,
    sessions: Vec<Session>,
    failovers: u64,
}
struct Shared {
    state: Mutex<State>,
    generation: watch::Sender<u64>,
    limit: Arc<Semaphore>,
    last_used: AtomicI64,
}
#[derive(Clone)]
pub struct Pool(Arc<Shared>);
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidPool;
struct Snapshot {
    generation: u64,
    password: Zeroizing<String>,
    candidates: Vec<Session>,
    changed: watch::Receiver<u64>,
}
fn valid_username(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}
fn valid_password(value: &str) -> bool {
    !value.is_empty() && value.len() <= 255 && !value.chars().any(|c| c.is_control())
}
fn valid_sessions(sessions: &[Session]) -> bool {
    let mut names = std::collections::BTreeSet::new();
    sessions.len() <= 4
        && sessions.iter().all(|session| {
            valid_username(&session.username)
                && names.insert(session.username.as_str())
                && session.expires_at >= 0
                && session.last_success >= 0
                && session.retry_after >= 0
                && session.last_checked >= 0
        })
}
impl Pool {
    /// Share one semaphore between every region to retain the global connection
    /// bound. Creating an enabled pool does not bind or open any socket.
    pub fn new(limit: Arc<Semaphore>) -> Self {
        let (generation, _) = watch::channel(0);
        Self(Arc::new(Shared {
            state: Mutex::new(State {
                generation: 0,
                enabled: false,
                password: Zeroizing::new(String::new()),
                sessions: Vec::new(),
                failovers: 0,
            }),
            generation,
            limit,
            last_used: AtomicI64::new(0),
        }))
    }
    /// A credential or enablement change increments the generation and closes
    /// existing relays. Call only for an actual authorization change; routine
    /// probe updates must not invalidate active sessions.
    pub fn replace(
        &self,
        enabled: bool,
        password: String,
        sessions: Vec<Session>,
    ) -> Result<(), InvalidPool> {
        let password = Zeroizing::new(password);
        if (enabled && !valid_password(&password)) || !valid_sessions(&sessions) {
            return Err(InvalidPool);
        }
        let mut state = self.0.state.lock().map_err(|_| InvalidPool)?;
        let next = state.generation.checked_add(1).ok_or(InvalidPool)?;
        state.enabled = enabled;
        state.password = password;
        state.sessions = sessions;
        state.generation = next;
        self.0.generation.send_replace(next);
        Ok(())
    }
    pub fn generation(&self) -> Result<u64, InvalidPool> {
        self.0
            .state
            .lock()
            .map(|state| state.generation)
            .map_err(|_| InvalidPool)
    }
    /// Atomically reconcile a completed maintenance pass with the current
    /// primary, which may have been promoted by a concurrent connection.
    /// The closure must be in-memory only: it must not block or re-enter Pool.
    pub fn commit_sessions<T, F>(&self, expected: u64, finish: F) -> Result<T, InvalidPool>
    where
        F: FnOnce(Option<&str>) -> Result<(Vec<Session>, T), InvalidPool>,
    {
        let mut state = self.0.state.lock().map_err(|_| InvalidPool)?;
        if !state.enabled || state.generation != expected {
            return Err(InvalidPool);
        }
        let (sessions, result) = finish(
            state
                .sessions
                .first()
                .map(|session| session.username.as_str()),
        )?;
        if !valid_sessions(&sessions) {
            return Err(InvalidPool);
        }
        state.sessions = sessions;
        Ok(result)
    }
    fn snapshot(&self, now: i64) -> Result<Snapshot, ()> {
        let state = self.0.state.lock().map_err(|_| ())?;
        if !state.enabled || !valid_password(&state.password) {
            return Err(());
        }
        let mut candidates: Vec<_> = state
            .sessions
            .iter()
            .filter(|session| session.fresh(now))
            .cloned()
            .collect();
        candidates.sort_by_key(|session| session.retry_after > now);
        if candidates.is_empty() {
            return Err(());
        }
        Ok(Snapshot {
            generation: state.generation,
            password: state.password.clone(),
            candidates,
            changed: self.0.generation.subscribe(),
        })
    }
    fn current(&self, generation: u64) -> bool {
        self.0
            .state
            .lock()
            .is_ok_and(|state| state.enabled && state.generation == generation)
    }
    fn failed(&self, generation: u64, username: &str, now: i64) {
        if let Ok(mut state) = self.0.state.lock() {
            if state.generation != generation {
                return;
            }
            if let Some(session) = state
                .sessions
                .iter_mut()
                .find(|session| session.username.as_str() == username)
            {
                session.retry_after = now.saturating_add(30);
                session.last_checked = 0;
            }
        }
    }
    fn promote(&self, generation: u64, username: &str, failed: &[Zeroizing<String>]) {
        if let Ok(mut state) = self.0.state.lock() {
            if state.generation != generation
                || state.sessions.first().is_none_or(|session| {
                    !failed
                        .iter()
                        .any(|name| name.as_str() == session.username.as_str())
                })
            {
                return;
            }
            if let Some(index) = state
                .sessions
                .iter()
                .position(|session| session.username.as_str() == username)
            {
                let mut selected = state.sessions.remove(index);
                selected.retry_after = 0;
                state.sessions.insert(0, selected);
                state.failovers = state.failovers.saturating_add(1);
            }
        }
    }
    pub fn failovers(&self) -> u64 {
        self.0.state.lock().map_or(0, |state| state.failovers)
    }
    pub fn primary_name(&self) -> Option<Zeroizing<String>> {
        self.0.state.lock().ok().and_then(|state| {
            state
                .sessions
                .first()
                .map(|session| session.username.clone())
        })
    }
    pub fn last_used(&self) -> i64 {
        self.0.last_used.load(Ordering::Relaxed)
    }
}
fn epoch() -> Result<i64, ()> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ())?
            .as_secs(),
    )
    .map_err(|_| ())
}
fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || a == 100 && (64..=127).contains(&b)
        || a == 169 && b == 254
        || a == 172 && (16..=31).contains(&b)
        || a == 192 && (b == 168 || b == 0 && (c == 0 || c == 2) || b == 88 && c == 99)
        || a == 198 && (b == 18 || b == 19 || b == 51 && c == 100)
        || a == 203 && b == 0 && c == 113)
}
fn public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return public_v4(v4);
    }
    let octets = ip.octets();
    if octets[0] & 0xe0 != 0x20 {
        return false;
    }
    let segments = ip.segments();
    !(segments[0] == 0x2001 && (segments[1] < 0x0200 || segments[1] == 0x0db8)
        || segments[0] == 0x2002)
}
pub(crate) fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => public_v4(ip),
        IpAddr::V6(ip) => public_v6(ip),
    }
}
fn valid_domain(raw: &[u8]) -> bool {
    if raw.is_empty()
        || !raw
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(byte))
    {
        return false;
    }
    let Ok(name) = std::str::from_utf8(raw) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    if lower == "localhost"
        || lower.ends_with(".localhost")
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
    {
        return false;
    }
    if name
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return name.parse::<IpAddr>().is_ok_and(public_ip);
    }
    name.parse::<IpAddr>().map_or(true, public_ip)
}
struct Destination {
    kind: u8,
    address: Vec<u8>,
    port: [u8; 2],
}
enum Handshake {
    Replied,
    Failed,
}
async fn read_destination(client: &mut TcpStream) -> Result<Destination, Handshake> {
    let mut hello = [0u8; 2];
    client
        .read_exact(&mut hello)
        .await
        .map_err(|_| Handshake::Failed)?;
    let mut methods = vec![0u8; usize::from(hello[1])];
    client
        .read_exact(&mut methods)
        .await
        .map_err(|_| Handshake::Failed)?;
    if hello[0] != 5 || !methods.contains(&0) {
        let _ = client.write_all(&[5, 255]).await;
        return Err(Handshake::Replied);
    }
    client
        .write_all(&[5, 0])
        .await
        .map_err(|_| Handshake::Failed)?;
    let mut header = [0u8; 4];
    client
        .read_exact(&mut header)
        .await
        .map_err(|_| Handshake::Failed)?;
    if header[0] != 5 || header[1] != 1 || header[2] != 0 {
        let _ = client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        return Err(Handshake::Replied);
    }
    let address = match header[3] {
        1 => {
            let mut bytes = [0u8; 4];
            client
                .read_exact(&mut bytes)
                .await
                .map_err(|_| Handshake::Failed)?;
            if !public_v4(Ipv4Addr::from(bytes)) {
                return Err(Handshake::Failed);
            }
            bytes.to_vec()
        }
        4 => {
            let mut bytes = [0u8; 16];
            client
                .read_exact(&mut bytes)
                .await
                .map_err(|_| Handshake::Failed)?;
            if !public_v6(Ipv6Addr::from(bytes)) {
                return Err(Handshake::Failed);
            }
            bytes.to_vec()
        }
        3 => {
            let length = client.read_u8().await.map_err(|_| Handshake::Failed)?;
            let mut name = vec![0u8; usize::from(length)];
            client
                .read_exact(&mut name)
                .await
                .map_err(|_| Handshake::Failed)?;
            if !valid_domain(&name) {
                return Err(Handshake::Failed);
            }
            let mut address = vec![length];
            address.extend_from_slice(&name);
            address
        }
        _ => return Err(Handshake::Failed),
    };
    let mut port = [0u8; 2];
    client
        .read_exact(&mut port)
        .await
        .map_err(|_| Handshake::Failed)?;
    if port == [0, 0] {
        return Err(Handshake::Failed);
    }
    Ok(Destination {
        kind: header[3],
        address,
        port,
    })
}
#[derive(Clone, Copy)]
enum Endpoint {
    Fixture(SocketAddr),
    Webshare,
}
async fn connect_endpoint(endpoint: Endpoint) -> Result<TcpStream, ()> {
    match endpoint {
        Endpoint::Fixture(address) => TcpStream::connect(address).await.map_err(|_| ()),
        Endpoint::Webshare => {
            let resolved = tokio::net::lookup_host(("p.webshare.io", 80))
                .await
                .map_err(|_| ())?;
            for address in resolved
                .filter(|address| matches!(address.ip(),IpAddr::V4(ip) if public_v4(ip)))
                .take(8)
            {
                if let Ok(stream) = TcpStream::connect(address).await {
                    return Ok(stream);
                }
            }
            Err(())
        }
    }
}
async fn upstream(
    endpoint: Endpoint,
    session: &Session,
    password: &str,
    dest: &Destination,
) -> Result<TcpStream, ()> {
    let mut stream = connect_endpoint(endpoint).await?;
    stream.write_all(&[5, 1, 2]).await.map_err(|_| ())?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.map_err(|_| ())?;
    if reply != [5, 2] {
        return Err(());
    }
    let mut auth = Zeroizing::new(Vec::with_capacity(
        session.username.len() + password.len() + 3,
    ));
    auth.extend_from_slice(&[1, session.username.len() as u8]);
    auth.extend_from_slice(session.username.as_bytes());
    auth.push(password.len() as u8);
    auth.extend_from_slice(password.as_bytes());
    stream.write_all(&auth).await.map_err(|_| ())?;
    stream.read_exact(&mut reply).await.map_err(|_| ())?;
    if reply != [1, 0] {
        return Err(());
    }
    stream
        .write_all(&[5, 1, 0, dest.kind])
        .await
        .map_err(|_| ())?;
    stream.write_all(&dest.address).await.map_err(|_| ())?;
    stream.write_all(&dest.port).await.map_err(|_| ())?;
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.map_err(|_| ())?;
    if header[0] != 5 || header[1] != 0 || header[2] != 0 {
        return Err(());
    }
    let remaining = match header[3] {
        1 => 6,
        4 => 18,
        3 => usize::from(stream.read_u8().await.map_err(|_| ())?) + 2,
        _ => return Err(()),
    };
    let mut ignored = vec![0u8; remaining];
    stream.read_exact(&mut ignored).await.map_err(|_| ())?;
    Ok(stream)
}
async fn transfer<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
) -> Result<(), ()> {
    let mut data = Zeroizing::new(vec![0u8; 65536]);
    loop {
        let count = timeout(Duration::from_secs(600), reader.read(&mut data))
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
        if count == 0 {
            writer.shutdown().await.map_err(|_| ())?;
            return Ok(());
        }
        timeout(Duration::from_secs(600), writer.write_all(&data[..count]))
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
    }
}
async fn wait_revocation(changed: &mut watch::Receiver<u64>, generation: u64) {
    loop {
        if *changed.borrow() != generation {
            break;
        }
        if changed.changed().await.is_err() {
            break;
        }
    }
}

/// Handles one connection using the fixed Webshare SOCKS endpoint. A caller
/// must bind its listener to loopback and own the pool's enablement lifecycle.
pub async fn handle_webshare(client: TcpStream, pool: Pool) {
    handle(client, pool, Endpoint::Webshare).await;
}

/// The injected endpoint is restricted to loopback for isolated tests.
pub async fn handle_fixture(client: TcpStream, pool: Pool, endpoint: SocketAddr) {
    if endpoint.ip().is_loopback() {
        handle(client, pool, Endpoint::Fixture(endpoint)).await;
    }
}
async fn handle(mut client: TcpStream, pool: Pool, endpoint: Endpoint) {
    let Ok(_permit) = pool.0.limit.clone().try_acquire_owned() else {
        return;
    };
    let destination = match timeout(Duration::from_secs(12), read_destination(&mut client)).await {
        Ok(Ok(value)) => value,
        Ok(Err(Handshake::Replied)) => return,
        _ => {
            let _ = client.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            return;
        }
    };
    let Ok(now) = epoch() else {
        return;
    };
    pool.0.last_used.store(now, Ordering::Relaxed);
    let Ok(mut snapshot) = pool.snapshot(now) else {
        let _ = client.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        return;
    };
    let mut failed = Vec::new();
    let mut connected = None;
    for session in snapshot.candidates.iter().take(3) {
        if !pool.current(snapshot.generation) {
            break;
        }
        let result = tokio::select! {
            value=timeout(Duration::from_secs(6),upstream(endpoint,session,&snapshot.password,&destination))=>Some(value),
            _=wait_revocation(&mut snapshot.changed,snapshot.generation)=>None,
        };
        let Some(result) = result else {
            break;
        };
        match result {
            Ok(Ok(stream)) if pool.current(snapshot.generation) => {
                if !failed.is_empty() {
                    pool.promote(snapshot.generation, &session.username, &failed);
                }
                connected = Some(stream);
                break;
            }
            _ => {
                pool.failed(
                    snapshot.generation,
                    &session.username,
                    epoch().unwrap_or(now),
                );
                failed.push(session.username.clone());
            }
        }
    }
    let Some(mut upstream) = connected else {
        let _ = client.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        return;
    };
    if !pool.current(snapshot.generation)
        || client
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .is_err()
    {
        return;
    }
    let (mut client_read, mut client_write) = client.split();
    let (mut server_read, mut server_write) = upstream.split();
    let copy = async {
        let _ = tokio::try_join!(
            transfer(&mut client_read, &mut server_write),
            transfer(&mut server_read, &mut client_write)
        );
    };
    tokio::select! { _=timeout(Duration::from_secs(86_400),copy)=>{}, _=wait_revocation(&mut snapshot.changed,snapshot.generation)=>{} }
}
