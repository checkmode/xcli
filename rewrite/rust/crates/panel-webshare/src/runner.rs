//! Experimental orchestration for loopback residential SOCKS listeners.
//! It has no production installer or complete operational acceptance.
use crate::coordinator::{Coordinator, CoreError, ReportInfo, SyncEffect, SyncJob};
use crate::probe::{ProbeError, ProbeResult};
use crate::provider::{Endpoint, Provider, ProviderError, ProviderResponse};
use crate::relay::{handle_fixture, handle_webshare, Pool};
use crate::sync::{Decision, SyncError};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::{watch, Notify, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{interval, timeout};

#[derive(Debug, PartialEq, Eq)]
pub enum RunError {
    InvalidFixture,
    State,
    Listener,
    Task,
}
pub trait Prober: Send + Sync {
    fn check(
        &self,
        username: &str,
        password: &str,
        country: &str,
    ) -> Result<ProbeResult, ProbeError>;
}
pub struct WebshareProber;
impl Prober for WebshareProber {
    fn check(
        &self,
        username: &str,
        password: &str,
        country: &str,
    ) -> Result<ProbeResult, ProbeError> {
        crate::probe::probe(username, password, country)
    }
}
#[derive(Clone, Copy)]
enum Upstream {
    Webshare,
    Fixture(SocketAddr),
}
pub struct FixtureOptions {
    pub control_interval: Duration,
    pub maintenance_interval: Duration,
}
impl Default for FixtureOptions {
    fn default() -> Self {
        Self {
            control_interval: Duration::from_secs(3),
            maintenance_interval: Duration::from_secs(20),
        }
    }
}
type Shared = Arc<Mutex<Coordinator>>;
type SharedProvider = Arc<dyn Provider + Send + Sync>;
type SharedProber = Arc<dyn Prober>;
struct RegionRuntime {
    prober: SharedProber,
    limit: Arc<Semaphore>,
    cancel: Arc<AtomicBool>,
}
fn stamp() -> Result<i64, RunError> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RunError::State)?
            .as_secs(),
    )
    .map_err(|_| RunError::State)
}
async fn state<T, F>(core: Shared, action: F) -> Result<T, RunError>
where
    T: Send + 'static,
    F: FnOnce(&mut Coordinator) -> Result<T, CoreError> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut core = core.lock().map_err(|_| CoreError::InvalidState)?;
        action(&mut core)
    })
    .await
    .map_err(|_| RunError::Task)?
    .map_err(|_| RunError::State)
}
async fn stopped(stop: &mut watch::Receiver<bool>) {
    loop {
        if *stop.borrow() {
            break;
        }
        if stop.changed().await.is_err() {
            break;
        }
    }
}
struct Cancellable {
    provider: SharedProvider,
    cancel: Arc<AtomicBool>,
}
impl Provider for Cancellable {
    fn fetch(
        &self,
        key: &str,
        endpoint: Endpoint,
        parameters: &[(&str, &str)],
    ) -> Result<ProviderResponse, ProviderError> {
        if self.cancel.load(Ordering::SeqCst) {
            return Err(ProviderError::Unavailable);
        }
        let response = self.provider.fetch(key, endpoint, parameters)?;
        if self.cancel.load(Ordering::SeqCst) {
            return Err(ProviderError::Unavailable);
        }
        Ok(response)
    }
}
type SyncTask = JoinHandle<(SyncJob, Result<Decision, SyncError>)>;
type UsageTask = JoinHandle<(SyncJob, Result<serde_json::Value, ProviderError>)>;
fn sync_message(error: &SyncError) -> (&'static str, i64) {
    match error {
        SyncError::Provider(ProviderError::Unauthorized) => {
            ("API Key 无效或没有访问此套餐的权限", 300)
        }
        SyncError::Provider(ProviderError::RateLimited) => ("Webshare 请求限流，稍后自动重试", 90),
        _ => ("Webshare 暂时不可用，稍后自动重试", 60),
    }
}
async fn control_loop(
    core: Shared,
    provider: SharedProvider,
    notifiers: Vec<Arc<Notify>>,
    cancel: Arc<AtomicBool>,
    mut stop: watch::Receiver<bool>,
    period: Duration,
) -> Result<(), RunError> {
    let mut tick = interval(period);
    let mut task: Option<SyncTask> = None;
    let mut usage_task: Option<UsageTask> = None;
    let mut usage_due = false;
    let mut info = ReportInfo::default();
    let mut report_failed = false;
    loop {
        tokio::select! {_=stopped(&mut stop)=>break,_=tick.tick()=>{}}
        let now = stamp()?;
        if report_failed {
            let copy = info.clone();
            if state(core.clone(), move |value| value.report(now, &copy))
                .await
                .is_err()
            {
                continue;
            }
            report_failed = false;
        }
        let refreshed = state(core.clone(), move |value| {
            let before = value.desired_revision().map(str::to_owned);
            let result = value.refresh(now);
            let after = value.desired_revision().map(str::to_owned);
            match result {
                Err(CoreError::Pool) => Err(CoreError::Pool),
                _ => Ok((result.is_ok(), before != after)),
            }
        })
        .await?;
        if refreshed.1 {
            info.usage = serde_json::Value::Null;
            info.usage_error = "";
            usage_due = false;
            for notifier in &notifiers {
                notifier.notify_one();
            }
        }
        if !refreshed.0 {
            info.sync_error = "无法读取池配置，请重新保存设置";
        }
        if task.as_ref().is_some_and(JoinHandle::is_finished) {
            let Some(finished) = task.take() else {
                return Err(RunError::Task);
            };
            let (job, result) = finished.await.map_err(|_| RunError::Task)?;
            match result {
                Ok(decision) => {
                    let failed_job = job.clone();
                    let effect = state(core.clone(), move |value| {
                        Ok(value.commit_sync(&job, decision, now))
                    })
                    .await?;
                    match effect {
                        Ok(SyncEffect::Applied) => {
                            info.last_sync = now;
                            info.next_sync = now.saturating_add(300);
                            info.sync_error = "";
                            usage_due = true;
                            for notifier in &notifiers {
                                notifier.notify_one();
                            }
                        }
                        Ok(SyncEffect::InvalidPlan) => {
                            info.next_sync = now.saturating_add(60);
                            info.sync_error = "所选套餐不是有效的动态住宅套餐";
                        }
                        Ok(SyncEffect::Stale) => (),
                        Err(CoreError::Pool | CoreError::InvalidState | CoreError::Entropy) => {
                            return Err(RunError::State);
                        }
                        Err(CoreError::Storage) => {
                            if state(core.clone(), move |value| value.failed_sync(&failed_job))
                                .await
                                .unwrap_or(false)
                            {
                                info.next_sync = now.saturating_add(60);
                                info.sync_error = "保存池状态失败，稍后重试";
                            }
                        }
                    }
                }
                Err(error) => {
                    let (message, retry) = sync_message(&error);
                    if state(core.clone(), move |value| value.failed_sync(&job))
                        .await
                        .unwrap_or(false)
                    {
                        info.next_sync = now.saturating_add(retry);
                        info.sync_error = message;
                    }
                }
            }
        }
        if usage_task.as_ref().is_some_and(JoinHandle::is_finished) {
            let Some(finished) = usage_task.take() else {
                return Err(RunError::Task);
            };
            let (job, result) = finished.await.map_err(|_| RunError::Task)?;
            if state(core.clone(), move |value| value.current_job(&job)).await? {
                match result {
                    Ok(usage) => {
                        info.usage = usage;
                        info.usage_error = "";
                    }
                    Err(_) => info.usage_error = "暂时无法读取 Webshare 用量",
                }
            }
        }
        if refreshed.0 && usage_due && usage_task.is_none() {
            usage_due = false;
            if let Some(job) = state(core.clone(), |value| Ok(value.sync_job())).await? {
                if job.wants_usage() {
                    let provider = Cancellable {
                        provider: provider.clone(),
                        cancel: cancel.clone(),
                    };
                    usage_task = Some(tokio::task::spawn_blocking(move || {
                        let result = job.run_usage(&provider, now);
                        (job, result)
                    }));
                }
            }
        }
        let copy = info.clone();
        if state(core.clone(), move |value| value.report(now, &copy))
            .await
            .is_err()
        {
            let _ = state(core.clone(), |value| value.shutdown()).await;
            report_failed = true;
            continue;
        }
        if refreshed.0 && task.is_none() {
            let next = info.next_sync;
            let job = state(core.clone(), move |value| {
                Ok(if value.needs_sync(now, next) {
                    value.sync_job()
                } else {
                    None
                })
            })
            .await?;
            if let Some(job) = job {
                info.last_attempt = now;
                let provider = Cancellable {
                    provider: provider.clone(),
                    cancel: cancel.clone(),
                };
                task = Some(tokio::task::spawn_blocking(move || {
                    let result = job.run(&provider);
                    (job, result)
                }));
            }
        }
    }
    if let Some(task) = task {
        let _ = timeout(Duration::from_secs(15), task).await;
    }
    if let Some(task) = usage_task {
        let _ = timeout(Duration::from_secs(15), task).await;
    }
    Ok(())
}
async fn region_loop(
    core: Shared,
    country: String,
    runtime: RegionRuntime,
    notify: Arc<Notify>,
    mut stop: watch::Receiver<bool>,
    period: Duration,
) -> Result<(), RunError> {
    let mut tick = interval(period);
    loop {
        tokio::select! {_=stopped(&mut stop)=>break,_=tick.tick()=>{},_=notify.notified()=>{}}
        let name = country.clone();
        let job = state(core.clone(), move |value| Ok(value.begin_region(&name))).await?;
        let Some(job) = job else {
            continue;
        };
        let permit = tokio::select! {_=stopped(&mut stop)=>break,value=runtime.limit.clone().acquire_owned()=>value.map_err(|_|RunError::Task)?};
        let prober = runtime.prober.clone();
        let cancel_probe = runtime.cancel.clone();
        let now = stamp()?;
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            job.run(now, |username, password, country| {
                if cancel_probe.load(Ordering::SeqCst) {
                    return Err(ProbeError::Unavailable);
                }
                prober.check(username, password, country)
            })
        });
        let result = tokio::select! {_=stopped(&mut stop)=>break,value=task=>value.map_err(|_|RunError::Task)?};
        let completion = result.map_err(|_| RunError::State)?;
        if !runtime.cancel.load(Ordering::SeqCst) {
            state(core.clone(), move |value| {
                value.commit_region(completion, now)
            })
            .await?;
        }
    }
    Ok(())
}
async fn accept_loop(
    listener: TcpListener,
    pool: Pool,
    upstream: Upstream,
    mut stop: watch::Receiver<bool>,
) -> Result<(), RunError> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _=stopped(&mut stop)=>break,
            accepted=listener.accept()=>{
                let (client,peer)=accepted.map_err(|_|RunError::Listener)?;
                if peer.ip().is_loopback() {
                    match upstream {
                        Upstream::Webshare => {connections.spawn(handle_webshare(client,pool.clone()));}
                        Upstream::Fixture(address) => {connections.spawn(handle_fixture(client,pool.clone(),address));}
                    }
                }
            },
            Some(_)=connections.join_next(),if !connections.is_empty()=>{},
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

/// Runs with loopback listeners and a loopback fake upstream. The injected
/// provider and prober must themselves be synthetic when used for testing.
pub async fn run_fixture(
    core: Shared,
    provider: SharedProvider,
    prober: SharedProber,
    listeners: BTreeMap<String, TcpListener>,
    upstream: SocketAddr,
    external_stop: watch::Receiver<bool>,
    options: FixtureOptions,
) -> Result<(), RunError> {
    run(
        core,
        provider,
        prober,
        listeners,
        Upstream::Fixture(upstream),
        external_stop,
        options,
    )
    .await
}
/// Experimental fixed-provider runner. The caller must hold a worker lease,
/// stop the legacy worker first, and bind only the intended loopback ports.
pub async fn run_webshare(
    core: Shared,
    provider: SharedProvider,
    listeners: BTreeMap<String, TcpListener>,
    external_stop: watch::Receiver<bool>,
) -> Result<(), RunError> {
    run(
        core,
        provider,
        Arc::new(WebshareProber),
        listeners,
        Upstream::Webshare,
        external_stop,
        FixtureOptions::default(),
    )
    .await
}
async fn run(
    core: Shared,
    provider: SharedProvider,
    prober: SharedProber,
    listeners: BTreeMap<String, TcpListener>,
    upstream: Upstream,
    mut external_stop: watch::Receiver<bool>,
    options: FixtureOptions,
) -> Result<(), RunError> {
    if matches!(upstream, Upstream::Fixture(address) if !address.ip().is_loopback())
        || listeners.is_empty()
        || options.control_interval < Duration::from_millis(10)
        || options.maintenance_interval < Duration::from_millis(10)
    {
        return Err(RunError::InvalidFixture);
    }
    let mut pools = BTreeMap::new();
    for (country, listener) in &listeners {
        if !listener
            .local_addr()
            .map_err(|_| RunError::Listener)?
            .ip()
            .is_loopback()
        {
            return Err(RunError::InvalidFixture);
        }
        let name = country.clone();
        let pool = state(core.clone(), move |value| {
            value.pool(&name).ok_or(CoreError::InvalidState)
        })
        .await?;
        pools.insert(country.clone(), pool);
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let (stop_tx, stop_rx) = watch::channel(false);
    let limiter = Arc::new(Semaphore::new(4));
    let mut tasks = JoinSet::new();
    let mut notifiers = Vec::new();
    for (country, listener) in listeners {
        let pool = pools.remove(&country).ok_or(RunError::InvalidFixture)?;
        let notify = Arc::new(Notify::new());
        notifiers.push(notify.clone());
        tasks.spawn(accept_loop(listener, pool, upstream, stop_rx.clone()));
        tasks.spawn(region_loop(
            core.clone(),
            country,
            RegionRuntime {
                prober: prober.clone(),
                limit: limiter.clone(),
                cancel: cancel.clone(),
            },
            notify,
            stop_rx.clone(),
            options.maintenance_interval,
        ));
    }
    tasks.spawn(control_loop(
        core.clone(),
        provider,
        notifiers,
        cancel.clone(),
        stop_rx,
        options.control_interval,
    ));
    let result = tokio::select! {
        _=stopped(&mut external_stop)=>Ok(()),
        result=tasks.join_next()=>match result {Some(Ok(Err(error)))=>Err(error),_=>Err(RunError::Task)},
    };
    cancel.store(true, Ordering::SeqCst);
    let _ = state(core, |value| value.shutdown()).await;
    let _ = stop_tx.send(true);
    if timeout(Duration::from_secs(30), async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ActiveSnapshot, Control};
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct FakeProvider;
    impl Provider for FakeProvider {
        fn fetch(
            &self,
            _key: &str,
            endpoint: Endpoint,
            parameters: &[(&str, &str)],
        ) -> Result<ProviderResponse, ProviderError> {
            Ok(match endpoint {
                Endpoint::Plans => ProviderResponse::fixture(
                    json!({"results":[{"id":17,"status":"active","pool_filter":"residential"}],"next":null}),
                ),
                Endpoint::Proxies => ProviderResponse::fixture(
                    json!({"results":[{"username":"fixture-123","password":"synthetic-password"}]}),
                ),
                Endpoint::Usage => {
                    assert!(parameters.contains(&("plan_id", "17")));
                    assert!(parameters
                        .iter()
                        .any(|(key, value)| *key == "timestamp__gte" && value.ends_with("+00:00")));
                    assert!(parameters
                        .iter()
                        .any(|(key, value)| *key == "timestamp__lte" && value.ends_with("+00:00")));
                    ProviderResponse::fixture(json!({"bandwidth_total":123,"requests_total":4,
                        "requests_failed":-1,"secret":"synthetic-password"}))
                }
                _ => return Err(ProviderError::InvalidRequest),
            })
        }
    }
    struct FakeProber {
        slow_us: Option<Arc<AtomicBool>>,
    }
    impl Prober for FakeProber {
        fn check(
            &self,
            _username: &str,
            _password: &str,
            country: &str,
        ) -> Result<ProbeResult, ProbeError> {
            if country == "US" {
                if let Some(gate) = &self.slow_us {
                    let deadline = std::time::Instant::now() + Duration::from_secs(5);
                    while !gate.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
            Ok(ProbeResult {
                exit_ip: if country == "JP" {
                    "8.8.4.1"
                } else {
                    "8.8.8.1"
                }
                .parse()
                .unwrap(),
                exit_country: country.to_owned(),
                https_ms: 10,
                doh_ms: 10,
                last_success: stamp().unwrap(),
            })
        }
    }
    fn setup(
        root: &std::path::Path,
        countries: &[&str],
        now: i64,
        with_session: bool,
    ) -> (Arc<Control>, Shared) {
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
        let mut pools = json!({});
        for country in countries {
            pools[*country] = json!([]);
        }
        if with_session {
            pools["US"] = json!([{"username":"fixture-us-1","expires_at":now+1800,"exit_ip":"8.8.8.1","exit_country":"US","last_success":now,"last_checked":now}]);
        }
        let active=ActiveSnapshot::from_value(json!({"active":{"enabled":true,"plan_id":17,"api_key":"synthetic-api-key-for-test",
            "credentials":{"base":"fixture","password":"synthetic-password"}},"processed_revision":"old","plans":[],"pools":pools}),countries,now).unwrap();
        control.save_active(&active).unwrap();
        let coordinator = Coordinator::open(control.clone(), countries, now).unwrap();
        (control, Arc::new(Mutex::new(coordinator)))
    }
    async fn fake_upstream(mut stream: tokio::net::TcpStream) {
        let mut hello = [0u8; 3];
        if stream.read_exact(&mut hello).await.is_err() {
            return;
        }
        assert_eq!(hello, [5, 1, 2]);
        stream.write_all(&[5, 2]).await.unwrap();
        let mut head = [0u8; 2];
        stream.read_exact(&mut head).await.unwrap();
        let mut username = vec![0u8; head[1] as usize];
        stream.read_exact(&mut username).await.unwrap();
        let n = stream.read_u8().await.unwrap();
        let mut password = vec![0u8; n as usize];
        stream.read_exact(&mut password).await.unwrap();
        assert_eq!(password, b"synthetic-password");
        stream.write_all(&[1, 0]).await.unwrap();
        let mut request = [0u8; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [5, 1, 0, 3]);
        let n = stream.read_u8().await.unwrap();
        let mut address = vec![0u8; n as usize + 2];
        stream.read_exact(&mut address).await.unwrap();
        stream
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut bytes = [0u8; 128];
        loop {
            match stream.read(&mut bytes).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stream.write_all(&bytes[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
    async fn wait_report(path: &std::path::Path, predicate: impl Fn(&Value) -> bool) {
        timeout(Duration::from_secs(4), async {
            loop {
                if let Ok(bytes) = std::fs::read(path) {
                    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                        if predicate(&value) {
                            break;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("isolated report did not become ready");
    }
    async fn connect_fixture(address: SocketAddr) -> tokio::net::TcpStream {
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut greeting = [0u8; 2];
        timeout(Duration::from_secs(2), client.read_exact(&mut greeting))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(greeting, [5, 0]);
        let mut request = vec![5, 1, 0, 3, 11];
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        timeout(Duration::from_secs(2), client.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply[1], 0);
        client
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn fixture_runner_relays_then_revokes_and_shuts_down() {
        let dir = tempfile::tempdir().unwrap();
        let now = stamp().unwrap();
        let (control, core) = setup(dir.path(), &["US"], now, true);
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let fake = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = upstream.accept().await else {
                    break;
                };
                tokio::spawn(fake_upstream(stream));
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop_tx, stop_rx) = watch::channel(false);
        let runner = tokio::spawn(run_fixture(
            core.clone(),
            Arc::new(FakeProvider),
            Arc::new(FakeProber { slow_us: None }),
            BTreeMap::from([("US".into(), listener)]),
            upstream_addr,
            stop_rx,
            FixtureOptions {
                control_interval: Duration::from_millis(40),
                maintenance_interval: Duration::from_millis(80),
            },
        ));
        wait_report(&dir.path().join("webshare/report.json"), |value| {
            value["status"] == "healthy" && value["bandwidth_total"] == 123
        })
        .await;
        let mut client = connect_fixture(address).await;
        client.write_all(b"fixture").await.unwrap();
        let mut echoed = [0u8; 7];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"fixture");
        let report_path = dir.path().join("webshare/report.json");
        {
            let _guard = core.lock().unwrap();
            std::fs::remove_file(&report_path).unwrap();
            std::fs::create_dir(&report_path).unwrap();
        }
        let mut byte = [0u8; 1];
        assert_eq!(
            timeout(Duration::from_secs(3), client.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        std::fs::remove_dir(&report_path).unwrap();
        wait_report(&report_path, |value| value["status"] == "healthy").await;
        let mut client = connect_fixture(address).await;
        control
            .configure(&json!({"clear_key":true}), stamp().unwrap())
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(3), client.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        stop_tx.send(true).unwrap();
        timeout(Duration::from_secs(3), runner)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
        fake.abort();
        let report = std::fs::read_to_string(dir.path().join("webshare/report.json")).unwrap();
        assert!(!report.contains("synthetic-password"));
        assert!(!report.contains("synthetic-api-key-for-test"));
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slow_region_does_not_block_another_region() {
        let dir = tempfile::tempdir().unwrap();
        let now = stamp().unwrap();
        let (_control, core) = setup(dir.path(), &["US", "JP"], now, false);
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let us = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let jp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (stop_tx, stop_rx) = watch::channel(false);
        let release = Arc::new(AtomicBool::new(false));
        let runner = tokio::spawn(run_fixture(
            core,
            Arc::new(FakeProvider),
            Arc::new(FakeProber {
                slow_us: Some(release.clone()),
            }),
            BTreeMap::from([("US".into(), us), ("JP".into(), jp)]),
            upstream_addr,
            stop_rx,
            FixtureOptions {
                control_interval: Duration::from_millis(30),
                maintenance_interval: Duration::from_millis(80),
            },
        ));
        timeout(
            Duration::from_secs(3),
            wait_report(&dir.path().join("webshare/report.json"), |value| {
                value["pools"].as_array().is_some_and(|pools| {
                    pools
                        .iter()
                        .any(|p| p["country"] == "JP" && p["status"] == "healthy")
                        && pools
                            .iter()
                            .any(|p| p["country"] == "US" && p["status"] == "unavailable")
                })
            }),
        )
        .await
        .expect("one slow country blocked the other");
        release.store(true, Ordering::SeqCst);
        stop_tx.send(true).unwrap();
        timeout(Duration::from_secs(3), runner)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
