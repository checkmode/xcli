//! Experimental residential worker. Do not install or run alongside the
//! legacy worker; production migration and full acceptance remain incomplete.
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use xcli_panel_webshare::coordinator::Coordinator;
use xcli_panel_webshare::provider::ProviderClient;
use xcli_panel_webshare::runner::run_webshare;
use xcli_panel_webshare::{Control, REGIONS};
use zeroize::Zeroizing;

struct Args {
    state: PathBuf,
    settings: PathBuf,
    key: PathBuf,
}
fn arguments() -> Result<Args, ()> {
    let mut input = std::env::args().skip(1);
    if input.next().as_deref() != Some("--experimental") {
        return Err(());
    }
    let (mut state, mut settings, mut key) = (None, None, None);
    while let Some(name) = input.next() {
        let value = PathBuf::from(input.next().ok_or(())?);
        let target = match name.as_str() {
            "--state" => &mut state,
            "--settings" => &mut settings,
            "--secret-key" => &mut key,
            _ => return Err(()),
        };
        if target.replace(value).is_some() {
            return Err(());
        }
    }
    Ok(Args {
        state: state.ok_or(())?,
        settings: settings.ok_or(())?,
        key: key.ok_or(())?,
    })
}
fn read_key(path: &Path) -> Result<Zeroizing<[u8; 32]>, ()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file() || metadata.len() != 32 || metadata.mode() & 0o007 != 0 {
        return Err(());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    file.read_exact(key.as_mut()).map_err(|_| ())?;
    Ok(key)
}
fn read_settings(path: &Path) -> Result<Value, ()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(());
    }
    let mut data = Zeroizing::new(Vec::new());
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut data)
        .map_err(|_| ())?;
    if data.len() > 1024 * 1024 {
        return Err(());
    }
    serde_json::from_slice(&data).map_err(|_| ())
}
fn installed(settings: &Value) -> Result<Vec<&'static str>, ()> {
    let exits = settings
        .get("residential_exits")
        .and_then(Value::as_array)
        .ok_or(())?;
    let mut countries = BTreeSet::new();
    for exit in exits {
        if exit.get("dynamic").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let country = exit.get("country").and_then(Value::as_str).ok_or(())?;
        let region = REGIONS.iter().find(|r| r.country == country).ok_or(())?;
        if exit.get("tag").and_then(Value::as_str) != Some(region.tag)
            || exit.get("port").and_then(Value::as_u64) != Some(u64::from(region.port))
            || !countries.insert(region.country)
        {
            return Err(());
        }
    }
    if countries.is_empty() {
        return Err(());
    }
    Ok(countries.into_iter().collect())
}
async fn serve(
    coordinator: Coordinator,
    countries: Vec<&'static str>,
    provider: Arc<ProviderClient>,
) -> Result<(), ()> {
    let mut listeners = BTreeMap::new();
    for country in countries {
        let region = REGIONS.iter().find(|r| r.country == country).ok_or(())?;
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, region.socks_port));
        let listener = TcpListener::bind(address).await.map_err(|_| ())?;
        listeners.insert(country.to_owned(), listener);
    }
    let mut terminate = signal(SignalKind::terminate()).map_err(|_| ())?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| ())?;
    let (stop, receiver) = watch::channel(false);
    let worker = run_webshare(
        Arc::new(Mutex::new(coordinator)),
        provider,
        listeners,
        receiver,
    );
    tokio::pin!(worker);
    tokio::select! {
        result = &mut worker => result.map_err(|_| ()),
        _ = terminate.recv() => {let _ = stop.send(true); worker.await.map_err(|_| ())},
        _ = interrupt.recv() => {let _ = stop.send(true); worker.await.map_err(|_| ())},
    }
}
fn run() -> Result<(), ()> {
    let args = arguments()?;
    let settings = read_settings(&args.settings)?;
    let countries = installed(&settings)?;
    let key = read_key(&args.key)?;
    let control = Arc::new(Control::open(&args.state, settings, *key).map_err(|_| ())?);
    let _lease = control.worker_lease().map_err(|_| ())?;
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ())?
            .as_secs(),
    )
    .map_err(|_| ())?;
    let coordinator = Coordinator::open(control, &countries, now).map_err(|_| ())?;
    // Construct and finally drop the blocking client outside the Tokio runtime.
    let provider = Arc::new(ProviderClient::try_new().map_err(|_| ())?);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| ())?;
    let result = runtime.block_on(serve(coordinator, countries, provider.clone()));
    drop(runtime);
    drop(provider);
    result
}
fn main() {
    if run().is_err() {
        eprintln!("住宅测试服务启动或运行失败，请检查本机配置和日志");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_only_known_unique_installed_dynamic_entrances() {
        let good = json!({"residential_exits":[
            {"dynamic":true,"country":"US","tag":"residential-11","port":10110},
            {"dynamic":false,"country":"XX"}]});
        assert_eq!(installed(&good).unwrap(), vec!["US"]);
        let bad = json!({"residential_exits":[
            {"dynamic":true,"country":"US","tag":"residential-11","port":10110},
            {"dynamic":true,"country":"US","tag":"residential-11","port":10110}]});
        assert!(installed(&bad).is_err());
        assert!(installed(&json!({"residential_exits":[{"dynamic":true,"country":"US","tag":"wrong","port":10110}]})).is_err());
        assert!(installed(&json!({"residential_exits":[]})).is_err());
    }
}
