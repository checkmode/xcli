//! Disposable unprivileged webhook process. Secrets arrive only on stdin.
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{self, Read};
use xcli_panel_operations::webhook::{self, Config};
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    url: String,
    bearer: String,
    signing: String,
    payload: Value,
    timestamp: i64,
}
impl Drop for Input {
    fn drop(&mut self) {
        self.url.zeroize();
        self.bearer.zeroize();
        self.signing.zeroize();
        fn clear(value: &mut Value) {
            match value {
                Value::String(text) => text.zeroize(),
                Value::Array(values) => values.iter_mut().for_each(clear),
                Value::Object(values) => values.values_mut().for_each(clear),
                _ => {}
            }
        }
        clear(&mut self.payload);
    }
}
fn run() -> Result<(), ()> {
    if std::env::args_os().skip(1).collect::<Vec<_>>() != ["--experimental"]
        || unsafe { libc::geteuid() } == 0
    {
        return Err(());
    }
    let limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limits) } != 0 {
        return Err(());
    }
    #[cfg(target_os = "linux")]
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    io::stdin()
        .lock()
        .take(32_769)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > 32_768 {
        return Err(());
    }
    let input: Input = serde_json::from_slice(&bytes).map_err(|_| ())?;
    let config = Config {
        url: Zeroizing::new(input.url.clone()),
        bearer: Zeroizing::new(input.bearer.clone()),
        signing: Zeroizing::new(input.signing.clone()),
    };
    let result = webhook::post(&config, &input.payload, input.timestamp);
    println!(
        "{}",
        json!({"status":result.status,"error":result.error.is_some()})
    );
    Ok(())
}
fn main() {
    if run().is_err() {
        std::process::exit(1);
    }
}
