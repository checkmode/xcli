//! Experimental one-shot probe helper. Its parent must drop privileges, clear
//! the environment, bound runtime and resources, and send credentials on stdin.
use serde_json::{json, Map, Value};
use std::io::Read;
use xcli_panel_import::parse_fixed;
use xcli_panel_import::probe::{probe, ProbeResult, Protocol};
use xcli_panel_import::vmess::{SecretJson, VmessProxy};
use xcli_panel_import::vmess_probe::probe_vmess;
use zeroize::Zeroizing;

fn exact(map: &Map<String, Value>, fields: &[&str]) -> bool {
    map.len() == fields.len() && fields.iter().all(|field| map.contains_key(*field))
}
fn report(result: &ProbeResult) -> Value {
    json!({"ok":true,"exit_ip":result.exit_ip.to_string(),"country":result.country,
        "https_ms":result.https_ms,"doh_ms":result.doh_ms})
}
async fn execute() -> Result<Value, ()> {
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::stdin()
        .lock()
        .take(20_001)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > 20_000 {
        return Err(());
    }
    let input = SecretJson::parse(&bytes).map_err(|_| ())?;
    let object = input.as_value().as_object().ok_or(())?;
    if !exact(object, &["kind", "protocol", "fields"]) {
        return Err(());
    }
    let fields = object["fields"].as_object().ok_or(())?;
    match object["kind"].as_str() {
        Some("fixed") => {
            if !exact(fields, &["address", "port", "username", "password"]) {
                return Err(());
            }
            let address = fields["address"].as_str().ok_or(())?;
            let port = fields["port"].as_u64().ok_or(())?;
            let username = fields["username"]
                .as_str()
                .filter(|value| !value.contains(':'))
                .ok_or(())?;
            let password = fields["password"].as_str().ok_or(())?;
            let text = Zeroizing::new(format!("{address}:{port}:{username}:{password}"));
            let values = parse_fixed(&text).map_err(|_| ())?;
            if values.len() != 1
                || values[0].username() != username
                || values[0].password() != password
            {
                return Err(());
            }
            let protocol = match object["protocol"].as_str() {
                Some("socks") => Protocol::Socks,
                Some("http") => Protocol::Http,
                _ => return Err(()),
            };
            Ok(match probe(&values[0], protocol) {
                Ok(result) => report(&result),
                Err(error) => json!({"ok":false,"reason":error.code()}),
            })
        }
        Some("vmess") => {
            if object["protocol"] != "vmess" {
                return Err(());
            }
            let proxy = VmessProxy::from_record(&object["fields"]).map_err(|_| ())?;
            let result = match probe_vmess(&proxy).await {
                Ok(result) => result,
                Err(error) => return Ok(json!({"ok":false,"reason":error.code()})),
            };
            let mut output = report(&result.observed);
            output["server_ip"] = json!(result.server_ip.to_string());
            Ok(output)
        }
        _ => Err(()),
    }
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    // SAFETY: geteuid only reads the current process identity.
    if unsafe { libc::geteuid() } == 0 || std::env::args_os().len() != 1 {
        std::process::exit(1);
    }
    let output = execute().await.unwrap_or_else(|_| json!({"ok":false}));
    println!("{output}");
}
