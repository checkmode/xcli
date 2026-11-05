//! HTTPS and DNS-over-HTTPS checks through a Webshare SOCKS session. The
//! production endpoints are fixed; invoke from a bounded blocking worker.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use reqwest::blocking::{Client, Response};
use reqwest::redirect::Policy;
use reqwest::Proxy;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const DNS_QUERY: &[u8] =
    b"XG\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
#[derive(Debug, PartialEq, Eq)]
pub enum ProbeError {
    InvalidInput,
    Unavailable,
    InvalidExit,
    InvalidDns,
}
pub struct ProbeResult {
    pub exit_ip: IpAddr,
    pub exit_country: String,
    pub https_ms: u64,
    pub doh_ms: u64,
    pub last_success: i64,
}
struct Targets {
    proxy: String,
    trace: String,
    dns: String,
    root: Option<reqwest::Certificate>,
}
fn body(response: Response) -> Result<Zeroizing<Vec<u8>>, ProbeError> {
    if !response.status().is_success() {
        return Err(ProbeError::Unavailable);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    response
        .take(32769)
        .read_to_end(&mut bytes)
        .map_err(|_| ProbeError::Unavailable)?;
    if bytes.len() > 32768 {
        return Err(ProbeError::Unavailable);
    }
    Ok(bytes)
}
fn valid_identity(username: &str, password: &str, country: &str) -> bool {
    !username.is_empty()
        && username.len() <= 255
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        && !password.is_empty()
        && password.len() <= 255
        && !password.chars().any(|c| (c as u32) < 32)
        && crate::REGIONS
            .iter()
            .any(|region| region.country == country)
}
fn run(
    targets: &Targets,
    username: &str,
    password: &str,
    country: &str,
) -> Result<ProbeResult, ProbeError> {
    if !valid_identity(username, password, country) {
        return Err(ProbeError::InvalidInput);
    }
    let proxy = Proxy::all(&targets.proxy)
        .map_err(|_| ProbeError::Unavailable)?
        .basic_auth(username, password);
    let mut builder = Client::builder()
        .no_proxy()
        .proxy(proxy)
        .redirect(Policy::none())
        .https_only(true)
        .local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(14));
    if let Some(root) = &targets.root {
        builder = builder.add_root_certificate(root.clone());
    }
    let client = builder.build().map_err(|_| ProbeError::Unavailable)?;
    let started = Instant::now();
    let trace = body(
        client
            .get(&targets.trace)
            .send()
            .map_err(|_| ProbeError::Unavailable)?,
    )?;
    let trace = std::str::from_utf8(&trace).map_err(|_| ProbeError::InvalidExit)?;
    let mut ip = None;
    let mut location = None;
    for line in trace.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key {
                "ip" => ip = Some(value),
                "loc" => location = Some(value),
                _ => (),
            }
        }
    }
    let ip = ip
        .and_then(|value| value.parse::<IpAddr>().ok())
        .filter(|ip| crate::relay::public_ip(*ip))
        .ok_or(ProbeError::InvalidExit)?;
    let location = location.unwrap_or("");
    if location.len() > 16 || !location.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(ProbeError::InvalidExit);
    }
    if country != "ZZ" && location != country {
        return Err(ProbeError::InvalidExit);
    }
    let https_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let started = Instant::now();
    let answer = body(
        client
            .get(&targets.dns)
            .query(&[("dns", URL_SAFE_NO_PAD.encode(DNS_QUERY))])
            .header("accept", "application/dns-message")
            .send()
            .map_err(|_| ProbeError::Unavailable)?,
    )?;
    if answer.len() < 12
        || &answer[..2] != b"XG"
        || answer[2] & 128 == 0
        || answer[3] & 15 != 0
        || u16::from_be_bytes([answer[6], answer[7]]) == 0
    {
        return Err(ProbeError::InvalidDns);
    }
    let doh_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let last_success = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProbeError::Unavailable)?
            .as_secs(),
    )
    .map_err(|_| ProbeError::Unavailable)?;
    Ok(ProbeResult {
        exit_ip: ip,
        exit_country: location.to_owned(),
        https_ms,
        doh_ms,
        last_success,
    })
}
pub fn probe(username: &str, password: &str, country: &str) -> Result<ProbeResult, ProbeError> {
    run(
        &Targets {
            proxy: "socks5h://p.webshare.io:80".into(),
            trace: "https://www.cloudflare.com/cdn-cgi/trace".into(),
            dns: "https://1.1.1.1/dns-query".into(),
            root: None,
        },
        username,
        password,
        country,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::path::Path;
    use std::process::{Child, Command, Stdio};

    struct Fixture(Child);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn server(cert: &Path, key: &Path, mode: &str) -> (Fixture, u16, u16) {
        let script =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/probe_socks_tls.py");
        let mut child = Command::new("python3")
            .arg("-u")
            .arg(script)
            .arg(cert)
            .arg(key)
            .arg(mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut ports = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ports)
            .unwrap();
        let ports: Vec<u16> = ports
            .split_whitespace()
            .map(|value| value.parse().unwrap())
            .collect();
        (Fixture(child), ports[0], ports[1])
    }
    #[test]
    fn probes_https_and_dns_through_authenticated_socks_without_dns_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("key.pem");
        let cert = dir.path().join("cert.pem");
        let config = dir.path().join("openssl.cnf");
        std::fs::write(&config,"[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n").unwrap();
        let status = Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-config",
            ])
            .arg(&config)
            .arg("-keyout")
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let root = reqwest::Certificate::from_pem(&std::fs::read(&cert).unwrap()).unwrap();
        for mode in ["good", "wrong-country", "private", "dnsfail", "oversize"] {
            let (_server, proxy, web) = server(&cert, &key, mode);
            let targets = Targets {
                proxy: format!("socks5h://127.0.0.1:{proxy}"),
                trace: format!("https://localhost:{web}/trace"),
                dns: format!("https://localhost:{web}/dns-query"),
                root: Some(root.clone()),
            };
            let value = run(&targets, "fixture-us-1", "synthetic-password", "US");
            match mode {
                "good" => {
                    let value = value.unwrap();
                    assert_eq!(value.exit_ip.to_string(), "8.8.8.8");
                    assert_eq!(value.exit_country, "US");
                    let no_trust = Targets {
                        root: None,
                        ..targets
                    };
                    assert!(matches!(
                        run(&no_trust, "fixture-us-1", "synthetic-password", "US"),
                        Err(ProbeError::Unavailable)
                    ));
                }
                "wrong-country" | "private" => {
                    assert!(matches!(value, Err(ProbeError::InvalidExit)))
                }
                "dnsfail" => assert!(matches!(value, Err(ProbeError::InvalidDns))),
                "oversize" => assert!(matches!(value, Err(ProbeError::Unavailable))),
                _ => unreachable!(),
            }
        }
    }
}
