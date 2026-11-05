//! Fixed public HTTPS and DoH checks through one authenticated proxy. This
//! library does not provide the privileged worker's required process sandbox.
use crate::{public_ipv4, Proxy as ImportProxy};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use reqwest::blocking::{Client, Response};
use reqwest::redirect::Policy;
use reqwest::Proxy;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const DNS_QUERY: &[u8] =
    b"XG\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
#[derive(Clone, Copy)]
pub enum Protocol {
    Socks,
    Http,
}
impl Protocol {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Socks => "socks",
            Self::Http => "http",
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum ProbeError {
    Unavailable,
    InvalidExit,
    InvalidDns,
}
pub struct ProbeResult {
    pub exit_ip: Ipv4Addr,
    pub country: String,
    pub https_ms: u64,
    pub doh_ms: u64,
}
pub(crate) struct Targets {
    pub(crate) proxy: String,
    pub(crate) trace: String,
    pub(crate) dns: String,
    pub(crate) root: Option<reqwest::Certificate>,
}
fn body(response: Response) -> Result<Zeroizing<Vec<u8>>, ProbeError> {
    if !response.status().is_success() {
        return Err(ProbeError::Unavailable);
    }
    let mut result = Zeroizing::new(Vec::new());
    response
        .take(8193)
        .read_to_end(&mut result)
        .map_err(|_| ProbeError::Unavailable)?;
    if result.len() > 8192 {
        return Err(ProbeError::Unavailable);
    }
    Ok(result)
}
pub(crate) fn run(proxy: &ImportProxy, targets: &Targets) -> Result<ProbeResult, ProbeError> {
    let outbound = Proxy::all(&targets.proxy)
        .map_err(|_| ProbeError::Unavailable)?
        .basic_auth(proxy.username(), proxy.password());
    let mut builder = Client::builder()
        .no_proxy()
        .proxy(outbound)
        .redirect(Policy::none())
        .https_only(true)
        .local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(20));
    if let Some(root) = &targets.root {
        builder = builder.add_root_certificate(root.clone());
    }
    let client = builder.build().map_err(|_| ProbeError::Unavailable)?;
    let start = Instant::now();
    let trace = body(
        client
            .get(&targets.trace)
            .send()
            .map_err(|_| ProbeError::Unavailable)?,
    )?;
    let trace = std::str::from_utf8(&trace).map_err(|_| ProbeError::InvalidExit)?;
    let (mut address, mut country) = (None, None);
    for line in trace.lines() {
        match line.split_once('=') {
            Some(("ip", value)) => address = Some(value),
            Some(("loc", value)) => country = Some(value),
            _ => (),
        }
    }
    let address = address
        .and_then(|value| value.parse::<Ipv4Addr>().ok())
        .filter(|ip| public_ipv4(*ip))
        .ok_or(ProbeError::InvalidExit)?;
    let country = country
        .filter(|value| value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_uppercase()))
        .ok_or(ProbeError::InvalidExit)?
        .to_owned();
    let https_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let start = Instant::now();
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
    let doh_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(ProbeResult {
        exit_ip: address,
        country,
        https_ms,
        doh_ms,
    })
}
/// Probe only the configured public IPv4 through fixed vendor-independent
/// HTTPS targets. Call from a bounded worker with restrictive OS privileges.
pub fn probe(proxy: &ImportProxy, protocol: Protocol) -> Result<ProbeResult, ProbeError> {
    // The import controller may need elevated filesystem access, but an
    // arbitrary remote proxy must only be contacted by an unprivileged helper.
    if unsafe { libc::geteuid() } == 0 {
        return Err(ProbeError::Unavailable);
    }
    if !public_ipv4(proxy.address) {
        return Err(ProbeError::InvalidExit);
    }
    let scheme = match protocol {
        Protocol::Socks => "socks5h",
        Protocol::Http => "http",
    };
    run(
        proxy,
        &Targets {
            proxy: format!("{scheme}://{}:{}", proxy.address, proxy.port),
            trace: "https://www.cloudflare.com/cdn-cgi/trace".into(),
            dns: "https://1.1.1.1/dns-query".into(),
            root: None,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_fixed;
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
    fn server(cert: &Path, key: &Path, protocol: &str, mode: &str) -> (Fixture, u16, u16) {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proxy_tls.py");
        let mut child = Command::new("python3")
            .arg("-u")
            .arg(script)
            .arg(cert)
            .arg(key)
            .arg(protocol)
            .arg(mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let values: Vec<u16> = line
            .split_whitespace()
            .map(|value| value.parse().unwrap())
            .collect();
        (Fixture(child), values[0], values[1])
    }
    #[test]
    fn authenticated_socks_and_http_probes_reject_unsafe_or_invalid_responses() {
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
        let valid = parse_fixed("1.1.1.1:80:fixture-user:synthetic-password").unwrap();
        let invalid = parse_fixed("1.1.1.1:80:fixture-user:wrong-password").unwrap();
        for protocol in ["socks", "http"] {
            for mode in ["good", "private", "dnsfail", "oversize"] {
                let (_fixture, proxy, web) = server(&cert, &key, protocol, mode);
                let scheme = if protocol == "socks" {
                    "socks5h"
                } else {
                    "http"
                };
                let targets = Targets {
                    proxy: format!("{scheme}://127.0.0.1:{proxy}"),
                    trace: format!("https://localhost:{web}/trace"),
                    dns: format!("https://localhost:{web}/dns-query"),
                    root: Some(root.clone()),
                };
                let result = run(&valid[0], &targets);
                match mode {
                    "good" => {
                        let result = result.unwrap();
                        assert_eq!(result.exit_ip.to_string(), "8.8.8.8");
                        assert_eq!(result.country, "US");
                        assert!(matches!(
                            run(&invalid[0], &targets),
                            Err(ProbeError::Unavailable)
                        ));
                        let untrusted = Targets {
                            root: None,
                            ..targets
                        };
                        assert!(matches!(
                            run(&valid[0], &untrusted),
                            Err(ProbeError::Unavailable)
                        ));
                    }
                    "private" => assert!(matches!(result, Err(ProbeError::InvalidExit))),
                    "dnsfail" => assert!(matches!(result, Err(ProbeError::InvalidDns))),
                    "oversize" => assert!(matches!(result, Err(ProbeError::Unavailable))),
                    _ => unreachable!(),
                }
            }
        }
    }
}
