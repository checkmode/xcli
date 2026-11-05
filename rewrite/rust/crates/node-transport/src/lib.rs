//! HTTPS transport for the existing node synchronization endpoint.
//!
//! Responses must still be validated by `xcli-node-protocol` before changing
//! authorization or acknowledging traffic. This crate does not run a node.
use reqwest::blocking::Client;
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{redirect::Policy, StatusCode, Url};
use serde_json::Value;
use std::fmt;
use std::io::Read;
use std::time::Duration;

const MAX_RESPONSE: u64 = 256 * 1024;

#[derive(Debug)]
pub struct TransportError(&'static str);
impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for TransportError {}
type Result<T> = std::result::Result<T, TransportError>;

fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn valid_key(key: &str) -> bool {
    key.len() == 43
        && key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// Accept only a credential-free HTTPS origin, with no path, query or fragment.
pub fn panel_origin(value: &str) -> Result<String> {
    if value.is_empty() || value.len() > 2048 || value.chars().any(|c| c <= ' ' || c == '\u{7f}') {
        return Err(TransportError("Invalid panel URL"));
    }
    let (_, rest) = value
        .split_once("://")
        .ok_or(TransportError("Invalid panel URL"))?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, suffix) = rest.split_at(authority_end);
    if authority.is_empty() || authority.contains('@') || !(suffix.is_empty() || suffix == "/") {
        return Err(TransportError("Invalid panel URL"));
    }
    let parsed = Url::parse(value).map_err(|_| TransportError("Invalid panel URL"))?;
    if parsed.scheme() != "https"
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(TransportError("Invalid panel URL"));
    }
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}

pub struct Transport {
    client: Client,
    origin: String,
    authorization: HeaderValue,
}

impl Transport {
    pub fn new(origin: &str, node_id: &str, key: &str) -> Result<Self> {
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(8))
            .build()
            .map_err(|_| TransportError("Cannot initialize HTTPS transport"))?;
        Self::with_client(origin, node_id, key, client)
    }

    fn with_client(origin: &str, node_id: &str, key: &str, client: Client) -> Result<Self> {
        if !valid_id(node_id) || !valid_key(key) {
            return Err(TransportError("Invalid node identity"));
        }
        let origin = panel_origin(origin)?;
        let mut authorization = HeaderValue::from_str(&format!("Xcli-Node {node_id}.{key}"))
            .map_err(|_| TransportError("Invalid node identity"))?;
        authorization.set_sensitive(true);
        Ok(Self {
            client,
            origin,
            authorization,
        })
    }

    pub fn exchange(&self, payload: &Value) -> Result<Value> {
        let response = self
            .client
            .post(format!("{}/api/nodes/sync", self.origin))
            .header(AUTHORIZATION, self.authorization.clone())
            .json(payload)
            .send()
            .map_err(|_| TransportError("Panel synchronization unavailable"))?;
        if response.status() != StatusCode::OK
            || !response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(';').next())
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
        {
            return Err(TransportError("Panel rejected synchronization"));
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| TransportError("Panel synchronization unavailable"))?;
        if bytes.len() as u64 > MAX_RESPONSE {
            return Err(TransportError("Panel response too large"));
        }
        serde_json::from_slice(&bytes).map_err(|_| TransportError("Invalid panel response"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::path::Path;
    use std::process::{Child, Command, Stdio};

    #[test]
    fn rejects_non_https_credentials_paths_and_fragments() {
        for value in [
            "http://example.com",
            "https://user:pass@example.com",
            "https://@example.com",
            "https://example.com/path",
            "https://example.com/a/..",
            "https://example.com/?q=x",
            "https://example.com/#x",
            "https://example.com/\n",
            "https://example.com:99999",
        ] {
            assert!(panel_origin(value).is_err(), "{value}");
        }
        assert_eq!(
            panel_origin("https://example.com:443/").unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn rejects_invalid_identity_without_echoing_it() {
        let err = Transport::new("https://example.com", "bad-id", "secret")
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "Invalid node identity");
    }

    struct Fixture(Child);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn server(cert: &Path, key: &Path, mode: &str) -> (Fixture, u16) {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/panel_tls.py");
        let mut child = Command::new("python3")
            .arg("-u")
            .arg(script)
            .arg(cert)
            .arg(key)
            .arg(mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start TLS fixture");
        let mut port = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut port)
            .unwrap();
        (Fixture(child), port.trim().parse().expect("fixture port"))
    }

    #[test]
    fn verified_tls_endpoint_rejects_untrusted_redirect_wrong_host_and_oversize() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("key.pem");
        let cert = dir.path().join("cert.pem");
        let config = dir.path().join("openssl.cnf");
        std::fs::write(&config, "[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n").unwrap();
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
            .expect("openssl required for TLS test");
        assert!(status.success());
        let ca = reqwest::Certificate::from_pem(&std::fs::read(&cert).unwrap()).unwrap();
        let client = Client::builder()
            .add_root_certificate(ca)
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let payload = serde_json::json!({"revision":"", "counters":[]});
        let id = "a".repeat(32);
        let token = "B".repeat(43);
        for mode in ["good", "redirect", "oversize", "badtype"] {
            let (_server, port) = server(&cert, &key, mode);
            let origin = format!("https://localhost:{port}");
            let transport = Transport::with_client(&origin, &id, &token, client.clone()).unwrap();
            let result = transport.exchange(&payload);
            if mode == "good" {
                assert_eq!(result.unwrap(), serde_json::json!({"ok":true}));
                assert!(Transport::new(&origin, &id, &token)
                    .unwrap()
                    .exchange(&payload)
                    .is_err());
                let wrong_host = format!("https://127.0.0.1:{port}");
                assert!(
                    Transport::with_client(&wrong_host, &id, &token, client.clone())
                        .unwrap()
                        .exchange(&payload)
                        .is_err()
                );
            } else {
                assert!(result.is_err(), "mode {mode}");
            }
        }
    }
}
