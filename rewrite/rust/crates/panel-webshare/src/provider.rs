//! Bounded parsing of provider responses. No network or credentials are logged.
use crate::REGIONS;
use reqwest::blocking::Client;
use reqwest::header::{HeaderValue, AUTHORIZATION};
use reqwest::redirect::Policy;
use serde_json::{json, Value};
use std::io::Read;
use std::time::Duration;
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub enum ProviderError {
    InvalidPlanData,
    NoCredentials,
    InvalidUsername,
    InvalidPassword,
    InvalidSession,
    InvalidRequest,
    Unauthorized,
    RateLimited,
    Unavailable,
    Oversized,
}
impl ProviderError {
    pub fn retry_seconds(&self) -> u64 {
        match self {
            Self::Unauthorized => 300,
            Self::RateLimited => 90,
            _ => 60,
        }
    }
}
#[derive(Clone)]
pub struct Credentials {
    pub base: Zeroizing<String>,
    pub password: Zeroizing<String>,
}
#[derive(Clone, Copy)]
pub enum Endpoint {
    Plans,
    Proxies,
    Config,
    Usage,
}
impl Endpoint {
    fn path(self) -> &'static str {
        match self {
            Self::Plans => "/api/v2/subscription/plan/",
            Self::Proxies => "/api/v2/proxy/list/",
            Self::Config => "/api/v3/proxy/config",
            Self::Usage => "/api/v2/stats/aggregate/",
        }
    }
    fn allowed(self, key: &str) -> bool {
        match self {
            Self::Plans => ["page", "page_size"].contains(&key),
            Self::Proxies => ["mode", "plan_id", "page", "page_size"].contains(&key),
            Self::Config => false,
            Self::Usage => ["plan_id", "timestamp__gte", "timestamp__lte"].contains(&key),
        }
    }
}
/// May contain provider credentials. It deliberately has no Debug implementation.
pub struct ProviderResponse(super::Secret);
impl ProviderResponse {
    pub fn as_value(&self) -> &Value {
        &self.0 .0
    }
    #[cfg(test)]
    pub(crate) fn fixture(value: Value) -> Self {
        Self(super::Secret(value))
    }
}
pub trait Provider {
    fn fetch(
        &self,
        key: &str,
        endpoint: Endpoint,
        parameters: &[(&str, &str)],
    ) -> Result<ProviderResponse, ProviderError>;
}

/// Only the fixed Webshare HTTPS origin can be used by production callers.
/// Call this blocking client from a dedicated worker or `spawn_blocking`.
pub struct ProviderClient {
    client: Client,
    origin: String,
}
impl ProviderClient {
    pub fn try_new() -> Result<Self, ProviderError> {
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(12))
            .build()
            .map_err(|_| ProviderError::Unavailable)?;
        Ok(Self {
            client,
            origin: "https://proxy.webshare.io".into(),
        })
    }
    pub fn get(
        &self,
        key: &str,
        endpoint: Endpoint,
        parameters: &[(&str, &str)],
    ) -> Result<ProviderResponse, ProviderError> {
        if !super::api_key(key)
            || parameters.len() > 8
            || parameters.iter().any(|(name, value)| {
                !endpoint.allowed(name)
                    || value.len() > 128
                    || value.chars().any(|ch| ch.is_control())
            })
        {
            return Err(ProviderError::InvalidRequest);
        }
        let mut names = std::collections::BTreeSet::new();
        if parameters.iter().any(|(name, _)| !names.insert(*name)) {
            return Err(ProviderError::InvalidRequest);
        }
        let token = Zeroizing::new(format!("Token {key}"));
        let mut authorization =
            HeaderValue::from_str(&token).map_err(|_| ProviderError::InvalidRequest)?;
        authorization.set_sensitive(true);
        let response = self
            .client
            .get(format!("{}{}", self.origin, endpoint.path()))
            .query(parameters)
            .header(AUTHORIZATION, authorization)
            .header("accept", "application/json")
            .header("user-agent", "xcli-webshare/1")
            .send()
            .map_err(|_| ProviderError::Unavailable)?;
        match response.status().as_u16() {
            200..=299 => (),
            401 | 403 => return Err(ProviderError::Unauthorized),
            429 => return Err(ProviderError::RateLimited),
            _ => return Err(ProviderError::Unavailable),
        }
        let mut body = Zeroizing::new(Vec::new());
        response
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut body)
            .map_err(|_| ProviderError::Unavailable)?;
        if body.len() > 2 * 1024 * 1024 {
            return Err(ProviderError::Oversized);
        }
        let value = serde_json::from_slice(&body).map_err(|_| ProviderError::Unavailable)?;
        Ok(ProviderResponse(super::Secret(value)))
    }
}
impl Provider for ProviderClient {
    fn fetch(
        &self,
        key: &str,
        endpoint: Endpoint,
        parameters: &[(&str, &str)],
    ) -> Result<ProviderResponse, ProviderError> {
        self.get(key, endpoint, parameters)
    }
}

fn text(value: Option<&Value>, default: &str) -> String {
    match value {
        None => default.to_owned(),
        Some(Value::String(value)) => value.clone(),
        Some(Value::Null) => "None".to_owned(),
        Some(Value::Bool(value)) => if *value { "True" } else { "False" }.to_owned(),
        Some(Value::Number(value)) => value.to_string(),
        _ => default.to_owned(),
    }
    .chars()
    .take(40)
    .collect()
}
/// The caller must still enforce response byte and pagination limits.
pub fn plans(value: &Value) -> Result<Vec<Value>, ProviderError> {
    let rows = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or(ProviderError::InvalidPlanData)?;
    if rows.len() > 1000 {
        return Err(ProviderError::InvalidPlanData);
    }
    let mut plans = Vec::new();
    for row in rows {
        let Some(id) = row.get("id").and_then(Value::as_i64) else {
            continue;
        };
        let eligible = row.get("status").and_then(Value::as_str) == Some("active")
            && (row.get("pool_filter").and_then(Value::as_str) == Some("residential")
                || row.get("proxy_subtype").and_then(Value::as_str) == Some("residential"));
        plans.push(json!({"id":id,"status":text(row.get("status"),"unknown"),"pool_filter":text(row.get("pool_filter"),""),
            "proxy_subtype":text(row.get("proxy_subtype"),""),"bandwidth_limit":row.get("bandwidth_limit").filter(|value|value.is_number()).cloned(),
            "eligible":eligible,"label":format!("{} · #{}",if eligible {"动态住宅"} else {"不可用于动态住宅池"},id)}));
    }
    Ok(plans)
}
fn valid_base(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}
fn valid_username(value: &str) -> bool {
    let (base, tail) = value
        .split_once('-')
        .map_or((value, None), |(base, tail)| (base, Some(tail)));
    valid_base(base)
        && tail.is_none_or(|tail| {
            !tail.is_empty()
                && tail
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        })
}
pub fn credentials(value: &Value) -> Result<Credentials, ProviderError> {
    let first = value
        .get("results")
        .and_then(Value::as_array)
        .and_then(|rows| rows.first())
        .ok_or(ProviderError::NoCredentials)?;
    let username = first
        .get("username")
        .and_then(Value::as_str)
        .filter(|value| valid_username(value))
        .ok_or(ProviderError::InvalidUsername)?;
    let password = first
        .get("password")
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty() && value.len() <= 255 && !value.chars().any(|c| (c as u32) < 32)
        })
        .ok_or(ProviderError::InvalidPassword)?;
    Ok(Credentials {
        base: Zeroizing::new(username.split('-').next().unwrap_or("").to_owned()),
        password: Zeroizing::new(password.to_owned()),
    })
}
pub fn session_username(
    base: &str,
    country: &str,
    identifier: &str,
) -> Result<Zeroizing<String>, ProviderError> {
    if !valid_base(base)
        || !REGIONS.iter().any(|region| region.country == country)
        || identifier.is_empty()
        || identifier.len() > 15
        || !identifier.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ProviderError::InvalidSession);
    }
    Ok(Zeroizing::new(format!(
        "{base}{}-{identifier}",
        if country == "ZZ" {
            String::new()
        } else {
            format!("-{}", country.to_ascii_lowercase())
        }
    )))
}
pub fn usage(value: &Value) -> Value {
    let mut result = json!({});
    for key in [
        "bandwidth_total",
        "requests_total",
        "requests_successful",
        "requests_failed",
    ] {
        if let Some(number) = value.get(key).and_then(Value::as_u64) {
            result[key] = json!(number);
        }
    }
    result
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
    fn server(cert: &Path, key: &Path, mode: &str) -> (Fixture, u16) {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/provider_tls.py");
        let mut child = Command::new("python3")
            .arg("-u")
            .arg(script)
            .arg(cert)
            .arg(key)
            .arg(mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start HTTPS fixture");
        let mut port = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut port)
            .unwrap();
        (Fixture(child), port.trim().parse().unwrap())
    }
    #[test]
    fn tls_client_rejects_untrusted_certificates_redirects_and_large_responses() {
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
        let ca = reqwest::Certificate::from_pem(&std::fs::read(&cert).unwrap()).unwrap();
        let trusted = Client::builder()
            .add_root_certificate(ca)
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let plain = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let parameters = [("page", "1"), ("page_size", "100")];
        let token = "synthetic-api-key-for-test";
        for mode in [
            "good",
            "redirect",
            "unauthorized",
            "rate",
            "oversize",
            "badjson",
        ] {
            let (_server, port) = server(&cert, &key, mode);
            let origin = format!("https://localhost:{port}");
            let client = ProviderClient {
                client: trusted.clone(),
                origin: origin.clone(),
            };
            let result = client.get(token, Endpoint::Plans, &parameters);
            match mode {
                "good" => {
                    assert_eq!(result.unwrap().as_value(), &json!({"results":[]}));
                    assert!(matches!(
                        ProviderClient {
                            client: plain.clone(),
                            origin: origin.clone()
                        }
                        .get(token, Endpoint::Plans, &parameters),
                        Err(ProviderError::Unavailable)
                    ));
                    let wrong = ProviderClient {
                        client: trusted.clone(),
                        origin: format!("https://127.0.0.1:{port}"),
                    };
                    assert!(matches!(
                        wrong.get(token, Endpoint::Plans, &parameters),
                        Err(ProviderError::Unavailable)
                    ));
                    assert!(matches!(
                        client.get(token, Endpoint::Plans, &[("unexpected", "1")]),
                        Err(ProviderError::InvalidRequest)
                    ));
                    assert!(matches!(
                        client.get(token, Endpoint::Plans, &[("page", "1"), ("page", "2")]),
                        Err(ProviderError::InvalidRequest)
                    ));
                }
                "unauthorized" => assert!(matches!(result, Err(ProviderError::Unauthorized))),
                "rate" => assert!(matches!(result, Err(ProviderError::RateLimited))),
                "oversize" => assert!(matches!(result, Err(ProviderError::Oversized))),
                _ => assert!(matches!(result, Err(ProviderError::Unavailable))),
            }
        }
    }
}
