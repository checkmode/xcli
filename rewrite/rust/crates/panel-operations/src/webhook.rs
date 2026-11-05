//! Experimental webhook transport; no background delivery is enabled here.
//!
//! HTTPS and certificate verification are mandatory. DNS is filtered at the
//! point of connection; literal addresses are checked before creating a
//! request. Proxy environment variables and redirects are never used.
use hmac::{Hmac, Mac};
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use serde_json::Value;
use sha2::Sha256;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use url::{Host, Url};
use zeroize::Zeroizing;

const ERROR: &str = "连接失败、超时、证书不受信任或目标不是公网地址";
const MAX_RESPONSE: u64 = 16_384;

pub struct Config {
    pub url: Zeroizing<String>,
    pub bearer: Zeroizing<String>,
    pub signing: Zeroizing<String>,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Delivery {
    pub status: u16,
    pub error: Option<String>,
}

/// Returns only the public authority, never the path or query that may contain
/// a secret. The full URL and credentials must not be logged or displayed.
pub fn validate_url(value: &str) -> Result<String, &'static str> {
    if value.is_empty() || value.len() > 4096 || value.bytes().any(|c| c <= 32 || c == 127) {
        return Err("Webhook 地址格式不正确");
    }
    let parsed = Url::parse(value).map_err(|_| "Webhook 地址格式不正确")?;
    if parsed.scheme() != "https" {
        return Err("Webhook 必须使用 HTTPS");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return Err("地址不能包含用户名、密码或片段；请使用独立的认证字段");
    }
    match parsed.host().ok_or("Webhook 缺少主机名")? {
        Host::Ipv4(ip) if !public_ip(IpAddr::V4(ip)) => return Err("Webhook 必须指向公网地址"),
        Host::Ipv6(ip) if !public_ip(IpAddr::V6(ip)) => return Err("Webhook 必须指向公网地址"),
        Host::Domain(domain) => {
            let name = domain.trim_end_matches('.').to_ascii_lowercase();
            if name.is_empty()
                || name == "localhost"
                || name.ends_with(".localhost")
                || name.ends_with(".local")
            {
                return Err("Webhook 必须指向公网地址");
            }
        }
        _ => {}
    }
    let host = parsed.host().ok_or("Webhook 缺少主机名")?.to_string();
    Ok(match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}
fn v4(ip: Ipv4Addr) -> bool {
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
fn v6(ip: Ipv6Addr) -> bool {
    let b = ip.octets();
    b[0] & 0xe0 == 0x20
        && !(b[0] == 0x20 && b[1] == 0x02)
        && !(b[0] == 0x20
            && b[1] == 0x01
            && (b[2] == 0x0d && b[3] == 0xb8 || b[2] == 0 && b[3] < 0x20))
        && !(b[0] == 0x3f && b[1] == 0xff && b[2] & 0xf0 == 0)
}
pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => v4(ip),
        IpAddr::V6(ip) => v6(ip),
    }
}
fn public_addresses(addresses: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    addresses
        .into_iter()
        .filter(|address| public_ip(address.ip()))
        .take(64)
        .collect()
}
struct PublicResolver;
impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((name.as_str(), 0)).await?;
            let allowed = public_addresses(addresses);
            if allowed.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "no public address",
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(allowed.into_iter()) as Addrs)
        })
    }
}
fn builder() -> ClientBuilder {
    Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(8))
        .dns_resolver(Arc::new(PublicResolver))
}
fn signature(secret: &[u8], timestamp: i64, body: &[u8]) -> Result<String, ()> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).map_err(|_| ())?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    Ok(format!(
        "sha256={}",
        hex::encode(mac.finalize().into_bytes())
    ))
}
fn post_with_client(client: &Client, config: &Config, payload: &Value, timestamp: i64) -> Delivery {
    let failed = || Delivery {
        status: 0,
        error: Some(ERROR.into()),
    };
    if validate_url(&config.url).is_err()
        || timestamp < 0
        || config.bearer.len() > 2048
        || config.signing.len() > 256
        || config.bearer.bytes().any(|c| c < 32 || c == 127)
        || config.signing.bytes().any(|c| c < 32 || c == 127)
    {
        return failed();
    }
    let Some(id) = payload.get("id").and_then(Value::as_str).filter(|id| {
        !id.is_empty()
            && id.len() <= 64
            && id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    }) else {
        return failed();
    };
    let Ok(body) = serde_json::to_vec(payload).map(Zeroizing::new) else {
        return failed();
    };
    if body.len() > MAX_RESPONSE as usize {
        return failed();
    }
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(USER_AGENT, HeaderValue::from_static("xcli/0.1.0"));
    let Ok(event) = HeaderValue::from_str(id) else {
        return failed();
    };
    let Ok(time) = HeaderValue::from_str(&timestamp.to_string()) else {
        return failed();
    };
    headers.insert("X-Xcli-Event-Id", event);
    headers.insert("X-Xcli-Timestamp", time);
    if !config.bearer.is_empty() {
        let value = Zeroizing::new(format!("Bearer {}", config.bearer.as_str()));
        let Ok(mut header) = HeaderValue::from_str(&value) else {
            return failed();
        };
        header.set_sensitive(true);
        headers.insert(AUTHORIZATION, header);
    }
    if !config.signing.is_empty() {
        let Ok(value) = signature(config.signing.as_bytes(), timestamp, &body) else {
            return failed();
        };
        let Ok(mut header) = HeaderValue::from_str(&value) else {
            return failed();
        };
        header.set_sensitive(true);
        headers.insert("X-Xcli-Signature", header);
    }
    let Ok(response) = client
        .post(config.url.as_str())
        .headers(headers)
        .body(body.to_vec())
        .send()
    else {
        return failed();
    };
    let code = response.status().as_u16();
    let mut bytes = Vec::new();
    if response
        .take(MAX_RESPONSE + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > MAX_RESPONSE as usize
    {
        return Delivery {
            status: code,
            error: Some(ERROR.into()),
        };
    }
    if !(200..300).contains(&code) {
        return Delivery {
            status: code,
            error: Some(format!("接收端未返回成功状态（HTTP {code}）")),
        };
    }
    Delivery {
        status: code,
        error: None,
    }
}
/// Blocking call; run on a dedicated worker and do not hold the database lock
/// during network I/O. The caller owns retry, idempotence and audit handling.
pub fn post(config: &Config, payload: &Value, timestamp: i64) -> Delivery {
    match builder().build() {
        Ok(client) => post_with_client(&client, config, payload, timestamp),
        Err(_) => Delivery {
            status: 0,
            error: Some(ERROR.into()),
        },
    }
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
    fn config(url: String) -> Config {
        Config {
            url: Zeroizing::new(url),
            bearer: Zeroizing::new("fixture-bearer".into()),
            signing: Zeroizing::new("fixture-signing-secret".into()),
        }
    }
    #[test]
    fn url_and_resolution_reject_private_redirect_and_special_addresses() {
        for value in [
            "http://example.com",
            "https://127.0.0.1/path",
            "https://127.1/",
            "https://10.0.0.1/",
            "https://[::1]/",
            "https://[::ffff:8.8.8.8]/",
            "https://[2001:db8::1]/",
            "https://localhost./",
            "https://example.local/",
            "https://user@example.com",
            "https://example.com/#fragment",
            "https://exa mple.com",
        ] {
            assert!(validate_url(value).is_err(), "{value}");
        }
        assert_eq!(
            validate_url("https://example.com:8443/path?synthetic-secret").unwrap(),
            "example.com:8443"
        );
        assert!(!validate_url("https://example.com/path?synthetic-secret")
            .unwrap()
            .contains("synthetic-secret"));
        for value in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(public_ip(value.parse().unwrap()), "{value}");
        }
        for value in [
            "0.0.0.0",
            "100.64.0.1",
            "192.168.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "2002::1",
            "2001:db8::1",
            "3fff::1",
        ] {
            assert!(!public_ip(value.parse().unwrap()), "{value}");
        }
        let mixed = [
            "127.0.0.1:0".parse().unwrap(),
            "8.8.8.8:0".parse().unwrap(),
            "[::1]:0".parse().unwrap(),
        ];
        assert_eq!(
            public_addresses(mixed),
            vec!["8.8.8.8:0".parse::<SocketAddr>().unwrap()]
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(runtime
            .block_on(PublicResolver.resolve("localhost".parse().unwrap()))
            .is_err());
        assert_eq!(
            post(
                &config("https://127.0.0.1/".into()),
                &serde_json::json!({"id":"fixture-id"}),
                1
            )
            .status,
            0
        );
    }
    #[test]
    fn posts_signed_event_through_verified_tls_and_does_not_follow_redirects() {
        let temp = tempfile::tempdir().unwrap();
        let cert = temp.path().join("cert.pem");
        let key = temp.path().join("key.pem");
        let output = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=fixture.test",
                "-addext",
                "subjectAltName=DNS:fixture.test",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
            ])
            .arg("-keyout")
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(output.success());
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/webhook_tls.py");
        let mut child = Command::new("python3")
            .arg("-u")
            .arg(script)
            .arg(&cert)
            .arg(&key)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let port: u16 = line.trim().parse().unwrap();
        let _fixture = Fixture(child);
        let root = reqwest::Certificate::from_pem(&std::fs::read(&cert).unwrap()).unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let client = builder()
            .resolve("fixture.test", addr)
            .add_root_certificate(root)
            .build()
            .unwrap();
        let event = serde_json::json!({"schema":1,"id":"fixture-id","event":"test"});
        let endpoint = |path: &str| config(format!("https://fixture.test:{port}/{path}"));
        assert_eq!(
            post_with_client(&client, &endpoint("ok"), &event, 1234567),
            Delivery {
                status: 200,
                error: None
            }
        );
        let redirect = post_with_client(&client, &endpoint("redirect"), &event, 1234567);
        assert_eq!(redirect.status, 302);
        assert!(redirect.error.is_some());
        let oversized = post_with_client(&client, &endpoint("oversize"), &event, 1234567);
        assert_eq!(oversized.status, 200);
        assert!(oversized.error.is_some());
        let failure = post_with_client(&client, &endpoint("failed"), &event, 1234567);
        assert_eq!(failure.status, 503);
        assert!(failure.error.is_some());
        let untrusted = builder().resolve("fixture.test", addr).build().unwrap();
        assert_eq!(
            post_with_client(&untrusted, &endpoint("ok"), &event, 1234567).status,
            0
        );
    }
}
