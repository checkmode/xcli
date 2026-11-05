//! Experimental VMess v2 parsing and pinned-outbound generation. DNS
//! resolution, proxy verification and transaction application remain separate.
use crate::{public_ipv4, ImportError};
use base64::engine::{
    general_purpose::{GeneralPurpose, GeneralPurposeConfig},
    DecodePaddingMode,
};
use base64::{alphabet, Engine};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::Semaphore;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone)]
pub struct VmessProxy {
    address: String,
    port: u16,
    uuid: Zeroizing<String>,
    security: String,
    network: String,
    tls: bool,
    server_name: String,
    host: String,
    path: String,
    alpn: String,
    fingerprint: String,
}
pub struct SecretJson(Value);
impl SecretJson {
    pub(crate) fn new(value: Value) -> Self {
        Self(value)
    }
    pub fn as_value(&self) -> &Value {
        &self.0
    }
    /// Parse a sensitive JSON document and clear its strings on drop.
    pub fn parse(bytes: &[u8]) -> Result<Self, ImportError> {
        Ok(Self(
            serde_json::from_slice(bytes).map_err(|_| ImportError("JSON 格式不正确"))?,
        ))
    }
    pub(crate) fn value_mut(&mut self) -> &mut Value {
        &mut self.0
    }
}
impl Drop for SecretJson {
    fn drop(&mut self) {
        fn scrub(value: &mut Value) {
            match value {
                Value::String(value) => value.zeroize(),
                Value::Array(values) => values.iter_mut().for_each(scrub),
                Value::Object(values) => values.values_mut().for_each(scrub),
                _ => (),
            }
        }
        scrub(&mut self.0);
    }
}
fn visible(value: &str, max: usize) -> bool {
    value.len() <= max && !value.chars().any(|c| c < ' ' || c == '\u{7f}')
}
fn domain_name(value: &str) -> Result<String, ImportError> {
    if !visible(value, 253) {
        return Err(ImportError("VMess 字段格式或长度不正确"));
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(ip) if public_ipv4(ip) && ip.to_string() == value => Ok(value.into()),
            _ => Err(ImportError("VMess 服务器必须使用公网 IPv4 或域名")),
        };
    }
    // Match the legacy Python IDNA codec's transitional mappings before
    // UTS 46 processing (notably ß and final sigma).
    let mut mapped = String::new();
    for value in value.chars() {
        match value {
            'ß' | 'ẞ' => mapped.push_str("ss"),
            'ς' => mapped.push('σ'),
            '\u{200c}' | '\u{200d}' => (),
            value => mapped.push(value),
        }
    }
    let normalized = idna::domain_to_ascii(&mapped)
        .map_err(|_| ImportError("VMess 服务器域名不正确"))?
        .to_ascii_lowercase()
        .trim_end_matches('.')
        .to_owned();
    let labels: Vec<&str> = normalized.split('.').collect();
    if normalized.len() > 253
        || labels.len() < 2
        || labels.iter().any(|label| {
            let bytes = label.as_bytes();
            bytes.is_empty()
                || bytes.len() > 63
                || !bytes[0].is_ascii_alphanumeric()
                || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
                || !bytes
                    .iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        })
        || !labels
            .last()
            .is_some_and(|label| label.as_bytes()[0].is_ascii_lowercase())
    {
        return Err(ImportError("VMess 服务器必须使用公网 IPv4 或有效域名"));
    }
    if [".localhost", ".local", ".internal", ".invalid", ".test"]
        .iter()
        .any(|suffix| normalized.ends_with(suffix))
    {
        return Err(ImportError("不支持本地或保留域名"));
    }
    Ok(normalized)
}
fn text<'a>(
    map: &'a Map<String, Value>,
    name: &str,
    default: &'a str,
) -> Result<&'a str, ImportError> {
    match map.get(name) {
        None => Ok(default),
        Some(Value::String(value)) => Ok(value),
        _ => Err(ImportError("VMess 字段格式或长度不正确")),
    }
}
fn host(value: &str) -> bool {
    if !visible(value, 253) {
        return false;
    }
    let bytes = value.as_bytes();
    bytes.is_empty()
        || (bytes[0].is_ascii_alphanumeric()
            && bytes[bytes.len() - 1].is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || *c == b'.' || *c == b'-'))
}
fn integer_string(value: Option<&Value>, default: &str) -> Option<String> {
    match value {
        None => Some(default.to_owned()),
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Number(value)) => Some(value.to_string()),
        _ => None,
    }
}
fn falsey(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => true,
        Value::Number(number) => number.as_f64() == Some(0.0),
        Value::String(value) => value.is_empty(),
        Value::Array(value) => value.is_empty(),
        Value::Object(value) => value.is_empty(),
        Value::Bool(true) => false,
    }
}
fn parse_one(link: &Value) -> Result<VmessProxy, ImportError> {
    let map = link
        .as_object()
        .ok_or(ImportError("VMess 链接内容必须是对象"))?;
    const FIELDS: &[&str] = &[
        "v",
        "ps",
        "add",
        "port",
        "id",
        "aid",
        "scy",
        "net",
        "type",
        "host",
        "path",
        "tls",
        "sni",
        "alpn",
        "fp",
        "allowInsecure",
        "serviceName",
        "mode",
    ];
    if map.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        return Err(ImportError(
            "VMess 链接含有未支持的字段，请使用标准 v2rayN JSON 分享格式",
        ));
    }
    if !matches!(integer_string(map.get("v"), "2").as_deref(), Some("" | "2")) {
        return Err(ImportError("仅支持 VMess v2 分享格式"));
    }
    if !matches!(
        integer_string(map.get("aid"), "0").as_deref(),
        Some("" | "0")
    ) {
        return Err(ImportError("仅支持 VMess AEAD，alterId 必须为 0"));
    }
    if !matches!(map.get("allowInsecure"), None | Some(Value::Bool(false)))
        && !matches!(map.get("allowInsecure"), Some(Value::Number(value)) if value.as_f64()==Some(0.0))
        && !matches!(map.get("allowInsecure"), Some(Value::String(value)) if ["0","false", ""].contains(&value.as_str()))
    {
        return Err(ImportError("不支持跳过 TLS 证书验证"));
    }
    if !["", "gun"].contains(&text(map, "mode", "")?) {
        return Err(ImportError("暂不支持 gRPC multiMode"));
    }
    let network = match text(map, "net", "tcp")? {
        "raw" => "tcp",
        value => value,
    };
    if !["tcp", "ws", "grpc"].contains(&network) {
        return Err(ImportError("VMess 支持 TCP、WebSocket 和 gRPC 传输"));
    }
    let disguise = text(map, "type", "none")?;
    if !["", "none"].contains(&disguise) && !(network == "grpc" && disguise == "gun") {
        return Err(ImportError("不支持此 VMess 伪装类型"));
    }
    let uuid = Uuid::parse_str(text(map, "id", "")?)
        .map_err(|_| ImportError("VMess UUID 或端口不正确"))?;
    let port = integer_string(map.get("port"), "").ok_or(ImportError("VMess UUID 或端口不正确"))?;
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|c| c.is_ascii_digit()) {
        return Err(ImportError("VMess UUID 或端口不正确"));
    }
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(ImportError("VMess 端口不正确"))?;
    let tls = match text(map, "tls", "")? {
        "" | "none" => false,
        "tls" => true,
        _ => return Err(ImportError("VMess 传输安全仅支持无 TLS 或 TLS")),
    };
    let security = match map.get("scy") {
        None => "auto",
        Some(value) if falsey(value) => "auto",
        Some(Value::String(value)) => value.as_str(),
        _ => return Err(ImportError("不支持此 VMess 加密方式")),
    };
    if !["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"].contains(&security) {
        return Err(ImportError("不支持此 VMess 加密方式"));
    }
    let address = domain_name(text(map, "add", "")?)?;
    let server_name = text(map, "sni", "")?;
    let host_value = text(map, "host", "")?;
    if !host(server_name) || !host(host_value) {
        return Err(ImportError("VMess SNI / Host 格式不正确"));
    }
    let original_path = if network == "ws" && map.get("path").is_some_and(falsey) {
        ""
    } else {
        text(map, "path", "")?
    };
    let path = if network == "ws" && original_path.is_empty() {
        "/"
    } else if network == "grpc" {
        text(map, "serviceName", original_path)?
    } else {
        original_path
    };
    if !visible(path, 1024)
        || network == "ws" && !path.starts_with('/')
        || network == "grpc"
            && (path.is_empty()
                || path.len() > 200
                || !path
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c)))
        || network == "tcp" && (!path.is_empty() || !host_value.is_empty())
    {
        return Err(ImportError("VMess 传输路径不正确"));
    }
    let alpn = text(map, "alpn", "")?;
    if !visible(alpn, 100)
        || !alpn.is_empty()
            && alpn
                .split(',')
                .any(|part| !["h2", "http/1.1"].contains(&part))
    {
        return Err(ImportError("不支持此 ALPN 配置"));
    }
    let fingerprint = text(map, "fp", "")?;
    if ![
        "",
        "chrome",
        "firefox",
        "safari",
        "ios",
        "android",
        "edge",
        "random",
        "randomized",
    ]
    .contains(&fingerprint)
    {
        return Err(ImportError("不支持此 TLS 指纹"));
    }
    if !tls && (!server_name.is_empty() || !alpn.is_empty() || !fingerprint.is_empty()) {
        return Err(ImportError("SNI、ALPN 和 TLS 指纹需要开启 TLS"));
    }
    Ok(VmessProxy {
        address,
        port,
        uuid: Zeroizing::new(uuid.hyphenated().to_string()),
        security: security.into(),
        network: network.into(),
        tls,
        server_name: server_name.into(),
        host: host_value.into(),
        path: path.into(),
        alpn: alpn.into(),
        fingerprint: fingerprint.into(),
    })
}
pub fn parse_links(text: &str) -> Result<Vec<VmessProxy>, ImportError> {
    if text.is_empty() || text.len() > 12_000 {
        return Err(ImportError("VMess 链接列表过长或为空"));
    }
    let decoder = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    );
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if result.len() >= 20 {
            return Err(ImportError("每次最多导入 20 个代理"));
        }
        let raw = line
            .strip_prefix("vmess://")
            .ok_or(ImportError("每行必须是一个 vmess:// 分享链接"))?;
        let encoded = raw.split('#').next().unwrap_or("");
        if encoded.is_empty()
            || encoded.len() > 11_000
            || !encoded
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_+/=-".contains(&c))
        {
            return Err(ImportError("VMess 分享链接编码不正确"));
        }
        let normalized = Zeroizing::new(encoded.replace('-', "+").replace('_', "/"));
        let decoded = Zeroizing::new(
            decoder
                .decode(normalized.as_bytes())
                .map_err(|_| ImportError("VMess 分享链接无法解析"))?,
        );
        let value = SecretJson(
            serde_json::from_slice::<Value>(&decoded)
                .map_err(|_| ImportError("VMess 分享链接无法解析"))?,
        );
        let proxy = parse_one(&value.0)?;
        if !seen.insert((proxy.address.clone(), proxy.port)) {
            return Err(ImportError("列表包含重复地址和端口"));
        }
        result.push(proxy);
    }
    if result.is_empty() {
        return Err(ImportError("请填写至少一个 VMess 链接"));
    }
    Ok(result)
}
/// Reject the entire DNS response if any answer is not a public IPv4. The
/// caller must pin this result in Xray and never resolve it again afterwards.
pub fn pin_answers(answers: &[IpAddr]) -> Result<Ipv4Addr, ImportError> {
    let mut values = BTreeMap::new();
    for answer in answers {
        match answer {
            IpAddr::V4(ip) if public_ipv4(*ip) => {
                values.insert(ip.to_string(), *ip);
            }
            _ => return Err(ImportError("VMess 域名解析包含非公网地址")),
        }
    }
    values
        .into_values()
        .next()
        .ok_or(ImportError("VMess 服务器没有 IPv4 地址"))
}
static DNS_LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();
async fn resolve_task<F>(
    limit: Arc<Semaphore>,
    deadline: Duration,
    lookup: F,
) -> Result<Ipv4Addr, ImportError>
where
    F: FnOnce() -> std::io::Result<Vec<Ipv4Addr>> + Send + 'static,
{
    let permit = tokio::time::timeout(deadline, limit.acquire_owned())
        .await
        .map_err(|_| ImportError("VMess 服务器域名解析超时"))?
        .map_err(|_| ImportError("VMess 服务器域名解析失败"))?;
    // A timed-out getaddrinfo call cannot be cancelled; its permit stays held
    // until the blocking call actually returns, bounding stuck resolver jobs.
    let job = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        lookup()
    });
    let answers = tokio::time::timeout(deadline, job)
        .await
        .map_err(|_| ImportError("VMess 服务器域名解析超时"))?
        .map_err(|_| ImportError("VMess 服务器域名解析失败"))?
        .map_err(|_| ImportError("VMess 服务器域名解析失败"))?;
    if answers.len() > 100 {
        return Err(ImportError("VMess 服务器解析结果过多"));
    }
    pin_answers(&answers.into_iter().map(IpAddr::V4).collect::<Vec<_>>())
}
/// Resolve once with bounded concurrent lookups and reject every private or
/// reserved IPv4 answer. Supply the returned address directly to `outbound`.
pub async fn resolve_public(proxy: &VmessProxy) -> Result<Ipv4Addr, ImportError> {
    if let Ok(address) = proxy.address.parse::<Ipv4Addr>() {
        return if public_ipv4(address) {
            Ok(address)
        } else {
            Err(ImportError("VMess 服务器解析地址无效"))
        };
    }
    let host = proxy.address.clone();
    let port = proxy.port;
    let limit = DNS_LIMIT
        .get_or_init(|| Arc::new(Semaphore::new(4)))
        .clone();
    resolve_task(limit, Duration::from_secs(8), move || {
        Ok((host.as_str(), port)
            .to_socket_addrs()?
            .filter_map(|answer| match answer.ip() {
                IpAddr::V4(value) => Some(value),
                IpAddr::V6(_) => None,
            })
            .take(101)
            .collect())
    })
    .await
}

impl VmessProxy {
    /// Revalidate an existing worker record before reusing its credentials.
    pub fn from_record(value: &Value) -> Result<Self, ImportError> {
        let object = value
            .as_object()
            .ok_or(ImportError("VMess 代理字段不正确"))?;
        const FIELDS: &[&str] = &[
            "address",
            "port",
            "uuid",
            "security",
            "network",
            "tls",
            "server_name",
            "host",
            "path",
            "alpn",
            "fingerprint",
        ];
        if object.len() != FIELDS.len() || FIELDS.iter().any(|key| !object.contains_key(*key)) {
            return Err(ImportError("VMess 代理字段不正确"));
        }
        for key in [
            "address",
            "uuid",
            "security",
            "network",
            "server_name",
            "host",
            "path",
            "alpn",
            "fingerprint",
        ] {
            if !object[key].is_string() {
                return Err(ImportError("VMess 字段格式或长度不正确"));
            }
        }
        if !object["port"]
            .as_u64()
            .is_some_and(|port| (1..=65535).contains(&port))
            || object["security"].as_str() == Some("")
        {
            return Err(ImportError("VMess 端口或加密方式不正确"));
        }
        let id = object["uuid"]
            .as_str()
            .ok_or(ImportError("VMess UUID 不正确"))?;
        let parsed = Uuid::parse_str(id).map_err(|_| ImportError("VMess UUID 不正确"))?;
        if parsed.hyphenated().to_string() != id {
            return Err(ImportError("VMess UUID 不正确"));
        }
        let network = object["network"]
            .as_str()
            .ok_or(ImportError("VMess 支持 TCP、WebSocket 和 gRPC 传输"))?;
        if !["tcp", "ws", "grpc"].contains(&network)
            || network == "ws" && object["path"].as_str() == Some("")
        {
            return Err(ImportError("VMess 传输路径不正确"));
        }
        let tls = object["tls"]
            .as_bool()
            .ok_or(ImportError("VMess TLS 开关不正确"))?;
        let mut link = SecretJson::new(
            json!({"add":object["address"],"port":object["port"],"id":id,"scy":object["security"],
            "net":network,"tls":if tls {"tls"} else {""},"sni":object["server_name"],"host":object["host"],
            "path":object["path"],"alpn":object["alpn"],"fp":object["fingerprint"]}),
        );
        if network == "grpc" {
            link.value_mut()["serviceName"] = object["path"].clone();
        }
        parse_one(link.as_value())
    }
    pub fn address(&self) -> &str {
        &self.address
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub(crate) fn record(&self) -> SecretJson {
        SecretJson::new(
            json!({"address":self.address,"port":self.port,"uuid":self.uuid.as_str(),"security":self.security,
            "network":self.network,"tls":self.tls,"server_name":self.server_name,"host":self.host,"path":self.path,
            "alpn":self.alpn,"fingerprint":self.fingerprint}),
        )
    }
    pub fn outbound(&self, ip: Ipv4Addr) -> Result<SecretJson, ImportError> {
        if !public_ipv4(ip) {
            return Err(ImportError("VMess 服务器解析地址无效"));
        }
        let mut stream =
            json!({"network":self.network,"security":if self.tls {"tls"} else {"none"}});
        if self.network == "ws" {
            stream["wsSettings"] = json!({"path":self.path,"headers":{"Host":if self.host.is_empty(){&self.address}else{&self.host}}});
        }
        if self.network == "grpc" {
            stream["grpcSettings"] = json!({"serviceName":self.path,"authority":if !self.host.is_empty(){&self.host}else if !self.server_name.is_empty(){&self.server_name}else{&self.address}});
        }
        if self.tls {
            let name = if !self.server_name.is_empty() {
                &self.server_name
            } else if !self.host.is_empty() {
                &self.host
            } else {
                &self.address
            };
            let mut tls = json!({"serverName":name,"allowInsecure":false,"useSystemCA":true});
            if !self.alpn.is_empty() {
                tls["alpn"] = json!(self.alpn.split(',').collect::<Vec<_>>());
            } else if self.network == "grpc" {
                tls["alpn"] = json!(["h2"]);
            }
            if !self.fingerprint.is_empty() {
                tls["fingerprint"] = json!(self.fingerprint);
            }
            stream["tlsSettings"] = tls;
        }
        Ok(SecretJson(
            json!({"protocol":"vmess","settings":{"vnext":[{"address":ip.to_string(),"port":self.port,
            "users":[{"id":self.uuid.as_str(),"security":self.security}]}]},"streamSettings":stream}),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    fn link(value: &Value) -> String {
        format!(
            "vmess://{}",
            STANDARD.encode(serde_json::to_vec(value).unwrap())
        )
    }
    #[test]
    fn parses_websocket_and_pins_a_public_outbound() {
        let input = json!({"v":"2","add":"Example.COM","port":"443","id":"11111111-2222-3333-4444-555555555555",
            "aid":"0","net":"ws","tls":"tls","host":"cdn.example.com","sni":"edge.example.com","path":"/fixture","alpn":"h2,http/1.1","fp":"chrome"});
        let values = parse_links(&link(&input)).unwrap();
        assert_eq!(values[0].address(), "example.com");
        assert_eq!(values[0].port(), 443);
        let ip = "8.8.8.8".parse().unwrap();
        assert_eq!(
            values[0].outbound(ip).unwrap().as_value(),
            &json!({"protocol":"vmess","settings":{"vnext":[{"address":"8.8.8.8","port":443,
            "users":[{"id":"11111111-2222-3333-4444-555555555555","security":"auto"}]}]},"streamSettings":{"network":"ws","security":"tls",
            "wsSettings":{"path":"/fixture","headers":{"Host":"cdn.example.com"}},"tlsSettings":{"serverName":"edge.example.com",
            "allowInsecure":false,"useSystemCA":true,"alpn":["h2","http/1.1"],"fingerprint":"chrome"}}})
        );
    }
    #[test]
    fn grpc_defaults_and_dns_answers_are_checked() {
        let input = json!({"add":"example.com","port":443,"id":"11111111222233334444555555555555","net":"grpc","tls":"tls","serviceName":"service"});
        let values = parse_links(&link(&input)).unwrap();
        let output = values[0].outbound("1.1.1.1".parse().unwrap()).unwrap();
        assert_eq!(
            output.as_value()["streamSettings"]["grpcSettings"]["serviceName"],
            "service"
        );
        assert_eq!(
            output.as_value()["streamSettings"]["tlsSettings"]["alpn"],
            json!(["h2"])
        );
        assert_eq!(
            pin_answers(&["8.8.8.2".parse().unwrap(), "8.8.8.10".parse().unwrap()])
                .unwrap()
                .to_string(),
            "8.8.8.10"
        );
        assert!(pin_answers(&["8.8.8.8".parse().unwrap(), "127.0.0.1".parse().unwrap()]).is_err());
        assert!(pin_answers(&[]).is_err());
        assert!(values[0].outbound("127.0.0.1".parse().unwrap()).is_err());
    }
    #[test]
    fn rejects_insecure_unsupported_private_and_duplicate_inputs() {
        let base =
            json!({"add":"example.com","port":"443","id":"11111111-2222-3333-4444-555555555555"});
        for (key, value) in [
            ("add", json!("127.0.0.1")),
            ("add", json!("thing.local")),
            ("port", json!(0)),
            ("aid", json!(1)),
            ("v", json!(1)),
            ("allowInsecure", json!(true)),
            ("unknown", json!("x")),
            ("tls", json!("reality")),
            ("net", json!("quic")),
            ("sni", json!("edge.example.com")),
            ("path", json!("/wrong")),
        ] {
            let mut input = base.clone();
            input[key] = value;
            assert!(
                parse_links(&link(&input)).is_err(),
                "invalid fixture accepted"
            );
        }
        let original = link(&base);
        assert!(parse_links(&format!("{original}\n{original}")).is_err());
        assert!(parse_links("vmess://%%% ").is_err());
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn timed_out_dns_keeps_its_slot_until_the_blocking_lookup_finishes() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        struct Release(Arc<AtomicBool>);
        impl Drop for Release {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let limit = Arc::new(Semaphore::new(1));
        let gate = Arc::new(AtomicBool::new(false));
        let _release = Release(gate.clone());
        let calls = Arc::new(AtomicUsize::new(0));
        let (started, ready) = tokio::sync::oneshot::channel();
        let first_gate = gate.clone();
        let first_calls = calls.clone();
        let first = tokio::spawn(resolve_task(
            limit.clone(),
            Duration::from_millis(100),
            move || {
                first_calls.fetch_add(1, Ordering::SeqCst);
                let _ = started.send(());
                while !first_gate.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(vec!["8.8.8.8".parse().unwrap()])
            },
        ));
        tokio::time::timeout(Duration::from_secs(2), ready)
            .await
            .unwrap()
            .unwrap();
        assert!(first.await.unwrap().is_err());
        let second_calls = calls.clone();
        let second = resolve_task(limit.clone(), Duration::from_millis(50), move || {
            second_calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec!["1.1.1.1".parse().unwrap()])
        })
        .await;
        gate.store(true, Ordering::SeqCst);
        assert!(second.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::timeout(Duration::from_secs(2), async {
            while limit.available_permits() == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            resolve_task(limit, Duration::from_secs(1), || Ok(vec!["1.1.1.1"
                .parse()
                .unwrap()]))
            .await
            .unwrap()
            .to_string(),
            "1.1.1.1"
        );
    }
}
