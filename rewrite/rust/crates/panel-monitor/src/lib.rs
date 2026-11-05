//! Experimental client configuration for gateway self-tests. This is not a
//! monitor service and does not launch a process or access the network.
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

mod dns;
pub mod report;
pub mod requests;
pub mod runner;
pub mod service;
pub mod status;
pub mod store;
pub mod udp;

#[derive(Debug, PartialEq, Eq)]
pub struct Invalid;
type Result<T> = std::result::Result<T, Invalid>;
pub struct Sensitive(Value);
impl Sensitive {
    pub fn as_value(&self) -> &Value {
        &self.0
    }
}
impl Drop for Sensitive {
    fn drop(&mut self) {
        fn scrub(value: &mut Value) {
            match value {
                Value::String(text) => text.zeroize(),
                Value::Array(items) => items.iter_mut().for_each(scrub),
                Value::Object(items) => items.values_mut().for_each(scrub),
                _ => (),
            }
        }
        scrub(&mut self.0);
    }
}
pub struct Config {
    value: Sensitive,
    kinds: Vec<String>,
}
pub struct SocksAuth {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}
impl SocksAuth {
    /// One random account per temporary probe process; never expose it in a report.
    pub fn random() -> Result<Self> {
        let mut user = Zeroizing::new([0u8; 12]);
        let mut pass = Zeroizing::new([0u8; 24]);
        getrandom::fill(user.as_mut()).map_err(|_| Invalid)?;
        getrandom::fill(pass.as_mut()).map_err(|_| Invalid)?;
        Ok(Self {
            username: Zeroizing::new(hex::encode(user.as_ref())),
            password: Zeroizing::new(hex::encode(pass.as_ref())),
        })
    }
}
fn text<'a>(value: &'a Value, key: &str, maximum: usize) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= maximum
                && !value.chars().any(|c| c < ' ' || c == '\u{7f}')
        })
        .ok_or(Invalid)
}
fn tag(value: &str) -> bool {
    value
        .strip_prefix("residential-")
        .is_some_and(|digits| digits.len() == 2 && digits.bytes().all(|c| c.is_ascii_digit()))
}
fn port(value: &Value, key: &str, default: u16) -> Result<u16> {
    match value.get(key) {
        None => Ok(default),
        Some(value) => value
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0)
            .ok_or(Invalid),
    }
}
impl Config {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 1_048_576 {
            return Err(Invalid);
        }
        let value = Sensitive(serde_json::from_slice(bytes).map_err(|_| Invalid)?);
        let cfg = value.as_value();
        if !cfg.is_object() {
            return Err(Invalid);
        }
        text(cfg, "domain", 253)?;
        text(cfg, "public_ip", 15)?
            .parse::<Ipv4Addr>()
            .map_err(|_| Invalid)?;
        text(cfg, "reality_sni", 253)?;
        text(cfg, "reality_public", 512)?;
        text(cfg, "short_id", 32)?;
        let uuid = text(cfg, "uuid", 36)?;
        Uuid::parse_str(uuid).map_err(|_| Invalid)?;
        if !text(cfg, "ws_path", 1024)?.starts_with('/') {
            return Err(Invalid);
        }
        port(cfg, "public_port", 443)?;
        if cfg
            .get("node_address_ip")
            .is_some_and(|value| !value.is_boolean())
        {
            return Err(Invalid);
        }
        let mut kinds = vec!["reality".to_owned(), "websocket".to_owned()];
        if let Some(value) = cfg.get("hysteria2_port") {
            if value != 0 {
                port(cfg, "hysteria2_port", 443)?;
                kinds.push("hysteria2".to_owned());
            }
        }
        if let Some(value) = cfg.get("vmess_ws_path") {
            if !value.is_null() && value != "" {
                if !text(cfg, "vmess_ws_path", 1024)?.starts_with('/') {
                    return Err(Invalid);
                }
                kinds.push("vmess".to_owned());
            }
        }
        let mut seen = BTreeSet::new();
        if let Some(exits) = cfg.get("residential_exits") {
            let exits = exits
                .as_array()
                .filter(|items| items.len() <= 40)
                .ok_or(Invalid)?;
            for entry in exits {
                let name = text(entry, "tag", 14)?;
                if !tag(name) || !seen.insert(name.to_owned()) {
                    return Err(Invalid);
                }
                text(entry, "exit_ip", 15)?
                    .parse::<Ipv4Addr>()
                    .map_err(|_| Invalid)?;
                let hy2 = entry
                    .get("hysteria2")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if entry
                    .get("hysteria2")
                    .is_some_and(|value| !value.is_boolean())
                {
                    return Err(Invalid);
                }
                if hy2 {
                    if !kinds.iter().any(|kind| kind == "hysteria2") {
                        return Err(Invalid);
                    }
                } else if !text(entry, "ws_path", 1024)?.starts_with('/') {
                    return Err(Invalid);
                }
                kinds.push(name.to_owned());
            }
        }
        Ok(Self { value, kinds })
    }
    pub fn kinds(&self) -> &[String] {
        &self.kinds
    }
    pub fn residential(&self, kind: &str) -> bool {
        self.value.as_value()["residential_exits"]
            .as_array()
            .is_some_and(|items| items.iter().any(|entry| entry["tag"] == kind))
    }
    pub fn expected_exit(&self, kind: &str) -> Result<Ipv4Addr> {
        if !self.kinds.iter().any(|value| value == kind) {
            return Err(Invalid);
        }
        let cfg = self.value.as_value();
        let value = cfg["residential_exits"]
            .as_array()
            .and_then(|items| items.iter().find(|entry| entry["tag"] == kind))
            .map_or(&cfg["public_ip"], |entry| &entry["exit_ip"]);
        value
            .as_str()
            .and_then(|value| value.parse().ok())
            .ok_or(Invalid)
    }
    /// A private, zeroized client configuration for an isolated Xray probe.
    pub fn legacy_client_for_compatibility(
        &self,
        kind: &str,
        local_port: u16,
    ) -> Result<Sensitive> {
        if local_port == 0 || !self.kinds.iter().any(|value| value == kind) {
            return Err(Invalid);
        }
        let cfg = self.value.as_value();
        let exit = cfg["residential_exits"]
            .as_array()
            .and_then(|items| items.iter().find(|entry| entry["tag"] == kind));
        let transport = match exit {
            Some(entry) if entry["hysteria2"] == true => "hysteria2",
            Some(_) => "websocket",
            None => kind,
        };
        let id = text(cfg, "uuid", 36)?;
        let domain = text(cfg, "domain", 253)?;
        let public_ip = text(cfg, "public_ip", 15)?;
        let public_port = port(cfg, "public_port", 443)?;
        let outbound = if transport == "hysteria2" {
            let auth = if exit.is_some() {
                format!("{id}.{kind}-hy2")
            } else {
                id.to_owned()
            };
            json!({"protocol":"hysteria","settings":{"version":2,"address":public_ip,"port":port(cfg,"hysteria2_port",443)?},
                "streamSettings":{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2,"auth":auth},
                    "tlsSettings":{"serverName":domain,"allowInsecure":false,"useSystemCA":true,"alpn":["h3"]},
                    "finalmask":{"quicParams":{"congestion":"bbr"}}}})
        } else {
            let (host, stream, user, protocol) = match transport {
                "reality" => (
                    public_ip,
                    json!({"network":"tcp","security":"reality","realitySettings":{
                    "serverName":text(cfg,"reality_sni",253)?,"fingerprint":"chrome","publicKey":text(cfg,"reality_public",512)?,"shortId":text(cfg,"short_id",32)?}}),
                    json!({"id":id,"encryption":"none","flow":"xtls-rprx-vision"}),
                    "vless",
                ),
                "websocket" | "vmess" => {
                    let path = if let Some(entry) = exit {
                        text(entry, "ws_path", 1024)?
                    } else if transport == "vmess" {
                        text(cfg, "vmess_ws_path", 1024)?
                    } else {
                        text(cfg, "ws_path", 1024)?
                    };
                    let stream = json!({"network":"ws","security":"tls","tlsSettings":{"serverName":domain,"allowInsecure":false,"useSystemCA":true},
                        "wsSettings":{"path":path,"headers":{"Host":domain}}});
                    let host = if cfg["node_address_ip"] == true {
                        public_ip
                    } else {
                        domain
                    };
                    let user = if transport == "vmess" {
                        json!({"id":id,"security":"auto"})
                    } else {
                        json!({"id":id,"encryption":"none"})
                    };
                    (
                        host,
                        stream,
                        user,
                        if transport == "vmess" {
                            "vmess"
                        } else {
                            "vless"
                        },
                    )
                }
                _ => return Err(Invalid),
            };
            json!({"protocol":protocol,"settings":{"vnext":[{"address":host,"port":public_port,"users":[user]}]},"streamSettings":stream})
        };
        Ok(Sensitive(
            json!({"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":local_port,
            "protocol":"socks","settings":{"auth":"noauth","udp":true}}],"outbounds":[outbound]}),
        ))
    }
    /// Production probes must use the random authenticated local listener.
    pub fn client_secured(
        &self,
        kind: &str,
        local_port: u16,
        auth: &SocksAuth,
    ) -> Result<Sensitive> {
        let mut config = self.legacy_client_for_compatibility(kind, local_port)?;
        config.0["inbounds"][0]["settings"] = json!({"auth":"password","udp":true,
            "accounts":[{"user":auth.username.as_str(),"pass":auth.password.as_str()}]});
        Ok(config)
    }
}
