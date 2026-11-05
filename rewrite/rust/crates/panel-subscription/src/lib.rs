//! Experimental legacy-compatible connection links and generic subscriptions.
//! Clash, Shadowrocket rules and HTTP authentication are not implemented here.
//! Returned links contain credentials and must not be logged.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::Value;
mod store;
pub use store::{ClashInput, StoreError, SubscriptionStore};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidConfiguration,
    Inactive,
}
type Result<T> = std::result::Result<T, Error>;

// Deliberately no Debug: token and UUID are connection credentials.
#[derive(Deserialize)]
pub struct User {
    pub name: String,
    pub uuid: String,
    pub token: String,
    pub enabled: bool,
    pub deleted: bool,
    pub quota: i64,
    pub expires: i64,
    pub upload: i64,
    pub download: i64,
}
pub struct Links {
    pub entries: Vec<(String, String)>,
    inbound_tags: Vec<String>,
}
impl Links {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
    pub fn generic_subscription(&self, user: &User, now: i64) -> Result<(String, String)> {
        if user.deleted
            || xcli_panel_users::status(
                user.enabled,
                user.expires,
                user.quota,
                user.upload,
                user.download,
                now,
            ) != "active"
        {
            return Err(Error::Inactive);
        }
        let mut text = String::new();
        for tag in &self.inbound_tags {
            if let Some(value) = self.get(tag) {
                text.push_str(value);
                text.push('\n');
            }
        }
        for (tag, value) in &self.entries {
            if tag.starts_with("remote-") {
                text.push_str(value);
                text.push('\n');
            }
        }
        Ok((
            STANDARD.encode(text.as_bytes()),
            format!(
                "upload={}; download={}; total={}; expire={}",
                user.upload, user.download, user.quota, user.expires
            ),
        ))
    }
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Error::InvalidConfiguration)
}
fn flag(value: &Value, key: &str, default: bool) -> Result<bool> {
    value.get(key).map_or(Ok(default), |v| {
        v.as_bool().ok_or(Error::InvalidConfiguration)
    })
}
fn port(value: &Value, key: &str, default: i64) -> Result<i64> {
    let port = value.get(key).map_or(Ok(default), |v| {
        v.as_i64().ok_or(Error::InvalidConfiguration)
    })?;
    if !(0..=65535).contains(&port) {
        return Err(Error::InvalidConfiguration);
    }
    Ok(port)
}
fn quote(value: &str, plus: bool, safe_slash: bool) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || safe_slash && byte == b'/'
        {
            out.push(byte as char);
        } else if plus && byte == b' ' {
            out.push('+');
        } else {
            out.push('%');
            out.push(DIGITS[(byte >> 4) as usize] as char);
            out.push(DIGITS[(byte & 15) as usize] as char);
        }
    }
    out
}
#[derive(Serialize)]
struct Vmess<'a> {
    v: &'a str,
    ps: String,
    add: &'a str,
    port: String,
    id: &'a str,
    aid: &'a str,
    scy: &'a str,
    net: &'a str,
    r#type: &'a str,
    host: &'a str,
    path: &'a str,
    tls: &'a str,
    sni: &'a str,
}

/// `remote_nodes` must already be filtered to enabled nodes with an applied
/// grant for this user's current UUID, exactly as the old panel does.
pub fn build(
    settings: &Value,
    user: &User,
    remote_nodes: &[Value],
    dynamic_enabled: bool,
) -> Result<Links> {
    let address = field(settings, "public_ip")?;
    let domain = field(settings, "domain")?;
    let origin = field(settings, "origin")?;
    let reality_sni = field(settings, "reality_sni")?;
    let reality_public = field(settings, "reality_public")?;
    let short_id = field(settings, "short_id")?;
    let ws_path = field(settings, "ws_path")?;
    let public_port = port(settings, "public_port", 443)?;
    if public_port == 0 {
        return Err(Error::InvalidConfiguration);
    }
    let hy2_port = port(settings, "hysteria2_port", 0)?;
    let hy2_brutal_port = port(settings, "hysteria2_brutal_port", 0)?;
    if hy2_brutal_port > 0 && (hy2_port == 0 || hy2_brutal_port == hy2_port) {
        return Err(Error::InvalidConfiguration);
    }
    let node_host = if flag(settings, "node_address_ip", false)? {
        address
    } else {
        domain
    };
    let mut entries = Vec::new();
    entries.push(("reality".into(),format!("vless://{}@{}:{}?encryption=none&fp=chrome&sni={}&pbk={}&sid={}&type=tcp&security=reality&flow=xtls-rprx-vision#{}",
        user.uuid,address,public_port,quote(reality_sni,true,false),quote(reality_public,true,false),quote(short_id,true,false),quote(&format!("{} · REALITY",user.name),false,true))));
    entries.push((
        "websocket".into(),
        format!(
            "vless://{}@{}:{}?encryption=none&security=tls&sni={}&type=ws&host={}&path={}#{}",
            user.uuid,
            node_host,
            public_port,
            quote(domain, true, false),
            quote(domain, true, false),
            quote(ws_path, true, false),
            quote(&format!("{} · HTTPS", user.name), false, true)
        ),
    ));
    entries.push(("subscription".into(), format!("{origin}/s/{}", user.token)));
    let mut inbound_tags = vec!["reality".into(), "websocket".into()];
    if hy2_port > 0 {
        inbound_tags.push("hysteria2".into());
        entries.push((
            "hysteria2".into(),
            format!(
                "hysteria2://{}@{}:{}/?sni={}#{}",
                quote(&user.uuid, false, false),
                node_host,
                hy2_port,
                quote(domain, false, false),
                quote(&format!("{} · Hysteria 2", user.name), false, true)
            ),
        ));
    }
    if hy2_brutal_port > 0 {
        inbound_tags.push("hysteria2-brutal".into());
        entries.push((
            "hysteria2-brutal".into(),
            format!(
                "hysteria2://{}@{}:{}/?sni={}#{}",
                quote(&user.uuid, false, false),
                node_host,
                hy2_brutal_port,
                quote(domain, false, false),
                quote(
                    &format!("{} · Hysteria 2 Brutal 40 Mbps", user.name),
                    false,
                    true
                )
            ),
        ));
        inbound_tags.push("hysteria2-brutal-current".into());
        entries.push((
            "hysteria2-brutal-current".into(),
            format!(
                "hysteria2://{}@{}:{}/?sni={}#{}",
                quote(&user.uuid, false, false),
                node_host,
                hy2_brutal_port,
                quote(domain, false, false),
                quote(&format!("{} · Hysteria 2 Brutal", user.name), false, true)
            ),
        ));
    }
    if settings.get("vmess_ws_path").is_some() {
        let path = field(settings, "vmess_ws_path")?;
        inbound_tags.push("vmess".into());
        let vmess = Vmess {
            v: "2",
            ps: format!("{} · VMess TLS", user.name),
            add: node_host,
            port: public_port.to_string(),
            id: &user.uuid,
            aid: "0",
            scy: "auto",
            net: "ws",
            r#type: "none",
            host: domain,
            path,
            tls: "tls",
            sni: domain,
        };
        entries.push((
            "vmess".into(),
            format!(
                "vmess://{}",
                STANDARD
                    .encode(serde_json::to_vec(&vmess).map_err(|_| Error::InvalidConfiguration)?)
            ),
        ));
    }
    let exits: Vec<Value> = settings
        .get("residential_exits")
        .map_or(Ok(Vec::new()), |value| {
            value.as_array().cloned().ok_or(Error::InvalidConfiguration)
        })?;
    for exit in &exits {
        let tag = field(exit, "tag")?;
        inbound_tags.push(tag.to_owned());
        let supports_hy2 = flag(exit, "hysteria2", false)?;
        if supports_hy2 {
            inbound_tags.push(format!("{tag}-hy2"));
        }
        let dynamic = flag(exit, "dynamic", false)?;
        if dynamic && !dynamic_enabled {
            continue;
        }
        let label = field(exit, "label")?;
        let exit_ip = field(exit, "exit_ip")?;
        let name = format!(
            "{} · {}{}",
            user.name,
            label,
            if dynamic {
                String::new()
            } else {
                format!(" · {exit_ip}")
            }
        );
        if supports_hy2 {
            if hy2_port == 0 {
                return Err(Error::InvalidConfiguration);
            }
            entries.push((
                format!("{tag}-hy2"),
                format!(
                    "hysteria2://{}@{}:{}/?sni={}#{}",
                    quote(&format!("{}.{tag}-hy2", user.uuid), false, false),
                    node_host,
                    hy2_port,
                    quote(domain, false, false),
                    quote(&name, false, true)
                ),
            ));
        }
        entries.push((
            tag.to_owned(),
            format!(
                "vless://{}@{}:{}?encryption=none&security=tls&sni={}&type=ws&host={}&path={}#{}",
                user.uuid,
                node_host,
                public_port,
                quote(domain, true, false),
                quote(domain, true, false),
                quote(field(exit, "ws_path")?, true, false),
                quote(
                    &format!("{name}{}", if supports_hy2 { " · HTTPS" } else { "" }),
                    false,
                    true
                )
            ),
        ));
    }
    for node in remote_nodes {
        let id = field(node, "id")?;
        if id.len() != 32
            || !id
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(Error::InvalidConfiguration);
        }
        let endpoint = node.get("endpoint").ok_or(Error::InvalidConfiguration)?;
        let host = field(endpoint, "public_ip")?;
        let domain = field(endpoint, "domain")?;
        let public_port = port(endpoint, "public_port", 0)?;
        let hy2_port = port(endpoint, "hysteria2_port", 0)?;
        if public_port == 0 || hy2_port == 0 {
            return Err(Error::InvalidConfiguration);
        }
        let name = format!(
            "{} · 节点 {} · {}",
            user.name,
            &id[..8],
            field(node, "name")?
        );
        entries.push((format!("remote-{id}-reality"),format!("vless://{}@{}:{}?encryption=none&fp=chrome&sni={}&pbk={}&sid={}&type=tcp&security=reality&flow=xtls-rprx-vision#{}",
            user.uuid,host,public_port,quote(field(endpoint,"reality_sni")?,true,false),quote(field(endpoint,"reality_public")?,true,false),
            quote(field(endpoint,"short_id")?,true,false),quote(&format!("{name} · REALITY"),false,true))));
        entries.push((
            format!("remote-{id}-websocket"),
            format!(
                "vless://{}@{}:{}?encryption=none&security=tls&sni={}&type=ws&host={}&path={}#{}",
                user.uuid,
                host,
                public_port,
                quote(domain, true, false),
                quote(domain, true, false),
                quote(field(endpoint, "ws_path")?, true, false),
                quote(&format!("{name} · HTTPS"), false, true)
            ),
        ));
        entries.push((
            format!("remote-{id}-hysteria2"),
            format!(
                "hysteria2://{}@{}:{}/?sni={}#{}",
                quote(&user.uuid, false, false),
                host,
                hy2_port,
                quote(domain, false, false),
                quote(&format!("{name} · Hysteria 2"), false, true)
            ),
        ));
    }
    Ok(Links {
        entries,
        inbound_tags,
    })
}
