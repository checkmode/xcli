//! Pure candidate construction for fixed proxies. No file or service changes.
//! The caller must establish that every supplied probe result belongs to the
//! matching credential, recheck snapshot digests, and apply transactionally.
use crate::probe::{ProbeResult, Protocol};
use crate::vmess::{SecretJson, VmessProxy};
use crate::vmess_probe::VmessProbeResult;
use crate::{parse_fixed, public_ipv4, ImportError, Proxy};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

pub struct Files {
    settings: SecretJson,
    core: SecretJson,
    monitor: SecretJson,
    pool: SecretJson,
    nginx: Zeroizing<String>,
    locations: Zeroizing<String>,
    had_locations: bool,
}
impl Files {
    pub fn new(
        settings: Value,
        core: Value,
        monitor: Value,
        nginx: String,
        locations: Option<String>,
        pool: Option<Value>,
    ) -> Result<Self, ImportError> {
        let settings = SecretJson::new(settings);
        let core = SecretJson::new(core);
        let monitor = SecretJson::new(monitor);
        let pool = SecretJson::new(pool.unwrap_or_else(|| json!({"proxies":[]})));
        let nginx = Zeroizing::new(nginx);
        let had_locations = locations.is_some();
        let locations = Zeroizing::new(locations.unwrap_or_default());
        if !settings.as_value().is_object()
            || !core.as_value().is_object()
            || !monitor.as_value().is_object()
            || nginx.len() > 1_048_576
            || locations.len() > 1_048_576
        {
            return Err(ImportError("服务器配置不完整，未修改配置"));
        }
        Ok(Self {
            settings,
            core,
            monitor,
            pool,
            nginx,
            locations,
            had_locations,
        })
    }
    pub fn settings(&self) -> &Value {
        self.settings.as_value()
    }
    pub fn core(&self) -> &Value {
        self.core.as_value()
    }
    pub fn monitor(&self) -> &Value {
        self.monitor.as_value()
    }
    pub fn pool(&self) -> &Value {
        self.pool.as_value()
    }
    pub fn nginx(&self) -> &str {
        &self.nginx
    }
    pub fn locations(&self) -> &str {
        &self.locations
    }
}
pub struct Verified<'a> {
    pub proxy: &'a Proxy,
    pub protocol: Protocol,
    pub result: &'a ProbeResult,
}
pub struct VerifiedVmess<'a> {
    pub proxy: &'a VmessProxy,
    pub result: &'a VmessProbeResult,
}
struct Prepared {
    address: String,
    port: u16,
    protocol: &'static str,
    exit_ip: std::net::Ipv4Addr,
    country: String,
    server_ip: Option<std::net::Ipv4Addr>,
    outbound: SecretJson,
    record: SecretJson,
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, ImportError> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or(ImportError("服务器配置不完整，未修改配置"))
}
fn array_mut<'a>(value: &'a mut Value, key: &str) -> Result<&'a mut Vec<Value>, ImportError> {
    value
        .get_mut(key)
        .and_then(Value::as_array_mut)
        .ok_or(ImportError("服务器配置不完整，未修改配置"))
}
fn ensure_array<'a>(value: &'a mut Value, key: &str) -> Result<&'a mut Vec<Value>, ImportError> {
    let object = value
        .as_object_mut()
        .ok_or(ImportError("服务器配置不完整，未修改配置"))?;
    object
        .entry(key)
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or(ImportError("服务器配置不完整，未修改配置"))
}
fn country_name(code: &str) -> &str {
    match code {
        "US" => "美国",
        "JP" => "日本",
        "SG" => "新加坡",
        "HK" => "香港",
        "TW" => "台湾",
        "KR" => "韩国",
        "TH" => "泰国",
        "MY" => "马来西亚",
        "IN" => "印度",
        "CA" => "加拿大",
        "GB" => "英国",
        "DE" => "德国",
        "FR" => "法国",
        "NL" => "荷兰",
        "AU" => "澳大利亚",
        _ => code,
    }
}
fn valid_path(path: &str) -> bool {
    path.strip_prefix("/connect/").is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    })
}
fn peer(value: &Value) -> Option<(String, u16)> {
    Some((
        value.get("address")?.as_str()?.to_owned(),
        u16::try_from(value.get("port")?.as_u64()?).ok()?,
    ))
}
fn existing_peers(core: &Value) -> Result<BTreeSet<(String, u16)>, ImportError> {
    peers_except(core, None)
}
fn peers_except(
    core: &Value,
    excluded: Option<&str>,
) -> Result<BTreeSet<(String, u16)>, ImportError> {
    let mut result = BTreeSet::new();
    for outbound in array(core, "outbounds")? {
        if excluded.is_some_and(|tag| outbound.get("tag").and_then(Value::as_str) == Some(tag)) {
            continue;
        }
        let entries = match outbound.get("protocol").and_then(Value::as_str) {
            Some("socks" | "http") => outbound
                .pointer("/settings/servers")
                .and_then(Value::as_array),
            Some("vmess") => outbound
                .pointer("/settings/vnext")
                .and_then(Value::as_array),
            _ => None,
        };
        if let Some(entries) = entries {
            for item in entries {
                if let Some(value) = peer(item) {
                    result.insert(value);
                }
            }
        }
    }
    Ok(result)
}
fn subscription_rule(rule: &Value, settings: &Value, core: &Value) -> bool {
    let Some(tag) = rule.get("ruleTag").and_then(Value::as_str) else {
        return false;
    };
    let Some(id) = tag.strip_prefix("subscription-https-") else {
        return false;
    };
    let pattern = if id == "all" {
        "regexp:^[0-9a-f]{32}\\.[0-9a-f]{8}@".to_owned()
    } else if id.len() == 32
        && id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        format!("regexp:^{id}\\.[0-9a-f]{{8}}@")
    } else {
        return false;
    };
    let Some(ip) = settings
        .get("public_ip")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<std::net::Ipv4Addr>().ok())
        .filter(|ip| public_ipv4(*ip))
    else {
        return false;
    };
    let port = settings
        .get("public_port")
        .and_then(Value::as_u64)
        .unwrap_or(443)
        .to_string();
    if *rule
        != json!({"type":"field","ruleTag":tag,"user":[pattern],"ip":[format!("{ip}/32")],"port":port,"network":"tcp","outboundTag":"direct"})
    {
        return false;
    }
    core.get("outbounds")
        .and_then(Value::as_array)
        .is_some_and(|outbounds| {
            outbounds
                .iter()
                .any(|item| item["tag"] == "direct" && item["protocol"] == "freedom")
        })
        && core
            .pointer("/routing/rules")
            .and_then(Value::as_array)
            .is_some_and(|rules| {
                rules.iter().any(|item| {
                    item["outboundTag"] == "blocked"
                        && item
                            .get("ip")
                            .and_then(Value::as_array)
                            .is_some_and(|ips| ips.iter().any(|value| value == &format!("{ip}/32")))
                })
            })
}

/// Produce a candidate only. A successful return does not authorize writes or
/// prove the probes were run; the worker must bind probe results to its input.
pub fn add_fixed(
    files: Files,
    inputs: &[Verified<'_>],
    label: &str,
) -> Result<(Files, Vec<Value>), ImportError> {
    if inputs.is_empty() || inputs.len() > 20 {
        return Err(ImportError("代理数量或名称不正确"));
    }
    let mut prepared = Vec::new();
    for input in inputs {
        if !public_ipv4(input.proxy.address) || input.proxy.port == 0 {
            return Err(ImportError("代理或出口地址无效"));
        }
        let address = input.proxy.address.to_string();
        let port = input.proxy.port;
        let protocol = input.protocol.name();
        let outbound = SecretJson::new(
            json!({"protocol":protocol,"settings":{"servers":[{"address":address,"port":port,
            "users":[{"user":input.proxy.username(),"pass":input.proxy.password()}]}]}}),
        );
        let record = SecretJson::new(
            json!({"address":address,"port":port,"username":input.proxy.username(),"password":input.proxy.password()}),
        );
        prepared.push(Prepared {
            address,
            port,
            protocol,
            exit_ip: input.result.exit_ip,
            country: input.result.country.clone(),
            server_ip: None,
            outbound,
            record,
        });
    }
    add_prepared(files, &prepared, label)
}
/// VMess candidates use the exact public server address verified by the probe.
pub fn add_vmess(
    files: Files,
    inputs: &[VerifiedVmess<'_>],
    label: &str,
) -> Result<(Files, Vec<Value>), ImportError> {
    if inputs.is_empty() || inputs.len() > 20 {
        return Err(ImportError("代理数量或名称不正确"));
    }
    let mut prepared = Vec::new();
    for input in inputs {
        let ip = input.result.server_ip;
        if input
            .proxy
            .address()
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|literal| literal != ip)
        {
            return Err(ImportError("VMess 服务器解析地址无效"));
        }
        let outbound = input.proxy.outbound(ip)?;
        prepared.push(Prepared {
            address: input.proxy.address().to_owned(),
            port: input.proxy.port(),
            protocol: "vmess",
            exit_ip: input.result.observed.exit_ip,
            country: input.result.observed.country.clone(),
            server_ip: Some(ip),
            outbound,
            record: input.proxy.record(),
        });
    }
    add_prepared(files, &prepared, label)
}
fn add_prepared(
    mut files: Files,
    inputs: &[Prepared],
    label: &str,
) -> Result<(Files, Vec<Value>), ImportError> {
    if inputs.is_empty()
        || inputs.len() > 20
        || label.is_empty()
        || label.chars().count() > 30
        || label.chars().any(|c| c < ' ')
    {
        return Err(ImportError("代理数量或名称不正确"));
    }
    let settings = files.settings.as_value();
    let core = files.core.as_value();
    let exits = settings
        .get("residential_exits")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if exits
        .iter()
        .any(|entry| entry.get("tag").and_then(Value::as_str).is_none())
    {
        return Err(ImportError("代理记录与入口不一致，请检查配置"));
    }
    if exits.len() + inputs.len() > 40 {
        return Err(ImportError(
            "固定和动态入口合计最多 40 个，请减少本次导入数量",
        ));
    }
    let rules = core
        .pointer("/routing/rules")
        .and_then(Value::as_array)
        .ok_or(ImportError("服务器配置不完整，未修改配置"))?;
    if rules.iter().any(|rule| {
        let scoped = rule
            .get("inboundTag")
            .and_then(Value::as_array)
            .is_some_and(|tags| !tags.is_empty());
        let blocked = rule
            .get("ip")
            .and_then(Value::as_array)
            .is_some_and(|ips| !ips.is_empty())
            && rule["outboundTag"] == "blocked";
        !scoped && !blocked && !subscription_rule(rule, settings, core)
    }) {
        return Err(ImportError("现有自定义全局路由需要人工检查，未修改配置"));
    }
    let path = settings
        .get("ws_path")
        .and_then(Value::as_str)
        .filter(|path| valid_path(path))
        .ok_or(ImportError("现有入口路径需要人工检查"))?
        .to_owned();
    let hysteria = settings
        .get("hysteria2_port")
        .and_then(Value::as_u64)
        .is_some_and(|port| port != 0)
        && array(core, "inbounds")?
            .iter()
            .any(|entry| entry["tag"] == "hysteria2" && entry["protocol"] == "hysteria");
    let mut tags = BTreeSet::new();
    let mut ports = BTreeSet::new();
    for entry in array(core, "inbounds")? {
        let tag = entry
            .get("tag")
            .and_then(Value::as_str)
            .ok_or(ImportError("服务器配置不完整，未修改配置"))?;
        tags.insert(tag.to_owned());
        if let Some(port) = entry.get("port").and_then(Value::as_u64) {
            ports.insert(port);
        }
    }
    for entry in array(core, "outbounds")? {
        tags.insert(
            entry
                .get("tag")
                .and_then(Value::as_str)
                .ok_or(ImportError("服务器配置不完整，未修改配置"))?
                .to_owned(),
        );
    }
    let mut peers = existing_peers(core)?;
    let entries_by_tag: BTreeMap<_, _> = exits
        .iter()
        .filter_map(|entry| {
            entry
                .get("tag")
                .and_then(Value::as_str)
                .map(|tag| (tag.to_owned(), entry.clone()))
        })
        .collect();
    let pool = array_mut(files.pool.value_mut(), "proxies")?;
    for item in pool.iter_mut() {
        let tag = item
            .get("tag")
            .and_then(Value::as_str)
            .ok_or(ImportError("代理记录与入口不一致，请检查配置"))?
            .to_owned();
        if item.get("entry").is_none() {
            item["entry"] = entries_by_tag
                .get(&tag)
                .cloned()
                .ok_or(ImportError("代理记录与入口不一致，请检查配置"))?;
        }
        let object = item
            .as_object_mut()
            .ok_or(ImportError("代理记录与入口不一致，请检查配置"))?;
        object.entry("enabled").or_insert(json!(true));
        object.entry("deleted_at").or_insert(json!(0));
        tags.insert(tag);
        if let Some(port) = item.pointer("/entry/port").and_then(Value::as_u64) {
            ports.insert(port);
        }
        if let Some(value) = peer(item) {
            peers.insert(value);
        }
    }
    let inventory_tags: BTreeSet<_> = pool
        .iter()
        .filter_map(|item| item.get("tag").and_then(Value::as_str))
        .collect();
    let unmanaged = exits
        .iter()
        .filter(|entry| {
            entry
                .get("tag")
                .and_then(Value::as_str)
                .is_none_or(|tag| !inventory_tags.contains(tag))
        })
        .count();
    if unmanaged + inventory_tags.len() + inputs.len() > 40 {
        return Err(ImportError(
            "入口与回收站合计最多 40 个，已保留找回所需的编号和端口",
        ));
    }
    for input in inputs {
        let address = input.address.clone();
        let port = input.port;
        if port == 0
            || !public_ipv4(input.exit_ip)
            || input.country.len() != 2
            || !input.country.bytes().all(|c| c.is_ascii_uppercase())
        {
            return Err(ImportError("代理或出口地址无效"));
        }
        if !peers.insert((address, port)) {
            return Err(ImportError("列表包含已接入的代理地址和端口，请移除重复项"));
        }
    }
    let include = "include /etc/nginx/xcli-import-locations.conf;";
    let marker = format!("location = {path} {{");
    if files.had_locations {
        if !files.nginx.contains(include) {
            return Err(ImportError("既有导入入口与 Nginx 配置不一致"));
        }
    } else {
        if files.nginx.contains(include) || !files.nginx.contains(&marker) {
            return Err(ImportError("无法定位 Nginx 入口"));
        }
        *files.nginx = files
            .nginx
            .replace(&marker, &format!("{include}\n        {marker}"));
    }
    let mut entries = Vec::new();
    for input in inputs {
        let number = (27..100)
            .find(|number| {
                !tags.contains(&format!("residential-{number:02}"))
                    && !tags.contains(&format!("residential-{number:02}-exit"))
            })
            .ok_or(ImportError("没有可用入口编号或端口"))?;
        let port = (10450..10550)
            .find(|port| !ports.contains(port))
            .ok_or(ImportError("没有可用入口编号或端口"))?;
        let tag = format!("residential-{number:02}");
        tags.insert(tag.clone());
        ports.insert(port);
        let entry_path = format!("{path}/{tag}");
        let mut entry = json!({"tag":tag,"label":format!("{label} {number} · {}",country_name(&input.country)),
            "exit_ip":input.exit_ip.to_string(),"country":input.country,"ws_path":entry_path,"port":port});
        if hysteria {
            entry["hysteria2"] = json!(true);
        }
        ensure_array(files.settings.value_mut(), "residential_exits")?.push(entry.clone());
        ensure_array(files.monitor.value_mut(), "residential_exits")?.push(entry.clone());
        array_mut(files.core.value_mut(),"inbounds")?.push(json!({"tag":tag,"listen":"127.0.0.1","port":port,"protocol":"vless",
            "settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"ws","wsSettings":{"path":entry_path}}}));
        let mut outbound = SecretJson::new(input.outbound.as_value().clone());
        outbound.value_mut()["tag"] = json!(format!("{tag}-exit"));
        array_mut(files.core.value_mut(), "outbounds")?.push(std::mem::take(outbound.value_mut()));
        let mut record = SecretJson::new(input.record.as_value().clone());
        record.value_mut()["tag"] = json!(tag);
        record.value_mut()["protocol"] = json!(input.protocol);
        record.value_mut()["country"] = json!(input.country);
        record.value_mut()["entry"] = entry.clone();
        record.value_mut()["enabled"] = json!(true);
        record.value_mut()["deleted_at"] = json!(0);
        if let Some(ip) = input.server_ip {
            record.value_mut()["server_ip"] = json!(ip.to_string());
        }
        array_mut(files.pool.value_mut(), "proxies")?.push(std::mem::take(record.value_mut()));
        files.locations.push_str(&format!("\nlocation = {entry_path} {{\n    proxy_pass http://127.0.0.1:{port};\n    proxy_http_version 1.1;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection $connection_upgrade;\n    proxy_set_header Host $host;\n    proxy_read_timeout 600s;\n    proxy_send_timeout 600s;\n    proxy_buffering off;\n}}\n"));
        entries.push(entry);
    }
    let rules = files
        .core
        .value_mut()
        .pointer_mut("/routing/rules")
        .and_then(Value::as_array_mut)
        .ok_or(ImportError("服务器配置不完整，未修改配置"))?;
    let all: Vec<&str> = entries
        .iter()
        .map(|entry| entry["tag"].as_str().unwrap_or(""))
        .collect();
    rules.push(json!({"type":"field","inboundTag":all,"network":"udp","outboundTag":"blocked"}));
    for entry in &entries {
        let tag = entry["tag"]
            .as_str()
            .ok_or(ImportError("服务器配置不完整，未修改配置"))?;
        rules.push(json!({"type":"field","inboundTag":[tag],"network":"tcp","outboundTag":format!("{tag}-exit")}));
    }
    if hysteria {
        for entry in &entries {
            let tag = entry["tag"]
                .as_str()
                .ok_or(ImportError("服务器配置不完整，未修改配置"))?;
            for (network, target) in [
                ("udp", "blocked".to_owned()),
                ("tcp", format!("{tag}-exit")),
            ] {
                rules.push(json!({"type":"field","ruleTag":format!("{tag}-hy2-{network}"),"inboundTag":["hysteria2"],
                "user":[format!("regexp:@{tag}-hy2$")],"network":network,"outboundTag":target}));
            }
        }
    }
    let monitor_bytes = Zeroizing::new(
        serde_json::to_vec(files.monitor.as_value())
            .map_err(|_| ImportError("探测配置容量不足，未修改配置"))?,
    );
    if monitor_bytes.len() > 16384 {
        return Err(ImportError("探测配置容量不足，未修改配置"));
    }
    Ok((files, entries))
}

/// A verified result must have been obtained for the exact stored credentials.
/// The caller owns that binding and must still apply the candidate through a
/// quiesced, recoverable transaction; constructing it never changes services.
pub enum Manage<'a> {
    Disable,
    Delete {
        now: u64,
    },
    Restore,
    Enable {
        result: &'a ProbeResult,
        server_ip: Option<std::net::Ipv4Addr>,
    },
    Edit {
        changes: &'a Value,
        result: &'a ProbeResult,
        server_ip: Option<std::net::Ipv4Addr>,
    },
}

fn replace_secret(value: &mut Value, replacement: Value) {
    drop(SecretJson::new(std::mem::replace(value, replacement)));
}

fn remove_tagged(values: &mut Vec<Value>, tag: &str) {
    for value in std::mem::take(values) {
        if value.get("tag").and_then(Value::as_str) == Some(tag) {
            drop(SecretJson::new(value));
        } else {
            values.push(value);
        }
    }
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|number| number != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

/// Build the optional VMess-over-WebSocket client entrance without writing it.
pub fn enable_vmess(mut files: Files) -> Result<(Files, Vec<Value>), ImportError> {
    if truthy(&files.settings.as_value()["vmess_ws_path"]) {
        return Err(ImportError("VMess 客户端入口已经启用"));
    }
    if array(files.core.as_value(), "inbounds")?
        .iter()
        .any(|entry| entry["tag"] == "vmess" || entry["port"] == 10081)
    {
        return Err(ImportError("VMess 入口编号或端口已被占用"));
    }
    let path = files
        .settings
        .as_value()
        .get("ws_path")
        .and_then(Value::as_str)
        .filter(|path| valid_path(path))
        .ok_or(ImportError("现有 WebSocket 路径无效"))?
        .to_owned();
    let vmess_path = format!("{path}/vmess");
    let marker = format!("location = {path} {{");
    if !files.nginx.contains(&marker)
        || files.nginx.contains(&format!("location = {vmess_path} {{"))
    {
        return Err(ImportError("无法确定 VMess 的 Nginx 入口"));
    }
    let include = "include /etc/nginx/xcli-import-locations.conf;";
    if !files.had_locations {
        if files.nginx.contains(include) {
            return Err(ImportError("导入入口配置不一致"));
        }
        let updated = files
            .nginx
            .replace(&marker, &format!("{include}\n        {marker}"));
        drop(Zeroizing::new(std::mem::replace(
            &mut *files.nginx,
            updated,
        )));
    }
    let block = format!("location = {vmess_path} {{\n            proxy_pass http://127.0.0.1:10081;\n            proxy_http_version 1.1;\n            proxy_set_header Upgrade $http_upgrade;\n            proxy_set_header Connection $connection_upgrade;\n            proxy_set_header Host $host;\n            proxy_read_timeout 600s;\n            proxy_send_timeout 600s;\n            proxy_buffering off;\n        }}\n        ");
    let updated = files.nginx.replace(&marker, &format!("{block}{marker}"));
    drop(Zeroizing::new(std::mem::replace(
        &mut *files.nginx,
        updated,
    )));
    files.settings.value_mut()["vmess_ws_path"] = json!(vmess_path);
    files.settings.value_mut()["vmess_port"] = json!(10081);
    files.monitor.value_mut()["vmess_ws_path"] = json!(vmess_path);
    array_mut(files.core.value_mut(), "inbounds")?.push(json!({"tag":"vmess","listen":"127.0.0.1","port":10081,"protocol":"vmess",
        "settings":{"clients":[]},"streamSettings":{"network":"ws","wsSettings":{"path":vmess_path}}}));
    Ok((files, vec![json!({"tag":"vmess","port":10081})]))
}

fn normalize_management_pool(files: &mut Files) -> Result<(), ImportError> {
    let entries: BTreeMap<_, _> = files
        .settings
        .as_value()
        .get("residential_exits")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            entry
                .get("tag")
                .and_then(Value::as_str)
                .map(|tag| (tag.to_owned(), entry.clone()))
        })
        .collect();
    let mut seen = BTreeSet::new();
    for item in array_mut(files.pool.value_mut(), "proxies")? {
        let tag = item
            .get("tag")
            .and_then(Value::as_str)
            .ok_or(ImportError("代理记录与入口不一致，请检查配置"))?
            .to_owned();
        if !seen.insert(tag.clone()) {
            return Err(ImportError("代理编号重复，请检查配置"));
        }
        if item.get("entry").is_none() {
            item["entry"] = entries
                .get(&tag)
                .cloned()
                .ok_or(ImportError("代理记录与入口不一致，请检查配置"))?;
        }
        let object = item
            .as_object_mut()
            .ok_or(ImportError("代理记录与入口不一致，请检查配置"))?;
        object.entry("enabled").or_insert(json!(true));
        object.entry("deleted_at").or_insert(json!(0));
        if !object["enabled"].is_boolean() || !object["deleted_at"].is_u64() {
            return Err(ImportError("代理记录与入口不一致，请检查配置"));
        }
    }
    Ok(())
}

/// Public catalog for the administrator. Authentication material stays in
/// the private pool and is never copied into the worker's status channel.
pub fn catalog(mut files: Files) -> Result<Vec<Value>, ImportError> {
    normalize_management_pool(&mut files)?;
    let proxies = array(files.pool.as_value(), "proxies")?;
    if proxies.len() > 40 {
        return Err(ImportError("代理记录过多"));
    }
    let mut output = Vec::with_capacity(proxies.len());
    for proxy in proxies {
        let mut item = serde_json::Map::new();
        for key in ["tag", "protocol", "address"] {
            let value = proxy
                .get(key)
                .and_then(Value::as_str)
                .ok_or(ImportError("代理记录不完整"))?;
            if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                return Err(ImportError("代理记录无效"));
            }
            item.insert(key.into(), json!(value));
        }
        for key in ["label", "country", "exit_ip"] {
            let value = proxy["entry"]
                .get(key)
                .and_then(Value::as_str)
                .ok_or(ImportError("代理记录不完整"))?;
            if value.len() > 256 || value.chars().any(char::is_control) {
                return Err(ImportError("代理记录无效"));
            }
            item.insert(key.into(), json!(value));
        }
        if proxy["protocol"] == "vmess" {
            for key in [
                "network",
                "security",
                "server_name",
                "host",
                "path",
                "alpn",
                "fingerprint",
            ] {
                if let Some(value) = proxy.get(key).and_then(Value::as_str) {
                    let limit = if key == "path" { 1024 } else { 256 };
                    if value.len() > limit || value.chars().any(char::is_control) {
                        return Err(ImportError("代理记录无效"));
                    }
                    item.insert(key.into(), json!(value));
                }
            }
            if let Some(tls) = proxy.get("tls").and_then(Value::as_bool) {
                item.insert("tls".into(), json!(tls));
            }
        }
        let port = proxy["port"]
            .as_u64()
            .filter(|v| (1..=65535).contains(v))
            .ok_or(ImportError("代理端口无效"))?;
        item.insert("port".into(), json!(port));
        item.insert("enabled".into(), proxy["enabled"].clone());
        item.insert("deleted_at".into(), proxy["deleted_at"].clone());
        output.push(Value::Object(item));
    }
    Ok(output)
}

fn hysteria_available(files: &Files) -> Result<bool, ImportError> {
    Ok(truthy(&files.settings.as_value()["hysteria2_port"])
        && array(files.core.as_value(), "inbounds")?
            .iter()
            .any(|entry| entry["tag"] == "hysteria2" && entry["protocol"] == "hysteria"))
}

/// Add Hysteria routing to one active manual proxy, without applying it.
pub fn enable_residential_hysteria(
    mut files: Files,
    tag: &str,
) -> Result<(Files, Vec<Value>), ImportError> {
    if !residential_tag(tag) {
        return Err(ImportError("入口编号无效"));
    }
    if !hysteria_available(&files)? {
        return Err(ImportError("请先启用 Hysteria 2 基础入口"));
    }
    normalize_management_pool(&mut files)?;
    let target = array_mut(files.pool.value_mut(), "proxies")?
        .iter_mut()
        .find(|item| item["tag"] == tag)
        .ok_or(ImportError("请选择尚未启用 Hysteria 2 的有效手动代理"))?;
    if target["enabled"] != true
        || target["deleted_at"] != 0
        || target["entry"]["dynamic"] == true
        || truthy(&target["entry"]["hysteria2"])
        || target["entry"]["tag"] != tag
    {
        return Err(ImportError("请选择尚未启用 Hysteria 2 的有效手动代理"));
    }
    target["entry"]["hysteria2"] = json!(true);
    for config in [files.settings.value_mut(), files.monitor.value_mut()] {
        let exits = array_mut(config, "residential_exits")?;
        if exits.iter().filter(|entry| entry["tag"] == tag).count() != 1 {
            return Err(ImportError("代理记录与入口不一致，请检查配置"));
        }
        let entry = exits
            .iter_mut()
            .find(|entry| entry["tag"] == tag)
            .ok_or(ImportError("代理记录与入口不一致，请检查配置"))?;
        entry["hysteria2"] = json!(true);
    }
    let rules = files
        .core
        .value_mut()
        .pointer_mut("/routing/rules")
        .and_then(Value::as_array_mut)
        .ok_or(ImportError("服务器配置不完整，未修改配置"))?;
    if rules.iter().any(|rule| {
        rule["ruleTag"] == format!("{tag}-hy2-udp") || rule["ruleTag"] == format!("{tag}-hy2-tcp")
    }) {
        return Err(ImportError("Hysteria 2 路由已存在，请检查配置"));
    }
    for (network, target) in [
        ("udp", "blocked".to_owned()),
        ("tcp", format!("{tag}-exit")),
    ] {
        rules.push(json!({"type":"field","ruleTag":format!("{tag}-hy2-{network}"),"inboundTag":["hysteria2"],
            "user":[format!("regexp:@{tag}-hy2$")],"network":network,"outboundTag":target}));
    }
    Ok((files, vec![]))
}

pub fn enable_all_residential_hysteria(
    mut files: Files,
) -> Result<(Files, Vec<Value>), ImportError> {
    if !hysteria_available(&files)? {
        return Err(ImportError("请先启用 Hysteria 2 基础入口"));
    }
    let mut original_pool = SecretJson::new(files.pool.as_value().clone());
    normalize_management_pool(&mut files)?;
    let tags: Vec<String> = array(files.pool.as_value(), "proxies")?
        .iter()
        .filter(|item| {
            item["enabled"] == true
                && item["deleted_at"] == 0
                && item["entry"]["dynamic"] != true
                && !truthy(&item["entry"]["hysteria2"])
        })
        .filter_map(|item| item["tag"].as_str().map(str::to_owned))
        .collect();
    if tags.is_empty() {
        replace_secret(
            files.pool.value_mut(),
            std::mem::take(original_pool.value_mut()),
        );
    }
    for tag in tags {
        files = enable_residential_hysteria(files, &tag)?.0;
    }
    Ok((files, vec![]))
}

fn residential_tag(tag: &str) -> bool {
    tag.strip_prefix("residential-")
        .is_some_and(|number| number.len() == 2 && number.bytes().all(|c| c.is_ascii_digit()))
}

fn residential_path(path: &str, tag: &str) -> bool {
    path.strip_suffix(&format!("/{tag}"))
        .is_some_and(valid_path)
}

fn location(entry: &Value) -> Result<String, ImportError> {
    let tag = entry
        .get("tag")
        .and_then(Value::as_str)
        .filter(|tag| residential_tag(tag))
        .ok_or(ImportError("已保存的入口无效"))?;
    let path = entry
        .get("ws_path")
        .and_then(Value::as_str)
        .filter(|path| residential_path(path, tag))
        .ok_or(ImportError("已保存的入口无效"))?;
    let port = entry
        .get("port")
        .and_then(Value::as_u64)
        .filter(|port| (10450..10550).contains(port))
        .ok_or(ImportError("已保存的入口无效"))?;
    Ok(format!("\nlocation = {path} {{\n    proxy_pass http://127.0.0.1:{port};\n    proxy_http_version 1.1;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection $connection_upgrade;\n    proxy_set_header Host $host;\n    proxy_read_timeout 600s;\n    proxy_send_timeout 600s;\n    proxy_buffering off;\n}}\n"))
}

/// Build a candidate for one existing manual residential proxy.
pub fn manage(
    mut files: Files,
    tag: &str,
    action: Manage<'_>,
) -> Result<(Files, Vec<Value>), ImportError> {
    if !residential_tag(tag) {
        return Err(ImportError("代理操作不正确"));
    }
    let old_settings = files
        .settings
        .as_value()
        .get("residential_exits")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if old_settings
        .iter()
        .any(|entry| entry.get("tag").and_then(Value::as_str).is_none())
    {
        return Err(ImportError("代理记录与入口不一致，请检查配置"));
    }
    let entries: BTreeMap<_, _> = old_settings
        .iter()
        .filter_map(|entry| {
            entry
                .get("tag")
                .and_then(Value::as_str)
                .map(|name| (name.to_owned(), entry.clone()))
        })
        .collect();
    let pool = array_mut(files.pool.value_mut(), "proxies")?;
    let mut seen = BTreeSet::new();
    for item in pool.iter_mut() {
        let name = item
            .get("tag")
            .and_then(Value::as_str)
            .ok_or(ImportError("代理记录与入口不一致，请检查配置"))?
            .to_owned();
        if !seen.insert(name.clone()) {
            return Err(ImportError("代理编号重复，请检查配置"));
        }
        if item.get("entry").is_none() {
            item["entry"] = entries
                .get(&name)
                .cloned()
                .ok_or(ImportError("代理记录与入口不一致，请检查配置"))?;
        }
        let object = item
            .as_object_mut()
            .ok_or(ImportError("代理记录与入口不一致，请检查配置"))?;
        object.entry("enabled").or_insert(json!(true));
        object.entry("deleted_at").or_insert(json!(0));
        if !object["enabled"].is_boolean() || !object["deleted_at"].is_u64() {
            return Err(ImportError("代理记录与入口不一致，请检查配置"));
        }
    }
    let inventory = old_settings
        .iter()
        .filter(|entry| !seen.contains(entry["tag"].as_str().unwrap_or("")))
        .count()
        + seen.len();
    if inventory > 40 {
        return Err(ImportError("入口与回收站合计最多 40 个"));
    }
    let index = pool
        .iter()
        .position(|item| item["tag"] == tag)
        .ok_or(ImportError("只能管理手动导入的代理"))?;
    let mut target = SecretJson::new(pool[index].clone());
    let deleted = target.as_value()["deleted_at"].as_u64().unwrap_or(0) != 0;
    if deleted != matches!(action, Manage::Restore) {
        return Err(ImportError("代理状态已变化，请刷新列表"));
    }
    let original_protocol = target.as_value()["protocol"]
        .as_str()
        .ok_or(ImportError("代理协议无效"))?
        .to_owned();
    match action {
        Manage::Disable => target.value_mut()["enabled"] = json!(false),
        Manage::Delete { now } if now != 0 => {
            target.value_mut()["enabled"] = json!(false);
            target.value_mut()["deleted_at"] = json!(now);
        }
        Manage::Delete { .. } => return Err(ImportError("删除时间无效")),
        Manage::Restore => {
            target.value_mut()["enabled"] = json!(false);
            target.value_mut()["deleted_at"] = json!(0);
        }
        Manage::Enable { .. } => target.value_mut()["enabled"] = json!(true),
        Manage::Edit { changes, .. } => {
            let changes = changes.as_object().ok_or(ImportError("编辑字段不正确"))?;
            const ALLOWED: &[&str] = &[
                "label",
                "address",
                "port",
                "protocol",
                "username",
                "password",
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
            if changes.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
                return Err(ImportError("编辑字段不正确"));
            }
            for (key, value) in changes {
                if key == "label" {
                    let label = value
                        .as_str()
                        .filter(|label| {
                            !label.is_empty()
                                && label.chars().count() <= 60
                                && !label.chars().any(|c| c < ' ' || c == '\u{7f}')
                        })
                        .ok_or(ImportError("名称需为 1～60 个可见字符"))?;
                    target.value_mut()["entry"]["label"] = json!(label);
                } else if !["username", "password", "uuid"].contains(&key.as_str()) || truthy(value)
                {
                    replace_secret(&mut target.value_mut()[key], value.clone());
                }
            }
        }
    }
    let protocol = target.as_value()["protocol"]
        .as_str()
        .ok_or(ImportError("代理协议无效"))?
        .to_owned();
    if protocol != original_protocol && (protocol == "vmess" || original_protocol == "vmess") {
        return Err(ImportError("VMess 与 HTTP/SOCKS5 之间请使用重新导入"));
    }
    let mut outbound = match protocol.as_str() {
        "socks" | "http" => {
            let p = target.as_value();
            let address = p["address"].as_str().ok_or(ImportError("代理地址无效"))?;
            let port = p["port"].as_u64().ok_or(ImportError("代理端口不正确"))?;
            let user = p["username"]
                .as_str()
                .filter(|user| !user.contains(':'))
                .ok_or(ImportError("代理账号无效"))?;
            let pass = p["password"].as_str().ok_or(ImportError("代理密码无效"))?;
            let text = Zeroizing::new(format!("{address}:{port}:{user}:{pass}"));
            let parsed = parse_fixed(&text)?;
            if parsed.len() != 1 || parsed[0].username() != user || parsed[0].password() != pass {
                return Err(ImportError("代理账号无效"));
            }
            SecretJson::new(
                json!({"protocol":protocol,"settings":{"servers":[{"address":address,"port":port,
                "users":[{"user":user,"pass":pass}]}]}}),
            )
        }
        "vmess" => {
            let p = target.as_value();
            let fields = [
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
            let mut record = SecretJson::new(json!({}));
            for key in fields {
                record.value_mut()[key] = p
                    .get(key)
                    .ok_or(ImportError("VMess 代理字段不正确"))?
                    .clone();
            }
            let proxy = VmessProxy::from_record(record.as_value())?;
            let normalized = proxy.address().to_owned();
            target.value_mut()["address"] = json!(normalized);
            let address = match action {
                Manage::Enable {
                    server_ip: Some(ip),
                    ..
                }
                | Manage::Edit {
                    server_ip: Some(ip),
                    ..
                } => Some(ip),
                Manage::Enable {
                    server_ip: None, ..
                }
                | Manage::Edit {
                    server_ip: None, ..
                } => return Err(ImportError("VMess 服务器解析地址无效")),
                _ => target.as_value()["server_ip"]
                    .as_str()
                    .and_then(|s| s.parse().ok()),
            };
            if let Some(ip) = address {
                if proxy
                    .address()
                    .parse::<std::net::Ipv4Addr>()
                    .is_ok_and(|literal| literal != ip)
                {
                    return Err(ImportError("VMess 服务器解析地址无效"));
                }
                if matches!(action, Manage::Enable { .. } | Manage::Edit { .. }) {
                    target.value_mut()["server_ip"] = json!(ip.to_string());
                }
                proxy.outbound(ip)?
            } else if target.as_value()["enabled"] == true {
                return Err(ImportError("VMess 服务器解析地址无效"));
            } else {
                SecretJson::new(json!({}))
            }
        }
        _ => return Err(ImportError("代理协议无效")),
    };
    let upstream = peer(target.as_value()).ok_or(ImportError("代理地址或端口无效"))?;
    if pool
        .iter()
        .enumerate()
        .any(|(i, p)| i != index && peer(p).as_ref() == Some(&upstream))
    {
        return Err(ImportError("地址和端口与其他代理或回收站记录重复"));
    }
    if peers_except(files.core.as_value(), Some(&format!("{tag}-exit")))?.contains(&upstream) {
        return Err(ImportError("地址和端口与现有出口重复"));
    }
    if let Manage::Enable { result, server_ip }
    | Manage::Edit {
        result, server_ip, ..
    } = action
    {
        if !public_ipv4(result.exit_ip)
            || result.country.len() != 2
            || !result.country.bytes().all(|c| c.is_ascii_uppercase())
            || protocol != "vmess" && server_ip.is_some()
        {
            return Err(ImportError("代理或出口地址无效"));
        }
        target.value_mut()["country"] = json!(result.country);
        target.value_mut()["entry"]["country"] = json!(result.country);
        target.value_mut()["entry"]["exit_ip"] = json!(result.exit_ip.to_string());
    }
    if target.as_value()["entry"]["tag"] != tag || target.as_value()["entry"]["dynamic"] == true {
        return Err(ImportError("代理记录与入口不一致，请检查配置"));
    }
    let active = target.as_value()["enabled"] == true && target.as_value()["deleted_at"] == 0;
    let entry = target.as_value()["entry"].clone();
    if active {
        location(&entry)?;
    }
    let settings_pos = old_settings.iter().position(|item| item["tag"] == tag);
    let old_monitor = files
        .monitor
        .as_value()
        .get("residential_exits")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let monitor_pos = old_monitor.iter().position(|item| item["tag"] == tag);
    for (config, position) in [
        (files.settings.value_mut(), settings_pos),
        (files.monitor.value_mut(), monitor_pos),
    ] {
        let exits = ensure_array(config, "residential_exits")?;
        exits.retain(|item| item["tag"] != tag);
        if active {
            exits.insert(
                position.unwrap_or(exits.len()).min(exits.len()),
                entry.clone(),
            );
        }
    }
    remove_tagged(array_mut(files.core.value_mut(), "inbounds")?, tag);
    remove_tagged(
        array_mut(files.core.value_mut(), "outbounds")?,
        &format!("{tag}-exit"),
    );
    let rules = files
        .core
        .value_mut()
        .pointer_mut("/routing/rules")
        .and_then(Value::as_array_mut)
        .ok_or(ImportError("服务器配置不完整，未修改配置"))?;
    let mut retained = Vec::new();
    for mut rule in std::mem::take(rules) {
        if rule["ruleTag"] == format!("{tag}-hy2-udp")
            || rule["ruleTag"] == format!("{tag}-hy2-tcp")
        {
            continue;
        }
        if let Some(inbounds) = rule.get_mut("inboundTag").and_then(Value::as_array_mut) {
            let had_tag = inbounds.iter().any(|name| name == tag);
            inbounds.retain(|name| name != tag);
            if had_tag && inbounds.is_empty() {
                continue;
            }
        }
        if rule["outboundTag"] == format!("{tag}-exit") {
            return Err(ImportError("代理被自定义路由引用，请先检查配置"));
        }
        retained.push(rule);
    }
    *rules = retained;
    if active {
        array_mut(files.core.value_mut(),"inbounds")?.push(json!({"tag":tag,"listen":"127.0.0.1","port":entry["port"],"protocol":"vless",
            "settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"ws","wsSettings":{"path":entry["ws_path"]}}}));
        outbound.value_mut()["tag"] = json!(format!("{tag}-exit"));
        array_mut(files.core.value_mut(), "outbounds")?.push(std::mem::take(outbound.value_mut()));
        let rules = files
            .core
            .value_mut()
            .pointer_mut("/routing/rules")
            .and_then(Value::as_array_mut)
            .ok_or(ImportError("服务器配置不完整，未修改配置"))?;
        rules.push(
            json!({"type":"field","inboundTag":[tag],"network":"udp","outboundTag":"blocked"}),
        );
        rules.push(json!({"type":"field","inboundTag":[tag],"network":"tcp","outboundTag":format!("{tag}-exit")}));
        if entry["hysteria2"] == true {
            for (network, target) in [
                ("udp", "blocked".to_owned()),
                ("tcp", format!("{tag}-exit")),
            ] {
                rules.push(json!({"type":"field","ruleTag":format!("{tag}-hy2-{network}"),"inboundTag":["hysteria2"],
                    "user":[format!("regexp:@{tag}-hy2$")],"network":network,"outboundTag":target}));
            }
        }
    }
    replace_secret(
        &mut array_mut(files.pool.value_mut(), "proxies")?[index],
        std::mem::take(target.value_mut()),
    );
    let mut locations = Zeroizing::new(String::new());
    for item in array(files.pool.as_value(), "proxies")? {
        if item["enabled"] == true && item["deleted_at"] == 0 {
            locations.push_str(&location(&item["entry"])?);
        }
    }
    files.locations = locations;
    let monitor_bytes = Zeroizing::new(
        serde_json::to_vec(files.monitor.as_value())
            .map_err(|_| ImportError("探测配置容量不足"))?,
    );
    if monitor_bytes.len() > 16384 {
        return Err(ImportError("探测配置容量不足"));
    }
    Ok((files, if active { vec![entry] } else { vec![] }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_fixed;
    #[test]
    fn catalog_exposes_editable_vmess_fields_without_credentials() {
        let files = Files::new(json!({}), json!({}), json!({}), String::new(), None,
            Some(json!({"proxies":[{"tag":"residential-27","protocol":"vmess","address":"example.com","port":443,
                "uuid":"synthetic-secret-uuid","network":"ws","security":"auto","tls":true,"path":"/example",
                "entry":{"label":"fixture","country":"US","exit_ip":"8.8.8.8"}}]}))).unwrap();
        let items = catalog(files).unwrap();
        assert_eq!(items[0]["path"], "/example");
        assert_eq!(items[0]["tls"], true);
        assert!(!serde_json::to_string(&items)
            .unwrap()
            .contains("synthetic-secret-uuid"));
    }
    #[test]
    fn malformed_existing_entrances_are_rejected_before_building_a_candidate() {
        let files = Files::new(
            json!({"public_ip":"8.8.8.8","ws_path":"/connect/fixture","residential_exits":[{}]}),
            json!({"inbounds":[],"outbounds":[],"routing":{"rules":[]}}),
            json!({}),
            "location = /connect/fixture {}".into(),
            None,
            None,
        )
        .unwrap();
        let proxies = parse_fixed("1.1.1.1:80:fixture:synthetic-password").unwrap();
        let result = ProbeResult {
            exit_ip: "1.1.1.1".parse().unwrap(),
            country: "US".into(),
            https_ms: 1,
            doh_ms: 1,
        };
        let input = [Verified {
            proxy: &proxies[0],
            protocol: Protocol::Socks,
            result: &result,
        }];
        assert!(matches!(
            add_fixed(files, &input, "fixture"),
            Err(ImportError(_))
        ));
    }
}
