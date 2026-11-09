//! Experimental Shadowrocket configuration generation. Returned configuration
//! contains credentials; inputs must come from authenticated panel state.
use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use xcli_panel_rules::{factory_independent_rules, ApplyError};

// No Debug: uuid and token are credentials.
#[derive(Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    pub uuid: String,
    pub token: String,
}
type Result<T> = std::result::Result<T, ApplyError>;
fn failure(status: u16, detail: &str) -> ApplyError {
    ApplyError {
        status,
        detail: detail.into(),
    }
}
fn invalid() -> ApplyError {
    failure(503, "Shadowrocket 配置不可用")
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or_else(invalid)
}
fn flag(value: &Value, key: &str, default: bool) -> Result<bool> {
    value
        .get(key)
        .map_or(Ok(default), |v| v.as_bool().ok_or_else(invalid))
}
fn list<'a>(value: &'a Value, key: &str) -> Result<&'a [Value]> {
    value.get(key).map_or(Ok(&[]), |v| {
        v.as_array().map(Vec::as_slice).ok_or_else(invalid)
    })
}
fn trim(value: &str) -> &str {
    value.trim_matches([' ', '\t', '\r', '\n'])
}
fn header() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^\[([^\]]+)\]\s*(#.*)?$").unwrap())
}
fn generic() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"^[ \t]*(.+),[ \t]*(PROXY|DIRECT|REJECT)([ \t]*(?:,no-resolve)?[ \t]*(?:#.*)?\r?\n?)$",
        )
        .unwrap()
    })
}
fn proxy_tail() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r",PROXY([ \t]*(?:,no-resolve)?[ \t]*(?:#.*)?\r?\n?)$").unwrap())
}
fn provider_udp() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^AND,\(\(RULE-SET,([^,]+)\),\(NETWORK,UDP\)\),REJECT$").unwrap())
}
fn quote(value: &str) -> String {
    const HEX: &[u8] = b"0123456789ABCDEF";
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            output.push(byte as char)
        } else {
            output.push('%');
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 15) as usize] as char);
        }
    }
    output
}
fn valid_metadata(user: &User, domain: &str, address: &str) -> Result<()> {
    let uuid = user.uuid.as_bytes();
    let valid_uuid = uuid.len() == 36
        && uuid.iter().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                *c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(c)
            }
        });
    if domain.is_empty()
        || address.is_empty()
        || !domain
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
        || !address
            .bytes()
            .all(|c| c.is_ascii_hexdigit() || c == b'.' || c == b':')
        || !valid_uuid
    {
        return Err(failure(503, "Invalid Shadowrocket node metadata"));
    }
    Ok(())
}
fn categorized(settings: &Value, policy: &Value) -> Result<bool> {
    let defaults = match policy.get("group_defaults") {
        Some(value) => !value.as_object().ok_or_else(invalid)?.is_empty(),
        None => false,
    };
    let order = match policy.get("group_order") {
        Some(value) => !value.as_array().ok_or_else(invalid)?.is_empty(),
        None => false,
    };
    let system = match policy.get("system_overrides") {
        Some(value) => !value.as_object().ok_or_else(invalid)?.is_empty(),
        None => false,
    };
    let names = match policy.get("group_names") {
        Some(value) => !value.as_object().ok_or_else(invalid)?.is_empty(),
        None => false,
    };
    let fixed = list(settings, "residential_exits")?.iter().try_fold(false, |found, exit| {
        Ok::<_, ApplyError>(found || (!flag(exit, "dynamic", false)? && flag(exit, "hysteria2", false)?))
    })?;
    Ok(fixed || field(policy, "base")? == "independent"
        || (flag(policy, "managed", false)?
            && (!field(policy, "rules")?.is_empty()
                || !list(policy, "groups")?.is_empty()
                || defaults || order || system || names)))
}
pub fn setup(settings: &Value, user: &User, policy: &Value) -> Result<Value> {
    let categorized = categorized(settings, policy)?;
    let enabled = categorized
        || list(settings, "shadowrocket_service_users")?
            .iter()
            .any(|v| v.as_str() == Some(&user.id));
    let mut result = json!({"service_routing":enabled,"resource":if enabled {format!("/s/{}/shadowrocket.conf",user.token)} else {"/shadowrocket-dns.sgmodule".into()}});
    if categorized {
        result["dns_routing"] = json!("integrated");
    }
    Ok(result)
}

/// Links contain the user's subscription token and must only be returned to an
/// authenticated administrator or encoded into a protected QR response.
pub fn client_links(settings: &Value, user: &User, policy: &Value) -> Result<Value> {
    let origin = field(settings, "origin")?;
    let module = format!("{origin}/shadowrocket-dns.sgmodule");
    let clash = format!("{origin}/s/{}/clash.yaml", user.token);
    let enabled = setup(settings, user, policy)?["service_routing"]
        .as_bool()
        .ok_or_else(invalid)?;
    let shadowrocket = if enabled {
        format!(
            "shadowrocket://config/add/{origin}/s/{}/shadowrocket.conf",
            user.token
        )
    } else {
        format!("{origin}/client/shadowrocket#{}", user.token)
    };
    let dns_install = format!("shadowrocket://install?module={}", quote(&module));
    let clash_install = format!(
        "clash://install-config?url={}&name={}",
        quote(&clash),
        quote(&format!("Xdistribute · {}", user.name))
    );
    Ok(
        json!({"shadowrocket":shadowrocket,"dns":module,"dns_install":dns_install,"clash":clash,"clash_install":clash_install}),
    )
}

pub fn dns_module(settings: &Value) -> Result<String> {
    let domain = field(settings, "domain")?;
    let address = field(settings, "public_ip")?;
    if domain.is_empty()
        || address.is_empty()
        || !domain
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
        || !address
            .bytes()
            .all(|c| c.is_ascii_hexdigit() || c == b'.' || c == b':')
    {
        return Err(invalid());
    }
    Ok(format!("#!name=Xcli DNS 随所选节点\n#!desc=DNS 通过首页所选节点；关闭系统 DNS 与不支持 UDP 时的直连回退。启用后将首页全局路由设为代理。已包含本服务器节点域名的 IP 映射。\n\n[General]\ndns-server = https://1.1.1.1/dns-query#proxy\nfallback-dns-server = https://1.0.0.1/dns-query#proxy\ndns-direct-system = false\nhijack-dns = :53\nudp-policy-not-supported-behaviour = REJECT\n\n[Host]\n{domain} = {address}\n"))
}

fn line_parts(text: &str) -> impl Iterator<Item = &str> {
    text.split_inclusive('\n')
}
fn eol(text: &str) -> &'static str {
    if text.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}
fn integrated_dns(profile: &str, domain: &str, address: &str, lookup: &str) -> Result<String> {
    let domestic = "https://223.5.5.5/dns-query,https://1.12.12.12/dns-query";
    let proxy = format!("#proxy={}", quote(lookup));
    let fields: BTreeMap<&str, String> = [
        ("dns-server", format!("https://1.1.1.1/dns-query{proxy}")),
        (
            "fallback-dns-server",
            format!("https://1.0.0.1/dns-query{proxy}"),
        ),
        ("direct-dns-server", domestic.into()),
        ("proxy-dns-server", domestic.into()),
        ("dns-fallback-system", "false".into()),
        ("dns-direct-system", "false".into()),
        ("dns-direct-fallback-proxy", "false".into()),
        ("always-ip-address", "false".into()),
        ("use-local-host-item-for-proxy", "false".into()),
        ("hijack-dns", ":53".into()),
        ("udp-policy-not-supported-behaviour", "REJECT".into()),
    ]
    .into_iter()
    .collect();
    let end = eol(profile);
    let mut out = String::new();
    let mut section = String::new();
    let mut host = false;
    for (index, original) in line_parts(profile).enumerate() {
        let line = trim(original);
        let line = if index == 0 {
            line.strip_prefix('\u{feff}').unwrap_or(line)
        } else {
            line
        };
        if line.starts_with('[') && line.contains(']') {
            section = line[1..line.find(']').ok_or_else(invalid)?].into();
            out.push_str(original);
            if !original.ends_with('\n') {
                out.push_str(end);
            }
            match section.as_str() {
                "General" => {
                    for comment in ["# Xcli DNS: DIRECT domain traffic uses direct-dns-server; proxy destinations normally resolve at their outbound.",
                        "# Node bootstrap uses proxy-dns-server; rule-evaluation DNS uses the HTTPS node.","# Keep the old Xcli DNS module disabled."] {out.push_str(comment);out.push_str(end);}
                    for (key, value) in &fields {
                        out.push_str(key);
                        out.push_str(" = ");
                        out.push_str(value);
                        out.push_str(end);
                    }
                }
                "Host" => {
                    if host {
                        return Err(failure(503, "Ambiguous Shadowrocket Host sections"));
                    }
                    host = true;
                    out.push_str(&format!("{domain} = {address}{end}"));
                }
                "Rule" => {
                    out.push_str("IP-CIDR,223.5.5.5/32,DIRECT,no-resolve");
                    out.push_str(end);
                    out.push_str("IP-CIDR,1.12.12.12/32,DIRECT,no-resolve");
                    out.push_str(end);
                }
                _ => (),
            }
        } else {
            let key = line.split_once('=').map_or("", |(key, _)| trim(key));
            if !((section == "General" && fields.contains_key(key))
                || (section == "Host" && key == domain))
            {
                out.push_str(original);
            }
        }
    }
    if !host {
        out.push_str(&format!("{end}[Host]{end}{domain} = {address}{end}"));
    }
    Ok(out)
}

struct BaseOptions<'a> {
    categorized: bool,
    managed: &'a BTreeMap<String, String>,
    has_other: bool,
    removed: &'a BTreeSet<String>,
    legacy_google: bool,
    geo_tail: &'a str,
    final_target: Option<&'a str>,
    proxy_target: &'a str,
    other_target: &'a str,
    google_target: &'a str,
}
fn extend_base(
    base: &str,
    groups: &str,
    rules: &str,
    update: &str,
    options: BaseOptions<'_>,
) -> Result<String> {
    if base.is_empty() || base.len() > 512 * 1024 || base.contains('\0') {
        return Err(failure(503, "Invalid Shadowrocket base profile"));
    }
    let end = eol(base);
    let mut sections: BTreeMap<String, usize> = BTreeMap::new();
    let mut section = String::new();
    let mut updates = 0;
    for (index, original) in line_parts(base).enumerate() {
        let line = trim(original);
        let line = if index == 0 {
            line.strip_prefix('\u{feff}').unwrap_or(line)
        } else {
            line
        };
        if let Some(capture) = header().captures(line) {
            section = capture[1].into();
            *sections.entry(section.clone()).or_default() += 1;
        } else if section == "General"
            && line.starts_with("update-url")
            && trim(line.split('=').next().unwrap_or("")) == "update-url"
        {
            updates += 1;
        } else if section == "Proxy Group" && line.starts_with("XCLI-") {
            return Err(failure(
                503,
                "Shadowrocket base contains reserved service groups",
            ));
        }
    }
    if sections.get("General") != Some(&1)
        || sections.get("Rule") != Some(&1)
        || sections.get("Proxy Group").copied().unwrap_or(0) > 1
        || updates > 1
    {
        return Err(failure(503, "Ambiguous Shadowrocket base sections"));
    }
    let mut out = String::new();
    section.clear();
    let convert = |value: &str| value.replace('\n', end);
    let mut tail_written = options.geo_tail.is_empty();
    let mut final_written = options.final_target.is_none();
    for (index, original) in line_parts(base).enumerate() {
        let line = trim(original);
        let line = if index == 0 {
            line.strip_prefix('\u{feff}').unwrap_or(line)
        } else {
            line
        };
        if let Some(capture) = header().captures(line) {
            if section == "Rule" && &capture[1] != "Rule" {
                if !tail_written { out.push_str(&convert(options.geo_tail)); tail_written = true; }
                if !final_written { out.push_str(&format!("FINAL,{}{end}", options.final_target.ok_or_else(invalid)?)); final_written = true; }
            }
            section = capture[1].into();
            if section == "Rule" && !sections.contains_key("Proxy Group") {
                out.push_str("[Proxy Group]");
                out.push_str(end);
                out.push_str(&convert(groups));
                out.push_str(end);
            }
            out.push_str(original);
            if !original.ends_with('\n') {
                out.push_str(end);
            }
            if section == "General" && updates == 0 {
                out.push_str(&format!("update-url = {update}{end}"));
            }
            if section == "Proxy Group" {
                out.push_str(&convert(groups));
            }
            if section == "Rule" {
                out.push_str(&convert(rules));
            }
        } else if section == "General"
            && line.starts_with("update-url")
            && trim(line.split('=').next().unwrap_or("")) == "update-url"
        {
            out.push_str(&format!("update-url = {update}{end}"));
        } else if options.categorized && section == "Rule" {
            if (line.starts_with("GEOIP,") || line.starts_with("FINAL,")) && !tail_written {
                out.push_str(&convert(options.geo_tail));
                tail_written = true;
            }
            if line.starts_with("FINAL,") && !final_written {
                if let Some(target) = options.final_target {
                    out.push_str(&format!("FINAL,{target}{end}"));
                    final_written = true;
                    continue;
                }
            }
            if let Some(capture) = generic().captures(original) {
                let condition = trim(&capture[1]);
                if options.removed.contains(condition) {
                    continue;
                }
                let replacement =
                    options
                        .managed
                        .get(condition)
                        .map(String::as_str)
                        .or_else(|| {
                            (options.legacy_google
                                && condition == "DOMAIN-KEYWORD,google"
                                && &capture[2] == "PROXY")
                                .then_some(options.google_target)
                        });
                if let Some(replacement) = replacement {
                    let target = capture.get(2).ok_or_else(invalid)?;
                    out.push_str(&original[..target.start()]);
                    out.push_str(replacement);
                    out.push_str(&original[target.end()..]);
                    continue;
                }
            }
            let target = if line.starts_with("FINAL,") && options.has_other {
                options.other_target
            } else {
                options.proxy_target
            };
            out.push_str(
                &proxy_tail().replace(original, |capture: &regex::Captures<'_>| {
                    format!(",{target}{}", &capture[1])
                }),
            );
        } else {
            out.push_str(original);
        }
    }
    if !tail_written { out.push_str(&convert(options.geo_tail)); }
    if !final_written { out.push_str(&format!("FINAL,{}{end}", options.final_target.ok_or_else(invalid)?)); }
    Ok(out)
}

fn policy_name(name: &str, nodes: &BTreeMap<String, String>) -> String {
    if name == "DIRECT" || name == "REJECT" {
        name.into()
    } else {
        nodes
            .get(name)
            .cloned()
            .unwrap_or_else(|| format!("XCLI-{name}"))
    }
}
fn renamed_base(base: &str, policy: &Value) -> String {
    let Some(names) = policy.get("group_names").and_then(Value::as_object).filter(|values| !values.is_empty()) else { return base.into(); };
    let aliases: BTreeMap<String, String> = names.iter().filter_map(|(old, new)| new.as_str().map(|name| (format!("XCLI-{old}"), format!("XCLI-{name}")))).collect();
    static TARGET: OnceLock<Regex> = OnceLock::new();
    let target = TARGET.get_or_init(|| Regex::new(r"^(.+?,[ \t]*)(XCLI-[^,\r\n#]+?)([ \t]*(?:,[^#\r\n]*)?(?:[ \t]*#.*)?\r?\n?)$").unwrap());
    let mut section = "";
    let mut out = String::new();
    for line in line_parts(base) {
        let stripped = trim(line);
        if let Some(capture) = header().captures(stripped) {
            section = if &capture[1] == "Rule" { "Rule" } else if &capture[1] == "Proxy Group" { "Proxy Group" } else { "" };
            out.push_str(line);
        } else if section == "Rule" {
            if let Some(capture) = target.captures(line) {
                if let Some(name) = aliases.get(capture[2].trim()) {
                    out.push_str(&capture[1]); out.push_str(name); out.push_str(&capture[3]); continue;
                }
            }
            out.push_str(line);
        } else if section == "Proxy Group" && !stripped.starts_with('#') {
            let mut first = true;
            for item in line.split(',') {
                if !first { out.push(','); } first = false;
                let leading = item.len() - item.trim_start().len();
                let trailing = item.len() - item.trim_end().len();
                let value = item.trim();
                if let Some(name) = aliases.get(value) {
                    out.push_str(&item[..leading]); out.push_str(name); out.push_str(&item[item.len()-trailing..]);
                } else { out.push_str(item); }
            }
        } else { out.push_str(line); }
    }
    out
}
fn safe(value: &str) -> Result<&str> {
    if value.contains([',', '=', '\r', '\n']) {
        Err(failure(503, "Shadowrocket policy delimiter in name"))
    } else {
        Ok(value)
    }
}

/// Keep custom base rules and groups referring to old subscription node names
/// usable after the compact residential names are introduced.
fn renamed_residential_nodes(base: &str, aliases: &BTreeMap<String, String>) -> String {
    let mut section = "";
    let mut output = String::new();
    for line in line_parts(base) {
        let trimmed = trim(line);
        if let Some(capture) = header().captures(trimmed) {
            section = match &capture[1] { "Proxy Group" => "group", "Rule" => "rule", _ => "" };
            output.push_str(line);
            continue;
        }
        if section.is_empty() || trimmed.starts_with('#') || trimmed.is_empty() {
            output.push_str(line);
            continue;
        }
        let (prefix, body) = if section == "group" {
            match line.split_once('=') {
                Some((head, tail)) => (format!("{head}="), tail),
                None => { output.push_str(line); continue; }
            }
        } else { (String::new(), line) };
        output.push_str(&prefix);
        for (index, part) in body.split(',').enumerate() {
            if index != 0 { output.push(','); }
            let candidate = part.trim_start();
            let start = part.len() - candidate.len();
            let matched = aliases.iter().find(|(old, _)| candidate.strip_prefix(old.as_str())
                .is_some_and(|rest| rest.trim_start().is_empty() || rest.trim_start().starts_with('#')));
            if let Some((old, replacement)) = matched {
                output.push_str(&part[..start]);
                output.push_str(replacement);
                output.push_str(&candidate[old.len()..]);
            } else {
                output.push_str(part);
            }
        }
    }
    output
}
fn categorized_profile(
    config: &Value,
    nodes: &BTreeMap<String, String>,
    base: &str,
    update: &str,
    replace: bool,
    policy: &Value,
    domain: &str,
    origin: &str,
) -> Result<String> {
    let mut groups = String::new();
    let mut rules = String::new();
    let mut managed = BTreeMap::new();
    let overrides = policy.get("system_overrides").and_then(Value::as_object);
    let alias = |name: &str| policy.get("group_names").and_then(|names| names.get(name)).and_then(Value::as_str).unwrap_or(name).to_owned();
    let proxy_target = policy_name(&alias("PROXY"), nodes);
    let other_target = policy_name(&alias("其他流量"), nodes);
    let google_target = policy_name(&alias("独立 · Google"), nodes);
    if let Some(names) = policy.get("group_names").and_then(Value::as_object) {
        for name in names.values().filter_map(Value::as_str) {
            if list(config, "proxy-groups")?.iter().any(|group| group["name"] == name)
                && (nodes.contains_key(name) || nodes.values().any(|node| node == &format!("XCLI-{name}"))) {
                return Err(failure(422, "分组名称与小火箭节点名称重复"));
            }
        }
    }
    let system_rows = if overrides.is_some_and(|values| !values.is_empty()) {
        xcli_panel_clash::system_rules_preview(domain, field(policy, "base")?)?
    } else { Vec::new() };
    let tail_mode = system_rows.iter().any(|row| {
        row.get("id").and_then(Value::as_str).is_some_and(|id| overrides.is_some_and(|values| values.contains_key(id)))
            && matches!(row.get("kind").and_then(Value::as_str), Some("GEOSITE" | "GEOIP" | "MATCH"))
    });
    let mut has_other = false;
    let mut has_google = false;
    for item in list(config, "proxy-groups")? {
        let name = field(item, "name")?;
        has_other |= name == alias("其他流量");
        has_google |= name == alias("独立 · Google");
        let kind = field(item, "type")?;
        groups.push_str(safe(&policy_name(name, nodes))?);
        groups.push_str(" = ");
        groups.push_str(kind);
        for member in list(item, "proxies")? {
            groups.push(',');
            groups.push_str(safe(&policy_name(
                member.as_str().ok_or_else(invalid)?,
                nodes,
            ))?);
        }
        if kind == "fallback" || kind == "url-test" {
            groups.push_str(",interval=120,timeout=5,url=https://www.gstatic.com/generate_204");
            if kind == "url-test" {
                groups.push_str(",tolerance=100");
            }
        }
        if item.get("hidden").and_then(Value::as_bool) == Some(true) {
            groups.push_str(",hidden=1");
        }
        groups.push('\n');
    }
    let providers = config.get("rule-providers").ok_or_else(invalid)?;
    let payloads = |provider: &str| -> Result<Vec<String>> {
        let value = providers.get(provider).ok_or_else(invalid)?;
        let mut result = Vec::new();
        for item in list(value, "payload")? {
            let mut text = item.as_str().ok_or_else(invalid)?.to_owned();
            if field(value, "behavior")? == "domain" {
                text = format!(
                    "DOMAIN-SUFFIX,{}",
                    text.strip_prefix("+.")
                        .ok_or_else(|| failure(503, "Unsupported service domain"))?
                );
            }
            result.push(text);
        }
        Ok(result)
    };
    let mut emit = |value: &str, target: &str| {
        let mut value = value
            .replace("NETWORK,UDP", "PROTOCOL,UDP")
            .replace("IP-CIDR6,", "IP-CIDR,")
            .replace("DST-PORT,3478/443", "OR,((DST-PORT,3478),(DST-PORT,443))");
        let suffix = if value.ends_with(",no-resolve") {
            value.truncate(value.len() - 11);
            ",no-resolve"
        } else {
            ""
        };
        let destination = policy_name(target, nodes);
        if !value.starts_with("AND,") {
            managed
                .entry(value.clone())
                .or_insert_with(|| destination.clone());
        }
        rules.push_str(&format!("{value},{destination}{suffix}\n"));
    };
    let mut geo_tail = String::new();
    let mut final_target = None;
    let mut in_tail = false;
    for item in list(config, "rules")? {
        let rule = item.as_str().ok_or_else(invalid)?;
        if !in_tail && (rule.starts_with("GEOSITE,") || (tail_mode && (rule.starts_with("GEOIP,private,") || rule.starts_with("GEOIP,CN,") || rule.starts_with("MATCH,")))) {
            if !tail_mode { break; }
            in_tail = true;
        }
        if in_tail {
            let (stripped, suffix) = rule.strip_suffix(",no-resolve").map_or((rule, ""), |value| (value, ",no-resolve"));
            let (condition, target) = stripped.rsplit_once(',').ok_or_else(invalid)?;
            let target = policy_name(target, nodes);
            if condition == "MATCH" {
                final_target = Some(target);
            } else if let Some(category) = condition.strip_prefix("GEOSITE,") {
                geo_tail.push_str(&format!("RULE-SET,{origin}/api/geosite/{}.list,{}{suffix}\n", quote(category), safe(&target)?));
            } else {
                let condition = condition.replacen("GEOIP,private", "GEOIP,LAN", 1).replace("IP-CIDR6,", "IP-CIDR,");
                geo_tail.push_str(&format!("{condition},{}{suffix}\n", safe(&target)?));
            }
            continue;
        }
        if let Some(capture) = provider_udp().captures(rule) {
            for payload in payloads(&capture[1])? {
                emit(&format!("AND,(({payload}),(NETWORK,UDP))"), "REJECT");
            }
        } else if let Some(value) = rule.strip_prefix("RULE-SET,") {
            let (provider, target) = value.split_once(',').ok_or_else(invalid)?;
            for payload in payloads(provider)? {
                emit(&payload, target);
            }
        } else {
            let (stripped, suffix) = rule
                .strip_suffix(",no-resolve")
                .map_or((rule, ""), |v| (v, ",no-resolve"));
            let (condition, target) = stripped.rsplit_once(',').ok_or_else(invalid)?;
            emit(&format!("{condition}{suffix}"), target);
        }
    }
    let mut removed = BTreeSet::new();
    if replace {
        for line in factory_independent_rules().lines() {
            if let Some((condition, _)) = line.rsplit_once(',') {
                let condition = condition.replacen("IP-CIDR6,", "IP-CIDR,", 1);
                if !managed.contains_key(&condition) {
                    removed.insert(condition);
                }
            }
        }
    }
    if let Some(overrides) = overrides {
        for row in &system_rows {
            let id = field(row, "id")?;
            let Some(value) = overrides.get(id) else { continue; };
            let kind = field(row, "kind")?;
            if !matches!(kind, "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "IP-CIDR" | "IP-CIDR6" | "GEOIP") { continue; }
            let changed = value.is_null() || value.get("kind") != row.get("kind") || value.get("value") != row.get("value");
            let condition = format!("{kind},{}", field(row, "value")?).replacen("IP-CIDR6,", "IP-CIDR,", 1);
            if changed && !managed.contains_key(&condition) { removed.insert(condition); }
        }
    }
    let legacy_google = has_google && !managed.contains_key("DOMAIN-KEYWORD,google");
    extend_base(
        base,
        &groups,
        &rules,
        update,
        BaseOptions {
            categorized: true,
            managed: &managed,
            has_other,
            removed: &removed,
            legacy_google,
            geo_tail: &geo_tail,
            final_target: final_target.as_deref(),
            proxy_target: &proxy_target,
            other_target: &other_target,
            google_target: &google_target,
        },
    )
}

/// Build the configuration for an active user from a published effective
/// policy. Remote nodes must already have applied grants for that user.
pub fn profile(
    settings: &Value,
    user: &User,
    remote: &[Value],
    dynamic_enabled: bool,
    policy: &Value,
) -> Result<String> {
    if user.id.len() < 8 || !user.id.is_ascii() {
        return Err(invalid());
    }
    let is_categorized = categorized(settings, policy)?;
    if !is_categorized
        && !list(settings, "shadowrocket_service_users")?
            .iter()
            .any(|v| v.as_str() == Some(&user.id))
    {
        return Err(failure(404, "Not Found"));
    }
    let domain = field(settings, "domain")?;
    let address = field(settings, "public_ip")?;
    valid_metadata(user, domain, address)?;
    let fixed_names = xcli_panel_rules::residential::names(settings).map_err(|_| invalid())?;
    let origin = field(settings, "origin")?;
    let update = format!("{origin}/s/{}/shadowrocket.conf", user.token);
    let base = settings
        .get("shadowrocket_base_profiles")
        .and_then(|v| v.get(&user.id))
        .and_then(Value::as_str);
    if is_categorized {
        let mut legacy_names = BTreeMap::new();
        let mut nodes: BTreeMap<String, String> = [
            ("REALITY".into(), format!("{} · REALITY", user.name)),
            ("HTTPS".into(), format!("{} · HTTPS", user.name)),
            ("Hysteria 2".into(), format!("{} · Hysteria 2", user.name)),
            (
                "Hysteria 2 Brutal 40 Mbps".into(),
                format!("{} · Hysteria 2 Brutal 40 Mbps", user.name),
            ),
            (
                "Hysteria 2 Brutal".into(),
                format!("{} · Hysteria 2 Brutal", user.name),
            ),
            ("VMess TLS".into(), format!("{} · VMess TLS", user.name)),
        ]
        .into_iter()
        .collect();
        for exit in list(settings, "residential_exits")? {
            let dynamic = flag(exit, "dynamic", false)?;
            if dynamic && !dynamic_enabled {
                continue;
            }
            let label = if dynamic {
                field(exit, "label")?.to_owned()
            } else {
                fixed_names.get(field(exit, "tag")?).ok_or_else(invalid)?.clone()
            };
            let node = format!("{} · {label}", user.name);
            if !dynamic {
                let old_label = format!("{} · {}", field(exit, "label")?, field(exit, "exit_ip")?);
                let old_node = format!("{} · {old_label}", user.name);
                legacy_names.insert(old_node.clone(), node.clone());
                if flag(exit, "hysteria2", false)? {
                    legacy_names.insert(format!("{old_node} · HTTPS"), format!("{node} · HTTPS"));
                    legacy_names.insert(format!("XCLI-{old_label}"), format!("XCLI-{label}"));
                    legacy_names.insert(format!("XCLI-{old_label} · 自动"), format!("XCLI-{label}"));
                }
            }
            if flag(exit, "hysteria2", false)? {
                nodes.insert(format!("{label} · Hysteria2"), node.clone());
                nodes.insert(format!("{label} · HTTPS"), format!("{node} · HTTPS"));
            } else {
                nodes.insert(label, node);
            }
        }
        for node in remote {
            let id = field(node, "id")?;
            if id.len() != 32 || !id.is_ascii() {
                return Err(invalid());
            }
            let label = format!("节点 {} · {}", &id[..8], field(node, "name")?);
            for transport in ["REALITY", "HTTPS", "Hysteria 2"] {
                let name = format!("{label} · {transport}");
                nodes.insert(name.clone(), format!("{} · {name}", user.name));
            }
        }
        let clash_user = xcli_panel_clash::User {
            id: user.id.clone(),
            uuid: user.uuid.clone(),
        };
        let config =
            xcli_panel_clash::build(settings, &clash_user, remote, dynamic_enabled, policy)?;
        let replace = flag(policy, "managed", false)?
            && field(policy, "base")? == "independent"
            && field(policy, "rules")? != factory_independent_rules();
        let base = renamed_residential_nodes(base.unwrap_or("[General]\ninclude = default.conf\n\n[Rule]\nFINAL,PROXY\n"), &legacy_names);
        let base = renamed_base(&base, policy);
        let result = categorized_profile(&config, &nodes, &base, &update, replace, policy, domain, origin)?;
        return integrated_dns(
            &result,
            domain,
            address,
            nodes.get("HTTPS").ok_or_else(invalid)?,
        );
    }
    let mut proxies = String::new();
    let mut groups = String::new();
    let mut rules = String::new();
    let services = settings
        .get("clash_service_routes")
        .and_then(|v| v.get(&user.id))
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    let port = settings
        .get("hysteria2_port")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    for service in services {
        let name = field(service, "name")?;
        let tag = field(service, "outbound")?;
        let group = format!("XCLI-{name}");
        let node = format!("{group}-{}", &user.id[..8]);
        let mut available = port > 0;
        let mut auth = user.uuid.clone();
        let mut existing = format!("{} · Hysteria 2", user.name);
        if tag != "hysteria2" {
            let mut found = false;
            for exit in list(settings, "residential_exits")? {
                if field(exit, "tag")? == tag
                    && flag(exit, "hysteria2", false)?
                    && (!flag(exit, "dynamic", false)? || dynamic_enabled)
                {
                    found = true;
                    let label = if flag(exit, "dynamic", false)? {
                        field(exit, "label")?
                    } else {
                        fixed_names.get(tag).map(String::as_str).ok_or_else(invalid)?
                    };
                    existing = format!("{} · {label}", user.name);
                }
            }
            available &= found;
            auth.push_str(&format!(".{tag}-hy2"));
        }
        if available {
            proxies.push_str(&format!(
                "{node} = hysteria2,{address},{port},auth={auth},peer={domain},udp={}\n",
                if field(service, "udp")? == "reject" {
                    0
                } else {
                    1
                }
            ));
        }
        if base.is_some() && existing.contains([',', '=', '\r', '\n']) {
            return Err(failure(
                503,
                "Shadowrocket node name contains policy delimiters",
            ));
        }
        groups.push_str(&format!(
            "{group} = select,{}\n",
            if available {
                if base.is_some() {
                    &existing
                } else {
                    &node
                }
            } else {
                "REJECT"
            }
        ));
        for entry in list(service, "domains")? {
            let host = entry.as_str().ok_or_else(invalid)?;
            if field(service, "udp")? == "reject" {
                rules.push_str(&format!(
                    "AND,((DOMAIN-SUFFIX,{host}),(PROTOCOL,UDP)),REJECT\n"
                ));
            }
            rules.push_str(&format!("DOMAIN-SUFFIX,{host},{group}\n"));
        }
    }
    if let Some(base) = base {
        let rules = format!("DOMAIN,{domain},DIRECT\n{rules}");
        let empty_map = BTreeMap::new();
        let empty_set = BTreeSet::new();
        return extend_base(
            base,
            &groups,
            &rules,
            &update,
            BaseOptions {
                categorized: false,
                managed: &empty_map,
                has_other: true,
                removed: &empty_set,
                legacy_google: false,
                geo_tail: "",
                final_target: None,
                proxy_target: "XCLI-PROXY",
                other_target: "XCLI-其他流量",
                google_target: "XCLI-独立 · Google",
            },
        );
    }
    Ok(format!("# Xcli 专属业务分流；继承手机现有 default.conf，请保留该文件。\n# 全局路由必须为配置。节点与规则随本远程配置一同更新；含个人凭据，请勿分享。\n\n[General]\ninclude = default.conf\nupdate-url = {update}\nudp-policy-not-supported-behaviour = REJECT\n\n[Proxy]\n{proxies}\n[Proxy Group]\n{groups}\n[Rule]\n{rules}"))
}
