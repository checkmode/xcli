//! Experimental Clash/Mihomo generation. Inputs must be from trusted,
//! previously validated panel settings and authorized node grants.
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use xcli_panel_rules::{
    apply_client_policy, apply_google_policy, apply_template_rules, factory_independent_rules,
    ApplyError,
};

// No Debug: the UUID authorizes access to the node.
#[derive(Deserialize)]
pub struct User {
    pub id: String,
    pub uuid: String,
}
type Result<T> = std::result::Result<T, ApplyError>;
fn invalid() -> ApplyError {
    ApplyError {
        status: 503,
        detail: "客户端配置不可用".into(),
    }
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or_else(invalid)
}
fn number(value: &Value, key: &str, default: i64) -> Result<i64> {
    value
        .get(key)
        .map_or(Ok(default), |v| v.as_i64().ok_or_else(invalid))
}
fn flag(value: &Value, key: &str, default: bool) -> Result<bool> {
    value
        .get(key)
        .map_or(Ok(default), |v| v.as_bool().ok_or_else(invalid))
}
fn sequence<'a>(value: &'a Value, key: &str) -> Result<&'a [Value]> {
    match value.get(key) {
        Some(v) => v.as_array().map(Vec::as_slice).ok_or_else(invalid),
        None => Ok(&[]),
    }
}
fn add(proxies: &mut Vec<Value>, names: &mut Vec<Value>, proxy: Value) -> Result<()> {
    names.push(json!(field(&proxy, "name")?));
    proxies.push(proxy);
    Ok(())
}
fn country_label(country: &str) -> &str {
    match country {
        "US" => "美国",
        "JP" => "日本",
        "SG" => "新加坡",
        "ZZ" => "全球",
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
        _ => country,
    }
}
fn reality(
    name: &str,
    address: &str,
    port: i64,
    uuid: &str,
    sni: &str,
    public: &str,
    short: &str,
) -> Value {
    json!({"name":name,"type":"vless","server":address,"port":port,"uuid":uuid,"udp":true,"tls":true,
        "network":"tcp","flow":"xtls-rprx-vision","packet-encoding":"xudp","servername":sni,"client-fingerprint":"chrome",
        "reality-opts":{"public-key":public,"short-id":short,"support-x25519mlkem768":true}})
}
fn websocket(
    name: &str,
    address: &str,
    port: i64,
    uuid: &str,
    domain: &str,
    path: &str,
    udp: bool,
) -> Value {
    json!({"name":name,"type":"vless","server":address,"port":port,"uuid":uuid,"udp":udp,"tls":true,
        "skip-cert-verify":false,"servername":domain,"client-fingerprint":"chrome","network":"ws",
        "ws-opts":{"path":path,"headers":{"Host":domain}}})
}
fn selector(name: &str, members: Vec<Value>) -> Value {
    json!({"name":name,"type":"select","proxies":members})
}

/// `remote_nodes` must already contain only enabled nodes with an applied
/// grant for this UUID. `policy` is the trusted effective published policy.
pub fn build(
    settings: &Value,
    user: &User,
    remote_nodes: &[Value],
    dynamic_enabled: bool,
    policy: &Value,
) -> Result<Value> {
    let address = field(settings, "public_ip")?;
    let domain = field(settings, "domain")?;
    let public_port = number(settings, "public_port", 443)?;
    let hy2_port = number(settings, "hysteria2_port", 0)?;
    let hy2_brutal_port = number(settings, "hysteria2_brutal_port", 0)?;
    let hy2_brutal_mbps = number(settings, "hysteria2_brutal_mbps", 40)?;
    if !(0..=65535).contains(&hy2_brutal_port)
        || !(1..=1000).contains(&hy2_brutal_mbps)
        || hy2_brutal_port > 0 && (hy2_port <= 0 || hy2_brutal_port == hy2_port)
    {
        return Err(invalid());
    }
    let path = field(settings, "ws_path")?;
    let mut proxies = Vec::new();
    let mut names = Vec::new();
    let mut outbound: BTreeMap<String, String> = [
        ("reality".into(), "REALITY".into()),
        ("websocket".into(), "HTTPS".into()),
    ]
    .into_iter()
    .collect();
    add(
        &mut proxies,
        &mut names,
        reality(
            "REALITY",
            address,
            public_port,
            &user.uuid,
            field(settings, "reality_sni")?,
            field(settings, "reality_public")?,
            field(settings, "short_id")?,
        ),
    )?;
    add(
        &mut proxies,
        &mut names,
        websocket(
            "HTTPS",
            address,
            public_port,
            &user.uuid,
            domain,
            path,
            true,
        ),
    )?;
    if hy2_port > 0 {
        add(
            &mut proxies,
            &mut names,
            json!({"name":"Hysteria 2","type":"hysteria2","server":address,"port":hy2_port,"password":user.uuid,"sni":domain,"skip-cert-verify":false}),
        )?;
    }
    if hy2_brutal_port > 0 {
        add(
            &mut proxies,
            &mut names,
            json!({"name":"Hysteria 2 Brutal 40 Mbps","type":"hysteria2","server":address,"port":hy2_brutal_port,"password":user.uuid,"sni":domain,"skip-cert-verify":false,"down":format!("{hy2_brutal_mbps} Mbps")}),
        )?;
        add(
            &mut proxies,
            &mut names,
            json!({"name":"Hysteria 2 Brutal","type":"hysteria2","server":address,"port":hy2_brutal_port,"password":user.uuid,"sni":domain,"skip-cert-verify":false,"down":format!("{hy2_brutal_mbps} Mbps")}),
        )?;
    }
    if settings.get("vmess_ws_path").is_some() {
        add(
            &mut proxies,
            &mut names,
            json!({"name":"VMess TLS","type":"vmess","server":address,"port":public_port,
        "uuid":user.uuid,"alterId":0,"cipher":"auto","udp":true,"tls":true,"skip-cert-verify":false,"servername":domain,"network":"ws",
        "ws-opts":{"path":field(settings,"vmess_ws_path")?,"headers":{"Host":domain}}}),
        )?;
    }
    for node in remote_nodes {
        let ep = node.get("endpoint").ok_or_else(invalid)?;
        let host = field(ep, "public_ip")?;
        let domain = field(ep, "domain")?;
        let port = number(ep, "public_port", 0)?;
        let id = field(node, "id")?;
        if id.len() != 32 || !id.is_ascii() {
            return Err(invalid());
        }
        let label = format!("节点 {} · {}", &id[..8], field(node, "name")?);
        let real = format!("{label} · REALITY");
        let ws = format!("{label} · HTTPS");
        let hy2 = format!("{label} · Hysteria 2");
        outbound.insert(format!("remote-{id}-reality"), real.clone());
        outbound.insert(format!("remote-{id}-websocket"), ws.clone());
        outbound.insert(format!("remote-{id}-hysteria2"), hy2.clone());
        add(
            &mut proxies,
            &mut names,
            reality(
                &real,
                host,
                port,
                &user.uuid,
                field(ep, "reality_sni")?,
                field(ep, "reality_public")?,
                field(ep, "short_id")?,
            ),
        )?;
        add(
            &mut proxies,
            &mut names,
            websocket(
                &ws,
                host,
                port,
                &user.uuid,
                domain,
                field(ep, "ws_path")?,
                true,
            ),
        )?;
        add(
            &mut proxies,
            &mut names,
            json!({"name":hy2,"type":"hysteria2","server":host,"port":number(ep,"hysteria2_port",0)?,"password":user.uuid,"sni":domain,"skip-cert-verify":false}),
        )?;
    }
    let exits = sequence(settings, "residential_exits")?;
    let mut countries: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut protocol_groups = Vec::new();
    for exit in exits {
        let dynamic = flag(exit, "dynamic", false)?;
        if dynamic && !dynamic_enabled {
            continue;
        }
        let tag = field(exit, "tag")?;
        let label = field(exit, "label")?;
        let name = if dynamic {
            label.to_owned()
        } else {
            format!("{label} · {}", field(exit, "exit_ip")?)
        };
        if flag(exit, "hysteria2", false)? {
            let hy2 = format!("{name} · Hysteria2");
            let https = format!("{name} · HTTPS");
            add(
                &mut proxies,
                &mut names,
                json!({"name":hy2,"type":"hysteria2","server":address,"port":hy2_port,"password":format!("{}.{tag}-hy2",user.uuid),"sni":domain,"skip-cert-verify":false,"udp":false}),
            )?;
            add(
                &mut proxies,
                &mut names,
                websocket(
                    &https,
                    address,
                    public_port,
                    &user.uuid,
                    domain,
                    field(exit, "ws_path")?,
                    false,
                ),
            )?;
            names.truncate(names.len() - 2);
            names.push(json!(name));
            protocol_groups.push(selector(&name, vec![json!(hy2), json!(https)]));
        } else {
            add(
                &mut proxies,
                &mut names,
                websocket(
                    &name,
                    address,
                    public_port,
                    &user.uuid,
                    domain,
                    field(exit, "ws_path")?,
                    false,
                ),
            )?;
        }
        let nodes = countries
            .entry(field(exit, "country")?.to_owned())
            .or_default();
        if dynamic {
            nodes.insert(0, json!(name));
        } else {
            nodes.push(json!(name));
        }
        outbound.insert(tag.to_owned(), name);
    }
    if hy2_port > 0 {
        outbound.insert("hysteria2".into(), "Hysteria 2".into());
    }
    if hy2_brutal_port > 0 {
        outbound.insert(
            "hysteria2-brutal".into(),
            "Hysteria 2 Brutal 40 Mbps".into(),
        );
        outbound.insert("hysteria2-brutal-current".into(), "Hysteria 2 Brutal".into());
    }
    if settings.get("vmess_ws_path").is_some() {
        outbound.insert("vmess".into(), "VMess TLS".into());
    }
    names.swap(0, 1);
    let mut groups = protocol_groups;
    for (country, nodes) in countries {
        let label = format!("住宅分组 · {}", country_label(&country));
        names.push(json!(label));
        groups.push(selector(&label, nodes));
    }
    groups.insert(0, selector("PROXY", names));
    let mut stun = Vec::new();
    if hy2_port > 0 {
        stun.push(json!("Hysteria 2"));
    }
    stun.push(json!("HTTPS"));
    stun.push(json!("REALITY"));
    if settings.get("vmess_ws_path").is_some() {
        stun.push(json!("VMess TLS"));
    }
    groups.push(selector("STUN", stun));
    let domestic = json!([
        "https://223.5.5.5/dns-query#DIRECT",
        "https://1.12.12.12/dns-query#DIRECT"
    ]);
    let mut rules = vec![
        json!(format!("DOMAIN,{domain},DIRECT")),
        json!("IP-CIDR,127.0.0.0/8,DIRECT,no-resolve"),
        json!("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"),
        json!("IP-CIDR,172.16.0.0/12,DIRECT,no-resolve"),
        json!("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve"),
        json!("DOMAIN-SUFFIX,todesk.com,DIRECT"),
    ];
    let mut dns = Map::new();
    dns.insert("+.todesk.com".into(), domestic.clone());
    let mut providers = Map::new();
    let services = settings
        .get("clash_service_routes")
        .and_then(|v| v.get(&user.id))
        .map_or(Ok(&[][..]), |v| {
            v.as_array().map(Vec::as_slice).ok_or_else(invalid)
        })?;
    for service in services {
        let group = field(service, "name")?;
        let tag = field(service, "outbound")?;
        if proxies
            .iter()
            .chain(&groups)
            .any(|item| item.get("name").and_then(Value::as_str) == Some(group))
        {
            return Err(ApplyError {
                status: 503,
                detail: "Service routing name conflict".into(),
            });
        }
        groups.push(selector(
            group,
            vec![json!(outbound.get(tag).map_or("REJECT", String::as_str))],
        ));
        let provider = format!("service-{group}");
        let mut payload = Vec::new();
        if field(service, "udp")? == "reject" {
            rules.push(json!(format!(
                "AND,((RULE-SET,{provider}),(NETWORK,UDP)),REJECT"
            )));
        }
        rules.push(json!(format!("RULE-SET,{provider},{group}")));
        for entry in sequence(service, "domains")? {
            let host = entry.as_str().ok_or_else(invalid)?;
            payload.push(json!(format!("+.{host}")));
            dns.insert(
                format!("+.{host}"),
                json!([
                    format!("https://1.1.1.1/dns-query#{group}"),
                    format!("https://1.0.0.1/dns-query#{group}")
                ]),
            );
        }
        providers.insert(
            provider,
            json!({"type":"inline","behavior":"domain","payload":payload}),
        );
    }
    let mut stun_payload = Vec::new();
    for (host, ports) in [
        ("stun.cloudflare.com", "3478"),
        ("stun.l.google.com", "19302"),
        ("stun1.l.google.com", "19302"),
        ("stun2.l.google.com", "19302"),
        ("stun3.l.google.com", "19302"),
        ("stun4.l.google.com", "19302"),
        ("turn.cloudflare.com", "3478/443"),
    ] {
        stun_payload.push(json!(format!(
            "AND,((NETWORK,UDP),(DOMAIN,{host}),(DST-PORT,{ports}))"
        )));
        dns.insert(
            host.into(),
            json!([
                "https://1.1.1.1/dns-query#STUN",
                "https://1.0.0.1/dns-query#STUN"
            ]),
        );
    }
    providers.insert(
        "stun-endpoints".into(),
        json!({"type":"inline","behavior":"classical","payload":stun_payload}),
    );
    for rule in [
        "RULE-SET,stun-endpoints,STUN",
        "RULE-SET,stun-endpoints,REJECT",
        "GEOSITE,private,DIRECT",
        "GEOSITE,cn,DIRECT",
        "GEOSITE,geolocation-!cn,PROXY",
        "GEOIP,private,DIRECT,no-resolve",
        "GEOIP,CN,DIRECT",
        "MATCH,PROXY",
    ] {
        rules.push(json!(rule));
    }
    dns.insert("geosite:cn,private".into(), domestic.clone());
    let mut result = json!({"mixed-port":7890,"allow-lan":false,"mode":"rule","log-level":"warning","ipv6":false,
        "profile":{"store-selected":true},"hosts":{domain:address},
        "dns":{"enable":true,"ipv6":false,"enhanced-mode":"fake-ip","fake-ip-range":"198.18.0.1/16","use-hosts":true,
            "default-nameserver":["223.5.5.5","119.29.29.29"],"proxy-server-nameserver":domestic,"direct-nameserver":domestic,
            "direct-nameserver-follow-policy":false,"nameserver-policy":dns,"nameserver":["https://1.1.1.1/dns-query#PROXY","https://1.0.0.1/dns-query#PROXY"]},
        "proxies":proxies,"proxy-groups":groups,"rules":rules});
    if !providers.is_empty() {
        result["rule-providers"] = Value::Object(providers);
    }
    let baseline = result["dns"]["nameserver-policy"].clone();
    let managed = flag(policy, "managed", false)?;
    let (independent, ai) = if managed {
        let independent = field(policy, "base")? == "independent";
        if independent
            && services.iter().any(|service| {
                service
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|s| {
                        ["AI", "CLAUDE", "Telegram", "YouTube", "Netflix", "Apple"].contains(&s)
                    })
            })
        {
            return Err(ApplyError {
                status: 422,
                detail: "该用户已有同名业务分流，请先处理冲突".into(),
            });
        }
        (independent, field(policy, "ai_outbound")?)
    } else if let Some(value) = settings
        .get("client_policies")
        .and_then(|v| v.get(&user.id))
    {
        (true, field(value, "ai_outbound")?)
    } else {
        (false, "proxy")
    };
    if independent {
        apply_client_policy(&mut result, ai, &outbound)?;
    }
    if managed {
        let mut spec = policy.clone();
        spec.as_object_mut()
            .ok_or_else(invalid)?
            .shift_remove("managed");
        apply_template_rules(&mut result, &spec, &baseline, factory_independent_rules())?;
    }
    if independent {
        apply_google_policy(&mut result)?;
    }
    apply_oracle(&mut result)?;
    Ok(result)
}

fn apply_oracle(config: &mut Value) -> Result<()> {
    let mut names = BTreeSet::new();
    for item in config["proxies"]
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .chain(config["proxy-groups"].as_array().ok_or_else(invalid)?)
    {
        names.insert(field(item, "name")?.to_owned());
    }
    let mut group = "oracle-cloud".to_owned();
    let mut n = 2;
    while names.contains(&group) {
        group = format!("oracle-cloud · 直连 {n}");
        n += 1;
    }
    config["proxy-groups"]
        .as_array_mut()
        .ok_or_else(invalid)?
        .push(selector(&group, vec![json!("DIRECT")]));
    let providers = config["rule-providers"]
        .as_object_mut()
        .ok_or_else(invalid)?;
    let mut provider = "xcli-oracle-cloud".to_owned();
    let mut n = 2;
    while providers.contains_key(&provider) {
        provider = format!("xcli-oracle-cloud-{n}");
        n += 1;
    }
    providers.insert(provider.clone(),json!({"type":"inline","behavior":"classical","payload":[
        "DOMAIN-SUFFIX,oracle.com","DOMAIN-SUFFIX,oraclecloud.com","DOMAIN-SUFFIX,oraclecloudapps.com",
        "DOMAIN-SUFFIX,oraclecloud.net","DOMAIN-SUFFIX,oraclegovcloud.com","DOMAIN-SUFFIX,oracleinfinity.io",
        "DOMAIN-SUFFIX,oracleimg.com","DOMAIN-SUFFIX,ocir.io","DOMAIN,oracle.112.2o7.net","DOMAIN,consent.trustarc.com"]}));
    let rules = config["rules"].as_array_mut().ok_or_else(invalid)?;
    let position = rules
        .iter()
        .position(|v| v == "DOMAIN-SUFFIX,todesk.com,DIRECT")
        .map_or(rules.len(), |n| n + 1);
    rules.insert(position, json!(format!("RULE-SET,{provider},{group}")));
    let dns = config["dns"]["nameserver-policy"]
        .as_object()
        .ok_or_else(invalid)?;
    let mut ordered = Map::new();
    ordered.insert(
        format!("rule-set:{provider}"),
        json!([
            "https://223.5.5.5/dns-query#DIRECT",
            "https://1.12.12.12/dns-query#DIRECT"
        ]),
    );
    for (key, value) in dns {
        ordered.insert(key.clone(), value.clone());
    }
    config["dns"]["nameserver-policy"] = Value::Object(ordered);
    Ok(())
}

/// Serialize with the same insertion order and JSON-compatible YAML quoting as
/// the existing subscription endpoint. The result contains user credentials.
pub fn render(config: &Value) -> Result<String> {
    fn emit(value: &Value, depth: usize, text: &mut String) -> Result<()> {
        let indent = " ".repeat(depth);
        if let Some(object) = value.as_object() {
            for (key, item) in object {
                text.push_str(&indent);
                text.push_str(&serde_json::to_string(key).map_err(|_| invalid())?);
                text.push(':');
                let structured = item.as_object().is_some_and(|v| !v.is_empty())
                    || item.as_array().is_some_and(|v| !v.is_empty());
                if structured {
                    text.push('\n');
                    emit(item, depth + 2, text)?;
                } else {
                    text.push(' ');
                    text.push_str(&serde_json::to_string(item).map_err(|_| invalid())?);
                    text.push('\n');
                }
            }
        } else if let Some(array) = value.as_array() {
            for item in array {
                text.push_str(&indent);
                text.push_str("- ");
                text.push_str(&serde_json::to_string(item).map_err(|_| invalid())?);
                text.push('\n');
            }
        } else {
            return Err(invalid());
        }
        Ok(())
    }
    let mut text=String::from("# Xdistribute — Clash Verge Rev / Mihomo\n# China/private destinations use DIRECT; other traffic uses PROXY.\n# Domestic DNS uses direct DoH; overseas DNS follows PROXY. Residential exits support TCP only.\n# Listed Google/Cloudflare STUN UDP endpoints use STUN (server egress, not residential egress).\n# Requires UDP capture and DNS metadata, e.g. TUN + fake-IP. Other/custom STUN endpoints are not covered.\n");
    emit(config, 0, &mut text)?;
    Ok(text)
}
