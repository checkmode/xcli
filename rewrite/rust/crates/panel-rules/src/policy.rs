use super::{apply::selects_direct, factory_independent_rules, ApplyError};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

fn unavailable() -> ApplyError {
    ApplyError {
        status: 503,
        detail: "策略配置不可用".into(),
    }
}
fn array(value: &Value) -> Result<&Vec<Value>, ApplyError> {
    value.as_array().ok_or_else(unavailable)
}
fn object(value: &Value) -> Result<&Map<String, Value>, ApplyError> {
    value.as_object().ok_or_else(unavailable)
}
fn name(value: &Value) -> Result<&str, ApplyError> {
    value
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(unavailable)
}
fn group(name: &str, members: Vec<Value>) -> Value {
    json!({"name":name,"type":"select","proxies":members})
}

struct Category {
    name: &'static str,
    direct: bool,
    entries: Vec<(String, String)>,
}
fn categories() -> Result<Vec<Category>, ApplyError> {
    let mut values: Vec<Category> = [
        ("EaseLian", false),
        ("AI", false),
        ("Telegram", false),
        ("YouTube", false),
        ("Netflix", false),
        ("国外媒体", false),
        ("哔哩哔哩", true),
        ("Apple", true),
    ]
    .into_iter()
    .map(|(name, direct)| Category {
        name,
        direct,
        entries: Vec::new(),
    })
    .collect();
    let bilibili = [
        "bilibili.com",
        "biliapi.com",
        "biliapi.net",
        "bilivideo.com",
        "hdslb.com",
    ];
    for line in factory_independent_rules().lines() {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() != 3 {
            return Err(unavailable());
        }
        let category = match fields[2] {
            "EaseLian" => "EaseLian",
            "DIRECT" if bilibili.contains(&fields[1]) => "哔哩哔哩",
            "DIRECT" => "Apple",
            name => name.strip_prefix("独立 · ").ok_or_else(unavailable)?,
        };
        let item = values
            .iter_mut()
            .find(|entry| entry.name == category)
            .ok_or_else(unavailable)?;
        item.entries.push((fields[0].into(), fields[1].into()));
    }
    Ok(values)
}

/// Add the legacy independent selectors and domain categories to a generated
/// configuration. The caller supplies the selected AI outbound from trusted
/// settings; errors never leave a partially changed configuration.
pub fn apply_client_policy(
    config: &mut Value,
    ai_outbound: &str,
    outbound: &BTreeMap<String, String>,
) -> Result<(), ApplyError> {
    let categories = categories()?;
    let mut groups = array(config.get("proxy-groups").ok_or_else(unavailable)?)?.clone();
    let proxies = array(config.get("proxies").ok_or_else(unavailable)?)?;
    let mut servers: Vec<Value> = Vec::new();
    for tag in ["reality", "websocket", "vmess", "hysteria2"] {
        if let Some(value) = outbound.get(tag) {
            servers.push(json!(value));
        }
    }
    for (tag, value) in outbound {
        if tag.starts_with("remote-") {
            servers.push(json!(value));
        }
    }
    let mut countries = Vec::new();
    for item in &mut groups {
        let group_name = name(item)?.to_owned();
        if group_name.starts_with("住宅分组 · ") {
            countries.push(json!(group_name));
        }
        if group_name == "STUN" {
            item["name"] = json!("独立 · STUN");
            item["proxies"] = json!(servers);
        }
        let members = item
            .get_mut("proxies")
            .and_then(Value::as_array_mut)
            .ok_or_else(unavailable)?;
        if members.len() == 2
            && members[0]
                .as_str()
                .is_some_and(|s| s.ends_with(" · Hysteria2"))
            && members[1].as_str().is_some_and(|s| s.ends_with(" · HTTPS"))
        {
            members.swap(0, 1);
        }
    }
    let mut top = Vec::new();
    let mut main = vec![json!("故障转移"), json!("自动选择")];
    main.extend(servers.clone());
    // The fixed-rate entry is explicitly selectable, but never silently added
    // to automatic or fallback groups for existing users.
    if let Some(value) = outbound.get("hysteria2-brutal") {
        main.push(json!(value));
    }
    if !countries.is_empty() {
        main.push(json!("住宅节点"));
    }
    main.push(json!("直连"));
    top.push(group("PROXY", main));
    top.push(group("直连", vec![json!("DIRECT")]));
    for (label, kind) in [("故障转移", "fallback"), ("自动选择", "url-test")] {
        let mut item = json!({"name":label,"type":kind,"proxies":servers,"url":"https://www.gstatic.com/generate_204",
            "interval":120,"timeout":5000,"lazy":true});
        if kind == "url-test" {
            item["tolerance"] = json!(100);
        }
        top.push(item);
    }
    if !countries.is_empty() {
        top.push(group("住宅节点", countries.clone()));
    }
    let default = if ai_outbound == "proxy" {
        "故障转移"
    } else {
        outbound.get(ai_outbound).map_or("REJECT", String::as_str)
    };
    for category in &categories {
        if category.direct {
            continue;
        }
        let mut choices = vec![json!("故障转移"), json!("自动选择")];
        if category.name == "EaseLian" {
            choices.insert(0, json!("DIRECT"));
            choices.insert(0, json!("PROXY"));
        }
        if category.name == "AI" && default != "故障转移" {
            choices.insert(0, json!(default));
        }
        choices.extend(countries.clone());
        for node in &servers {
            if !choices.contains(node) {
                choices.push(node.clone());
            }
        }
        if let Some(value) = outbound.get("hysteria2-brutal") {
            choices.push(json!(value));
        }
        let label = if category.name == "EaseLian" {
            "EaseLian".to_owned()
        } else {
            format!("独立 · {}", category.name)
        };
        top.push(group(&label, choices));
    }
    let mut google = vec![json!("故障转移"), json!("自动选择")];
    google.extend(countries);
    google.extend(servers);
    if let Some(value) = outbound.get("hysteria2-brutal") {
        google.push(json!(value));
    }
    top.push(group("独立 · Google", google));
    top.push(group("其他流量", vec![json!("PROXY"), json!("DIRECT")]));
    for item in groups {
        if name(&item)? != "PROXY" {
            top.push(item);
        }
    }
    let mut names = BTreeSet::new();
    for proxy in proxies {
        names.insert(name(proxy)?.to_owned());
    }
    for item in &top {
        if !names.insert(name(item)?.to_owned()) {
            return Err(ApplyError {
                status: 503,
                detail: "Client policy name conflict".into(),
            });
        }
    }
    let mut dns = object(
        config
            .get("dns")
            .and_then(|v| v.get("nameserver-policy"))
            .ok_or_else(unavailable)?,
    )?
    .clone();
    for resolvers in dns.values_mut() {
        for resolver in resolvers.as_array_mut().ok_or_else(unavailable)? {
            let text = resolver.as_str().ok_or_else(unavailable)?;
            if let Some(prefix) = text.strip_suffix("STUN") {
                if text.ends_with("#STUN") {
                    *resolver = json!(format!("{prefix}独立 · STUN"));
                }
            }
        }
    }
    let mut providers = object(config.get("rule-providers").ok_or_else(unavailable)?)?.clone();
    let mut additions = Vec::new();
    for category in categories {
        let target = if category.direct {
            "DIRECT".to_owned()
        } else if category.name == "EaseLian" {
            "EaseLian".to_owned()
        } else {
            format!("独立 · {}", category.name)
        };
        let direct = category.direct || selects_direct(&top, &target);
        let mut payload = Vec::new();
        for (kind, value) in category.entries {
            if kind == "DOMAIN" || kind == "DOMAIN-SUFFIX" {
                payload.push(json!(format!("{kind},{value}")));
                let key = if kind == "DOMAIN-SUFFIX" {
                    format!("+.{value}")
                } else {
                    value
                };
                let hosts = if direct {
                    [
                        "https://223.5.5.5/dns-query#",
                        "https://1.12.12.12/dns-query#",
                    ]
                } else {
                    ["https://1.1.1.1/dns-query#", "https://1.0.0.1/dns-query#"]
                };
                dns.insert(
                    key,
                    json!([
                        format!("{}{target}", hosts[0]),
                        format!("{}{target}", hosts[1])
                    ]),
                );
            } else {
                payload.push(json!(format!("{kind},{value},no-resolve")));
            }
        }
        let provider = format!("category-{}", category.name);
        providers.insert(
            provider.clone(),
            json!({"type":"inline","behavior":"classical","payload":payload}),
        );
        if category.name == "AI" {
            additions.push(json!(format!(
                "AND,((RULE-SET,{provider}),(NETWORK,UDP)),REJECT"
            )));
        }
        additions.push(json!(format!("RULE-SET,{provider},{target}")));
    }
    let mut rules = array(config.get("rules").ok_or_else(unavailable)?)?.clone();
    for item in &mut rules {
        if item == "RULE-SET,stun-endpoints,STUN" {
            *item = json!("RULE-SET,stun-endpoints,独立 · STUN");
        }
    }
    let position = rules
        .iter()
        .position(|v| v == "GEOSITE,private,DIRECT")
        .unwrap_or(rules.len());
    rules.splice(position..position, additions);
    *rules.last_mut().ok_or_else(unavailable)? = json!("MATCH,其他流量");
    config["proxy-groups"] = json!(top);
    config["dns"]["nameserver-policy"] = Value::Object(dns);
    config["rule-providers"] = Value::Object(providers);
    config["rules"] = json!(rules);
    Ok(())
}

/// Add the independent Google selector's provider after higher-priority
/// service and template rules. DNS insertion order is preserved.
pub fn apply_google_policy(config: &mut Value) -> Result<(), ApplyError> {
    let domains = [
        "google.com",
        "google.cn",
        "google.com.hk",
        "google.com.sg",
        "google.com.tw",
        "google.com.au",
        "google.co.jp",
        "google.co.uk",
        "google.co.in",
        "google.com.br",
        "google.de",
        "google.fr",
        "g.co",
        "android.com",
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
        "googleplay.com",
        "ggpht.com",
        "gvt1.com",
        "gvt2.com",
        "google-analytics.com",
        "googletagmanager.com",
        "googleadservices.com",
        "googlesyndication.com",
    ];
    let mut providers = object(config.get("rule-providers").ok_or_else(unavailable)?)?.clone();
    if providers.contains_key("category-Google") {
        return Err(ApplyError {
            status: 503,
            detail: "Google policy provider conflict".into(),
        });
    }
    providers.insert("category-Google".into(),json!({"type":"inline","behavior":"classical",
        "payload":domains.iter().map(|domain|format!("DOMAIN-SUFFIX,{domain}")).collect::<Vec<_>>()}));
    let mut rules = array(config.get("rules").ok_or_else(unavailable)?)?.clone();
    let position = rules
        .iter()
        .position(|v| v == "GEOSITE,private,DIRECT")
        .unwrap_or(rules.len());
    rules.splice(
        position..position,
        [
            json!("RULE-SET,category-Google,独立 · Google"),
            json!("RULE-SET,category-Google,REJECT"),
        ],
    );
    let dns = object(
        config
            .get("dns")
            .and_then(|v| v.get("nameserver-policy"))
            .ok_or_else(unavailable)?,
    )?;
    let mut ordered = Map::new();
    for (key, value) in dns {
        if !key.starts_with("geosite:") {
            ordered.insert(key.clone(), value.clone());
        }
    }
    for domain in domains {
        ordered.entry(format!("+.{domain}")).or_insert_with(|| {
            json!([
                "https://1.1.1.1/dns-query#独立 · Google",
                "https://1.0.0.1/dns-query#独立 · Google"
            ])
        });
    }
    for (key, value) in dns {
        if key.starts_with("geosite:") {
            ordered.insert(key.clone(), value.clone());
        }
    }
    config["rule-providers"] = Value::Object(providers);
    config["rules"] = json!(rules);
    config["dns"]["nameserver-policy"] = Value::Object(ordered);
    Ok(())
}
