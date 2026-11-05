use super::{parse_rules, validate};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

#[derive(Debug, PartialEq, Eq)]
pub struct ApplyError {
    pub status: u16,
    pub detail: String,
}
fn fail(status: u16, message: impl Into<String>) -> ApplyError {
    ApplyError {
        status,
        detail: message.into(),
    }
}
fn invalid() -> ApplyError {
    fail(503, "策略配置不可用")
}
fn name(value: &Value) -> Result<&str, ApplyError> {
    value
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(invalid)
}
fn array(value: &Value) -> Result<&Vec<Value>, ApplyError> {
    value.as_array().ok_or_else(invalid)
}
fn object(value: &Value) -> Result<&Map<String, Value>, ApplyError> {
    value.as_object().ok_or_else(invalid)
}
fn insert_unique(values: &mut Vec<Value>, value: Value) {
    if !values.contains(&value) {
        values.push(value);
    }
}

pub(super) fn selects_direct(groups: &[Value], target: &str) -> bool {
    fn visit(groups: &[Value], target: &str, visited: &mut BTreeSet<String>) -> bool {
        if target == "DIRECT" {
            return true;
        }
        if !visited.insert(target.to_owned()) {
            return false;
        }
        groups
            .iter()
            .filter(|group| group.get("name").and_then(Value::as_str) == Some(target))
            .filter_map(|group| group.get("proxies").and_then(Value::as_array))
            .flatten()
            .filter_map(Value::as_str)
            .any(|child| visit(groups, child, visited))
    }
    visit(groups, target, &mut BTreeSet::new())
}
fn resolvers(groups: &[Value], target: &str) -> Value {
    let direct = target == "DIRECT" || selects_direct(groups, target);
    let hosts = if direct {
        [
            "https://223.5.5.5/dns-query#",
            "https://1.12.12.12/dns-query#",
        ]
    } else {
        ["https://1.1.1.1/dns-query#", "https://1.0.0.1/dns-query#"]
    };
    json!([
        format!("{}{target}", hosts[0]),
        format!("{}{target}", hosts[1])
    ])
}
fn ordered_dns(dns: Map<String, Value>) -> Map<String, Value> {
    let mut output = Map::new();
    for (key, value) in &dns {
        if !key.starts_with("geosite:") && !key.starts_with("rule-set:") {
            output.insert(key.clone(), value.clone());
        }
    }
    for (key, value) in dns {
        if key.starts_with("geosite:") || key.starts_with("rule-set:") {
            output.insert(key, value);
        }
    }
    output
}

/// Apply custom groups and ordered rules to a generated Clash configuration.
/// `factory_independent_rules` must come from the matching factory catalog;
/// callers must not accept it from an unauthenticated client. On error the
/// original configuration remains untouched.
pub fn apply_template_rules(
    config: &mut Value,
    input: &Value,
    baseline_dns: &Value,
    factory_independent_rules: &str,
) -> Result<(), ApplyError> {
    let spec = validate(input).map_err(|error| fail(422, error.0))?;
    let base = spec["base"].as_str().ok_or_else(invalid)?;
    let text = spec["rules"].as_str().ok_or_else(invalid)?;
    let mut groups = array(config.get("proxy-groups").ok_or_else(invalid)?)?.clone();
    let proxies = array(config.get("proxies").ok_or_else(invalid)?)?;
    let mut available: BTreeSet<String> = ["DIRECT".into(), "REJECT".into()].into_iter().collect();
    for item in proxies.iter().chain(&groups) {
        available.insert(name(item)?.to_owned());
    }
    let proxy = groups
        .iter()
        .find(|item| item.get("name").and_then(Value::as_str) == Some("PROXY"))
        .ok_or_else(|| fail(503, "缺少 PROXY 策略组"))?;
    let candidates = array(proxy.get("proxies").ok_or_else(invalid)?)?.clone();
    let mut custom = BTreeSet::new();
    for group in spec
        .get("groups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = name(group)?;
        let choice = group
            .get("default")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        if !available.insert(name.to_owned()) {
            return Err(fail(422, format!("策略组与现有节点或策略组重名：{name}")));
        }
        if !available.contains(choice) {
            return Err(fail(422, format!("策略组默认出口不可用：{choice}")));
        }
        let mut members = vec![json!(choice)];
        for item in [json!("PROXY"), json!("DIRECT")]
            .into_iter()
            .chain(candidates.iter().cloned())
        {
            insert_unique(&mut members, item);
        }
        groups.push(json!({"name":name,"type":"select","proxies":members}));
        custom.insert(name.to_owned());
    }
    if base == "independent" && text == factory_independent_rules {
        config["proxy-groups"] = json!(groups);
        return Ok(());
    }
    let parsed = parse_rules(text, base, &custom).map_err(|error| fail(422, error.0))?;
    let mut rules = array(config.get("rules").ok_or_else(invalid)?)?.clone();
    let mut dns = object(
        config
            .get("dns")
            .and_then(|v| v.get("nameserver-policy"))
            .ok_or_else(invalid)?,
    )?
    .clone();
    let mut providers = object(config.get("rule-providers").ok_or_else(invalid)?)?.clone();
    if base == "independent" {
        rules.retain(|item| {
            item.as_str()
                .is_none_or(|value| !value.contains("RULE-SET,category-"))
        });
        for category in [
            "EaseLian",
            "AI",
            "Telegram",
            "YouTube",
            "Netflix",
            "国外媒体",
            "哔哩哔哩",
            "Apple",
        ] {
            providers.shift_remove(&format!("category-{category}"));
        }
        let baseline = object(baseline_dns)?;
        let factory = parse_rules(factory_independent_rules, "independent", &BTreeSet::new())
            .map_err(|_| invalid())?;
        for rule in factory {
            let key = match rule.kind.as_str() {
                "DOMAIN" => rule.value,
                "DOMAIN-SUFFIX" => format!("+.{}", rule.value),
                _ => continue,
            };
            if let Some(value) = baseline.get(&key) {
                dns.insert(key, value.clone());
            } else {
                dns.shift_remove(&key);
            }
        }
    }
    let mut targets: BTreeSet<String> = ["DIRECT".into(), "REJECT".into()].into_iter().collect();
    for item in &groups {
        targets.insert(name(item)?.to_owned());
    }
    let mut inserted = Vec::new();
    for rule in &parsed {
        if !targets.contains(&rule.target) {
            return Err(fail(
                422,
                format!("模板引用的策略组当前不可用：{}", rule.target),
            ));
        }
        let condition = format!("{},{}", rule.kind, rule.value);
        let suffix = if rule.no_resolve { ",no-resolve" } else { "" };
        let nested = if rule.no_resolve && rule.explicit_resolution {
            ",no-resolve"
        } else {
            ""
        };
        if rule.target == "独立 · AI" {
            inserted.push(json!(format!(
                "AND,(({condition}{nested}),(NETWORK,UDP)),REJECT"
            )));
        }
        inserted.push(json!(format!("{condition},{}{suffix}", rule.target)));
        if rule.target != "DIRECT" && rule.target != "REJECT" {
            inserted.push(json!(format!("{condition},REJECT{suffix}")));
        }
    }
    if parsed.iter().any(|rule| rule.kind == "DOMAIN-KEYWORD") {
        let mut ordered = Map::new();
        for (key, value) in &dns {
            if !key.starts_with("geosite:") && !key.starts_with("rule-set:") {
                ordered.insert(key.clone(), value.clone());
            }
        }
        let mut provider = String::new();
        let mut last_target = String::new();
        let mut count = 0;
        for rule in &parsed {
            if !matches!(
                rule.kind.as_str(),
                "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD"
            ) {
                continue;
            }
            if provider.is_empty() || last_target != rule.target {
                last_target.clone_from(&rule.target);
                count += 1;
                provider = format!("xcli-dns-{count}");
                providers.insert(
                    provider.clone(),
                    json!({"type":"inline","behavior":"classical","payload":[]}),
                );
                ordered.insert(
                    format!("rule-set:{provider}"),
                    resolvers(&groups, &rule.target),
                );
            }
            providers
                .get_mut(&provider)
                .and_then(|value| value.get_mut("payload"))
                .and_then(Value::as_array_mut)
                .ok_or_else(invalid)?
                .push(json!(format!("{},{}", rule.kind, rule.value)));
        }
        for (key, value) in dns {
            if key.starts_with("geosite:") || key.starts_with("rule-set:") {
                ordered.insert(key, value);
            }
        }
        dns = ordered;
    } else {
        for rule in parsed.iter().rev() {
            if !matches!(rule.kind.as_str(), "DOMAIN" | "DOMAIN-SUFFIX") {
                continue;
            }
            if rule.kind == "DOMAIN-SUFFIX" {
                let remove: Vec<String> = dns
                    .keys()
                    .filter(|key| {
                        let host = key.strip_prefix("+.").unwrap_or(key);
                        host == rule.value || host.ends_with(&format!(".{}", rule.value))
                    })
                    .cloned()
                    .collect();
                for key in remove {
                    dns.shift_remove(&key);
                }
            }
            let key = if rule.kind == "DOMAIN-SUFFIX" {
                format!("+.{}", rule.value)
            } else {
                rule.value.clone()
            };
            dns.insert(key, resolvers(&groups, &rule.target));
        }
        dns = ordered_dns(dns);
    }
    let position = rules
        .iter()
        .position(|rule| rule.as_str() == Some("GEOSITE,private,DIRECT"))
        .unwrap_or(rules.len());
    rules.splice(position..position, inserted);
    config["proxy-groups"] = json!(groups);
    config["rules"] = json!(rules);
    config["dns"]["nameserver-policy"] = Value::Object(dns);
    config["rule-providers"] = Value::Object(providers);
    Ok(())
}
