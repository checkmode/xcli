use super::{field, invalid, system_rules_preview, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use xcli_panel_rules::ApplyError;

#[derive(Clone)]
struct Entry {
    kind: String,
    value: String,
    target: String,
    option: String,
    provider: String,
}

fn fail(detail: &str) -> ApplyError {
    ApplyError {
        status: 422,
        detail: detail.into(),
    }
}

pub(super) fn identity(
    provider: &str,
    kind: &str,
    value: &str,
    target: &str,
    option: &str,
    domain: &str,
) -> String {
    let value = if provider.is_empty() && kind == "DOMAIN" && value == domain && target == "DIRECT"
    {
        "{panel-domain}"
    } else {
        value
    };
    let mut hash = Sha256::new();
    for part in [provider, kind, value, target, option] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    hex::encode(hash.finalize())
}

fn standalone(raw: &str) -> Result<Entry> {
    let (text, option) = raw
        .strip_suffix(",no-resolve")
        .map_or((raw, ""), |value| (value, "no-resolve"));
    let (condition, target) = text.rsplit_once(',').ok_or_else(invalid)?;
    let (kind, value) = condition
        .split_once(',')
        .unwrap_or((condition, "全部剩余流量"));
    Ok(Entry {
        kind: kind.into(),
        value: value.into(),
        target: target.into(),
        option: option.into(),
        provider: String::new(),
    })
}

fn payload(raw: &str, provider: &str, target: &str) -> Result<Entry> {
    let (text, option) = raw
        .strip_suffix(",no-resolve")
        .map_or((raw, ""), |value| (value, "no-resolve"));
    let (kind, value) = text.split_once(',').ok_or_else(invalid)?;
    Ok(Entry {
        kind: kind.into(),
        value: value.into(),
        target: target.into(),
        option: option.into(),
        provider: provider.into(),
    })
}

fn key(entry: &Entry, domain: &str) -> String {
    identity(
        &entry.provider,
        &entry.kind,
        &entry.value,
        &entry.target,
        &entry.option,
        domain,
    )
}

fn from_value(value: &Value) -> Result<Entry> {
    Ok(Entry {
        kind: field(value, "kind")?.into(),
        value: field(value, "value")?.into(),
        target: field(value, "target")?.into(),
        option: field(value, "option")?.into(),
        provider: String::new(),
    })
}

fn encode(entry: &Entry) -> String {
    let condition = if entry.kind == "MATCH" {
        "MATCH".to_owned()
    } else {
        format!("{},{}", entry.kind, entry.value)
    };
    let option = if entry.option == "no-resolve" {
        ",no-resolve"
    } else {
        ""
    };
    format!("{condition},{}{option}", entry.target)
}

fn nameserver(config: &Value, target: &str) -> Value {
    let groups = config["proxy-groups"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let hosts = if xcli_panel_rules::selects_direct(groups, target) {
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

fn dns_key(entry: &Entry) -> Option<String> {
    match entry.kind.as_str() {
        "DOMAIN" => Some(entry.value.clone()),
        "DOMAIN-SUFFIX" => Some(format!("+.{}", entry.value)),
        _ => None,
    }
}

fn first_domain_target(config: &Value, condition: &Entry) -> Result<Option<String>> {
    let providers = config["rule-providers"].as_object().ok_or_else(invalid)?;
    for value in config["rules"].as_array().ok_or_else(invalid)? {
        let raw = value.as_str().ok_or_else(invalid)?;
        if let Some(rest) = raw.strip_prefix("RULE-SET,") {
            let Some((name, target)) = rest.split_once(',') else {
                return Err(invalid());
            };
            let Some(provider) = providers.get(name) else {
                return Err(invalid());
            };
            if provider["behavior"].as_str() != Some("classical") {
                continue;
            }
            for item in provider["payload"].as_array().ok_or_else(invalid)? {
                let entry = payload(item.as_str().ok_or_else(invalid)?, name, target)?;
                if entry.kind == condition.kind && entry.value == condition.value {
                    return Ok(Some(entry.target));
                }
            }
        } else {
            let entry = standalone(raw)?;
            if entry.kind == condition.kind && entry.value == condition.value {
                return Ok(Some(entry.target));
            }
        }
    }
    Ok(None)
}

/// Apply edits at their original generated rule positions. With no overrides
/// the caller leaves the old configuration byte-for-byte unchanged.
pub(super) fn apply(config: &mut Value, policy: &Value, domain: &str) -> Result<()> {
    let Some(overrides) = policy
        .get("system_overrides")
        .and_then(Value::as_object)
        .filter(|v| !v.is_empty())
    else {
        return Ok(());
    };
    let base = field(policy, "base")?;
    let baseline = system_rules_preview(domain, base)?;
    let originals: BTreeMap<String, Entry> = baseline
        .iter()
        .map(|row| Ok((field(row, "id")?.to_owned(), from_value(row)?)))
        .collect::<Result<_>>()?;
    let mut provider_for = BTreeMap::new();
    for row in baseline {
        provider_for.insert(
            field(&row, "id")?.to_owned(),
            field(&row, "provider")?.to_owned(),
        );
    }
    let mut available: BTreeSet<String> = ["DIRECT".into(), "REJECT".into()].into_iter().collect();
    for group in config["proxy-groups"].as_array().ok_or_else(invalid)? {
        available.insert(field(group, "name")?.into());
    }
    for (id, value) in overrides {
        let original = originals
            .get(id)
            .ok_or_else(|| fail("系统规则已变化，请恢复默认后重新修改"))?;
        if original.kind == "MATCH" && value.is_null() {
            return Err(fail("兜底规则不能停用"));
        }
        if !value.is_null() {
            let edited = from_value(value)?;
            if !available.contains(&edited.target) {
                return Err(fail("系统规则的分流去向当前不可用"));
            }
            if (original.kind == "MATCH") != (edited.kind == "MATCH") {
                return Err(fail("兜底规则只能修改去向"));
            }
            if edited.kind == "AND" && (original.kind != "AND" || edited.value != original.value) {
                return Err(fail("复合规则只能修改去向"));
            }
        }
    }
    let providers = config["rule-providers"]
        .as_object()
        .ok_or_else(invalid)?
        .clone();
    let mut next = Vec::new();
    let mut used = BTreeSet::new();
    for item in config["rules"].as_array().ok_or_else(invalid)? {
        let raw = item.as_str().ok_or_else(invalid)?;
        if let Some(rest) = raw.strip_prefix("RULE-SET,") {
            let (name, target) = rest.split_once(',').ok_or_else(invalid)?;
            let Some(provider) = providers.get(name) else {
                return Err(invalid());
            };
            if provider["behavior"].as_str() != Some("classical") {
                next.push(item.clone());
                continue;
            }
            let entries = provider["payload"]
                .as_array()
                .ok_or_else(invalid)?
                .iter()
                .map(|item| payload(item.as_str().ok_or_else(invalid)?, name, target))
                .collect::<Result<Vec<_>>>()?;
            let changed = entries
                .iter()
                .any(|entry| overrides.contains_key(&key(entry, domain)));
            if !changed {
                next.push(item.clone());
                continue;
            }
            for entry in entries {
                let id = key(&entry, domain);
                if let Some(value) = overrides.get(&id) {
                    used.insert(id);
                    if !value.is_null() {
                        next.push(json!(encode(&from_value(value)?)));
                    }
                } else {
                    next.push(json!(encode(&entry)));
                }
            }
        } else {
            let entry = standalone(raw)?;
            let id = key(&entry, domain);
            if originals.contains_key(&id) && !used.contains(&id) && overrides.contains_key(&id) {
                used.insert(id.clone());
                let value = &overrides[&id];
                if !value.is_null() {
                    next.push(json!(encode(&from_value(value)?)));
                }
            } else {
                next.push(item.clone());
            }
        }
    }
    if used.len() != overrides.len() {
        return Err(fail("系统规则在该用户配置中不可用"));
    }
    config["rules"] = json!(next);

    let mut affected = BTreeMap::new();
    let mut geosite_changed = false;
    for (id, value) in overrides {
        let original = &originals[id];
        if let Some(key) = dns_key(original) {
            affected.insert(key, original.clone());
        }
        geosite_changed |= original.kind == "GEOSITE";
        if !value.is_null() {
            let edited = from_value(value)?;
            if let Some(key) = dns_key(&edited) {
                affected.insert(key, edited.clone());
            }
            geosite_changed |= edited.kind == "GEOSITE";
        }
    }
    let existing = config["dns"]["nameserver-policy"]
        .as_object()
        .ok_or_else(invalid)?
        .clone();
    let mut oracle_dns = BTreeMap::new();
    for (id, provider) in provider_for {
        if !overrides.contains_key(&id)
            || !provider.starts_with("xcli-oracle-cloud")
            || oracle_dns.contains_key(&provider)
        {
            continue;
        }
        if !existing.contains_key(&format!("rule-set:{provider}")) {
            continue;
        }
        let source = providers.get(&provider).ok_or_else(invalid)?;
        let target = &originals[&id].target;
        let kept = source["payload"]
            .as_array()
            .ok_or_else(invalid)?
            .iter()
            .filter_map(|item| {
                let entry = payload(item.as_str()?, &provider, target).ok()?;
                (!overrides.contains_key(&key(&entry, domain))).then(|| item.clone())
            })
            .collect::<Vec<_>>();
        let stem = format!("{provider}-dns-edited");
        let mut replacement = stem.clone();
        let mut suffix = 2;
        while config["rule-providers"].get(&replacement).is_some() {
            replacement = format!("{stem}-{suffix}");
            suffix += 1;
        }
        config["rule-providers"][&replacement] =
            json!({"type":"inline","behavior":"classical","payload":kept});
        oracle_dns.insert(provider, replacement);
    }
    let mut updates = BTreeMap::new();
    for (key, entry) in &affected {
        let value = first_domain_target(config, entry)?.map(|target| nameserver(config, &target));
        updates.insert(key.clone(), value);
    }
    let mut new_keys = updates
        .keys()
        .filter(|key| !existing.contains_key(*key))
        .cloned()
        .collect::<Vec<_>>();
    let mut dns = Map::new();
    for (name, value) in existing {
        if let Some(update) = updates.remove(&name) {
            if let Some(value) = update {
                dns.insert(name, value);
            }
            continue;
        }
        if name.starts_with("geosite:") || name.starts_with("rule-set:") {
            for key in new_keys.drain(..) {
                let value = updates
                    .remove(&key)
                    .expect("new DNS key was collected from updates");
                if let Some(value) = value {
                    dns.insert(key, value);
                }
            }
        }
        if geosite_changed && name.starts_with("geosite:") {
            continue;
        }
        let replacement = name
            .strip_prefix("rule-set:")
            .and_then(|provider| oracle_dns.get(provider));
        dns.insert(
            replacement.map_or(name.clone(), |provider| format!("rule-set:{provider}")),
            value,
        );
    }
    for (key, value) in updates {
        if let Some(value) = value {
            dns.insert(key, value);
        }
    }
    if geosite_changed {
        for item in config["rules"].as_array().ok_or_else(invalid)? {
            let raw = item.as_str().ok_or_else(invalid)?;
            if raw.starts_with("GEOSITE,") {
                let entry = standalone(raw)?;
                dns.entry(format!("geosite:{}", entry.value))
                    .or_insert_with(|| nameserver(config, &entry.target));
            }
        }
    }
    config["dns"]["nameserver-policy"] = Value::Object(dns);
    Ok(())
}
