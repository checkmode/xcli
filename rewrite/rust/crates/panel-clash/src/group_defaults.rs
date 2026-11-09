use super::{build_with_outbound, country_label, invalid, User};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use xcli_panel_rules::{configurable_group, ApplyError};

type Result<T> = std::result::Result<T, ApplyError>;
const CUSTOM: &str = "__XCLI_PREVIEW_CUSTOM__";

#[derive(Clone)]
struct Choice {
    value: String,
    label: String,
    target: String,
}

fn add(choices: &mut Vec<Choice>, value: String, label: String, target: String) {
    if !choices.iter().any(|item| item.value == value) {
        choices.push(Choice {
            value,
            label,
            target,
        });
    }
}

fn choices(
    config: &Value,
    settings: &Value,
    outbound: &BTreeMap<String, String>,
    group: &str,
) -> Result<Vec<Choice>> {
    let groups = config
        .get("proxy-groups")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    let item = groups
        .iter()
        .find(|item| item.get("name").and_then(Value::as_str) == Some(group))
        .filter(|item| item.get("type").and_then(Value::as_str) == Some("select"))
        .ok_or_else(invalid)?;
    let members = item
        .get("proxies")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    let mut output = Vec::new();
    for member in members {
        let name = member.as_str().ok_or_else(invalid)?;
        if name == group || name == "REJECT" {
            continue;
        }
        if matches!(name, "PROXY" | "DIRECT" | "直连" | "故障转移" | "自动选择") {
            let label = if name == "PROXY" {
                "跟随 PROXY"
            } else if name == "DIRECT" {
                "直连（DIRECT）"
            } else {
                name
            };
            add(
                &mut output,
                format!("selector:{name}"),
                label.into(),
                name.into(),
            );
            continue;
        }
        if let Some((tag, _)) = outbound.iter().find(|(_, target)| target.as_str() == name) {
            add(&mut output, format!("node:{tag}"), name.into(), name.into());
            continue;
        }
        for exit in settings
            .get("residential_exits")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let country = exit
                .get("country")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?;
            if name == format!("住宅分组 · {}", country_label(country)) {
                add(
                    &mut output,
                    format!("country:{country}"),
                    name.into(),
                    name.into(),
                );
            }
        }
    }
    if members.iter().any(|member| member == "DIRECT") {
        add(&mut output, "selector:直连".into(), "直连（旧默认）".into(), "DIRECT".into());
    }
    // Older templates can name a country as their default. In flattened
    // policies resolve that legacy value to the country's first actual exit.
    if !matches!(group, "STUN" | "独立 · STUN") {
        let mut first: BTreeMap<String, String> = BTreeMap::new();
        for exit in settings.get("residential_exits").and_then(Value::as_array).into_iter().flatten() {
            let country = exit.get("country").and_then(Value::as_str).ok_or_else(invalid)?;
            let tag = exit.get("tag").and_then(Value::as_str).ok_or_else(invalid)?;
            if let Some(target) = outbound.get(tag) {
                if exit.get("dynamic").and_then(Value::as_bool) == Some(true) {
                    first.insert(country.into(), target.clone());
                } else {
                    first.entry(country.into()).or_insert_with(|| target.clone());
                }
            }
        }
        for (country, target) in first {
            add(&mut output, format!("country:{country}"),
                format!("{} · 首个出口（旧默认）", country_label(&country)), target);
        }
    }
    // An administrator may select a concrete configured node instead of a
    // country selector. STUN must remain on UDP-capable server entries.
    for (tag, target) in outbound {
        if matches!(group, "STUN" | "独立 · STUN") && tag.starts_with("residential-") {
            continue;
        }
        add(
            &mut output,
            format!("node:{tag}"),
            target.clone(),
            target.clone(),
        );
    }
    Ok(output)
}

pub(super) fn apply(
    config: &mut Value,
    settings: &Value,
    outbound: &BTreeMap<String, String>,
    spec: &Value,
) -> Result<()> {
    let Some(defaults) = spec.get("group_defaults").and_then(Value::as_object) else {
        return Ok(());
    };
    for (group, value) in defaults {
        let value = value.as_str().ok_or_else(invalid)?;
        let target = choices(config, settings, outbound, group)?
            .into_iter()
            .find(|choice| choice.value == value)
            .map(|choice| choice.target)
            .unwrap_or_else(|| "REJECT".into());
        let item = config["proxy-groups"]
            .as_array_mut()
            .ok_or_else(invalid)?
            .iter_mut()
            .find(|item| item.get("name").and_then(Value::as_str) == Some(group))
            .ok_or_else(invalid)?;
        let members = item
            .get_mut("proxies")
            .and_then(Value::as_array_mut)
            .ok_or_else(invalid)?;
        members.retain(|member| member.as_str() != Some(&target));
        members.insert(0, json!(target));
    }
    Ok(())
}

/// Reorder only named policy groups; generated helper groups keep their slots.
pub(super) fn order(config: &mut Value, spec: &Value) -> Result<()> {
    let Some(order) = spec.get("group_order").and_then(Value::as_array) else {
        return Ok(());
    };
    let mut ranks = order
        .iter()
        .enumerate()
        .map(|(index, value)| value.as_str().map(|name| (name, index)).ok_or_else(invalid))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut next = order.len();
    for name in ["PROXY", "STUN", "EaseLian", "独立 · AI", "独立 · Google", "独立 · Telegram",
                 "独立 · YouTube", "独立 · Netflix", "独立 · 国外媒体", "独立 · STUN", "其他流量", "oracle-cloud"]
        .into_iter()
        .chain(spec.get("groups").and_then(Value::as_array).into_iter().flatten()
            .filter_map(|group| group.get("name").and_then(Value::as_str)))
    {
        if !ranks.contains_key(name) {
            ranks.insert(name, next);
            next += 1;
        }
    }
    let groups = config["proxy-groups"].as_array_mut().ok_or_else(invalid)?;
    let mut slots = Vec::new();
    let mut selected = Vec::new();
    for (index, group) in groups.iter().enumerate() {
        let name = group.get("name").and_then(Value::as_str).ok_or_else(invalid)?;
        if let Some(rank) = ranks.get(name) {
            slots.push(index);
            selected.push((*rank, group.clone()));
        }
    }
    selected.sort_by_key(|(rank, _)| *rank);
    for (index, (_, group)) in slots.into_iter().zip(selected) {
        groups[index] = group;
    }
    Ok(())
}

/// Construct an authenticated editor catalog from configured resources using
/// the same generation path as subscriptions. It contains labels and stable
/// selectors only, never credentials or generated proxies.
pub(super) fn catalog(settings: &Value, remote: &[Value], dynamic_enabled: bool) -> Result<Value> {
    let mut settings = settings.clone();
    if let Some(object) = settings.as_object_mut() {
        object.remove("clash_service_routes");
        object.remove("client_policies");
    }
    let user = User {
        id: "f".repeat(32),
        uuid: "00000000-0000-4000-8000-000000000000".into(),
    };
    let mut result = Map::new();
    for base in ["standard", "independent"] {
        let policy = json!({"base":base,"ai_outbound":"proxy","rules":"","groups":[{"name":CUSTOM,"default":"PROXY"}],"managed":true});
        let (config, outbound) =
            build_with_outbound(&settings, &user, remote, dynamic_enabled, &policy)?;
        let mut custom = BTreeSet::new();
        custom.insert(CUSTOM.to_owned());
        let mut groups = Map::new();
        for item in config["proxy-groups"].as_array().ok_or_else(invalid)? {
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?;
            if !configurable_group(base, name, &custom) {
                continue;
            }
            let values = choices(&config, &settings, &outbound, name)?;
            let first = item
                .get("proxies")
                .and_then(Value::as_array)
                .and_then(|v| v.first())
                .and_then(Value::as_str);
            let default = values
                .iter()
                .find(|choice| Some(choice.target.as_str()) == first)
                .map(|choice| choice.value.as_str());
            let list = values
                .iter()
                .map(|choice| json!({"value":choice.value,"label":choice.label}))
                .collect::<Vec<_>>();
            groups.insert(
                if name == CUSTOM {
                    "__custom__".into()
                } else {
                    name.into()
                },
                json!({"default":default,"options":list}),
            );
        }
        result.insert(base.into(), Value::Object(groups));
    }
    Ok(Value::Object(result))
}
