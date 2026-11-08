use super::{field, invalid, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use xcli_panel_rules::ApplyError;

fn rename_dns(value: &mut Value, names: &BTreeMap<&str, &str>) {
    match value {
        Value::String(text) => {
            if let Some((url, group)) = text.rsplit_once('#') {
                if let Some(name) = names.get(group) {
                    *text = format!("{url}#{name}");
                }
            }
        }
        Value::Array(values) => {
            for item in values {
                rename_dns(item, names);
            }
        }
        Value::Object(values) => {
            for item in values.values_mut() {
                rename_dns(item, names);
            }
        }
        _ => (),
    }
}

/// The template keeps stable group identities; only the generated client configuration is renamed.
pub(super) fn apply(config: &mut Value, policy: &Value) -> Result<()> {
    let Some(values) = policy
        .get("group_names")
        .and_then(Value::as_object)
        .filter(|v| !v.is_empty())
    else {
        return Ok(());
    };
    let mut names = BTreeMap::new();
    for (original, value) in values {
        let display = value.as_str().ok_or_else(invalid)?;
        if original != display {
            names.insert(original.as_str(), display);
        }
    }
    let groups = config["proxy-groups"].as_array().ok_or_else(invalid)?;
    let proxies = config["proxies"].as_array().ok_or_else(invalid)?;
    for (original, display) in &names {
        if !groups
            .iter()
            .any(|group| group["name"].as_str() == Some(original))
        {
            continue;
        }
        if groups
            .iter()
            .chain(proxies)
            .any(|item| item["name"].as_str() == Some(display))
        {
            return Err(ApplyError {
                status: 422,
                detail: format!("分组名称与现有节点或分组重复：{display}"),
            });
        }
    }
    for group in config["proxy-groups"].as_array_mut().ok_or_else(invalid)? {
        let current = field(group, "name")?.to_owned();
        if let Some(name) = names.get(current.as_str()) {
            group["name"] = Value::String((*name).into());
        }
        for member in group["proxies"].as_array_mut().ok_or_else(invalid)? {
            if let Some(name) = member.as_str().and_then(|v| names.get(v)) {
                *member = Value::String((*name).into());
            }
        }
    }
    for rule in config["rules"].as_array_mut().ok_or_else(invalid)? {
        let text = rule.as_str().ok_or_else(invalid)?;
        let (main, option) = text
            .strip_suffix(",no-resolve")
            .map_or((text, ""), |v| (v, ",no-resolve"));
        let (condition, target) = main.rsplit_once(',').ok_or_else(invalid)?;
        if let Some(name) = names.get(target) {
            *rule = Value::String(format!("{condition},{name}{option}"));
        }
    }
    rename_dns(&mut config["dns"], &names);
    Ok(())
}
