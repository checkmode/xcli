//! Experimental legacy rule-template validation, ordering, and catalog reads.
//! Publishing and complete client rendering are intentionally not implemented.
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
mod apply;
mod policy;
mod store;
pub use apply::{apply_template_rules, ApplyError};
pub use policy::{apply_client_policy, apply_google_policy};
pub use store::{factory_independent_rules, factory_spec, RuleEditor, RuleStore, RuleStoreError};

#[derive(Debug, PartialEq, Eq)]
pub struct ValidationError(pub String);
type Result<T> = std::result::Result<T, ValidationError>;
fn invalid(message: &str) -> ValidationError {
    ValidationError(message.to_owned())
}

#[derive(Debug, PartialEq, Eq)]
pub struct Rule {
    pub kind: String,
    pub value: String,
    pub target: String,
    pub no_resolve: bool,
    pub explicit_resolution: bool,
}

fn trim(text: &str) -> &str {
    text.trim_matches([' ', '\t', '\r'])
}
fn domain(value: &str) -> bool {
    if value.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = value.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes[0].is_ascii_lowercase_or_digit()
                && bytes[bytes.len() - 1].is_ascii_lowercase_or_digit()
                && bytes
                    .iter()
                    .all(|c| c.is_ascii_lowercase_or_digit() || *c == b'-')
        })
}
trait LowercaseOrDigit {
    fn is_ascii_lowercase_or_digit(&self) -> bool;
}
impl LowercaseOrDigit for u8 {
    fn is_ascii_lowercase_or_digit(&self) -> bool {
        self.is_ascii_lowercase() || self.is_ascii_digit()
    }
}
fn network(value: &str, ipv6: bool) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    if prefix.is_empty() || prefix.len() > 3 || !prefix.bytes().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let Ok(bits) = prefix.parse::<u16>() else {
        return false;
    };
    if ipv6 {
        bits <= 128 && address.parse::<Ipv6Addr>().is_ok()
    } else {
        bits <= 32 && address.parse::<Ipv4Addr>().is_ok()
    }
}

/// Only selectable policy groups may carry a template default. DIRECT and
/// REJECT are actions; oracle-cloud is a system-maintained direct route.
pub fn configurable_group(base: &str, group: &str, custom: &BTreeSet<String>) -> bool {
    group == "PROXY"
        || (base == "standard" && group == "STUN")
        || (base == "independent"
            && matches!(
                group,
                "EaseLian"
                    | "独立 · AI"
                    | "独立 · Google"
                    | "独立 · Telegram"
                    | "独立 · YouTube"
                    | "独立 · Netflix"
                    | "独立 · 国外媒体"
                    | "独立 · STUN"
                    | "其他流量"
            ))
        || custom.contains(group)
}

fn default_choice(value: &str) -> bool {
    if let Some(name) = value.strip_prefix("selector:") {
        return matches!(name, "PROXY" | "DIRECT" | "直连" | "故障转移" | "自动选择");
    }
    if let Some(country) = value.strip_prefix("country:") {
        return country.len() == 2 && country.bytes().all(|v| v.is_ascii_uppercase());
    }
    let Some(node) = value.strip_prefix("node:") else {
        return false;
    };
    if matches!(
        node,
        "reality"
            | "websocket"
            | "vmess"
            | "hysteria2"
            | "hysteria2-brutal"
            | "hysteria2-brutal-current"
    ) {
        return true;
    }
    if let Some(number) = node.strip_prefix("residential-") {
        return number.len() == 2 && number.bytes().all(|v| v.is_ascii_digit());
    }
    let Some(remote) = node.strip_prefix("remote-") else {
        return false;
    };
    let Some((id, transport)) = remote.split_once('-') else {
        return false;
    };
    id.len() == 32
        && id
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        && matches!(transport, "reality" | "websocket" | "hysteria2")
}

/// Interpret rules without changing their text or precedence.
pub fn parse_rules(text: &str, base: &str, groups: &BTreeSet<String>) -> Result<Vec<Rule>> {
    if text.len() > 14000 {
        return Err(invalid("规则内容过长，最多 14000 字节"));
    }
    let mut result = Vec::new();
    for (index, line) in text.split('\n').enumerate() {
        let fail = |detail: &str| ValidationError(format!("第 {} 行：{}", index + 1, detail));
        let line = trim(line);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() > 400 || result.len() >= 500 {
            return Err(fail("单条规则过长或规则超过 500 条"));
        }
        let fields: Vec<_> = line.split(',').map(trim).collect();
        if !(3..=4).contains(&fields.len()) {
            return Err(fail("规则格式应为 类型,内容,目标，IP 规则可附加解析选项"));
        }
        let (kind, value, target) = (fields[0], fields[1], fields[2]);
        let mut no_resolve = false;
        match kind {
            "DOMAIN" | "DOMAIN-SUFFIX" if !domain(value) => {
                return Err(fail("域名规则需要小写英文域名"))
            }
            "DOMAIN" | "DOMAIN-SUFFIX" => (),
            "DOMAIN-KEYWORD"
                if value.is_empty()
                    || value.len() > 253
                    || !value
                        .bytes()
                        .all(|c| c.is_ascii_lowercase_or_digit() || c == b'.' || c == b'-') =>
            {
                return Err(fail("域名关键词只能包含小写字母、数字、点和短横线"))
            }
            "DOMAIN-KEYWORD" => (),
            "IP-CIDR" | "IP-CIDR6" => {
                if !network(value, kind == "IP-CIDR6") {
                    return Err(fail("IP 网段格式不正确"));
                }
                no_resolve = true;
            }
            "GEOIP" if value.len() != 2 || !value.bytes().all(|c| c.is_ascii_uppercase()) => {
                return Err(fail("国家或地区代码应为两个大写字母，例如 CN"))
            }
            "GEOIP" => (),
            "DST-PORT" => {
                if value.is_empty()
                    || value.len() > 5
                    || !value.bytes().all(|c| c.is_ascii_digit())
                    || !value.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n))
                {
                    return Err(fail("目标端口应为 1 到 65535 的单个数字"));
                }
            }
            _ => return Err(fail("不支持的规则类型")),
        }
        let explicit_resolution = fields.len() == 4;
        if explicit_resolution {
            if !matches!(kind, "IP-CIDR" | "IP-CIDR6" | "GEOIP") {
                return Err(fail("此类型不支持解析选项"));
            }
            if !matches!(fields[3], "resolve" | "no-resolve") {
                return Err(fail("解析选项应为 resolve 或 no-resolve"));
            }
            no_resolve = fields[3] == "no-resolve";
        }
        let common = matches!(target, "DIRECT" | "REJECT" | "PROXY");
        let independent = matches!(
            target,
            "EaseLian"
                | "独立 · AI"
                | "独立 · Google"
                | "独立 · Telegram"
                | "独立 · YouTube"
                | "独立 · Netflix"
                | "独立 · 国外媒体"
                | "独立 · STUN"
                | "其他流量"
        );
        if !common
            && !(base == "standard" && target == "STUN")
            && !(base == "independent" && independent)
            && !groups.contains(target)
        {
            return Err(fail("规则目标不属于所选模板"));
        }
        result.push(Rule {
            kind: kind.into(),
            value: value.into(),
            target: target.into(),
            no_resolve,
            explicit_resolution,
        });
    }
    Ok(result)
}

/// Validate and normalize a template exactly as the existing editor expects.
pub fn validate(input: &Value) -> Result<Value> {
    let object = input.as_object().ok_or_else(|| invalid("模板格式不正确"))?;
    if !object.contains_key("base")
        || !object.contains_key("ai_outbound")
        || !object.contains_key("rules")
        || object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "base" | "ai_outbound" | "rules" | "groups" | "group_defaults" | "group_order" | "group_names" | "system_overrides"
            )
        })
    {
        return Err(invalid("模板格式不正确"));
    }
    let base = input["base"]
        .as_str()
        .ok_or_else(|| invalid("模板格式不正确"))?;
    let ai = input["ai_outbound"]
        .as_str()
        .ok_or_else(|| invalid("模板格式不正确"))?;
    let rules = input["rules"]
        .as_str()
        .ok_or_else(|| invalid("模板格式不正确"))?;
    if !matches!(base, "standard" | "independent") {
        return Err(invalid("模板类型不正确"));
    }
    let residential = ai
        .strip_prefix("residential-")
        .is_some_and(|rest| rest.len() == 2 && rest.bytes().all(|c| c.is_ascii_digit()));
    if !matches!(
        ai,
        "proxy" | "reality" | "websocket" | "vmess" | "hysteria2"
    ) && !residential
    {
        return Err(invalid("AI 默认出口不正确"));
    }
    let mut names = BTreeSet::new();
    let mut groups = Vec::new();
    if let Some(value) = input.get("groups") {
        let items = value
            .as_array()
            .filter(|v| v.len() <= 16)
            .ok_or_else(|| invalid("自定义策略组最多 16 个"))?;
        for item in items {
            let group = item
                .as_object()
                .filter(|v| v.len() == 2 && v.contains_key("name") && v.contains_key("default"))
                .ok_or_else(|| invalid("策略组格式不正确"))?;
            let name = group["name"]
                .as_str()
                .ok_or_else(|| invalid("策略组格式不正确"))?;
            let choice = group["default"]
                .as_str()
                .ok_or_else(|| invalid("策略组格式不正确"))?;
            let reserved = matches!(
                name,
                "DIRECT"
                    | "REJECT"
                    | "PROXY"
                    | "STUN"
                    | "直连"
                    | "故障转移"
                    | "自动选择"
                    | "住宅节点"
                    | "EaseLian"
                    | "独立 · AI"
                    | "独立 · Google"
                    | "独立 · Telegram"
                    | "独立 · YouTube"
                    | "独立 · Netflix"
                    | "独立 · 国外媒体"
                    | "独立 · STUN"
                    | "其他流量"
                    | "oracle-cloud"
            );
            if name.is_empty()
                || name.len() > 64
                || trim(name) != name
                || name
                    .bytes()
                    .any(|c| c < 32 || c == 127 || b",=\r\n\t#".contains(&c))
                || reserved
                || !names.insert(name.to_owned())
            {
                return Err(invalid("策略组名称无效、重复或与内置名称冲突"));
            }
            if !matches!(choice, "PROXY" | "DIRECT")
                && !(base == "independent" && matches!(choice, "故障转移" | "自动选择"))
            {
                return Err(invalid("策略组默认出口不属于当前基础模板"));
            }
            groups.push(json!({"name":name,"default":choice}));
        }
    }
    parse_rules(rules, base, &names)?;
    let mut output = json!({"base":base,"ai_outbound":ai,"rules":rules});
    if !groups.is_empty() {
        output["groups"] = json!(groups);
    }
    if let Some(value) = input.get("group_defaults") {
        let defaults = value
            .as_object()
            .filter(|items| items.len() <= 32)
            .ok_or_else(|| invalid("分组默认出口格式不正确"))?;
        for (group, choice) in defaults {
            if !configurable_group(base, group, &names)
                || !choice.as_str().is_some_and(default_choice)
            {
                return Err(invalid("分组或默认出口不属于当前模板"));
            }
        }
        if !defaults.is_empty() {
            output["group_defaults"] = json!(defaults);
        }
    }
    if let Some(value) = input.get("group_order") {
        let items = value
            .as_array()
            .filter(|items| items.len() <= 32)
            .ok_or_else(|| invalid("分组顺序格式不正确"))?;
        let mut seen = BTreeSet::new();
        for item in items {
            let name = item.as_str().ok_or_else(|| invalid("分组顺序格式不正确"))?;
            let builtin = matches!(name, "PROXY" | "DIRECT" | "REJECT" | "STUN" | "EaseLian" |
                "独立 · AI" | "独立 · Google" | "独立 · Telegram" | "独立 · YouTube" |
                "独立 · Netflix" | "独立 · 国外媒体" | "独立 · STUN" | "其他流量" | "oracle-cloud");
            if !(builtin || names.contains(name)) || !seen.insert(name) {
                return Err(invalid("分组顺序包含重复或未知分组"));
            }
        }
        if !items.is_empty() {
            output["group_order"] = json!(items);
        }
    }
    if let Some(value) = input.get("group_names") {
        let entries = value.as_object().filter(|entries| entries.len() <= 16)
            .ok_or_else(|| invalid("分组名称格式不正确"))?;
        let reserved = ["DIRECT", "REJECT", "PROXY", "STUN", "直连", "故障转移", "自动选择", "住宅节点",
            "EaseLian", "独立 · AI", "独立 · Google", "独立 · Telegram", "独立 · YouTube", "独立 · Netflix",
            "独立 · 国外媒体", "独立 · STUN", "其他流量", "oracle-cloud"];
        let mut seen = names.clone();
        let mut normalized = serde_json::Map::new();
        for (group, value) in entries {
            let name = value.as_str().ok_or_else(|| invalid("分组名称格式不正确"))?;
            if !(group == "oracle-cloud" || configurable_group("standard", group, &BTreeSet::new())
                || configurable_group("independent", group, &BTreeSet::new())) {
                return Err(invalid("不能修改该分组名称"));
            }
            if name == group { continue; }
            if name.is_empty() || name.len() > 64 || trim(name) != name || reserved.contains(&name)
                || name.bytes().any(|c| c < 32 || c == 127 || b",=\r\n\t#".contains(&c))
                || !seen.insert(name.to_owned()) {
                return Err(invalid("分组名称无效、重复或与内置名称冲突"));
            }
            normalized.insert(group.clone(), json!(name));
        }
        if !normalized.is_empty() { output["group_names"] = Value::Object(normalized); }
    }
    if let Some(value) = input.get("system_overrides") {
        let items = value.as_object().filter(|items| items.len() <= 128)
            .ok_or_else(|| invalid("系统规则修改格式不正确"))?;
        for (id, item) in items {
            if id.len() != 64 || !id.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
                return Err(invalid("系统规则标识不正确"));
            }
            if item.is_null() { continue; }
            let object = item.as_object().filter(|object| object.len() == 4
                && ["kind", "value", "target", "option"].iter().all(|key| object.contains_key(*key)))
                .ok_or_else(|| invalid("系统规则修改格式不正确"))?;
            let kind = object["kind"].as_str().ok_or_else(|| invalid("系统规则类型不正确"))?;
            let value = object["value"].as_str().ok_or_else(|| invalid("系统规则内容不正确"))?;
            let target = object["target"].as_str().ok_or_else(|| invalid("系统规则去向不正确"))?;
            let option = object["option"].as_str().ok_or_else(|| invalid("系统规则解析选项不正确"))?;
            if !(matches!(target, "DIRECT" | "REJECT" | "oracle-cloud") || configurable_group(base, target, &names)) {
                return Err(invalid("系统规则去向不属于当前模板"));
            }
            match kind {
                "GEOSITE" if option.is_empty() && !value.is_empty() && value.len() <= 80 && value.bytes().all(|c|
                    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'_' | b'!' | b'@')) => (),
                "MATCH" if value == "全部剩余流量" && option.is_empty() => (),
                "AND" if option.is_empty() && value.len() <= 400 && value.starts_with("((") && value.ends_with("))")
                    && value.bytes().all(|c| c.is_ascii_alphanumeric() || b"(),._-:/!+".contains(&c)) => (),
                "GEOIP" if value == "private" && matches!(option, "" | "resolve" | "no-resolve") => (),
                _ => {
                    let line = format!("{kind},{value},DIRECT{}", if option.is_empty() { String::new() } else { format!(",{option}") });
                    parse_rules(&line, base, &names)?;
                }
            }
        }
        if !items.is_empty() { output["system_overrides"] = json!(items); }
    }
    Ok(output)
}
