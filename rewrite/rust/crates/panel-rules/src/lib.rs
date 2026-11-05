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
    if !(object.len() == 3 || object.len() == 4)
        || !object.contains_key("base")
        || !object.contains_key("ai_outbound")
        || !object.contains_key("rules")
        || (object.len() == 4 && !object.contains_key("groups"))
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
    Ok(output)
}
