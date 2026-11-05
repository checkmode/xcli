//! Experimental legacy settings preflight. Returns only an error category;
//! configuration values may contain paths, account policy and credentials.
use serde_json::Value;
use std::collections::BTreeSet;
use std::net::IpAddr;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Base,
    Exit,
    Route,
    Policy,
    Shadowrocket,
}
type Result<T> = std::result::Result<T, Error>;

fn fields(value: &Value, allowed: &[&str], required: &[&str]) -> bool {
    value.as_object().is_some_and(|map| {
        map.keys().all(|key| allowed.contains(&key.as_str()))
            && required.iter().all(|key| map.contains_key(*key))
    })
}
fn text(value: &Value, min: usize, max: usize) -> Option<&str> {
    let string = value.as_str()?;
    (min..=max)
        .contains(&string.chars().count())
        .then_some(string)
}
fn tag(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 14
        && bytes.starts_with(b"residential-")
        && bytes[12..].iter().all(u8::is_ascii_digit)
}
fn id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn optional_bool(object: &Value, key: &str) -> Option<bool> {
    object.get(key).map_or(Some(false), Value::as_bool)
}
fn port(object: &Value, key: &str, default: i64, min: i64) -> Option<i64> {
    let value = object.get(key).map_or(Some(default), Value::as_i64)?;
    (min..=65535).contains(&value).then_some(value)
}
fn domain(value: &str) -> bool {
    let mut count = 0;
    for part in value.split('.') {
        let bytes = part.as_bytes();
        if bytes.is_empty()
            || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
            || !bytes[bytes.len() - 1].is_ascii_lowercase()
                && !bytes[bytes.len() - 1].is_ascii_digit()
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        {
            return false;
        }
        count += 1;
    }
    count >= 2
}
fn outbound(value: &str, proxy: bool) -> bool {
    matches!(value, "reality" | "websocket" | "vmess" | "hysteria2")
        || proxy && value == "proxy"
        || tag(value)
}
fn default_object<'a>(
    settings: &'a Value,
    key: &str,
    empty: &'a Value,
) -> Result<&'a serde_json::Map<String, Value>> {
    settings
        .get(key)
        .unwrap_or(empty)
        .as_object()
        .ok_or(Error::Base)
}

/// Checks the existing panel constructor's configuration boundaries. It does
/// not inspect files, connect to Xray, or prove that nodes are reachable.
pub fn validate(settings: &Value) -> Result<()> {
    for key in [
        "domain",
        "public_ip",
        "origin",
        "reality_sni",
        "reality_public",
        "short_id",
        "ws_path",
    ] {
        if settings.get(key).and_then(Value::as_str).is_none() {
            return Err(Error::Base);
        }
    }
    let ws = settings["ws_path"].as_str().ok_or(Error::Base)?;
    let hy2 = port(settings, "hysteria2_port", 0, 0).ok_or(Error::Base)?;
    let hy2_brutal = port(settings, "hysteria2_brutal_port", 0, 0).ok_or(Error::Base)?;
    settings
        .get("hysteria2_brutal_mbps")
        .map_or(Some(40), Value::as_u64)
        .filter(|v| (1..=1000).contains(v))
        .ok_or(Error::Base)?;
    if hy2_brutal > 0 && (hy2 == 0 || hy2_brutal == hy2) {
        return Err(Error::Base);
    }
    port(settings, "public_port", 443, 1).ok_or(Error::Base)?;
    if settings
        .get("node_address_ip")
        .is_some_and(|v| !v.is_boolean())
    {
        return Err(Error::Base);
    }
    if let Some(value) = settings.get("vmess_ws_path") {
        if text(value, 1, 256) != Some(format!("{ws}/vmess").as_str())
            || settings.get("vmess_port").and_then(Value::as_i64) != Some(10081)
        {
            return Err(Error::Base);
        }
    }
    let empty_array = serde_json::json!([]);
    let empty_object = serde_json::json!({});
    let exits = settings
        .get("residential_exits")
        .unwrap_or(&empty_array)
        .as_array()
        .ok_or(Error::Exit)?;
    if exits.len() > 40 {
        return Err(Error::Exit);
    }
    let mut exit_tags = BTreeSet::new();
    let mut exit_paths = BTreeSet::new();
    let mut exit_ports = BTreeSet::new();
    for exit in exits {
        if !fields(
            exit,
            &[
                "tag",
                "label",
                "exit_ip",
                "country",
                "ws_path",
                "port",
                "dynamic",
                "hysteria2",
            ],
            &["tag", "label", "exit_ip", "country", "ws_path", "port"],
        ) {
            return Err(Error::Exit);
        }
        let name = text(&exit["tag"], 14, 14).ok_or(Error::Exit)?;
        let path = text(&exit["ws_path"], 1, 256).ok_or(Error::Exit)?;
        let dynamic = optional_bool(exit, "dynamic").ok_or(Error::Exit)?;
        let hysteria = optional_bool(exit, "hysteria2").ok_or(Error::Exit)?;
        let address = text(&exit["exit_ip"], if dynamic { 0 } else { 7 }, 15).ok_or(Error::Exit)?;
        let country = text(&exit["country"], 2, 2).ok_or(Error::Exit)?;
        let port = exit["port"]
            .as_i64()
            .filter(|p| (1024..=65535).contains(p))
            .ok_or(Error::Exit)?;
        let valid_address = if dynamic {
            address.is_empty()
        } else {
            address
                .parse::<IpAddr>()
                .is_ok_and(xcli_panel_operations::webhook::public_ip)
        };
        if !tag(name)
            || path != format!("{ws}/{name}")
            || !valid_address
            || !country.bytes().all(|b| b.is_ascii_uppercase())
            || hysteria && (dynamic || hy2 == 0)
            || !exit_tags.insert(name)
            || !exit_paths.insert(path)
            || !exit_ports.insert(port)
            || dynamic
                && !xcli_panel_webshare::REGIONS
                    .iter()
                    .any(|r| r.tag == name && r.country == country && i64::from(r.port) == port)
            || xcli_panel_users::validate(&serde_json::json!({"name":exit["label"]})).is_err()
        {
            return Err(Error::Exit);
        }
    }
    let routes = default_object(settings, "clash_service_routes", &empty_object)
        .map_err(|_| Error::Route)?;
    if routes.len() > 1000 {
        return Err(Error::Route);
    }
    for (user, services) in routes {
        let services = services
            .as_array()
            .filter(|s| s.len() <= 32)
            .ok_or(Error::Route)?;
        if !id(user) {
            return Err(Error::Route);
        }
        let mut names = BTreeSet::new();
        let mut domains: BTreeSet<&str> = BTreeSet::new();
        for service in services {
            if !fields(
                service,
                &["name", "outbound", "domains", "udp"],
                &["name", "outbound", "domains", "udp"],
            ) {
                return Err(Error::Route);
            }
            let name = text(&service["name"], 1, 32).ok_or(Error::Route)?;
            let target = text(&service["outbound"], 1, 32).ok_or(Error::Route)?;
            let udp = text(&service["udp"], 5, 6).ok_or(Error::Route)?;
            if !name.as_bytes()[0].is_ascii_uppercase()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
                || [
                    "PROXY",
                    "STUN",
                    "DIRECT",
                    "REJECT",
                    "REJECT-DROP",
                    "PASS",
                    "COMPATIBLE",
                    "GLOBAL",
                    "REALITY",
                    "HTTPS",
                ]
                .contains(&name)
                || !names.insert(name)
                || !outbound(target, false)
                || !["reject", "proxy"].contains(&udp)
                || target.starts_with("residential-") && udp != "reject"
            {
                return Err(Error::Route);
            }
            let list = service["domains"]
                .as_array()
                .filter(|v| !v.is_empty() && v.len() <= 128)
                .ok_or(Error::Route)?;
            for item in list {
                let value = text(item, 3, 253).ok_or(Error::Route)?;
                if !domain(value)
                    || domains.iter().any(|old| {
                        value == *old
                            || value.ends_with(&format!(".{old}"))
                            || old.ends_with(&format!(".{value}"))
                    })
                {
                    return Err(Error::Route);
                }
                domains.insert(value);
            }
        }
    }
    let policies =
        default_object(settings, "client_policies", &empty_object).map_err(|_| Error::Policy)?;
    let bases = default_object(settings, "shadowrocket_base_profiles", &empty_object)
        .map_err(|_| Error::Shadowrocket)?;
    if policies.len() > 1000 {
        return Err(Error::Policy);
    }
    for (user, policy) in policies {
        if !id(user) || !fields(policy, &["ai_outbound"], &["ai_outbound"]) {
            return Err(Error::Policy);
        }
        let target = text(&policy["ai_outbound"], 1, 32).ok_or(Error::Policy)?;
        if !outbound(target, true) || !bases.contains_key(user) {
            return Err(Error::Policy);
        }
        if let Some(services) = routes.get(user).and_then(Value::as_array) {
            if services.iter().any(|s| {
                ["AI", "CLAUDE", "Telegram", "YouTube", "Netflix", "Apple"]
                    .contains(&s["name"].as_str().unwrap_or(""))
            }) {
                return Err(Error::Policy);
            }
        }
    }
    let shadow = settings
        .get("shadowrocket_service_users")
        .unwrap_or(&empty_array)
        .as_array()
        .ok_or(Error::Shadowrocket)?;
    if shadow.len() > 1000 || bases.len() > 16 {
        return Err(Error::Shadowrocket);
    }
    let mut selected = BTreeSet::new();
    for value in shadow {
        let user = text(value, 32, 32).ok_or(Error::Shadowrocket)?;
        let services = routes
            .get(user)
            .and_then(Value::as_array)
            .filter(|v| !v.is_empty())
            .ok_or(Error::Shadowrocket)?;
        if !selected.insert(user) {
            return Err(Error::Shadowrocket);
        }
        for service in services {
            let target = service["outbound"].as_str().ok_or(Error::Shadowrocket)?;
            if target != "hysteria2" && !target.starts_with("residential-") {
                return Err(Error::Shadowrocket);
            }
            for exit in exits {
                if exit["tag"].as_str() == Some(target)
                    && !optional_bool(exit, "hysteria2").ok_or(Error::Shadowrocket)?
                {
                    return Err(Error::Shadowrocket);
                }
            }
        }
    }
    let mut total = 0usize;
    for (user, base) in bases {
        let text = base.as_str().ok_or(Error::Shadowrocket)?;
        total = total.checked_add(text.len()).ok_or(Error::Shadowrocket)?;
        if !selected.contains(user.as_str()) && !policies.contains_key(user)
            || text.is_empty()
            || total > 512 * 1024
            || text.contains('\0')
        {
            return Err(Error::Shadowrocket);
        }
    }
    Ok(())
}

/// Match the legacy panel's inbound set so imported entries receive users
/// after the service restarts with updated settings.
pub fn inbound_tags(settings: &Value) -> Result<Vec<String>> {
    let mut tags = vec!["reality".into(), "websocket".into()];
    let hy2 = port(settings, "hysteria2_port", 0, 0).ok_or(Error::Base)?;
    let brutal = port(settings, "hysteria2_brutal_port", 0, 0).ok_or(Error::Base)?;
    if brutal > 0 && (hy2 == 0 || brutal == hy2) {
        return Err(Error::Base);
    }
    if hy2 > 0 {
        tags.push("hysteria2".into());
    }
    if brutal > 0 {
        tags.push("hysteria2-brutal".into());
    }
    if settings.get("vmess_ws_path").is_some() {
        text(&settings["vmess_ws_path"], 1, 256).ok_or(Error::Base)?;
        tags.push("vmess".into());
    }
    if let Some(exits) = settings.get("residential_exits") {
        for exit in exits
            .as_array()
            .filter(|v| v.len() <= 40)
            .ok_or(Error::Exit)?
        {
            let name = exit["tag"].as_str().filter(|v| tag(v)).ok_or(Error::Exit)?;
            tags.push(name.into());
            if optional_bool(exit, "hysteria2").ok_or(Error::Exit)? {
                tags.push(format!("{name}-hy2"));
            }
        }
    }
    if !xcli_panel_controller::validate_tags(&tags) {
        return Err(Error::Exit);
    }
    Ok(tags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn derives_all_local_entry_tags_after_import() {
        let config = json!({"hysteria2_port":443,"vmess_ws_path":"/connect/test/vmess",
            "residential_exits":[{"tag":"residential-27","hysteria2":true},
                                 {"tag":"residential-11","dynamic":true}]});
        assert_eq!(
            inbound_tags(&config).unwrap(),
            vec![
                "reality",
                "websocket",
                "hysteria2",
                "vmess",
                "residential-27",
                "residential-27-hy2",
                "residential-11"
            ]
        );
        assert!(
            inbound_tags(&json!({"residential_exits":[{"tag":"residential-27"},
                                                           {"tag":"residential-27"}]}))
            .is_err()
        );
    }

    #[test]
    fn optional_brutal_entry_has_an_independent_valid_port() {
        assert_eq!(
            inbound_tags(&json!({"hysteria2_port":443,"hysteria2_brutal_port":8443})).unwrap(),
            vec!["reality", "websocket", "hysteria2", "hysteria2-brutal"]
        );
        assert!(inbound_tags(&json!({"hysteria2_brutal_port":8443})).is_err());
        assert!(inbound_tags(&json!({"hysteria2_port":443,"hysteria2_brutal_port":443})).is_err());
        assert!(
            inbound_tags(&json!({"hysteria2_port":443,"hysteria2_brutal_port":65536})).is_err()
        );
    }
}
