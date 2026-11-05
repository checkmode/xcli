//! Prepare a bounded encrypted request for the privileged import queue.
//! Authentication, audit, atomic publication and worker status are the
//! caller's responsibility; this module does not write files or apply changes.
use crate::vmess::{parse_links, SecretJson};
use crate::{parse_fixed, ImportError};
use serde_json::{json, Value};
use zeroize::Zeroizing;

const CONTEXT: &[u8] = b"xcli:proxy-import:request:v1";
pub struct Prepared {
    id: String,
    encrypted: Zeroizing<Vec<u8>>,
}
impl Prepared {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn encrypted(&self) -> &[u8] {
        &self.encrypted
    }
}
fn invalid() -> ImportError {
    ImportError("导入请求格式不正确")
}
fn exact(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}
fn visible(value: &Value, max: usize) -> Result<&str, ImportError> {
    value
        .as_str()
        .filter(|s| s.len() <= max && !s.chars().any(|c| c < ' ' || c == '\u{7f}'))
        .ok_or_else(invalid)
}
fn tag(value: &Value) -> Result<&str, ImportError> {
    value
        .as_str()
        .filter(|s| {
            s.len() == 14
                && s.starts_with("residential-")
                && s[12..].bytes().all(|b| b.is_ascii_digit())
        })
        .ok_or_else(invalid)
}
fn identifier(value: &Value) -> Result<&str, ImportError> {
    value
        .as_str()
        .filter(|s| {
            s.len() == 32
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or_else(invalid)
}

/// Encrypt credentials immediately and return no plaintext. The caller must
/// validate the signed-in administrator and CSRF before invoking this method.
pub fn prepare(
    input: &Value,
    now: i64,
    key: &[u8; 32],
    existing_exits: usize,
) -> Result<Prepared, ImportError> {
    if now < 0 {
        return Err(invalid());
    }
    let action = input
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let mut nonce = Zeroizing::new([0u8; 16]);
    getrandom::fill(nonce.as_mut()).map_err(|_| ImportError("导入请求不可用"))?;
    let id = hex::encode(nonce.as_ref());
    let mut result = SecretJson::new(json!({"id":id,"action":action,"requested_at":now}));
    match action {
        "preview" if exact(input, &["action", "protocol", "label", "text"]) => {
            let protocol = input["protocol"].as_str().ok_or_else(invalid)?;
            let label = xcli_panel_users::validate(&json!({"name":input["label"]}))
                .map_err(|_| invalid())?
                .name;
            if label.chars().count() > 30 {
                return Err(invalid());
            }
            let text = input["text"]
                .as_str()
                .filter(|v| !v.is_empty() && v.len() <= 12000)
                .ok_or_else(invalid)?;
            result.value_mut()["protocol"] = json!(protocol);
            result.value_mut()["label"] = json!(label);
            match protocol {
                "socks" | "http" => {
                    let proxies = parse_fixed(text)?;
                    if existing_exits
                        .checked_add(proxies.len())
                        .is_none_or(|n| n > 40)
                    {
                        return Err(invalid());
                    }
                    result.value_mut()["proxies"] = Value::Array(
                        proxies
                            .iter()
                            .map(|proxy| {
                                json!({
                        "address":proxy.address.to_string(),"port":proxy.port,
                        "username":proxy.username(),"password":proxy.password()})
                            })
                            .collect(),
                    );
                }
                "vmess" => {
                    let proxies = parse_links(text)?;
                    if existing_exits
                        .checked_add(proxies.len())
                        .is_none_or(|n| n > 40)
                    {
                        return Err(invalid());
                    }
                    result.value_mut()["links"] = json!(text);
                }
                _ => return Err(invalid()),
            }
        }
        "manage" => {
            let operation = input
                .get("operation")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?;
            let allowed = ["edit", "enable", "disable", "delete", "restore"];
            if !allowed.contains(&operation) {
                return Err(invalid());
            }
            let shape_ok = if operation == "edit" {
                exact(input, &["action", "operation", "tag", "changes"])
            } else {
                exact(input, &["action", "operation", "tag"])
            };
            if !shape_ok {
                return Err(invalid());
            }
            result.value_mut()["operation"] = json!(operation);
            result.value_mut()["tag"] = json!(tag(&input["tag"])?);
            if operation == "edit" {
                let changes = input["changes"].as_object().ok_or_else(invalid)?;
                let allowed = [
                    "label",
                    "address",
                    "port",
                    "protocol",
                    "username",
                    "password",
                    "uuid",
                    "network",
                    "security",
                    "tls",
                    "server_name",
                    "host",
                    "path",
                    "alpn",
                    "fingerprint",
                ];
                if changes.keys().any(|key| !allowed.contains(&key.as_str()))
                    || !["label", "address", "port", "protocol"]
                        .iter()
                        .all(|key| changes.contains_key(*key))
                {
                    return Err(invalid());
                }
                let label = xcli_panel_users::validate(&json!({"name":changes["label"]}))
                    .map_err(|_| invalid())?
                    .name;
                let protocol = changes["protocol"]
                    .as_str()
                    .filter(|p| ["socks", "http", "vmess"].contains(p))
                    .ok_or_else(invalid)?;
                let address = visible(&changes["address"], 253)?;
                if address.is_empty() {
                    return Err(invalid());
                }
                let port = changes["port"]
                    .as_u64()
                    .filter(|p| (1..=65535).contains(p))
                    .ok_or_else(invalid)?;
                if protocol != "vmess"
                    && address
                        .parse::<std::net::Ipv4Addr>()
                        .ok()
                        .filter(|ip| ip.to_string() == address && crate::public_ipv4(*ip))
                        .is_none()
                {
                    return Err(invalid());
                }
                let mut edited = SecretJson::new(
                    json!({"label":label,"address":address,"port":port,"protocol":protocol}),
                );
                for (name, value) in changes {
                    if ["label", "address", "port", "protocol"].contains(&name.as_str()) {
                        continue;
                    }
                    if name == "tls" {
                        if protocol != "vmess" || !value.is_boolean() {
                            return Err(invalid());
                        }
                    } else {
                        let val = visible(value, if name == "path" { 1024 } else { 255 })?;
                        if (protocol == "vmess")
                            == ["username", "password"].contains(&name.as_str())
                            || name == "username" && val.contains(':')
                        {
                            return Err(invalid());
                        }
                    }
                    edited.value_mut()[name] = value.clone();
                }
                result.value_mut()["changes"] = std::mem::take(edited.value_mut());
            }
        }
        "apply" if exact(input, &["action", "preview_id"]) => {
            result.value_mut()["preview_id"] = json!(identifier(&input["preview_id"])?);
        }
        _ => return Err(invalid()),
    }
    let bytes = Zeroizing::new(serde_json::to_vec(result.as_value()).map_err(|_| invalid())?);
    let encrypted = Zeroizing::new(
        xcli_auth_compat::seal_xgb1(&bytes, key, CONTEXT)
            .map_err(|_| ImportError("导入请求不可用"))?,
    );
    if encrypted.len() > 20000 {
        return Err(invalid());
    }
    Ok(Prepared { id, encrypted })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use xcli_auth_compat::open_xgb1;

    #[test]
    fn prepared_request_round_trips_into_the_authenticated_queue() {
        let key = [42u8; 32];
        let input = json!({"action":"preview","protocol":"socks","label":" fixture ",
            "text":"1.1.1.1:0080:synthetic-user:synthetic-password:extra"});
        let prepared = prepare(&input, 1000, &key, 0).unwrap();
        assert_eq!(prepared.id().len(), 32);
        assert!(!prepared
            .encrypted()
            .windows(18)
            .any(|part| part == b"synthetic-password"));
        let plain = open_xgb1(prepared.encrypted(), &key, CONTEXT).unwrap();
        let payload: Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(payload["id"], prepared.id());
        assert_eq!(payload["label"], "fixture");
        assert_eq!(payload["proxies"][0]["port"], 80);
        assert_eq!(
            payload["proxies"][0]["password"],
            "synthetic-password:extra"
        );
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let state = dir.path().join("state");
        for path in [&inbox, &state] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(inbox.join("request.xgb"), prepared.encrypted()).unwrap();
        let queue = crate::queue::Queue::open(&inbox, &state, None, key).unwrap();
        let claimed = queue.claim(1000).unwrap().unwrap();
        assert_eq!(claimed.id(), prepared.id());
        assert_eq!(
            claimed.payload()["proxies"][0]["username"],
            "synthetic-user"
        );
        assert!(queue.claim(1000).unwrap().is_none());
    }

    #[test]
    fn rejects_bad_shapes_capacity_unsafe_targets_and_unsupported_edits() {
        let key = [7u8; 32];
        let valid = json!({"action":"preview","protocol":"http","label":"fixture","text":"8.8.8.8:443:u:p"});
        assert!(prepare(&valid, 100, &key, 39).is_ok());
        assert!(prepare(&valid, 100, &key, 40).is_err());
        for value in [
            json!({"action":"preview","protocol":"http","label":"fixture","text":"127.0.0.1:80:u:p"}),
            json!({"action":"preview","protocol":"http","label":"fixture","text":"8.8.8.8:80:u:p","extra":true}),
            json!({"action":"apply","preview_id":"not-a-valid-id"}),
            json!({"action":"manage","operation":"disable","tag":"residential-xx"}),
            json!({"action":"manage","operation":"edit","tag":"residential-27","changes":{
                "label":"fixture","address":"8.8.8.8","port":80,"protocol":"http","uuid":"nope"}}),
            json!({"action":"manage","operation":"edit","tag":"residential-27","changes":{
                "label":"fixture","address":"8.8.8.8","port":80,"protocol":"http","username":"bad:name"}}),
        ] {
            assert!(prepare(&value, 100, &key, 0).is_err());
        }
        let edit = json!({"action":"manage","operation":"edit","tag":"residential-27","changes":{
            "label":"fixture","address":"8.8.8.8","port":80,"protocol":"http","password":"synthetic-secret"}});
        assert!(prepare(&edit, 100, &key, 0).is_ok());
    }
}
