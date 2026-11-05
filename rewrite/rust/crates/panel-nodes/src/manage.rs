//! Experimental registration and user-selection transactions.
use super::{exact_shape, hash, lowercase_hex, token, NodeSync};
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq, Eq)]
pub enum ManageError {
    InvalidInput,
    NotFound,
    Conflict,
    Unavailable,
}
type Result<T> = std::result::Result<T, ManageError>;

fn registry(db: &rusqlite::Connection) -> Result<Value> {
    let raw: Option<String> = db
        .query_row(
            "SELECT value FROM metadata WHERE key='remote_nodes_v1'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| ManageError::Unavailable)?;
    let value: Value = match raw {
        Some(raw) => serde_json::from_str(&raw).map_err(|_| ManageError::Unavailable)?,
        None => json!([]),
    };
    if value.as_array().is_none_or(|items| items.len() > 20) {
        return Err(ManageError::Unavailable);
    }
    Ok(value)
}
fn save(tx: &Transaction<'_>, registry: &Value) -> Result<()> {
    tx.execute(
        "INSERT OR REPLACE INTO metadata(key,value) VALUES('remote_nodes_v1',?)",
        [serde_json::to_string(registry).map_err(|_| ManageError::Unavailable)?],
    )
    .map_err(|_| ManageError::Unavailable)?;
    Ok(())
}
fn audit(tx: &Transaction<'_>, now: i64, action: &str, name: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO events(ts,action,detail) VALUES(?,?,?)",
        params![now, action, name],
    )
    .map_err(|_| ManageError::Unavailable)?;
    tx.execute(
        "DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM events)",
        [],
    )
    .map_err(|_| ManageError::Unavailable)?;
    Ok(())
}
fn name(value: &Value) -> Result<String> {
    let name = xcli_panel_users::validate(&json!({ "name": value }))
        .map_err(|_| ManageError::InvalidInput)?
        .name;
    if name.contains([',', '=', '\r', '\n']) {
        return Err(ManageError::InvalidInput);
    }
    Ok(name)
}
fn domain(value: &Value) -> Result<String> {
    let domain = value
        .as_str()
        .filter(|v| (3..=253).contains(&v.len()))
        .ok_or(ManageError::InvalidInput)?;
    let labels: Vec<_> = domain.split('.').collect();
    if labels.len() < 2
        || labels.iter().any(|label| {
            let bytes = label.as_bytes();
            bytes.is_empty()
                || bytes.len() > 63
                || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
                || !bytes[bytes.len() - 1].is_ascii_lowercase()
                    && !bytes[bytes.len() - 1].is_ascii_digit()
                || bytes
                    .iter()
                    .any(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit() && *c != b'-')
        })
    {
        return Err(ManageError::InvalidInput);
    }
    Ok(domain.to_owned())
}
fn public_ipv4(value: &Value) -> Result<String> {
    let text = value
        .as_str()
        .filter(|value| (7..=15).contains(&value.len()))
        .ok_or(ManageError::InvalidInput)?;
    let address = text
        .parse::<Ipv4Addr>()
        .map_err(|_| ManageError::InvalidInput)?;
    let [a, b, c, _] = address.octets();
    if a == 0
        || a == 10
        || a == 127
        || a >= 224
        || a == 100 && (64..=127).contains(&b)
        || a == 169 && b == 254
        || a == 172 && (16..=31).contains(&b)
        || a == 192 && (b == 168 || b == 0 && (c == 0 || c == 2) || b == 88 && c == 99)
        || a == 198 && (b == 18 || b == 19 || b == 51 && c == 100)
        || a == 203 && b == 0 && c == 113
    {
        return Err(ManageError::InvalidInput);
    }
    Ok(text.to_owned())
}
fn registration(value: &Value) -> Result<Value> {
    if !exact_shape(
        value,
        &[
            "version",
            "id",
            "key",
            "public_ip",
            "domain",
            "public_port",
            "reality_sni",
            "reality_public",
            "short_id",
            "ws_path",
            "hysteria2_port",
        ],
    ) || value["version"].as_i64() != Some(1)
    {
        return Err(ManageError::InvalidInput);
    }
    let id = value["id"]
        .as_str()
        .filter(|v| lowercase_hex(v, 32))
        .ok_or(ManageError::InvalidInput)?;
    let key = value["key"]
        .as_str()
        .filter(|v| token(v))
        .ok_or(ManageError::InvalidInput)?;
    let reality_public = value["reality_public"]
        .as_str()
        .filter(|v| token(v))
        .ok_or(ManageError::InvalidInput)?;
    let short_id = value["short_id"]
        .as_str()
        .filter(|v| lowercase_hex(v, 16))
        .ok_or(ManageError::InvalidInput)?;
    let path = value["ws_path"]
        .as_str()
        .filter(|v| {
            v.strip_prefix("/connect/")
                .is_some_and(|suffix| lowercase_hex(suffix, 24))
        })
        .ok_or(ManageError::InvalidInput)?;
    let port = |field: &str| {
        value[field]
            .as_i64()
            .filter(|n| (1..=65535).contains(n))
            .ok_or(ManageError::InvalidInput)
    };
    Ok(json!({"id":id,"key_hash":hash(key.as_bytes()),"endpoint":{
        "public_ip":public_ipv4(&value["public_ip"])?,"domain":domain(&value["domain"])?,"public_port":port("public_port")?,
        "reality_sni":domain(&value["reality_sni"])?,"reality_public":reality_public,"short_id":short_id,"ws_path":path,
        "hysteria2_port":port("hysteria2_port")?,
    }}))
}
fn selected(tx: &Transaction<'_>, value: &Value) -> Result<Vec<String>> {
    let ids: Vec<String> = if let Some(packed) = value.as_str() {
        let raw = STANDARD
            .decode(packed)
            .map_err(|_| ManageError::InvalidInput)?;
        if raw.len() > 8000 || raw.len() % 16 != 0 || STANDARD.encode(&raw) != packed {
            return Err(ManageError::InvalidInput);
        }
        raw.as_chunks::<16>().0.iter().map(hex::encode).collect()
    } else {
        value
            .as_array()
            .ok_or(ManageError::InvalidInput)?
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or(ManageError::InvalidInput)
            })
            .collect::<Result<_>>()?
    };
    if ids.len() > 500 {
        return Err(ManageError::InvalidInput);
    }
    let mut seen = BTreeSet::new();
    for id in ids {
        if !lowercase_hex(&id, 32) || !seen.insert(id.clone()) {
            return Err(ManageError::InvalidInput);
        }
        let exists: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM users WHERE id=? AND deleted=0",
                [&id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ManageError::Unavailable)?;
        if exists.is_none() {
            return Err(ManageError::InvalidInput);
        }
    }
    Ok(seen.into_iter().collect())
}
fn display(node: &Value) -> Result<Value> {
    let required = |key: &str| node.get(key).cloned().ok_or(ManageError::Unavailable);
    let optional_string = |key: &str| {
        node.get(key)
            .map_or(Ok(""), |v| v.as_str().ok_or(ManageError::Unavailable))
    };
    let last = node
        .get("last_seen")
        .map_or(Ok(0), |v| v.as_i64().ok_or(ManageError::Unavailable))?;
    Ok(
        json!({"id":required("id")?,"name":required("name")?,"endpoint":required("endpoint")?,"users":required("users")?,
        "enabled":required("enabled")?,"last_seen":last,"applied_revision":optional_string("applied_revision")?,
        "pending_revision":optional_string("pending_revision")?}),
    )
}

impl NodeSync {
    pub fn list(&self) -> Result<Value> {
        let registry = registry(&self.db)?;
        let nodes = registry
            .as_array()
            .ok_or(ManageError::Unavailable)?
            .iter()
            .map(display)
            .collect::<Result<Vec<_>>>()?;
        Ok(json!({ "nodes": nodes }))
    }
    pub fn add(&mut self, input: &Value, now: i64) -> Result<Value> {
        if now < 0 || !exact_shape(input, &["name", "registration", "users"]) {
            return Err(ManageError::InvalidInput);
        }
        let mut node = registration(&input["registration"])?;
        let name = name(&input["name"])?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ManageError::Unavailable)?;
        let mut registry = registry(&tx)?;
        let nodes = registry.as_array_mut().ok_or(ManageError::Unavailable)?;
        if nodes.len() >= 20 {
            return Err(ManageError::Conflict);
        }
        let id = node["id"].as_str().ok_or(ManageError::Unavailable)?;
        for previous in nodes.iter() {
            let existing = previous
                .get("id")
                .and_then(Value::as_str)
                .ok_or(ManageError::Unavailable)?;
            if existing == id || existing.get(..8) == id.get(..8) {
                return Err(ManageError::Conflict);
            }
        }
        let users = selected(&tx, &input["users"])?;
        node["name"] = json!(name);
        node["users"] = json!(users);
        node["history"] = json!(users);
        node["enabled"] = json!(true);
        node["last_seen"] = json!(0);
        node["pending_revision"] = json!("");
        node["applied_revision"] = json!("");
        node["pending_users"] = json!([]);
        node["applied_users"] = json!([]);
        node["counters"] = json!({});
        let result = display(&node)?;
        nodes.push(node);
        save(&tx, &registry)?;
        audit(&tx, now, "node_added", &name)?;
        tx.commit().map_err(|_| ManageError::Unavailable)?;
        Ok(result)
    }
    pub fn update(&mut self, id: &str, input: &Value, now: i64) -> Result<Value> {
        if now < 0
            || !lowercase_hex(id, 32)
            || !exact_shape(input, &["name", "users", "enabled"])
            || !input["enabled"].is_boolean()
        {
            return Err(ManageError::InvalidInput);
        }
        let name = name(&input["name"])?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ManageError::Unavailable)?;
        let mut registry = registry(&tx)?;
        let node = registry
            .as_array_mut()
            .ok_or(ManageError::Unavailable)?
            .iter_mut()
            .find(|node| node.get("id").and_then(Value::as_str) == Some(id))
            .ok_or(ManageError::NotFound)?;
        let users = selected(&tx, &input["users"])?;
        let mut history: BTreeSet<String> = node
            .get("history")
            .and_then(Value::as_array)
            .ok_or(ManageError::Unavailable)?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or(ManageError::Unavailable)
            })
            .collect::<Result<_>>()?;
        history.extend(users.iter().cloned());
        if history.len() > 5000 {
            return Err(ManageError::Conflict);
        }
        node["name"] = json!(name);
        node["users"] = json!(users);
        node["history"] = json!(history);
        node["enabled"] = input["enabled"].clone();
        let result = display(node)?;
        save(&tx, &registry)?;
        audit(&tx, now, "node_updated", &name)?;
        tx.commit().map_err(|_| ManageError::Unavailable)?;
        Ok(result)
    }
}
