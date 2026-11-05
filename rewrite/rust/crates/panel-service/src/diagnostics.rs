//! Read-only, server-side subscription generation diagnostics.
//! Generated credentials stay in memory and must not be included in output.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use xcli_panel_rules::RuleStore;
use xcli_panel_subscription::SubscriptionStore;
use zeroize::Zeroizing;

use super::SubscriptionError;

fn sha256(content: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(content))
}

fn selected_template(catalog: &Value, id: &str) -> Value {
    let mut selected = json!({"name":"沿用原配置","revision":null,"published_at":null});
    if let Some(assignment) = catalog["users"]
        .as_array()
        .and_then(|users| users.iter().find(|user| user["id"].as_str() == Some(id)))
    {
        let choice = assignment["template_id"].as_str().unwrap_or("legacy");
        if choice == "legacy" && assignment["legacy_independent"].as_bool() == Some(true) {
            selected["name"] = json!("沿用原配置（独立服务分组）");
        } else if let Some(item) = catalog["templates"].as_array().and_then(|templates| {
            templates
                .iter()
                .find(|item| item["id"].as_str() == Some(choice))
        }) {
            selected = json!({"name":item["name"],"revision":item["published_revision"],
                "published_at":item["published_at"]});
        }
    }
    selected
}

fn clash_result(config: &Value) -> Option<Value> {
    let nodes = config["proxies"].as_array()?.len();
    let groups: Option<Vec<_>> = config["proxy-groups"]
        .as_array()?
        .iter()
        .map(|item| item["name"].as_str().map(str::to_owned))
        .collect();
    let content = Zeroizing::new(serde_json::to_string(config).ok()?);
    Some(
        json!({"status":"ready","node_count":nodes,"groups":groups?,"sha256":sha256(content.as_bytes())}),
    )
}

fn shadow_result(content: &str) -> Value {
    let mut groups = Vec::new();
    let mut in_groups = false;
    for line in content.lines().map(|line| line.trim_end_matches('\r')) {
        if line.starts_with('[') {
            in_groups = line == "[Proxy Group]";
        } else if in_groups && !line.is_empty() && !line.starts_with(['#', ';']) {
            if let Some((name, _)) = line.split_once('=') {
                let name = name.trim_matches([' ', '\t']);
                if !name.is_empty() {
                    groups.push(name.to_owned());
                }
            }
        }
    }
    json!({"status":"ready","groups":groups,
        "inherits_local_base":content.contains("include = default.conf"),"sha256":sha256(content)})
}

/// The caller must serialize this with all user and rules mutations and must
/// authenticate the administrator before invoking it.
pub(super) fn generate(
    store: &mut SubscriptionStore,
    rules: &mut RuleStore,
    id: &str,
    origin: &str,
    now: i64,
) -> Result<Value, SubscriptionError> {
    let (token, status) = store
        .diagnostic_user(id, now)
        .map_err(SubscriptionError::Store)?;
    let catalog = rules.catalog().map_err(|_| SubscriptionError::Rules)?;
    let mut result = json!({"generated_at":now,"origin":origin,"user_status":status,
        "template":selected_template(&catalog, id),"client_enabled":"unknown","last_fetch":"unknown",
        "formats":{"nodes":{"status":"inactive"},"clash":{"status":"inactive"},
                   "shadowrocket":{"status":"inactive"}}});
    if status != "active" {
        return Ok(result);
    }
    let invalid = || json!({"status":"error"});
    result["formats"]["nodes"] = store
        .generic(&token, now)
        .ok()
        .and_then(|(body, _)| {
            let body = Zeroizing::new(body);
            let decoded = Zeroizing::new(STANDARD.decode(body.as_bytes()).ok()?);
            Some(
                json!({"status":"ready","node_count":decoded.iter().filter(|v| **v==b'\n').count(),
            "sha256":sha256(body.as_bytes())}),
            )
        })
        .unwrap_or_else(invalid);
    result["formats"]["clash"] = invalid();
    result["formats"]["shadowrocket"] = invalid();
    if let (Ok(input), Ok(policy)) = (store.clash_input(&token, now), rules.effective(id)) {
        let user = xcli_panel_clash::User {
            id: input.user_id.clone(),
            uuid: input.uuid.clone(),
        };
        result["formats"]["clash"] = xcli_panel_clash::build(
            &input.settings,
            &user,
            &input.remote_nodes,
            input.dynamic_enabled,
            &policy,
        )
        .ok()
        .and_then(|config| clash_result(&config))
        .unwrap_or_else(invalid);
        let user = xcli_panel_shadowrocket::User {
            id: input.user_id,
            name: input.name,
            uuid: input.uuid,
            token: input.token,
        };
        result["formats"]["shadowrocket"] = match xcli_panel_shadowrocket::profile(
            &input.settings,
            &user,
            &input.remote_nodes,
            input.dynamic_enabled,
            &policy,
        ) {
            Ok(content) => shadow_result(&Zeroizing::new(content)),
            Err(error) if error.status == 404 => json!({"status":"unavailable"}),
            Err(_) => invalid(),
        };
    }
    Ok(result)
}
