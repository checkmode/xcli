use super::validate;
use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::{json, Value};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
pub enum RuleStoreError {
    NotFound,
    UserNotFound,
    Unpublished,
    Conflict(String),
    Invalid(String),
    Service(String),
    Unavailable,
}

fn template_name(value: &Value) -> Result<String> {
    let name = value
        .as_str()
        .ok_or_else(|| RuleStoreError::Invalid("字段类型不正确".into()))?;
    if !(1..=60).contains(&name.chars().count()) {
        return Err(RuleStoreError::Invalid("字段长度不符合要求".into()));
    }
    xcli_panel_users::validate(&json!({ "name": name }))
        .map(|value| value.name)
        .map_err(|_| RuleStoreError::Invalid("请输入有效名称".into()))
}
fn save_registry(tx: &Transaction<'_>, registry: &Value) -> Result<()> {
    let data = serde_json::to_string(registry).map_err(|_| RuleStoreError::Unavailable)?;
    if data.len() > 1024 * 1024 {
        return Err(RuleStoreError::Invalid("模板总内容过大".into()));
    }
    tx.execute(
        "INSERT OR REPLACE INTO metadata(key,value) VALUES('rule_templates_v1',?)",
        [data],
    )
    .map_err(|_| RuleStoreError::Unavailable)?;
    Ok(())
}
fn audit(tx: &Transaction<'_>, stamp: i64, action: &str, detail: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO events(ts,action,detail) VALUES(?,?,?)",
        rusqlite::params![stamp, action, detail],
    )
    .map_err(|_| RuleStoreError::Unavailable)?;
    tx.execute(
        "DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM events)",
        [],
    )
    .map_err(|_| RuleStoreError::Unavailable)?;
    Ok(())
}
fn editor_input(input: &Value, update: bool) -> Result<(String, Value, Option<i64>)> {
    let object = input
        .as_object()
        .filter(|v| {
            v.len() == if update { 3 } else { 2 }
                && v.contains_key("name")
                && v.contains_key("spec")
                && (!update || v.contains_key("expected_revision"))
        })
        .ok_or_else(|| RuleStoreError::Invalid("请求格式不正确".into()))?;
    let name = template_name(&object["name"])?;
    let spec = checked(&object["spec"])?;
    let revision = if update {
        let value = object["expected_revision"]
            .as_i64()
            .filter(|value| *value >= 1)
            .ok_or_else(|| RuleStoreError::Invalid("模板版本不正确".into()))?;
        if value == i64::MAX {
            return Err(RuleStoreError::Invalid("模板版本已达上限".into()));
        }
        Some(value)
    } else {
        None
    };
    Ok((name, spec, revision))
}
fn expected_revision(input: &Value) -> Result<i64> {
    let object = input
        .as_object()
        .filter(|v| v.len() == 1 && v.contains_key("expected_revision"))
        .ok_or_else(|| RuleStoreError::Invalid("请求格式不正确".into()))?;
    object["expected_revision"]
        .as_i64()
        .filter(|n| *n >= 1)
        .ok_or_else(|| RuleStoreError::Invalid("模板版本不正确".into()))
}
fn editable<'a>(data: &'a mut Value, id: &str) -> Result<&'a mut Value> {
    if builtin(id) {
        if data.get("builtins").is_none() {
            data["builtins"] = json!({});
        }
        if data["builtins"].get(id).is_none() {
            data["builtins"][id] = default_item(id)?;
        }
        data.get_mut("builtins")
            .and_then(|v| v.get_mut(id))
            .ok_or(RuleStoreError::NotFound)
    } else {
        data.get_mut("templates")
            .and_then(|v| v.get_mut(id))
            .ok_or(RuleStoreError::NotFound)
    }
}
fn check_revision(item: &Value, expected: i64) -> Result<()> {
    if field(item, "revision")?
        .as_i64()
        .ok_or(RuleStoreError::Unavailable)?
        != expected
    {
        Err(RuleStoreError::Conflict(
            "模板已被其他操作修改，请重新读取".into(),
        ))
    } else {
        Ok(())
    }
}
fn validate_assignments<F>(
    tx: &Transaction<'_>,
    data: &Value,
    id: &str,
    spec: &Value,
    validate: &mut F,
) -> Result<i64>
where
    F: FnMut(&str, &Value) -> Result<()>,
{
    let assignments = field(data, "assignments")?
        .as_object()
        .ok_or(RuleStoreError::Unavailable)?;
    let mut policy = spec.clone();
    policy["managed"] = json!(true);
    let mut affected = 0;
    for (user_id, choice) in assignments {
        if choice.as_str() != Some(id) {
            continue;
        }
        let exists = tx
            .query_row(
                "SELECT 1 FROM users WHERE id=? AND deleted=0",
                [user_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| RuleStoreError::Unavailable)?
            .is_some();
        if exists {
            validate(user_id, &policy)?;
            affected += 1;
        }
    }
    Ok(affected)
}
/// Draft editing is safe to expose independently of publishing: existing
/// subscriptions continue using the previous published revision.
pub struct RuleEditor {
    db: Connection,
}
impl RuleEditor {
    pub fn open(path: &Path) -> Result<Self> {
        if std::fs::symlink_metadata(path)
            .map_err(|_| RuleStoreError::Unavailable)?
            .file_type()
            .is_symlink()
        {
            return Err(RuleStoreError::Unavailable);
        }
        let name = path.file_name().ok_or(RuleStoreError::Unavailable)?;
        let parent = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = std::fs::canonicalize(parent).map_err(|_| RuleStoreError::Unavailable)?;
        let db = Connection::open_with_flags(
            parent.join(name),
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| RuleStoreError::Unavailable)?;
        db.busy_timeout(Duration::from_secs(15))
            .map_err(|_| RuleStoreError::Unavailable)?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;")
            .map_err(|_| RuleStoreError::Unavailable)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(|_| RuleStoreError::Unavailable)?;
        Ok(Self { db })
    }
    pub fn create(&mut self, input: &Value, stamp: i64) -> Result<Value> {
        let (name, spec, _) = editor_input(input, false)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RuleStoreError::Unavailable)?;
        let mut data = registry(&tx)?;
        let templates = data
            .get_mut("templates")
            .and_then(Value::as_object_mut)
            .ok_or(RuleStoreError::Unavailable)?;
        if templates.len() >= 64 {
            return Err(RuleStoreError::Conflict("最多支持 64 个自定义模板".into()));
        }
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| RuleStoreError::Unavailable)?;
        bytes[6] = (bytes[6] & 15) | 0x40;
        bytes[8] = (bytes[8] & 63) | 0x80;
        let id = hex::encode(bytes);
        if templates.contains_key(&id) {
            return Err(RuleStoreError::Unavailable);
        }
        templates.insert(id.clone(),json!({"name":name,"draft":spec,"revision":1,"published":null,"published_revision":0,"published_at":0}));
        save_registry(&tx, &data)?;
        audit(&tx, stamp, "rule_template_created", &name)?;
        tx.commit().map_err(|_| RuleStoreError::Unavailable)?;
        Ok(json!({"id":id,"revision":1}))
    }
    pub fn update(&mut self, id: &str, input: &Value, stamp: i64) -> Result<Value> {
        let (name, spec, expected) = editor_input(input, true)?;
        let expected = expected.ok_or(RuleStoreError::Unavailable)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RuleStoreError::Unavailable)?;
        let mut data = registry(&tx)?;
        let item = editable(&mut data, id)?;
        check_revision(item, expected)?;
        item["name"] = json!(name);
        item["draft"] = spec;
        item["revision"] = json!(expected + 1);
        save_registry(&tx, &data)?;
        audit(&tx, stamp, "rule_template_saved", &name)?;
        tx.commit().map_err(|_| RuleStoreError::Unavailable)?;
        Ok(json!({ "revision": expected + 1 }))
    }
    pub fn publish<F>(
        &mut self,
        id: &str,
        input: &Value,
        stamp: i64,
        mut validate: F,
    ) -> Result<Value>
    where
        F: FnMut(&str, &Value) -> Result<()>,
    {
        let expected = expected_revision(input)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RuleStoreError::Unavailable)?;
        let mut data = registry(&tx)?;
        let spec = {
            let item = editable(&mut data, id)?;
            check_revision(item, expected)?;
            checked(field(item, "draft")?)?
        };
        let affected = validate_assignments(&tx, &data, id, &spec, &mut validate)?;
        let item = editable(&mut data, id)?;
        let name = field(item, "name")?
            .as_str()
            .ok_or(RuleStoreError::Unavailable)?
            .to_owned();
        item["published"] = spec;
        item["published_revision"] = json!(expected);
        item["published_at"] = json!(stamp);
        save_registry(&tx, &data)?;
        audit(&tx, stamp, "rule_template_published", &name)?;
        tx.commit().map_err(|_| RuleStoreError::Unavailable)?;
        Ok(json!({"published_revision":expected,"affected_users":affected}))
    }
    pub fn reset<F>(
        &mut self,
        id: &str,
        input: &Value,
        stamp: i64,
        mut validate: F,
    ) -> Result<Value>
    where
        F: FnMut(&str, &Value) -> Result<()>,
    {
        let expected = expected_revision(input)?;
        if !builtin(id) {
            return Err(RuleStoreError::NotFound);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RuleStoreError::Unavailable)?;
        let mut data = registry(&tx)?;
        let initial = default_item(id)?;
        let (unchanged, initial_content, backup) = {
            let item = editable(&mut data, id)?;
            check_revision(item, expected)?;
            let initial_content = field(item, "name")? == field(&initial, "name")?
                && field(item, "draft")? == field(&initial, "draft")?
                && field(item, "published")? == field(&initial, "published")?;
            let unchanged =
                initial_content && field(item, "revision")? == field(item, "published_revision")?;
            let backup = if initial_content && item.get("reset_backup").is_some() {
                field(item, "reset_backup")?.clone()
            } else {
                json!({"name":field(item,"name")?,"draft":field(item,"draft")?,"published":field(item,"published")?,
                    "draft_dirty":field(item,"revision")?!=field(item,"published_revision")?,"published_at":field(item,"published_at")?})
            };
            (unchanged, initial_content, backup)
        };
        if unchanged {
            return Ok(json!({"unchanged":true,"revision":expected,"affected_users":0}));
        }
        let _ = initial_content;
        if expected == i64::MAX {
            return Err(RuleStoreError::Invalid("模板版本已达上限".into()));
        }
        let affected =
            validate_assignments(&tx, &data, id, field(&initial, "published")?, &mut validate)?;
        let item = editable(&mut data, id)?;
        item["name"] = field(&initial, "name")?.clone();
        item["draft"] = field(&initial, "draft")?.clone();
        item["published"] = field(&initial, "published")?.clone();
        item["revision"] = json!(expected + 1);
        item["published_revision"] = json!(expected + 1);
        item["published_at"] = json!(stamp);
        item["reset_backup"] = backup;
        let name = field(item, "name")?
            .as_str()
            .ok_or(RuleStoreError::Unavailable)?
            .to_owned();
        save_registry(&tx, &data)?;
        audit(&tx, stamp, "rule_template_reset", &name)?;
        tx.commit().map_err(|_| RuleStoreError::Unavailable)?;
        Ok(json!({"unchanged":false,"revision":expected+1,"affected_users":affected}))
    }
    pub fn undo_reset<F>(
        &mut self,
        id: &str,
        input: &Value,
        stamp: i64,
        mut validate: F,
    ) -> Result<Value>
    where
        F: FnMut(&str, &Value) -> Result<()>,
    {
        let expected = expected_revision(input)?;
        if !builtin(id) {
            return Err(RuleStoreError::NotFound);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RuleStoreError::Unavailable)?;
        let mut data = registry(&tx)?;
        let backup = {
            let item = editable(&mut data, id)?;
            check_revision(item, expected)?;
            item.get("reset_backup")
                .filter(|v| v.is_object())
                .cloned()
                .ok_or_else(|| RuleStoreError::Conflict("没有可撤销的恢复记录".into()))?
        };
        if expected == i64::MAX {
            return Err(RuleStoreError::Invalid("模板版本已达上限".into()));
        }
        let draft = checked(field(&backup, "draft")?)?;
        let published = checked(field(&backup, "published")?)?;
        let affected = validate_assignments(&tx, &data, id, &published, &mut validate)?;
        let item = editable(&mut data, id)?;
        item["name"] = field(&backup, "name")?.clone();
        item["draft"] = draft;
        item["published"] = published;
        item["revision"] = json!(expected + 1);
        item["published_revision"] = json!(if field(&backup, "draft_dirty")?
            .as_bool()
            .ok_or(RuleStoreError::Unavailable)?
        {
            expected
        } else {
            expected + 1
        });
        item["published_at"] = field(&backup, "published_at")?.clone();
        item.as_object_mut()
            .ok_or(RuleStoreError::Unavailable)?
            .shift_remove("reset_backup");
        let name = field(item, "name")?
            .as_str()
            .ok_or(RuleStoreError::Unavailable)?
            .to_owned();
        save_registry(&tx, &data)?;
        audit(&tx, stamp, "rule_template_reset_undone", &name)?;
        tx.commit().map_err(|_| RuleStoreError::Unavailable)?;
        Ok(json!({"revision":expected+1,"affected_users":affected}))
    }
    pub fn assign<F>(
        &mut self,
        user_id: &str,
        input: &Value,
        stamp: i64,
        mut validate: F,
    ) -> Result<Value>
    where
        F: FnMut(&str, &Value) -> Result<()>,
    {
        let input = input
            .as_object()
            .filter(|v| v.len() == 1 && v.contains_key("template_id"))
            .ok_or_else(|| RuleStoreError::Invalid("请求格式不正确".into()))?;
        let choice = input["template_id"]
            .as_str()
            .ok_or_else(|| RuleStoreError::Invalid("字段类型不正确".into()))?;
        if !(1..=32).contains(&choice.chars().count()) {
            return Err(RuleStoreError::Invalid("字段长度不符合要求".into()));
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RuleStoreError::Unavailable)?;
        let name: String = tx
            .query_row(
                "SELECT name FROM users WHERE id=? AND deleted=0",
                [user_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| RuleStoreError::Unavailable)?
            .ok_or(RuleStoreError::UserNotFound)?;
        let mut data = registry(&tx)?;
        if choice == "legacy" {
            data["assignments"]
                .as_object_mut()
                .ok_or(RuleStoreError::Unavailable)?
                .shift_remove(user_id);
        } else {
            let mut spec = selected(&data, choice)?;
            spec["managed"] = json!(true);
            validate(user_id, &spec)?;
            data["assignments"][user_id] = json!(choice);
        }
        save_registry(&tx, &data)?;
        audit(&tx, stamp, "user_rule_template_changed", &name)?;
        tx.commit().map_err(|_| RuleStoreError::Unavailable)?;
        Ok(json!({"ok":true}))
    }
}
type Result<T> = std::result::Result<T, RuleStoreError>;
pub fn factory_independent_rules() -> &'static str {
    // Legacy category data is also used to recognize existing published
    // templates and to generate the base independent policy.
    include_str!("factory-independent.rules")
}
pub fn factory_spec(id: &str) -> Result<Value> {
    match id {
        "standard" => Ok(json!({"base":"standard","ai_outbound":"proxy","rules":""})),
        "independent" => {
            // Keep the editable factory template separate from the legacy
            // category data: published rules may add groups or reorder targets.
            let mut spec: Value = serde_json::from_str(include_str!(
                "factory-independent-defaults.json"
            ))
            .map_err(|_| RuleStoreError::Unavailable)?;
            spec["rules"] = json!(include_str!("factory-independent-published.rules"));
            checked(&spec)
        }
        _ => Err(RuleStoreError::NotFound),
    }
}
fn builtin(id: &str) -> bool {
    matches!(id, "standard" | "independent")
}
fn default_item(id: &str) -> Result<Value> {
    let spec = factory_spec(id)?;
    Ok(
        json!({"name":if id=="standard" {"标准分流"} else {"独立服务分组"},"draft":spec,
        "revision":1,"published":spec,"published_revision":1,"published_at":0}),
    )
}
fn checked(spec: &Value) -> Result<Value> {
    validate(spec).map_err(|error| RuleStoreError::Invalid(error.0))
}
fn registry(tx: &Transaction<'_>) -> Result<Value> {
    let raw: Option<String> = tx
        .query_row(
            "SELECT value FROM metadata WHERE key='rule_templates_v1'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| RuleStoreError::Unavailable)?;
    let Some(raw) = raw else {
        return Ok(json!({"version":1,"templates":{},"assignments":{}}));
    };
    if raw.len() > 1024 * 1024 {
        return Err(RuleStoreError::Unavailable);
    }
    let value: Value = serde_json::from_str(&raw).map_err(|_| RuleStoreError::Unavailable)?;
    let templates = value
        .get("templates")
        .and_then(Value::as_object)
        .ok_or(RuleStoreError::Unavailable)?;
    let assignments = value
        .get("assignments")
        .and_then(Value::as_object)
        .ok_or(RuleStoreError::Unavailable)?;
    if value.get("version").and_then(Value::as_i64) != Some(1)
        || templates.len() > 64
        || assignments.len() > 500
    {
        return Err(RuleStoreError::Unavailable);
    }
    if let Some(entries) = value.get("builtins") {
        let entries = entries
            .as_object()
            .filter(|items| items.len() <= 2)
            .ok_or(RuleStoreError::Unavailable)?;
        if entries
            .iter()
            .any(|(id, item)| !builtin(id) || !item.is_object())
        {
            return Err(RuleStoreError::Unavailable);
        }
    }
    Ok(value)
}
fn builtin_item(registry: &Value, id: &str) -> Result<Value> {
    registry
        .get("builtins")
        .and_then(|v| v.get(id))
        .cloned()
        .map_or_else(|| default_item(id), Ok)
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value.get(key).ok_or(RuleStoreError::Unavailable)
}
fn selected(registry: &Value, id: &str) -> Result<Value> {
    if builtin(id) {
        if let Some(item) = registry.get("builtins").and_then(|v| v.get(id)) {
            return checked(field(item, "published")?);
        }
        return factory_spec(id);
    }
    if id.len() != 32
        || !id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(RuleStoreError::NotFound);
    }
    let item = registry
        .get("templates")
        .and_then(|v| v.get(id))
        .ok_or(RuleStoreError::NotFound)?;
    let published = field(item, "published")?;
    if published.is_null() {
        return Err(RuleStoreError::Unpublished);
    }
    checked(published)
}
fn has_legacy_policy(settings: &Value, user_id: &str) -> Result<bool> {
    match settings.get("client_policies") {
        None => Ok(false),
        Some(value) => Ok(value
            .as_object()
            .ok_or(RuleStoreError::Unavailable)?
            .contains_key(user_id)),
    }
}

/// Read-only view of existing rule data. Callers must authorize access and
/// serialize with panel writers; mutation and publication are not implemented.
pub struct RuleStore {
    db: Connection,
    settings: Value,
}
impl RuleStore {
    pub fn open(path: &Path, settings: Value) -> Result<Self> {
        if std::fs::symlink_metadata(path)
            .map_err(|_| RuleStoreError::Unavailable)?
            .file_type()
            .is_symlink()
        {
            return Err(RuleStoreError::Unavailable);
        }
        let name = path.file_name().ok_or(RuleStoreError::Unavailable)?;
        let parent = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = std::fs::canonicalize(parent).map_err(|_| RuleStoreError::Unavailable)?;
        let db = Connection::open_with_flags(
            parent.join(name),
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| RuleStoreError::Unavailable)?;
        db.busy_timeout(Duration::from_secs(15))
            .map_err(|_| RuleStoreError::Unavailable)?;
        db.execute_batch("PRAGMA trusted_schema=OFF;")
            .map_err(|_| RuleStoreError::Unavailable)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(|_| RuleStoreError::Unavailable)?;
        Ok(Self { db, settings })
    }
    pub fn effective(&mut self, user_id: &str) -> Result<Value> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| RuleStoreError::Unavailable)?;
        let registry = registry(&tx)?;
        let choice = field(&registry, "assignments")?.get(user_id);
        let result = if let Some(choice) = choice {
            let choice = choice.as_str().ok_or(RuleStoreError::Unavailable)?;
            let mut spec = selected(&registry, choice)?;
            spec["managed"] = json!(true);
            spec
        } else {
            let independent = has_legacy_policy(&self.settings, user_id)?;
            let ai = if independent {
                self.settings
                    .get("client_policies")
                    .and_then(|v| v.get(user_id))
                    .and_then(|v| v.get("ai_outbound"))
                    .and_then(Value::as_str)
                    .ok_or(RuleStoreError::Unavailable)?
            } else {
                "proxy"
            };
            json!({"base":if independent {"independent"} else {"standard"},"ai_outbound":ai,"rules":"","managed":false})
        };
        tx.commit().map_err(|_| RuleStoreError::Unavailable)?;
        Ok(result)
    }
    pub fn catalog(&mut self) -> Result<Value> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| RuleStoreError::Unavailable)?;
        let registry = registry(&tx)?;
        let mut templates = Vec::new();
        for id in ["standard", "independent"] {
            let item = builtin_item(&registry, id)?;
            let draft = checked(field(&item, "draft")?)?;
            let published = checked(field(&item, "published")?)?;
            templates.push(json!({"id":id,"name":field(&item,"name")?,"builtin":true,"spec":draft,
                "revision":field(&item,"revision")?,"published":true,"published_spec":published,
                "published_revision":field(&item,"published_revision")?,"published_at":field(&item,"published_at")?,
                "factory_spec":factory_spec(id)?,"can_undo_reset":item.get("reset_backup").is_some_and(Value::is_object)}));
        }
        let custom = field(&registry, "templates")?
            .as_object()
            .ok_or(RuleStoreError::Unavailable)?;
        for (id, item) in custom {
            if id.len() != 32
                || !id
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            {
                return Err(RuleStoreError::Unavailable);
            }
            let draft = checked(field(item, "draft")?)?;
            let value = field(item, "published")?;
            let published = if value.is_null() {
                Value::Null
            } else {
                checked(value)?
            };
            templates.push(json!({"id":id,"name":field(item,"name")?,"builtin":false,"spec":draft,
                "revision":field(item,"revision")?,"published":!published.is_null(),"published_spec":published,
                "published_revision":field(item,"published_revision")?,"published_at":field(item,"published_at")?}));
        }
        let assignments = field(&registry, "assignments")?;
        let mut users = Vec::new();
        {
            let mut query = tx
                .prepare("SELECT id,name FROM users WHERE deleted=0 ORDER BY created")
                .map_err(|_| RuleStoreError::Unavailable)?;
            let mut rows = query.query([]).map_err(|_| RuleStoreError::Unavailable)?;
            while let Some(row) = rows.next().map_err(|_| RuleStoreError::Unavailable)? {
                let id: String = row.get(0).map_err(|_| RuleStoreError::Unavailable)?;
                let name: String = row.get(1).map_err(|_| RuleStoreError::Unavailable)?;
                let choice = match assignments.get(&id) {
                    Some(value) => value.as_str().ok_or(RuleStoreError::Unavailable)?,
                    None => "legacy",
                };
                users.push(json!({"id":id,"name":name,"template_id":choice,
                    "legacy_independent":choice=="legacy" && assignments.get(&id).is_none() && has_legacy_policy(&self.settings,&id)?}));
            }
        }
        tx.commit().map_err(|_| RuleStoreError::Unavailable)?;
        Ok(json!({"templates":templates,"users":users}))
    }
}
