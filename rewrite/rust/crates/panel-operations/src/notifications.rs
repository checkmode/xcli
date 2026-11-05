//! Experimental legacy-compatible notification outbox.
//!
//! No scheduler is started by this module. The caller must serialize all
//! writes and run at most one delivery worker. Event IDs permit receivers to
//! deduplicate a retry after a crash between HTTP delivery and committing it.
use crate::{alarm, open_db, webhook, Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use uuid::Uuid;
use xcli_auth_compat::{open_xgb1, seal_xgb1};
use zeroize::{Zeroize, Zeroizing};

pub struct Notifications {
    db: Connection,
    key: Zeroizing<[u8; 32]>,
    site: String,
    services: BTreeMap<String, String>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigureError {
    Invalid(&'static str),
    Unavailable,
}
#[derive(Debug, PartialEq, Eq)]
pub enum EnqueueError {
    NotConfigured,
    RateLimited,
    Unavailable,
}
#[derive(Clone, Copy)]
pub struct BackupObservation {
    pub started: i64,
    pub interval: i64,
}
/// Intentionally not Debug/Clone: contains the decrypted destination and auth.
pub struct Pending {
    id: String,
    generation: String,
    attempts: i64,
    config: webhook::Config,
    payload: Value,
}
impl Pending {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn deliver(
        &self,
        sender: &crate::sender::Sender,
        timestamp: i64,
        stop: &std::sync::atomic::AtomicBool,
    ) -> webhook::Delivery {
        sender.deliver(&self.config, &self.payload, timestamp, stop)
    }
}
impl Notifications {
    pub fn open(
        path: &Path,
        key: [u8; 32],
        site: &str,
        mut services: BTreeMap<String, String>,
    ) -> Result<Self> {
        if site.is_empty()
            || site.len() > 253
            || !site
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.')
            || services.len() > 45
            || services.iter().any(|(tag, label)| {
                !crate::valid_transport(tag)
                    || label.is_empty()
                    || label.chars().count() > 80
                    || label.chars().any(char::is_control)
            })
        {
            return Err(Error::Invalid);
        }
        for (name, label) in [
            ("probe", "探测结果采集"),
            ("core", "Xray 管理接口"),
            ("backup", "本地自动加密备份"),
        ] {
            services.insert(name.into(), label.into());
        }
        let db = open_db(path)?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS notification_config(id INTEGER PRIMARY KEY CHECK(id=1),enabled INTEGER NOT NULL DEFAULT 0,
              url TEXT NOT NULL DEFAULT '',bearer TEXT NOT NULL DEFAULT '',signing TEXT NOT NULL DEFAULT '',
              generation TEXT NOT NULL DEFAULT '',failures INTEGER NOT NULL DEFAULT 3,recoveries INTEGER NOT NULL DEFAULT 2);
            INSERT OR IGNORE INTO notification_config(id) VALUES(1);
            CREATE TABLE IF NOT EXISTS alarm_state(service TEXT PRIMARY KEY,bad INTEGER NOT NULL DEFAULT 0,
              good INTEGER NOT NULL DEFAULT 0,firing INTEGER NOT NULL DEFAULT 0,since INTEGER NOT NULL DEFAULT 0,
              last_sample INTEGER NOT NULL DEFAULT 0,last_seen INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS notifications(id TEXT PRIMARY KEY,created INTEGER NOT NULL,service TEXT NOT NULL,
              kind TEXT NOT NULL,payload TEXT NOT NULL,generation TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',
              attempts INTEGER NOT NULL DEFAULT 0,next_attempt INTEGER NOT NULL DEFAULT 0,
              delivered INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '',http_status INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS notification_pending ON notifications(status,next_attempt);")
            .map_err(|_|Error::Unavailable)?;
        Ok(Self {
            db,
            key: Zeroizing::new(key),
            site: site.into(),
            services,
        })
    }

    /// Atomically persist an observation, its audit record, and any new event.
    /// Unknown results should use `unknown` and never clear a firing alarm.
    pub fn observe(
        &mut self,
        service: &str,
        failed: bool,
        sample: i64,
        now: i64,
    ) -> Result<Option<alarm::Transition>> {
        let label = self.services.get(service).ok_or(Error::Invalid)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Unavailable)?;
        let result = observe_tx(&tx, &self.site, service, label, failed, sample, now)?;
        tx.commit().map_err(|_| Error::Unavailable)?;
        Ok(result)
    }
    pub fn unknown(&mut self, service: &str) -> Result<()> {
        if !self.services.contains_key(service) {
            return Err(Error::Invalid);
        }
        self.db
            .execute(
                "UPDATE alarm_state SET bad=0,good=0 WHERE service=?",
                [service],
            )
            .map_err(|_| Error::Unavailable)?;
        Ok(())
    }

    /// Observe a filtered monitor report as one transaction. Missing results
    /// break individual streaks and affect the separate probe-sensor alarm.
    pub fn collect_monitor(&mut self, report: &Value, now: i64) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Unavailable)?;
        collect_monitor_tx(&tx, &self.site, &self.services, report, now)?;
        tx.commit().map_err(|_| Error::Unavailable)
    }
    /// Persist historical samples and alarm changes atomically in the same DB.
    /// The panel must first initialize the compatible history tables.
    pub fn collect_with_history(&mut self, report: &Value, now: i64) -> Result<()> {
        self.collect_runtime(Some(report), None, None, now)
    }
    /// Collect enabled monitoring sources together, so no alarm can commit
    /// without its corresponding history and sibling observations.
    pub fn collect_runtime(
        &mut self,
        report: Option<&Value>,
        core: Option<bool>,
        backup: Option<BackupObservation>,
        now: i64,
    ) -> Result<()> {
        if now < 0 {
            return Err(Error::Invalid);
        }
        let transports = self
            .services
            .keys()
            .filter(|name| crate::valid_transport(name))
            .cloned()
            .collect::<Vec<_>>();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Unavailable)?;
        if let Some(report) = report {
            crate::record_history(&tx, &transports, report, now)?;
            collect_monitor_tx(&tx, &self.site, &self.services, report, now)?;
        }
        if let Some(healthy) = core {
            observe_tx(
                &tx,
                &self.site,
                "core",
                self.services.get("core").ok_or(Error::Invalid)?,
                !healthy,
                now / 60,
                now,
            )?;
        }
        if let Some(options) = backup {
            if options.started < 0
                || options.started > now
                || !(60..=604_800).contains(&options.interval)
            {
                return Err(Error::Invalid);
            }
            let error: Option<String> = tx
                .query_row(
                    "SELECT value FROM metadata WHERE key='backup_error'",
                    [],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|_| Error::Unavailable)?;
            let last: Option<String> = tx
                .query_row(
                    "SELECT value FROM metadata WHERE key='last_backup'",
                    [],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|_| Error::Unavailable)?;
            let last = match last {
                Some(value) => value
                    .parse::<i64>()
                    .ok()
                    .filter(|value| *value >= 0 && *value <= now.saturating_add(60))
                    .ok_or(Error::Unavailable)?,
                None => options.started,
            };
            let failed = error.is_some_and(|value| !value.is_empty())
                || now.saturating_sub(last) > options.interval + 900;
            observe_tx(
                &tx,
                &self.site,
                "backup",
                self.services.get("backup").ok_or(Error::Invalid)?,
                failed,
                now / 60,
                now,
            )?;
        }
        tx.commit().map_err(|_| Error::Unavailable)
    }

    /// Queue an explicit user-initiated test even when fault alerts are off.
    pub fn enqueue_test(&mut self, now: i64) -> std::result::Result<String, EnqueueError> {
        use EnqueueError::{NotConfigured, RateLimited, Unavailable};
        if now < 0 {
            return Err(Unavailable);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Unavailable)?;
        let configured: bool = tx
            .query_row(
                "SELECT url<>'' FROM notification_config WHERE id=1",
                [],
                |r| r.get(0),
            )
            .map_err(|_| Unavailable)?;
        if !configured {
            return Err(NotConfigured);
        }
        let recent: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM notifications WHERE kind='test' AND created>?)",
                [now.saturating_sub(30)],
                |r| r.get(0),
            )
            .map_err(|_| Unavailable)?;
        if recent {
            return Err(RateLimited);
        }
        let id = queue(&tx, &self.site, "test", "通知通道测试", "test", now, now)
            .map_err(|_| Unavailable)?
            .ok_or(Unavailable)?;
        tx.execute(
            "INSERT INTO events(ts,action,detail) VALUES(?,'notification_test','测试通知已排队')",
            [now],
        )
        .map_err(|_| Unavailable)?;
        tx.execute(
            "DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM events)",
            [],
        )
        .map_err(|_| Unavailable)?;
        tx.commit().map_err(|_| Unavailable)?;
        Ok(id)
    }

    /// Apply validated configuration within the administrator's existing
    /// reauthentication transaction. This method does not authenticate on its
    /// own. In-flight network requests may already have reached the old target.
    pub fn configure(
        &self,
        tx: &Transaction<'_>,
        input: &Value,
        now: i64,
    ) -> std::result::Result<(), ConfigureError> {
        use ConfigureError::{Invalid, Unavailable};
        let object = input.as_object().ok_or(Invalid("请求必须是 JSON 对象"))?;
        const FIELDS: &[&str] = &[
            "enabled",
            "url",
            "bearer",
            "signing_secret",
            "clear_auth",
            "clear_url",
            "failures",
            "recoveries",
            "current_password",
            "code",
        ];
        if now < 0 || object.keys().any(|name| !FIELDS.contains(&name.as_str())) {
            return Err(Invalid("包含不支持的通知字段"));
        }
        let (old_enabled, old_url, old_bearer, old_signing, old_failures, old_recoveries): (i64,String,String,String,i64,i64) = tx
            .query_row("SELECT enabled,url,bearer,signing,failures,recoveries FROM notification_config WHERE id=1", [],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))
            .map_err(|_| Unavailable)?;
        let mut url = decrypt(self.key.as_ref(), "url", &old_url).map_err(|_| Unavailable)?;
        let mut bearer =
            decrypt(self.key.as_ref(), "bearer", &old_bearer).map_err(|_| Unavailable)?;
        let mut signing =
            decrypt(self.key.as_ref(), "signing", &old_signing).map_err(|_| Unavailable)?;
        let bool_field =
            |name: &str, fallback: bool| -> std::result::Result<bool, ConfigureError> {
                object.get(name).map_or(Ok(fallback), |value| {
                    value.as_bool().ok_or(Invalid("通知开关必须是布尔值"))
                })
            };
        let integer = |name: &str, fallback: i64| -> std::result::Result<i64, ConfigureError> {
            let value = object
                .get(name)
                .map_or(Some(fallback), Value::as_i64)
                .ok_or(Invalid("通知阈值必须是有效整数"))?;
            if !(1..=10).contains(&value) {
                return Err(Invalid("通知阈值超出允许范围"));
            }
            Ok(value)
        };
        let secret = |name: &str,
                      maximum: usize|
         -> std::result::Result<Zeroizing<String>, ConfigureError> {
            let text = object
                .get(name)
                .map_or(Some(""), Value::as_str)
                .ok_or(Invalid("字段格式不正确"))?;
            if text.len() > maximum || text.chars().any(char::is_control) {
                return Err(Invalid("凭据格式不正确"));
            }
            Ok(Zeroizing::new(text.to_owned()))
        };
        let mut enabled = bool_field("enabled", old_enabled != 0)?;
        let new_url = secret("url", 4096)?;
        let new_bearer = secret("bearer", 2048)?;
        let new_signing = secret("signing_secret", 256)?;
        if !new_url.is_empty() {
            webhook::validate_url(&new_url).map_err(Invalid)?;
            url = new_url;
        }
        if bool_field("clear_auth", false)? {
            bearer.zeroize();
            signing.zeroize();
        }
        if !new_bearer.is_empty() {
            bearer = new_bearer;
        }
        if !new_signing.is_empty() {
            if new_signing.len() < 16 {
                return Err(Invalid("签名密钥至少 16 个字符"));
            }
            signing = new_signing;
        }
        if bool_field("clear_url", false)? {
            url.zeroize();
            bearer.zeroize();
            signing.zeroize();
            enabled = false;
        }
        if enabled && url.is_empty() {
            return Err(Invalid("请先填写 Webhook 地址"));
        }
        let failures = integer("failures", old_failures)?;
        let recoveries = integer("recoveries", old_recoveries)?;
        let encrypt = |field: &str, plain: &str| -> std::result::Result<String, ConfigureError> {
            if plain.is_empty() {
                return Ok(String::new());
            }
            let context = format!("xcli:webhook:{field}:v1");
            let bytes = seal_xgb1(plain.as_bytes(), self.key.as_ref(), context.as_bytes())
                .map_err(|_| Unavailable)?;
            Ok(STANDARD.encode(bytes))
        };
        let generation = Uuid::new_v4().simple().to_string();
        tx.execute("UPDATE notification_config SET enabled=?,url=?,bearer=?,signing=?,generation=?,failures=?,recoveries=? WHERE id=1",
            params![i64::from(enabled),encrypt("url",&url)?,encrypt("bearer",&bearer)?,encrypt("signing",&signing)?,generation,failures,recoveries])
            .map_err(|_|Unavailable)?;
        tx.execute("UPDATE notifications SET status='cancelled',last_error='通知配置已变更' WHERE status='pending'",[]).map_err(|_|Unavailable)?;
        if enabled {
            let alarms = {
                let mut statement = tx
                    .prepare("SELECT service,since FROM alarm_state WHERE firing=1")
                    .map_err(|_| Unavailable)?;
                let rows = statement
                    .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
                    .map_err(|_| Unavailable)?;
                rows.collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|_| Unavailable)?
            };
            for (service, since) in alarms {
                if let Some(label) = self.services.get(&service) {
                    queue(tx, &self.site, &service, label, "fault", now, since)
                        .map_err(|_| Unavailable)?;
                }
            }
        }
        tx.execute(
            "INSERT INTO events(ts,action,detail) VALUES(?,'notifications_configured',?)",
            params![
                now,
                if enabled {
                    "已启用 Webhook 通知"
                } else {
                    "已关闭 Webhook 通知"
                }
            ],
        )
        .map_err(|_| Unavailable)?;
        tx.execute(
            "DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM events)",
            [],
        )
        .map_err(|_| Unavailable)?;
        Ok(())
    }

    /// Read the existing configuration and recent outcomes without exposing
    /// destination paths, bearer tokens, signing keys, or event payloads.
    pub fn status(&mut self) -> Result<Value> {
        let tx = self.db.transaction().map_err(|_| Error::Unavailable)?;
        let (enabled, url, bearer, signing, failures, recoveries): (i64, String, String, String, i64, i64) = tx
            .query_row("SELECT enabled,url,bearer,signing,failures,recoveries FROM notification_config WHERE id=1", [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
            .map_err(|_| Error::Unavailable)?;
        let alarms = {
            let mut statement = tx.prepare("SELECT service,firing,since,bad,good,last_seen FROM alarm_state WHERE firing=1 ORDER BY since").map_err(|_| Error::Unavailable)?;
            let rows = statement.query_map([], |r| Ok(json!({"service":r.get::<_,String>(0)?,"firing":r.get::<_,i64>(1)?,"since":r.get::<_,i64>(2)?,"bad":r.get::<_,i64>(3)?,"good":r.get::<_,i64>(4)?,"last_seen":r.get::<_,i64>(5)?}))).map_err(|_| Error::Unavailable)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| Error::Unavailable)?
        };
        let deliveries = {
            let mut statement = tx.prepare("SELECT id,created,service,kind,status,attempts,next_attempt,delivered,last_error,http_status FROM notifications ORDER BY created DESC,rowid DESC LIMIT 50").map_err(|_| Error::Unavailable)?;
            let rows = statement.query_map([], |r| {
                let last_error:String=r.get(8)?;
                let allowed = last_error.is_empty() || last_error == "通知配置已变更" || last_error == "已有更新的故障状态"
                    || last_error == "连接失败、超时、证书不受信任或目标不是公网地址"
                    || last_error.strip_prefix("接收端未返回成功状态（HTTP ").and_then(|value| value.strip_suffix('）'))
                        .filter(|value| value.len() == 3 && value.bytes().all(|c| c.is_ascii_digit()))
                        .and_then(|value| value.parse::<u16>().ok()).is_some_and(|code| (100..=599).contains(&code));
                Ok(json!({"id":r.get::<_,String>(0)?,"created":r.get::<_,i64>(1)?,"service":r.get::<_,String>(2)?,"kind":r.get::<_,String>(3)?,"status":r.get::<_,String>(4)?,"attempts":r.get::<_,i64>(5)?,"next_attempt":r.get::<_,i64>(6)?,"delivered":r.get::<_,i64>(7)?,"last_error":if allowed {last_error.as_str()} else {"通知投递失败"},"http_status":r.get::<_,i64>(9)?}))
            }).map_err(|_| Error::Unavailable)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| Error::Unavailable)?
        };
        tx.commit().map_err(|_| Error::Unavailable)?;
        let url = decrypt(self.key.as_ref(), "url", &url)?;
        let bearer = decrypt(self.key.as_ref(), "bearer", &bearer)?;
        let signing = decrypt(self.key.as_ref(), "signing", &signing)?;
        let destination = if url.is_empty() {
            String::new()
        } else {
            webhook::validate_url(&url).map_err(|_| Error::Unavailable)?
        };
        Ok(
            json!({"enabled":enabled != 0,"configured":!url.is_empty(),"destination":destination,
            "has_bearer":!bearer.is_empty(),"has_signing_secret":!signing.is_empty(),
            "failures":failures,"recoveries":recoveries,"alarms":alarms,"deliveries":deliveries}),
        )
    }

    /// A crash after successful HTTP delivery may cause the same ID to be sent
    /// again. A changed generation or superseded event cannot be committed.
    pub fn next(&mut self, now: i64) -> Result<Option<Pending>> {
        if now < 0 {
            return Err(Error::Invalid);
        }
        let tx = self.db.transaction().map_err(|_| Error::Unavailable)?;
        let (enabled, url, bearer, signing, generation): (i64, String, String, String, String) = tx
            .query_row(
                "SELECT enabled,url,bearer,signing,generation FROM notification_config WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .map_err(|_| Error::Unavailable)?;
        let row:Option<(String,String,i64)>=tx.query_row(
            "SELECT id,payload,attempts FROM notifications WHERE status='pending' AND generation=? AND next_attempt<=? AND (?=1 OR kind='test') ORDER BY created,rowid LIMIT 1",
            params![generation,now,enabled],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(|_|Error::Unavailable)?;
        tx.commit().map_err(|_| Error::Unavailable)?;
        let Some((id, body, attempts)) = row else {
            return Ok(None);
        };
        if !(0..6).contains(&attempts)
            || id.len() != 32
            || !id.bytes().all(|c| c.is_ascii_hexdigit())
            || body.len() > 16_384
        {
            return Err(Error::Unavailable);
        }
        let payload: Value = serde_json::from_str(&body).map_err(|_| Error::Unavailable)?;
        if payload["id"].as_str() != Some(id.as_str()) {
            return Err(Error::Unavailable);
        }
        let config = webhook::Config {
            url: decrypt(self.key.as_ref(), "url", &url)?,
            bearer: decrypt(self.key.as_ref(), "bearer", &bearer)?,
            signing: decrypt(self.key.as_ref(), "signing", &signing)?,
        };
        webhook::validate_url(&config.url).map_err(|_| Error::Unavailable)?;
        Ok(Some(Pending {
            id,
            generation,
            attempts,
            config,
            payload,
        }))
    }
    pub fn finish(
        &mut self,
        pending: &Pending,
        delivery: &webhook::Delivery,
        now: i64,
    ) -> Result<bool> {
        if now < 0 || delivery.status > 599 {
            return Err(Error::Invalid);
        }
        let attempts = pending.attempts + 1;
        let success = delivery.error.is_none() && (200..300).contains(&delivery.status);
        let status = if success {
            "delivered"
        } else if attempts >= 6 {
            "failed"
        } else {
            "pending"
        };
        let delay = [30, 120, 600, 1800, 3600];
        let next = if status == "pending" {
            now.checked_add(delay[(attempts - 1) as usize])
                .ok_or(Error::Invalid)?
        } else {
            0
        };
        let last_error = if success {
            String::new()
        } else if !(200..300).contains(&delivery.status) && delivery.status > 0 {
            format!("接收端未返回成功状态（HTTP {}）", delivery.status)
        } else {
            "连接失败、超时、证书不受信任或目标不是公网地址".into()
        };
        let count=self.db.execute("UPDATE notifications SET status=?,attempts=?,next_attempt=?,delivered=?,last_error=?,http_status=? WHERE id=? AND generation=? AND status='pending' AND attempts=? AND EXISTS(SELECT 1 FROM notification_config WHERE id=1 AND generation=?)",
            params![status,attempts,next,if success {now}else{0},last_error,i64::from(delivery.status),pending.id,pending.generation,pending.attempts,pending.generation])
            .map_err(|_|Error::Unavailable)?;
        Ok(count == 1)
    }
}
fn collect_monitor_tx(
    tx: &Transaction<'_>,
    site: &str,
    services: &BTreeMap<String, String>,
    report: &Value,
    now: i64,
) -> Result<()> {
    if now < 0 || !report.is_object() {
        return Err(Error::Invalid);
    }
    let expected: BTreeMap<&str, &str> = services
        .iter()
        .filter(|(name, _)| crate::valid_transport(name))
        .map(|(name, label)| (name.as_str(), label.as_str()))
        .collect();
    if expected.is_empty() {
        return Err(Error::Invalid);
    }
    let updated = report["updated"].as_i64().unwrap_or(-1);
    let fresh = updated >= 0
        && matches!(report["status"].as_str(), Some("healthy" | "failed"))
        && (-60..=180).contains(&now.saturating_sub(updated));
    let mut checks = BTreeMap::new();
    if fresh {
        if let Some(rows) = report["checks"].as_array().filter(|rows| rows.len() <= 45) {
            for row in rows {
                let Some(name) = row["transport"]
                    .as_str()
                    .filter(|name| expected.contains_key(name))
                else {
                    continue;
                };
                let Some(state) = row["status"]
                    .as_str()
                    .filter(|value| matches!(*value, "healthy" | "failed"))
                else {
                    continue;
                };
                if checks.insert(name, state).is_some() {
                    return Err(Error::Invalid);
                }
            }
        }
    }
    observe_tx(
        tx,
        site,
        "probe",
        services.get("probe").ok_or(Error::Invalid)?,
        checks.len() != expected.len(),
        now / 60,
        now,
    )?;
    for (service, label) in expected {
        if let Some(state) = checks.get(service) {
            observe_tx(tx, site, service, label, *state != "healthy", updated, now)?;
        } else {
            tx.execute(
                "UPDATE alarm_state SET bad=0,good=0 WHERE service=?",
                [service],
            )
            .map_err(|_| Error::Unavailable)?;
        }
    }
    Ok(())
}
fn observe_tx(
    tx: &Transaction<'_>,
    site: &str,
    service: &str,
    label: &str,
    failed: bool,
    sample: i64,
    now: i64,
) -> Result<Option<alarm::Transition>> {
    let (failure, recovery): (i64, i64) = tx
        .query_row(
            "SELECT failures,recoveries FROM notification_config WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|_| Error::Unavailable)?;
    let (failure, recovery) = if service == "backup" {
        (1, 1)
    } else {
        (failure, recovery)
    };
    tx.execute(
        "INSERT OR IGNORE INTO alarm_state(service) VALUES(?)",
        [service],
    )
    .map_err(|_| Error::Unavailable)?;
    let state = tx
        .query_row(
            "SELECT bad,good,firing,since,last_sample,last_seen FROM alarm_state WHERE service=?",
            [service],
            |r| {
                Ok(alarm::State {
                    bad: r.get(0)?,
                    good: r.get(1)?,
                    firing: r.get::<_, i64>(2)? != 0,
                    since: r.get(3)?,
                    last_sample: r.get(4)?,
                    last_seen: r.get(5)?,
                })
            },
        )
        .map_err(|_| Error::Unavailable)?;
    let observed = alarm::observe(state, failed, sample, now, failure, recovery)?;
    if observed.fresh {
        let s = observed.state;
        tx.execute("UPDATE alarm_state SET bad=?,good=?,firing=?,since=?,last_sample=?,last_seen=? WHERE service=?",
            params![s.bad,s.good,i64::from(s.firing),s.since,s.last_sample,s.last_seen,service]).map_err(|_|Error::Unavailable)?;
        if let Some(transition) = observed.transition {
            let (kind, started, action) = match transition {
                alarm::Transition::Fault { started } => ("fault", started, "fault_detected"),
                alarm::Transition::Recovery { started } => ("recovery", started, "fault_recovered"),
            };
            queue(tx, site, service, label, kind, now, started)?;
            tx.execute(
                "INSERT INTO events(ts,action,detail) VALUES(?,?,?)",
                params![now, action, label],
            )
            .map_err(|_| Error::Unavailable)?;
            tx.execute(
                "DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM events)",
                [],
            )
            .map_err(|_| Error::Unavailable)?;
        }
    }
    Ok(observed.transition)
}
fn decrypt(key: &[u8], field: &str, value: &str) -> Result<Zeroizing<String>> {
    if value.is_empty() {
        return Ok(Zeroizing::new(String::new()));
    }
    if value.len() > 16_384 {
        return Err(Error::Unavailable);
    }
    let bytes = STANDARD.decode(value).map_err(|_| Error::Unavailable)?;
    let context = format!("xcli:webhook:{field}:v1");
    let plain = open_xgb1(&bytes, key, context.as_bytes()).map_err(|_| Error::Unavailable)?;
    Ok(Zeroizing::new(
        std::str::from_utf8(&plain)
            .map_err(|_| Error::Unavailable)?
            .to_owned(),
    ))
}
fn queue(
    tx: &Transaction<'_>,
    site: &str,
    service: &str,
    label: &str,
    kind: &str,
    now: i64,
    started: i64,
) -> Result<Option<String>> {
    let (enabled, url, generation): (i64, String, String) = tx
        .query_row(
            "SELECT enabled,url,generation FROM notification_config WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(|_| Error::Unavailable)?;
    if (enabled != 1 && kind != "test") || url.is_empty() {
        return Ok(None);
    }
    let id = Uuid::new_v4().simple().to_string();
    let title = if kind == "test" {
        "xcli 测试通知".to_owned()
    } else if kind == "fault" {
        format!("{label}持续异常")
    } else {
        format!("{label}已恢复")
    };
    let message = if kind == "test" {
        "通知通道测试，不代表节点发生故障。"
    } else if kind == "recovery" {
        "已达到连续恢复阈值。"
    } else {
        match service {
            "probe" => "探测结果缺失或已过期，当前无法判断节点可用性。",
            "backup" => "自动备份失败或未在预期时间完成，请查看面板备份状态。",
            "core" => "管理接口持续不可用，请检查核心和统计服务。",
            _ => "公网入口探测连续失败，请检查面板中的 HTTPS 和 UDP DNS 自检结果。",
        }
    };
    let payload=json!({"schema":1,"id":id,"site":site,"event":kind,"service":service,"title":title,
        "message":message,"time":now,"started":started,"duration_seconds":now.saturating_sub(started)}).to_string();
    if kind != "test" {
        tx.execute("UPDATE notifications SET status='superseded',last_error='已有更新的故障状态' WHERE service=? AND status='pending'",[service]).map_err(|_|Error::Unavailable)?;
    }
    tx.execute("INSERT INTO notifications(id,created,service,kind,payload,generation,next_attempt) VALUES(?,?,?,?,?,?,?)",
        params![id,now,service,kind,payload,generation,now]).map_err(|_|Error::Unavailable)?;
    Ok(Some(id))
}
