//! Experimental, partial management API. No production installer or deployment.
use axum::body::Body;
use axum::extract::{
    rejection::JsonRejection, ConnectInfo, DefaultBodyLimit, Path as UrlPath, Query, State,
};
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use xcli_panel_auth::{AdminAuth, AuthError, ConfirmedError, PasswordChange, Reauthentication};
use xcli_panel_backup::{BackupError, BackupStore};
use xcli_panel_controller::{
    checkpoint_before_restart, poll, validate_tags, Core, Outcome as CoreOutcome, SqliteStore, User,
};
use xcli_panel_import::{
    publisher::{audit::SqliteAuditor as ImportAuditor, PublishError, Publisher},
    report::ReportChannel as ImportReport,
};
use xcli_panel_nodes::{ManageError, NodeSync, SyncError};
use xcli_panel_operations::{
    notifications::{BackupObservation, ConfigureError, EnqueueError, Notifications, Pending},
    sender::Sender as WebhookSender,
    webhook::Delivery,
    Error as HistoryError, History,
};
use xcli_panel_rules::{RuleEditor, RuleStore, RuleStoreError};
use xcli_panel_subscription::{StoreError as SubscriptionStoreError, SubscriptionStore};
use xcli_panel_users::{Repository, StoreError};
use xcli_panel_webshare::{
    audit::SqliteAuditor, Control as WebshareControl, Error as WebshareError,
};
use xcli_panel_xray::ManagedCore;
use zeroize::{Zeroize, Zeroizing};
mod diagnostics;
mod settings;

#[derive(Clone)]
struct App {
    database: PathBuf,
    auth: Arc<Mutex<AdminAuth>>,
    users: Arc<Mutex<Repository>>,
    nodes: Arc<Mutex<NodeSync>>,
    subscription: Option<Arc<Mutex<SubscriptionStore>>>,
    rules: Option<Arc<Mutex<RuleStore>>>,
    rule_editor: Option<Arc<Mutex<RuleEditor>>>,
    backups: Option<Arc<Mutex<BackupStore>>>,
    webshare: Option<Arc<Mutex<WebshareState>>>,
    monitor: Option<MonitorView>,
    import_report: Option<Arc<ImportReport>>,
    import_preview: Option<Arc<Mutex<ImportPreview>>>,
    import_apply: bool,
    history: Arc<Mutex<History>>,
    notifications: Option<Arc<Mutex<Notifications>>>,
    notification_delivery_active: Arc<AtomicBool>,
    security_domain: Option<String>,
    shadow_dns: Option<String>,
    core: Option<CoreOptions>,
    core_health: Option<Arc<Mutex<CoreHealth>>>,
    host: Arc<Mutex<HostHealth>>,
    mutation: Arc<Mutex<()>>,
    origin: String,
    start: Instant,
}
struct WebshareState {
    control: WebshareControl,
    audit: SqliteAuditor,
}
struct ImportPreview {
    publisher: Publisher,
    audit: ImportAuditor,
    key: Zeroizing<[u8; 32]>,
    existing_exits: usize,
}
#[derive(Clone)]
struct MonitorView {
    report: PathBuf,
    expected: Vec<String>,
}

fn error(status: StatusCode, detail: &'static str) -> Response {
    (status, Json(json!({ "detail": detail }))).into_response()
}
fn auth_error(value: AuthError) -> Response {
    match value {
        AuthError::InvalidInput => error(StatusCode::UNPROCESSABLE_ENTITY, "请求格式不正确"),
        AuthError::InvalidCredentials => {
            error(StatusCode::UNAUTHORIZED, "账号、密码或二次验证码错误")
        }
        AuthError::RateLimited => error(StatusCode::TOO_MANY_REQUESTS, "尝试过于频繁，请稍后重试"),
        AuthError::Unauthorized => error(StatusCode::UNAUTHORIZED, "请先登录"),
        AuthError::Csrf => error(StatusCode::FORBIDDEN, "请求校验失败，请刷新页面"),
        AuthError::Conflict => error(StatusCode::CONFLICT, "当前安全状态不允许此操作"),
        AuthError::Unavailable => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "服务暂时不可用，请稍后重试",
        ),
    }
}
fn now() -> Result<i64, AuthError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError::Unavailable)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| AuthError::Unavailable)
}
fn cookie(headers: &HeaderMap) -> String {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .map(str::trim)
        .find_map(|item| item.strip_prefix("xg_session="))
        .unwrap_or("")
        .to_owned()
}
fn same_origin(headers: &HeaderMap, origin: &str) -> bool {
    headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) == Some(origin)
}
fn client_ip(headers: &HeaderMap, peer: SocketAddr) -> String {
    if peer.ip().is_loopback() {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<IpAddr>().ok())
        {
            return ip.to_string();
        }
    }
    peer.ip().to_string()
}
async fn secure_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let h = response.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::CONTENT_SECURITY_POLICY,HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"));
    response
}
async fn health() -> Json<serde_json::Value> {
    Json(json!({"status":"ok"}))
}

// Used only on the loopback Rust service by a local service supervisor. The
// Node gateway does not expose this path, and it returns no user information.
async fn internal_ready(State(app): State<App>) -> StatusCode {
    let ready = app
        .core_health
        .as_ref()
        .and_then(|health| health.lock().ok())
        .is_some_and(|health| health.status()["state"] == "ready");
    if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginInput {
    username: String,
    password: String,
    #[serde(default)]
    code: String,
}
impl Drop for LoginInput {
    fn drop(&mut self) {
        self.password.zeroize();
        self.code.zeroize();
    }
}

async fn login(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    input: Result<Json<LoginInput>, JsonRejection>,
) -> Response {
    if !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    let Json(input) = match input {
        Ok(value) => value,
        Err(value) if value.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return error(StatusCode::PAYLOAD_TOO_LARGE, "请求过大")
        }
        Err(_) => return error(StatusCode::UNPROCESSABLE_ENTITY, "请求格式不正确"),
    };
    let ip = client_ip(&headers, peer);
    let start = app.start;
    let auth = app.auth.clone();
    let result = tokio::task::spawn_blocking(move || match auth.lock() {
        Ok(mut service) => service.login(
            &input.username,
            &input.password,
            &input.code,
            &ip,
            now()?,
            start.elapsed(),
        ),
        Err(_) => Err(AuthError::Unavailable),
    })
    .await;
    match result {
        Ok(Ok(value)) => {
            let mut response = Json(json!({"username":"admin","csrf":value.csrf})).into_response();
            let text = format!(
                "xg_session={}; HttpOnly; Max-Age=28800; Path=/; SameSite=Strict; Secure",
                value.cookie
            );
            if let Ok(cookie) = HeaderValue::from_str(&text) {
                response.headers_mut().insert(header::SET_COOKIE, cookie);
                response
            } else {
                auth_error(AuthError::Unavailable)
            }
        }
        Ok(Err(error)) => auth_error(error),
        Err(_) => auth_error(AuthError::Unavailable),
    }
}
async fn session(State(app): State<App>, headers: HeaderMap) -> Response {
    let cookie = cookie(&headers);
    let auth = app.auth.clone();
    match tokio::task::spawn_blocking(move || match auth.lock() {
        Ok(service) => service.session(&cookie, None, now()?),
        Err(_) => Err(AuthError::Unavailable),
    })
    .await
    {
        Ok(Ok(value)) => Json(json!({"username":"admin","csrf":value.csrf})).into_response(),
        Ok(Err(error)) => auth_error(error),
        Err(_) => auth_error(AuthError::Unavailable),
    }
}
async fn monitor_status(State(app): State<App>, headers: HeaderMap) -> Response {
    let token = cookie(&headers);
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app.mutation.lock().map_err(|_| AuthError::Unavailable)?;
        let auth = app.auth.lock().map_err(|_| AuthError::Unavailable)?;
        let timestamp = now()?;
        auth.session(&token, None, timestamp)?;
        Ok::<_, AuthError>(app.monitor.as_ref().map_or_else(
            xcli_panel_monitor::status::unavailable,
            |monitor| {
                xcli_panel_monitor::status::read(&monitor.report, &monitor.expected, timestamp)
            },
        ))
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(error)) => auth_error(error),
        Err(_) => auth_error(AuthError::Unavailable),
    }
}
async fn host_status(State(app): State<App>, headers: HeaderMap) -> Response {
    let token = Zeroizing::new(cookie(&headers));
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app.mutation.lock().map_err(|_| AuthError::Unavailable)?;
        let auth = app.auth.lock().map_err(|_| AuthError::Unavailable)?;
        auth.session(&token, None, now()?)?;
        Ok::<_, AuthError>(
            app.host
                .lock()
                .map_err(|_| AuthError::Unavailable)?
                .snapshot(),
        )
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(value)) => auth_error(value),
        Err(_) => auth_error(AuthError::Unavailable),
    }
}

async fn core_sync_status(State(app): State<App>, headers: HeaderMap) -> Response {
    let token = Zeroizing::new(cookie(&headers));
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app.mutation.lock().map_err(|_| AuthError::Unavailable)?;
        let auth = app.auth.lock().map_err(|_| AuthError::Unavailable)?;
        auth.session(&token, None, now()?)?;
        match &app.core_health {
            Some(health) => {
                Ok::<_, AuthError>(health.lock().map_err(|_| AuthError::Unavailable)?.status())
            }
            None => Ok(json!({"scope":"local", "state":"unavailable"})),
        }
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(value)) => auth_error(value),
        Err(_) => auth_error(AuthError::Unavailable),
    }
}

async fn import_status(State(app): State<App>, headers: HeaderMap) -> Response {
    let token = Zeroizing::new(cookie(&headers));
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app.mutation.lock().map_err(|_| AuthError::Unavailable)?;
        let auth = app.auth.lock().map_err(|_| AuthError::Unavailable)?;
        let timestamp = now()?;
        auth.session(&token, None, timestamp)?;
        let mut report = app
            .import_report
            .as_ref()
            .and_then(|report| report.read(timestamp).ok())
            .unwrap_or_else(|| json!({"status":"unavailable"}));
        report["apply_enabled"] = json!(app.import_apply);
        report["items"] = json!(app
            .import_report
            .as_ref()
            .and_then(|channel| channel.read_catalog().ok()));
        Ok::<_, AuthError>(report)
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(value)) => auth_error(value),
        Err(_) => auth_error(AuthError::Unavailable),
    }
}
enum ImportRequestError {
    Auth(AuthError),
    Invalid,
    Busy,
    Disabled,
    Unavailable,
}
async fn request_import_preview(
    State(app): State<App>,
    headers: HeaderMap,
    input: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = user_body(input).map(SensitiveJson);
    if !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    let input = match input {
        Ok(value) => value,
        Err(status) => return user_body_error(status),
    };
    let token = Zeroizing::new(cookie(&headers));
    let csrf = Zeroizing::new(
        headers
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned(),
    );
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app
            .mutation
            .lock()
            .map_err(|_| ImportRequestError::Unavailable)?;
        let auth = app
            .auth
            .lock()
            .map_err(|_| ImportRequestError::Unavailable)?;
        let stamp = now().map_err(ImportRequestError::Auth)?;
        auth.session(&token, Some(&csrf), stamp)
            .map_err(ImportRequestError::Auth)?;
        if input.0["action"] == "apply" && !app.import_apply {
            return Err(ImportRequestError::Disabled);
        }
        let report = app
            .import_report
            .as_ref()
            .ok_or(ImportRequestError::Unavailable)?
            .read(stamp)
            .map_err(|_| ImportRequestError::Unavailable)?;
        let mut state = app
            .import_preview
            .as_ref()
            .ok_or(ImportRequestError::Unavailable)?
            .lock()
            .map_err(|_| ImportRequestError::Unavailable)?;
        let ImportPreview {
            publisher,
            audit,
            key,
            existing_exits,
        } = &mut *state;
        let prepared = xcli_panel_import::request::prepare(&input.0, stamp, key, *existing_exits)
            .map_err(|_| ImportRequestError::Invalid)?;
        let submitted = if app.import_apply {
            publisher.submit(&prepared, &report, stamp, audit)
        } else {
            publisher.submit_preview_only(&prepared, &report, stamp, audit)
        };
        submitted.map_err(|error| match error {
            PublishError::Invalid => ImportRequestError::Invalid,
            PublishError::Busy => ImportRequestError::Busy,
            PublishError::Unavailable | PublishError::Expired => ImportRequestError::Unavailable,
        })?;
        Ok::<_, ImportRequestError>(json!({"id":prepared.id(),"pending":true}))
    })
    .await;
    match result {
        Ok(Ok(value)) => (StatusCode::ACCEPTED, Json(value)).into_response(),
        Ok(Err(ImportRequestError::Auth(value))) => auth_error(value),
        Ok(Err(ImportRequestError::Invalid)) => {
            error(StatusCode::UNPROCESSABLE_ENTITY, "导入请求格式不正确")
        }
        Ok(Err(ImportRequestError::Busy)) => error(StatusCode::CONFLICT, "已有导入任务正在处理"),
        Ok(Err(ImportRequestError::Disabled)) => {
            error(StatusCode::CONFLICT, "应用代理变更尚未启用")
        }
        _ => auth_error(AuthError::Unavailable),
    }
}
#[derive(Deserialize)]
struct HistoryQuery {
    range: Option<String>,
}
async fn history(
    State(app): State<App>,
    headers: HeaderMap,
    Query(query): Query<HistoryQuery>,
) -> Response {
    let token = cookie(&headers);
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app.mutation.lock().map_err(|_| AuthError::Unavailable)?;
        let auth = app.auth.lock().map_err(|_| AuthError::Unavailable)?;
        let timestamp = now()?;
        auth.session(&token, None, timestamp)?;
        let mut history = app.history.lock().map_err(|_| AuthError::Unavailable)?;
        Ok::<_, AuthError>(history.query(query.range.as_deref().unwrap_or("24h"), timestamp))
    })
    .await;
    match result {
        Ok(Ok(Ok(value))) => Json(value).into_response(),
        Ok(Ok(Err(HistoryError::Invalid))) => error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "请选择 1h、24h、7d 或 30d",
        ),
        Ok(Err(error)) => auth_error(error),
        _ => auth_error(AuthError::Unavailable),
    }
}
async fn notifications_status(State(app): State<App>, headers: HeaderMap) -> Response {
    let token = cookie(&headers);
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app.mutation.lock().map_err(|_| AuthError::Unavailable)?;
        let auth = app.auth.lock().map_err(|_| AuthError::Unavailable)?;
        auth.session(&token, None, now()?)?;
        let mut notifications = app
            .notifications
            .as_ref()
            .ok_or(AuthError::Unavailable)?
            .lock()
            .map_err(|_| AuthError::Unavailable)?;
        let mut value = notifications.status().map_err(|_| AuthError::Unavailable)?;
        value["delivery_active"] = json!(app.notification_delivery_active.load(Ordering::Acquire));
        Ok::<_, AuthError>(value)
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(error)) => auth_error(error),
        Err(_) => auth_error(AuthError::Unavailable),
    }
}
async fn configure_notifications(
    State(app): State<App>,
    headers: HeaderMap,
    input: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    if !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    let input = match user_body(input) {
        Ok(value) => SensitiveJson(value),
        Err(status) => return user_body_error(status),
    };
    if !input.0.is_object() {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "请求必须是 JSON 对象");
    }
    let Some(password) = input
        .0
        .get("current_password")
        .map_or(Some(""), serde_json::Value::as_str)
    else {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "请求格式不正确");
    };
    let Some(code) = input
        .0
        .get("code")
        .map_or(Some(""), serde_json::Value::as_str)
    else {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "请求格式不正确");
    };
    if password.chars().count() > 256 || code.chars().count() > 128 {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "请求格式不正确");
    }
    let cookie = Zeroizing::new(cookie(&headers));
    let csrf = Zeroizing::new(
        headers
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned(),
    );
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app
            .mutation
            .lock()
            .map_err(|_| ConfirmedError::Auth(AuthError::Unavailable))?;
        let mut auth = app
            .auth
            .lock()
            .map_err(|_| ConfirmedError::Auth(AuthError::Unavailable))?;
        let notifications = app
            .notifications
            .as_ref()
            .ok_or(ConfirmedError::Auth(AuthError::Unavailable))?
            .lock()
            .map_err(|_| ConfirmedError::Auth(AuthError::Unavailable))?;
        let password = input
            .0
            .get("current_password")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let code = input
            .0
            .get("code")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let timestamp = now().map_err(ConfirmedError::Auth)?;
        auth.confirmed(
            &cookie,
            &csrf,
            Reauthentication { password, code },
            timestamp,
            app.start.elapsed(),
            |tx| notifications.configure(tx, &input.0, timestamp),
        )
    })
    .await;
    match result {
        Ok(Ok(())) => Json(json!({"ok":true})).into_response(),
        Ok(Err(ConfirmedError::Auth(AuthError::InvalidCredentials))) => {
            error(StatusCode::FORBIDDEN, "密码或二次验证码错误")
        }
        Ok(Err(ConfirmedError::Auth(value))) => auth_error(value),
        Ok(Err(ConfirmedError::Operation(ConfigureError::Invalid(detail)))) => {
            error(StatusCode::UNPROCESSABLE_ENTITY, detail)
        }
        _ => auth_error(AuthError::Unavailable),
    }
}
async fn test_notification(State(app): State<App>, headers: HeaderMap) -> Response {
    if !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    let token = Zeroizing::new(cookie(&headers));
    let csrf = Zeroizing::new(
        headers
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned(),
    );
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app.mutation.lock().map_err(|_| AuthError::Unavailable)?;
        let auth = app.auth.lock().map_err(|_| AuthError::Unavailable)?;
        let timestamp = now()?;
        auth.session(&token, Some(&csrf), timestamp)?;
        if !app.notification_delivery_active.load(Ordering::Acquire) {
            return Ok(None);
        }
        let mut notifications = app
            .notifications
            .as_ref()
            .ok_or(AuthError::Unavailable)?
            .lock()
            .map_err(|_| AuthError::Unavailable)?;
        Ok::<_, AuthError>(Some(notifications.enqueue_test(timestamp)))
    })
    .await;
    match result {
        Ok(Ok(Some(Ok(id)))) => Json(json!({"id":id,"status":"pending"})).into_response(),
        Ok(Ok(Some(Err(EnqueueError::NotConfigured)))) => {
            error(StatusCode::CONFLICT, "请先保存 Webhook 地址")
        }
        Ok(Ok(Some(Err(EnqueueError::RateLimited)))) => {
            error(StatusCode::TOO_MANY_REQUESTS, "请等待 30 秒后再发送测试")
        }
        Ok(Ok(None)) => error(StatusCode::SERVICE_UNAVAILABLE, "通知投递尚未启用"),
        Ok(Err(value)) => auth_error(value),
        _ => auth_error(AuthError::Unavailable),
    }
}
async fn logout(State(app): State<App>, headers: HeaderMap) -> Response {
    if !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    let cookie = cookie(&headers);
    let csrf = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let auth = app.auth.clone();
    match tokio::task::spawn_blocking(move || match auth.lock() {
        Ok(mut service) => service.logout(&cookie, &csrf, now()?),
        Err(_) => Err(AuthError::Unavailable),
    })
    .await
    {
        Ok(Ok(())) => {
            let mut response = Json(json!({"ok":true})).into_response();
            response.headers_mut().insert(
                header::SET_COOKIE,
                HeaderValue::from_static(
                    "xg_session=; HttpOnly; Max-Age=0; Path=/; SameSite=Strict; Secure",
                ),
            );
            response
        }
        Ok(Err(error)) => auth_error(error),
        Err(_) => auth_error(AuthError::Unavailable),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordInput {
    current_password: String,
    new_password: String,
    #[serde(default)]
    code: String,
}
impl Drop for PasswordInput {
    fn drop(&mut self) {
        self.current_password.zeroize();
        self.new_password.zeroize();
        self.code.zeroize();
    }
}
async fn change_password(
    State(app): State<App>,
    headers: HeaderMap,
    input: Result<Json<PasswordInput>, JsonRejection>,
) -> Response {
    if !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    let Json(input) = match input {
        Ok(value) => value,
        Err(value) if value.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return error(StatusCode::PAYLOAD_TOO_LARGE, "请求过大")
        }
        Err(_) => return error(StatusCode::UNPROCESSABLE_ENTITY, "请求格式不正确"),
    };
    let cookie = Zeroizing::new(cookie(&headers));
    let csrf = Zeroizing::new(
        headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned(),
    );
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app.mutation.lock().map_err(|_| AuthError::Unavailable)?;
        let mut auth = app.auth.lock().map_err(|_| AuthError::Unavailable)?;
        auth.change_password(
            &cookie,
            &csrf,
            PasswordChange {
                current: &input.current_password,
                next: &input.new_password,
                code: &input.code,
            },
            now()?,
            app.start.elapsed(),
        )
    })
    .await;
    match result {
        Ok(Ok(())) => {
            let mut response = Json(json!({"ok":true})).into_response();
            response.headers_mut().insert(
                header::SET_COOKIE,
                HeaderValue::from_static(
                    "xg_session=; HttpOnly; Max-Age=0; Path=/; SameSite=Strict; Secure",
                ),
            );
            response
        }
        Ok(Err(AuthError::InvalidCredentials)) => {
            error(StatusCode::FORBIDDEN, "密码或二次验证码错误")
        }
        Ok(Err(error)) => auth_error(error),
        Err(_) => auth_error(AuthError::Unavailable),
    }
}

async fn security_status(State(app): State<App>, headers: HeaderMap) -> Response {
    let cookie = Zeroizing::new(cookie(&headers));
    let result = tokio::task::spawn_blocking(move || {
        let auth = app.auth.lock().map_err(|_| AuthError::Unavailable)?;
        auth.security_status(&cookie, now()?)
    })
    .await;
    match result {
        Ok(Ok(value)) => {
            Json(json!({"enabled":value.enabled,"recovery_remaining":value.recovery_remaining}))
                .into_response()
        }
        Ok(Err(error)) => auth_error(error),
        Err(_) => auth_error(AuthError::Unavailable),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityInput {
    current_password: String,
    #[serde(default)]
    code: String,
}
impl Drop for SecurityInput {
    fn drop(&mut self) {
        self.current_password.zeroize();
        self.code.zeroize();
    }
}
enum SecurityAction {
    Setup,
    Enable,
    Disable,
    Recovery,
}
fn quote_uri(value: &str) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            result.push(byte as char);
        } else {
            result.push_str(&format!("%{byte:02X}"));
        }
    }
    result
}
fn qr_png(value: &str) -> Result<Zeroizing<Vec<u8>>, AuthError> {
    if value.len() > 4096 {
        return Err(AuthError::InvalidInput);
    }
    let qr = qrcode::QrCode::with_error_correction_level(value.as_bytes(), qrcode::EcLevel::M)
        .map_err(|_| AuthError::Unavailable)?;
    let width = (qr.width() + 8)
        .checked_mul(10)
        .ok_or(AuthError::Unavailable)?;
    let mut pixels = Zeroizing::new(vec![
        255u8;
        width
            .checked_mul(width)
            .ok_or(AuthError::Unavailable)?
    ]);
    for y in 0..qr.width() {
        for x in 0..qr.width() {
            if qr[(x, y)] == qrcode::Color::Dark {
                for dy in 0..10 {
                    pixels[((y + 4) * 10 + dy) * width + (x + 4) * 10..][..10].fill(0);
                }
            }
        }
    }
    let mut output = Zeroizing::new(Vec::new());
    {
        let mut encoder = png::Encoder::new(&mut *output, width as u32, width as u32);
        encoder.set_color(png::ColorType::Grayscale);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().map_err(|_| AuthError::Unavailable)?;
        writer
            .write_image_data(&pixels)
            .map_err(|_| AuthError::Unavailable)?;
    }
    Ok(output)
}
async fn security_mutation(
    app: App,
    headers: HeaderMap,
    input: Result<Json<SecurityInput>, JsonRejection>,
    action: SecurityAction,
) -> Response {
    if !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    let Json(input) = match input {
        Ok(value) => value,
        Err(value) if value.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return error(StatusCode::PAYLOAD_TOO_LARGE, "请求过大")
        }
        Err(_) => return error(StatusCode::UNPROCESSABLE_ENTITY, "请求格式不正确"),
    };
    let cookie = Zeroizing::new(cookie(&headers));
    let csrf = Zeroizing::new(
        headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned(),
    );
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app.mutation.lock().map_err(|_| AuthError::Unavailable)?;
        let mut auth = app.auth.lock().map_err(|_| AuthError::Unavailable)?;
        let confirmation = Reauthentication { password: &input.current_password, code: &input.code };
        let stamp = now()?;
        let elapsed = app.start.elapsed();
        match action {
            SecurityAction::Setup => {
                let domain = app.security_domain.as_ref().ok_or(AuthError::Unavailable)?;
                let setup = auth.setup_totp(&cookie, &csrf, confirmation, stamp, elapsed)?;
                let uri = Zeroizing::new(format!("otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30", quote_uri(&format!("{domain}:admin")), setup.secret.as_str(), quote_uri(domain)));
                let qr = qr_png(&uri)?;
                Ok(json!({"secret":setup.secret.as_str(),"qr":format!("data:image/png;base64,{}", STANDARD.encode(qr.as_slice())),"expires":setup.expires}))
            }
            SecurityAction::Enable => { let codes = auth.enable_totp(&cookie, &csrf, confirmation, stamp, elapsed)?; Ok(json!({"recovery_codes":codes.as_slice()})) }
            SecurityAction::Disable => { auth.disable_totp(&cookie, &csrf, confirmation, stamp, elapsed)?; Ok(json!({"ok":true})) }
            SecurityAction::Recovery => { let codes = auth.regenerate_recovery(&cookie, &csrf, confirmation, stamp, elapsed)?; Ok(json!({"recovery_codes":codes.as_slice()})) }
        }
    }).await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(AuthError::InvalidCredentials)) => {
            error(StatusCode::FORBIDDEN, "密码或二次验证码错误")
        }
        Ok(Err(value)) => auth_error(value),
        Err(_) => auth_error(AuthError::Unavailable),
    }
}
async fn setup_totp(
    State(app): State<App>,
    headers: HeaderMap,
    input: Result<Json<SecurityInput>, JsonRejection>,
) -> Response {
    security_mutation(app, headers, input, SecurityAction::Setup).await
}
async fn enable_totp(
    State(app): State<App>,
    headers: HeaderMap,
    input: Result<Json<SecurityInput>, JsonRejection>,
) -> Response {
    security_mutation(app, headers, input, SecurityAction::Enable).await
}
async fn disable_totp(
    State(app): State<App>,
    headers: HeaderMap,
    input: Result<Json<SecurityInput>, JsonRejection>,
) -> Response {
    security_mutation(app, headers, input, SecurityAction::Disable).await
}
async fn regenerate_recovery(
    State(app): State<App>,
    headers: HeaderMap,
    input: Result<Json<SecurityInput>, JsonRejection>,
) -> Response {
    security_mutation(app, headers, input, SecurityAction::Recovery).await
}

enum UserAction {
    Create(serde_json::Value),
    Update(String, serde_json::Value),
    Delete(String),
    Rotate(String),
    ResetTraffic(String),
}
enum MutationError {
    Auth(AuthError),
    Store(StoreError),
}
fn mutation_error(value: MutationError) -> Response {
    match value {
        MutationError::Auth(value) => auth_error(value),
        MutationError::Store(StoreError::InvalidInput(_)) => {
            error(StatusCode::UNPROCESSABLE_ENTITY, "请求格式不正确")
        }
        MutationError::Store(StoreError::NotFound) => error(StatusCode::NOT_FOUND, "用户不存在"),
        MutationError::Store(StoreError::Limit) => {
            error(StatusCode::CONFLICT, "最多支持 500 位用户")
        }
        MutationError::Store(StoreError::RemoteHistory) => error(
            StatusCode::CONFLICT,
            "该用户曾被授权使用独立节点，无法安全清零：离线节点可能仍有未上报流量",
        ),
        MutationError::Store(StoreError::Unavailable) => auth_error(AuthError::Unavailable),
    }
}

fn reset_user_traffic(
    users: &mut Repository,
    options: Option<&CoreOptions>,
    id: &str,
    timestamp: i64,
) -> Result<(), StoreError> {
    let options = options.ok_or(StoreError::Unavailable)?;
    users.ensure_resettable(id)?;
    let hy2 = options
        .tags
        .iter()
        .filter(|tag| tag.ends_with("-hy2"))
        .cloned()
        .collect();
    let mut core = ManagedCore::new(&options.api, &options.binary, &options.pid_file, hy2)
        .map_err(|_| StoreError::Unavailable)?;
    let generation = core.generation().map_err(|_| StoreError::Unavailable)?;
    let counters = core.counters().map_err(|_| StoreError::Unavailable)?;
    if core.generation().map_err(|_| StoreError::Unavailable)? != generation {
        return Err(StoreError::Unavailable);
    }
    users.reset_sampled(
        id,
        &generation,
        &counters,
        timestamp,
        options.interval as i64,
    )
}

async fn mutate_user(app: App, headers: HeaderMap, action: UserAction) -> Response {
    if !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    let value = match &action {
        UserAction::Create(value) | UserAction::Update(_, value) => Some(value),
        _ => None,
    };
    if value.is_some_and(|value| xcli_panel_users::validate(value).is_err()) {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "请求格式不正确");
    }
    let cookie = cookie(&headers);
    let csrf = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let auth = app.auth.clone();
    let users = app.users.clone();
    let mutation = app.mutation.clone();
    let core = app.core.clone();
    let core_health = app.core_health.clone();
    let result = tokio::task::spawn_blocking(move || {
        // Every user, node and future core mutation shares this lock.
        let _mutation = mutation
            .lock()
            .map_err(|_| MutationError::Auth(AuthError::Unavailable))?;
        // Keep the auth mutex held across the user transaction so logout or
        // another authenticated mutation cannot race this session check.
        let auth_guard = auth
            .lock()
            .map_err(|_| MutationError::Auth(AuthError::Unavailable))?;
        let timestamp = now().map_err(MutationError::Auth)?;
        auth_guard
            .session(&cookie, Some(&csrf), timestamp)
            .map_err(MutationError::Auth)?;
        let mut users = users
            .lock()
            .map_err(|_| MutationError::Store(StoreError::Unavailable))?;
        let affects_authorization = !matches!(&action, UserAction::ResetTraffic(_));
        // Reserve a revision while holding the shared mutation lock. It is
        // published only after the database transaction succeeds.
        let mut sync = if affects_authorization {
            core_health
                .as_ref()
                .map(|health| health.lock())
                .transpose()
                .map_err(|_| MutationError::Store(StoreError::Unavailable))?
        } else {
            None
        };
        let revision = match sync.as_ref() {
            Some(health) => Some(
                health
                    .desired
                    .checked_add(1)
                    .filter(|value| *value <= 9_007_199_254_740_991)
                    .ok_or(MutationError::Store(StoreError::Unavailable))?,
            ),
            None => None,
        };
        let result = match action {
            UserAction::Create(value) => users
                .create(&value, timestamp)
                .map(|id| json!({ "id": id })),
            UserAction::Update(id, value) => users
                .update(&id, &value, timestamp)
                .map(|_| json!({"ok":true})),
            UserAction::Delete(id) => users.delete(&id, timestamp).map(|_| json!({"ok":true})),
            UserAction::Rotate(id) => users.rotate(&id, timestamp).map(|_| json!({"ok":true})),
            UserAction::ResetTraffic(id) => {
                reset_user_traffic(&mut users, core.as_ref(), &id, timestamp)
                    .map(|_| json!({"ok":true}))
            }
        }
        .map_err(MutationError::Store);
        let result = result.map(|mut value| {
            if let (Some(health), Some(revision)) = (sync.as_mut(), revision) {
                health.desired = revision;
                value["local_core_sync"] = json!({"instance":health.instance, "revision":revision});
            }
            value
        });
        drop(auth_guard);
        result
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(value)) => mutation_error(value),
        Err(_) => auth_error(AuthError::Unavailable),
    }
}
fn user_body(
    input: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<serde_json::Value, StatusCode> {
    match input {
        Ok(Json(value)) => Ok(value),
        Err(value) if value.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            Err(StatusCode::PAYLOAD_TOO_LARGE)
        }
        Err(_) => Err(StatusCode::UNPROCESSABLE_ENTITY),
    }
}
fn user_body_error(status: StatusCode) -> Response {
    error(
        status,
        if status == StatusCode::PAYLOAD_TOO_LARGE {
            "请求过大"
        } else {
            "请求格式不正确"
        },
    )
}
async fn create_user(
    State(app): State<App>,
    headers: HeaderMap,
    input: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    if !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    match user_body(input) {
        Ok(value) => mutate_user(app, headers, UserAction::Create(value)).await,
        Err(status) => user_body_error(status),
    }
}
async fn update_user(
    State(app): State<App>,
    UrlPath(id): UrlPath<String>,
    headers: HeaderMap,
    input: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    if !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    match user_body(input) {
        Ok(value) => mutate_user(app, headers, UserAction::Update(id, value)).await,
        Err(status) => user_body_error(status),
    }
}
async fn delete_user(
    State(app): State<App>,
    UrlPath(id): UrlPath<String>,
    headers: HeaderMap,
) -> Response {
    mutate_user(app, headers, UserAction::Delete(id)).await
}
async fn rotate_user(
    State(app): State<App>,
    UrlPath(id): UrlPath<String>,
    headers: HeaderMap,
) -> Response {
    mutate_user(app, headers, UserAction::Rotate(id)).await
}
async fn reset_user(
    State(app): State<App>,
    UrlPath(id): UrlPath<String>,
    headers: HeaderMap,
) -> Response {
    mutate_user(app, headers, UserAction::ResetTraffic(id)).await
}
async fn list_users(State(app): State<App>, headers: HeaderMap) -> Response {
    let cookie = cookie(&headers);
    let auth = app.auth.clone();
    let users = app.users.clone();
    let mutation = app.mutation.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = mutation
            .lock()
            .map_err(|_| MutationError::Auth(AuthError::Unavailable))?;
        let auth_guard = auth
            .lock()
            .map_err(|_| MutationError::Auth(AuthError::Unavailable))?;
        let timestamp = now().map_err(MutationError::Auth)?;
        auth_guard
            .session(&cookie, None, timestamp)
            .map_err(MutationError::Auth)?;
        let users = users
            .lock()
            .map_err(|_| MutationError::Store(StoreError::Unavailable))?;
        let result = users.list(timestamp).map_err(MutationError::Store);
        drop(auth_guard);
        result
    })
    .await;
    match result {
        Ok(Ok(value)) => {
            // JSON numbers above 2^53 cannot round-trip through JavaScript.
            // This new Vue-facing endpoint exposes byte counts as decimals.
            let users: Vec<_> = value.into_iter().map(|user| json!({
                "id":user.id,"name":user.name,"enabled":user.enabled!=0,"quota":user.quota.to_string(),
                "upload":user.upload.to_string(),"download":user.download.to_string(),
                "expires":user.expires,"created":user.created,"status":user.status,
            })).collect();
            Json(json!({ "users": users })).into_response()
        }
        Ok(Err(value)) => mutation_error(value),
        Err(_) => auth_error(AuthError::Unavailable),
    }
}
async fn user_activity(State(app): State<App>, headers: HeaderMap) -> Response {
    let cookie = Zeroizing::new(cookie(&headers));
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app
            .mutation
            .lock()
            .map_err(|_| MutationError::Auth(AuthError::Unavailable))?;
        let auth = app
            .auth
            .lock()
            .map_err(|_| MutationError::Auth(AuthError::Unavailable))?;
        let timestamp = now().map_err(MutationError::Auth)?;
        auth.session(&cookie, None, timestamp)
            .map_err(MutationError::Auth)?;
        let users = app
            .users
            .lock()
            .map_err(|_| MutationError::Store(StoreError::Unavailable))?;
        users.activity(timestamp).map_err(MutationError::Store)
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(json!({"scope":"local","activity":value})).into_response(),
        Ok(Err(value)) => mutation_error(value),
        Err(_) => auth_error(AuthError::Unavailable),
    }
}
async fn recent_events(State(app): State<App>, headers: HeaderMap) -> Response {
    let cookie = Zeroizing::new(cookie(&headers));
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app
            .mutation
            .lock()
            .map_err(|_| MutationError::Auth(AuthError::Unavailable))?;
        let auth = app
            .auth
            .lock()
            .map_err(|_| MutationError::Auth(AuthError::Unavailable))?;
        auth.session(&cookie, None, now().map_err(MutationError::Auth)?)
            .map_err(MutationError::Auth)?;
        let users = app
            .users
            .lock()
            .map_err(|_| MutationError::Store(StoreError::Unavailable))?;
        users.recent_events().map_err(MutationError::Store)
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(json!({ "events": value })).into_response(),
        Ok(Err(value)) => mutation_error(value),
        Err(_) => auth_error(AuthError::Unavailable),
    }
}
enum SubscriptionError {
    Auth(AuthError),
    Store(SubscriptionStoreError),
    Rules,
    Render,
}

fn client_links_locked(app: &App, id: &str) -> Result<serde_json::Value, SubscriptionError> {
    let mut store = app
        .subscription
        .as_ref()
        .ok_or(SubscriptionError::Store(
            SubscriptionStoreError::Unavailable,
        ))?
        .lock()
        .map_err(|_| SubscriptionError::Store(SubscriptionStoreError::Unavailable))?;
    let input = store.template_input(id).map_err(SubscriptionError::Store)?;
    let mut rules = app
        .rules
        .as_ref()
        .ok_or(SubscriptionError::Rules)?
        .lock()
        .map_err(|_| SubscriptionError::Rules)?;
    let policy = rules
        .effective(&input.user_id)
        .map_err(|_| SubscriptionError::Rules)?;
    let user = xcli_panel_shadowrocket::User {
        id: input.user_id,
        name: input.name,
        uuid: input.uuid,
        token: input.token,
    };
    xcli_panel_shadowrocket::client_links(&input.settings, &user, &policy)
        .map_err(|_| SubscriptionError::Render)
}
fn subscription_error(value: SubscriptionError) -> Response {
    match value {
        SubscriptionError::Auth(value) => auth_error(value),
        SubscriptionError::Store(SubscriptionStoreError::NotFound) => {
            error(StatusCode::NOT_FOUND, "用户不存在")
        }
        SubscriptionError::Store(_) | SubscriptionError::Rules | SubscriptionError::Render => {
            auth_error(AuthError::Unavailable)
        }
    }
}
async fn user_client_links(
    State(app): State<App>,
    UrlPath(id): UrlPath<String>,
    headers: HeaderMap,
) -> Response {
    let cookie = Zeroizing::new(cookie(&headers));
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app
            .mutation
            .lock()
            .map_err(|_| SubscriptionError::Auth(AuthError::Unavailable))?;
        let auth = app
            .auth
            .lock()
            .map_err(|_| SubscriptionError::Auth(AuthError::Unavailable))?;
        auth.session(&cookie, None, now().map_err(SubscriptionError::Auth)?)
            .map_err(SubscriptionError::Auth)?;
        client_links_locked(&app, &id)
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(value)) => subscription_error(value),
        Err(_) => auth_error(AuthError::Unavailable),
    }
}
async fn user_qr(
    State(app): State<App>,
    UrlPath((id, kind)): UrlPath<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let cookie = Zeroizing::new(cookie(&headers));
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app
            .mutation
            .lock()
            .map_err(|_| SubscriptionError::Auth(AuthError::Unavailable))?;
        let auth = app
            .auth
            .lock()
            .map_err(|_| SubscriptionError::Auth(AuthError::Unavailable))?;
        auth.session(&cookie, None, now().map_err(SubscriptionError::Auth)?)
            .map_err(SubscriptionError::Auth)?;
        let link = if ["shadowrocket", "dns", "clash"].contains(&kind.as_str()) {
            let clients = client_links_locked(&app, &id)?;
            let key = if kind == "dns" { "dns_install" } else { &kind };
            clients
                .get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        } else {
            let mut store = app
                .subscription
                .as_ref()
                .ok_or(SubscriptionError::Store(
                    SubscriptionStoreError::Unavailable,
                ))?
                .lock()
                .map_err(|_| SubscriptionError::Store(SubscriptionStoreError::Unavailable))?;
            store
                .links_for_id(&id)
                .map_err(SubscriptionError::Store)?
                .into_iter()
                .find_map(|(key, value)| (key == kind).then_some(value))
        }
        .ok_or(SubscriptionError::Store(SubscriptionStoreError::NotFound))?;
        qr_png(&Zeroizing::new(link)).map_err(SubscriptionError::Auth)
    })
    .await;
    match result {
        Ok(Ok(png)) => ([(header::CONTENT_TYPE, "image/png")], png.to_vec()).into_response(),
        Ok(Err(value)) => subscription_error(value),
        Err(_) => auth_error(AuthError::Unavailable),
    }
}
async fn shadow_dns(State(app): State<App>) -> Response {
    match app.shadow_dns {
        Some(body) => ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response(),
        None => auth_error(AuthError::Unavailable),
    }
}

async fn user_links(
    State(app): State<App>,
    UrlPath(id): UrlPath<String>,
    headers: HeaderMap,
) -> Response {
    let cookie = Zeroizing::new(cookie(&headers));
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app
            .mutation
            .lock()
            .map_err(|_| SubscriptionError::Auth(AuthError::Unavailable))?;
        let auth = app
            .auth
            .lock()
            .map_err(|_| SubscriptionError::Auth(AuthError::Unavailable))?;
        auth.session(&cookie, None, now().map_err(SubscriptionError::Auth)?)
            .map_err(SubscriptionError::Auth)?;
        let store = app.subscription.as_ref().ok_or(SubscriptionError::Store(
            SubscriptionStoreError::Unavailable,
        ))?;
        let mut store = store
            .lock()
            .map_err(|_| SubscriptionError::Store(SubscriptionStoreError::Unavailable))?;
        let entries = store.links_for_id(&id).map_err(SubscriptionError::Store)?;
        Ok::<_, SubscriptionError>(
            entries
                .into_iter()
                .map(|(key, value)| (key, serde_json::Value::String(value)))
                .collect::<serde_json::Map<_, _>>(),
        )
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(SubscriptionError::Auth(value))) => auth_error(value),
        Ok(Err(SubscriptionError::Store(SubscriptionStoreError::NotFound))) => {
            error(StatusCode::NOT_FOUND, "用户不存在")
        }
        _ => auth_error(AuthError::Unavailable),
    }
}

async fn user_subscription_diagnostics(
    State(app): State<App>,
    UrlPath(id): UrlPath<String>,
    headers: HeaderMap,
) -> Response {
    let cookie = Zeroizing::new(cookie(&headers));
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app
            .mutation
            .lock()
            .map_err(|_| SubscriptionError::Auth(AuthError::Unavailable))?;
        let auth = app
            .auth
            .lock()
            .map_err(|_| SubscriptionError::Auth(AuthError::Unavailable))?;
        let timestamp = now().map_err(SubscriptionError::Auth)?;
        auth.session(&cookie, None, timestamp)
            .map_err(SubscriptionError::Auth)?;
        let mut store = app
            .subscription
            .as_ref()
            .ok_or(SubscriptionError::Store(
                SubscriptionStoreError::Unavailable,
            ))?
            .lock()
            .map_err(|_| SubscriptionError::Store(SubscriptionStoreError::Unavailable))?;
        let mut rules = app
            .rules
            .as_ref()
            .ok_or(SubscriptionError::Rules)?
            .lock()
            .map_err(|_| SubscriptionError::Rules)?;
        diagnostics::generate(&mut store, &mut rules, &id, &app.origin, timestamp)
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(value)) => subscription_error(value),
        Err(_) => auth_error(AuthError::Unavailable),
    }
}

async fn generic_subscription(State(app): State<App>, UrlPath(token): UrlPath<String>) -> Response {
    let token = Zeroizing::new(token);
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app
            .mutation
            .lock()
            .map_err(|_| SubscriptionStoreError::Unavailable)?;
        let store = app
            .subscription
            .as_ref()
            .ok_or(SubscriptionStoreError::Unavailable)?;
        let mut store = store
            .lock()
            .map_err(|_| SubscriptionStoreError::Unavailable)?;
        store.generic(
            &token,
            now().map_err(|_| SubscriptionStoreError::Unavailable)?,
        )
    })
    .await;
    match result {
        Ok(Ok((body, info))) => {
            let Ok(info) = HeaderValue::from_str(&info) else {
                return auth_error(AuthError::Unavailable);
            };
            let mut response = (
                [
                    (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"xdistribute.txt\"",
                    ),
                ],
                body,
            )
                .into_response();
            response.headers_mut().insert("subscription-userinfo", info);
            response
                .headers_mut()
                .insert("profile-update-interval", HeaderValue::from_static("6"));
            response
        }
        Ok(Err(SubscriptionStoreError::NotFound)) => error(StatusCode::NOT_FOUND, "Not found"),
        Ok(Err(SubscriptionStoreError::Inactive)) => {
            error(StatusCode::FORBIDDEN, "Subscription inactive")
        }
        _ => auth_error(AuthError::Unavailable),
    }
}

enum ClashError {
    Subscription(SubscriptionStoreError),
    Rules(RuleStoreError),
    Render(xcli_panel_rules::ApplyError),
}
async fn clash_subscription(State(app): State<App>, UrlPath(token): UrlPath<String>) -> Response {
    let token = Zeroizing::new(token);
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app
            .mutation
            .lock()
            .map_err(|_| ClashError::Subscription(SubscriptionStoreError::Unavailable))?;
        let store = app.subscription.as_ref().ok_or(ClashError::Subscription(
            SubscriptionStoreError::Unavailable,
        ))?;
        let mut store = store
            .lock()
            .map_err(|_| ClashError::Subscription(SubscriptionStoreError::Unavailable))?;
        let input = store
            .clash_input(
                &token,
                now().map_err(|_| ClashError::Subscription(SubscriptionStoreError::Unavailable))?,
            )
            .map_err(ClashError::Subscription)?;
        let rules = app
            .rules
            .as_ref()
            .ok_or(ClashError::Rules(RuleStoreError::Unavailable))?;
        let mut rules = rules
            .lock()
            .map_err(|_| ClashError::Rules(RuleStoreError::Unavailable))?;
        let policy = rules.effective(&input.user_id).map_err(ClashError::Rules)?;
        let user = xcli_panel_clash::User {
            id: input.user_id,
            uuid: input.uuid,
        };
        let config = xcli_panel_clash::build(
            &input.settings,
            &user,
            &input.remote_nodes,
            input.dynamic_enabled,
            &policy,
        )
        .map_err(ClashError::Render)?;
        let content = xcli_panel_clash::render(&config).map_err(ClashError::Render)?;
        Ok::<_, ClashError>((content, input.userinfo))
    })
    .await;
    match result {
        Ok(Ok((body, info))) => {
            let Ok(info) = HeaderValue::from_str(&info) else {
                return auth_error(AuthError::Unavailable);
            };
            let mut response = (
                [
                    (header::CONTENT_TYPE, "application/yaml; charset=utf-8"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"xdistribute-clash.yaml\"",
                    ),
                ],
                body,
            )
                .into_response();
            response.headers_mut().insert("subscription-userinfo", info);
            response
                .headers_mut()
                .insert("profile-update-interval", HeaderValue::from_static("6"));
            response
        }
        Ok(Err(ClashError::Subscription(SubscriptionStoreError::NotFound)))
        | Ok(Err(ClashError::Rules(RuleStoreError::NotFound))) => {
            error(StatusCode::NOT_FOUND, "Not Found")
        }
        Ok(Err(ClashError::Subscription(SubscriptionStoreError::Inactive))) => {
            error(StatusCode::FORBIDDEN, "Subscription inactive")
        }
        Ok(Err(ClashError::Rules(RuleStoreError::Unpublished))) => {
            error(StatusCode::CONFLICT, "请先发布模板，再分配给用户")
        }
        Ok(Err(ClashError::Rules(RuleStoreError::Invalid(detail)))) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "detail": detail })),
        )
            .into_response(),
        Ok(Err(ClashError::Render(value))) if value.status == 422 => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"detail":value.detail})),
        )
            .into_response(),
        _ => auth_error(AuthError::Unavailable),
    }
}

enum ShadowAction {
    Setup,
    Profile,
}
enum ShadowResponse {
    Setup(serde_json::Value),
    Profile(String),
}
async fn shadowrocket(app: App, token: String, action: ShadowAction) -> Response {
    let token = Zeroizing::new(token);
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app
            .mutation
            .lock()
            .map_err(|_| ClashError::Subscription(SubscriptionStoreError::Unavailable))?;
        let store = app.subscription.as_ref().ok_or(ClashError::Subscription(
            SubscriptionStoreError::Unavailable,
        ))?;
        let mut store = store
            .lock()
            .map_err(|_| ClashError::Subscription(SubscriptionStoreError::Unavailable))?;
        let input = store
            .clash_input(
                &token,
                now().map_err(|_| ClashError::Subscription(SubscriptionStoreError::Unavailable))?,
            )
            .map_err(ClashError::Subscription)?;
        let rules = app
            .rules
            .as_ref()
            .ok_or(ClashError::Rules(RuleStoreError::Unavailable))?;
        let mut rules = rules
            .lock()
            .map_err(|_| ClashError::Rules(RuleStoreError::Unavailable))?;
        let policy = rules.effective(&input.user_id).map_err(ClashError::Rules)?;
        let user = xcli_panel_shadowrocket::User {
            id: input.user_id,
            name: input.name,
            uuid: input.uuid,
            token: input.token,
        };
        match action {
            ShadowAction::Setup => xcli_panel_shadowrocket::setup(&input.settings, &user, &policy)
                .map(ShadowResponse::Setup),
            ShadowAction::Profile => xcli_panel_shadowrocket::profile(
                &input.settings,
                &user,
                &input.remote_nodes,
                input.dynamic_enabled,
                &policy,
            )
            .map(ShadowResponse::Profile),
        }
        .map_err(ClashError::Render)
    })
    .await;
    match result {
        Ok(Ok(ShadowResponse::Setup(value))) => Json(value).into_response(),
        Ok(Ok(ShadowResponse::Profile(body))) => {
            ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response()
        }
        Ok(Err(ClashError::Subscription(SubscriptionStoreError::NotFound)))
        | Ok(Err(ClashError::Rules(RuleStoreError::NotFound))) => {
            error(StatusCode::NOT_FOUND, "Not Found")
        }
        Ok(Err(ClashError::Subscription(SubscriptionStoreError::Inactive))) => {
            error(StatusCode::FORBIDDEN, "Subscription inactive")
        }
        Ok(Err(ClashError::Rules(RuleStoreError::Unpublished))) => {
            error(StatusCode::CONFLICT, "请先发布模板，再分配给用户")
        }
        Ok(Err(ClashError::Rules(RuleStoreError::Invalid(detail)))) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "detail": detail })),
        )
            .into_response(),
        Ok(Err(ClashError::Render(value))) if value.status == 404 => {
            error(StatusCode::NOT_FOUND, "Not Found")
        }
        Ok(Err(ClashError::Render(value))) if value.status == 422 => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"detail":value.detail})),
        )
            .into_response(),
        _ => auth_error(AuthError::Unavailable),
    }
}
async fn shadow_setup(State(app): State<App>, UrlPath(token): UrlPath<String>) -> Response {
    shadowrocket(app, token, ShadowAction::Setup).await
}
async fn shadow_profile(State(app): State<App>, UrlPath(token): UrlPath<String>) -> Response {
    shadowrocket(app, token, ShadowAction::Profile).await
}

enum RuleValidationError {
    Auth(AuthError),
    Invalid(String),
}
enum RuleCatalogError {
    Auth(AuthError),
    Store(RuleStoreError),
}
enum RuleDraftAction {
    Create(serde_json::Value),
    Update(String, serde_json::Value),
    Publish(String, serde_json::Value),
    Reset(String, serde_json::Value),
    UndoReset(String, serde_json::Value),
    Assign(String, serde_json::Value),
}
fn validate_template_profile(
    store: &mut SubscriptionStore,
    user_id: &str,
    policy: &serde_json::Value,
) -> Result<(), RuleStoreError> {
    let input = store.template_input(user_id).map_err(|error| match error {
        SubscriptionStoreError::NotFound => RuleStoreError::UserNotFound,
        _ => RuleStoreError::Unavailable,
    })?;
    let clash_user = xcli_panel_clash::User {
        id: input.user_id.clone(),
        uuid: input.uuid.clone(),
    };
    let map_error = |error: xcli_panel_rules::ApplyError| {
        if error.status == 422 {
            RuleStoreError::Invalid(error.detail)
        } else {
            RuleStoreError::Service(error.detail)
        }
    };
    let config = xcli_panel_clash::build(
        &input.settings,
        &clash_user,
        &input.remote_nodes,
        input.dynamic_enabled,
        policy,
    )
    .map_err(map_error)?;
    let independent = policy.get("base").and_then(serde_json::Value::as_str) == Some("independent");
    if independent
        && policy
            .get("ai_outbound")
            .and_then(serde_json::Value::as_str)
            != Some("proxy")
    {
        let unavailable = config
            .get("proxy-groups")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .any(|group| {
                group.get("name").and_then(serde_json::Value::as_str) == Some("独立 · AI")
                    && group
                        .get("proxies")
                        .and_then(serde_json::Value::as_array)
                        .and_then(|v| v.first())
                        .and_then(serde_json::Value::as_str)
                        == Some("REJECT")
            });
        if unavailable {
            return Err(RuleStoreError::Invalid("AI 默认出口当前不可用".into()));
        }
    }
    let has_rules = policy
        .get("rules")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|v| !v.is_empty());
    let has_groups = policy
        .get("groups")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|v| !v.is_empty());
    if independent || has_rules || has_groups {
        let user = xcli_panel_shadowrocket::User {
            id: input.user_id,
            name: input.name,
            uuid: input.uuid,
            token: input.token,
        };
        xcli_panel_shadowrocket::profile(
            &input.settings,
            &user,
            &input.remote_nodes,
            input.dynamic_enabled,
            policy,
        )
        .map_err(map_error)?;
    }
    Ok(())
}
async fn edit_rule_draft(app: App, headers: HeaderMap, action: RuleDraftAction) -> Response {
    if !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    let cookie = Zeroizing::new(cookie(&headers));
    let csrf = Zeroizing::new(
        headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned(),
    );
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app
            .mutation
            .lock()
            .map_err(|_| RuleCatalogError::Auth(AuthError::Unavailable))?;
        let auth = app
            .auth
            .lock()
            .map_err(|_| RuleCatalogError::Auth(AuthError::Unavailable))?;
        let stamp = now().map_err(RuleCatalogError::Auth)?;
        auth.session(&cookie, Some(&csrf), stamp)
            .map_err(RuleCatalogError::Auth)?;
        let editor = app
            .rule_editor
            .as_ref()
            .ok_or(RuleCatalogError::Store(RuleStoreError::Unavailable))?;
        let mut editor = editor
            .lock()
            .map_err(|_| RuleCatalogError::Store(RuleStoreError::Unavailable))?;
        let mut validate = |id: &str, spec: &serde_json::Value| {
            let store = app
                .subscription
                .as_ref()
                .ok_or(RuleStoreError::Unavailable)?;
            let mut store = store.lock().map_err(|_| RuleStoreError::Unavailable)?;
            validate_template_profile(&mut store, id, spec)
        };
        match action {
            RuleDraftAction::Create(input) => editor.create(&input, stamp),
            RuleDraftAction::Update(id, input) => editor.update(&id, &input, stamp),
            RuleDraftAction::Publish(id, input) => {
                editor.publish(&id, &input, stamp, &mut validate)
            }
            RuleDraftAction::Reset(id, input) => editor.reset(&id, &input, stamp, &mut validate),
            RuleDraftAction::UndoReset(id, input) => {
                editor.undo_reset(&id, &input, stamp, &mut validate)
            }
            RuleDraftAction::Assign(id, input) => editor.assign(&id, &input, stamp, &mut validate),
        }
        .map_err(RuleCatalogError::Store)
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(RuleCatalogError::Auth(value))) => auth_error(value),
        Ok(Err(RuleCatalogError::Store(RuleStoreError::NotFound))) => {
            error(StatusCode::NOT_FOUND, "模板不存在")
        }
        Ok(Err(RuleCatalogError::Store(RuleStoreError::UserNotFound))) => {
            error(StatusCode::NOT_FOUND, "用户不存在")
        }
        Ok(Err(RuleCatalogError::Store(RuleStoreError::Unpublished))) => {
            error(StatusCode::CONFLICT, "请先发布模板，再分配给用户")
        }
        Ok(Err(RuleCatalogError::Store(RuleStoreError::Service(detail)))) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "detail": detail })),
        )
            .into_response(),
        Ok(Err(RuleCatalogError::Store(RuleStoreError::Invalid(detail)))) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "detail": detail })),
        )
            .into_response(),
        Ok(Err(RuleCatalogError::Store(RuleStoreError::Conflict(detail)))) => {
            (StatusCode::CONFLICT, Json(json!({ "detail": detail }))).into_response()
        }
        _ => auth_error(AuthError::Unavailable),
    }
}
async fn rule_write_action(
    app: App,
    id: String,
    headers: HeaderMap,
    input: Result<Json<serde_json::Value>, JsonRejection>,
    kind: u8,
) -> Response {
    if !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    match user_body(input) {
        Ok(value) => {
            let action = match kind {
                0 => RuleDraftAction::Publish(id, value),
                1 => RuleDraftAction::Reset(id, value),
                2 => RuleDraftAction::UndoReset(id, value),
                _ => RuleDraftAction::Assign(id, value),
            };
            edit_rule_draft(app, headers, action).await
        }
        Err(status) => user_body_error(status),
    }
}
async fn publish_rule(
    State(app): State<App>,
    UrlPath(id): UrlPath<String>,
    headers: HeaderMap,
    input: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    rule_write_action(app, id, headers, input, 0).await
}
async fn reset_rule(
    State(app): State<App>,
    UrlPath(id): UrlPath<String>,
    headers: HeaderMap,
    input: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    rule_write_action(app, id, headers, input, 1).await
}
async fn undo_reset_rule(
    State(app): State<App>,
    UrlPath(id): UrlPath<String>,
    headers: HeaderMap,
    input: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    rule_write_action(app, id, headers, input, 2).await
}
async fn assign_rule(
    State(app): State<App>,
    UrlPath(id): UrlPath<String>,
    headers: HeaderMap,
    input: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    rule_write_action(app, id, headers, input, 3).await
}
async fn create_rule_draft(
    State(app): State<App>,
    headers: HeaderMap,
    input: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    if !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    match user_body(input) {
        Ok(value) => edit_rule_draft(app, headers, RuleDraftAction::Create(value)).await,
        Err(status) => user_body_error(status),
    }
}
async fn update_rule_draft(
    State(app): State<App>,
    UrlPath(id): UrlPath<String>,
    headers: HeaderMap,
    input: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    if !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    match user_body(input) {
        Ok(value) => edit_rule_draft(app, headers, RuleDraftAction::Update(id, value)).await,
        Err(status) => user_body_error(status),
    }
}
async fn list_rule_templates(State(app): State<App>, headers: HeaderMap) -> Response {
    let cookie = Zeroizing::new(cookie(&headers));
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app
            .mutation
            .lock()
            .map_err(|_| RuleCatalogError::Auth(AuthError::Unavailable))?;
        let auth = app
            .auth
            .lock()
            .map_err(|_| RuleCatalogError::Auth(AuthError::Unavailable))?;
        auth.session(&cookie, None, now().map_err(RuleCatalogError::Auth)?)
            .map_err(RuleCatalogError::Auth)?;
        let store = app
            .rules
            .as_ref()
            .ok_or(RuleCatalogError::Store(RuleStoreError::Unavailable))?;
        let mut store = store
            .lock()
            .map_err(|_| RuleCatalogError::Store(RuleStoreError::Unavailable))?;
        store.catalog().map_err(RuleCatalogError::Store)
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(RuleCatalogError::Auth(value))) => auth_error(value),
        Ok(Err(RuleCatalogError::Store(RuleStoreError::Invalid(detail)))) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "detail": detail })),
        )
            .into_response(),
        _ => auth_error(AuthError::Unavailable),
    }
}
async fn validate_rule_template(
    State(app): State<App>,
    headers: HeaderMap,
    input: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    if !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    let value = match user_body(input) {
        Ok(value) => value,
        Err(status) => return user_body_error(status),
    };
    let cookie = Zeroizing::new(cookie(&headers));
    let csrf = Zeroizing::new(
        headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned(),
    );
    let result = tokio::task::spawn_blocking(move || {
        let auth = app
            .auth
            .lock()
            .map_err(|_| RuleValidationError::Auth(AuthError::Unavailable))?;
        auth.session(
            &cookie,
            Some(&csrf),
            now().map_err(RuleValidationError::Auth)?,
        )
        .map_err(RuleValidationError::Auth)?;
        let object = value
            .as_object()
            .filter(|v| v.len() == 2 && v.contains_key("name") && v.contains_key("spec"))
            .ok_or_else(|| RuleValidationError::Invalid("请求格式不正确".into()))?;
        let name = object["name"]
            .as_str()
            .ok_or_else(|| RuleValidationError::Invalid("字段类型不正确".into()))?;
        if !(1..=60).contains(&name.chars().count()) {
            return Err(RuleValidationError::Invalid("字段长度不符合要求".into()));
        }
        let name = xcli_panel_users::validate(&json!({ "name": name }))
            .map_err(|_| RuleValidationError::Invalid("请输入有效名称".into()))?
            .name;
        let spec = xcli_panel_rules::validate(&object["spec"])
            .map_err(|e| RuleValidationError::Invalid(e.0))?;
        Ok::<_, RuleValidationError>(json!({"name":name,"spec":spec}))
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(RuleValidationError::Auth(value))) => auth_error(value),
        Ok(Err(RuleValidationError::Invalid(detail))) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "detail": detail })),
        )
            .into_response(),
        Err(_) => auth_error(AuthError::Unavailable),
    }
}
async fn sync_node(
    State(app): State<App>,
    headers: HeaderMap,
    input: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let authorization = Zeroizing::new(
        headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned(),
    );
    let value = match user_body(input) {
        Ok(value) => value,
        Err(status) => return user_body_error(status),
    };
    let nodes = app.nodes.clone();
    let mutation = app.mutation.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = mutation.lock().map_err(|_| SyncError::Unavailable)?;
        let mut nodes = nodes.lock().map_err(|_| SyncError::Unavailable)?;
        let timestamp = now().map_err(|_| SyncError::Unavailable)?;
        nodes.sync(&authorization, &value, timestamp)
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(SyncError::Unauthorized)) => error(StatusCode::UNAUTHORIZED, "节点认证失败"),
        Ok(Err(SyncError::InvalidInput)) => {
            error(StatusCode::UNPROCESSABLE_ENTITY, "节点请求格式不正确")
        }
        Ok(Err(SyncError::CounterRollback)) => error(
            StatusCode::CONFLICT,
            "节点流量计数回退，需要重新核对节点状态",
        ),
        Ok(Err(SyncError::Unavailable)) | Err(_) => auth_error(AuthError::Unavailable),
    }
}
enum NodeAction {
    List,
    Add(serde_json::Value),
    Update(String, serde_json::Value),
}
enum NodeActionError {
    Auth(AuthError),
    Manage(ManageError),
}
async fn manage_node(app: App, headers: HeaderMap, action: NodeAction) -> Response {
    let writable = !matches!(action, NodeAction::List);
    if writable && !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    let cookie = cookie(&headers);
    let csrf = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let auth = app.auth.clone();
    let nodes = app.nodes.clone();
    let mutation = app.mutation.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = mutation
            .lock()
            .map_err(|_| NodeActionError::Auth(AuthError::Unavailable))?;
        let auth_guard = auth
            .lock()
            .map_err(|_| NodeActionError::Auth(AuthError::Unavailable))?;
        let stamp = now().map_err(NodeActionError::Auth)?;
        auth_guard
            .session(&cookie, if writable { Some(&csrf) } else { None }, stamp)
            .map_err(NodeActionError::Auth)?;
        let mut nodes = nodes
            .lock()
            .map_err(|_| NodeActionError::Manage(ManageError::Unavailable))?;
        let result = match action {
            NodeAction::List => nodes.list().map(|value| (StatusCode::OK, value)),
            NodeAction::Add(value) => nodes
                .add(&value, stamp)
                .map(|value| (StatusCode::CREATED, value)),
            NodeAction::Update(id, value) => nodes
                .update(&id, &value, stamp)
                .map(|value| (StatusCode::OK, value)),
        }
        .map_err(NodeActionError::Manage);
        drop(auth_guard);
        result
    })
    .await;
    match result {
        Ok(Ok((status, value))) => (status, Json(value)).into_response(),
        Ok(Err(NodeActionError::Auth(value))) => auth_error(value),
        Ok(Err(NodeActionError::Manage(ManageError::InvalidInput))) => {
            error(StatusCode::UNPROCESSABLE_ENTITY, "节点信息格式不正确")
        }
        Ok(Err(NodeActionError::Manage(ManageError::NotFound))) => {
            error(StatusCode::NOT_FOUND, "节点不存在")
        }
        Ok(Err(NodeActionError::Manage(ManageError::Conflict))) => {
            error(StatusCode::CONFLICT, "节点已存在、编号冲突或达到数量上限")
        }
        Ok(Err(NodeActionError::Manage(ManageError::Unavailable))) | Err(_) => {
            auth_error(AuthError::Unavailable)
        }
    }
}
async fn list_nodes(State(app): State<App>, headers: HeaderMap) -> Response {
    manage_node(app, headers, NodeAction::List).await
}

enum BackupAction {
    Status,
    Create,
    Inspect(String),
    Download(String),
}
enum BackupResponse {
    Json(serde_json::Value),
    File(String, Vec<u8>),
}
enum BackupActionError {
    Auth(AuthError),
    Store(BackupError),
}
async fn backup_action(app: App, headers: HeaderMap, action: BackupAction) -> Response {
    let writable = matches!(action, BackupAction::Create);
    if writable && !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    let cookie = Zeroizing::new(cookie(&headers));
    let csrf = Zeroizing::new(
        headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned(),
    );
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app
            .mutation
            .lock()
            .map_err(|_| BackupActionError::Auth(AuthError::Unavailable))?;
        let auth = app
            .auth
            .lock()
            .map_err(|_| BackupActionError::Auth(AuthError::Unavailable))?;
        let stamp = now().map_err(BackupActionError::Auth)?;
        auth.session(&cookie, if writable { Some(&csrf) } else { None }, stamp)
            .map_err(BackupActionError::Auth)?;
        let store = app
            .backups
            .as_ref()
            .ok_or(BackupActionError::Store(BackupError::Unavailable))?;
        let mut store = store
            .lock()
            .map_err(|_| BackupActionError::Store(BackupError::Unavailable))?;
        match action {
            BackupAction::Status => store.status().map(BackupResponse::Json),
            BackupAction::Create => store.create("manual", stamp).map(BackupResponse::Json),
            BackupAction::Inspect(id) => store.inspect(&id).map(BackupResponse::Json),
            BackupAction::Download(id) => store
                .download(&id)
                .map(|data| BackupResponse::File(id, data)),
        }
        .map_err(BackupActionError::Store)
    })
    .await;
    match result {
        Ok(Ok(BackupResponse::Json(value))) => Json(value).into_response(),
        Ok(Ok(BackupResponse::File(id, data))) => {
            let Ok(disposition) = HeaderValue::from_str(&format!("attachment; filename=\"{id}\""))
            else {
                return auth_error(AuthError::Unavailable);
            };
            let mut response =
                ([(header::CONTENT_TYPE, "application/octet-stream")], data).into_response();
            response
                .headers_mut()
                .insert(header::CONTENT_DISPOSITION, disposition);
            response
        }
        Ok(Err(BackupActionError::Auth(value))) => auth_error(value),
        Ok(Err(BackupActionError::Store(BackupError::NotFound))) => {
            error(StatusCode::NOT_FOUND, "备份不存在")
        }
        Ok(Err(BackupActionError::Store(BackupError::Invalid))) => {
            error(StatusCode::UNPROCESSABLE_ENTITY, "备份格式不支持")
        }
        _ => auth_error(AuthError::Unavailable),
    }
}
async fn backups_status(State(app): State<App>, headers: HeaderMap) -> Response {
    backup_action(app, headers, BackupAction::Status).await
}
struct SensitiveJson(serde_json::Value);
impl Drop for SensitiveJson {
    fn drop(&mut self) {
        fn clear(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::String(value) => value.zeroize(),
                serde_json::Value::Array(values) => values.iter_mut().for_each(clear),
                serde_json::Value::Object(values) => values.values_mut().for_each(clear),
                _ => (),
            }
        }
        clear(&mut self.0);
    }
}
enum WebshareAction {
    Status,
    Configure(SensitiveJson),
    Request(SensitiveJson),
}
enum WebshareActionError {
    Auth(AuthError),
    Store(WebshareError),
}
async fn webshare_action(app: App, headers: HeaderMap, action: WebshareAction) -> Response {
    let writable = !matches!(action, WebshareAction::Status);
    if writable && !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    let cookie = Zeroizing::new(cookie(&headers));
    let csrf = Zeroizing::new(
        headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned(),
    );
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app
            .mutation
            .lock()
            .map_err(|_| WebshareActionError::Auth(AuthError::Unavailable))?;
        let auth = app
            .auth
            .lock()
            .map_err(|_| WebshareActionError::Auth(AuthError::Unavailable))?;
        let stamp = now().map_err(WebshareActionError::Auth)?;
        auth.session(&cookie, if writable { Some(&csrf) } else { None }, stamp)
            .map_err(WebshareActionError::Auth)?;
        let mut state = app
            .webshare
            .as_ref()
            .ok_or(WebshareActionError::Store(WebshareError::Unavailable))?
            .lock()
            .map_err(|_| WebshareActionError::Store(WebshareError::Unavailable))?;
        let WebshareState { control, audit } = &mut *state;
        match action {
            WebshareAction::Status => control.recover(audit).and_then(|()| control.status(stamp)),
            WebshareAction::Configure(input) => control
                .configure_audited(&input.0, stamp, audit)
                .map(|_| json!({"ok":true,"pending":true})),
            WebshareAction::Request(input) => control
                .request_audited(&input.0, stamp, audit)
                .map(|_| json!({"ok":true,"pending":true})),
        }
        .map_err(WebshareActionError::Store)
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(WebshareActionError::Auth(value))) => auth_error(value),
        Ok(Err(WebshareActionError::Store(WebshareError::Invalid(detail)))) => {
            error(StatusCode::UNPROCESSABLE_ENTITY, detail)
        }
        _ => auth_error(AuthError::Unavailable),
    }
}
async fn webshare_status(State(app): State<App>, headers: HeaderMap) -> Response {
    webshare_action(app, headers, WebshareAction::Status).await
}
async fn configure_webshare(
    State(app): State<App>,
    headers: HeaderMap,
    input: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = user_body(input).map(SensitiveJson);
    if !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    match input {
        Ok(value) => webshare_action(app, headers, WebshareAction::Configure(value)).await,
        Err(status) => user_body_error(status),
    }
}
async fn request_webshare(
    State(app): State<App>,
    headers: HeaderMap,
    input: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = user_body(input).map(SensitiveJson);
    if !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    match input {
        Ok(value) => webshare_action(app, headers, WebshareAction::Request(value)).await,
        Err(status) => user_body_error(status),
    }
}
async fn create_backup(State(app): State<App>, headers: HeaderMap) -> Response {
    backup_action(app, headers, BackupAction::Create).await
}
async fn inspect_backup(
    State(app): State<App>,
    UrlPath(id): UrlPath<String>,
    headers: HeaderMap,
) -> Response {
    backup_action(app, headers, BackupAction::Inspect(id)).await
}
async fn download_backup(
    State(app): State<App>,
    UrlPath(id): UrlPath<String>,
    headers: HeaderMap,
) -> Response {
    backup_action(app, headers, BackupAction::Download(id)).await
}
enum RestoreError {
    Auth(AuthError),
    Store(BackupError),
}
async fn restore_backup(
    State(app): State<App>,
    headers: HeaderMap,
    input: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    if !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    let input = match user_body(input) {
        Ok(value) => SensitiveJson(value),
        Err(status) => return user_body_error(status),
    };
    let Some(object) = input.0.as_object() else {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "请求格式不正确");
    };
    let valid = object
        .keys()
        .all(|key| matches!(key.as_str(), "id" | "confirm" | "current_password" | "code"))
        && object
            .get("id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|id| {
                !id.is_empty()
                    && id.len() <= 80
                    && object.get("confirm").and_then(serde_json::Value::as_str) == Some(id)
            })
        && object
            .get("current_password")
            .and_then(serde_json::Value::as_str)
            .is_some()
        && object.get("code").is_none_or(serde_json::Value::is_string);
    if !valid {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "请确认备份和管理密码");
    }
    let cookie = Zeroizing::new(cookie(&headers));
    let csrf = Zeroizing::new(
        headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned(),
    );
    let result = tokio::task::spawn_blocking(move || {
        let _mutation = app.mutation.lock().map_err(|_| RestoreError::Auth(AuthError::Unavailable))?;
        let mut auth = app.auth.lock().map_err(|_| RestoreError::Auth(AuthError::Unavailable))?;
        let timestamp = now().map_err(RestoreError::Auth)?;
        let password = input.0["current_password"].as_str().ok_or(RestoreError::Auth(AuthError::InvalidInput))?;
        let code = input.0.get("code").and_then(serde_json::Value::as_str).unwrap_or("");
        auth.confirmed::<(), ()>(
            &cookie, &csrf, Reauthentication { password, code }, timestamp, app.start.elapsed(), |_| Ok(()),
        ).map_err(|error| match error {
            ConfirmedError::Auth(value) => RestoreError::Auth(value),
            ConfirmedError::Operation(()) => RestoreError::Auth(AuthError::Unavailable),
        })?;
        let options = app.core.as_ref().ok_or(RestoreError::Store(BackupError::Unavailable))?;
        let mut health = app.core_health.as_ref().ok_or(RestoreError::Store(BackupError::Unavailable))?
            .lock().map_err(|_| RestoreError::Store(BackupError::Unavailable))?;
        let revision = health.desired.checked_add(1).filter(|value| *value <= 9_007_199_254_740_991)
            .ok_or(RestoreError::Store(BackupError::Unavailable))?;
        let mut backup = app.backups.as_ref().ok_or(RestoreError::Store(BackupError::Unavailable))?
            .lock().map_err(|_| RestoreError::Store(BackupError::Unavailable))?;
        let id = input.0["id"].as_str().ok_or(RestoreError::Store(BackupError::Invalid))?;
        let safety = backup.restore_with_flush(id, timestamp, || {
            let hy2 = options.tags.iter().filter(|tag| tag.ends_with("-hy2")).cloned().collect();
            let mut core = ManagedCore::new(&options.api, &options.binary, &options.pid_file, hy2)
                .map_err(|_| BackupError::Unavailable)?;
            let mut counters = SqliteStore::open(&app.database, options.interval as i64, None)
                .map_err(|_| BackupError::Unavailable)?;
            let generation = core.generation().map_err(|_| BackupError::Unavailable)?;
            checkpoint_before_restart(&mut core, &mut counters, &generation, timestamp)
                .map_err(|_| BackupError::Unavailable)
        }).map_err(RestoreError::Store)?;
        health.desired = revision;
        Ok::<_, RestoreError>(json!({"ok":true,"safety_backup":safety,"local_core_sync":{"instance":health.instance,"revision":revision}}))
    }).await;
    match result {
        Ok(Ok(value)) => {
            let mut response = Json(value).into_response();
            response.headers_mut().insert(
                header::SET_COOKIE,
                HeaderValue::from_static(
                    "xg_session=; HttpOnly; Max-Age=0; Path=/; SameSite=Strict; Secure",
                ),
            );
            response
        }
        Ok(Err(RestoreError::Auth(AuthError::InvalidCredentials))) => {
            error(StatusCode::FORBIDDEN, "密码或二次验证码错误")
        }
        Ok(Err(RestoreError::Auth(value))) => auth_error(value),
        Ok(Err(RestoreError::Store(BackupError::NotFound))) => {
            error(StatusCode::NOT_FOUND, "备份不存在")
        }
        Ok(Err(RestoreError::Store(BackupError::Invalid))) => {
            error(StatusCode::UNPROCESSABLE_ENTITY, "备份格式不支持")
        }
        Ok(Err(RestoreError::Store(BackupError::DifferentServer))) => {
            error(StatusCode::CONFLICT, "备份来自不同的服务器配置")
        }
        _ => auth_error(AuthError::Unavailable),
    }
}
async fn add_node(
    State(app): State<App>,
    headers: HeaderMap,
    input: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    if !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    match user_body(input) {
        Ok(value) => manage_node(app, headers, NodeAction::Add(value)).await,
        Err(status) => user_body_error(status),
    }
}
async fn update_node(
    State(app): State<App>,
    UrlPath(id): UrlPath<String>,
    headers: HeaderMap,
    input: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    if !same_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "来源校验失败");
    }
    match user_body(input) {
        Ok(value) => manage_node(app, headers, NodeAction::Update(id, value)).await,
        Err(status) => user_body_error(status),
    }
}
fn app(state: App) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/internal/ready", get(internal_ready))
        .route("/api/login", post(login))
        .route("/api/session", get(session))
        .route("/api/core-sync", get(core_sync_status))
        .route("/api/host", get(host_status))
        .route("/api/monitor", get(monitor_status))
        .route(
            "/api/proxy-import",
            get(import_status).post(request_import_preview),
        )
        .route("/api/history", get(history))
        .route(
            "/api/notifications",
            get(notifications_status).put(configure_notifications),
        )
        .route("/api/notifications/test", post(test_notification))
        .route("/api/logout", post(logout))
        .route("/api/password", post(change_password))
        .route("/api/security", get(security_status))
        .route("/api/security/setup", post(setup_totp))
        .route("/api/security/enable", post(enable_totp))
        .route("/api/security/disable", post(disable_totp))
        .route("/api/security/recovery", post(regenerate_recovery))
        .route("/api/users", get(list_users).post(create_user))
        .route("/api/activity", get(user_activity))
        .route("/api/events", get(recent_events))
        .route("/api/users/{id}", put(update_user).delete(delete_user))
        .route("/api/users/{id}/rotate", post(rotate_user))
        .route("/api/users/{id}/reset-traffic", post(reset_user))
        .route("/api/users/{id}/links", get(user_links))
        .route(
            "/api/users/{id}/subscription-diagnostics",
            get(user_subscription_diagnostics),
        )
        .route("/api/users/{id}/shadowrocket", get(user_client_links))
        .route("/api/users/{id}/qr/{kind}", get(user_qr))
        .route("/shadowrocket-dns.sgmodule", get(shadow_dns))
        .route(
            "/api/rule-templates",
            get(list_rule_templates).post(create_rule_draft),
        )
        .route("/api/rule-templates/validate", post(validate_rule_template))
        .route("/api/rule-templates/{id}", put(update_rule_draft))
        .route("/api/rule-templates/{id}/publish", post(publish_rule))
        .route("/api/rule-templates/{id}/reset", post(reset_rule))
        .route("/api/rule-templates/{id}/undo-reset", post(undo_reset_rule))
        .route("/api/users/{id}/rule-template", post(assign_rule))
        .route("/s/{token}", get(generic_subscription))
        .route("/s/{token}/clash.yaml", get(clash_subscription))
        .route("/s/{token}/shadowrocket.json", get(shadow_setup))
        .route("/s/{token}/shadowrocket.conf", get(shadow_profile))
        .route("/api/nodes/sync", post(sync_node))
        .route("/api/remote-nodes", get(list_nodes).post(add_node))
        .route("/api/remote-nodes/{id}", put(update_node))
        .route("/api/backups", get(backups_status).post(create_backup))
        .route("/api/backups/restore", post(restore_backup))
        .route("/api/backups/{id}/inspect", get(inspect_backup))
        .route("/api/backups/{id}/download", get(download_backup))
        .route(
            "/api/webshare",
            get(webshare_status).put(configure_webshare),
        )
        .route("/api/webshare/action", post(request_webshare))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn(secure_headers))
        .with_state(state)
}
fn read_key(path: &Path) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "密钥不可用")?;
    let metadata = file.metadata().map_err(|_| "密钥不可用")?;
    if !metadata.is_file() || metadata.len() != 32 || metadata.mode() & 0o007 != 0 {
        return Err("密钥文件或权限无效");
    }
    let mut key = Zeroizing::new([0u8; 32]);
    file.read_exact(key.as_mut()).map_err(|_| "密钥不可用")?;
    Ok(key)
}
/// Shares the legacy panel's lock so two implementations cannot write the
/// same state directory concurrently during a future migration.
fn lock_controller(db: &Path) -> Result<File, &'static str> {
    let parent = db
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = std::fs::canonicalize(parent).map_err(|_| "状态目录不可用")?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent.join("controller.lock"))
        .map_err(|_| "控制器锁不可用")?;
    // SAFETY: the descriptor belongs to the returned File and remains open
    // for the service lifetime. The old panel uses the same flock protocol.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("已有面板控制器使用该状态目录");
    }
    Ok(file)
}
struct Arguments {
    db: PathBuf,
    key: PathBuf,
    origin: String,
    port: u16,
    core: Option<CoreOptions>,
    settings: Option<PathBuf>,
    strict_settings: bool,
    monitor_report: Option<PathBuf>,
    disk_probe: Option<PathBuf>,
    import_report: Option<(PathBuf, u32)>,
    import_inbox: Option<PathBuf>,
    import_apply: bool,
    notification_delivery: bool,
    automatic_backups: bool,
    backup_interval: i64,
    backup_retention: usize,
}
#[derive(Clone)]
struct CoreOptions {
    binary: PathBuf,
    api: String,
    pid_file: PathBuf,
    tags: Vec<String>,
    tags_from_settings: bool,
    interval: u64,
    probe: Option<User>,
}
fn arguments() -> Result<Arguments, &'static str> {
    let mut input = std::env::args().skip(1);
    if input.next().as_deref() != Some("--experimental") {
        return Err("测试服务需要 --experimental");
    }
    let mut db = None;
    let mut key = None;
    let mut origin = None;
    let mut port = None;
    let mut settings = None;
    let mut strict_settings = None;
    let mut monitor_report = None;
    let mut disk_probe = None;
    let mut import_report = None;
    let mut import_group = None;
    let mut import_inbox = None;
    let mut import_apply = None;
    let mut notification_delivery = None;
    let mut automatic_backups = None;
    let mut backup_interval = None;
    let mut backup_retention = None;
    let mut core_binary = None;
    let mut core_api = None;
    let mut core_pid_file = None;
    let mut core_tags = None;
    let mut core_interval = None;
    let mut core_probe = None;
    while let Some(name) = input.next() {
        let value = input.next().ok_or("缺少参数")?;
        let target = match name.as_str() {
            "--db" => &mut db,
            "--secret-key" => &mut key,
            "--origin" => &mut origin,
            "--port" => &mut port,
            "--settings" => &mut settings,
            "--experimental-strict-settings" => &mut strict_settings,
            "--monitor-report" => &mut monitor_report,
            "--experimental-disk-probe" => &mut disk_probe,
            "--experimental-import-report-dir" => &mut import_report,
            "--experimental-import-report-gid" => &mut import_group,
            "--experimental-import-inbox" => &mut import_inbox,
            "--experimental-import-apply" => &mut import_apply,
            "--experimental-notification-delivery" => &mut notification_delivery,
            "--automatic-backups" => &mut automatic_backups,
            "--backup-interval" => &mut backup_interval,
            "--backup-retention" => &mut backup_retention,
            "--core-binary" => &mut core_binary,
            "--core-api" => &mut core_api,
            "--core-pid-file" => &mut core_pid_file,
            "--core-tags" => &mut core_tags,
            "--core-poll-seconds" => &mut core_interval,
            "--core-probe-uuid" => &mut core_probe,
            _ => return Err("未知参数"),
        };
        if target.replace(value).is_some() {
            return Err("参数重复");
        }
    }
    let origin = origin.ok_or("缺少地址")?;
    let canonical = xcli_node_transport::panel_origin(&origin).map_err(|_| "管理地址无效")?;
    // The browser sends the canonical serialized origin, including normalized
    // hostname and default port. Accept equivalent configuration spellings.
    let port = port
        .unwrap_or_else(|| "18080".to_owned())
        .parse::<u16>()
        .map_err(|_| "端口无效")?;
    if port == 0 {
        return Err("端口无效");
    }
    let core = match (core_binary, core_api, core_pid_file, core_tags) {
        (None, None, None, None) if core_interval.is_none() && core_probe.is_none() => None,
        (Some(binary), Some(api), Some(pid_file), Some(tags)) => {
            let tags_from_settings = tags == "auto";
            let tags: Vec<String> = if tags_from_settings {
                Vec::new()
            } else {
                tags.split(',').map(str::to_owned).collect()
            };
            if !tags_from_settings && !validate_tags(&tags)
                || tags_from_settings && settings.is_none()
            {
                return Err("核心入口配置无效");
            }
            let interval = core_interval
                .unwrap_or_else(|| "5".to_owned())
                .parse::<u64>()
                .map_err(|_| "采样间隔无效")?;
            if !(1..=60).contains(&interval) {
                return Err("采样间隔无效");
            }
            let probe = core_probe.map(|uuid| User {
                id: "health-probe".into(),
                uuid,
                enabled: true,
                deleted: false,
                quota: 0,
                expires: 0,
                upload: 0,
                download: 0,
            });
            if probe
                .as_ref()
                .is_some_and(|user| user.email("reality").is_err())
            {
                return Err("探测用户无效");
            }
            Some(CoreOptions {
                binary: PathBuf::from(binary),
                api,
                pid_file: PathBuf::from(pid_file),
                tags,
                tags_from_settings,
                interval,
                probe,
            })
        }
        _ => return Err("核心配置不完整"),
    };
    if settings.is_none()
        && (automatic_backups.is_some() || backup_interval.is_some() || backup_retention.is_some())
    {
        return Err("备份需要订阅设置");
    }
    if monitor_report.is_some() && settings.is_none() {
        return Err("监测需要订阅设置");
    }
    let notification_delivery = match notification_delivery.as_deref().unwrap_or("false") {
        "true" => true,
        "false" => false,
        _ => return Err("通知投递设置无效"),
    };
    if notification_delivery && settings.is_none() {
        return Err("通知投递需要订阅设置");
    }
    let monitor_report = monitor_report.map(PathBuf::from);
    if monitor_report.as_ref().is_some_and(|path| {
        !path.is_absolute()
            || path.file_name().and_then(|value| value.to_str()) != Some("report.json")
    }) {
        return Err("监测报告路径无效");
    }
    let import_report = match (import_report, import_group) {
        (None, None) => None,
        (Some(path), Some(group)) => {
            let path = PathBuf::from(path);
            let group = group.parse::<u32>().map_err(|_| "导入报告组无效")?;
            if !path.is_absolute() || group == 0 {
                return Err("导入报告路径或组无效");
            }
            Some((path, group))
        }
        _ => return Err("导入报告配置不完整"),
    };
    let import_inbox = import_inbox.map(PathBuf::from);
    if import_inbox
        .as_ref()
        .is_some_and(|path| !path.is_absolute())
        || import_inbox.is_some() && (import_report.is_none() || settings.is_none())
    {
        return Err("导入请求配置不完整");
    }
    let import_apply = match import_apply.as_deref().unwrap_or("false") {
        "true" => true,
        "false" => false,
        _ => return Err("导入应用选项无效"),
    };
    if import_apply && import_inbox.is_none() {
        return Err("导入应用需要工作进程");
    }
    let automatic_backups = match automatic_backups.as_deref().unwrap_or("false") {
        "true" => true,
        "false" => false,
        _ => return Err("自动备份设置无效"),
    };
    let backup_interval = backup_interval
        .unwrap_or_else(|| "21600".into())
        .parse::<i64>()
        .map_err(|_| "备份间隔无效")?;
    let backup_retention = backup_retention
        .unwrap_or_else(|| "28".into())
        .parse::<usize>()
        .map_err(|_| "备份保留数量无效")?;
    if !(60..=604_800).contains(&backup_interval) || !(2..=365).contains(&backup_retention) {
        return Err("备份设置超出范围");
    }
    let strict_settings = match strict_settings.as_deref().unwrap_or("false") {
        "true" => true,
        "false" => false,
        _ => return Err("配置检查选项无效"),
    };
    if strict_settings && settings.is_none() {
        return Err("配置检查需要设置文件");
    }
    Ok(Arguments {
        db: PathBuf::from(db.ok_or("缺少数据库")?),
        key: PathBuf::from(key.ok_or("缺少密钥")?),
        origin: canonical,
        port,
        core,
        settings: settings.map(PathBuf::from),
        strict_settings,
        monitor_report,
        disk_probe: disk_probe.map(PathBuf::from),
        import_report,
        import_inbox,
        import_apply,
        notification_delivery,
        automatic_backups,
        backup_interval,
        backup_retention,
    })
}

fn read_settings(
    path: &Path,
    expected_origin: &str,
    strict: bool,
) -> Result<serde_json::Value, &'static str> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "订阅设置不可用")?;
    let metadata = file.metadata().map_err(|_| "订阅设置不可用")?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err("订阅设置无效");
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "订阅设置不可用")?;
    if bytes.len() > 1024 * 1024 {
        return Err("订阅设置无效");
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| "订阅设置无效")?;
    let origin = value
        .get("origin")
        .and_then(serde_json::Value::as_str)
        .ok_or("订阅设置无效")?;
    if xcli_node_transport::panel_origin(origin).map_err(|_| "订阅地址无效")? != expected_origin
    {
        return Err("订阅地址不匹配");
    }
    if strict {
        settings::validate(&value).map_err(|_| "订阅设置未通过检查")?;
    }
    Ok(value)
}

struct HostHealth {
    sampled: Option<Instant>,
    timestamp: i64,
    data: Option<serde_json::Value>,
}
impl HostHealth {
    fn new() -> Self {
        Self {
            sampled: None,
            timestamp: 0,
            data: None,
        }
    }
    fn snapshot(&self) -> serde_json::Value {
        let stale = self
            .sampled
            .is_none_or(|stamp| stamp.elapsed() > Duration::from_secs(30));
        json!({"scope":"server", "sampled":self.timestamp, "stale":stale, "host":self.data})
    }
}
struct HostWorker {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl HostWorker {
    fn start(
        health: Arc<Mutex<HostHealth>>,
        mut disk: Option<xcli_panel_runtime::disk_probe::DiskProbe>,
    ) -> Result<Self, &'static str> {
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let thread = std::thread::Builder::new()
            .name("xcli-host-sampler".into())
            .spawn(move || {
                let mut previous = None;
                let mut next_sample = Instant::now();
                while !signal.load(Ordering::SeqCst) {
                    let stamp = Instant::now();
                    let disk_value = disk.as_mut().and_then(|probe| probe.poll(stamp));
                    if stamp >= next_sample {
                        let (mut data, current) =
                            xcli_panel_runtime::sample_without_disk(Path::new("/proc"));
                        data["cpu_percent"] =
                            json!(xcli_panel_runtime::cpu_percent(previous, current));
                        data["disk"] = json!(disk_value);
                        previous = current;
                        if let (Ok(timestamp), Ok(mut status)) = (now(), health.lock()) {
                            status.timestamp = timestamp;
                            status.sampled = Some(stamp);
                            status.data = Some(data);
                        }
                        next_sample = stamp + Duration::from_secs(5);
                    } else if disk.is_some() {
                        if let Ok(mut status) = health.lock() {
                            if let Some(data) = status.data.as_mut() {
                                data["disk"] = json!(disk_value);
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            })
            .map_err(|_| "主机采样不可用")?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}
impl Drop for HostWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct ControllerWorker {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
#[derive(Clone, Copy)]
enum SyncPhase {
    Unknown,
    Ready,
    Restarting,
    Failed,
}
struct CoreHealth {
    sampled: Option<Instant>,
    healthy: bool,
    max_age: Duration,
    instance: String,
    desired: u64,
    applied: Option<u64>,
    phase: SyncPhase,
}
impl CoreHealth {
    fn new(max_age: Duration, instance: String) -> Self {
        Self {
            sampled: None,
            healthy: false,
            max_age,
            instance,
            desired: 0,
            applied: None,
            phase: SyncPhase::Unknown,
        }
    }
    fn status(&self) -> serde_json::Value {
        let fresh = self
            .sampled
            .is_some_and(|stamp| stamp.elapsed() <= self.max_age);
        let phase = if !fresh {
            "unavailable"
        } else {
            match self.phase {
                SyncPhase::Unknown | SyncPhase::Failed => "unavailable",
                SyncPhase::Restarting => "pending",
                SyncPhase::Ready if self.applied == Some(self.desired) => "ready",
                SyncPhase::Ready => "pending",
            }
        };
        json!({"scope":"local", "state":phase, "instance":self.instance,
            "revision":self.desired, "applied_revision":self.applied})
    }
    fn current(&self) -> bool {
        self.healthy
            && self
                .sampled
                .is_some_and(|stamp| stamp.elapsed() <= self.max_age)
    }
}
impl ControllerWorker {
    fn start(
        options: CoreOptions,
        db: &Path,
        mutation: Arc<Mutex<()>>,
        health: Arc<Mutex<CoreHealth>>,
    ) -> Result<Self, &'static str> {
        let hy2: BTreeSet<String> = options
            .tags
            .iter()
            .filter(|tag| tag.ends_with("-hy2"))
            .cloned()
            .collect();
        let mut core = ManagedCore::new(&options.api, &options.binary, &options.pid_file, hy2)
            .map_err(|_| "核心配置不可用")?;
        let mut store = SqliteStore::open(db, options.interval as i64, options.probe)
            .map_err(|_| "核心数据库不可用")?;
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let worker = std::thread::Builder::new()
            .name("xcli-core-controller".into())
            .spawn(move || {
                let mut last_warning: Option<Instant> = None;
                while !signal.load(Ordering::SeqCst) {
                    let result = match mutation.lock() {
                        Ok(_guard) => {
                            let result = now().map_err(|_| ()).and_then(|stamp| {
                                poll(&mut core, &mut store, &options.tags, stamp).map_err(|_| ())
                            });
                            if let Ok(mut state) = health.lock() {
                                state.sampled = Some(Instant::now());
                                state.healthy = matches!(result, Ok(CoreOutcome::Ready { .. }));
                                state.phase = match &result {
                                    Ok(CoreOutcome::Ready { .. }) => {
                                        state.applied = Some(state.desired);
                                        SyncPhase::Ready
                                    }
                                    Ok(CoreOutcome::Restarting) => SyncPhase::Restarting,
                                    Err(_) => SyncPhase::Failed,
                                };
                            }
                            result
                        }
                        Err(_) => Err(()),
                    };
                    if result.is_err()
                        && last_warning
                            .is_none_or(|stamp| stamp.elapsed() >= Duration::from_secs(60))
                    {
                        eprintln!("核心同步暂不可用，请检查管理接口和进程状态");
                        last_warning = Some(Instant::now());
                    }
                    let deadline = Instant::now() + Duration::from_secs(options.interval);
                    while !signal.load(Ordering::SeqCst) && Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            })
            .map_err(|_| "核心控制器不可用")?;
        Ok(Self {
            stop,
            thread: Some(worker),
        })
    }
}
impl Drop for ControllerWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct HistoryWorker {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl HistoryWorker {
    fn start(
        monitor: Option<MonitorView>,
        history: Arc<Mutex<History>>,
        notifications: Option<Arc<Mutex<Notifications>>>,
        core_health: Option<Arc<Mutex<CoreHealth>>>,
        backup: Option<BackupObservation>,
        mutation: Arc<Mutex<()>>,
    ) -> Result<Self, &'static str> {
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let thread = std::thread::Builder::new()
            .name("xcli-history".into())
            .spawn(move || {
                let mut last_warning: Option<Instant> = None;
                while !signal.load(Ordering::SeqCst) {
                    let result = (|| {
                        let _guard = mutation.lock().map_err(|_| ())?;
                        let timestamp = now().map_err(|_| ())?;
                        let report = monitor.as_ref().map(|monitor| {
                            xcli_panel_monitor::status::read(
                                &monitor.report,
                                &monitor.expected,
                                timestamp,
                            )
                        });
                        let core = core_health
                            .as_ref()
                            .map(|health| {
                                health.lock().map(|state| state.current()).map_err(|_| ())
                            })
                            .transpose()?;
                        match &notifications {
                            Some(notifications) => notifications
                                .lock()
                                .map_err(|_| ())?
                                .collect_runtime(report.as_ref(), core, backup, timestamp)
                                .map_err(|_| ()),
                            None => match report {
                                Some(report) => history
                                    .lock()
                                    .map_err(|_| ())?
                                    .collect(&report, timestamp)
                                    .map_err(|_| ()),
                                None => Ok(()),
                            },
                        }
                    })();
                    if result.is_err()
                        && last_warning
                            .is_none_or(|stamp| stamp.elapsed() >= Duration::from_secs(60))
                    {
                        eprintln!("历史采样暂不可用，请检查数据库状态");
                        last_warning = Some(Instant::now());
                    }
                    let deadline = Instant::now() + Duration::from_secs(60);
                    while !signal.load(Ordering::SeqCst) && Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            })
            .map_err(|_| "历史采样不可用")?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}
impl Drop for HistoryWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct NotificationWorker {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl NotificationWorker {
    fn start(
        notifications: Arc<Mutex<Notifications>>,
        mutation: Arc<Mutex<()>>,
        running: Arc<AtomicBool>,
    ) -> Result<Self, &'static str> {
        let sender = WebhookSender::production().map_err(|_| "通知投递程序不可用")?;
        Self::start_with(
            notifications,
            mutation,
            running,
            Duration::from_secs(5),
            move |pending, stamp, stop| pending.deliver(&sender, stamp, stop),
        )
    }
    fn start_with(
        notifications: Arc<Mutex<Notifications>>,
        mutation: Arc<Mutex<()>>,
        running: Arc<AtomicBool>,
        pause: Duration,
        deliver: impl Fn(&Pending, i64, &AtomicBool) -> Delivery + Send + 'static,
    ) -> Result<Self, &'static str> {
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let flag = running.clone();
        running.store(true, Ordering::Release);
        let thread = std::thread::Builder::new()
            .name("xcli-notifications".into())
            .spawn(move || {
                struct Running(Arc<AtomicBool>);
                impl Drop for Running {
                    fn drop(&mut self) {
                        self.0.store(false, Ordering::Release);
                    }
                }
                let _running = Running(flag);
                let mut last_warning: Option<Instant> = None;
                while !signal.load(Ordering::Acquire) {
                    let pending = (|| {
                        let _guard = mutation.lock().map_err(|_| ())?;
                        notifications
                            .lock()
                            .map_err(|_| ())?
                            .next(now().map_err(|_| ())?)
                            .map_err(|_| ())
                    })();
                    let result = match pending {
                        Ok(Some(pending)) => {
                            let result = now()
                                .map_err(|_| ())
                                .map(|stamp| deliver(&pending, stamp, &signal));
                            if signal.load(Ordering::Acquire) {
                                break;
                            }
                            result.and_then(|result| {
                                let _guard = mutation.lock().map_err(|_| ())?;
                                notifications
                                    .lock()
                                    .map_err(|_| ())?
                                    .finish(&pending, &result, now().map_err(|_| ())?)
                                    .map(|_| ())
                                    .map_err(|_| ())
                            })
                        }
                        Ok(None) => Ok(()),
                        Err(()) => Err(()),
                    };
                    if result.is_err()
                        && last_warning.is_none_or(|at| at.elapsed() >= Duration::from_secs(60))
                    {
                        eprintln!("通知队列暂不可用，请检查服务状态");
                        last_warning = Some(Instant::now());
                    }
                    let deadline = Instant::now() + pause;
                    while !signal.load(Ordering::Acquire) && Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
            });
        let thread = match thread {
            Ok(thread) => thread,
            Err(_) => {
                running.store(false, Ordering::Release);
                return Err("通知任务不可用");
            }
        };
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}
impl Drop for NotificationWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct BackupWorker {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl BackupWorker {
    fn start(
        backups: Arc<Mutex<BackupStore>>,
        mutation: Arc<Mutex<()>>,
    ) -> Result<Self, &'static str> {
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let thread = std::thread::Builder::new()
            .name("xcli-backup".into())
            .spawn(move || {
                while !signal.load(Ordering::SeqCst) {
                    let result = mutation.lock().map_err(|_| ()).and_then(|_guard| {
                        backups.lock().map_err(|_| ()).and_then(|mut store| {
                            let stamp = now().map_err(|_| ())?;
                            store.scheduled(stamp).map(|_| ()).map_err(|_| ())
                        })
                    });
                    if result.is_err() {
                        eprintln!("自动备份暂不可用，请检查备份状态");
                    }
                    let deadline = Instant::now() + Duration::from_secs(30);
                    while !signal.load(Ordering::SeqCst) && Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            })
            .map_err(|_| "备份任务不可用")?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}
impl Drop for BackupWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("管理测试服务启动失败，请检查本机配置");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), &'static str> {
    let mut args = arguments()?;
    let settings = args
        .settings
        .as_ref()
        .map(|path| read_settings(path, &args.origin, args.strict_settings))
        .transpose()?;
    if let Some(core) = args.core.as_mut().filter(|core| core.tags_from_settings) {
        core.tags = settings::inbound_tags(settings.as_ref().ok_or("缺少订阅设置")?)
            .map_err(|_| "核心入口配置无效")?;
    }
    let _controller_lock = lock_controller(&args.db)?;
    let key = read_key(&args.key)?;
    let auth = AdminAuth::open(&args.db, *key).map_err(|_| "管理数据库不可用")?;
    let users = Repository::open(&args.db).map_err(|_| "用户数据库不可用")?;
    let nodes = NodeSync::open(&args.db).map_err(|_| "节点数据库不可用")?;
    let security_domain = settings
        .as_ref()
        .and_then(|value| value.get("domain"))
        .and_then(serde_json::Value::as_str)
        .filter(|domain| {
            !domain.is_empty()
                && domain.len() <= 253
                && domain
                    .bytes()
                    .all(|v| v.is_ascii_alphanumeric() || v == b'-' || v == b'.')
        })
        .map(str::to_owned);
    let shadow_dns = settings
        .as_ref()
        .and_then(|value| xcli_panel_shadowrocket::dns_module(value).ok());
    let subscription = settings
        .as_ref()
        .map(|settings| {
            SubscriptionStore::open(&args.db, settings.clone(), *key)
                .map(|store| Arc::new(Mutex::new(store)))
                .map_err(|_| "订阅数据库不可用")
        })
        .transpose()?;
    let rules = settings
        .as_ref()
        .map(|settings| {
            RuleStore::open(&args.db, settings.clone())
                .map(|store| Arc::new(Mutex::new(store)))
                .map_err(|_| "规则数据库不可用")
        })
        .transpose()?;
    let rule_editor = settings
        .as_ref()
        .map(|_| {
            RuleEditor::open(&args.db)
                .map(|store| Arc::new(Mutex::new(store)))
                .map_err(|_| "规则数据库不可用")
        })
        .transpose()?;
    let backups = settings
        .as_ref()
        .map(|settings| {
            BackupStore::open(
                &args.db,
                settings.clone(),
                *key,
                env!("CARGO_PKG_VERSION").into(),
            )
            .and_then(|mut store| {
                store.configure(
                    args.automatic_backups,
                    args.backup_interval,
                    args.backup_retention,
                )?;
                Ok(Arc::new(Mutex::new(store)))
            })
            .map_err(|_| "备份数据库不可用")
        })
        .transpose()?;
    let webshare = settings
        .as_ref()
        .map(|settings| {
            let directory = args
                .db
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let control = WebshareControl::open(directory, settings.clone(), *key)
                .map_err(|_| "住宅状态不可用")?;
            let mut audit = SqliteAuditor::open(&args.db).map_err(|_| "住宅审计不可用")?;
            // An unrecoverable journal disables the residential component but
            // must not prevent the administrator from accessing the panel.
            let _ = control.recover(&mut audit);
            Ok::<_, &'static str>(Arc::new(Mutex::new(WebshareState { control, audit })))
        })
        .transpose()?;
    let monitor = match (&args.monitor_report, &settings) {
        (Some(report), Some(settings)) => Some(MonitorView {
            report: report.clone(),
            expected: xcli_panel_monitor::status::expected(settings)
                .map_err(|_| "监测入口配置无效")?,
        }),
        _ => None,
    };
    let import_report = args
        .import_report
        .as_ref()
        .map(|(path, group)| {
            ImportReport::open_trusted(path, *group)
                .map(Arc::new)
                .map_err(|_| "导入报告目录不可用")
        })
        .transpose()?;
    let import_preview = match (&args.import_inbox, &settings) {
        (Some(inbox), Some(settings)) => {
            let existing_exits = match settings.get("residential_exits") {
                None => 0,
                Some(value) => value.as_array().ok_or("住宅配置无效")?.len(),
            };
            if existing_exits > 40 {
                return Err("住宅配置无效");
            }
            Some(Arc::new(Mutex::new(ImportPreview {
                publisher: Publisher::open(inbox, *key).map_err(|_| "导入请求目录不可用")?,
                audit: ImportAuditor::open(&args.db).map_err(|_| "导入审计不可用")?,
                key: Zeroizing::new(*key),
                existing_exits,
            })))
        }
        _ => None,
    };
    let history_transports = settings
        .as_ref()
        .map(xcli_panel_monitor::status::expected)
        .transpose()
        .map_err(|_| "监测入口配置无效")?
        .unwrap_or_default();
    let notification_services = history_transports
        .iter()
        .map(|tag| {
            let label = match tag.as_str() {
                "reality" => Some("REALITY 入口"),
                "websocket" => Some("WebSocket / TLS 入口"),
                "hysteria2" => Some("Hysteria 2 入口"),
                "hysteria2-brutal" => Some("Hysteria 2 Brutal 40 Mbps 入口"),
                "vmess" => Some("VMess / TLS 入口"),
                _ => settings
                    .as_ref()
                    .and_then(|value| value.get("residential_exits"))
                    .and_then(serde_json::Value::as_array)
                    .and_then(|values| {
                        values
                            .iter()
                            .find(|value| value["tag"].as_str() == Some(tag))
                    })
                    .and_then(|value| value["label"].as_str()),
            }
            .filter(|label| {
                !label.is_empty()
                    && label.chars().count() <= 80
                    && !label.chars().any(char::is_control)
            })
            .unwrap_or(tag);
            (tag.clone(), label.to_owned())
        })
        .collect::<BTreeMap<_, _>>();
    let notifications = security_domain
        .as_ref()
        .map(|domain| {
            Notifications::open(&args.db, *key, domain, notification_services)
                .map(|value| Arc::new(Mutex::new(value)))
                .map_err(|_| "通知数据库不可用")
        })
        .transpose()?;
    let history = Arc::new(Mutex::new(
        History::open(&args.db, history_transports).map_err(|_| "历史数据库不可用")?,
    ));
    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), args.port))
            .await
            .map_err(|_| "管理端口不可用")?;
    let core_health = if let Some(options) = args.core.as_ref() {
        let mut instance = [0u8; 16];
        File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut instance))
            .map_err(|_| "核心状态不可用")?;
        Some(Arc::new(Mutex::new(CoreHealth::new(
            Duration::from_secs((options.interval * 3).max(30)),
            hex::encode(instance),
        ))))
    } else {
        None
    };
    let state = App {
        database: args.db.clone(),
        auth: Arc::new(Mutex::new(auth)),
        users: Arc::new(Mutex::new(users)),
        nodes: Arc::new(Mutex::new(nodes)),
        subscription,
        rules,
        rule_editor,
        backups,
        webshare,
        monitor,
        import_report,
        import_preview,
        import_apply: args.import_apply,
        history,
        notifications,
        notification_delivery_active: Arc::new(AtomicBool::new(false)),
        security_domain,
        shadow_dns,
        core: args.core.clone(),
        core_health: core_health.clone(),
        host: Arc::new(Mutex::new(HostHealth::new())),
        mutation: Arc::new(Mutex::new(())),
        origin: args.origin,
        start: Instant::now(),
    };
    let disk_probe = args
        .disk_probe
        .as_ref()
        .map(|program| {
            let parent = args
                .db
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let path = std::fs::canonicalize(parent).map_err(|_| "磁盘采样目录不可用")?;
            xcli_panel_runtime::disk_probe::DiskProbe::new(program, &path)
        })
        .transpose()?;
    let _host_worker = HostWorker::start(state.host.clone(), disk_probe)?;
    let _controller = match args.core {
        Some(options) => Some(ControllerWorker::start(
            options,
            &args.db,
            state.mutation.clone(),
            core_health.clone().ok_or("核心状态不可用")?,
        )?),
        None => None,
    };
    let backup_observation = if args.automatic_backups {
        Some(BackupObservation {
            started: now().map_err(|_| "时钟不可用")?,
            interval: args.backup_interval,
        })
    } else {
        None
    };
    let _history_worker = if state.monitor.is_some()
        || state.notifications.is_some() && (core_health.is_some() || backup_observation.is_some())
    {
        Some(HistoryWorker::start(
            state.monitor.clone(),
            state.history.clone(),
            state.notifications.clone(),
            core_health,
            backup_observation,
            state.mutation.clone(),
        )?)
    } else {
        None
    };
    let _notification_worker = if args.notification_delivery {
        Some(NotificationWorker::start(
            state.notifications.clone().ok_or("通知配置不可用")?,
            state.mutation.clone(),
            state.notification_delivery_active.clone(),
        )?)
    } else {
        None
    };
    let _backup_worker = if args.automatic_backups {
        Some(BackupWorker::start(
            state.backups.clone().ok_or("备份数据库不可用")?,
            state.mutation.clone(),
        )?)
    } else {
        None
    };
    println!("管理测试服务已在回环地址启动");
    axum::serve(
        listener,
        app(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await
    .map_err(|_| "管理服务失败")
}

async fn shutdown() {
    #[cfg(unix)]
    {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(value) => value,
                Err(_) => return,
            };
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::time::Duration;

    #[test]
    fn local_sync_status_never_acknowledges_pending_failed_or_stale_checks() {
        let mut state = CoreHealth::new(Duration::from_secs(30), "fixture-instance".into());
        assert_eq!(state.status()["state"], "unavailable");
        state.sampled = Some(Instant::now());
        state.phase = SyncPhase::Ready;
        state.applied = Some(0);
        state.desired = 1;
        assert_eq!(state.status()["state"], "pending");
        state.applied = Some(1);
        assert_eq!(state.status()["state"], "ready");
        assert_eq!(state.status()["scope"], "local");
        state.phase = SyncPhase::Restarting;
        assert_eq!(state.status()["state"], "pending");
        state.phase = SyncPhase::Failed;
        assert_eq!(state.status()["state"], "unavailable");
        state.phase = SyncPhase::Ready;
        state.sampled = Some(Instant::now() - Duration::from_secs(31));
        assert_eq!(state.status()["state"], "unavailable");
    }

    #[test]
    fn runtime_worker_observes_core_and_backup_without_monitor_service() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);
            CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            INSERT INTO metadata VALUES('backup_error','synthetic failure');").unwrap();
        let notifications = Arc::new(Mutex::new(
            Notifications::open(&path, [7; 32], "testserver", BTreeMap::new()).unwrap(),
        ));
        db.execute("UPDATE notification_config SET failures=1 WHERE id=1", [])
            .unwrap();
        let history = Arc::new(Mutex::new(History::open(&path, vec![]).unwrap()));
        let health = Arc::new(Mutex::new(CoreHealth::new(
            Duration::from_secs(30),
            "fixture".into(),
        )));
        let worker = HistoryWorker::start(
            None,
            history,
            Some(notifications),
            Some(health),
            Some(BackupObservation {
                started: now().unwrap(),
                interval: 60,
            }),
            Arc::new(Mutex::new(())),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let count: i64 = db
                .query_row("SELECT COUNT(*) FROM alarm_state WHERE firing=1", [], |r| {
                    r.get(0)
                })
                .unwrap();
            if count == 2 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "runtime alerts were not collected"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(worker);
        let services: Vec<String> = db
            .prepare("SELECT service FROM alarm_state WHERE firing=1 ORDER BY service")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(services, ["backup", "core"]);
    }

    #[test]
    fn notification_worker_commits_delivery_and_preserves_cancelled_inflight_event() {
        for cancel in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("gateway.sqlite");
            let mut db = Connection::open(&path).unwrap();
            db.execute_batch("CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);").unwrap();
            let mut notifications =
                Notifications::open(&path, [7; 32], "testserver", BTreeMap::new()).unwrap();
            {
                let tx = db.transaction().unwrap();
                notifications
                    .configure(
                        &tx,
                        &json!({"enabled":true,"url":"https://receiver.example.net/synthetic"}),
                        100,
                    )
                    .unwrap();
                tx.commit().unwrap();
            }
            notifications.observe("backup", true, 1, 100).unwrap();
            let notifications = Arc::new(Mutex::new(notifications));
            let mutation = Arc::new(Mutex::new(()));
            let running = Arc::new(AtomicBool::new(false));
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let worker = NotificationWorker::start_with(
                notifications,
                mutation,
                running.clone(),
                Duration::from_millis(50),
                move |_, _, stop| {
                    started_tx.send(()).unwrap();
                    if cancel {
                        while !stop.load(Ordering::Acquire) {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                    }
                    Delivery {
                        status: 204,
                        error: None,
                    }
                },
            )
            .unwrap();
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(running.load(Ordering::Acquire));
            if !cancel {
                let deadline = Instant::now() + Duration::from_secs(5);
                while Instant::now() < deadline {
                    let status: String = db
                        .query_row("SELECT status FROM notifications", [], |r| r.get(0))
                        .unwrap();
                    if status == "delivered" {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            drop(worker);
            assert!(!running.load(Ordering::Acquire));
            let (status, attempts): (String, i64) = db
                .query_row("SELECT status,attempts FROM notifications", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .unwrap();
            assert_eq!(
                (status.as_str(), attempts),
                if cancel {
                    ("pending", 0)
                } else {
                    ("delivered", 1)
                }
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn session_expiry_uses_the_time_after_auth_lock_contention() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL);
            CREATE TABLE sessions(hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
            CREATE TABLE mfa(id INTEGER PRIMARY KEY,enabled INTEGER NOT NULL,secret TEXT NOT NULL,last_step INTEGER NOT NULL);
            CREATE TABLE mfa_sessions(hash TEXT PRIMARY KEY);
            CREATE TABLE recovery_codes(hash TEXT PRIMARY KEY,used INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);
            INSERT INTO mfa VALUES(1,0,'',-1);").unwrap();
        db.execute("INSERT INTO admin VALUES(1,?)",["000102030405060708090a0b0c0d0e0f:afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf"]).unwrap();
        let mut service = AdminAuth::open(&path, [0; 32]).unwrap();
        let login = service
            .login(
                "admin",
                "fixture-password",
                "",
                "127.0.0.1",
                now().unwrap(),
                Duration::ZERO,
            )
            .unwrap();
        db.execute("UPDATE sessions SET expires=?", [now().unwrap() + 2])
            .unwrap();
        let app = App {
            database: path.clone(),
            auth: Arc::new(Mutex::new(service)),
            users: Arc::new(Mutex::new(Repository::open(&path).unwrap())),
            nodes: Arc::new(Mutex::new(NodeSync::open(&path).unwrap())),
            subscription: None,
            rules: None,
            rule_editor: None,
            backups: None,
            webshare: None,
            monitor: None,
            import_report: None,
            import_preview: None,
            import_apply: false,
            history: Arc::new(Mutex::new(History::open(&path, vec![]).unwrap())),
            notifications: None,
            notification_delivery_active: Arc::new(AtomicBool::new(false)),
            security_domain: None,
            shadow_dns: None,
            core: None,
            core_health: None,
            host: Arc::new(Mutex::new(HostHealth::new())),
            mutation: Arc::new(Mutex::new(())),
            origin: "https://testserver".to_owned(),
            start: Instant::now(),
        };
        let lock = app.auth.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _guard = lock.lock().unwrap();
            ready_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        ready_rx.recv().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("xg_session={}", login.cookie)).unwrap(),
        );
        let pending = tokio::spawn(session(State(app.clone()), headers));
        tokio::time::sleep(Duration::from_secs(3)).await;
        release_tx.send(()).unwrap();
        holder.join().unwrap();
        assert_eq!(pending.await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }
}
