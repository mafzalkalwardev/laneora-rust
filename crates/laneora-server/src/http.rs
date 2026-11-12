use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hmac::{Hmac, Mac};
use laneora_core::{
    account_status, apply_plan, denial_message, normalize_services, open_b64, plan_catalog,
    proxy_endpoint, require_services, seal_b64, seal_salted, AccountStatus, LoginRequest,
    SharedProxy, StreamBlob, LEGACY_PASSPHRASE, SERVICES,
};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;

use crate::db::{dispatcher_secret, stream_plaintext};
use crate::{AppState, COMPAT_VERSION, VERSION};

type HmacSha256 = Hmac<Sha256>;

const ADMIN_PAGE: &str = include_str!("../assets/admin.html");

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/latest_version", get(latest_version))
        .route("/linetext", get(linetext))
        .route("/update", get(empty_update))
        .route("/authenticate", get(authenticate))
        .route("/logger", get(logger_compat).post(logger_api))
        .route("/api/login", post(api_login))
        .route("/api/session", post(api_session))
        .route("/api/version", get(api_version))
        .route("/admin", get(admin_page))
        .route("/admin/", get(admin_page))
        .route("/admin/api/login", post(admin_login))
        .route("/admin/api/logout", post(admin_logout))
        .route("/admin/api/users", get(admin_users).post(admin_create))
        .route("/admin/api/users/update", post(admin_update))
        .route("/admin/api/users/delete", post(admin_delete))
        .route("/admin/api/password", post(admin_password))
        .route("/admin/api/proxy", post(admin_proxy))
        .route("/admin/api/settings", post(admin_settings))
        .route("/admin/api/cookies", post(admin_cookies))
        .layer(axum::extract::DefaultBodyLimit::max(8 * 1024 * 1024))
        .layer(middleware::from_fn(cors))
        .with_state(state)
}

async fn cors(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

fn text(body: impl Into<String>) -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body.into()))
        .unwrap()
}

fn json_response(status: StatusCode, value: Value) -> Response {
    (status, Json(value)).into_response()
}

async fn root() -> Response {
    text("Laneora Rust")
}

async fn health(State(state): State<AppState>) -> Response {
    let users = state.db.user_count().await.unwrap_or(0);
    let multi = state.sessions.lock().await.multi();
    json_response(
        StatusCode::OK,
        json!({
            "ok": true,
            "service": "laneora-rust",
            "version": VERSION,
            "users": users,
            "allow_multi_screen": multi,
        }),
    )
}

async fn latest_version() -> Response {
    text(COMPAT_VERSION)
}

async fn api_version() -> Response {
    json_response(StatusCode::OK, json!({"version": VERSION}))
}

async fn linetext(State(state): State<AppState>) -> Response {
    let multi = if state.sessions.lock().await.multi() {
        "multi-PC ON"
    } else {
        "single-screen"
    };
    let proxy = state
        .db
        .shared_proxy()
        .await
        .unwrap_or_default()
        .px;
    text(format!("Laneora Rust — {multi}; shared proxy={proxy}"))
}

async fn empty_update() -> Response {
    Response::builder()
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap()
}

async fn admin_page() -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(ADMIN_PAGE))
        .unwrap()
}

#[derive(Debug, Deserialize)]
struct AuthQuery {
    #[serde(default)]
    username: String,
    #[serde(default)]
    key: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    is_alive: String,
}

async fn authenticate(
    State(state): State<AppState>,
    Query(query): Query<AuthQuery>,
) -> Response {
    let Some(user) = (match state.db.find_user(&query.username).await {
        Ok(user) => user,
        Err(err) => return json_response(StatusCode::INTERNAL_SERVER_ERROR, json!({"error": err.to_string()})),
    }) else {
        return text("0");
    };
    if !crate::db::verify_password(&dispatcher_secret(&query.key), &user.password_hash) {
        return text("0");
    }
    if let Some(denied) = deny(&user) {
        return json_response(StatusCode::OK, denied);
    }
    state.sessions.lock().await.compat_register(
        &user.username,
        &query.value,
        &query.is_alive,
    );
    match compat_payload(&state, &user).await {
        Ok(payload) => json_response(StatusCode::OK, payload),
        Err(err) => json_response(StatusCode::INTERNAL_SERVER_ERROR, json!({"error": err})),
    }
}

#[derive(Debug, Deserialize)]
struct LoggerQuery {
    #[serde(default)]
    uva: String,
}

async fn logger_compat(
    State(state): State<AppState>,
    Query(query): Query<LoggerQuery>,
) -> Response {
    let echo = state.sessions.lock().await.compat_echo(&query.uva);
    text(echo)
}

fn deny(user: &crate::db::UserRow) -> Option<Value> {
    let status = account_status(user.is_active(), user.end(), chrono::Utc::now());
    denial_message(
        status,
        user.plan_label.as_deref(),
        user.subscription_end.as_deref(),
    )
    .map(|(code, message)| json!({"status": code, "message": message}))
}

async fn compat_payload(state: &AppState, user: &crate::db::UserRow) -> Result<Value, String> {
    let proxy = state.db.shared_proxy().await.map_err(|err| err.to_string())?;
    let services = normalize_services(&user.services);
    let mut payload = json!({
        "status": "okie",
        "p": proxy.p,
        "px": proxy.px,
        "pu": proxy.pu,
        "pd": proxy.pd,
        "active_subs": "one",
        "services": services.join(","),
    });
    let streams = sealed_streams(state, user).await?;
    for (name, sealed) in streams {
        let plain = open_b64(&state.data_key, &sealed).map_err(|err| err.to_string())?;
        let text = String::from_utf8(plain).map_err(|err| err.to_string())?;
        let legacy = seal_salted(LEGACY_PASSPHRASE, &text).map_err(|err| err.to_string())?;
        payload[name] = Value::String(legacy);
    }
    Ok(payload)
}

async fn sealed_streams(
    state: &AppState,
    user: &crate::db::UserRow,
) -> Result<Vec<(String, String)>, String> {
    let rows = state
        .db
        .streams_for(user.id)
        .await
        .map_err(|err| err.to_string())?;
    if !rows.is_empty() {
        return Ok(rows);
    }
    let plain = stream_plaintext(&StreamBlob::default())?;
    let sealed = seal_b64(&state.data_key, plain.as_bytes()).map_err(|err| err.to_string())?;
    Ok(vec![("one".into(), sealed)])
}

async fn api_login(State(state): State<AppState>, Json(body): Json<LoginRequest>) -> Response {
    let Some(user) = (match state.db.find_user(&body.username).await {
        Ok(user) => user,
        Err(err) => return json_response(StatusCode::INTERNAL_SERVER_ERROR, json!({"ok": false, "error": err.to_string()})),
    }) else {
        return json_response(StatusCode::UNAUTHORIZED, json!({"ok": false, "error": "Wrong username or password."}));
    };
    if !crate::db::verify_password(&dispatcher_secret(&body.password), &user.password_hash) {
        return json_response(
            StatusCode::UNAUTHORIZED,
            json!({"ok": false, "error": "Wrong username or password."}),
        );
    }
    if let Some(denied) = deny(&user) {
        return json_response(StatusCode::FORBIDDEN, json!({"ok": false, "status": denied["status"], "error": denied["message"]}));
    }
    let mut token = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token);
    let token = hex_token(&token);
    state
        .sessions
        .lock()
        .await
        .register_api(&user.username, &token);
    let proxy = state.db.shared_proxy().await.unwrap_or_default();
    json_response(
        StatusCode::OK,
        json!({
            "ok": true,
            "token": token,
            "services": normalize_services(&user.services),
            "proxy": proxy,
            "proxy_url": proxy_endpoint(&proxy),
            "subscription_end": user.subscription_end,
        }),
    )
}

#[derive(Debug, Deserialize)]
struct TokenBody {
    token: String,
}

async fn api_session(State(state): State<AppState>, Json(body): Json<TokenBody>) -> Response {
    if !state.sessions.lock().await.api_alive(&body.token) {
        return json_response(
            StatusCode::UNAUTHORIZED,
            json!({"ok": false, "reason": "kicked"}),
        );
    }
    let username = {
        // The token is the session id. Recover the username from a fresh lock.
        let sessions = state.sessions.lock().await;
        if !sessions.api_alive(&body.token) {
            return json_response(StatusCode::UNAUTHORIZED, json!({"ok": false, "reason": "kicked"}));
        }
        drop(sessions);
        String::new()
    };
    let _ = username;
    session_body(&state, &body.token).await
}

async fn session_body(state: &AppState, token: &str) -> Response {
    let username = {
        let sessions = state.sessions.lock().await;
        if !sessions.api_alive(token) {
            return json_response(StatusCode::UNAUTHORIZED, json!({"ok": false, "reason": "kicked"}));
        }
        match session_username(&sessions, token) {
            Some(name) => name,
            None => return json_response(StatusCode::UNAUTHORIZED, json!({"ok": false, "reason": "kicked"})),
        }
    };
    let Some(user) = state.db.find_user(&username).await.ok().flatten() else {
        return json_response(StatusCode::UNAUTHORIZED, json!({"ok": false, "error": "Unknown account."}));
    };
    let streams = match sealed_streams(state, &user).await {
        Ok(rows) => rows,
        Err(err) => return json_response(StatusCode::INTERNAL_SERVER_ERROR, json!({"ok": false, "error": err})),
    };
    let mut map = serde_json::Map::new();
    for (name, sealed) in streams {
        map.insert(name, Value::String(sealed));
    }
    let proxy = state.db.shared_proxy().await.unwrap_or_default();
    json_response(
        StatusCode::OK,
        json!({
            "ok": true,
            "streams": map,
            "services": normalize_services(&user.services),
            "proxy_url": proxy_endpoint(&proxy),
        }),
    )
}

fn session_username(sessions: &crate::Sessions, token: &str) -> Option<String> {
    sessions.username_for(token)
}

async fn logger_api(State(state): State<AppState>, Json(body): Json<TokenBody>) -> Response {
    if state.sessions.lock().await.api_alive(&body.token) {
        json_response(StatusCode::OK, json!({"ok": true}))
    } else {
        json_response(StatusCode::OK, json!({"ok": false, "reason": "kicked"}))
    }
}

fn hex_token(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn sign(state: &AppState, username: &str, epoch: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(&state.cookie_key).expect("hmac key");
    mac.update(username.as_bytes());
    mac.update(b".");
    mac.update(epoch.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn ct_eq(left: &str, right: &str) -> bool {
    let a = left.as_bytes();
    let b = right.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn admin_from_cookie(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    let token = raw.split(';').find_map(|part| {
        let part = part.trim();
        part.strip_prefix("laneora_admin=")
    })?;
    let mut bits = token.split('.');
    let username = bits.next()?.to_string();
    let epoch = bits.next()?.to_string();
    let mac = bits.next()?.to_string();
    if bits.next().is_some() {
        return None;
    }
    let stored = state.db.get_setting("admin_username").await.ok()??;
    let current = state.db.admin_epoch().await.ok()?;
    if username != stored || epoch != current {
        return None;
    }
    if !ct_eq(&sign(state, &username, &epoch), &mac) {
        return None;
    }
    Some(username)
}

fn set_cookie(value: &str, clear: bool) -> HeaderValue {
    let cookie = if clear {
        "laneora_admin=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0".to_string()
    } else {
        format!("laneora_admin={value}; HttpOnly; SameSite=Lax; Path=/")
    };
    HeaderValue::from_str(&cookie).unwrap_or(HeaderValue::from_static("laneora_admin=; Max-Age=0"))
}

async fn admin_login(State(state): State<AppState>, Json(body): Json<LoginRequest>) -> Response {
    let ok = state
        .db
        .verify_admin(&body.username, &body.password)
        .await
        .unwrap_or(false);
    if !ok {
        return json_response(StatusCode::UNAUTHORIZED, json!({"ok": false, "error": "Wrong admin login."}));
    }
    let epoch = state.db.admin_epoch().await.unwrap_or_else(|_| "1".into());
    let mac = sign(&state, body.username.trim(), &epoch);
    let mut response = json_response(StatusCode::OK, json!({"ok": true}));
    response.headers_mut().insert(
        header::SET_COOKIE,
        set_cookie(&format!("{}.{epoch}.{mac}", body.username.trim()), false),
    );
    response
}

async fn admin_logout() -> Response {
    let mut response = json_response(StatusCode::OK, json!({"ok": true}));
    response
        .headers_mut()
        .insert(header::SET_COOKIE, set_cookie("", true));
    response
}

async fn require_admin(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    if admin_from_cookie(state, headers).await.is_some() {
        Ok(())
    } else {
        Err(json_response(
            StatusCode::UNAUTHORIZED,
            json!({"ok": false, "error": "Sign in again."}),
        ))
    }
}

async fn admin_users(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_admin(&state, &headers).await {
        return response;
    }
    let users = match state.db.list_users().await {
        Ok(users) => users,
        Err(err) => return json_response(StatusCode::INTERNAL_SERVER_ERROR, json!({"ok": false, "error": err.to_string()})),
    };
    let now = chrono::Utc::now();
    let mut counts = json!({"total": users.len(), "active": 0, "expired": 0, "disabled": 0, "unset": 0});
    let listed: Vec<Value> = users
        .iter()
        .map(|user| {
            let status = account_status(user.is_active(), user.end(), now);
            let key = status.as_str();
            if let Some(slot) = counts.get_mut(key).and_then(|value| value.as_i64()) {
                counts[key] = json!(slot + 1);
            }
            json!({
                "username": user.username,
                "active": user.is_active(),
                "status": status.as_str(),
                "plan": user.plan_id,
                "plan_label": user.plan_label,
                "subscription_start": user.subscription_start,
                "subscription_end": user.subscription_end,
                "services": normalize_services(&user.services),
            })
        })
        .collect();
    let proxy = state.db.shared_proxy().await.unwrap_or_default();
    json_response(
        StatusCode::OK,
        json!({
            "ok": true,
            "users": listed,
            "plans": plan_catalog(),
            "services": SERVICES,
            "summary": counts,
            "allow_multi_screen": state.sessions.lock().await.multi(),
            "proxy": proxy,
        }),
    )
}

#[derive(Debug, Deserialize)]
struct CreateBody {
    username: String,
    password: String,
    #[serde(default)]
    plan: Option<String>,
    #[serde(default)]
    services: Option<String>,
}

async fn admin_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateBody>,
) -> Response {
    if let Err(response) = require_admin(&state, &headers).await {
        return response;
    }
    let services = body.services.unwrap_or_else(|| "dat".into());
    if let Err(err) = require_services(&services) {
        return json_response(StatusCode::BAD_REQUEST, json!({"ok": false, "error": err}));
    }
    if let Err(err) = state
        .db
        .create_user(&body.username, &body.password, &services, state.fast_hash)
        .await
    {
        return json_response(StatusCode::BAD_REQUEST, json!({"ok": false, "error": err}));
    }
    if let Some(plan) = body.plan.filter(|plan| !plan.is_empty()) {
        if let Err(err) = apply_user_plan(&state, &body.username, &plan, false).await {
            return json_response(StatusCode::BAD_REQUEST, json!({"ok": false, "error": err}));
        }
    }
    json_response(StatusCode::OK, json!({"ok": true}))
}

async fn apply_user_plan(
    state: &AppState,
    username: &str,
    plan: &str,
    extend: bool,
) -> Result<(), String> {
    let user = state
        .db
        .find_user(username)
        .await
        .map_err(|err| err.to_string())?
        .ok_or_else(|| "No such user.".to_string())?;
    let applied = apply_plan(plan, user.start(), user.end(), extend, chrono::Utc::now())?;
    state
        .db
        .set_plan(username, &applied.id, &applied.label, applied.start, applied.end)
        .await
}

#[derive(Debug, Deserialize)]
struct UpdateBody {
    username: String,
    password: Option<String>,
    plan: Option<String>,
    extend: Option<bool>,
    active: Option<bool>,
    services: Option<String>,
}

async fn admin_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UpdateBody>,
) -> Response {
    if let Err(response) = require_admin(&state, &headers).await {
        return response;
    }
    if let Some(password) = body.password.filter(|password| !password.is_empty()) {
        if let Err(err) = state
            .db
            .set_password(&body.username, &password, state.fast_hash)
            .await
        {
            return json_response(StatusCode::BAD_REQUEST, json!({"ok": false, "error": err}));
        }
    }
    if let Some(active) = body.active {
        if let Err(err) = state.db.set_active(&body.username, active).await {
            return json_response(StatusCode::BAD_REQUEST, json!({"ok": false, "error": err}));
        }
    }
    if let Some(services) = body.services {
        if let Err(err) = state.db.set_services(&body.username, &services).await {
            return json_response(StatusCode::BAD_REQUEST, json!({"ok": false, "error": err}));
        }
    }
    if let Some(plan) = body.plan.filter(|plan| !plan.is_empty()) {
        if let Err(err) = apply_user_plan(&state, &body.username, &plan, body.extend.unwrap_or(false)).await {
            return json_response(StatusCode::BAD_REQUEST, json!({"ok": false, "error": err}));
        }
    }
    json_response(StatusCode::OK, json!({"ok": true}))
}

#[derive(Debug, Deserialize)]
struct NameBody {
    username: String,
}

async fn admin_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<NameBody>,
) -> Response {
    if let Err(response) = require_admin(&state, &headers).await {
        return response;
    }
    match state.db.delete_user(&body.username).await {
        Ok(()) => json_response(StatusCode::OK, json!({"ok": true})),
        Err(err) => json_response(StatusCode::BAD_REQUEST, json!({"ok": false, "error": err})),
    }
}

#[derive(Debug, Deserialize)]
struct PasswordBody {
    password: String,
}

async fn admin_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PasswordBody>,
) -> Response {
    if let Err(response) = require_admin(&state, &headers).await {
        return response;
    }
    if body.password.trim().len() < 8 {
        return json_response(StatusCode::BAD_REQUEST, json!({"ok": false, "error": "Use at least 8 characters."}));
    }
    if let Err(err) = state
        .db
        .set_admin_password(&body.password, state.fast_hash)
        .await
    {
        return json_response(StatusCode::INTERNAL_SERVER_ERROR, json!({"ok": false, "error": err}));
    }
    admin_logout().await
}

#[derive(Debug, Deserialize)]
struct ProxyBody {
    px: String,
    #[serde(default)]
    p: String,
    #[serde(default)]
    pu: String,
    #[serde(default)]
    pd: String,
}

async fn admin_proxy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ProxyBody>,
) -> Response {
    if let Err(response) = require_admin(&state, &headers).await {
        return response;
    }
    let proxy = SharedProxy {
        px: body.px,
        p: if body.p.is_empty() { "0".into() } else { body.p },
        pu: body.pu,
        pd: body.pd,
    };
    match state.db.set_shared_proxy(&proxy).await {
        Ok(()) => json_response(StatusCode::OK, json!({"ok": true, "proxy_url": proxy_endpoint(&proxy)})),
        Err(err) => json_response(StatusCode::INTERNAL_SERVER_ERROR, json!({"ok": false, "error": err})),
    }
}

#[derive(Debug, Deserialize)]
struct SettingsBody {
    allow_multi_screen: bool,
}

async fn admin_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SettingsBody>,
) -> Response {
    if let Err(response) = require_admin(&state, &headers).await {
        return response;
    }
    let flag = if body.allow_multi_screen { "true" } else { "false" };
    if let Err(err) = state.db.set_setting("allow_multi_screen", flag).await {
        return json_response(StatusCode::INTERNAL_SERVER_ERROR, json!({"ok": false, "error": err.to_string()}));
    }
    state.sessions.lock().await.set_multi(body.allow_multi_screen);
    json_response(StatusCode::OK, json!({"ok": true}))
}

#[derive(Debug, Deserialize)]
struct CookieBody {
    #[serde(default)]
    username: String,
    #[serde(default = "one_stream")]
    stream: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    store: Value,
    #[serde(default)]
    lst: String,
    #[serde(default)]
    sst: String,
}

fn one_stream() -> String {
    "one".into()
}

async fn admin_cookies(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CookieBody>,
) -> Response {
    if let Err(response) = require_admin(&state, &headers).await {
        return response;
    }
    let store = match body.store {
        Value::Array(items) => items,
        Value::String(text) => match serde_json::from_str(&text) {
            Ok(Value::Array(items)) => items,
            _ => return json_response(StatusCode::BAD_REQUEST, json!({"ok": false, "error": "store must be a JSON array of cookies."})),
        },
        Value::Null => Vec::new(),
        _ => return json_response(StatusCode::BAD_REQUEST, json!({"ok": false, "error": "store must be a JSON array of cookies."})),
    };
    let blob = StreamBlob {
        url: if body.url.is_empty() {
            "https://one.dat.com/search-loads".into()
        } else {
            body.url
        },
        store,
        lst: if body.lst.is_empty() { "{}".into() } else { body.lst },
        sst: body.sst,
    };
    let plain = match stream_plaintext(&blob) {
        Ok(plain) => plain,
        Err(err) => return json_response(StatusCode::BAD_REQUEST, json!({"ok": false, "error": err})),
    };
    let sealed = match seal_b64(&state.data_key, plain.as_bytes()) {
        Ok(sealed) => sealed,
        Err(err) => return json_response(StatusCode::INTERNAL_SERVER_ERROR, json!({"ok": false, "error": err.to_string()})),
    };
    let names = if body.username.trim().is_empty() {
        match state.db.usernames().await {
            Ok(names) => names,
            Err(err) => return json_response(StatusCode::INTERNAL_SERVER_ERROR, json!({"ok": false, "error": err.to_string()})),
        }
    } else {
        vec![body.username]
    };
    if names.is_empty() {
        return json_response(StatusCode::BAD_REQUEST, json!({"ok": false, "error": "Create a user before pushing cookies."}));
    }
    for name in &names {
        if let Err(err) = state.db.put_stream(name, &body.stream, &sealed).await {
            return json_response(StatusCode::BAD_REQUEST, json!({"ok": false, "error": err}));
        }
    }
    json_response(StatusCode::OK, json!({"ok": true, "users": names.len()}))
}

#[allow(dead_code)]
fn _status_name(status: AccountStatus) -> &'static str {
    status.as_str()
}
