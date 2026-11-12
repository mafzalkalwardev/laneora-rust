use std::time::Duration;

use laneora_core::{open_b64, open_salted, LEGACY_PASSPHRASE};
use laneora_server::{boot, router, Boot};
use serde_json::Value;
use tokio::net::TcpListener;

struct Running {
    base: String,
    key: [u8; 32],
}

async fn start() -> Running {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("laneora.sqlite");
    // Keep the directory alive for the process by leaking it. Tests are short.
    std::mem::forget(dir);
    let key = [9u8; 32];
    let state = boot(Boot {
        db_path: path,
        data_key: key,
        cookie_key: Some([3u8; 32]),
        fast_hash: true,
        admin_user: Some("admin".into()),
        admin_password: Some("admin-pass-1".into()),
    })
    .await
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    Running {
        base: format!("http://{addr}"),
        key,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

#[tokio::test]
async fn login_session_kick_and_legacy_authenticate() {
    let running = start().await;
    let http = client();

    let health = http
        .get(format!("{}/health", running.base))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(health["ok"], true);

    let bad = http
        .post(format!("{}/admin/api/login", running.base))
        .json(&serde_json::json!({"username": "admin", "password": "nope"}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 401);

    let login = http
        .post(format!("{}/admin/api/login", running.base))
        .json(&serde_json::json!({"username": "admin", "password": "admin-pass-1"}))
        .send()
        .await
        .unwrap();
    assert!(login.status().is_success());
    let cookie = login
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let created = http
        .post(format!("{}/admin/api/users", running.base))
        .header("cookie", &cookie)
        .json(&serde_json::json!({
            "username": "Ada",
            "password": "Secret1",
            "services": "dat_dual"
        }))
        .send()
        .await
        .unwrap();
    assert!(created.status().is_success(), "{created:?}");

    let pushed = http
        .post(format!("{}/admin/api/cookies", running.base))
        .header("cookie", &cookie)
        .json(&serde_json::json!({
            "username": "ada",
            "store": [{"name": "dat_one", "value": "abc", "domain": ".dat.com", "path": "/"}]
        }))
        .send()
        .await
        .unwrap();
    assert!(pushed.status().is_success(), "{pushed:?}");

    let dispatcher = http
        .post(format!("{}/api/login", running.base))
        .json(&serde_json::json!({"username": "ADA", "password": "secret1"}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(dispatcher["ok"], true);
    assert_eq!(dispatcher["services"][0], "dat_dual");
    let token = dispatcher["token"].as_str().unwrap();

    let session = http
        .post(format!("{}/api/session", running.base))
        .json(&serde_json::json!({"token": token}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let sealed = session["streams"]["one"].as_str().unwrap();
    let plain = open_b64(&running.key, sealed).unwrap();
    let jar: Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(jar["store"][0]["value"], "abc");

    let beat = http
        .post(format!("{}/logger", running.base))
        .json(&serde_json::json!({"token": token}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(beat["ok"], true);

    let second = http
        .post(format!("{}/api/login", running.base))
        .json(&serde_json::json!({"username": "ada", "password": "secret1"}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let new_token = second["token"].as_str().unwrap();
    let kicked = http
        .post(format!("{}/logger", running.base))
        .json(&serde_json::json!({"token": token}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(kicked["reason"], "kicked");
    let alive = http
        .post(format!("{}/logger", running.base))
        .json(&serde_json::json!({"token": new_token}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(alive["ok"], true);

    let legacy = http
        .get(format!(
            "{}/authenticate?username=ada&key=secret1&value=42&is_alive=7",
            running.base
        ))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(legacy["status"], "okie");
    let opened = open_salted(LEGACY_PASSPHRASE, legacy["one"].as_str().unwrap()).unwrap();
    assert!(opened.contains("abc"));
    let echo = http
        .get(format!("{}/logger?uva=ada:42:7", running.base))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    // authenticate registers this window as the primary session, so the echo is the value it sent.
    assert_eq!(echo, "42");

    let expired = http
        .post(format!("{}/admin/api/users/update", running.base))
        .header("cookie", &cookie)
        .json(&serde_json::json!({"username": "ada", "active": false}))
        .send()
        .await
        .unwrap();
    assert!(expired.status().is_success());
    let denied = http
        .post(format!("{}/api/login", running.base))
        .json(&serde_json::json!({"username": "ada", "password": "secret1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
}
