use laneora_core::{open_b64, HeartbeatReport, LoginRequest, StreamBlob};
use serde::Deserialize;
use serde_json::Value;

#[derive(Clone)]
pub struct LaneoraClient {
    base: String,
    key: [u8; 32],
    http: reqwest::Client,
}

#[derive(Debug, Clone)]
pub struct SignedIn {
    pub token: String,
    pub services: Vec<String>,
    pub proxy_url: Option<String>,
    pub subscription_end: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OpenedSession {
    pub streams: Vec<(String, StreamBlob)>,
    pub services: Vec<String>,
    pub proxy_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginResponse {
    ok: bool,
    token: Option<String>,
    services: Option<Vec<String>>,
    proxy_url: Option<String>,
    subscription_end: Option<String>,
    error: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SessionResponse {
    ok: bool,
    streams: Option<std::collections::HashMap<String, String>>,
    services: Option<Vec<String>>,
    proxy_url: Option<String>,
    error: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BeatResponse {
    ok: bool,
    reason: Option<String>,
}

impl LaneoraClient {
    pub fn new(base: impl Into<String>, key: [u8; 32]) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|err| err.to_string())?;
        Ok(Self {
            base: base.into().trim_end_matches('/').to_string(),
            key,
            http,
        })
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<SignedIn, String> {
        let response = self
            .http
            .post(format!("{}/api/login", self.base))
            .json(&LoginRequest {
                username: username.to_string(),
                password: password.to_string(),
            })
            .send()
            .await
            .map_err(|err| err.to_string())?;
        let body: LoginResponse = response.json().await.map_err(|err| err.to_string())?;
        if !body.ok {
            return Err(body
                .error
                .or(body.reason)
                .unwrap_or_else(|| "Login failed".into()));
        }
        Ok(SignedIn {
            token: body.token.ok_or_else(|| "missing token".to_string())?,
            services: body.services.unwrap_or_else(|| vec!["dat".into()]),
            proxy_url: body.proxy_url,
            subscription_end: body.subscription_end,
        })
    }

    pub async fn session(&self, token: &str) -> Result<OpenedSession, String> {
        let response = self
            .http
            .post(format!("{}/api/session", self.base))
            .json(&serde_json::json!({"token": token}))
            .send()
            .await
            .map_err(|err| err.to_string())?;
        let body: SessionResponse = response.json().await.map_err(|err| err.to_string())?;
        if !body.ok {
            if body.reason.as_deref() == Some("kicked") {
                return Err("kicked".into());
            }
            return Err(body.error.unwrap_or_else(|| "No session".into()));
        }
        let mut streams = Vec::new();
        for (name, sealed) in body.streams.unwrap_or_default() {
            let plain = open_b64(&self.key, &sealed).map_err(|err| err.to_string())?;
            let blob: StreamBlob = serde_json::from_slice(&plain).map_err(|err| err.to_string())?;
            streams.push((name, blob));
        }
        Ok(OpenedSession {
            streams,
            services: body.services.unwrap_or_else(|| vec!["dat".into()]),
            proxy_url: body.proxy_url,
        })
    }

    pub async fn heartbeat(&self, token: &str) -> Result<HeartbeatReport, String> {
        let response = self
            .http
            .post(format!("{}/logger", self.base))
            .json(&serde_json::json!({"token": token}))
            .send()
            .await
            .map_err(|err| err.to_string())?;
        let body: BeatResponse = response.json().await.map_err(|err| err.to_string())?;
        Ok(heartbeat_decision(body.ok, body.reason.as_deref()))
    }
}

pub fn heartbeat_decision(ok: bool, reason: Option<&str>) -> HeartbeatReport {
    if ok && reason != Some("kicked") {
        HeartbeatReport::Alive
    } else {
        HeartbeatReport::Kicked
    }
}

#[allow(dead_code)]
pub fn cookie_script(store: &Value) -> String {
    let _ = store;
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use laneora_server::{boot, router, Boot};
    use tokio::net::TcpListener;

    #[test]
    fn kick_decision() {
        assert_eq!(heartbeat_decision(true, None), HeartbeatReport::Alive);
        assert_eq!(
            heartbeat_decision(false, Some("kicked")),
            HeartbeatReport::Kicked
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_opens_a_sealed_session() {
        let dir = tempfile::tempdir().unwrap();
        let key = [4u8; 32];
        let state = boot(Boot {
            db_path: dir.path().join("t.sqlite"),
            data_key: key,
            cookie_key: Some([1u8; 32]),
            fast_hash: true,
            admin_user: Some("admin".into()),
            admin_password: Some("admin-pass-1".into()),
        })
        .await
        .unwrap();
        state
            .db
            .create_user("ada", "Secret1", "dat", true)
            .await
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });
        let client = LaneoraClient::new(format!("http://{addr}"), key).unwrap();
        let signed = client.login("ada", "secret1").await.unwrap();
        assert_eq!(signed.services, vec!["dat".to_string()]);
        let opened = client.session(&signed.token).await.unwrap();
        assert!(opened.streams.iter().any(|(name, _)| name == "one"));
        assert_eq!(
            client.heartbeat(&signed.token).await.unwrap(),
            HeartbeatReport::Alive
        );
    }
}
