use std::sync::Arc;
use std::time::Duration;

use laneora_proxy::{basic_token, dial, handle_proxy, watchdog, DialFut};
use tokio::net::TcpListener;
use tracing::{info, warn};

#[derive(Clone)]
struct Config {
    bind: String,
    auth_b64: String,
    iface: String,
    token: Option<String>,
    chat: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "laneora_proxy=info".into()),
        )
        .init();

    let user = std::env::var("PROXY_USER").unwrap_or_default();
    let pass = std::env::var("PROXY_PASS").unwrap_or_default();
    if user.is_empty() || pass.is_empty() {
        return Err("Set PROXY_USER and PROXY_PASS".into());
    }
    let cfg = Arc::new(Config {
        bind: std::env::var("PROXY_BIND").unwrap_or_else(|_| "0.0.0.0:8888".into()),
        auth_b64: basic_token(&user, &pass),
        iface: std::env::var("WG_IFACE").unwrap_or_else(|_| "wg0".into()),
        token: std::env::var("TG_BOT_TOKEN").ok().filter(|value| !value.is_empty()),
        chat: std::env::var("TG_CHAT_ID").ok().filter(|value| !value.is_empty()),
    });

    let watchdog_cfg = cfg.clone();
    tokio::spawn(async move {
        watchdog::run(
            watchdog_cfg.iface.clone(),
            watchdog_cfg.token.clone(),
            watchdog_cfg.chat.clone(),
            Duration::from_secs(300),
        )
        .await;
    });

    let listener = TcpListener::bind(&cfg.bind).await?;
    info!(
        "Laneora Rust proxy on {} locked to {}",
        cfg.bind, cfg.iface
    );
    loop {
        let (client, peer) = listener.accept().await?;
        let cfg = cfg.clone();
        tokio::spawn(async move {
            let iface = cfg.iface.clone();
            let dialer = move |target: String| -> DialFut {
                let iface = iface.clone();
                Box::pin(async move { dial::dial_via(&target, &iface).await })
            };
            if let Err(err) = handle_proxy(client, &cfg.auth_b64, dialer).await {
                warn!("client {peer} closed: {err}");
            }
        });
    }
}
