use std::time::Duration;

use serde::Deserialize;
use tracing::{error, info};

use crate::{ip_change_message, tunnel_down_message};

#[derive(Debug, Clone, Deserialize)]
pub struct IpInfo {
    pub ip: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub country: String,
}

/// Check the address seen through `iface` on a timer.
/// Telegram, when configured, uses the normal route so a dead tunnel can still notify.
pub async fn run(iface: String, token: Option<String>, chat: Option<String>, every: Duration) {
    let mut previous = String::new();
    loop {
        match read_ipinfo(&iface).await {
            Ok(info) => {
                if let Some(message) =
                    ip_change_message(&mut previous, &info.ip, &info.city, &info.country)
                {
                    info!("{message}");
                    notify(&token, &chat, &message).await;
                }
            }
            Err(err) => {
                let message = tunnel_down_message(&err.to_string());
                error!("{message}");
                notify(&token, &chat, &message).await;
            }
        }
        tokio::time::sleep(every).await;
    }
}

async fn read_ipinfo(iface: &str) -> std::io::Result<IpInfo> {
    let stream = crate::dial::dial_via("ipinfo.io:443", iface).await?;
    // The CONNECT proxy does not terminate TLS. The watchdog asks the system
    // curl to speak HTTPS on the same interface so the check cannot leave wg0.
    let _ = stream;
    let output = tokio::process::Command::new("curl")
        .args([
            "--interface",
            iface,
            "--max-time",
            "10",
            "--fail",
            "--silent",
            "https://ipinfo.io/json",
        ])
        .output()
        .await
        .map_err(|err| std::io::Error::other(err))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(std::io::Error::other(format!(
            "ipinfo via {iface} failed: {stderr}"
        )));
    }
    serde_json::from_slice(&output.stdout).map_err(|err| std::io::Error::other(err))
}

async fn notify(token: &Option<String>, chat: &Option<String>, text: &str) {
    let (Some(token), Some(chat)) = (token, chat) else {
        return;
    };
    if token.is_empty() || chat.is_empty() {
        return;
    }
    let url = format!("https://api.telegram.org/bot{token}/sendMessage");
    let body = serde_json::json!({"chat_id": chat, "text": text}).to_string();
    let _ = tokio::process::Command::new("curl")
        .args([
            "--max-time",
            "10",
            "--silent",
            "--show-error",
            "-X",
            "POST",
            "-H",
            "content-type: application/json",
            "--data",
            &body,
            &url,
        ])
        .output()
        .await;
}
