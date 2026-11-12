use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SERVICES: &[ServiceInfo] = &[
    ServiceInfo {
        id: "dat",
        label: "DAT Search",
        description: "One DAT One search screen.",
        tabs: 1,
    },
    ServiceInfo {
        id: "dat_dual",
        label: "Dual DAT Search",
        description: "Two DAT search tabs. Searches stay separate.",
        tabs: 2,
    },
    ServiceInfo {
        id: "dat_3",
        label: "3 DAT Search",
        description: "Three DAT search tabs. Searches stay separate.",
        tabs: 3,
    },
    ServiceInfo {
        id: "dat_4",
        label: "4 DAT Search",
        description: "Four DAT search tabs. Searches stay separate.",
        tabs: 4,
    },
];

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ServiceInfo {
    pub id: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    pub tabs: u8,
}

pub fn tab_count(service_id: &str) -> usize {
    SERVICES
        .iter()
        .find(|service| service.id == service_id)
        .map(|service| service.tabs as usize)
        .unwrap_or(1)
}

pub fn normalize_services(raw: &str) -> Vec<String> {
    let chosen: Vec<&str> = raw
        .split(|ch: char| ch == ',' || ch.is_whitespace())
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();
    let found: Vec<String> = SERVICES
        .iter()
        .filter(|service| chosen.iter().any(|id| *id == service.id))
        .map(|service| service.id.to_string())
        .collect();
    if found.is_empty() {
        vec!["dat".to_string()]
    } else {
        found
    }
}

pub fn require_services(raw: &str) -> Result<Vec<String>, String> {
    let parts: Vec<&str> = raw
        .split(|ch: char| ch == ',' || ch.is_whitespace())
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        return Err("Assign at least one service.".into());
    }
    for part in &parts {
        if !SERVICES.iter().any(|service| service.id == *part) {
            let known = SERVICES
                .iter()
                .map(|service| service.id)
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!("Unknown service '{part}'. Use one of: {known}"));
        }
    }
    Ok(normalize_services(&parts.join(",")))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedProxy {
    #[serde(default = "none_host")]
    pub px: String,
    #[serde(default = "zero_port")]
    pub p: String,
    #[serde(default)]
    pub pu: String,
    #[serde(default)]
    pub pd: String,
}

fn none_host() -> String {
    "none".to_string()
}

fn zero_port() -> String {
    "0".to_string()
}

impl Default for SharedProxy {
    fn default() -> Self {
        Self {
            px: none_host(),
            p: zero_port(),
            pu: String::new(),
            pd: String::new(),
        }
    }
}

impl SharedProxy {
    pub fn is_direct(&self) -> bool {
        proxy_endpoint(self).is_none()
    }
}

pub fn proxy_endpoint(proxy: &SharedProxy) -> Option<String> {
    let host = proxy.px.trim();
    let lowered = host.to_ascii_lowercase();
    if host.is_empty() || matches!(lowered.as_str(), "none" | "direct" | "off" | "0") {
        return None;
    }
    let port = proxy.p.trim();
    let port = if port.is_empty() || port == "0" {
        "8888"
    } else {
        port
    };
    let auth = if proxy.pu.is_empty() {
        String::new()
    } else {
        format!("{}:{}@", encode_userinfo(&proxy.pu), encode_userinfo(&proxy.pd))
    };
    Some(format!("http://{auth}{host}:{port}"))
}

fn encode_userinfo(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamBlob {
    pub url: String,
    #[serde(default)]
    pub store: Vec<Value>,
    #[serde(default = "empty_object")]
    pub lst: String,
    #[serde(default)]
    pub sst: String,
}

fn empty_object() -> String {
    "{}".to_string()
}

impl Default for StreamBlob {
    fn default() -> Self {
        Self {
            url: "https://one.dat.com/search-loads".to_string(),
            store: Vec::new(),
            lst: empty_object(),
            sst: String::new(),
        }
    }
}

pub fn local_storage_script(lst: &str) -> Result<String, String> {
    let value: Value = serde_json::from_str(lst).map_err(|_| "lst is not JSON".to_string())?;
    let Value::Object(_) = value else {
        return Err("lst must be a JSON object".into());
    };
    Ok(format!(
        "(() => {{ const items = {value}; for (const key of Object.keys(items)) {{ localStorage.setItem(key, items[key] == null ? '' : String(items[key])); }} }})();"
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatReport {
    Alive,
    Kicked,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_services_fall_back_to_dat() {
        assert_eq!(normalize_services(""), vec!["dat".to_string()]);
        assert_eq!(
            normalize_services("dat_4,nope,dat"),
            vec!["dat".to_string(), "dat_4".to_string()]
        );
    }

    #[test]
    fn proxy_url_skips_direct_and_encodes_password() {
        assert!(proxy_endpoint(&SharedProxy::default()).is_none());
        let proxy = SharedProxy {
            px: "89.168.127.135".into(),
            p: "8888".into(),
            pu: "laneora".into(),
            pd: "a b@c".into(),
        };
        assert_eq!(
            proxy_endpoint(&proxy).as_deref(),
            Some("http://laneora:a%20b%40c@89.168.127.135:8888")
        );
    }

    #[test]
    fn tab_counts_match_the_modules() {
        assert_eq!(tab_count("dat"), 1);
        assert_eq!(tab_count("dat_dual"), 2);
        assert_eq!(tab_count("dat_4"), 4);
    }
}
