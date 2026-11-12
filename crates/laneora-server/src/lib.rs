//! Laneora Rust session server.

mod db;
mod http;
mod sessions;

use std::path::PathBuf;
use std::sync::Arc;

use laneora_core::parse_data_key;
use rand::RngCore;
use tokio::sync::Mutex;

pub use db::{default_db_path, dispatcher_secret, normalize_username, Db};
pub use http::router;
pub use sessions::Sessions;

pub const VERSION: &str = "0.1.0";
/// Reported to the Python client so it does not try to replace itself.
pub const COMPAT_VERSION: &str = "3.0.0";

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub sessions: Arc<Mutex<Sessions>>,
    pub data_key: [u8; 32],
    pub cookie_key: [u8; 32],
    pub fast_hash: bool,
}

pub struct Boot {
    pub db_path: PathBuf,
    pub data_key: [u8; 32],
    pub cookie_key: Option<[u8; 32]>,
    pub fast_hash: bool,
    pub admin_user: Option<String>,
    pub admin_password: Option<String>,
}

pub async fn boot(config: Boot) -> Result<AppState, anyhow::Error> {
    let db = Db::connect(&config.db_path).await?;
    if let (Some(user), Some(password)) = (&config.admin_user, &config.admin_password) {
        db.ensure_admin(user, password, config.fast_hash)
            .await
            .map_err(anyhow::Error::msg)?;
    }
    let cookie_key = match config.cookie_key {
        Some(key) => key,
        None => load_or_create_cookie_key(&db).await?,
    };
    let multi = matches!(
        db.get_setting("allow_multi_screen").await?.as_deref(),
        Some("true") | Some("1")
    );
    let mut sessions = Sessions::default();
    sessions.set_multi(multi);
    Ok(AppState {
        db,
        sessions: Arc::new(Mutex::new(sessions)),
        data_key: config.data_key,
        cookie_key,
        fast_hash: config.fast_hash,
    })
}

async fn load_or_create_cookie_key(db: &Db) -> Result<[u8; 32], anyhow::Error> {
    if let Some(saved) = db.get_setting("cookie_secret").await? {
        if let Ok(key) = parse_data_key(&saved) {
            return Ok(key);
        }
    }
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    db.set_setting("cookie_secret", &hex::encode(key)).await?;
    Ok(key)
}

pub fn load_data_key() -> Result<[u8; 32], anyhow::Error> {
    if let Ok(raw) = std::env::var("LANEORA_DATA_KEY") {
        return parse_data_key(&raw).map_err(|err| anyhow::anyhow!(err.to_string()));
    }
    let path = std::env::var("LANEORA_KEY_FILE").unwrap_or_else(|_| "laneora.key".into());
    let path = PathBuf::from(path);
    if path.exists() {
        let raw = std::fs::read_to_string(&path)?;
        return parse_data_key(&raw).map_err(|err| anyhow::anyhow!(err.to_string()));
    }
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&path, hex::encode(key))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    tracing::info!("wrote a new data key to {}", path.display());
    Ok(key)
}
