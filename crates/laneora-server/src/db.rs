use std::path::{Path, PathBuf};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use chrono::{DateTime, Utc};
use laneora_core::{
    format_utc, normalize_services, open_salted, parse_utc, seal_b64, SharedProxy, StreamBlob,
    LEGACY_PASSPHRASE,
};
use rand::rngs::OsRng;
use serde::Deserialize;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::Row;

const MIGRATION: &str = include_str!("../migrations/001_init.sql");

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub active: i64,
    pub plan_id: Option<String>,
    pub plan_label: Option<String>,
    pub subscription_start: Option<String>,
    pub subscription_end: Option<String>,
    pub services: String,
}

impl UserRow {
    pub fn is_active(&self) -> bool {
        self.active != 0
    }

    pub fn end(&self) -> Option<DateTime<Utc>> {
        self.subscription_end.as_deref().and_then(parse_utc)
    }

    pub fn start(&self) -> Option<DateTime<Utc>> {
        self.subscription_start.as_deref().and_then(parse_utc)
    }
}

#[derive(Clone)]
pub struct Db {
    pool: SqlitePool,
}

impl Db {
    pub async fn connect(path: &Path) -> Result<Self, sqlx::Error> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .after_connect(|conn, _| {
                Box::pin(async move {
                    sqlx::query("PRAGMA journal_mode = WAL")
                        .execute(&mut *conn)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await?;
        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::raw_sql(MIGRATION).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn get_setting(&self, key: &str) -> Result<Option<String>, sqlx::Error> {
        let row = sqlx::query("SELECT value FROM settings WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| row.get("value")))
    }

    pub async fn set_setting(&self, key: &str, value: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES (?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn ensure_admin(&self, username: &str, password: &str, fast: bool) -> Result<(), String> {
        if self.get_setting("admin_password_hash").await.map_err(|err| err.to_string())?.is_some() {
            return Ok(());
        }
        let hash = hash_password(password, fast)?;
        self.set_setting("admin_username", username.trim())
            .await
            .map_err(|err| err.to_string())?;
        self.set_setting("admin_password_hash", &hash)
            .await
            .map_err(|err| err.to_string())?;
        if self.get_setting("admin_epoch").await.map_err(|err| err.to_string())?.is_none() {
            self.set_setting("admin_epoch", "1")
                .await
                .map_err(|err| err.to_string())?;
        }
        Ok(())
    }

    pub async fn admin_epoch(&self) -> Result<String, sqlx::Error> {
        Ok(self.get_setting("admin_epoch").await?.unwrap_or_else(|| "1".into()))
    }

    pub async fn verify_admin(&self, username: &str, password: &str) -> Result<bool, sqlx::Error> {
        let Some(stored_user) = self.get_setting("admin_username").await? else {
            return Ok(false);
        };
        let Some(hash) = self.get_setting("admin_password_hash").await? else {
            return Ok(false);
        };
        Ok(stored_user == username.trim() && verify_password(password, &hash))
    }

    pub async fn set_admin_password(&self, password: &str, fast: bool) -> Result<(), String> {
        let hash = hash_password(password, fast)?;
        let epoch: i64 = self
            .admin_epoch()
            .await
            .map_err(|err| err.to_string())?
            .parse()
            .unwrap_or(1);
        self.set_setting("admin_password_hash", &hash)
            .await
            .map_err(|err| err.to_string())?;
        self.set_setting("admin_epoch", &(epoch + 1).to_string())
            .await
            .map_err(|err| err.to_string())?;
        Ok(())
    }

    pub async fn user_count(&self) -> Result<i64, sqlx::Error> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM users")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get("n"))
    }

    pub async fn list_users(&self) -> Result<Vec<UserRow>, sqlx::Error> {
        sqlx::query_as::<_, UserRow>(
            "SELECT id, username, password_hash, active, plan_id, plan_label,
                    subscription_start, subscription_end, services
             FROM users ORDER BY username",
        )
        .fetch_all(&self.pool)
        .await
    }

    pub async fn find_user(&self, username: &str) -> Result<Option<UserRow>, sqlx::Error> {
        sqlx::query_as::<_, UserRow>(
            "SELECT id, username, password_hash, active, plan_id, plan_label,
                    subscription_start, subscription_end, services
             FROM users WHERE username = ?",
        )
        .bind(normalize_username(username))
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        services: &str,
        fast: bool,
    ) -> Result<(), String> {
        let username = normalize_username(username);
        if username.is_empty() {
            return Err("Username is required.".into());
        }
        let services = normalize_services(services).join(",");
        let hash = hash_password(&dispatcher_secret(password), fast)?;
        let now = format_utc(Utc::now());
        let result = sqlx::query(
            "INSERT INTO users (username, password_hash, active, services, created_at)
             VALUES (?, ?, 1, ?, ?)",
        )
        .bind(username)
        .bind(hash)
        .bind(services)
        .bind(now)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(err)) if err.message().contains("UNIQUE") => {
                Err("That username already exists.".into())
            }
            Err(err) => Err(err.to_string()),
        }
    }

    pub async fn set_password(&self, username: &str, password: &str, fast: bool) -> Result<(), String> {
        let hash = hash_password(&dispatcher_secret(password), fast)?;
        let changed = sqlx::query("UPDATE users SET password_hash = ? WHERE username = ?")
            .bind(hash)
            .bind(normalize_username(username))
            .execute(&self.pool)
            .await
            .map_err(|err| err.to_string())?;
        if changed.rows_affected() == 0 {
            return Err("No such user.".into());
        }
        Ok(())
    }

    pub async fn set_active(&self, username: &str, active: bool) -> Result<(), String> {
        let changed = sqlx::query("UPDATE users SET active = ? WHERE username = ?")
            .bind(if active { 1 } else { 0 })
            .bind(normalize_username(username))
            .execute(&self.pool)
            .await
            .map_err(|err| err.to_string())?;
        if changed.rows_affected() == 0 {
            return Err("No such user.".into());
        }
        Ok(())
    }

    pub async fn set_services(&self, username: &str, services: &str) -> Result<(), String> {
        let services = laneora_core::require_services(services)?.join(",");
        let changed = sqlx::query("UPDATE users SET services = ? WHERE username = ?")
            .bind(services)
            .bind(normalize_username(username))
            .execute(&self.pool)
            .await
            .map_err(|err| err.to_string())?;
        if changed.rows_affected() == 0 {
            return Err("No such user.".into());
        }
        Ok(())
    }

    pub async fn set_plan(
        &self,
        username: &str,
        plan_id: &str,
        label: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<(), String> {
        let changed = sqlx::query(
            "UPDATE users
             SET plan_id = ?, plan_label = ?, subscription_start = ?, subscription_end = ?, active = 1
             WHERE username = ?",
        )
        .bind(plan_id)
        .bind(label)
        .bind(format_utc(start))
        .bind(format_utc(end))
        .bind(normalize_username(username))
        .execute(&self.pool)
        .await
        .map_err(|err| err.to_string())?;
        if changed.rows_affected() == 0 {
            return Err("No such user.".into());
        }
        Ok(())
    }

    pub async fn delete_user(&self, username: &str) -> Result<(), String> {
        let changed = sqlx::query("DELETE FROM users WHERE username = ?")
            .bind(normalize_username(username))
            .execute(&self.pool)
            .await
            .map_err(|err| err.to_string())?;
        if changed.rows_affected() == 0 {
            return Err("No such user.".into());
        }
        Ok(())
    }

    pub async fn put_stream(
        &self,
        username: &str,
        name: &str,
        sealed: &str,
    ) -> Result<(), String> {
        let user = self
            .find_user(username)
            .await
            .map_err(|err| err.to_string())?
            .ok_or_else(|| "No such user.".to_string())?;
        sqlx::query(
            "INSERT INTO streams (user_id, name, sealed) VALUES (?, ?, ?)
             ON CONFLICT(user_id, name) DO UPDATE SET sealed = excluded.sealed",
        )
        .bind(user.id)
        .bind(name)
        .bind(sealed)
        .execute(&self.pool)
        .await
        .map_err(|err| err.to_string())?;
        Ok(())
    }

    pub async fn streams_for(&self, user_id: i64) -> Result<Vec<(String, String)>, sqlx::Error> {
        let rows = sqlx::query("SELECT name, sealed FROM streams WHERE user_id = ?")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| (row.get("name"), row.get("sealed")))
            .collect())
    }

    pub async fn usernames(&self) -> Result<Vec<String>, sqlx::Error> {
        let rows = sqlx::query("SELECT username FROM users ORDER BY username")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|row| row.get("username")).collect())
    }

    pub async fn shared_proxy(&self) -> Result<SharedProxy, sqlx::Error> {
        Ok(self
            .get_setting("shared_proxy")
            .await?
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default())
    }

    pub async fn set_shared_proxy(&self, proxy: &SharedProxy) -> Result<(), String> {
        let raw = serde_json::to_string(proxy).map_err(|err| err.to_string())?;
        self.set_setting("shared_proxy", &raw)
            .await
            .map_err(|err| err.to_string())
    }

    pub async fn import_users(&self, path: &Path, key: &[u8; 32], fast: bool) -> Result<usize, String> {
        let text = std::fs::read_to_string(path).map_err(|err| err.to_string())?;
        let file: ImportFile = serde_json::from_str(&text).map_err(|err| err.to_string())?;
        let mut count = 0;
        for user in file.users {
            let username = normalize_username(&user.username);
            if username.is_empty() {
                continue;
            }
            if self.find_user(&username).await.map_err(|err| err.to_string())?.is_none() {
                self.create_user(&username, &user.password, &services_of(&user), fast)
                    .await?;
            }
            if let Some(active) = user.active {
                self.set_active(&username, active).await?;
            }
            if let (Some(plan), Some(label), Some(start), Some(end)) = (
                user.plan.as_deref(),
                user.plan_label.as_deref(),
                user.subscription_start.as_deref().and_then(parse_utc),
                user.subscription_end.as_deref().and_then(parse_utc),
            ) {
                self.set_plan(&username, plan, label, start, end).await?;
            }
            if let Some(services) = user.services.as_ref().and_then(|value| services_text(value)) {
                let _ = self.set_services(&username, &services).await;
            }
            if let Some(streams) = user.streams {
                for (name, value) in streams {
                    let plain = stream_plain(&value)?;
                    let sealed = seal_b64(key, plain.as_bytes()).map_err(|err| err.to_string())?;
                    self.put_stream(&username, &name, &sealed).await?;
                }
            }
            count += 1;
        }
        Ok(count)
    }
}

fn services_of(user: &ImportUser) -> String {
    user.services
        .as_ref()
        .and_then(|value| services_text(value))
        .unwrap_or_else(|| "dat".into())
}

fn services_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Array(items) => Some(
            items
                .iter()
                .filter_map(|item| item.as_str())
                .collect::<Vec<_>>()
                .join(","),
        ),
        _ => None,
    }
}

fn stream_plain(value: &serde_json::Value) -> Result<String, String> {
    match value {
        serde_json::Value::String(text) => {
            if let Ok(plain) = open_salted(LEGACY_PASSPHRASE, text) {
                Ok(plain)
            } else {
                Ok(text.clone())
            }
        }
        other => {
            let mut owned = other.clone();
            if let Some(map) = owned.as_object_mut() {
                if let Some(lst) = map.get("lst").cloned() {
                    if !lst.is_string() {
                        map.insert("lst".into(), serde_json::Value::String(lst.to_string()));
                    }
                }
            }
            let blob: StreamBlob = serde_json::from_value(owned).unwrap_or_default();
            serde_json::to_string(&blob).map_err(|err| err.to_string())
        }
    }
}

pub fn hash_password(password: &str, fast: bool) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let hasher = if fast {
        let params = Params::new(8 * 1024, 1, 1, None).map_err(|err| err.to_string())?;
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    } else {
        Argon2::default()
    };
    hasher
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| err.to_string())
}

pub fn verify_password(password: &str, encoded: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub fn dispatcher_secret(password: &str) -> String {
    password.trim().to_lowercase()
}

pub fn normalize_username(username: &str) -> String {
    username.trim().to_ascii_lowercase()
}

pub fn default_db_path() -> PathBuf {
    std::env::var_os("LANEORA_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("laneora.sqlite"))
}

#[derive(Debug, Deserialize)]
struct ImportFile {
    users: Vec<ImportUser>,
}

#[derive(Debug, Deserialize)]
struct ImportUser {
    username: String,
    #[serde(default)]
    password: String,
    active: Option<bool>,
    plan: Option<String>,
    plan_label: Option<String>,
    subscription_start: Option<String>,
    subscription_end: Option<String>,
    services: Option<serde_json::Value>,
    streams: Option<serde_json::Map<String, serde_json::Value>>,
}

pub fn stream_plaintext(blob: &StreamBlob) -> Result<String, String> {
    serde_json::to_string(blob).map_err(|err| err.to_string())
}
