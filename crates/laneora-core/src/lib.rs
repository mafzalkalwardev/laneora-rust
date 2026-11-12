//! Shared types for the Laneora Rust server, desktop client, and proxy.

mod crypto;
mod legacy;
mod models;
mod plans;

pub use crypto::{open, open_b64, parse_data_key, seal, seal_b64, CryptoError};
pub use legacy::{open_salted, seal_salted, LEGACY_PASSPHRASE};
pub use models::{
    local_storage_script, normalize_services, proxy_endpoint, require_services, tab_count,
    HeartbeatReport, LoginRequest, ServiceInfo, SharedProxy, StreamBlob, SERVICES,
};
pub use plans::{
    account_status, apply_plan, denial_message, format_utc, parse_utc, plan_by_id, plan_catalog,
    AccountStatus, AppliedPlan, Plan,
};
