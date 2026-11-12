use anyhow::Context;
use laneora_server::{boot, load_data_key, router, Boot};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "laneora_server=info".into()),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let command = args.next();
    let fast_hash = std::env::var("LANEORA_FAST_HASH").ok().as_deref() == Some("1");
    let data_key = load_data_key()?;
    let state = boot(Boot {
        db_path: laneora_server::default_db_path(),
        data_key,
        cookie_key: None,
        fast_hash,
        admin_user: std::env::var("LANEORA_ADMIN_USER").ok(),
        admin_password: std::env::var("LANEORA_ADMIN_PASSWORD").ok(),
    })
    .await?;

    if command.as_deref() == Some("import-users") {
        let path = args
            .next()
            .context("usage: laneora-server import-users FILE")?;
        let count = state
            .db
            .import_users(std::path::Path::new(&path), &state.data_key, state.fast_hash)
            .await
            .map_err(anyhow::Error::msg)?;
        println!("imported {count} users");
        return Ok(());
    }

    let bind = std::env::var("LANEORA_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let listener = TcpListener::bind(&bind)
        .await
        .with_context(|| format!("bind {bind}"))?;
    tracing::info!("Laneora Rust server on http://{bind}");
    axum::serve(listener, router(state)).await?;
    Ok(())
}
