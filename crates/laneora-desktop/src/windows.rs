//! Windows launcher. Each DAT search is its own process so WebView2 gets a
//! separate user-data folder. The scrubber runs before the page loads.

use std::path::PathBuf;
use std::sync::Mutex;

use laneora_core::tab_count;
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

use crate::{dat_tab_command, LaneoraClient, SignedIn, SCRUBBER, SEARCH_URL};

struct Desktop {
    key: [u8; 32],
    server: Mutex<String>,
    signed_in: Mutex<Option<SignedIn>>,
    children: Mutex<Vec<std::process::Child>>,
}

#[derive(Clone, serde::Serialize)]
struct SignedInView {
    services: Vec<String>,
    proxy_url: Option<String>,
    subscription_end: Option<String>,
}

#[tauri::command]
async fn login(
    server: String,
    username: String,
    password: String,
    state: tauri::State<'_, Desktop>,
) -> Result<SignedInView, String> {
    let client = LaneoraClient::new(&server, state.key)?;
    let signed = client.login(&username, &password).await?;
    let view = SignedInView {
        services: signed.services.clone(),
        proxy_url: signed.proxy_url.clone(),
        subscription_end: signed.subscription_end.clone(),
    };
    *state.server.lock().expect("server") = server;
    *state.signed_in.lock().expect("session") = Some(signed);
    Ok(view)
}

#[tauri::command]
async fn open_search(service: String, state: tauri::State<'_, Desktop>) -> Result<usize, String> {
    let signed = state
        .signed_in
        .lock()
        .expect("session")
        .clone()
        .ok_or_else(|| "Sign in first.".to_string())?;
    if !signed.services.iter().any(|item| item == &service) {
        return Err("That module is not on this account.".into());
    }
    let server = state.server.lock().expect("server").clone();
    let client = LaneoraClient::new(server, state.key)?;
    let opened = client.session(&signed.token).await?;
    let count = tab_count(&service);
    let exe = std::env::current_exe().map_err(|err| err.to_string())?;
    let root = profile_root();
    let mut children = state.children.lock().expect("children");
    for index in 0..count {
        let profile = root.join(format!("search-{}", index + 1));
        std::fs::create_dir_all(&profile).map_err(|err| err.to_string())?;
        let payload = serde_json::to_string(&opened.streams).map_err(|err| err.to_string())?;
        std::fs::write(profile.join("session.json"), payload).map_err(|err| err.to_string())?;
        let mut child = dat_tab_command(&exe, &profile, SEARCH_URL, signed.proxy_url.as_deref());
        children.push(child.spawn().map_err(|err| err.to_string())?);
    }
    Ok(count)
}

#[tauri::command]
fn close_search(state: tauri::State<'_, Desktop>) {
    if let Ok(mut children) = state.children.lock() {
        for child in children.iter_mut() {
            let _ = child.kill();
        }
        children.clear();
    }
}

fn profile_root() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("LaneoraRust").join("profiles")
}

pub fn run() {
    let key = client_key();
    tauri::Builder::default()
        .manage(Desktop {
            key,
            server: Mutex::new(
                std::env::var("LANEORA_SERVER_URL")
                    .unwrap_or_else(|_| "https://laneora.induswebagency.com".into()),
            ),
            signed_in: Mutex::new(None),
            children: Mutex::new(Vec::new()),
        })
        .invoke_handler(tauri::generate_handler![login, open_search, close_search])
        .setup(|app| {
            if std::env::args().any(|arg| arg == "--dat-tab") {
                if let Some(main) = app.get_webview_window("main") {
                    let _ = main.hide();
                }
                open_dat_window(app.handle())?;
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("Laneora Rust window");
}

fn open_dat_window(app: &tauri::AppHandle) -> tauri::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(3).cloned().unwrap_or_else(|| SEARCH_URL.to_string());
    let window = WebviewWindowBuilder::new(app, "dat", WebviewUrl::External(url.parse().unwrap()))
        .title("DAT Search")
        .inner_size(1280.0, 860.0)
        .initialization_script(SCRUBBER)
        .build()?;
    if let Some(profile) = args.get(2) {
        let session_path = PathBuf::from(profile).join("session.json");
        if let Ok(raw) = std::fs::read_to_string(session_path) {
            let _ = window.eval(local_storage_bootstrap(&raw));
        }
    }
    Ok(())
}

fn local_storage_bootstrap(session_json: &str) -> String {
    format!(
        "window.__laneoraSession = {session_json};"
    )
}

fn client_key() -> [u8; 32] {
    let raw = std::env::var("LANEORA_DATA_KEY").unwrap_or_else(|_| {
        option_env!("LANEORA_DATA_KEY").unwrap_or("").to_string()
    });
    laneora_core::parse_data_key(&raw).unwrap_or([0u8; 32])
}
