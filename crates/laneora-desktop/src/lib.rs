//! Laneora Rust desktop protocol client.
//!
//! The window shell is Windows-only (Tauri + WebView2). Login, session
//! unsealing, the scrubber, and the kick decision are tested on every OS.

mod client;

pub use client::{heartbeat_decision, LaneoraClient, OpenedSession, SignedIn};
pub use laneora_core::{local_storage_script, tab_count, HeartbeatReport};

pub const SCRUBBER: &str = include_str!("scrub.js");
pub const SEARCH_URL: &str = "https://one.dat.com/search-loads";
pub const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";

#[cfg(all(windows, not(test)))]
mod windows;

#[cfg(all(windows, not(test)))]
pub fn windows_main() {
    windows::run();
}

pub fn profile_dir(root: &std::path::Path, index: usize) -> std::path::PathBuf {
    root.join(format!("search-{}", index + 1))
}

pub fn dat_tab_command(
    exe: &std::path::Path,
    profile: &std::path::Path,
    url: &str,
    proxy: Option<&str>,
) -> std::process::Command {
    let mut command = std::process::Command::new(exe);
    command.arg("--dat-tab").arg(profile).arg(url);
    command.env("WEBVIEW2_USER_DATA_FOLDER", profile);
    if let Some(proxy) = proxy.filter(|value| !value.is_empty()) {
        command.env(
            "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
            format!("--proxy-server={proxy}"),
        );
    }
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubber_hides_billing_and_does_not_click_login_anyway() {
        assert!(SCRUBBER.contains("logged in on another device"));
        assert!(SCRUBBER.contains("one.dat.com/search-loads"));
        assert!(!SCRUBBER.to_lowercase().contains("click("));
    }

    #[test]
    fn four_search_opens_four_profiles() {
        assert_eq!(tab_count("dat_4"), 4);
        let root = std::path::Path::new("profiles");
        assert_eq!(
            profile_dir(root, 3),
            std::path::PathBuf::from("profiles/search-4")
        );
    }
}
