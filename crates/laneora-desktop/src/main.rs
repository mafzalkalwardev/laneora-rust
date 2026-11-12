fn main() {
    if std::env::args().any(|arg| arg == "--self-check") {
        println!("laneora-desktop {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    #[cfg(windows)]
    {
        laneora_desktop::windows_main();
    }
    #[cfg(not(windows))]
    {
        eprintln!("Laneora Rust desktop runs on Windows and uses the system WebView2 runtime.");
        std::process::exit(1);
    }
}
