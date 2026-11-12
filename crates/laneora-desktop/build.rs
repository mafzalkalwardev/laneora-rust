fn main() {
    println!("cargo:rerun-if-changed=tauri.conf.json");
    println!("cargo:rerun-if-changed=ui");
    println!("cargo:rerun-if-changed=src/scrub.js");
    #[cfg(windows)]
    tauri_build::build();
}
