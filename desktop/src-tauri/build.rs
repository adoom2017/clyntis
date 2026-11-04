fn main() {
    println!("cargo:rerun-if-env-changed=CLYNTIS_UPDATER_PUBLIC_KEY");
    println!("cargo:rerun-if-env-changed=CLYNTIS_UPDATER_ENDPOINT");
    tauri_build::build()
}
