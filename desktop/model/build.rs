use sha2::{Digest, Sha256};
use std::{fs, path::Path};

fn hash_tree(path: &Path, hash: &mut Sha256) {
    println!("cargo:rerun-if-changed={}", path.display());
    if path.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for entry in entries {
            if entry
                .file_name()
                .is_some_and(|n| n == "target" || n == "node_modules" || n == ".DS_Store")
            {
                continue;
            }
            hash_tree(&entry, hash);
        }
    } else {
        let bytes = fs::read(path).unwrap();
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
}
fn main() {
    let root =
        std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("../..");
    let mut hash = Sha256::new();
    // Same inputs for the app and all sidecars, even when Cargo builds them separately.
    for name in [
        "crates",
        "desktop/model/src",
        "desktop/model/build.rs",
        "desktop/model/Cargo.toml",
        "desktop/service/src",
        "desktop/service/Cargo.toml",
        "desktop/runner/src",
        "desktop/runner/Cargo.toml",
        "desktop/packaging",
        "desktop/Cargo.toml",
        "desktop/Cargo.lock",
        "Cargo.lock",
    ] {
        hash.update(name.as_bytes());
        hash_tree(&root.join(name), &mut hash);
    }
    for key in ["CLYNTIS_BUILD_ID", "CLYNTIS_SIGNING_TEAM_ID"] {
        println!("cargo:rerun-if-env-changed={key}");
        hash.update(std::env::var(key).unwrap_or_default().as_bytes());
    }
    println!(
        "cargo:rustc-env=CLYNTIS_SERVICE_BUILD={:x}",
        hash.finalize()
    );
}
