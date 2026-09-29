//! A registered macOS bundle can be moved or replaced by its owner. Never execute
//! a mutable bundle sidecar as root: snapshot it, verify the snapshot, then run
//! only the copy in the service's root-owned directory.
#[cfg(target_os = "macos")]
pub fn prepare(directory: &std::path::Path) -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use std::os::unix::fs::PermissionsExt;
    let team = option_env!("CLYNTIS_SIGNING_TEAM_ID")
        .context("此服务构建未设置 CLYNTIS_SIGNING_TEAM_ID，不能启用提权功能")?;
    ensure!(
        !team.is_empty()
            && team
                .bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
        "invalid signing team"
    );
    let source = std::env::current_exe()?;
    let source = source.parent().context("missing bundle directory")?;
    let destination = directory.join("bin");
    clyntis_desktop_model::private_dir(&destination)?;
    for name in ["clyntis-runner", "clyntis-service-manager"] {
        let staged = destination.join(format!(".{name}-{}", uuid::Uuid::new_v4()));
        let result: anyhow::Result<()> = (|| {
            let bytes = clyntis_desktop_model::read_limited(&source.join(name), 256 * 1024 * 1024)?;
            clyntis_desktop_model::atomic_write(&staged, &bytes)?;
            std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o700))?;
            let requirement = format!(
                "=anchor apple generic and certificate leaf[subject.OU] = \"{team}\" and identifier \"{name}\""
            );
            let output = std::process::Command::new("/usr/bin/codesign")
                .args(["--verify", "--strict", "-R", &requirement])
                .arg(&staged)
                .output()?;
            ensure!(output.status.success(), "辅助程序签名校验失败：{name}");
            std::fs::rename(&staged, destination.join(name))?;
            Ok(())
        })();
        let _ = std::fs::remove_file(staged);
        result?;
    }
    Ok(())
}
