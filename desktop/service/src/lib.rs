pub mod diagnostics;
pub mod client;
pub mod update;
pub mod system_proxy;
pub mod transport;
pub mod trusted;

pub const SERVICE_NAME: &str = "org.clyntis.desktop.service";
pub const PIPE_NAME: &str = r"\\.\pipe\org.clyntis.desktop.service.v1";
pub const SOCKET_PATH: &str = "/var/run/org.clyntis.desktop.service.sock";

pub fn sibling(name: &str) -> anyhow::Result<std::path::PathBuf> {
    let executable = std::env::current_exe()?;
    #[cfg(target_os = "macos")]
    if executable
        .file_name()
        .is_some_and(|file| file == "clyntis-service")
    {
        anyhow::ensure!(
            ["clyntis-runner", "clyntis-service-manager"].contains(&name),
            "invalid sidecar"
        );
        return Ok(std::path::Path::new(
            "/Library/Application Support/org.clyntis.desktop.service/bin",
        )
        .join(name));
    }
    let directory = executable
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing executable directory"))?;
    Ok(directory.join(if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.into()
    }))
}
