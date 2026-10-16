//! Windows-only installation policy. The installer uses the same embedded script.
use anyhow::{Context, Result, ensure};
use std::{
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const POLICY: &str = include_str!("../../packaging/windows/install-security.ps1");

pub fn local_path(path: &Path) -> Result<std::path::PathBuf> {
    use std::path::{Component, Prefix};
    ensure!(
        path.is_absolute(),
        "expected an absolute local Windows path"
    );
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        anyhow::bail!("expected a local Windows drive");
    };
    match prefix.kind() {
        Prefix::Disk(_) => Ok(path.to_path_buf()),
        Prefix::VerbatimDisk(drive) => {
            let mut normal = std::path::PathBuf::from(format!("{}:", char::from(drive)));
            normal.push(components.as_path());
            Ok(normal)
        }
        _ => anyhow::bail!("network shares and device paths are not supported"),
    }
}

pub fn system_exe(relative: &str) -> Result<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buffer = vec![0u16; 32768];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    ensure!(
        length > 0 && length < buffer.len(),
        "cannot resolve Windows system directory"
    );
    Ok(std::path::PathBuf::from(std::ffi::OsString::from_wide(&buffer[..length])).join(relative))
}

pub fn powershell_exe() -> Result<std::path::PathBuf> {
    system_exe("WindowsPowerShell/v1.0/powershell.exe")
}

fn run(directory: &Path, action: &str) -> Result<()> {
    use std::os::windows::process::CommandExt;
    let directory = local_path(directory)?;
    let mut child = Command::new(powershell_exe()?)
        .args(["-NoProfile", "-NonInteractive", "-Command", POLICY])
        .env("CLYNTIS_INSTALL_DIRECTORY", directory)
        .env("CLYNTIS_INSTALL_SECURITY_ACTION", action)
        .creation_flags(0x08000000)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("无法检查 Windows 安装目录权限")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait()?.is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("Windows 安装目录权限检查超时，请检查系统 PowerShell 是否可用");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output()?;
    ensure!(
        output.status.success(),
        "Windows 安装目录权限检查失败：{}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

pub fn verify_installation(executable: &Path) -> Result<()> {
    run(
        executable.parent().context("missing install directory")?,
        "Verify",
    )
}

pub fn protect_data(directory: &Path) -> Result<()> {
    let install = directory.parent().context("missing install directory")?;
    ensure!(
        directory == install.join("service-data"),
        "invalid service data directory"
    );
    run(install, "ProtectData")
}

pub fn service_status() -> Result<Option<windows_service::service::ServiceStatus>> {
    use windows_service::{
        service::ServiceAccess,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    match manager.open_service(crate::SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(service) => Ok(Some(service.query_status()?)),
        Err(windows_service::Error::Winapi(error)) if error.raw_os_error() == Some(1060) => {
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

pub fn startup_log() -> Result<std::path::PathBuf> {
    Ok(local_path(&std::env::current_exe()?)?
        .parent()
        .context("missing install directory")?
        .join("clyntis-service.log"))
}

pub fn stopped_error(exit_code: windows_service::service::ServiceExitCode) -> anyhow::Error {
    let detail = startup_log()
        .ok()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .unwrap_or_default();
    let detail = if detail.trim().is_empty() {
        "请查看安装目录中的 clyntis-service.log 和 Windows 系统服务事件".into()
    } else {
        clyntis_desktop_model::redact(detail.trim())
    };
    anyhow::anyhow!("Windows 网络辅助服务启动失败（{exit_code:?}）：{detail}")
}

pub fn require_service_alive(status: &windows_service::service::ServiceStatus) -> Result<()> {
    if status.current_state == windows_service::service::ServiceState::Stopped {
        return Err(stopped_error(status.exit_code));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_scm_paths_without_resolving_junctions() {
        for (input, expected) in [
            (
                r"\\?\D:\Clyntis\clyntis-service.exe",
                r"D:\Clyntis\clyntis-service.exe",
            ),
            (
                r"D:\自定义 安装\service-data",
                r"D:\自定义 安装\service-data",
            ),
            (
                r"\\?\D:\自定义 安装\service-data",
                r"D:\自定义 安装\service-data",
            ),
        ] {
            assert_eq!(local_path(Path::new(input)).unwrap(), Path::new(expected));
        }
        for input in [
            r"D:relative",
            r"\\server\share\Clyntis",
            r"\\?\UNC\server\share\Clyntis",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\Clyntis",
        ] {
            assert!(local_path(Path::new(input)).is_err(), "{input}");
        }
    }

    #[test]
    fn stopped_service_is_reported_without_waiting_for_ipc() {
        use windows_service::service::{
            ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
        };
        let mut status = ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(1),
            checkpoint: 0,
            wait_hint: Duration::ZERO,
            process_id: None,
        };
        assert!(
            require_service_alive(&status)
                .unwrap_err()
                .to_string()
                .contains("启动失败")
        );
        status.current_state = ServiceState::StartPending;
        assert!(require_service_alive(&status).is_ok());
        status.current_state = ServiceState::Running;
        assert!(require_service_alive(&status).is_ok());
    }

    #[test]
    fn rejects_unprotected_custom_directory_through_embedded_policy() {
        let directory = tempfile::tempdir().unwrap();
        let custom = directory.path().join("自定义 安装 &'$ Clyntis");
        std::fs::create_dir(&custom).unwrap();
        let error = verify_installation(&custom.join("clyntis-service.exe"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("Windows 安装目录权限检查失败"), "{error}");
        assert!(
            error.contains("ordinary user") || error.contains("Ordinary users"),
            "{error}"
        );
    }

    #[test]
    fn refuses_to_protect_arbitrary_sibling_data() {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            protect_data(&directory.path().join("other-data"))
                .unwrap_err()
                .to_string()
                .contains("invalid service data directory")
        );
    }
}
