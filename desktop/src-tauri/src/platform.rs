use anyhow::{Result, ensure};
use tauri_plugin_autostart::ManagerExt;

pub fn autostart(app: &tauri::AppHandle, enabled: bool) -> Result<()> {
    if enabled {
        app.autolaunch().enable()?;
    } else {
        app.autolaunch().disable()?;
    }
    Ok(())
}

pub async fn service(action: &str) -> Result<String> {
    ensure!(
        ["install", "uninstall", "status"].contains(&action),
        "invalid service action"
    );
    #[cfg(target_os = "macos")]
    {
        let output = tokio::process::Command::new(clyntis_desktop_service::sibling(
            "clyntis-service-manager",
        )?)
        .arg(action)
        .output()
        .await?;
        ensure!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(String::from_utf8_lossy(&output.stdout).trim().into())
    }
    #[cfg(windows)]
    {
        if action == "status" {
            let output = tokio::process::Command::new("sc.exe")
                .args(["query", clyntis_desktop_service::SERVICE_NAME])
                .creation_flags(0x08000000)
                .output()
                .await?;
            return Ok(if output.status.success() {
                "installed"
            } else {
                "not_installed"
            }
            .into());
        }
        // Script text is constant; the executable path is passed through an environment variable.
        let output = tokio::process::Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference='Stop'; $p = Start-Process -FilePath $env:CLYNTIS_SERVICE_EXE -ArgumentList $env:CLYNTIS_SERVICE_ACTION -Verb RunAs -Wait -PassThru; exit $p.ExitCode"])
            .env("CLYNTIS_SERVICE_EXE", clyntis_desktop_service::sibling("clyntis-service")?)
            .env("CLYNTIS_SERVICE_ACTION", format!("--{action}"))
            .creation_flags(0x08000000).output().await?;
        ensure!(
            output.status.success(),
            "辅助服务操作失败或管理员授权被取消"
        );
        Ok(if action == "install" {
            "installed"
        } else {
            "not_installed"
        }
        .into())
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        anyhow::bail!("不支持的平台")
    }
}
