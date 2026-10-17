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
        ["install", "update", "uninstall", "status"].contains(&action),
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
        if action == "status" || action == "uninstall" {
            let output = tokio::process::Command::new(
                clyntis_desktop_service::windows_security::system_exe("sc.exe")?,
            )
            .args(["query", clyntis_desktop_service::SERVICE_NAME])
            .creation_flags(0x08000000)
            .output()
            .await?;
            if output.status.code() == Some(1060) {
                return Ok("not_installed".into());
            }
            ensure!(
                output.status.success(),
                "无法查询 Windows 辅助服务：{}",
                String::from_utf8_lossy(&output.stdout).trim()
            );
            if action == "status" {
                return Ok("installed".into());
            }
        }
        let service_exe = clyntis_desktop_service::sibling("clyntis-service")?;
        // Only installing or updating hands this directory to SYSTEM; removal
        // must stay possible even if the directory no longer passes.
        if action != "uninstall" {
            let path = service_exe.clone();
            tokio::task::spawn_blocking(move || {
                clyntis_desktop_service::windows_security::verify_installation(&path)
            })
            .await??;
        }
        // Script text is constant; the executable path is passed through an environment variable.
        // Windows PowerShell writes redirected errors in the OEM code page (GBK on
        // Chinese systems): switch to UTF-8 and print only the message.
        const ELEVATE: &str = "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; try { $p = Start-Process -FilePath $env:CLYNTIS_SERVICE_EXE -ArgumentList $env:CLYNTIS_SERVICE_ACTION -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }";
        let mut command = tokio::process::Command::new(
            clyntis_desktop_service::windows_security::powershell_exe()?,
        );
        command
            .args(["-NoProfile", "-NonInteractive", "-Command", ELEVATE])
            .env("CLYNTIS_SERVICE_EXE", service_exe)
            .env("CLYNTIS_SERVICE_ACTION", format!("--{action}"))
            .creation_flags(0x08000000)
            .kill_on_drop(true);
        let output = tokio::time::timeout(std::time::Duration::from_secs(180), command.output())
            .await
            .map_err(|_| {
                anyhow::anyhow!("管理员授权或辅助服务操作等待超时，请检查系统授权弹窗及服务状态")
            })??;
        if !output.status.success()
            && output.stderr.is_empty()
            && let Some(status) = tokio::task::spawn_blocking(
                clyntis_desktop_service::windows_security::service_status,
            )
            .await??
        {
            clyntis_desktop_service::windows_security::require_service_alive(&status)?;
        }
        ensure!(
            output.status.success(),
            "辅助服务操作失败或管理员授权被取消：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(if action == "install" || action == "update" {
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

/// A live response is required: registration status alone says nothing about the running build.
pub async fn service_is_current() -> bool {
    tokio::time::timeout(std::time::Duration::from_secs(12), async {
        let mut client = clyntis_desktop_service::client::Client::connect().await?;
        client.is_current().await
    })
    .await
    .is_ok_and(|result| result.unwrap_or(false))
}

pub async fn update_service() -> Result<String> {
    let status = service("update").await?;
    #[cfg(windows)]
    {
        // A stopped process will never answer IPC: fail immediately with its startup
        // diagnostics instead of polling for 75 seconds with a generic permission hint.
        let mut last_error = String::new();
        let verified = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let service = tokio::task::spawn_blocking(
                    clyntis_desktop_service::windows_security::service_status,
                )
                .await??
                .ok_or_else(|| anyhow::anyhow!("Windows 网络辅助服务尚未注册"))?;
                clyntis_desktop_service::windows_security::require_service_alive(&service)?;
                let probe = tokio::time::timeout(std::time::Duration::from_secs(12), async {
                    let mut client = clyntis_desktop_service::client::Client::connect().await?;
                    client.is_current().await
                })
                .await;
                match probe {
                    Ok(Ok(true)) => return Ok(status),
                    Ok(Ok(false)) => last_error = "辅助服务的构建版本与桌面程序不一致".into(),
                    Ok(Err(error)) => {
                        last_error = clyntis_desktop_model::redact(&format!("{error:#}"))
                    }
                    Err(_) => last_error = "辅助服务身份校验或状态请求超时".into(),
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        })
        .await;
        verified.map_err(|_| anyhow::anyhow!("Windows 网络辅助服务未能响应：{last_error}"))?
    }
    #[cfg(not(windows))]
    {
        clyntis_desktop_service::update::verify(
            status,
            service_is_current,
            std::time::Duration::from_secs(75),
        )
        .await
    }
}
