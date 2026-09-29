//! An update is successful only after the running process confirms the expected build.
use anyhow::{Result, ensure};
use std::{future::Future, time::Duration};

pub async fn verify<P, F>(status: String, mut current: P, timeout: Duration) -> Result<String>
where
    P: FnMut() -> F,
    F: Future<Output = bool>,
{
    ensure!(
        status != "requires_approval",
        "请在系统设置 → 通用 → 登录项与扩展中允许 Clyntis 在后台运行，然后再次点击启动。辅助服务用于配置 TUN、路由、DNS 和系统代理，并在停止时恢复网络设置。"
    );
    let verified = tokio::time::timeout(timeout, async {
        loop {
            if current().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await;
    ensure!(
        verified.is_ok(),
        "辅助服务更新后未能确认新版已运行。请检查系统后台权限后重试启动；无需手动卸载服务。"
    );
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn registration_alone_cannot_pass_verification() {
        assert!(
            verify(
                "enabled".into(),
                || async { false },
                Duration::from_millis(5)
            )
            .await
            .is_err()
        );
    }
    #[tokio::test]
    async fn waits_for_replacement_process() {
        let mut attempts = 0;
        let status = verify(
            "enabled".into(),
            || {
                attempts += 1;
                std::future::ready(attempts == 2)
            },
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(status, "enabled");
        assert_eq!(attempts, 2);
    }
    #[tokio::test]
    async fn pending_permission_explains_purpose_without_polling() {
        let error = verify(
            "requires_approval".into(),
            || async { panic!("must not probe") },
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("DNS"));
        assert!(error.to_string().contains("登录项与扩展"));
    }
}
