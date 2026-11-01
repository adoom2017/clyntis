use anyhow::{Context, Result, ensure};
use clyntis_desktop_model::protocol::FrameReader;
use clyntis_desktop_model::protocol::{self, Request, Response, VERSION};
use clyntis_desktop_model::tr;

pub struct Client {
    stream: FrameReader<super::transport::Stream>,
}
impl Client {
    pub async fn connect() -> Result<Self> {
        Ok(Self {
            stream: FrameReader::new(
                super::transport::connect()
                    .await
                    .with_context(|| tr!("辅助服务不可用，请先安装或在系统设置中允许后台服务", "The helper service is unavailable; install it or allow it to run in the background in System Settings"))?,
            ),
        })
    }
    pub async fn connect_current() -> Result<Self> {
        let mut client = Self::connect().await?;
        ensure!(
            client.is_current().await?,
            "{}",
            tr!(
                "辅助服务尚未更新到当前构建，请重试启动以完成自动更新",
                "The helper service is not yet updated to this build; start again to finish the automatic update"
            )
        );
        Ok(client)
    }
    pub async fn request(&mut self, request: &Request) -> Result<Response> {
        protocol::write_frame(self.stream.get_mut(), request).await?;
        let timeout = match request {
            Request::Start { .. } => 120,
            Request::Stop { .. } => 35,
            _ => 10,
        };
        let line = tokio::time::timeout(
            std::time::Duration::from_secs(timeout),
            protocol::read_frame(&mut self.stream),
        )
        .await??
        .with_context(|| tr!("辅助服务已断开", "The helper service disconnected"))?;
        let response: Response =
            serde_json::from_str(&line).context("invalid helper service response JSON")?;
        if let Response::Error { message, .. } = &response {
            anyhow::bail!("{message}");
        }
        let version = match &response {
            Response::Ready { version, .. }
            | Response::Ok { version }
            | Response::Status { version, .. }
            | Response::Error { version, .. }
            | Response::Stopped { version } => *version,
        };
        ensure!(
            version == VERSION,
            "{}",
            tr!(
                "辅助服务通信版本不匹配，请重试启动以完成自动更新",
                "The helper service protocol does not match; start again to finish the automatic update"
            )
        );
        Ok(response)
    }
    pub async fn is_current(&mut self) -> Result<bool> {
        let response = self.request(&Request::Status { version: VERSION }).await?;
        matches_build(response)
    }
    pub async fn ping(&mut self) -> Result<()> {
        ensure!(
            matches!(
                self.request(&Request::Ping { version: VERSION }).await?,
                Response::Ok { .. }
            ),
            "{}",
            tr!("无效心跳响应", "Invalid heartbeat response")
        );
        Ok(())
    }
    pub async fn stop(&mut self) -> Result<()> {
        ensure!(
            matches!(
                self.request(&Request::Stop { version: VERSION }).await?,
                Response::Stopped { .. }
            ),
            "{}",
            tr!(
                "服务未确认完成网络恢复",
                "The service did not confirm that the network was restored"
            )
        );
        Ok(())
    }
}

fn matches_build(response: Response) -> Result<bool> {
    match response {
        Response::Status { build, .. } => Ok(build.as_deref() == Some(protocol::SERVICE_BUILD)),
        _ => anyhow::bail!(
            "{}",
            tr!(
                "辅助服务没有返回版本信息",
                "The helper service returned no version"
            )
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_and_stale_services_require_update() {
        let legacy =
            serde_json::from_str(r#"{"event":"status","version":1,"running":false}"#).unwrap();
        assert!(!matches_build(legacy).unwrap());
        for (build, expected) in [("old", false), (protocol::SERVICE_BUILD, true)] {
            assert_eq!(
                matches_build(Response::Status {
                    version: VERSION,
                    running: false,
                    build: Some(build.into())
                })
                .unwrap(),
                expected
            );
        }
        assert!(matches_build(Response::Ok { version: VERSION }).is_err());
    }
}
