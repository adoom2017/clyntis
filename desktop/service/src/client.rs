use anyhow::{Context, Result, ensure};
use clyntis_desktop_model::protocol::FrameReader;
use clyntis_desktop_model::protocol::{self, Request, Response, VERSION};

pub struct Client {
    stream: FrameReader<super::transport::Stream>,
}
impl Client {
    pub async fn connect() -> Result<Self> {
        Ok(Self {
            stream: FrameReader::new(
                super::transport::connect()
                    .await
                    .context("辅助服务不可用，请先安装或在系统设置中允许后台服务")?,
            ),
        })
    }
    pub async fn connect_current() -> Result<Self> {
        let mut client = Self::connect().await?;
        ensure!(
            client.is_current().await?,
            "辅助服务尚未更新到当前构建，请重试启动以完成自动更新"
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
        .context("辅助服务已断开")?;
        let response: Response =
            serde_json::from_str(&line).context("辅助服务响应不是有效的 JSON")?;
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
            "辅助服务通信版本不匹配，请重试启动以完成自动更新"
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
            "无效心跳响应"
        );
        Ok(())
    }
    pub async fn stop(&mut self) -> Result<()> {
        ensure!(
            matches!(
                self.request(&Request::Stop { version: VERSION }).await?,
                Response::Stopped { .. }
            ),
            "服务未确认完成网络恢复"
        );
        Ok(())
    }
}

fn matches_build(response: Response) -> Result<bool> {
    match response {
        Response::Status { build, .. } => Ok(build.as_deref() == Some(protocol::SERVICE_BUILD)),
        _ => anyhow::bail!("辅助服务没有返回版本信息"),
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
