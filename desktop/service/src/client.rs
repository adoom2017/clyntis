use anyhow::{Context, Result, ensure};
use clyntis_desktop_model::protocol::{self, Request, Response, VERSION};
use tokio::io::BufReader;

pub struct Client {
    stream: BufReader<super::transport::Stream>,
}
impl Client {
    pub async fn connect() -> Result<Self> {
        Ok(Self {
            stream: BufReader::new(
                super::transport::connect()
                    .await
                    .context("辅助服务不可用，请先安装或在系统设置中允许后台服务")?,
            ),
        })
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
        let response: Response = serde_json::from_str(&line)?;
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
        ensure!(version == VERSION, "辅助服务版本不匹配，请重新安装");
        Ok(response)
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
