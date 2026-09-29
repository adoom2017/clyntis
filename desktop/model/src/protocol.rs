use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

pub const VERSION: u32 = 1;
pub const MAX_FRAME: usize = super::CONFIG_LIMIT + 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Start {
        version: u32,
        yaml: String,
        profile_id: String,
        system_proxy_port: Option<u16>,
    },
    Resource {
        version: u32,
        name: String,
        data: String,
    },
    Proxy {
        version: u32,
        port: u16,
    },
    Ping {
        version: u32,
    },
    Stop {
        version: u32,
    },
    Status {
        version: u32,
    },
}
impl Request {
    pub fn version(&self) -> u32 {
        match self {
            Self::Start { version, .. }
            | Self::Resource { version, .. }
            | Self::Proxy { version, .. }
            | Self::Ping { version }
            | Self::Stop { version }
            | Self::Status { version } => *version,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Response {
    Ready {
        version: u32,
        controller: SocketAddr,
    },
    Ok {
        version: u32,
    },
    Status {
        version: u32,
        running: bool,
    },
    Error {
        version: u32,
        message: String,
    },
    Stopped {
        version: u32,
    },
}

pub async fn read_frame<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> anyhow::Result<Option<String>> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};
    let mut data = Vec::new();
    let n = reader
        .take(MAX_FRAME as u64 + 1)
        .read_until(b'\n', &mut data)
        .await?;
    anyhow::ensure!(n <= MAX_FRAME, "IPC frame too large");
    if n == 0 {
        return Ok(None);
    }
    anyhow::ensure!(data.last() == Some(&b'\n'), "incomplete IPC frame");
    Ok(Some(String::from_utf8(data)?))
}

pub async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    value: &impl Serialize,
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut data = serde_json::to_vec(value)?;
    anyhow::ensure!(data.len() < MAX_FRAME, "IPC frame too large");
    data.push(b'\n');
    writer.write_all(&data).await?;
    writer.flush().await?;
    Ok(())
}
