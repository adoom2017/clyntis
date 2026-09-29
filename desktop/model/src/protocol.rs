use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

pub const VERSION: u32 = 1;
pub const SERVICE_BUILD: &str = env!("CLYNTIS_SERVICE_BUILD");
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
        #[serde(default)]
        build: Option<String>,
    },
    Error {
        version: u32,
        message: String,
    },
    Stopped {
        version: u32,
    },
}

/// Keep partial frames outside the read future: select!/timeout may cancel a
/// read whenever a heartbeat or network refresh wins, including mid-JSON.
pub struct FrameReader<R> {
    reader: tokio::io::BufReader<R>,
    pending: Vec<u8>,
}
impl<R: tokio::io::AsyncRead + Unpin> FrameReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader: tokio::io::BufReader::new(reader),
            pending: Vec::new(),
        }
    }
    pub fn get_mut(&mut self) -> &mut R {
        self.reader.get_mut()
    }
}

pub async fn read_frame<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut FrameReader<R>,
) -> anyhow::Result<Option<String>> {
    use tokio::io::AsyncBufReadExt;
    loop {
        // fill_buf is cancellation-safe. No await occurs between copying its
        // bytes into persistent state and consuming those bytes from the stream.
        let available = reader.reader.fill_buf().await?;
        if available.is_empty() {
            anyhow::ensure!(reader.pending.is_empty(), "incomplete IPC frame");
            return Ok(None);
        }
        let end = available.iter().position(|byte| *byte == b'\n');
        let count = end.map_or(available.len(), |index| index + 1);
        anyhow::ensure!(
            reader.pending.len() + count <= MAX_FRAME,
            "IPC frame too large"
        );
        reader.pending.extend_from_slice(&available[..count]);
        reader.reader.consume(count);
        if end.is_some() {
            return Ok(Some(String::from_utf8(std::mem::take(
                &mut reader.pending,
            ))?));
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn interrupted_read_keeps_the_beginning_of_a_json_frame() {
        let (mut writer, stream) = tokio::io::duplex(128);
        let mut reader = FrameReader::new(stream);
        writer.write_all(b"{\"command\":\"").await.unwrap();
        // Model a service refresh tick winning select! halfway through a frame.
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                read_frame(&mut reader)
            )
            .await
            .is_err()
        );
        writer.write_all(b"ping\",\"version\":1}\n").await.unwrap();
        let frame = read_frame(&mut reader).await.unwrap().unwrap();
        assert!(matches!(
            serde_json::from_str::<Request>(&frame).unwrap(),
            Request::Ping { version: 1 }
        ));
    }

    #[tokio::test]
    async fn consecutive_frames_and_clean_eof_remain_separate() {
        let input = b"{\"command\":\"ping\",\"version\":1}\n{\"command\":\"stop\",\"version\":1}\n";
        let mut reader = FrameReader::new(&input[..]);
        assert!(matches!(
            serde_json::from_str::<Request>(&read_frame(&mut reader).await.unwrap().unwrap())
                .unwrap(),
            Request::Ping { .. }
        ));
        assert!(matches!(
            serde_json::from_str::<Request>(&read_frame(&mut reader).await.unwrap().unwrap())
                .unwrap(),
            Request::Stop { .. }
        ));
        assert!(read_frame(&mut reader).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn partial_and_oversized_frames_are_rejected() {
        let mut partial = FrameReader::new(&b"{\"command\":"[..]);
        assert!(
            read_frame(&mut partial)
                .await
                .unwrap_err()
                .to_string()
                .contains("incomplete")
        );
        let oversized = vec![b'x'; MAX_FRAME + 1];
        let mut reader = FrameReader::new(oversized.as_slice());
        assert!(
            read_frame(&mut reader)
                .await
                .unwrap_err()
                .to_string()
                .contains("too large")
        );
    }

    #[tokio::test]
    async fn cancelled_read_preserves_partial_utf8() {
        let (mut writer, stream) = tokio::io::duplex(128);
        let mut reader = FrameReader::new(stream);
        let frame = "{\"name\":\"节点\"}\n".as_bytes();
        let split = frame.iter().position(|b| *b >= 128).unwrap() + 1;
        writer.write_all(&frame[..split]).await.unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                read_frame(&mut reader)
            )
            .await
            .is_err()
        );
        writer.write_all(&frame[split..]).await.unwrap();
        assert_eq!(
            read_frame(&mut reader).await.unwrap().unwrap().as_bytes(),
            frame
        );
    }
}
