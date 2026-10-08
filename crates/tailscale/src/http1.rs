//! Just enough HTTP/1.1 for Tailscale's endpoints: one request per connection,
//! either read to the end or upgraded to another protocol.
use anyhow::{Context, Result, bail, ensure};
use meta_protocol::BoxStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// Bytes read past the header block.
    pub rest: Vec<u8>,
}
impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Writes the request and reads the status line and headers.
pub async fn request(
    stream: &mut BoxStream,
    method: &str,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<Response> {
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Clyntis\r\n");
    for (key, value) in headers {
        head.push_str(&format!("{key}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.flush().await?;
    let mut buf = Vec::with_capacity(4096);
    loop {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        ensure!(n > 0, "connection closed before the HTTP response");
        buf.extend_from_slice(&chunk[..n]);
        let mut parsed = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut parsed);
        if let httparse::Status::Complete(len) = response.parse(&buf)? {
            let status = response.code.context("HTTP status")?;
            let headers = response
                .headers
                .iter()
                .map(|h| {
                    (
                        h.name.to_owned(),
                        String::from_utf8_lossy(h.value).into_owned(),
                    )
                })
                .collect();
            return Ok(Response {
                status,
                headers,
                rest: buf[len..].to_vec(),
            });
        }
        ensure!(buf.len() < 64 * 1024, "HTTP response header too large");
    }
}

/// Reads the body of `response` (Content-Length, chunked or until close).
pub async fn body(stream: &mut BoxStream, response: Response, limit: usize) -> Result<Vec<u8>> {
    let mut data = response.rest.clone();
    let chunked = response
        .header("transfer-encoding")
        .is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
    let length = response
        .header("content-length")
        .and_then(|v| v.trim().parse::<usize>().ok());
    let mut chunk = [0u8; 8192];
    loop {
        if let Some(length) = length
            && data.len() >= length
        {
            data.truncate(length);
            return Ok(data);
        }
        if chunked && let Some(body) = dechunk(&data)? {
            return Ok(body);
        }
        ensure!(data.len() <= limit, "HTTP body too large");
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            if length.is_none() && !chunked {
                return Ok(data);
            }
            bail!("connection closed in the HTTP body");
        }
        data.extend_from_slice(&chunk[..n]);
    }
}

/// The decoded body once the final chunk has arrived.
fn dechunk(data: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    let mut at = 0;
    loop {
        let Some(end) = data[at..].windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };
        let line = std::str::from_utf8(&data[at..at + end])?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
            .context("invalid chunk size")?;
        at += end + 2;
        if size == 0 {
            return Ok(Some(out));
        }
        if data.len() < at + size + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&data[at..at + size]);
        at += size + 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dechunks_complete_bodies_only() {
        assert_eq!(
            dechunk(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n")
                .unwrap()
                .unwrap(),
            b"Wikipedia"
        );
        assert!(dechunk(b"4\r\nWiki\r\n5\r\nped").unwrap().is_none());
    }
}
