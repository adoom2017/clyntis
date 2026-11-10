//! Relays HTTP/1.x between a client and a server byte for byte while reading
//! each request and response off the wire for the request log. Anything that
//! does not parse as HTTP, and everything after a protocol upgrade, is passed
//! through unread.
use crate::{
    Core,
    requests::{Body, HttpDetail, HttpSummary, now_ms},
    traffic,
};
use std::{
    io,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{
        AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
        BufReader,
    },
    sync::mpsc,
};

/// A request head this long without its end is not HTTP worth reading.
const HEAD_LIMIT: usize = 64 << 10;
const LINE_LIMIT: usize = 8 << 10;

pub(crate) struct Context {
    pub(crate) core: Arc<Core>,
    pub(crate) state: Arc<traffic::State>,
    /// `https` when decrypted.
    pub(crate) scheme: &'static str,
    /// `host` or `host:port`, for requests without a Host header.
    pub(crate) authority: String,
}

/// A request sent on, waiting for its response.
struct Pending {
    started: u64,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Arc<Mutex<Body>>,
}

enum Head {
    Http(Vec<u8>),
    /// The peer closed between messages.
    End,
    /// Not HTTP: pass the rest through as is.
    Other,
}

enum Framing {
    Length(u64),
    Chunked,
    /// Until the server closes.
    Close,
}

pub(crate) async fn relay<C, U>(client: C, upstream: U, context: &Context) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let (sender, mut pending) = mpsc::unbounded_channel();
    // Per direction; the iOS tunnel decrypting many connections cannot
    // afford large buffers.
    let capacity = if context.core.config.internal_host_packet_io {
        8 << 10
    } else {
        32 << 10
    };
    let result = tokio::try_join!(
        requests(
            BufReader::with_capacity(capacity, client_read),
            upstream_write,
            sender,
            context
        ),
        responses(
            BufReader::with_capacity(capacity, upstream_read),
            client_write,
            &mut pending,
            context
        ),
    );
    // Requests the server never answered still show up.
    while let Ok(request) = pending.try_recv() {
        let error = match &result {
            Err(error) => error.to_string(),
            Ok(_) => "no response".into(),
        };
        record(context, request, None, Body::default(), Some(error));
    }
    result.map(drop)
}

async fn requests<R, W>(
    mut reader: R,
    mut writer: W,
    sender: mpsc::UnboundedSender<Pending>,
    context: &Context,
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let head = match read_head(&mut reader, true).await? {
            Head::Http(head) => head,
            Head::End => break,
            Head::Other => {
                tokio::io::copy_buf(&mut reader, &mut writer).await?;
                break;
            }
        };
        let mut storage = [httparse::EMPTY_HEADER; 128];
        let mut request = httparse::Request::new(&mut storage);
        if !matches!(request.parse(&head), Ok(httparse::Status::Complete(_))) {
            writer.write_all(&head).await?;
            tokio::io::copy_buf(&mut reader, &mut writer).await?;
            break;
        }
        let method = request.method.unwrap_or_default().to_owned();
        let path = request.path.unwrap_or_default();
        let headers = header_list(request.headers);
        let url = if path.starts_with("http://") || path.starts_with("https://") {
            path.to_owned()
        } else {
            let authority = find(&headers, "host").unwrap_or(&context.authority);
            if method == "CONNECT" {
                format!("{}://{path}", context.scheme)
            } else {
                format!("{}://{authority}{path}", context.scheme)
            }
        };
        let upgrade = method == "CONNECT"
            || (find(&headers, "upgrade").is_some()
                && find(&headers, "connection")
                    .is_some_and(|c| c.to_ascii_lowercase().contains("upgrade")));
        // Requests carry a body only when they say so.
        let framing = framing(&headers).unwrap_or(Framing::Length(0));
        let body = Arc::new(Mutex::new(Body::default()));
        let _ = sender.send(Pending {
            started: now_ms(),
            method,
            url,
            headers,
            body: body.clone(),
        });
        writer.write_all(&head).await?;
        let cap = context.core.requests.body_cap();
        copy_body(&mut reader, &mut writer, framing, |bytes| {
            body.lock().unwrap().push(bytes, cap)
        })
        .await?;
        writer.flush().await?;
        if upgrade {
            tokio::io::copy_buf(&mut reader, &mut writer).await?;
            break;
        }
    }
    writer.shutdown().await
}

async fn responses<R, W>(
    mut reader: R,
    mut writer: W,
    pending: &mut mpsc::UnboundedReceiver<Pending>,
    context: &Context,
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let head = match read_head(&mut reader, false).await? {
            Head::Http(head) => head,
            Head::End => break,
            Head::Other => {
                tokio::io::copy_buf(&mut reader, &mut writer).await?;
                break;
            }
        };
        let mut storage = [httparse::EMPTY_HEADER; 128];
        let mut response = httparse::Response::new(&mut storage);
        if !matches!(response.parse(&head), Ok(httparse::Status::Complete(_))) {
            writer.write_all(&head).await?;
            tokio::io::copy_buf(&mut reader, &mut writer).await?;
            break;
        }
        let code = response.code.unwrap_or_default();
        let headers = header_list(response.headers);
        writer.write_all(&head).await?;
        if (100..200).contains(&code) && code != 101 {
            // Informational: the final response follows.
            writer.flush().await?;
            continue;
        }
        let request = pending.recv().await;
        let method = request.as_ref().map_or("", |r| r.method.as_str());
        // After a switch the bytes that follow belong to another protocol.
        let switched = code == 101 || method == "CONNECT" && (200..300).contains(&code);
        let framing = if switched || method == "HEAD" || code == 204 || code == 304 {
            Framing::Length(0)
        } else {
            framing(&headers).unwrap_or(Framing::Close)
        };
        let close = matches!(framing, Framing::Close);
        let mut body = Body::default();
        let cap = context.core.requests.body_cap();
        let copied = copy_body(&mut reader, &mut writer, framing, |bytes| {
            body.push(bytes, cap)
        })
        .await;
        if let Some(request) = request {
            record(
                context,
                request,
                Some((code, headers)),
                body,
                copied.as_ref().err().map(ToString::to_string),
            );
        }
        copied?;
        writer.flush().await?;
        if switched {
            tokio::io::copy_buf(&mut reader, &mut writer).await?;
            break;
        }
        if close {
            break;
        }
    }
    writer.shutdown().await
}

fn record(
    context: &Context,
    request: Pending,
    response: Option<(u16, Vec<(String, String)>)>,
    response_body: Body,
    error: Option<String>,
) {
    let request_body = std::mem::take(&mut *request.body.lock().unwrap());
    let (status, response_headers) = match response {
        Some((code, headers)) => (Some(code), headers),
        None => (None, vec![]),
    };
    let summary = HttpSummary {
        method: request.method,
        url: request.url,
        decrypted: context.scheme == "https",
        status,
        content_type: find(&response_headers, "content-type").map(str::to_owned),
        request_size: request_body.size,
        response_size: response_body.size,
        error,
    };
    context.core.requests.exchange(
        &context.state,
        request.started,
        summary,
        HttpDetail {
            request_headers: request.headers,
            response_headers,
            request_body,
            response_body,
        },
    );
}

fn header_list(headers: &[httparse::Header<'_>]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|h| {
            (
                h.name.to_owned(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect()
}

fn find<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
}

/// How the message's body ends, when its headers say.
fn framing(headers: &[(String, String)]) -> Option<Framing> {
    if find(headers, "transfer-encoding").is_some_and(|v| {
        v.rsplit(',')
            .next()
            .is_some_and(|last| last.trim().eq_ignore_ascii_case("chunked"))
    }) {
        return Some(Framing::Chunked);
    }
    find(headers, "content-length")
        .and_then(|v| v.parse().ok())
        .map(Framing::Length)
}

/// Reads one message head, through its blank line. Requests must start with
/// a method token and responses with `HTTP/`, or the stream is something
/// else.
async fn read_head<R: AsyncBufRead + Unpin>(reader: &mut R, request: bool) -> io::Result<Head> {
    let mut head = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if head.is_empty() {
                Ok(Head::End)
            } else {
                Err(io::ErrorKind::UnexpectedEof.into())
            };
        }
        if head.is_empty() {
            // Blank lines between messages are allowed.
            let blank = available
                .iter()
                .take_while(|b| **b == b'\r' || **b == b'\n')
                .count();
            if blank > 0 {
                reader.consume(blank);
                continue;
            }
            if !looks_like_http(available, request) {
                return Ok(Head::Other);
            }
        }
        let searched = head.len().saturating_sub(3);
        head.extend_from_slice(available);
        if let Some(end) = head[searched..]
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|i| searched + i + 4)
        {
            let used = available.len() - (head.len() - end);
            head.truncate(end);
            reader.consume(used);
            return Ok(Head::Http(head));
        }
        let used = available.len();
        reader.consume(used);
        if head.len() > HEAD_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP head too long",
            ));
        }
    }
}

fn looks_like_http(start: &[u8], request: bool) -> bool {
    if request {
        let method = start.iter().take_while(|b| b.is_ascii_uppercase()).count();
        // A method and its space, unless all we have so far is the method.
        (1..=16).contains(&method) && start.get(method).is_none_or(|b| *b == b' ')
    } else {
        let prefix = &start[..start.len().min(5)];
        b"HTTP/".starts_with(prefix)
    }
}

/// Copies one body, giving `tap` its content (chunk framing removed).
async fn copy_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    framing: Framing,
    mut tap: impl FnMut(&[u8]),
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match framing {
        Framing::Length(length) => copy_exact(reader, writer, length, &mut tap).await,
        Framing::Close => loop {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                return Ok(());
            }
            let n = available.len();
            writer.write_all(available).await?;
            tap(available);
            reader.consume(n);
            writer.flush().await?;
        },
        Framing::Chunked => loop {
            let line = read_line(reader).await?;
            writer.write_all(&line).await?;
            let size = std::str::from_utf8(&line)
                .ok()
                .and_then(|l| l.split(';').next())
                .and_then(|s| u64::from_str_radix(s.trim(), 16).ok())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
            if size == 0 {
                // Trailers, through the blank line.
                loop {
                    let line = read_line(reader).await?;
                    writer.write_all(&line).await?;
                    if line == b"\r\n" || line == b"\n" {
                        return Ok(());
                    }
                }
            }
            copy_exact(reader, writer, size, &mut tap).await?;
            let end = read_line(reader).await?;
            writer.write_all(&end).await?;
            writer.flush().await?;
        },
    }
}

async fn copy_exact<R, W>(
    reader: &mut R,
    writer: &mut W,
    mut remaining: u64,
    tap: &mut impl FnMut(&[u8]),
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    while remaining > 0 {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let n = available.len().min(remaining as usize);
        writer.write_all(&available[..n]).await?;
        tap(&available[..n]);
        reader.consume(n);
        remaining -= n as u64;
        writer.flush().await?;
    }
    Ok(())
}

async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let n = (&mut *reader)
        .take(LINE_LIMIT as u64)
        .read_until(b'\n', &mut line)
        .await?;
    if n == 0 || !line.ends_with(b"\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "chunk line too long or cut short",
        ));
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_http_starts() {
        assert!(looks_like_http(b"GET / HTTP/1.1", true));
        assert!(looks_like_http(b"POS", true));
        assert!(!looks_like_http(b"\x16\x03\x01", true));
        assert!(!looks_like_http(b"PRI\x00", true));
        assert!(looks_like_http(b"HTTP/1.1 200 OK", false));
        assert!(looks_like_http(b"HT", false));
        assert!(!looks_like_http(b"SSH-2.0", false));
    }
}
