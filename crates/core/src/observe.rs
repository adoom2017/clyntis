//! Relays HTTP/1.x between a client and a server byte for byte while reading
//! each request and response off the wire for the request log. Anything that
//! does not parse as HTTP, and everything after a protocol upgrade, is passed
//! through unread.
use crate::{
    Core,
    requests::{Body, HttpDetail, HttpSummary, now_ms},
    rewrite::{self, Answer, Rewriter},
    script, traffic,
};
use clyntis_config::rewrite::{Action, Phase};
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
    /// As sent on, after rewrites.
    headers: Vec<(String, String)>,
    body: Arc<Mutex<Body>>,
    /// Answered by a rewrite rule instead of the server.
    answer: Option<Answer>,
    /// Rewrite rules for the response.
    response_rules: Vec<usize>,
    /// Labels of the rewrite rules that acted.
    applied: Vec<String>,
}

enum Head {
    Http(Vec<u8>),
    /// The peer closed between messages.
    End,
    /// Not HTTP: pass the rest through as is.
    Other,
}

#[derive(Clone, Copy)]
enum Framing {
    Length(u64),
    Chunked,
    /// Until the server closes.
    Close,
}

/// Rewrites for the connection: the module snapshot when it began.
struct Rewrites {
    rewriter: Arc<Rewriter>,
    /// Bodies longer than this pass through unchanged.
    limit: usize,
}

pub(crate) async fn relay<C, U>(client: C, upstream: U, context: &Context) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let (sender, mut pending) = mpsc::unbounded_channel();
    let hosted = context.core.config.internal_host_packet_io;
    // Per direction; the iOS tunnel decrypting many connections cannot
    // afford large buffers.
    let capacity = if hosted { 8 << 10 } else { 32 << 10 };
    let rewrites = context
        .core
        .rewriter()
        .filter(|rewriter| rewriter.rule_count() > 0)
        .map(|rewriter| Rewrites {
            rewriter,
            limit: if hosted { 2 << 20 } else { 8 << 20 },
        });
    let result = tokio::try_join!(
        requests(
            BufReader::with_capacity(capacity, client_read),
            upstream_write,
            sender,
            context,
            rewrites.as_ref(),
        ),
        responses(
            BufReader::with_capacity(capacity, upstream_read),
            client_write,
            &mut pending,
            context,
            rewrites.as_ref(),
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

/// A message as the rewrite rules see it and change it.
struct Message {
    url: String,
    status: u16,
    headers: Vec<(String, String)>,
    /// The whole body, decoded; `None` when the rules do not need it or it
    /// could not be read whole.
    body: Option<Vec<u8>>,
    head_changed: bool,
    body_changed: bool,
}

enum Verdict {
    Continue,
    Answer(Answer),
    Drop,
}

/// Applies `rules` (indices into the rewriter) in order.
async fn apply_rules(
    context: &Context,
    rewrites: &Rewrites,
    rules: &[usize],
    phase: Phase,
    request: (&str, &str, &[(String, String)]),
    message: &mut Message,
    applied: &mut Vec<String>,
) -> Verdict {
    let (method, request_url, request_headers) = request;
    for &index in rules {
        let rule = rewrites.rewriter.rule(index);
        let acted = match &rule.action {
            Action::Header(_) => {
                rewrite::apply_header(rule, &mut message.headers);
                message.head_changed = true;
                true
            }
            Action::BodyReplace(_) | Action::JsonDelete(_) | Action::JsonSet(_) => {
                let changed = message
                    .body
                    .as_mut()
                    .is_some_and(|body| rewrite::apply_body(rule, body));
                message.body_changed |= changed;
                changed
            }
            Action::Script(script) => {
                if script.requires_body
                    && (message.body.is_none()
                        || script.max_size.is_some_and(|max| {
                            message.body.as_ref().map_or(0, Vec::len) as u64 > max
                        }))
                {
                    continue;
                }
                let Some(path) = rewrites.rewriter.file(&script.url) else {
                    continue;
                };
                let body = script
                    .requires_body
                    .then(|| message.body.clone().unwrap_or_default());
                let job = script::Job {
                    name: script.name.clone(),
                    path: path.clone(),
                    argument: script.argument.clone(),
                    timeout: script
                        .timeout
                        .map_or(script::DEFAULT_TIMEOUT, std::time::Duration::from_secs),
                    binary: script.binary,
                    phase,
                    url: request_url.to_owned(),
                    method: method.to_owned(),
                    request_headers: if phase == Phase::Request {
                        message.headers.clone()
                    } else {
                        request_headers.to_vec()
                    },
                    request_body: if phase == Phase::Request {
                        body.clone()
                    } else {
                        None
                    },
                    response: (phase == Phase::Response).then(|| script::ResponseInput {
                        status: message.status,
                        headers: message.headers.clone(),
                        body,
                    }),
                };
                match script::run(&context.core, job).await {
                    Ok(outcome) => {
                        if outcome.abort {
                            context.core.rewrite_stats.record(rule, request_url);
                            applied.push(rule.label());
                            return Verdict::Drop;
                        }
                        if let Some(answer) = outcome.response.filter(|_| phase == Phase::Request) {
                            context.core.rewrite_stats.record(rule, request_url);
                            applied.push(rule.label());
                            return Verdict::Answer(answer);
                        }
                        if let Some(url) = outcome.url.filter(|u| *u != message.url) {
                            message.url = url;
                            message.head_changed = true;
                        }
                        if let Some(status) = outcome.status.filter(|s| *s != message.status) {
                            message.status = status;
                            message.head_changed = true;
                        }
                        if let Some(headers) = outcome.headers {
                            message.headers = headers;
                            message.head_changed = true;
                        }
                        if let Some(body) = outcome.body
                            && message.body.as_ref() != Some(&body)
                        {
                            message.body = Some(body);
                            message.body_changed = true;
                        }
                        true
                    }
                    Err(error) => {
                        tracing::warn!(module = %rule.module, line = rule.line, "rewrite {error:#}");
                        false
                    }
                }
            }
            _ => false,
        };
        if acted {
            context.core.rewrite_stats.record(rule, request_url);
            applied.push(rule.label());
        }
    }
    Verdict::Continue
}

/// Reads a whole body (chunk framing removed) unless it is over `limit`:
/// then what was read so far and false. A known length over the limit is
/// not read at all.
async fn read_body<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    framing: Framing,
    limit: usize,
) -> io::Result<(Vec<u8>, bool)> {
    let mut body = Vec::new();
    match framing {
        Framing::Length(length) => {
            if length > limit as u64 {
                return Ok((body, false));
            }
            copy_exact(reader, &mut tokio::io::sink(), length, &mut |b: &[u8]| {
                body.extend_from_slice(b)
            })
            .await?;
            Ok((body, true))
        }
        Framing::Close => loop {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                return Ok((body, true));
            }
            let n = available.len();
            body.extend_from_slice(available);
            reader.consume(n);
            if body.len() > limit {
                return Ok((body, false));
            }
        },
        Framing::Chunked => loop {
            let line = read_line(reader).await?;
            let size = chunk_size(&line)?;
            if size == 0 {
                loop {
                    let line = read_line(reader).await?;
                    if line == b"\r\n" || line == b"\n" {
                        return Ok((body, true));
                    }
                }
            }
            copy_exact(reader, &mut tokio::io::sink(), size, &mut |b: &[u8]| {
                body.extend_from_slice(b)
            })
            .await?;
            read_line(reader).await?;
            if body.len() > limit {
                return Ok((body, false));
            }
        },
    }
}

/// Writes the part of a body read by [`read_body`] that was over the limit,
/// then relays the rest as it comes.
async fn finish_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    framing: Framing,
    read: &[u8],
    tap: impl FnMut(&[u8]),
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match framing {
        Framing::Chunked if !read.is_empty() => {
            writer
                .write_all(format!("{:x}\r\n", read.len()).as_bytes())
                .await?;
            writer.write_all(read).await?;
            writer.write_all(b"\r\n").await?;
        }
        _ => writer.write_all(read).await?,
    }
    copy_body(reader, writer, framing, tap).await
}

/// The head to send for a rewritten message whose body is `body`, or whose
/// original framing stays when `body` is `None`.
fn encode_head(start: &str, headers: &[(String, String)], body: Option<(usize, bool)>) -> Vec<u8> {
    let mut out = format!("{start}\r\n").into_bytes();
    for (name, value) in headers {
        if let Some((_, decoded)) = body
            && (name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("transfer-encoding")
                || decoded && name.eq_ignore_ascii_case("content-encoding"))
        {
            continue;
        }
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    if let Some((length, _)) = body {
        out.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// The whole body ready for the rules: decoded when it was compressed.
/// `None` when it is compressed in a way that cannot be undone.
fn decoded(headers: &[(String, String)], raw: &[u8], limit: usize) -> Option<(Vec<u8>, bool)> {
    match find(headers, "content-encoding").filter(|e| !e.eq_ignore_ascii_case("identity")) {
        Some(encoding) if !raw.is_empty() => {
            crate::requests::decode_limited(encoding, raw, limit).map(|plain| (plain, true))
        }
        _ => Some((raw.to_vec(), false)),
    }
}

async fn requests<R, W>(
    mut reader: R,
    mut writer: W,
    sender: mpsc::UnboundedSender<Pending>,
    context: &Context,
    rewrites: Option<&Rewrites>,
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Dropped before passing anything through unread, so the response side
    // stops waiting for requests and passes the server's bytes through too.
    let mut sender = Some(sender);
    loop {
        let head = match read_head(&mut reader, true).await? {
            Head::Http(head) => head,
            Head::End => break,
            Head::Other => {
                drop(sender.take());
                tokio::io::copy_buf(&mut reader, &mut writer).await?;
                break;
            }
        };
        let mut storage = [httparse::EMPTY_HEADER; 128];
        let mut request = httparse::Request::new(&mut storage);
        if !matches!(request.parse(&head), Ok(httparse::Status::Complete(_))) {
            drop(sender.take());
            writer.write_all(&head).await?;
            tokio::io::copy_buf(&mut reader, &mut writer).await?;
            break;
        }
        let method = request.method.unwrap_or_default().to_owned();
        let path = request.path.unwrap_or_default().to_owned();
        let minor = request.version.unwrap_or(1);
        let headers = header_list(request.headers);
        let url = if path.starts_with("http://") || path.starts_with("https://") {
            path.clone()
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
        let cap = context.core.requests.body_cap();
        let mut pending = Pending {
            started: now_ms(),
            method,
            url,
            headers,
            body: body.clone(),
            answer: None,
            response_rules: vec![],
            applied: vec![],
        };
        let rules = match rewrites {
            Some(rewrites) if !upgrade => rewrites.rewriter.matching(Phase::Request, &pending.url),
            _ => vec![],
        };
        let Some(rewrites) = rewrites.filter(|_| !rules.is_empty()) else {
            if let Some(rewrites) = rewrites.filter(|_| !upgrade) {
                pending.response_rules = rewrites.rewriter.matching(Phase::Response, &pending.url);
            }
            let Some(channel) = &sender else { break };
            let _ = channel.send(pending);
            writer.write_all(&head).await?;
            copy_body(&mut reader, &mut writer, framing, |bytes| {
                body.lock().unwrap().push(bytes, cap)
            })
            .await?;
            writer.flush().await?;
            if upgrade {
                drop(sender.take());
                tokio::io::copy_buf(&mut reader, &mut writer).await?;
                break;
            }
            continue;
        };
        // A rule that answers the request ends the request's rules.
        let mut verdict = Verdict::Continue;
        let mut rest = Vec::new();
        for &index in &rules {
            let rule = rewrites.rewriter.rule(index);
            if rule.action.answers() {
                context.core.rewrite_stats.record(rule, &pending.url);
                pending.applied.push(rule.label());
                verdict = match rewrite::answer(&rewrites.rewriter, rule, &pending.url) {
                    Some(answer) => Verdict::Answer(answer),
                    None => Verdict::Drop,
                };
                break;
            }
            rest.push(index);
        }
        let mut message = Message {
            url: pending.url.clone(),
            status: 0,
            headers: pending.headers.clone(),
            body: None,
            head_changed: false,
            body_changed: false,
        };
        let needs_body = rest
            .iter()
            .any(|&i| rewrites.rewriter.rule(i).action.needs_body());
        let (mut raw, mut complete) = (Vec::new(), true);
        let mut decoded_body = false;
        if matches!(verdict, Verdict::Continue) && needs_body {
            (raw, complete) = read_body(&mut reader, framing, rewrites.limit).await?;
            if complete
                && let Some((plain, was_decoded)) = decoded(&message.headers, &raw, rewrites.limit)
            {
                message.body = Some(plain);
                decoded_body = was_decoded;
            }
        }
        if matches!(verdict, Verdict::Continue) {
            verdict = apply_rules(
                context,
                rewrites,
                &rest,
                Phase::Request,
                (&pending.method.clone(), &pending.url.clone(), &[]),
                &mut message,
                &mut pending.applied,
            )
            .await;
        }
        match verdict {
            Verdict::Drop => {
                record(
                    context,
                    pending,
                    None,
                    Body::default(),
                    Some("closed by a rewrite rule".into()),
                );
                return Err(io::Error::other("closed by a rewrite rule"));
            }
            Verdict::Answer(answer) => {
                // The body is read and dropped; the server never sees it.
                if !needs_body {
                    copy_body(&mut reader, &mut tokio::io::sink(), framing, |bytes| {
                        body.lock().unwrap().push(bytes, cap)
                    })
                    .await?;
                } else {
                    body.lock().unwrap().push(&raw, cap);
                }
                pending.answer = Some(answer);
                let Some(sender) = &sender else { break };
                let _ = sender.send(pending);
                continue;
            }
            Verdict::Continue => {}
        }
        pending.response_rules = rewrites.rewriter.matching(Phase::Response, &message.url);
        // A script may move the request to another path on the same host.
        let mut target = path;
        if message.url != pending.url {
            match same_origin(&pending.url, &message.url) {
                Some(path) => {
                    target = path;
                    pending.url = message.url.clone();
                }
                None => {
                    tracing::warn!(url = %message.url, "a rewrite script moved a request to another host; ignored")
                }
            }
        }
        pending.headers = message.headers.clone();
        let start = format!("{} {target} HTTP/1.{minor}", pending.method);
        let Some(sender) = &sender else { break };
        if complete && needs_body {
            let (send, decoded_body) = if message.body_changed {
                (message.body.take().unwrap_or_default(), decoded_body)
            } else {
                (raw, false)
            };
            body.lock().unwrap().push(&send, cap);
            let framed = framing_header(&message.headers) || !send.is_empty();
            let _ = sender.send(pending);
            let head = encode_head(
                &start,
                &message.headers,
                framed.then_some((send.len(), decoded_body)),
            );
            writer.write_all(&head).await?;
            writer.write_all(&send).await?;
        } else {
            let _ = sender.send(pending);
            if message.head_changed {
                writer
                    .write_all(&encode_head(&start, &message.headers, None))
                    .await?;
            } else {
                writer.write_all(&head).await?;
            }
            body.lock().unwrap().push(&raw, cap);
            finish_body(&mut reader, &mut writer, framing, &raw, |bytes| {
                body.lock().unwrap().push(bytes, cap)
            })
            .await?;
        }
        writer.flush().await?;
    }
    writer.shutdown().await
}

fn framing_header(headers: &[(String, String)]) -> bool {
    find(headers, "content-length").is_some() || find(headers, "transfer-encoding").is_some()
}

/// The path of `to` when it has the same scheme and host as `from`.
fn same_origin(from: &str, to: &str) -> Option<String> {
    let (from, to): (http::Uri, http::Uri) = (from.parse().ok()?, to.parse().ok()?);
    (from.scheme() == to.scheme() && from.authority() == to.authority()).then(|| {
        to.path_and_query()
            .map_or("/".into(), |p| p.as_str().to_owned())
    })
}

async fn responses<R, W>(
    mut reader: R,
    mut writer: W,
    pending: &mut mpsc::UnboundedReceiver<Pending>,
    context: &Context,
    rewrites: Option<&Rewrites>,
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        // The next request, unless the server closes first: then the
        // client must see the close rather than wait for an answer.
        let next = tokio::select! {
            biased;
            request = pending.recv() => request,
            available = reader.fill_buf() => {
                if available?.is_empty() {
                    break;
                }
                pending.recv().await
            }
        };
        let Some(mut request) = next else {
            // No more requests: whatever else the server sends goes through.
            tokio::io::copy_buf(&mut reader, &mut writer).await?;
            break;
        };
        if let Some(answer) = request.answer.take() {
            writer.write_all(&answer.encode()).await?;
            writer.flush().await?;
            let mut body = Body::default();
            body.push(&answer.body, context.core.requests.body_cap());
            record(
                context,
                request,
                Some((answer.status, answer.headers)),
                body,
                None,
            );
            continue;
        }
        // The final response, after any informational ones.
        let (head, code, minor, reason, headers) = loop {
            let head = match read_head(&mut reader, false).await? {
                Head::Http(head) => head,
                Head::End => {
                    record(
                        context,
                        request,
                        None,
                        Body::default(),
                        Some("no response".into()),
                    );
                    return writer.shutdown().await;
                }
                Head::Other => {
                    record(
                        context,
                        request,
                        None,
                        Body::default(),
                        Some("not HTTP".into()),
                    );
                    tokio::io::copy_buf(&mut reader, &mut writer).await?;
                    return writer.shutdown().await;
                }
            };
            let mut storage = [httparse::EMPTY_HEADER; 128];
            let mut response = httparse::Response::new(&mut storage);
            if !matches!(response.parse(&head), Ok(httparse::Status::Complete(_))) {
                record(
                    context,
                    request,
                    None,
                    Body::default(),
                    Some("bad response".into()),
                );
                writer.write_all(&head).await?;
                tokio::io::copy_buf(&mut reader, &mut writer).await?;
                return writer.shutdown().await;
            }
            let code = response.code.unwrap_or_default();
            if (100..200).contains(&code) && code != 101 {
                // Informational: the final response follows.
                writer.write_all(&head).await?;
                writer.flush().await?;
                continue;
            }
            break (
                head.clone(),
                code,
                response.version.unwrap_or(1),
                response.reason.unwrap_or_default().to_owned(),
                header_list(response.headers),
            );
        };
        // After a switch the bytes that follow belong to another protocol.
        let switched = code == 101 || request.method == "CONNECT" && (200..300).contains(&code);
        let bodiless = switched || request.method == "HEAD" || code == 204 || code == 304;
        let framing = if bodiless {
            Framing::Length(0)
        } else {
            framing(&headers).unwrap_or(Framing::Close)
        };
        let close = matches!(framing, Framing::Close);
        let cap = context.core.requests.body_cap();
        let mut body = Body::default();
        let rules = std::mem::take(&mut request.response_rules);
        let (status, headers, copied) = match rewrites.filter(|_| !rules.is_empty() && !switched) {
            None => {
                writer.write_all(&head).await?;
                let copied = copy_body(&mut reader, &mut writer, framing, |bytes| {
                    body.push(bytes, cap)
                })
                .await;
                (code, headers, copied)
            }
            Some(rewrites) => {
                let needs_body = !bodiless
                    && rules
                        .iter()
                        .any(|&i| rewrites.rewriter.rule(i).action.needs_body());
                let (raw, complete) = if needs_body {
                    read_body(&mut reader, framing, rewrites.limit).await?
                } else {
                    (Vec::new(), true)
                };
                let unpacked = (needs_body && complete)
                    .then(|| decoded(&headers, &raw, rewrites.limit))
                    .flatten();
                let mut message = Message {
                    url: request.url.clone(),
                    status: code,
                    headers: headers.clone(),
                    body: unpacked.as_ref().map(|(b, _)| b.clone()),
                    head_changed: false,
                    body_changed: false,
                };
                let verdict = apply_rules(
                    context,
                    rewrites,
                    &rules,
                    Phase::Response,
                    (&request.method, &request.url, &request.headers),
                    &mut message,
                    &mut request.applied,
                )
                .await;
                if matches!(verdict, Verdict::Drop) {
                    record(
                        context,
                        request,
                        Some((code, headers)),
                        Body::default(),
                        Some("closed by a rewrite rule".into()),
                    );
                    return Err(io::Error::other("closed by a rewrite rule"));
                }
                let reason = if message.status == code && !reason.is_empty() {
                    reason.clone()
                } else {
                    rewrite::reason(message.status).to_owned()
                };
                let start = format!("HTTP/1.{minor} {} {reason}", message.status);
                if needs_body && complete {
                    let (send, decoded_body) = if message.body_changed {
                        (
                            message.body.take().unwrap_or_default(),
                            unpacked.as_ref().is_some_and(|(_, d)| *d),
                        )
                    } else {
                        (raw, false)
                    };
                    writer
                        .write_all(&encode_head(
                            &start,
                            &message.headers,
                            Some((send.len(), decoded_body)),
                        ))
                        .await?;
                    writer.write_all(&send).await?;
                    body.push(&send, cap);
                    let mut headers = message.headers;
                    if decoded_body {
                        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-encoding"));
                    }
                    (message.status, headers, Ok(()))
                } else {
                    if message.head_changed {
                        writer
                            .write_all(&encode_head(&start, &message.headers, None))
                            .await?;
                    } else {
                        writer.write_all(&head).await?;
                    }
                    body.push(&raw, cap);
                    let copied = finish_body(&mut reader, &mut writer, framing, &raw, |bytes| {
                        body.push(bytes, cap)
                    })
                    .await;
                    (message.status, message.headers, copied)
                }
            }
        };
        record(
            context,
            request,
            Some((status, headers)),
            body,
            copied.as_ref().err().map(ToString::to_string),
        );
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
        rewrite: (!request.applied.is_empty()).then(|| request.applied.join(", ")),
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
            let size = chunk_size(&line)?;
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

fn chunk_size(line: &[u8]) -> io::Result<u64> {
    std::str::from_utf8(line)
        .ok()
        .and_then(|l| l.split(';').next())
        .and_then(|s| u64::from_str_radix(s.trim(), 16).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))
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
