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
    answer: Option<Box<Answer>>,
    rewrites: Option<Rewrites>,
    close_after_answer: bool,
    /// Rewrite rules for the response.
    response_rules: Vec<usize>,
    /// `(label, action)` of the rewrite rules that acted.
    applied: Vec<(String, String)>,
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

enum RequestEvent {
    Continue,
    Request(Pending),
}

/// The request and its response share one module snapshot.
#[derive(Clone)]
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

    let result = tokio::try_join!(
        requests(
            BufReader::with_capacity(capacity, client_read),
            upstream_write,
            sender,
            context,
        ),
        responses(
            BufReader::with_capacity(capacity, upstream_read),
            client_write,
            &mut pending,
            context,
        ),
    );
    // Requests the server never answered still show up.
    while let Ok(event) = pending.try_recv() {
        let RequestEvent::Request(request) = event else {
            continue;
        };
        let error = match &result {
            Err(error) => error.to_string(),
            Ok(_) => "no response".into(),
        };
        record(context, request, None, Body::default(), Some(error), false);
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

struct BodySource<'a, R> {
    reader: &'a mut R,
    buffered: BufferedBody,
    limit: usize,
    bodiless: bool,
    loaded: bool,
    expects_continue: Option<&'a mpsc::UnboundedSender<RequestEvent>>,
    sent_continue: bool,
}

impl<'a, R: AsyncBufRead + Unpin> BodySource<'a, R> {
    async fn ensure_loaded(
        &mut self,
        message: &mut Message,
        original_headers: &[(String, String)],
    ) -> io::Result<()> {
        // If an earlier `requires-body=0` rule already replaced the body, reuse that
        // replacement body here and drain the unread wire body when forwarding.
        if self.loaded || self.bodiless || message.body_changed {
            return Ok(());
        }
        self.loaded = true;
        if let Some(sender) = self.expects_continue {
            sender
                .send(RequestEvent::Continue)
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            self.sent_continue = true;
            message
                .headers
                .retain(|(k, _)| !k.eq_ignore_ascii_case("expect"));
            message.head_changed = true;
        }
        let framing = self.buffered.remaining.take().unwrap_or(Framing::Length(0));
        self.buffered = read_body(self.reader, framing, self.limit).await?;
        if self.buffered.remaining.is_none() {
            message.body = decoded(original_headers, &self.buffered.bytes, self.limit);
        }
        Ok(())
    }
}

/// Applies `rules` (indices into the rewriter) in order, lazily buffering and
/// decoding the body only when a matching rule needs it.
async fn apply_rules<R: AsyncBufRead + Unpin>(
    context: &Context,
    rewrites: &Rewrites,
    rules: &[usize],
    phase: Phase,
    request: (&str, &str, &[(String, String)]),
    original_headers: &[(String, String)],
    message: &mut Message,
    body_source: &mut BodySource<'_, R>,
    applied: &mut Vec<(String, String)>,
) -> io::Result<Verdict> {
    let (method, request_url, request_headers) = request;
    let mut last_group: Option<(&str, usize, bool)> = None;
    for &index in rules {
        let rule = rewrites.rewriter.rule(index);
        if rule.pipe_continuation {
            if last_group != Some((rule.module.as_str(), rule.line, true)) {
                continue;
            }
        } else {
            let (req_headers, resp_status, resp_headers) = match phase {
                Phase::Request => (message.headers.as_slice(), None, &[][..]),
                Phase::Response => (
                    request_headers,
                    Some(message.status),
                    message.headers.as_slice(),
                ),
            };
            let matched = rule.matches_conditions(method, req_headers, resp_status, resp_headers);
            last_group = Some((rule.module.as_str(), rule.line, matched));
            if !matched {
                continue;
            }
        }
        if rule.action.needs_body() {
            body_source.ensure_loaded(message, original_headers).await?;
        }
        let acted = match &rule.action {
            action if action.answers() && phase == Phase::Request => {
                context.core.rewrite_stats.record(rule, request_url);
                applied.push((rule.label(), action.kind()));
                return Ok(rewrite::answer(&rewrites.rewriter, rule, request_url)
                    .map_or(Verdict::Drop, Verdict::Answer));
            }
            Action::UrlReplace(_) if phase == Phase::Request => {
                if let Some(new_url) = rewrite::replace_url(rule, &message.url) {
                    if same_origin(&message.url, &new_url).is_some() {
                        if new_url != message.url {
                            message.url = new_url;
                            message.head_changed = true;
                        }
                        true
                    } else {
                        tracing::warn!(
                            from = %message.url,
                            to = %new_url,
                            "cross-origin url.replace is not supported; ignored"
                        );
                        false
                    }
                } else {
                    false
                }
            }
            Action::Header(_) => {
                rewrite::apply_header(rule, &mut message.headers);
                message.head_changed = true;
                true
            }
            Action::Jq(_) => {
                let output = match (&rule.jq, &message.body) {
                    (Some(filter), Some(body)) => filter.apply(body.clone()).await,
                    _ => None,
                };
                match output {
                    Some(body) if message.body.as_ref() != Some(&body) => {
                        message.body = Some(body);
                        message.body_changed = true;
                        true
                    }
                    _ => false,
                }
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
                            applied.push((rule.label(), rule.action.kind()));
                            return Ok(Verdict::Drop);
                        }
                        if let Some(answer) = outcome.response.filter(|_| phase == Phase::Request) {
                            context.core.rewrite_stats.record(rule, request_url);
                            applied.push((rule.label(), rule.action.kind()));
                            return Ok(Verdict::Answer(answer));
                        }
                        if let Some(url) = outcome.url.filter(|u| *u != message.url) {
                            message.url = url;
                            message.head_changed = true;
                        }
                        if let Some(status) = outcome.status.filter(|s| *s != message.status) {
                            message.status = status;
                            message.head_changed = true;
                        }
                        if let Some(mut headers) = outcome.headers {
                            headers.retain(|(k, _)| !rewrite::is_framing(k));
                            headers.extend(
                                message
                                    .headers
                                    .iter()
                                    .filter(|(k, _)| rewrite::is_framing(k))
                                    .cloned(),
                            );
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
            applied.push((rule.label(), rule.action.kind()));
        }
    }
    Ok(Verdict::Continue)
}

struct BufferedBody {
    bytes: Vec<u8>,
    remaining: Option<Framing>,
    // Header of the first chunk that did not fit; its payload is still unread.
    next_chunk: Option<(Vec<u8>, u64)>,
}

impl BufferedBody {
    fn unread(framing: Framing) -> Self {
        Self {
            bytes: Vec::new(),
            remaining: Some(framing),
            next_chunk: None,
        }
    }

    async fn finish<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        reader: &mut R,
        writer: &mut W,
        mut tap: impl FnMut(&[u8]),
    ) -> io::Result<()> {
        tap(&self.bytes);
        if matches!(self.remaining, Some(Framing::Chunked)) && !self.bytes.is_empty() {
            writer
                .write_all(format!("{:x}\r\n", self.bytes.len()).as_bytes())
                .await?;
            writer.write_all(&self.bytes).await?;
            writer.write_all(b"\r\n").await?;
        } else {
            writer.write_all(&self.bytes).await?;
        }
        if let Some((line, size)) = &self.next_chunk {
            writer.write_all(line).await?;
            copy_exact(reader, writer, *size, &mut tap).await?;
            writer.write_all(&read_line(reader).await?).await?;
        }
        if let Some(remaining) = self.remaining {
            copy_body(reader, writer, remaining, tap).await?;
        }
        Ok(())
    }
}

/// Reads a whole body (chunk framing removed) unless it is over `limit`:
/// then what was read so far and false. A known length over the limit is
/// not read at all.
async fn read_body<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    framing: Framing,
    limit: usize,
) -> io::Result<BufferedBody> {
    let mut body = BufferedBody::unread(framing);
    match framing {
        Framing::Length(length) => {
            if length > limit as u64 {
                return Ok(body);
            }
            copy_exact(reader, &mut tokio::io::sink(), length, &mut |b: &[u8]| {
                body.bytes.extend_from_slice(b)
            })
            .await?;
            body.remaining = None;
            Ok(body)
        }
        Framing::Close => loop {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                body.remaining = None;
                return Ok(body);
            }
            let n = available.len().min(limit - body.bytes.len());
            if n == 0 {
                return Ok(body);
            }
            body.bytes.extend_from_slice(&available[..n]);
            reader.consume(n);
        },
        Framing::Chunked => loop {
            let line = read_line(reader).await?;
            let size = chunk_size(&line)?;
            if size == 0 {
                loop {
                    let line = read_line(reader).await?;
                    if line == b"\r\n" || line == b"\n" {
                        body.remaining = None;
                        return Ok(body);
                    }
                }
            }
            if size > (limit - body.bytes.len()) as u64 {
                body.next_chunk = Some((line, size));
                return Ok(body);
            }
            copy_exact(reader, &mut tokio::io::sink(), size, &mut |b: &[u8]| {
                body.bytes.extend_from_slice(b)
            })
            .await?;
            read_line(reader).await?;
        },
    }
}

fn encode_head(start: &str, headers: &[(String, String)]) -> Vec<u8> {
    let mut out = format!("{start}\r\n").into_bytes();
    for (name, value) in headers {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Set the headers for the bytes sent and recorded, after buffering the body.
fn set_body_headers(headers: &mut Vec<(String, String)>, length: usize, replaced: bool) {
    headers.retain(|(name, _)| {
        !(rewrite::is_framing(name) || replaced && name.eq_ignore_ascii_case("content-encoding"))
    });
    headers.push(("Content-Length".into(), length.to_string()));
}

/// The whole body ready for the rules, decoded when it was compressed.
/// `None` when it is compressed in a way that cannot be undone.
fn decoded(headers: &[(String, String)], raw: &[u8], limit: usize) -> Option<Vec<u8>> {
    match find(headers, "content-encoding").filter(|e| !e.eq_ignore_ascii_case("identity")) {
        Some(encoding) if !raw.is_empty() => crate::requests::decode_limited(encoding, raw, limit),
        _ => Some(raw.to_vec()),
    }
}

async fn requests<R, W>(
    mut reader: R,
    mut writer: W,
    sender: mpsc::UnboundedSender<RequestEvent>,
    context: &Context,
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
        let rewrites = context
            .core
            .rewriter()
            .filter(|r| !upgrade && r.rule_count() > 0)
            .map(|rewriter| Rewrites {
                rewriter,
                limit: if context.core.config.internal_host_packet_io {
                    2 << 20
                } else {
                    8 << 20
                },
            });
        let mut pending = Pending {
            rewrites: rewrites.clone(),
            close_after_answer: false,
            started: now_ms(),
            method,
            url,
            headers,
            body: body.clone(),
            answer: None,
            response_rules: vec![],
            applied: vec![],
        };
        let rewrites = rewrites.as_ref();
        let rules = match rewrites {
            Some(rewrites) if !upgrade => rewrites.rewriter.matching(Phase::Request, &pending.url),
            _ => vec![],
        };
        let Some(rewrites) = rewrites.filter(|_| !rules.is_empty()) else {
            if let Some(rewrites) = rewrites.filter(|_| !upgrade) {
                pending.response_rules = rewrites.rewriter.matching(Phase::Response, &pending.url);
            }
            let Some(channel) = &sender else { break };
            let _ = channel.send(RequestEvent::Request(pending));
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
        let expects = find(&pending.headers, "expect")
            .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
            && !matches!(framing, Framing::Length(0));
        let mut message = Message {
            url: pending.url.clone(),
            status: 0,
            headers: pending.headers.clone(),
            body: None,
            head_changed: false,
            body_changed: false,
        };
        let mut body_source = BodySource {
            reader: &mut reader,
            buffered: BufferedBody::unread(framing),
            limit: rewrites.limit,
            bodiless: false,
            loaded: false,
            expects_continue: expects.then(|| sender.as_ref().unwrap()),
            sent_continue: false,
        };
        let verdict = apply_rules(
            context,
            rewrites,
            &rules,
            Phase::Request,
            (&pending.method, &pending.url, &[]),
            &pending.headers,
            &mut message,
            &mut body_source,
            &mut pending.applied,
        )
        .await?;
        let buffered = body_source.buffered;
        let sent_continue = body_source.sent_continue;
        match verdict {
            Verdict::Drop => {
                record(
                    context,
                    pending,
                    None,
                    Body::default(),
                    Some("closed by a rewrite rule".into()),
                    false,
                );
                return Err(io::Error::other("closed by a rewrite rule"));
            }
            Verdict::Answer(mut answer) => {
                let close = buffered.remaining.is_some()
                    && ((expects && !sent_continue)
                        || buffered
                            .finish(&mut reader, &mut tokio::io::sink(), |b| {
                                body.lock().unwrap().push(b, cap)
                            })
                            .await
                            .is_err());
                if close {
                    answer
                        .headers
                        .retain(|(k, _)| !k.eq_ignore_ascii_case("connection"));
                    answer.headers.push(("Connection".into(), "close".into()));
                    pending.close_after_answer = true;
                } else if buffered.remaining.is_none() {
                    body.lock().unwrap().push(&buffered.bytes, cap);
                }
                pending.answer = Some(Box::new(answer));
                let Some(sender) = &sender else { break };
                let _ = sender.send(RequestEvent::Request(pending));
                if close {
                    break;
                }
                continue;
            }
            Verdict::Continue => {}
        }
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
        pending.response_rules = rewrites.rewriter.matching(Phase::Response, &pending.url);
        let start = format!("{} {target} HTTP/1.{minor}", pending.method);
        let Some(sender) = &sender else { break };
        if message.body_changed || buffered.remaining.is_none() {
            if message.body_changed && buffered.remaining.is_some() {
                if expects && !sent_continue {
                    sender
                        .send(RequestEvent::Continue)
                        .map_err(|_| io::ErrorKind::BrokenPipe)?;
                    message
                        .headers
                        .retain(|(k, _)| !k.eq_ignore_ascii_case("expect"));
                }
                buffered
                    .finish(&mut reader, &mut tokio::io::sink(), |_| {})
                    .await?;
            }
            let send = if message.body_changed {
                message.body.take().unwrap_or_default()
            } else {
                buffered.bytes
            };
            if message.body_changed
                || !send.is_empty()
                || !matches!(framing, Framing::Length(0))
                || message
                    .headers
                    .iter()
                    .any(|(name, _)| rewrite::is_framing(name))
            {
                set_body_headers(&mut message.headers, send.len(), message.body_changed);
            }
            body.lock().unwrap().push(&send, cap);
            pending.headers = message.headers.clone();
            let _ = sender.send(RequestEvent::Request(pending));
            let head = encode_head(&start, &message.headers);
            writer.write_all(&head).await?;
            writer.write_all(&send).await?;
        } else {
            if expects && !sent_continue && find(&message.headers, "expect").is_none() {
                sender
                    .send(RequestEvent::Continue)
                    .map_err(|_| io::ErrorKind::BrokenPipe)?;
            }
            pending.headers = message.headers.clone();
            let _ = sender.send(RequestEvent::Request(pending));
            if message.head_changed {
                writer
                    .write_all(&encode_head(&start, &message.headers))
                    .await?;
            } else {
                writer.write_all(&head).await?;
            }
            buffered
                .finish(&mut reader, &mut writer, |bytes| {
                    body.lock().unwrap().push(bytes, cap)
                })
                .await?;
        }
        writer.flush().await?;
    }
    writer.shutdown().await
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
    pending: &mut mpsc::UnboundedReceiver<RequestEvent>,
    context: &Context,
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
        let Some(event) = next else {
            // No more requests: whatever else the server sends goes through.
            tokio::io::copy_buf(&mut reader, &mut writer).await?;
            break;
        };
        let RequestEvent::Request(mut request) = event else {
            writer.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
            writer.flush().await?;
            continue;
        };
        let rewrites = request.rewrites.take();
        if let Some(answer) = request.answer.take() {
            let close = request.close_after_answer;
            let mut body = Body::default();
            let cap = context.core.requests.body_cap();
            let file = match &answer.file {
                Some(path) => Some(tokio::fs::File::open(path).await?),
                None => None,
            };
            let length = match &file {
                Some(file) => file.metadata().await?.len(),
                None => answer.body.len() as u64,
            };
            writer.write_all(&answer.encode_head(length)).await?;
            if request.method != "HEAD"
                && !(100..200).contains(&answer.status)
                && !matches!(answer.status, 204 | 304)
            {
                match file {
                    Some(file) => {
                        copy_exact(&mut BufReader::new(file), &mut writer, length, &mut |b| {
                            body.push(b, cap)
                        })
                        .await?
                    }
                    None => {
                        writer.write_all(&answer.body).await?;
                        body.push(&answer.body, cap);
                    }
                }
            }
            writer.flush().await?;
            record(
                context,
                request,
                Some((answer.status, answer.headers)),
                body,
                None,
                true,
            );
            if close {
                break;
            }
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
                        false,
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
                        false,
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
                    false,
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
        let (status, headers, copied) =
            match rewrites.as_ref().filter(|_| !rules.is_empty() && !switched) {
                None => {
                    writer.write_all(&head).await?;
                    let copied = copy_body(&mut reader, &mut writer, framing, |bytes| {
                        body.push(bytes, cap)
                    })
                    .await;
                    (code, headers, copied)
                }
                Some(rewrites) => {
                    let mut message = Message {
                        url: request.url.clone(),
                        status: code,
                        headers: headers.clone(),
                        body: None,
                        head_changed: false,
                        body_changed: false,
                    };
                    let mut body_source = BodySource {
                        reader: &mut reader,
                        buffered: BufferedBody::unread(framing),
                        limit: rewrites.limit,
                        bodiless,
                        loaded: false,
                        expects_continue: None,
                        sent_continue: false,
                    };
                    let verdict = apply_rules(
                        context,
                        rewrites,
                        &rules,
                        Phase::Response,
                        (&request.method, &request.url, &request.headers),
                        &headers,
                        &mut message,
                        &mut body_source,
                        &mut request.applied,
                    )
                    .await?;
                    let buffered = body_source.buffered;
                    if matches!(verdict, Verdict::Drop) {
                        record(
                            context,
                            request,
                            Some((code, headers)),
                            Body::default(),
                            Some("closed by a rewrite rule".into()),
                            false,
                        );
                        return Err(io::Error::other("closed by a rewrite rule"));
                    }
                    let reason = if message.status == code && !reason.is_empty() {
                        reason.clone()
                    } else {
                        rewrite::reason(message.status).to_owned()
                    };
                    let start = format!("HTTP/1.{minor} {} {reason}", message.status);
                    if request.method == "HEAD" || matches!(message.status, 204 | 304) {
                        if message.status == 204 || !bodiless {
                            message
                                .headers
                                .retain(|(name, _)| !rewrite::is_framing(name));
                        }
                        writer
                            .write_all(&encode_head(&start, &message.headers))
                            .await?;
                        let copied = buffered
                            .finish(&mut reader, &mut tokio::io::sink(), |_| {})
                            .await;
                        (message.status, message.headers, copied)
                    } else if message.body_changed || buffered.remaining.is_none() || bodiless {
                        if message.body_changed && buffered.remaining.is_some() {
                            buffered
                                .finish(&mut reader, &mut tokio::io::sink(), |_| {})
                                .await?;
                        }
                        let send = if message.body_changed {
                            message.body.take().unwrap_or_default()
                        } else {
                            buffered.bytes
                        };
                        set_body_headers(&mut message.headers, send.len(), message.body_changed);
                        writer
                            .write_all(&encode_head(&start, &message.headers))
                            .await?;
                        writer.write_all(&send).await?;
                        body.push(&send, cap);
                        (message.status, message.headers, Ok(()))
                    } else {
                        if message.head_changed {
                            writer
                                .write_all(&encode_head(&start, &message.headers))
                                .await?;
                        } else {
                            writer.write_all(&head).await?;
                        }
                        let copied = buffered
                            .finish(&mut reader, &mut writer, |bytes| body.push(bytes, cap))
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
            false,
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
    answered: bool,
) {
    let request_body = std::mem::take(&mut *request.body.lock().unwrap());
    let (status, response_headers) = match response {
        Some((code, headers)) => (Some(code), headers),
        None => (None, vec![]),
    };
    let (labels, rewrite_actions): (Vec<String>, Vec<String>) = request.applied.into_iter().unzip();
    let summary = HttpSummary {
        method: request.method,
        url: request.url,
        decrypted: context.scheme == "https",
        status,
        content_type: find(&response_headers, "content-type").map(str::to_owned),
        request_size: request_body.size,
        response_size: response_body.size,
        error,
        rewrite: (!labels.is_empty()).then(|| labels.join(", ")),
        rewrite_actions,
        answered,
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

    #[tokio::test]
    async fn oversized_chunk_passes_through_without_buffering_its_payload() {
        let wire = b"2\r\nab\r\n5\r\ncdefg\r\n0\r\n\r\nNEXT";
        let mut reader = &wire[..];
        let body = read_body(&mut reader, Framing::Chunked, 4).await.unwrap();
        assert_eq!(body.bytes, b"ab");
        assert!(reader.starts_with(b"cdefg"));
        let mut out = Vec::new();
        let mut content = Vec::new();
        body.finish(&mut reader, &mut out, |b| content.extend_from_slice(b))
            .await
            .unwrap();
        assert_eq!(out, &wire[..wire.len() - 4]);
        assert_eq!(content, b"abcdefg");
        assert_eq!(reader, b"NEXT");
    }

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
