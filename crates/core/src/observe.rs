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
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{
        AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
        BufReader,
    },
    sync::{Notify, OwnedSemaphorePermit, mpsc},
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

/// Tracks active HTTP requests awaiting a complete response so hosted idle
/// keep-alive connections can close between requests without interrupting
/// slow or streaming responses.
struct InFlightTracker {
    count: Arc<AtomicUsize>,
    notify: Arc<Notify>,
}

impl InFlightTracker {
    fn new() -> Self {
        Self {
            count: Arc::new(AtomicUsize::new(0)),
            notify: Arc::new(Notify::new()),
        }
    }

    fn enter(&self) -> InFlight {
        self.count.fetch_add(1, Ordering::AcqRel);
        InFlight {
            count: self.count.clone(),
            notify: self.notify.clone(),
        }
    }

    fn count(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.notify.notified()
    }
}

struct InFlight {
    count: Arc<AtomicUsize>,
    notify: Arc<Notify>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
        self.notify.notify_one();
    }
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
    /// Hosted body-budget reservation held until a local answer is sent.
    answer_budget: Option<OwnedSemaphorePermit>,
    rewrites: Option<Rewrites>,
    close_after_answer: bool,
    /// Rewrite rules for the response.
    response_rules: Vec<usize>,
    /// `(label, action)` of the rewrite rules that acted.
    applied: Vec<(String, String)>,
    in_flight: Option<InFlight>,
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
    let in_flight = InFlightTracker::new();
    let raw_passthrough = Arc::new(AtomicBool::new(false));

    let result = tokio::try_join!(
        requests(
            BufReader::with_capacity(capacity, client_read),
            upstream_write,
            sender,
            context,
            &in_flight,
            &raw_passthrough,
        ),
        responses(
            BufReader::with_capacity(capacity, upstream_read),
            client_write,
            &mut pending,
            context,
            &raw_passthrough,
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
    Answer(Answer, Option<OwnedSemaphorePermit>),
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
    permit: Option<Arc<OwnedSemaphorePermit>>,
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
    let mut group_runtimes: Option<rewrite::CachedGroup> = None;
    for (pos, &index) in rules.iter().enumerate() {
        let allow_compile = !context.core.mitm.memory_limited();
        let rule = rewrites.rewriter.rule(index);
        if rule.pipe_continuation {
            if last_group != Some((rule.module.as_str(), rule.line, true)) {
                continue;
            }
        } else {
            group_runtimes = None;
            let (req_headers, resp_status, resp_headers) = match phase {
                Phase::Request => (message.headers.as_slice(), None, &[][..]),
                Phase::Response => (
                    request_headers,
                    Some(message.status),
                    message.headers.as_slice(),
                ),
            };
            let matched = rewrites.rewriter.matches_conditions_with(
                index,
                method,
                req_headers,
                resp_status,
                resp_headers,
                allow_compile,
            );
            if !matched {
                last_group = Some((rule.module.as_str(), rule.line, false));
                continue;
            }
            let group_end = rules[pos + 1..]
                .iter()
                .position(|&next_index| {
                    let next = rewrites.rewriter.rule(next_index);
                    !(next.pipe_continuation
                        && next.module == rule.module
                        && next.line == rule.line)
                })
                .map_or(rules.len(), |offset| pos + 1 + offset);
            let group = &rules[pos..group_end];
            if context.core.config.internal_host_packet_io {
                let needs_body = group
                    .iter()
                    .any(|&idx| rewrites.rewriter.rule(idx).action.needs_body());
                let has_bodiless_script = group.iter().any(|&idx| {
                    let action = &rewrites.rewriter.rule(idx).action;
                    matches!(action, Action::Script(_)) && !action.needs_body()
                });
                if has_bodiless_script && context.core.mitm.memory_limited() {
                    tracing::debug!(module = %rule.module, "skipping script: memory limited");
                    last_group = Some((rule.module.as_str(), rule.line, false));
                    continue;
                }
                if needs_body && body_source.permit.is_none() {
                    body_source.permit = context.core.mitm.try_rewrite();
                    if body_source.permit.is_none() {
                        tracing::debug!(
                            module = %rule.module,
                            "skipping rewrite: memory budget busy"
                        );
                        last_group = Some((rule.module.as_str(), rule.line, false));
                        continue;
                    }
                }
            }
            if group.len() > 1 || !allow_compile {
                match rewrites
                    .rewriter
                    .prepare_group_runtimes(group, allow_compile)
                {
                    Some(pinned) => group_runtimes = Some(pinned),
                    None => {
                        tracing::debug!(
                            module = %rule.module,
                            line = rule.line,
                            "skipping rewrite: uncached stage under memory pressure"
                        );
                        last_group = Some((rule.module.as_str(), rule.line, false));
                        continue;
                    }
                }
            }
            last_group = Some((rule.module.as_str(), rule.line, true));
        }
        if rule.action.needs_body() {
            body_source.ensure_loaded(message, original_headers).await?;
        }
        let acted = match &rule.action {
            action if action.answers() && phase == Phase::Request => {
                match rewrite::answer_with(
                    &rewrites.rewriter,
                    index,
                    request_url,
                    allow_compile,
                    group_runtimes.as_ref(),
                ) {
                    rewrite::AnswerOutcome::Drop => {
                        context.core.rewrite_stats.record(rule, request_url);
                        applied.push((rule.label(), action.kind()));
                        return Ok(Verdict::Drop);
                    }
                    rewrite::AnswerOutcome::Skip => false,
                    rewrite::AnswerOutcome::Answer(mut answer) => {
                        answer.body.shrink_to_fit();
                        match context.core.requests.reserve_body_budget(answer.body.len()) {
                            Ok(budget) => {
                                context.core.rewrite_stats.record(rule, request_url);
                                applied.push((rule.label(), action.kind()));
                                return Ok(Verdict::Answer(answer, budget));
                            }
                            Err(()) => {
                                tracing::debug!(
                                    module = %rule.module,
                                    bytes = answer.body.len(),
                                    "skipping local rewrite answer: body budget exhausted"
                                );
                                false
                            }
                        }
                    }
                }
            }
            Action::UrlReplace(_) if phase == Phase::Request => {
                if let Some(new_url) = rewrite::replace_url_with(
                    &rewrites.rewriter,
                    index,
                    &message.url,
                    allow_compile,
                    group_runtimes.as_ref(),
                ) {
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
                if rewrite::apply_header_with(
                    &rewrites.rewriter,
                    index,
                    &mut message.headers,
                    allow_compile,
                    group_runtimes.as_ref(),
                ) {
                    message.head_changed = true;
                    true
                } else {
                    false
                }
            }
            Action::Jq(_) => {
                let output = match (
                    rewrites
                        .rewriter
                        .jq_with(index, allow_compile, group_runtimes.as_ref()),
                    &message.body,
                ) {
                    (Some(filter), Some(body)) => {
                        filter.apply(body.clone(), body_source.permit.clone()).await
                    }
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
                let changed = message.body.as_mut().is_some_and(|body| {
                    rewrite::apply_body_with(
                        &rewrites.rewriter,
                        index,
                        body,
                        allow_compile,
                        group_runtimes.as_ref(),
                    )
                });
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
                let mut body = script
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
                        body.take()
                    } else {
                        None
                    },
                    response: (phase == Phase::Response).then(|| script::ResponseInput {
                        status: message.status,
                        headers: message.headers.clone(),
                        body,
                    }),
                };
                match script::run(&context.core, job, body_source.permit.clone()).await {
                    Ok(outcome) => {
                        if outcome.abort {
                            context.core.rewrite_stats.record(rule, request_url);
                            applied.push((rule.label(), rule.action.kind()));
                            return Ok(Verdict::Drop);
                        }
                        if let Some(mut answer) =
                            outcome.response.filter(|_| phase == Phase::Request)
                        {
                            answer.body.shrink_to_fit();
                            match context.core.requests.reserve_body_budget(answer.body.len()) {
                                Ok(budget) => {
                                    context.core.rewrite_stats.record(rule, request_url);
                                    applied.push((rule.label(), rule.action.kind()));
                                    return Ok(Verdict::Answer(answer, budget));
                                }
                                Err(()) => {
                                    tracing::debug!(
                                        module = %rule.module,
                                        bytes = answer.body.len(),
                                        "skipping local script response: body budget exhausted"
                                    );
                                    false
                                }
                            }
                        } else {
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
        mut self,
        reader: &mut R,
        writer: &mut W,
        permit: Option<Arc<OwnedSemaphorePermit>>,
        mut tap: impl FnMut(&[u8]),
    ) -> io::Result<()> {
        if !self.bytes.is_empty() {
            tap(&self.bytes);
            if matches!(self.remaining, Some(Framing::Chunked)) {
                writer
                    .write_all(format!("{:x}\r\n", self.bytes.len()).as_bytes())
                    .await?;
                writer.write_all(&self.bytes).await?;
                writer.write_all(b"\r\n").await?;
            } else {
                writer.write_all(&self.bytes).await?;
            }
        }
        drop(std::mem::take(&mut self.bytes));
        drop(permit);
        if let Some((line, size)) = self.next_chunk.take() {
            writer.write_all(&line).await?;
            copy_exact(reader, writer, size, &mut tap).await?;
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
    in_flight: &InFlightTracker,
    raw_passthrough: &AtomicBool,
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Dropped before passing anything through unread, so the response side
    // stops waiting for requests and passes the server's bytes through too.
    let mut sender = Some(sender);
    let mut seen_request = false;
    let keepalive_idle = context.core.mitm.hosted_keepalive_idle();
    loop {
        let idle = seen_request
            .then_some(keepalive_idle)
            .flatten()
            .map(|duration| (duration, in_flight));
        let head = match read_head(&mut reader, true, idle).await? {
            Head::Http(head) => head,
            Head::End => break,
            Head::Other => {
                raw_passthrough.store(true, Ordering::Release);
                drop(sender.take());
                tokio::io::copy_buf(&mut reader, &mut writer).await?;
                break;
            }
        };
        let mut storage = [httparse::EMPTY_HEADER; 128];
        let mut request = httparse::Request::new(&mut storage);
        if !matches!(request.parse(&head), Ok(httparse::Status::Complete(_))) {
            raw_passthrough.store(true, Ordering::Release);
            drop(sender.take());
            writer.write_all(&head).await?;
            tokio::io::copy_buf(&mut reader, &mut writer).await?;
            break;
        }
        seen_request = true;
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
        let cap = context
            .core
            .requests
            .body_cap(find(&headers, "content-type"));
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
            answer_budget: None,
            response_rules: vec![],
            applied: vec![],
            in_flight: None,
        };
        let allow_compile = !context.core.mitm.memory_limited();
        let rewrites = rewrites.as_ref();
        let rules = match rewrites {
            Some(rewrites) if !upgrade => {
                rewrites
                    .rewriter
                    .matching_with(Phase::Request, &pending.url, allow_compile)
            }
            _ => vec![],
        };
        let Some(rewrites) = rewrites.filter(|_| !rules.is_empty()) else {
            if let Some(rewrites) = rewrites.filter(|_| !upgrade) {
                pending.response_rules =
                    rewrites
                        .rewriter
                        .matching_with(Phase::Response, &pending.url, allow_compile);
            }
            let Some(channel) = &sender else { break };
            pending.in_flight = Some(in_flight.enter());
            if channel.send(RequestEvent::Request(pending)).is_err() {
                break;
            }
            writer.write_all(&head).await?;
            copy_body(&mut reader, &mut writer, framing, |bytes| {
                capture(context, &mut body.lock().unwrap(), bytes, cap)
            })
            .await?;
            writer.flush().await?;
            if upgrade {
                raw_passthrough.store(true, Ordering::Release);
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
            permit: None,
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
        let BodySource {
            buffered,
            sent_continue,
            permit,
            ..
        } = body_source;
        match verdict {
            Verdict::Drop => {
                drop(buffered);
                drop(permit);
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
            Verdict::Answer(mut answer, answer_budget) => {
                let was_unread = buffered.remaining.is_some();
                let close = if was_unread {
                    if expects && !sent_continue {
                        drop(buffered);
                        drop(permit);
                        true
                    } else {
                        buffered
                            .finish(&mut reader, &mut tokio::io::sink(), permit, |b| {
                                capture(context, &mut body.lock().unwrap(), b, cap)
                            })
                            .await
                            .is_err()
                    }
                } else {
                    capture(context, &mut body.lock().unwrap(), &buffered.bytes, cap);
                    drop(buffered);
                    drop(permit);
                    false
                };
                if close {
                    answer
                        .headers
                        .retain(|(k, _)| !k.eq_ignore_ascii_case("connection"));
                    answer.headers.push(("Connection".into(), "close".into()));
                    pending.close_after_answer = true;
                }
                pending.answer = Some(Box::new(answer));
                pending.answer_budget = answer_budget;
                let Some(sender) = &sender else { break };
                pending.in_flight = Some(in_flight.enter());
                if sender.send(RequestEvent::Request(pending)).is_err() {
                    break;
                }
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
        let allow_compile = !context.core.mitm.memory_limited();
        pending.response_rules =
            rewrites
                .rewriter
                .matching_with(Phase::Response, &pending.url, allow_compile);
        let start = format!("{} {target} HTTP/1.{minor}", pending.method);
        let Some(sender) = &sender else { break };
        if message.body_changed || buffered.remaining.is_none() {
            let send = if message.body_changed {
                if buffered.remaining.is_some() {
                    if expects && !sent_continue {
                        sender
                            .send(RequestEvent::Continue)
                            .map_err(|_| io::ErrorKind::BrokenPipe)?;
                        message
                            .headers
                            .retain(|(k, _)| !k.eq_ignore_ascii_case("expect"));
                    }
                    buffered
                        .finish(&mut reader, &mut tokio::io::sink(), None, |_| {})
                        .await?;
                }
                message.body.take().unwrap_or_default()
            } else {
                buffered.bytes
            };
            message.body = None;
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
            capture(context, &mut body.lock().unwrap(), &send, cap);
            pending.headers = message.headers.clone();
            pending.in_flight = Some(in_flight.enter());
            if sender.send(RequestEvent::Request(pending)).is_err() {
                break;
            }
            let head = encode_head(&start, &message.headers);
            writer.write_all(&head).await?;
            writer.write_all(&send).await?;
            drop(send);
            drop(permit);
        } else {
            if expects && !sent_continue && find(&message.headers, "expect").is_none() {
                sender
                    .send(RequestEvent::Continue)
                    .map_err(|_| io::ErrorKind::BrokenPipe)?;
            }
            pending.headers = message.headers.clone();
            pending.in_flight = Some(in_flight.enter());
            if sender.send(RequestEvent::Request(pending)).is_err() {
                break;
            }
            if message.head_changed {
                writer
                    .write_all(&encode_head(&start, &message.headers))
                    .await?;
            } else {
                writer.write_all(&head).await?;
            }
            buffered
                .finish(&mut reader, &mut writer, permit, |bytes| {
                    capture(context, &mut body.lock().unwrap(), bytes, cap)
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
    raw_passthrough: &AtomicBool,
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
            if raw_passthrough.load(Ordering::Acquire) {
                // No more requests after switching to raw passthrough: whatever
                // else the server sends goes through.
                tokio::io::copy_buf(&mut reader, &mut writer).await?;
            }
            break;
        };
        let RequestEvent::Request(mut request) = event else {
            writer.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
            writer.flush().await?;
            continue;
        };
        let rewrites = request.rewrites.take();
        if let Some(mut answer) = request.answer.take() {
            let answer_budget = request.answer_budget.take();
            let close = request.close_after_answer;
            let mut body = Body::default();
            let cap = context
                .core
                .requests
                .body_cap(find(&answer.headers, "content-type"));
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
                            capture(context, &mut body, b, cap)
                        })
                        .await?
                    }
                    None => {
                        writer.write_all(&answer.body).await?;
                        capture(context, &mut body, &answer.body, cap);
                    }
                }
            }
            writer.flush().await?;
            let status = answer.status;
            let headers = std::mem::take(&mut answer.headers);
            drop(answer);
            drop(answer_budget);
            record(context, request, Some((status, headers)), body, None, true);
            if close {
                break;
            }
            continue;
        }
        // The final response, after any informational ones.
        let (head, code, minor, reason, headers) = loop {
            let head = match read_head(&mut reader, false, None).await? {
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
        let cap = context
            .core
            .requests
            .body_cap(find(&headers, "content-type"));
        let mut body = Body::default();
        let rules = std::mem::take(&mut request.response_rules);
        let (status, headers, copied) =
            match rewrites.as_ref().filter(|_| !rules.is_empty() && !switched) {
                None => {
                    writer.write_all(&head).await?;
                    let copied = copy_body(&mut reader, &mut writer, framing, |bytes| {
                        capture(context, &mut body, bytes, cap)
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
                        permit: None,
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
                    let BodySource {
                        buffered, permit, ..
                    } = body_source;
                    let cap = context
                        .core
                        .requests
                        .body_cap(find(&message.headers, "content-type"));
                    if matches!(verdict, Verdict::Drop) {
                        drop(buffered);
                        drop(permit);
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
                            .finish(&mut reader, &mut tokio::io::sink(), permit, |_| {})
                            .await;
                        (message.status, message.headers, copied)
                    } else if message.body_changed || buffered.remaining.is_none() || bodiless {
                        let send = if message.body_changed {
                            if buffered.remaining.is_some() {
                                buffered
                                    .finish(&mut reader, &mut tokio::io::sink(), None, |_| {})
                                    .await?;
                            }
                            message.body.take().unwrap_or_default()
                        } else {
                            buffered.bytes
                        };
                        message.body = None;
                        set_body_headers(&mut message.headers, send.len(), message.body_changed);
                        capture(context, &mut body, &send, cap);
                        writer
                            .write_all(&encode_head(&start, &message.headers))
                            .await?;
                        writer.write_all(&send).await?;
                        drop(send);
                        drop(permit);
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
                            .finish(&mut reader, &mut writer, permit, |bytes| {
                                capture(context, &mut body, bytes, cap)
                            })
                            .await;
                        (message.status, message.headers, copied)
                    }
                }
            };
        let in_flight = request.in_flight.take();
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
        drop(in_flight);
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

fn capture(context: &Context, body: &mut Body, bytes: &[u8], cap: usize) {
    let cap = if context.core.mitm.memory_limited() {
        0
    } else {
        cap
    };
    context.core.requests.capture(body, bytes, cap);
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

async fn wait_between_requests<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    idle: Duration,
    in_flight: &InFlightTracker,
) -> io::Result<bool> {
    loop {
        if in_flight.count() == 0 {
            tokio::select! {
                biased;
                available = reader.fill_buf() => {
                    return Ok(!available?.is_empty());
                }
                _ = tokio::time::sleep(idle) => {
                    if in_flight.count() == 0 {
                        return Ok(false);
                    }
                }
            }
        } else {
            tokio::select! {
                biased;
                available = reader.fill_buf() => {
                    return Ok(!available?.is_empty());
                }
                _ = in_flight.notified() => {}
            }
        }
    }
}

/// Reads one message head, through its blank line. Requests must start with
/// a method token and responses with `HTTP/`, or the stream is something
/// else.
async fn read_head<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    request: bool,
    keepalive_idle: Option<(Duration, &InFlightTracker)>,
) -> io::Result<Head> {
    let mut head = Vec::new();
    loop {
        if head.is_empty()
            && let Some((idle, in_flight)) = keepalive_idle
            && !wait_between_requests(reader, idle, in_flight).await?
        {
            return Ok(Head::End);
        }
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
    use std::path::{Path, PathBuf};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct TestDir(PathBuf);
    impl TestDir {
        fn new(prefix: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn hosted_core(dir: &Path, module_text: &str, files: Vec<(&str, &Path)>) -> Arc<Core> {
        let mut config = clyntis_config::Config::default();
        config.directory = dir.to_path_buf();
        config.internal_host_packet_io = true;
        config.mitm = crate::mitm::test_settings(&["ads.test"]);
        let core = Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        if !module_text.is_empty() {
            let module = clyntis_config::rewrite::parse_module(module_text);
            assert!(module.skipped.is_empty(), "{:?}", module.skipped);
            let file_map = files
                .into_iter()
                .map(|(url, path)| {
                    (
                        url.to_owned(),
                        crate::rewrite::RewriteFile::pin(path).unwrap(),
                    )
                })
                .collect();
            let rewriter = crate::rewrite::Rewriter::new_hosted(
                vec![crate::rewrite::Loaded {
                    name: "ads".into(),
                    module,
                    updated: None,
                    missing: vec![],
                    files: file_map,
                }],
                vec![],
                true,
            );
            let mut resources = crate::resources::Resources::default();
            resources.rewrite = Some(Arc::new(rewriter));
            *core.resources.write().unwrap() = Arc::new(resources);
        }
        core
    }

    fn make_context(core: &Arc<Core>) -> (Arc<Context>, traffic::Tracker) {
        let tracker = traffic::Tracker::new(
            core.clone(),
            clyntis_protocol::Target::new("ads.test", 80).unwrap(),
            crate::Routed::from("DIRECT"),
            "tcp",
        )
        .unwrap();
        let context = Arc::new(Context {
            core: core.clone(),
            state: tracker.state.clone(),
            scheme: "http",
            authority: "ads.test".into(),
        });
        (context, tracker)
    }

    async fn read_http_head<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
        head
    }

    async fn read_http_response<S: AsyncRead + Unpin>(stream: &mut S) -> (String, Vec<u8>) {
        let head = String::from_utf8(read_http_head(stream).await).unwrap();
        let length = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .map_or(0, |v| v.trim().parse().unwrap());
        let mut body = vec![0u8; length];
        stream.read_exact(&mut body).await.unwrap();
        (head, body)
    }

    #[tokio::test]
    async fn oversized_chunk_passes_through_without_buffering_its_payload() {
        let wire = b"2\r\nab\r\n5\r\ncdefg\r\n0\r\n\r\nNEXT";
        let mut reader = &wire[..];
        let body = read_body(&mut reader, Framing::Chunked, 4).await.unwrap();
        assert_eq!(body.bytes, b"ab");
        assert!(reader.starts_with(b"cdefg"));
        let mut out = Vec::new();
        let mut content = Vec::new();
        body.finish(&mut reader, &mut out, None, |b| {
            content.extend_from_slice(b)
        })
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

    #[tokio::test]
    async fn hosted_oversized_streaming_response_releases_rewrite_slot_before_stream_finishes() {
        let dir = TestDir::new("clyntis-observe-oversized");
        let core = hosted_core(
            dir.path(),
            r#"[Rewrite]
response if ${url} ~= /^http:\/\/ads\.test\/stream$/ then response.json.delete("ad")
"#,
            vec![],
        );
        let (context, _tracker) = make_context(&core);
        let (mut app, client) = tokio::io::duplex(64 << 10);
        let (mut server, upstream) = tokio::io::duplex(64 << 10);
        let relay_task = tokio::spawn({
            let context = context.clone();
            async move { relay(client, upstream, &context).await }
        });

        let first_len = 1024usize;
        let rest_len = 2usize << 20;
        let total_len = first_len + rest_len;
        let continue_stream = Arc::new(Notify::new());
        let server_task = tokio::spawn({
            let continue_stream = continue_stream.clone();
            async move {
                let req = String::from_utf8(read_http_head(&mut server).await).unwrap();
                assert!(req.starts_with("GET /stream HTTP/1.1"));
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {total_len}\r\n\r\n"
                );
                server.write_all(head.as_bytes()).await.unwrap();
                server.write_all(&vec![b'a'; first_len]).await.unwrap();
                continue_stream.notified().await;
                let chunk = vec![b'b'; 64 << 10];
                let mut sent = 0usize;
                while sent < rest_len {
                    let n = (rest_len - sent).min(chunk.len());
                    server.write_all(&chunk[..n]).await.unwrap();
                    sent += n;
                }
                server.shutdown().await.unwrap();
            }
        });

        tokio::time::timeout(Duration::from_secs(5), async {
            app.write_all(b"GET /stream HTTP/1.1\r\nHost: ads.test\r\n\r\n")
                .await
                .unwrap();
            let head = String::from_utf8(read_http_head(&mut app).await).unwrap();
            assert!(head.starts_with("HTTP/1.1 200 OK"));
            let mut prefix = vec![0u8; first_len];
            app.read_exact(&mut prefix).await.unwrap();
            assert!(prefix.iter().all(|&b| b == b'a'));

            // Stream is still open and waiting on the server; rewrite_slot must already be free.
            let permit = core.mitm.try_rewrite();
            assert!(
                permit.is_some(),
                "rewrite_slot remained held while streaming oversized response"
            );
            drop(permit);

            continue_stream.notify_one();
            let mut rest = vec![0u8; rest_len];
            app.read_exact(&mut rest).await.unwrap();
            assert!(rest.iter().all(|&b| b == b'b'));
            drop(app);
            server_task.await.unwrap();
            relay_task.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn hosted_bodiless_script_runs_when_rewrite_slot_busy_and_skips_when_memory_limited() {
        let dir = TestDir::new("clyntis-observe-bodiless-script");
        let script = dir.path().join("header.js");
        std::fs::write(
            &script,
            r#"const headers = Object.assign({}, $response.headers, {"X-Bodiless": "1"});
$done({headers});"#,
        )
        .unwrap();
        let core = hosted_core(
            dir.path(),
            r#"[Script]
bodiless = type=http-response,pattern=^http://ads\.test/bodiless$,requires-body=0,script-path=https://s.test/header.js
"#,
            vec![("https://s.test/header.js", &script)],
        );
        let (context, _tracker) = make_context(&core);
        let (mut app, client) = tokio::io::duplex(8192);
        let (mut server, upstream) = tokio::io::duplex(8192);
        let relay_task = tokio::spawn({
            let context = context.clone();
            async move { relay(client, upstream, &context).await }
        });

        tokio::time::timeout(Duration::from_secs(5), async {
            let busy = core.mitm.try_rewrite().unwrap();
            app.write_all(b"GET /bodiless HTTP/1.1\r\nHost: ads.test\r\n\r\n")
                .await
                .unwrap();
            read_http_head(&mut server).await;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            let (head, body) = read_http_response(&mut app).await;
            assert!(head.contains("X-Bodiless: 1\r\n"), "{head}");
            assert_eq!(body, b"ok");
            drop(busy);

            core.mitm.set_memory_limited(true);
            app.write_all(b"GET /bodiless HTTP/1.1\r\nHost: ads.test\r\n\r\n")
                .await
                .unwrap();
            read_http_head(&mut server).await;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            let (head, body) = read_http_response(&mut app).await;
            assert!(!head.contains("X-Bodiless"), "{head}");
            assert_eq!(body, b"ok");

            drop(app);
            drop(server);
            relay_task.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn hosted_piped_rules_skip_atomically_when_rewrite_slot_busy() {
        let dir = TestDir::new("clyntis-observe-piped");
        let core = hosted_core(
            dir.path(),
            r#"[Rewrite]
response if ${url} ~= /^http:\/\/ads\.test\/body-first$/ then response.json.delete("ad") | response.header.set("X-Pipe-BF", "1")
response if ${url} ~= /^http:\/\/ads\.test\/header-first$/ then response.header.set("X-Pipe-HB", "1") | response.json.delete("ad")
response if ${url} ~= /^http:\/\/ads\.test\/(body|header)-first$/ then response.header.set("X-Independent", "1")
"#,
            vec![],
        );
        let (context, _tracker) = make_context(&core);
        let (mut app, client) = tokio::io::duplex(8192);
        let (mut server, upstream) = tokio::io::duplex(8192);
        let relay_task = tokio::spawn({
            let context = context.clone();
            async move { relay(client, upstream, &context).await }
        });

        let payload = br#"{"ad":1,"ok":2}"#;
        let send_resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            payload.len()
        );

        tokio::time::timeout(Duration::from_secs(5), async {
            let busy = core.mitm.try_rewrite().unwrap();

            for (path, header) in [("/body-first", "X-Pipe-BF"), ("/header-first", "X-Pipe-HB")] {
                app.write_all(format!("GET {path} HTTP/1.1\r\nHost: ads.test\r\n\r\n").as_bytes())
                    .await
                    .unwrap();
                read_http_head(&mut server).await;
                server.write_all(send_resp.as_bytes()).await.unwrap();
                server.write_all(payload).await.unwrap();
                let (head, body) = read_http_response(&mut app).await;
                assert!(!head.contains(header), "{path} half-executed: {head}");
                assert!(head.contains("X-Independent: 1\r\n"), "{head}");
                assert_eq!(body, payload);
            }

            drop(busy);

            for (path, header) in [
                ("/body-first", "X-Pipe-BF: 1\r\n"),
                ("/header-first", "X-Pipe-HB: 1\r\n"),
            ] {
                app.write_all(format!("GET {path} HTTP/1.1\r\nHost: ads.test\r\n\r\n").as_bytes())
                    .await
                    .unwrap();
                read_http_head(&mut server).await;
                server.write_all(send_resp.as_bytes()).await.unwrap();
                server.write_all(payload).await.unwrap();
                let (head, body) = read_http_response(&mut app).await;
                assert!(head.contains(header), "{path} missing {header}: {head}");
                assert!(head.contains("X-Independent: 1\r\n"), "{head}");
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                    serde_json::json!({"ok": 2})
                );
            }

            drop(app);
            drop(server);
            relay_task.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn hosted_websocket_upgrade_and_idle_keepalive_slot_lifecycle() {
        let dir = TestDir::new("clyntis-observe-slots");
        let core = hosted_core(dir.path(), "", vec![]);
        core.mitm
            .hosted_keepalive_idle_ms
            .store(60, Ordering::Relaxed);

        // 1. WebSocket upgrade keeps inspection_slot held until the upgraded connection closes.
        let slot = core.mitm.try_inspect().unwrap();
        assert_eq!(core.mitm.active_inspections(), 1);
        let (mut app, client) = tokio::io::duplex(4096);
        let (mut server, upstream) = tokio::io::duplex(4096);
        let observe_task = tokio::spawn({
            let core = core.clone();
            async move {
                core.observe(
                    client,
                    clyntis_protocol::Target::new("ads.test", 80).unwrap(),
                    Box::new(upstream),
                    crate::Routed::from("DIRECT"),
                    false,
                    slot,
                )
                .await
            }
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            app.write_all(
                b"GET /ws HTTP/1.1\r\nHost: ads.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            )
            .await
            .unwrap();
            let req = String::from_utf8(read_http_head(&mut server).await).unwrap();
            assert!(req.starts_with("GET /ws HTTP/1.1"));
            server
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                )
                .await
                .unwrap();
            let resp = String::from_utf8(read_http_head(&mut app).await).unwrap();
            assert!(resp.starts_with("HTTP/1.1 101 "));
            app.write_all(b"\x81\x04ping").await.unwrap();
            let mut buf = [0u8; 6];
            server.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"\x81\x04ping");
            assert_eq!(core.mitm.active_inspections(), 1);
            server.write_all(b"\x81\x04pong").await.unwrap();
            app.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"\x81\x04pong");
            assert_eq!(core.mitm.active_inspections(), 1);
            drop(app);
            drop(server);
            observe_task.await.unwrap().unwrap();
            assert_eq!(core.mitm.active_inspections(), 0);
        })
        .await
        .unwrap();

        // 2. Idle keep-alive closes after hosted_keepalive_idle_ms, without closing slow response.
        let slot = core.mitm.try_inspect().unwrap();
        assert_eq!(core.mitm.active_inspections(), 1);
        let (mut app, client) = tokio::io::duplex(4096);
        let (mut server, upstream) = tokio::io::duplex(4096);
        let observe_task = tokio::spawn({
            let core = core.clone();
            async move {
                core.observe(
                    client,
                    clyntis_protocol::Target::new("ads.test", 80).unwrap(),
                    Box::new(upstream),
                    crate::Routed::from("DIRECT"),
                    false,
                    slot,
                )
                .await
            }
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            app.write_all(b"GET /slow HTTP/1.1\r\nHost: ads.test\r\n\r\n")
                .await
                .unwrap();
            read_http_head(&mut server).await;
            // In-flight response exceeds hosted_keepalive_idle_ms (60 ms).
            tokio::time::sleep(Duration::from_millis(160)).await;
            assert_eq!(core.mitm.active_inspections(), 1);
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nslow")
                .await
                .unwrap();
            let (_, body) = read_http_response(&mut app).await;
            assert_eq!(body, b"slow");

            // Keep both client and server open; idle timer must end the relay and free the slot.
            let mut eof = [0u8; 1];
            assert_eq!(app.read(&mut eof).await.unwrap(), 0);
            observe_task.await.unwrap().unwrap();
            assert_eq!(core.mitm.active_inspections(), 0);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn hosted_local_answer_reserves_shared_body_budget_until_sent() {
        let dir = TestDir::new("clyntis-observe-answer-budget");
        let script = dir.path().join("answer.js");
        let body_len = 256usize << 10;
        std::fs::write(
            &script,
            format!(r#"$done({{response: {{status: 200, body: "x".repeat({body_len})}}}});"#),
        )
        .unwrap();
        let core = hosted_core(
            dir.path(),
            r#"[Script]
ans = type=http-request,pattern=^http://ads\.test/local$,requires-body=0,script-path=https://s.test/answer.js
"#,
            vec![("https://s.test/answer.js", &script)],
        );
        let (context, _tracker) = make_context(&core);
        let (mut app, client) = tokio::io::duplex(512 << 10);
        let (mut server, upstream) = tokio::io::duplex(8192);
        let relay_task = tokio::spawn({
            let context = context.clone();
            async move { relay(client, upstream, &context).await }
        });

        tokio::time::timeout(Duration::from_secs(5), async {
            // Queue a slow upstream request first, then a requires-body=0 local script answer behind it.
            app.write_all(b"GET /upstream HTTP/1.1\r\nHost: ads.test\r\n\r\n")
                .await
                .unwrap();
            read_http_head(&mut server).await;
            app.write_all(b"GET /local HTTP/1.1\r\nHost: ads.test\r\n\r\n")
                .await
                .unwrap();

            while core.requests.captured_bytes() < body_len {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(core.requests.captured_bytes(), body_len);
            assert!(
                core.mitm.try_rewrite().is_some(),
                "requires-body=0 local answer must not occupy rewrite_slot"
            );
            assert!(
                core.requests
                    .reserve_body_budget(crate::requests::HOSTED_CAPTURE_BYTES - body_len + 1)
                    .is_err(),
                "local answer must share Requests::capture_budget"
            );

            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            assert!(read_http_response(&mut app).await.1.is_empty());
            assert_eq!(read_http_response(&mut app).await.1.len(), body_len);

            while core
                .requests
                .list(0, 10)
                .0
                .iter()
                .filter(|e| e.status == "http")
                .count()
                < 2
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            // Only the 128 KiB log body cap remains after sending; the 256 KiB answer budget is freed.
            assert_eq!(core.requests.captured_bytes(), 128 << 10);
            core.requests.clear();
            assert_eq!(core.requests.captured_bytes(), 0);

            drop(app);
            drop(server);
            relay_task.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn hosted_local_answer_forwards_upstream_when_body_budget_exhausted() {
        let dir = TestDir::new("clyntis-observe-answer-exhausted");
        let script = dir.path().join("answer.js");
        let script_body = "local-script-body-over-16-bytes";
        let mock_body = "local-mock-body-over-16-bytes";
        std::fs::write(
            &script,
            format!(
                r#"$done({{headers: {{"X-Mutated": "1"}}, response: {{status: 200, body: "{script_body}"}}}});"#
            ),
        )
        .unwrap();
        let core = hosted_core(
            dir.path(),
            &format!(
                r#"[Script]
ans = type=http-request,pattern=^http://ads\.test/script$,requires-body=0,script-path=https://s.test/answer.js
[Rewrite]
request if ${{url}} == "http://ads.test/mock" then response.body.mock("text", "{mock_body}", 200)
"#
            ),
            vec![("https://s.test/answer.js", &script)],
        );
        let (context, _tracker) = make_context(&core);
        let (mut app, client) = tokio::io::duplex(16 << 10);
        let (mut server, upstream) = tokio::io::duplex(16 << 10);
        let relay_task = tokio::spawn({
            let context = context.clone();
            async move { relay(client, upstream, &context).await }
        });

        tokio::time::timeout(Duration::from_secs(5), async {
            let held = core
                .requests
                .reserve_body_budget(crate::requests::HOSTED_CAPTURE_BYTES - 16)
                .unwrap()
                .unwrap();

            app.write_all(b"GET /script HTTP/1.1\r\nHost: ads.test\r\n\r\n")
                .await
                .unwrap();
            let req = String::from_utf8(read_http_head(&mut server).await).unwrap();
            assert!(req.starts_with("GET /script HTTP/1.1"), "{req}");
            assert!(!req.contains("X-Mutated"), "{req}");
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nupstream")
                .await
                .unwrap();
            assert_eq!(read_http_response(&mut app).await.1, b"upstream");

            app.write_all(b"GET /mock HTTP/1.1\r\nHost: ads.test\r\n\r\n")
                .await
                .unwrap();
            let req = String::from_utf8(read_http_head(&mut server).await).unwrap();
            assert!(req.starts_with("GET /mock HTTP/1.1"), "{req}");
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nmock-miss")
                .await
                .unwrap();
            assert_eq!(read_http_response(&mut app).await.1, b"mock-miss");

            while core
                .requests
                .list(0, 10)
                .0
                .iter()
                .filter(|e| e.status == "http")
                .count()
                < 2
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(core.rewrite_status()["total"], 0);
            for entry in core
                .requests
                .list(0, 10)
                .0
                .into_iter()
                .filter_map(|e| e.http)
            {
                assert!(entry.rewrite.is_none(), "{entry:?}");
                assert!(entry.rewrite_actions.is_empty(), "{entry:?}");
                assert!(!entry.answered, "{entry:?}");
            }

            // Once budget frees up, subsequent requests answer locally.
            drop(held);
            app.write_all(b"GET /script HTTP/1.1\r\nHost: ads.test\r\n\r\n")
                .await
                .unwrap();
            assert_eq!(read_http_response(&mut app).await.1, script_body.as_bytes());

            app.write_all(b"GET /mock HTTP/1.1\r\nHost: ads.test\r\n\r\n")
                .await
                .unwrap();
            assert_eq!(read_http_response(&mut app).await.1, mock_body.as_bytes());

            drop(app);
            drop(server);
            relay_task.await.unwrap().unwrap();
            assert_eq!(core.rewrite_status()["total"], 2);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn hosted_memory_limited_reuses_cached_rules_and_skips_uncached_without_recompiling() {
        let dir = TestDir::new("clyntis-observe-memory-limited-cache");
        let core = hosted_core(
            dir.path(),
            r#"[Rewrite]
request if ${url} ~= /^http:\/\/ads\.test\/warm$/ then url.replace("http://ads.test/rewritten") | header.replace("X-Test", /^old-/, "new-")
response if ${url} ~= /^http:\/\/ads\.test\/rewritten$/ && ${response.header["X-Tag"]} ~= /^hit-\d+$/ then response.header.set("X-Resp", "ok")
request if ${url} ~= /^http:\/\/ads\.test\/redir\/(.*)$/ as m then redirect(302, "http://other.test/${m.1}")
"#,
            vec![],
        );
        let rewriter = core.rewriter().unwrap();
        assert_eq!(rewriter.cached_bucket_count(), 0);
        assert_eq!(rewriter.cached_rule_runtime_count(), 0);

        let (context, _tracker) = make_context(&core);
        let (mut app, client) = tokio::io::duplex(16 << 10);
        let (mut server, upstream) = tokio::io::duplex(16 << 10);
        let relay_task = tokio::spawn({
            let context = context.clone();
            async move { relay(client, upstream, &context).await }
        });

        tokio::time::timeout(Duration::from_secs(5), async {
            // 1. Warm the host bucket and runtimes for /warm (leaving /redir runtime uncompiled).
            app.write_all(b"GET /warm HTTP/1.1\r\nHost: ads.test\r\nX-Test: old-1\r\n\r\n")
                .await
                .unwrap();
            let req = String::from_utf8(read_http_head(&mut server).await).unwrap();
            assert!(req.starts_with("GET /rewritten HTTP/1.1"), "{req}");
            assert!(req.contains("X-Test: new-1\r\n"), "{req}");
            server
                .write_all(b"HTTP/1.1 200 OK\r\nX-Tag: hit-1\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            let (head, body) = read_http_response(&mut app).await;
            assert!(head.contains("X-Resp: ok\r\n"), "{head}");
            assert_eq!(body, b"ok");
            assert_eq!(rewriter.cached_bucket_count(), 1);
            let warm_runtimes = rewriter.cached_rule_runtime_count();
            assert!(warm_runtimes >= 3);

            // 2. Under memory_limited(true), already-compiled rules still apply while uncached
            // Redirect skips cleanly without dropping the connection or compiling its runtime.
            core.mitm.set_memory_limited(true);
            app.write_all(b"GET /warm HTTP/1.1\r\nHost: ads.test\r\nX-Test: old-2\r\n\r\n")
                .await
                .unwrap();
            let req = String::from_utf8(read_http_head(&mut server).await).unwrap();
            assert!(req.starts_with("GET /rewritten HTTP/1.1"), "{req}");
            assert!(req.contains("X-Test: new-2\r\n"), "{req}");
            server
                .write_all(b"HTTP/1.1 200 OK\r\nX-Tag: hit-2\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            let (head, body) = read_http_response(&mut app).await;
            assert!(head.contains("X-Resp: ok\r\n"), "{head}");
            assert_eq!(body, b"ok");

            app.write_all(b"GET /redir/one HTTP/1.1\r\nHost: ads.test\r\n\r\n")
                .await
                .unwrap();
            let req = String::from_utf8(read_http_head(&mut server).await).unwrap();
            assert!(req.starts_with("GET /redir/one HTTP/1.1"), "{req}");
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nredir")
                .await
                .unwrap();
            let (head, body) = read_http_response(&mut app).await;
            assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
            assert_eq!(body, b"redir");
            assert_eq!(rewriter.cached_rule_runtime_count(), warm_runtimes);

            // 3. After relieve_memory(), uncached rules skip without recompiling on the same socket.
            rewriter.relieve_memory();
            assert_eq!(rewriter.cached_bucket_count(), 0);
            assert_eq!(rewriter.cached_rule_runtime_count(), 0);

            app.write_all(b"GET /warm HTTP/1.1\r\nHost: ads.test\r\nX-Test: old-3\r\n\r\n")
                .await
                .unwrap();
            let req = String::from_utf8(read_http_head(&mut server).await).unwrap();
            assert!(req.starts_with("GET /warm HTTP/1.1"), "{req}");
            assert!(req.contains("X-Test: old-3\r\n"), "{req}");
            server
                .write_all(b"HTTP/1.1 200 OK\r\nX-Tag: hit-3\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            let (head, body) = read_http_response(&mut app).await;
            assert!(!head.contains("X-Resp"), "{head}");
            assert_eq!(body, b"ok");

            app.write_all(b"GET /redir/two HTTP/1.1\r\nHost: ads.test\r\n\r\n")
                .await
                .unwrap();
            let req = String::from_utf8(read_http_head(&mut server).await).unwrap();
            assert!(req.starts_with("GET /redir/two HTTP/1.1"), "{req}");
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo")
                .await
                .unwrap();
            let (head, body) = read_http_response(&mut app).await;
            assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
            assert_eq!(body, b"two");
            assert_eq!(rewriter.cached_bucket_count(), 0);
            assert_eq!(rewriter.cached_rule_runtime_count(), 0);

            // 4. Even if response_rules were collected before pressure, relief during flight skips
            // uncached response rules without recompiling.
            core.mitm.set_memory_limited(false);
            app.write_all(b"GET /warm HTTP/1.1\r\nHost: ads.test\r\nX-Test: old-4\r\n\r\n")
                .await
                .unwrap();
            let req = String::from_utf8(read_http_head(&mut server).await).unwrap();
            assert!(req.starts_with("GET /rewritten HTTP/1.1"), "{req}");
            core.mitm.set_memory_limited(true);
            rewriter.relieve_memory();
            server
                .write_all(b"HTTP/1.1 200 OK\r\nX-Tag: hit-4\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            let (head, body) = read_http_response(&mut app).await;
            assert!(!head.contains("X-Resp"), "{head}");
            assert_eq!(body, b"ok");
            assert_eq!(rewriter.cached_bucket_count(), 0);
            assert_eq!(rewriter.cached_rule_runtime_count(), 0);

            drop(app);
            drop(server);
            relay_task.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    async fn relay_single_piped_get(
        prefix: &str,
        rule_text: &str,
        warm: impl FnOnce(&crate::rewrite::Rewriter),
    ) -> (String, Arc<Core>, Arc<crate::rewrite::Rewriter>) {
        let dir = TestDir::new(prefix);
        let core = hosted_core(dir.path(), rule_text, vec![]);
        let rewriter = core.rewriter().unwrap();
        warm(&rewriter);
        core.mitm.set_memory_limited(true);

        let (context, _tracker) = make_context(&core);
        let (mut app, client) = tokio::io::duplex(16 << 10);
        let (mut server, upstream) = tokio::io::duplex(16 << 10);
        let relay_task = tokio::spawn({
            let context = context.clone();
            async move { relay(client, upstream, &context).await }
        });

        let upstream_req = tokio::time::timeout(Duration::from_secs(5), async {
            app.write_all(b"GET /pipe HTTP/1.1\r\nHost: ads.test\r\nX-Test: old-1\r\n\r\n")
                .await
                .unwrap();
            let req = String::from_utf8(read_http_head(&mut server).await).unwrap();
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            let (_, body) = read_http_response(&mut app).await;
            assert_eq!(body, b"ok");
            while core
                .requests
                .list(0, 10)
                .0
                .iter()
                .filter(|e| e.status == "http")
                .count()
                < 1
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            drop(app);
            drop(server);
            relay_task.await.unwrap().unwrap();
            req
        })
        .await
        .unwrap();
        (upstream_req, core, rewriter)
    }

    #[tokio::test]
    async fn hosted_pipeline_finishes_after_memory_pressure_arrives_during_body_read() {
        let dir = TestDir::new("clyntis-observe-pipe-pressure");
        let core = hosted_core(
            dir.path(),
            r#"[Rewrite]
request if ${url} ~= /^http:\/\/ads\.test\/pipe$/ then header.set("X-Stage1", "applied") | request.body.replace("old", "new") | header.replace("X-Test", /^old-/, "new-")
"#,
            vec![],
        );
        let rewriter = core.rewriter().unwrap();
        let (context, _tracker) = make_context(&core);
        let (mut app, client) = tokio::io::duplex(8192);
        let (mut server, upstream) = tokio::io::duplex(8192);
        let relay_task = tokio::spawn(async move { relay(client, upstream, &context).await });

        tokio::time::timeout(Duration::from_secs(5), async {
            app.write_all(b"POST /pipe HTTP/1.1\r\nHost: ads.test\r\nX-Test: old-1\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n")
                .await
                .unwrap();
            assert_eq!(read_http_head(&mut app).await, b"HTTP/1.1 100 Continue\r\n\r\n");
            core.mitm.set_memory_limited(true);
            rewriter.relieve_memory();
            app.write_all(b"old").await.unwrap();

            let req = String::from_utf8(read_http_head(&mut server).await).unwrap();
            assert!(req.contains("X-Stage1: applied\r\n"), "{req}");
            assert!(req.contains("X-Test: new-1\r\n"), "{req}");
            let mut body = [0; 3];
            server.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"new");
            assert_eq!(rewriter.cached_rule_runtime_count(), 0);
            server.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await.unwrap();
            assert_eq!(read_http_response(&mut app).await.1, b"ok");

            app.write_all(b"GET /next HTTP/1.1\r\nHost: ads.test\r\n\r\n").await.unwrap();
            assert!(read_http_head(&mut server).await.starts_with(b"GET /next HTTP/1.1\r\n"));
            server.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnext").await.unwrap();
            assert_eq!(read_http_response(&mut app).await.1, b"next");
            drop(app);
            drop(server);
            relay_task.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn hosted_piped_url_replace_and_header_replace_skips_atomically_on_mixed_cache() {
        let (req, core, rewriter) = relay_single_piped_get(
            "clyntis-observe-pipe-mixed-url",
            r#"[Rewrite]
request if ${url} ~= /^http:\/\/ads\.test\/pipe$/ then url.replace("http://ads.test/rewritten") | header.replace("X-Test", /^old-/, "new-")
"#,
            |rewriter| {
                assert_eq!(
                    rewriter.matching(Phase::Request, "http://ads.test/pipe"),
                    vec![0, 1]
                );
                assert_eq!(
                    rewrite::replace_url(rewriter, 0, "http://ads.test/pipe").as_deref(),
                    Some("http://ads.test/rewritten")
                );
                assert_eq!(rewriter.cached_bucket_count(), 1);
                assert_eq!(rewriter.cached_rule_runtime_count(), 1);
            },
        )
        .await;

        assert!(req.starts_with("GET /pipe HTTP/1.1"), "{req}");
        assert!(req.contains("X-Test: old-1\r\n"), "{req}");
        assert_eq!(rewriter.cached_rule_runtime_count(), 1);
        assert_eq!(core.rewrite_status()["total"], 0);
        let http = core
            .requests
            .list(0, 10)
            .0
            .into_iter()
            .find_map(|e| e.http)
            .unwrap();
        assert!(http.rewrite.is_none(), "{http:?}");
        assert!(http.rewrite_actions.is_empty(), "{http:?}");
    }

    #[tokio::test]
    async fn hosted_piped_header_set_and_header_replace_skips_atomically_on_mixed_cache() {
        let (req, core, rewriter) = relay_single_piped_get(
            "clyntis-observe-pipe-mixed-header",
            r#"[Rewrite]
request if ${url} ~= /^http:\/\/ads\.test\/pipe$/ then header.set("X-Stage1", "applied") | header.replace("X-Test", /^old-/, "new-")
"#,
            |rewriter| {
                assert_eq!(
                    rewriter.matching(Phase::Request, "http://ads.test/pipe"),
                    vec![0, 1]
                );
                assert_eq!(rewriter.cached_bucket_count(), 1);
                assert_eq!(rewriter.cached_rule_runtime_count(), 0);
            },
        )
        .await;

        assert!(req.starts_with("GET /pipe HTTP/1.1"), "{req}");
        assert!(!req.contains("X-Stage1"), "{req}");
        assert!(req.contains("X-Test: old-1\r\n"), "{req}");
        assert_eq!(rewriter.cached_rule_runtime_count(), 0);
        assert_eq!(core.rewrite_status()["total"], 0);
        let http = core
            .requests
            .list(0, 10)
            .0
            .into_iter()
            .find_map(|e| e.http)
            .unwrap();
        assert!(http.rewrite.is_none(), "{http:?}");
        assert!(http.rewrite_actions.is_empty(), "{http:?}");
    }

    #[tokio::test]
    async fn hosted_piped_url_replace_and_header_replace_applies_when_both_warm() {
        let (req, core, rewriter) = relay_single_piped_get(
            "clyntis-observe-pipe-both-warm",
            r#"[Rewrite]
request if ${url} ~= /^http:\/\/ads\.test\/pipe$/ then url.replace("http://ads.test/rewritten") | header.replace("X-Test", /^old-/, "new-")
"#,
            |rewriter| {
                assert_eq!(
                    rewriter.matching(Phase::Request, "http://ads.test/pipe"),
                    vec![0, 1]
                );
                assert_eq!(
                    rewrite::replace_url(rewriter, 0, "http://ads.test/pipe").as_deref(),
                    Some("http://ads.test/rewritten")
                );
                let mut headers = vec![("X-Test".into(), "old-0".into())];
                rewrite::apply_header(rewriter, 1, &mut headers);
                assert_eq!(headers[0].1, "new-0");
                assert_eq!(rewriter.cached_bucket_count(), 1);
                assert_eq!(rewriter.cached_rule_runtime_count(), 2);
            },
        )
        .await;

        assert!(req.starts_with("GET /rewritten HTTP/1.1"), "{req}");
        assert!(req.contains("X-Test: new-1\r\n"), "{req}");
        assert_eq!(rewriter.cached_rule_runtime_count(), 2);
        assert_eq!(core.rewrite_status()["total"], 2);
        let http = core
            .requests
            .list(0, 10)
            .0
            .into_iter()
            .find_map(|e| e.http)
            .unwrap();
        assert_eq!(http.rewrite_actions, vec!["url", "header"]);
    }
}
