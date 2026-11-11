//! Scripts of rewrite modules, run in QuickJS with the API that Surge, Loon
//! and Quantumult X scripts expect: `$request`, `$response`, `$argument`,
//! `$done`, `$persistentStore` / `$prefs`, `$notification` / `$notify`,
//! `$httpClient`, `setTimeout` and `console`. Each run gets a fresh runtime
//! with a memory limit and a deadline, on a blocking thread; runs at once
//! are limited, since the iOS tunnel has little memory.
use crate::rewrite::Answer;
use anyhow::Result;
use clyntis_config::rewrite::Phase;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

/// The default and the longest time a script may take.
pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const MAX_TIMEOUT: Duration = Duration::from_secs(60);
/// What `$httpClient` responses and stored values may hold.
const HTTP_BODY_LIMIT: usize = 8 << 20;
const STORE_VALUE_LIMIT: usize = 512 << 10;
const STORE_LIMIT: usize = 4 << 20;

/// One script run.
pub(crate) struct Job {
    pub(crate) name: String,
    pub(crate) path: PathBuf,
    pub(crate) argument: String,
    pub(crate) timeout: Duration,
    pub(crate) binary: bool,
    pub(crate) phase: Phase,
    pub(crate) url: String,
    pub(crate) method: String,
    pub(crate) request_headers: Vec<(String, String)>,
    /// `None` when the script does not ask for bodies.
    pub(crate) request_body: Option<Vec<u8>>,
    pub(crate) response: Option<ResponseInput>,
}
pub(crate) struct ResponseInput {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Option<Vec<u8>>,
}

/// What `$done` asked for; `None` fields stay as they were.
#[derive(Debug, Default)]
pub(crate) struct Outcome {
    pub(crate) url: Option<String>,
    pub(crate) status: Option<u16>,
    pub(crate) headers: Option<Vec<(String, String)>>,
    pub(crate) body: Option<Vec<u8>>,
    /// A request script answering in the server's place.
    pub(crate) response: Option<Answer>,
    /// Close the connection.
    pub(crate) abort: bool,
}

/// Scripts' shared state: the store and how many may run at once.
pub(crate) struct Engine {
    permits: tokio::sync::Semaphore,
    memory: usize,
    store: Arc<Mutex<Store>>,
}

struct Store {
    path: PathBuf,
    values: Option<HashMap<String, String>>,
}
impl Store {
    fn values(&mut self) -> &mut HashMap<String, String> {
        self.values.get_or_insert_with(|| {
            std::fs::read(&self.path)
                .ok()
                .and_then(|data| serde_json::from_slice(&data).ok())
                .unwrap_or_default()
        })
    }
    fn read(&mut self, key: &str) -> Option<String> {
        self.values().get(key).cloned()
    }
    fn write(&mut self, key: &str, value: Option<String>) -> bool {
        if value.as_ref().is_some_and(|v| v.len() > STORE_VALUE_LIMIT) {
            return false;
        }
        let values = self.values();
        match value {
            Some(value) => {
                values.insert(key.to_owned(), value);
            }
            None => {
                values.remove(key);
            }
        }
        let total: usize = values.iter().map(|(k, v)| k.len() + v.len()).sum();
        if total > STORE_LIMIT {
            values.remove(key);
            return false;
        }
        let Ok(data) = serde_json::to_vec(values) else {
            return false;
        };
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let temp = self.path.with_extension("tmp");
        std::fs::write(&temp, data)
            .and_then(|_| std::fs::rename(&temp, &self.path))
            .is_ok()
    }
}

impl Engine {
    pub(crate) fn new(directory: &std::path::Path, hosted: bool) -> Self {
        Self {
            permits: tokio::sync::Semaphore::new(if hosted { 1 } else { 4 }),
            memory: if hosted { 16 << 20 } else { 128 << 20 },
            store: Arc::new(Mutex::new(Store {
                path: directory.join("rewrite/store.json"),
                values: None,
            })),
        }
    }
}

/// Runs a script on a blocking thread, waiting for a free slot first.
pub(crate) async fn run(core: &Arc<crate::Core>, job: Job) -> Result<Outcome> {
    let timeout = job.timeout.min(MAX_TIMEOUT);
    let deadline = tokio::time::Instant::now() + timeout;
    let _permit = tokio::time::timeout_at(deadline, core.scripts.permits.acquire())
        .await
        .map_err(|_| anyhow::anyhow!("script {}: waited too long for a free slot", job.name))??;
    let source = tokio::fs::read_to_string(&job.path).await?;
    let core = core.clone();
    let handle = tokio::runtime::Handle::current();
    let deadline = deadline.into_std();
    tokio::task::spawn_blocking(move || imp::run(core, handle, job, source, deadline)).await?
}

#[cfg(target_os = "android")]
mod imp {
    use super::*;
    pub(super) fn run(
        _core: Arc<crate::Core>,
        _handle: tokio::runtime::Handle,
        _job: Job,
        _source: String,
        _deadline: std::time::Instant,
    ) -> Result<Outcome> {
        anyhow::bail!("scripts are not supported on this platform")
    }
}

#[cfg(not(target_os = "android"))]
mod imp {
    use super::*;
    use anyhow::{Context as _, anyhow};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use rquickjs::{ArrayBuffer, Context, Ctx, Function, Object, Runtime, TypedArray, Value};
    use std::{cell::RefCell, rc::Rc, time::Instant};

    const PRELUDE: &str = include_str!("script_prelude.js");

    struct State {
        done: Option<Outcome>,
        logs: Vec<String>,
    }

    pub(super) fn run(
        core: Arc<crate::Core>,
        handle: tokio::runtime::Handle,
        job: Job,
        source: String,
        deadline: Instant,
    ) -> Result<Outcome> {
        let runtime = Runtime::new()?;
        runtime.set_memory_limit(core.scripts.memory);
        runtime.set_max_stack_size(1 << 20);
        runtime.set_interrupt_handler(Some(Box::new(move || Instant::now() >= deadline)));
        let context = Context::full(&runtime)?;
        let state = Rc::new(RefCell::new(State {
            done: None,
            logs: Vec::new(),
        }));
        let name = job.name.clone();
        let result = (|| -> Result<()> {
            context.with(|ctx| -> Result<()> {
                install(&ctx, &core, &job, &state)?;
                exec(&ctx, &source, &name)
            })?;
            // The event loop: promise jobs, then `$httpClient` calls and
            // timers in order, until `$done` or nothing is left.
            loop {
                loop {
                    if Instant::now() >= deadline {
                        anyhow::bail!("timed out");
                    }
                    match runtime.execute_pending_job() {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(error) => {
                            let message = error.0.with(|ctx| describe(&ctx.catch()));
                            state
                                .borrow_mut()
                                .logs
                                .push(format!("unhandled: {message}"));
                        }
                    }
                }
                if state.borrow().done.is_some() {
                    return Ok(());
                }
                match context.with(|ctx| step(&ctx))? {
                    Step::Idle => return Ok(()),
                    Step::Timer(at) => {
                        let wait = Duration::from_millis((at - now_ms()).max(0.0) as u64);
                        if Instant::now() + wait >= deadline {
                            anyhow::bail!("timed out waiting for a timer");
                        }
                        std::thread::sleep(wait);
                        context.with(|ctx| call(&ctx, "__fire", ()))?;
                    }
                    Step::Http(call_info) => {
                        let left = deadline.saturating_duration_since(Instant::now());
                        let reply = handle.block_on(async {
                            tokio::time::timeout(
                                call_info.timeout.min(left),
                                fetch(
                                    &core,
                                    &call_info.method,
                                    &call_info.url,
                                    call_info.headers,
                                    call_info.body,
                                ),
                            )
                            .await
                            .unwrap_or_else(|_| Err(anyhow!("request timed out")))
                        });
                        context.with(|ctx| -> Result<()> {
                            match reply {
                                Ok((status, headers, body)) => {
                                    let object = Object::new(ctx.clone())?;
                                    for (name, value) in headers {
                                        object.set(name, value)?;
                                    }
                                    let body: Value = if call_info.binary {
                                        TypedArray::<u8>::new(ctx.clone(), body)?.into_value()
                                    } else {
                                        rquickjs::String::from_str(
                                            ctx.clone(),
                                            &String::from_utf8_lossy(&body),
                                        )?
                                        .into_value()
                                    };
                                    call(
                                        &ctx,
                                        "__reply",
                                        (Value::new_null(ctx.clone()), status, object, body),
                                    )
                                }
                                Err(error) => call(&ctx, "__reply", (format!("{error:#}"),)),
                            }
                        })?;
                    }
                }
            }
        })();
        let mut state = state.borrow_mut();
        for line in state.logs.drain(..) {
            tracing::info!(script = %name, "{line}");
        }
        match result {
            Ok(()) => Ok(state.done.take().unwrap_or_default()),
            // A script that called `$done` and then failed still counts.
            Err(_) if state.done.is_some() => Ok(state.done.take().unwrap_or_default()),
            Err(error) => Err(error.context(format!("script {name}"))),
        }
    }

    struct HttpCall {
        method: String,
        url: String,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
        binary: bool,
        timeout: Duration,
    }
    enum Step {
        Idle,
        Timer(f64),
        Http(HttpCall),
    }

    /// What the script waits for next.
    fn step(ctx: &Ctx<'_>) -> Result<Step> {
        let next: Value = ctx.globals().get::<_, Function>("__next")?.call(())?;
        let Some(next) = next.as_object() else {
            return Ok(Step::Idle);
        };
        let kind: String = next.get("kind")?;
        if kind == "timer" {
            return Ok(Step::Timer(next.get("at")?));
        }
        Ok(Step::Http(HttpCall {
            method: next.get("method")?,
            url: next.get("url")?,
            headers: header_list(&next.get::<_, Value>("headers")?),
            body: bytes_of(&next.get::<_, Value>("body")?),
            binary: next.get::<_, Option<bool>>("binary")?.unwrap_or(false),
            timeout: next
                .get::<_, Option<f64>>("timeout")?
                .filter(|t| *t > 0.0)
                // Surge takes seconds, Loon milliseconds.
                .map(|t| if t > 120.0 { t / 1000.0 } else { t })
                .map_or(Duration::from_secs(10), Duration::from_secs_f64),
        }))
    }

    fn now_ms() -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64() * 1000.0)
    }

    fn call<'js, A: rquickjs::function::IntoArgs<'js>>(
        ctx: &Ctx<'js>,
        name: &str,
        args: A,
    ) -> Result<()> {
        let function: Function = ctx.globals().get(name)?;
        let result: rquickjs::Result<Value> = function.call(args);
        if result.is_err() {
            anyhow::bail!("{}", describe(&ctx.catch()));
        }
        Ok(())
    }

    fn exec(ctx: &Ctx<'_>, source: &str, name: &str) -> Result<()> {
        // Sloppy mode, as Surge and Loon run scripts: many assign to
        // undeclared variables.
        let mut options = rquickjs::context::EvalOptions::default();
        options.strict = false;
        let result: rquickjs::Result<Value> =
            ctx.eval_with_options(source.as_bytes().to_vec(), options);
        if result.is_err() {
            anyhow::bail!("{name}: {}", describe(&ctx.catch()));
        }
        Ok(())
    }

    fn describe(error: &Value<'_>) -> String {
        if let Some(object) = error.as_object() {
            let message: Option<String> = object.get("message").ok();
            let stack: Option<String> = object.get("stack").ok();
            if let Some(message) = message {
                let at = stack
                    .and_then(|s| s.lines().find(|l| !l.trim().is_empty()).map(str::to_owned))
                    .unwrap_or_default();
                return format!("{message} {}", at.trim()).trim().to_owned();
            }
        }
        if let Some(text) = error.as_string() {
            return text.to_string().unwrap_or_default();
        }
        if error.is_null() || error.is_undefined() {
            return "uncatchable error (time or memory limit)".into();
        }
        format!("{error:?}")
    }

    fn install<'js>(
        ctx: &Ctx<'js>,
        core: &Arc<crate::Core>,
        job: &Job,
        state: &Rc<RefCell<State>>,
    ) -> Result<()> {
        let globals = ctx.globals();
        let native = Object::new(ctx.clone())?;
        {
            let state = state.clone();
            native.set(
                "done",
                Function::new(ctx.clone(), move |value: Value| {
                    let mut state = state.borrow_mut();
                    if state.done.is_none() {
                        state.done = Some(outcome(&value));
                    }
                })?,
            )?;
        }
        {
            let state = state.clone();
            native.set(
                "log",
                Function::new(ctx.clone(), move |line: String| {
                    let mut state = state.borrow_mut();
                    if state.logs.len() < 100 {
                        state.logs.push(line.chars().take(2000).collect());
                    }
                })?,
            )?;
        }
        {
            let store = core.scripts.store.clone();
            native.set(
                "read",
                Function::new(ctx.clone(), move |key: String| {
                    store.lock().unwrap().read(&key)
                })?,
            )?;
        }
        {
            let store = core.scripts.store.clone();
            native.set(
                "write",
                Function::new(ctx.clone(), move |value: Option<String>, key: String| {
                    store.lock().unwrap().write(&key, value)
                })?,
            )?;
        }
        native.set("now", Function::new(ctx.clone(), now_ms)?)?;
        native.set(
            "utf8Decode",
            Function::new(ctx.clone(), |value: Value| {
                String::from_utf8_lossy(&bytes_of(&value).unwrap_or_default()).into_owned()
            })?,
        )?;
        native.set(
            "utf8Encode",
            Function::new(ctx.clone(), |ctx: Ctx<'js>, text: String| {
                TypedArray::<u8>::new(ctx, text.into_bytes())
            })?,
        )?;
        native.set(
            "btoa",
            Function::new(ctx.clone(), |text: String| {
                // Latin-1, as browsers do.
                let bytes: Vec<u8> = text.chars().map(|c| c as u32 as u8).collect();
                STANDARD.encode(bytes)
            })?,
        )?;
        native.set(
            "atob",
            Function::new(ctx.clone(), |text: String| {
                let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
                let padded = format!("{cleaned}{}", "=".repeat((4 - cleaned.len() % 4) % 4));
                STANDARD
                    .decode(padded)
                    .map(|bytes| bytes.into_iter().map(char::from).collect::<String>())
                    .unwrap_or_default()
            })?,
        )?;
        globals.set("__native", native)?;
        exec(ctx, PRELUDE, "prelude")?;

        let request = Object::new(ctx.clone())?;
        request.set("url", job.url.as_str())?;
        request.set("method", job.method.as_str())?;
        request.set("headers", headers_object(ctx, &job.request_headers)?)?;
        if let Some(body) = &job.request_body {
            set_body(ctx, &request, body, job.binary)?;
        }
        globals.set("$request", request)?;
        if let Some(response) = &job.response {
            let object = Object::new(ctx.clone())?;
            object.set("status", response.status)?;
            object.set("statusCode", response.status)?;
            object.set("headers", headers_object(ctx, &response.headers)?)?;
            if let Some(body) = &response.body {
                set_body(ctx, &object, body, job.binary)?;
            }
            globals.set("$response", object)?;
        }
        globals.set("$argument", job.argument.as_str())?;
        let script = Object::new(ctx.clone())?;
        script.set("name", job.name.as_str())?;
        script.set(
            "type",
            match job.phase {
                Phase::Request => "http-request",
                Phase::Response => "http-response",
            },
        )?;
        script.set("startTime", now_ms())?;
        globals.set("$script", script)?;
        Ok(())
    }

    fn set_body<'js>(
        ctx: &Ctx<'js>,
        object: &Object<'js>,
        body: &[u8],
        binary: bool,
    ) -> Result<()> {
        if binary {
            let bytes = TypedArray::<u8>::new(ctx.clone(), body.to_vec())?;
            object.set("bodyBytes", bytes.arraybuffer()?)?;
            object.set("body", bytes)?;
        } else {
            object.set("body", String::from_utf8_lossy(body).as_ref())?;
        }
        Ok(())
    }

    fn headers_object<'js>(ctx: &Ctx<'js>, headers: &[(String, String)]) -> Result<Object<'js>> {
        let object = Object::new(ctx.clone())?;
        for (name, value) in headers {
            // Repeated headers (Set-Cookie) are joined, as Surge does.
            let joined = match object.get::<_, Option<String>>(name.as_str())? {
                Some(existing) => format!("{existing}, {value}"),
                None => value.clone(),
            };
            object.set(name.as_str(), joined)?;
        }
        Ok(object)
    }

    fn header_list(value: &Value<'_>) -> Vec<(String, String)> {
        let Some(object) = value.as_object() else {
            return vec![];
        };
        object
            .props::<String, Value>()
            .filter_map(|prop| prop.ok())
            .filter_map(|(name, value)| {
                let text = if let Some(s) = value.as_string() {
                    s.to_string().ok()?
                } else if let Some(n) = value.as_number() {
                    if n.fract() == 0.0 {
                        format!("{}", n as i64)
                    } else {
                        n.to_string()
                    }
                } else if let Some(b) = value.as_bool() {
                    b.to_string()
                } else {
                    return None;
                };
                Some((name, text))
            })
            .collect()
    }

    /// A string as UTF-8, or the bytes of a `Uint8Array` or `ArrayBuffer`.
    fn bytes_of(value: &Value<'_>) -> Option<Vec<u8>> {
        if let Some(text) = value.as_string() {
            return text.to_string().ok().map(String::into_bytes);
        }
        if let Ok(array) = TypedArray::<u8>::from_value(value.clone()) {
            // SAFETY: the view is alive and not resized while copied.
            return array.as_raw().map(|raw| unsafe { raw.as_ref() }.to_vec());
        }
        if let Some(buffer) = ArrayBuffer::from_value(value.clone()) {
            // SAFETY: as above.
            return buffer.as_raw().map(|raw| unsafe { raw.as_ref() }.to_vec());
        }
        None
    }

    fn status_of(value: &Value<'_>) -> Option<u16> {
        if let Some(n) = value.as_number() {
            return Some(n as u16).filter(|s| (100..=599).contains(s));
        }
        // Quantumult X: "HTTP/1.1 200 OK".
        let text = value.as_string()?.to_string().ok()?;
        let code = text
            .split_whitespace()
            .find(|part| part.len() == 3 && part.bytes().all(|b| b.is_ascii_digit()))?;
        code.parse().ok().filter(|s| (100..=599).contains(s))
    }

    fn body_field(object: &Object<'_>) -> Option<Vec<u8>> {
        let bytes: Value = object.get("bodyBytes").ok()?;
        bytes_of(&bytes).or_else(|| bytes_of(&object.get::<_, Value>("body").ok()?))
    }

    fn outcome(value: &Value<'_>) -> Outcome {
        let Some(object) = value.as_object() else {
            return Outcome::default();
        };
        let get = |key: &str| {
            object
                .get::<_, Value>(key)
                .ok()
                .filter(|v| !v.is_undefined() && !v.is_null())
        };
        let mut outcome = Outcome {
            url: get("url").and_then(|v| v.as_string()?.to_string().ok()),
            status: get("status").and_then(|v| status_of(&v)),
            headers: get("headers").map(|v| header_list(&v)),
            body: body_field(object),
            abort: get("abort").and_then(|v| v.as_bool()).unwrap_or(false),
            response: None,
        };
        if let Some(response) = get("response").and_then(|v| v.as_object().cloned()) {
            let status = response
                .get::<_, Value>("status")
                .ok()
                .and_then(|v| status_of(&v))
                .unwrap_or(200);
            outcome.response = Some(Answer {
                status,
                headers: response
                    .get::<_, Value>("headers")
                    .map(|v| header_list(&v))
                    .unwrap_or_default(),
                body: body_field(&response).unwrap_or_default(),
            });
        }
        outcome
    }

    /// `$httpClient`: a request routed by the rules like any other.
    async fn fetch(
        core: &Arc<crate::Core>,
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
        use http_body_util::{BodyExt, Full};
        let uri: http::Uri = url.parse().context("invalid URL")?;
        let scheme = uri.scheme_str().unwrap_or("");
        anyhow::ensure!(
            scheme == "https" || scheme == "http",
            "URL must use HTTP(S)"
        );
        let target =
            clyntis_protocol::Target::from_uri(&uri, if scheme == "https" { 443 } else { 80 })?;
        let (tunnel, _) = core.dial(&target, None).await?;
        let stream: clyntis_protocol::BoxStream = if scheme == "https" {
            clyntis_protocol::tls::SecureConnector::new(core.clock.clone())
                .connect(
                    tunnel,
                    &clyntis_protocol::tls::TlsConnectConfig {
                        server_name: target.host.clone(),
                        alpn: vec!["http/1.1".into()],
                        verify_cert: true,
                        fingerprint: clyntis_protocol::tls::TlsFingerprint::Native,
                        reality: None,
                    },
                )
                .await?
        } else {
            tunnel
        };
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
        let _driver = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(connection));
        let mut request = http::Request::builder()
            .method(method)
            .uri(uri.path_and_query().map_or("/", |v| v.as_str()));
        let mut has_host = false;
        for (name, value) in &headers {
            if name.eq_ignore_ascii_case("host") {
                has_host = true;
            }
            if name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("transfer-encoding")
            {
                continue;
            }
            request = request.header(name.as_str(), value.as_str());
        }
        if !has_host {
            request = request.header(
                http::header::HOST,
                uri.authority().context("missing authority")?.as_str(),
            );
        }
        let request = request.body(Full::new(bytes::Bytes::from(body.unwrap_or_default())))?;
        let response = sender.send_request(request).await?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_owned(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect::<Vec<_>>();
        let encoding = crate::rewrite::find(&headers, "content-encoding").map(str::to_owned);
        let mut body = Vec::new();
        let mut incoming = response.into_body();
        while let Some(frame) = incoming.frame().await {
            if let Ok(data) = frame?.into_data() {
                anyhow::ensure!(
                    body.len() + data.len() <= HTTP_BODY_LIMIT,
                    "response too large"
                );
                body.extend_from_slice(&data);
            }
        }
        let (headers, body) = match encoding
            .and_then(|e| crate::requests::decode_limited(&e, &body, HTTP_BODY_LIMIT))
        {
            Some(plain) => (
                headers
                    .into_iter()
                    .filter(|(k, _)| !k.eq_ignore_ascii_case("content-encoding"))
                    .collect(),
                plain,
            ),
            None => (headers, body),
        };
        Ok((status, headers, body))
    }
}

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use super::*;

    fn job(path: PathBuf, timeout: Duration, binary: bool) -> Job {
        Job {
            name: "test".into(),
            path,
            argument: "arg".into(),
            timeout,
            binary,
            phase: Phase::Response,
            url: "https://a.test/x".into(),
            method: "GET".into(),
            request_headers: vec![("Host".into(), "a.test".into())],
            request_body: None,
            response: Some(ResponseInput {
                status: 200,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: Some(b"\x01\x02\x03".to_vec()),
            }),
        }
    }

    #[tokio::test]
    async fn runs_scripts_within_limits() {
        let directory =
            std::env::temp_dir().join(format!("clyntis-script-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let config = clyntis_config::Config {
            directory: directory.clone(),
            ..Default::default()
        };
        let core = crate::Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        let script = |name: &str, source: &str| {
            let path = directory.join(name);
            std::fs::write(&path, source).unwrap();
            path
        };

        // Binary bodies, status, and the first `$done` wins.
        let path = script(
            "binary.js",
            r#"const b = $response.body;
const out = new Uint8Array(b.length + 1);
out.set(b); out[b.length] = 4;
$done({bodyBytes: out.buffer, status: "HTTP/1.1 201 Created", headers: {"X-Len": b.length}});
$done({body: "ignored"});"#,
        );
        let outcome = run(&core, job(path, DEFAULT_TIMEOUT, true)).await.unwrap();
        assert_eq!(outcome.body.as_deref(), Some(&[1u8, 2, 3, 4][..]));
        assert_eq!(outcome.status, Some(201));
        assert_eq!(
            outcome.headers.unwrap(),
            [("X-Len".to_owned(), "3".to_owned())]
        );

        // Scripts run in sloppy mode: undeclared assignments make globals.
        let path = script(
            "sloppy.js",
            "body = 'x'; $done({body: body + globalThis.body});",
        );
        let outcome = run(&core, job(path, DEFAULT_TIMEOUT, false)).await.unwrap();
        assert_eq!(outcome.body.as_deref(), Some(&b"xx"[..]));

        // Ending without `$done` changes nothing; a request script may answer.
        let path = script("none.js", "console.log('hi', {a: 1});");
        let outcome = run(&core, job(path, DEFAULT_TIMEOUT, false)).await.unwrap();
        assert!(outcome.body.is_none() && outcome.response.is_none());
        let path = script(
            "answer.js",
            r#"$done({response: {status: 403, body: "no"}});"#,
        );
        let outcome = run(&core, job(path, DEFAULT_TIMEOUT, false)).await.unwrap();
        let answer = outcome.response.unwrap();
        assert_eq!((answer.status, answer.body.as_slice()), (403, &b"no"[..]));

        // Errors, endless loops and runaway memory fail the run, not the core.
        let path = script("throw.js", "throw new Error('boom')");
        let error = run(&core, job(path, DEFAULT_TIMEOUT, false))
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("boom"), "{error:#}");
        let path = script("loop.js", "while (true) {}");
        let started = std::time::Instant::now();
        assert!(
            run(&core, job(path, Duration::from_millis(300), false))
                .await
                .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        let path = script(
            "memory.js",
            "const a = []; while (true) a.push('x'.repeat(1 << 20));",
        );
        assert!(run(&core, job(path, DEFAULT_TIMEOUT, false)).await.is_err());
        let _ = std::fs::remove_dir_all(&directory);
    }
}
