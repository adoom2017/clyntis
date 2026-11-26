//! The request log: recent connections (refused ones too) and the HTTP
//! requests read from decrypted or plain HTTP connections, for finding what
//! an app loads, ads among it. Memory only, bounded by entries and by body
//! bytes; the apps poll it with the last id they have.
use crate::{RouteDecision, traffic};
use base64::{Engine, engine::general_purpose::STANDARD};
use clyntis_protocol::Target;
use serde::{
    Serialize,
    ser::{SerializeSeq, Serializer},
};
use serde_json::{Value, json};
use std::{
    borrow::Cow,
    collections::VecDeque,
    io::{Read, Write},
    sync::{Arc, Mutex, atomic::Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Limits on what the log keeps.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub(crate) entries: usize,
    /// All kept bodies together.
    pub(crate) body_bytes: usize,
    /// One body; the rest of a longer body is counted but not kept.
    pub(crate) body_cap: usize,
    /// All kept headers and URLs together (0 disables).
    pub(crate) header_bytes: usize,
    /// Decoded body cap for the detail view.
    pub(crate) decoded_cap: u64,
}
const DESKTOP: Limits = Limits {
    entries: 5000,
    body_bytes: 64 << 20,
    body_cap: 2 << 20,
    header_bytes: 0,
    decoded_cap: DECODED_CAP,
};
/// The iOS tunnel lives within about 50 MiB.
const HOSTED: Limits = Limits {
    entries: 500,
    body_bytes: 1 << 20,
    body_cap: 128 << 10,
    header_bytes: 2 << 20,
    decoded_cap: HOSTED_DECODED_CAP,
};
// Leave space for in-flight exchanges even when the log fills its share.
pub(crate) const HOSTED_CAPTURE_BYTES: usize = 2 << 20;
/// Whole-export byte limit for hosted/iOS HAR and CSV exports.
pub(crate) const HOSTED_HAR_BYTES: usize = 2 << 20;
/// A decoded body shown to the apps stops here.
const DECODED_CAP: u64 = 4 << 20;
pub(crate) const HOSTED_DECODED_CAP: u64 = 512 << 10;
const TRUNCATED_BODY_COMMENT: &str = "truncated: only the beginning was kept";
const OMITTED_BODY_COMMENT: &str = "omitted: export size limit reached";
const HAR_LOG_PREFIX_START: &str =
    r#"{"log":{"version":"1.2","creator":{"name":"Clyntis","version":"#;
const HAR_LOG_PREFIX_END: &str = r#"},"pages":[],"entries":["#;
const HAR_LOG_SUFFIX: &str = "]}}";
const HAR_TRUNCATED_SUFFIX: &str =
    r#"],"comment":"Some entries were omitted to fit the export size limit."}}"#;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    pub id: u64,
    /// When the connection or request started, Unix milliseconds.
    pub time: u64,
    pub network: String,
    pub source: String,
    pub host: String,
    pub port: u16,
    pub rule: String,
    pub chain: String,
    /// `rejected`, `closed` (a connection) or `http` (one request on one).
    pub status: String,
    /// Milliseconds.
    pub duration: u64,
    pub upload: u64,
    pub download: u64,
    /// The connection id, shared by the requests made on it.
    pub connection: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// HTTP requests recorded on a closed connection.
    pub requests: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpSummary>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpSummary {
    pub method: String,
    pub url: String,
    /// Whether it was decrypted (HTTPS) rather than plain HTTP.
    pub decrypted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub request_size: u64,
    pub response_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The rewrite rules that acted on it: `action (module)`, comma-separated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rewrite: Option<String>,
    /// Structured action kinds of the rewrite rules that acted on it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rewrite_actions: Vec<String>,
    /// Whether a rewrite rule answered locally without reaching the server.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub answered: bool,
}

/// Headers and the kept part of the bodies, as sent (still compressed).
#[derive(Debug, Default)]
pub(crate) struct HttpDetail {
    pub(crate) request_headers: Vec<(String, String)>,
    pub(crate) response_headers: Vec<(String, String)>,
    pub(crate) request_body: Body,
    pub(crate) response_body: Body,
}

#[derive(Debug, Default)]
pub(crate) struct Body {
    pub(crate) bytes: Vec<u8>,
    /// Bytes seen, kept or not.
    pub(crate) size: u64,
    reservation: Option<OwnedSemaphorePermit>,
}
impl Body {
    #[cfg(test)]
    pub(crate) fn push(&mut self, bytes: &[u8], cap: usize) {
        self.capture(bytes, cap, None);
    }
    fn capture(&mut self, bytes: &[u8], cap: usize, budget: Option<&Arc<Semaphore>>) {
        let seen = self.size;
        self.size += bytes.len() as u64;
        // Once bytes were omitted, keep only the contiguous prefix.
        if seen != self.bytes.len() as u64 {
            return;
        }
        let end = self.bytes.len() + bytes.len().min(cap.saturating_sub(self.bytes.len()));
        if let Some(budget) = budget {
            let capacity = self.bytes.capacity();
            if end > capacity {
                let growth = end
                    .max(capacity.saturating_mul(2))
                    .min(cap)
                    .saturating_sub(capacity)
                    .min(budget.available_permits());
                if growth != 0
                    && let Ok(permit) = budget.clone().try_acquire_many_owned(growth as u32)
                {
                    self.bytes
                        .reserve_exact(capacity + growth - self.bytes.len());
                    match &mut self.reservation {
                        Some(held) => held.merge(permit),
                        None => self.reservation = Some(permit),
                    }
                }
            }
            let end = end.min(self.bytes.capacity());
            self.bytes
                .extend_from_slice(&bytes[..end - self.bytes.len()]);
        } else {
            self.bytes
                .extend_from_slice(&bytes[..end - self.bytes.len()]);
        }
    }
    fn without_bytes(&self) -> Self {
        Self {
            size: self.size,
            ..Self::default()
        }
    }
    fn truncated(&self) -> bool {
        (self.bytes.len() as u64) < self.size
    }
}

struct Entry {
    summary: Request,
    detail: Option<HttpDetail>,
}
impl Entry {
    fn body_bytes(&self) -> usize {
        self.detail.as_ref().map_or(0, |d| {
            d.request_body.bytes.capacity() + d.response_body.bytes.capacity()
        })
    }
    fn header_bytes(&self) -> usize {
        let url_bytes = self.summary.http.as_ref().map_or(0, |h| h.url.capacity());
        let headers = self.detail.as_ref().map_or(0, |d| {
            d.request_headers
                .iter()
                .chain(&d.response_headers)
                .map(|(k, v)| k.capacity() + v.capacity())
                .sum::<usize>()
        });
        url_bytes + headers
    }
}

#[derive(Default)]
struct Log {
    entries: VecDeque<Arc<Entry>>,
    next: u64,
    body_bytes: usize,
    header_bytes: usize,
}

pub struct Requests {
    log: Mutex<Log>,
    limits: Limits,
    capture_budget: Option<Arc<Semaphore>>,
    rewrite_budget: Option<Arc<Semaphore>>,
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

impl Requests {
    pub(crate) fn new(hosted: bool) -> Self {
        Self {
            log: Mutex::default(),
            limits: if hosted { HOSTED } else { DESKTOP },
            capture_budget: hosted.then(|| Arc::new(Semaphore::new(HOSTED_CAPTURE_BYTES))),
            rewrite_budget: hosted.then(|| Arc::new(Semaphore::new(HOSTED_CAPTURE_BYTES))),
        }
    }
    pub(crate) fn body_cap(&self, content_type: Option<&str>) -> usize {
        if self.capture_budget.is_some()
            && let Some(mime) = content_type
            && let Some((kind, _)) = mime.split_once('/')
            && ["image", "video", "audio"]
                .iter()
                .any(|k| kind.eq_ignore_ascii_case(k))
        {
            return 0;
        }
        self.limits.body_cap
    }
    pub(crate) fn capture(&self, body: &mut Body, bytes: &[u8], cap: usize) {
        body.capture(bytes, cap, self.capture_budget.as_ref());
    }
    pub(crate) fn captured_bytes(&self) -> usize {
        self.capture_budget.as_ref().map_or(0, |budget| {
            HOSTED_CAPTURE_BYTES.saturating_sub(budget.available_permits())
        })
    }
    /// Reserves `bytes` from the hosted rewrite body-memory budget, independent
    /// of captured request/response log bodies. Returns `Ok(None)` when
    /// unbudgeted (desktop) or `bytes == 0`, `Ok(Some(permit))` on success,
    /// or `Err(())` when the hosted rewrite budget cannot cover `bytes`.
    pub(crate) fn reserve_body_budget(
        &self,
        bytes: usize,
    ) -> Result<Option<OwnedSemaphorePermit>, ()> {
        let Some(budget) = &self.rewrite_budget else {
            return Ok(None);
        };
        if bytes == 0 {
            return Ok(None);
        }
        let permits = u32::try_from(bytes).map_err(|_| ())?;
        budget
            .clone()
            .try_acquire_many_owned(permits)
            .map(Some)
            .map_err(|_| ())
    }
    /// Drops stored HTTP body payloads under memory pressure while retaining
    /// summaries and headers.
    pub(crate) fn relieve_memory(&self) {
        let mut log = self.log.lock().unwrap();
        for slot in &mut log.entries {
            let has_bodies = slot.detail.as_ref().is_some_and(|d| {
                d.request_body.bytes.capacity() > 0 || d.response_body.bytes.capacity() > 0
            });
            if has_bodies {
                if let Some(entry) = Arc::get_mut(slot) {
                    let detail = entry.detail.as_mut().unwrap();
                    detail.request_body = detail.request_body.without_bytes();
                    detail.response_body = detail.response_body.without_bytes();
                } else {
                    let detail = slot.detail.as_ref().unwrap();
                    *slot = Arc::new(Entry {
                        summary: slot.summary.clone(),
                        detail: Some(HttpDetail {
                            request_headers: detail.request_headers.clone(),
                            response_headers: detail.response_headers.clone(),
                            request_body: detail.request_body.without_bytes(),
                            response_body: detail.response_body.without_bytes(),
                        }),
                    });
                }
            }
        }
        log.body_bytes = 0;
    }
    fn push(&self, mut summary: Request, mut detail: Option<HttpDetail>) {
        if let Some(detail) = &mut detail {
            detail.request_headers.shrink_to_fit();
            detail.response_headers.shrink_to_fit();
            if self.capture_budget.is_none() {
                detail.request_body.bytes.shrink_to_fit();
                detail.response_body.bytes.shrink_to_fit();
            }
        }
        let mut log = self.log.lock().unwrap();
        log.next += 1;
        summary.id = log.next;
        let entry = Arc::new(Entry { summary, detail });
        log.body_bytes += entry.body_bytes();
        log.header_bytes += entry.header_bytes();
        log.entries.push_back(entry);
        while log.entries.len() > self.limits.entries
            || ((log.body_bytes > self.limits.body_bytes
                || (self.limits.header_bytes > 0 && log.header_bytes > self.limits.header_bytes))
                && log.entries.len() > 1)
        {
            if let Some(old) = log.entries.pop_front() {
                log.body_bytes -= old.body_bytes();
                log.header_bytes -= old.header_bytes();
            }
        }
    }
    /// A connection refused by its route.
    pub(crate) fn rejected(
        &self,
        network: &str,
        source: &str,
        target: &Target,
        decision: &RouteDecision,
    ) {
        self.push(
            Request {
                id: 0,
                time: now_ms(),
                network: network.into(),
                source: source.into(),
                host: target.host.clone(),
                port: target.port,
                rule: decision.rule.clone(),
                chain: decision.node.clone(),
                status: "rejected".into(),
                duration: 0,
                upload: 0,
                download: 0,
                connection: String::new(),
                reason: None,
                requests: 0,
                http: None,
            },
            None,
        );
    }
    /// A relayed connection that ended.
    pub(crate) fn finished(&self, state: &traffic::State) {
        let info = state.snapshot();
        let duration = state.lifetime().as_millis() as u64;
        self.push(
            Request {
                id: 0,
                time: now_ms().saturating_sub(duration),
                network: info.network,
                source: info.source,
                host: info.metadata.host,
                port: info.metadata.port,
                rule: info.rule,
                chain: info.chains.join(" / "),
                status: "closed".into(),
                duration,
                upload: info.upload,
                download: info.download,
                connection: info.id,
                reason: state.reason(),
                requests: state.exchanges.load(Ordering::Relaxed),
                http: None,
            },
            None,
        );
    }
    /// One HTTP request and its response (or how it failed).
    pub(crate) fn exchange(
        &self,
        state: &traffic::State,
        started: u64,
        summary: HttpSummary,
        detail: HttpDetail,
    ) {
        state.exchanges.fetch_add(1, Ordering::Relaxed);
        let info = state.snapshot();
        let (upload, download) = (summary.request_size, summary.response_size);
        self.push(
            Request {
                id: 0,
                time: started,
                network: info.network,
                source: info.source,
                host: info.metadata.host,
                port: info.metadata.port,
                rule: info.rule,
                chain: info.chains.join(" / "),
                status: "http".into(),
                duration: now_ms().saturating_sub(started),
                upload,
                download,
                connection: info.id,
                reason: None,
                requests: 0,
                http: Some(summary),
            },
            Some(detail),
        );
    }
    /// Entries newer than `after`, oldest first, at most `limit`; and the
    /// newest id, which the next call passes as `after`.
    pub fn list(&self, after: u64, limit: usize) -> (Vec<Request>, u64) {
        let log = self.log.lock().unwrap();
        let start = log.entries.partition_point(|e| e.summary.id <= after);
        let entries: Vec<_> = log
            .entries
            .iter()
            .skip(start)
            .take(limit)
            .map(|e| e.summary.clone())
            .collect();
        let next = entries.last().map_or(log.next.max(after), |e| e.id);
        (entries, next)
    }
    /// One entry with its headers and bodies (decompressed when possible).
    pub fn detail(&self, id: u64) -> Option<Value> {
        let bytes = self.detail_json(id)?;
        serde_json::from_slice(&bytes).ok()
    }
    /// Serialized JSON for one entry with its headers and bodies, avoiding an
    /// intermediate `serde_json::Value` tree.
    pub fn detail_json(&self, id: u64) -> Option<Vec<u8>> {
        let entry = {
            let log = self.log.lock().unwrap();
            let index = log
                .entries
                .binary_search_by_key(&id, |e| e.summary.id)
                .ok()?;
            log.entries[index].clone()
        };
        let cap = self.limits.decoded_cap;
        let view = match &entry.detail {
            Some(detail) => DetailView {
                summary: &entry.summary,
                request_headers: Some(HeaderTuples(&detail.request_headers)),
                response_headers: Some(HeaderTuples(&detail.response_headers)),
                request_body: Some(render_body_with_cap(
                    &detail.request_body,
                    &detail.request_headers,
                    cap,
                )),
                response_body: Some(render_body_with_cap(
                    &detail.response_body,
                    &detail.response_headers,
                    cap,
                )),
            },
            None => DetailView {
                summary: &entry.summary,
                request_headers: None,
                response_headers: None,
                request_body: None,
                response_body: None,
            },
        };
        serde_json::to_vec(&view).ok()
    }
    fn snapshot(&self) -> Vec<Arc<Entry>> {
        self.log.lock().unwrap().entries.iter().cloned().collect()
    }
    /// The HTTP requests as an HTTP Archive (HAR 1.2), which Charles,
    /// Proxyman and browser developer tools open. Bodies are the kept part,
    /// decompressed; connections without HTTP are left out (see
    /// [`Requests::export_csv`]).
    pub fn export_har(&self) -> Value {
        if self.capture_budget.is_some() {
            return self
                .export_har_with_limit(Some(HOSTED_HAR_BYTES))
                .and_then(|bytes| serde_json::from_slice(&bytes))
                .expect("serialized HAR must be valid JSON");
        }
        let entries: Vec<Value> = self
            .snapshot()
            .iter()
            .filter_map(|entry| {
                let http = entry.summary.http.as_ref()?;
                let detail = entry.detail.as_ref()?;
                Some(har_entry(&entry.summary, http, detail))
            })
            .collect();
        json!({"log": {
            "version": "1.2",
            "creator": {"name": "Clyntis", "version": env!("CARGO_PKG_VERSION")},
            "pages": [],
            "entries": entries,
        }})
    }
    /// Serialized HAR 1.2 JSON bytes. Hosted logs stream compact JSON capped at
    /// [`HOSTED_HAR_BYTES`]; desktop logs keep pretty-printed unbounded JSON.
    pub fn export_har_json(&self) -> serde_json::Result<Vec<u8>> {
        if self.capture_budget.is_some() {
            self.export_har_with_limit(Some(HOSTED_HAR_BYTES))
        } else {
            serde_json::to_vec_pretty(&self.export_har())
        }
    }
    /// Streams compact HAR 1.2 JSON directly into a single buffer, optionally
    /// enforcing a whole-export byte limit. Keep complete entries, newest first
    /// when choosing which fit, and use the remaining space for bodies.
    pub(crate) fn export_har_with_limit(
        &self,
        limit: Option<usize>,
    ) -> serde_json::Result<Vec<u8>> {
        let snapshot = self.snapshot();
        let mut entries: Vec<_> = snapshot
            .iter()
            .filter_map(|entry| {
                let http = entry.summary.http.as_ref()?;
                let detail = entry.detail.as_ref()?;
                Some((&entry.summary, http, detail))
            })
            .collect();

        let mut suffix = HAR_LOG_SUFFIX;
        let (base_bytes, mut remaining_body_bytes) = if let Some(max) = limit {
            let mut counter = ByteCounter(0);
            write_har_prefix(&mut counter)?;
            let prefix_bytes = counter.0;
            let mut sizes = Vec::with_capacity(entries.len());
            for (summary, http, detail) in &entries {
                let entry = HarEntry::without_bodies(summary, http, detail);
                sizes.push(json_byte_len(&entry)?);
            }
            let mut base = prefix_bytes
                + HAR_LOG_SUFFIX.len()
                + sizes.iter().sum::<usize>()
                + entries.len().saturating_sub(1);
            if base > max {
                suffix = HAR_TRUNCATED_SUFFIX;
                base = prefix_bytes + suffix.len();
                if base > max {
                    return Err(serde_json::Error::io(har_size_error()));
                }
                entries.reverse();
                let mut retained_any = false;
                let mut sizes = sizes.into_iter().rev();
                entries.retain(|_| {
                    let size = sizes.next().unwrap() + usize::from(retained_any);
                    if size > max - base {
                        return false;
                    }
                    base += size;
                    retained_any = true;
                    true
                });
                entries.reverse();
            }
            (base, Some(max - base))
        } else {
            (0, None)
        };

        let mut out = HarBuffer {
            bytes: Vec::with_capacity(base_bytes),
            limit,
        };
        write_har_prefix(&mut out)?;
        for (index, (summary, http, detail)) in entries.iter().enumerate() {
            if index > 0 {
                out.write_all(b",").map_err(serde_json::Error::io)?;
            }
            let post_data = har_post_data_for_export(detail, &mut remaining_body_bytes)?;
            let content = har_content_for_export(detail, &mut remaining_body_bytes)?;
            let entry = HarEntry::new(summary, http, detail, post_data, content);
            serde_json::to_writer(&mut out, &entry)?;
        }
        out.write_all(suffix.as_bytes())
            .map_err(serde_json::Error::io)?;
        Ok(out.bytes)
    }
    /// Every entry, one line each, as CSV with a header line. Hosted logs cap
    /// the whole export at [`HOSTED_HAR_BYTES`], keeping the newest entries.
    pub fn export_csv(&self) -> String {
        self.export_csv_with_limit(self.capture_budget.is_some().then_some(HOSTED_HAR_BYTES))
    }
    pub(crate) fn export_csv_with_limit(&self, limit: Option<usize>) -> String {
        const HEADER: &str = "id,time,kind,network,source,host,port,method,url,status,content_type,rule,chain,upload,download,duration_ms,reason\n";
        let snapshot = self.snapshot();
        let Some(max) = limit else {
            let mut out = String::from(HEADER);
            for entry in &snapshot {
                write_csv_row(&entry.summary, &mut out);
            }
            return out;
        };
        if max < HEADER.len() {
            return String::new();
        }
        let mut rows: Vec<String> = Vec::with_capacity(snapshot.len());
        let mut total = HEADER.len();
        for entry in snapshot.iter().rev() {
            let mut row = String::new();
            write_csv_row(&entry.summary, &mut row);
            if total + row.len() > max {
                break;
            }
            total += row.len();
            rows.push(row);
        }
        let mut out = String::with_capacity(total);
        out.push_str(HEADER);
        for row in rows.iter().rev() {
            out.push_str(row);
        }
        out
    }
    pub fn clear(&self) {
        let mut log = self.log.lock().unwrap();
        log.entries.clear();
        log.entries.shrink_to_fit();
        log.body_bytes = 0;
        log.header_bytes = 0;
    }
}

fn write_csv_row(r: &Request, out: &mut String) {
    use std::fmt::Write;
    let http = r.http.as_ref();
    let _ = write!(out, "{},{},", r.id, iso_time(r.time));
    push_csv_field(out, &r.status);
    out.push(',');
    push_csv_field(out, &r.network);
    out.push(',');
    push_csv_field(out, &r.source);
    out.push(',');
    push_csv_field(out, &r.host);
    let _ = write!(out, ",{},", r.port);
    push_csv_field(out, http.map_or("", |h| h.method.as_str()));
    out.push(',');
    push_csv_field(out, http.map_or("", |h| h.url.as_str()));
    out.push(',');
    if let Some(status) = http.and_then(|h| h.status) {
        let _ = write!(out, "{status}");
    }
    out.push(',');
    push_csv_field(
        out,
        http.and_then(|h| h.content_type.as_deref()).unwrap_or(""),
    );
    out.push(',');
    push_csv_field(out, &r.rule);
    out.push(',');
    push_csv_field(out, &r.chain);
    let _ = write!(out, ",{},{},{},", r.upload, r.download, r.duration);
    let reason = http
        .and_then(|h| h.error.as_deref())
        .or(r.reason.as_deref())
        .unwrap_or("");
    push_csv_field(out, reason);
    out.push('\n');
}

fn push_csv_field(out: &mut String, value: &str) {
    // A leading =, +, - or @ would run as a formula in a spreadsheet.
    let prefix_quote = value.starts_with(['=', '+', '-', '@']);
    let needs_quotes = value.contains([',', '"', '\n', '\r']);
    if needs_quotes {
        out.push('"');
        if prefix_quote {
            out.push('\'');
        }
        for ch in value.chars() {
            if ch == '"' {
                out.push_str("\"\"");
            } else {
                out.push(ch);
            }
        }
        out.push('"');
    } else {
        if prefix_quote {
            out.push('\'');
        }
        out.push_str(value);
    }
}

/// Unix milliseconds as RFC 3339 UTC.
fn iso_time(ms: u64) -> String {
    let (secs, millis) = ((ms / 1000) as i64, ms % 1000);
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

struct ByteCounter(usize);

fn har_size_error() -> std::io::Error {
    std::io::Error::other("HAR exceeds export size limit")
}

struct HarBuffer {
    bytes: Vec<u8>,
    limit: Option<usize>,
}

impl Write for HarBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(limit) = self.limit {
            if buf.len() > limit - self.bytes.len() {
                return Err(har_size_error());
            }
            let end = self.bytes.len() + buf.len();
            if end > self.bytes.capacity() {
                let capacity = end.max(self.bytes.capacity().saturating_mul(2)).min(limit);
                self.bytes.reserve_exact(capacity - self.bytes.len());
            }
        }
        self.bytes.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn json_byte_len<T: Serialize>(value: &T) -> serde_json::Result<usize> {
    let mut counter = ByteCounter(0);
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.0)
}

fn write_har_prefix(mut w: impl Write) -> serde_json::Result<()> {
    w.write_all(HAR_LOG_PREFIX_START.as_bytes())
        .map_err(serde_json::Error::io)?;
    serde_json::to_writer(&mut w, env!("CARGO_PKG_VERSION"))?;
    w.write_all(HAR_LOG_PREFIX_END.as_bytes())
        .map_err(serde_json::Error::io)?;
    Ok(())
}

#[derive(Serialize)]
struct HarPair<'a> {
    name: &'a str,
    value: &'a str,
}

struct HarHeaders<'a>(&'a [(String, String)]);

impl Serialize for HarHeaders<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for (name, value) in self.0 {
            seq.serialize_element(&HarPair { name, value })?;
        }
        seq.end()
    }
}

struct HarQueryString<'a>(&'a str);

impl Serialize for HarQueryString<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        if let Some((_, query)) = self.0.split_once('?') {
            for pair in query.split('&').filter(|pair| !pair.is_empty()) {
                let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                seq.serialize_element(&HarPair { name, value })?;
            }
        }
        seq.end()
    }
}

struct HarRuleComment<'a>(&'a str, &'a str);

impl Serialize for HarRuleComment<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{} -> {}", self.0, self.1))
    }
}

#[derive(Serialize)]
struct HarEmpty {}

#[derive(Serialize)]
struct HarTimings {
    send: u64,
    wait: u64,
    receive: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HarPostData<'a> {
    mime_type: &'a str,
    text: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HarContent<'a> {
    size: u64,
    mime_type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encoding: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HarRequest<'a> {
    method: &'a str,
    url: &'a str,
    http_version: &'static str,
    cookies: [(); 0],
    headers: HarHeaders<'a>,
    query_string: HarQueryString<'a>,
    headers_size: i32,
    body_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    post_data: Option<HarPostData<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HarResponse<'a> {
    status: u16,
    status_text: &'a str,
    http_version: &'static str,
    cookies: [(); 0],
    headers: HarHeaders<'a>,
    content: HarContent<'a>,
    #[serde(rename = "redirectURL")]
    redirect_url: &'static str,
    headers_size: i32,
    body_size: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HarEntry<'a> {
    started_date_time: String,
    time: u64,
    request: HarRequest<'a>,
    response: HarResponse<'a>,
    cache: HarEmpty,
    timings: HarTimings,
    connection: &'a str,
    comment: HarRuleComment<'a>,
}

impl<'a> HarEntry<'a> {
    fn without_bodies(r: &'a Request, http: &'a HttpSummary, detail: &'a HttpDetail) -> Self {
        Self::new(
            r,
            http,
            detail,
            har_post_data_placeholder(detail),
            har_content_placeholder(detail),
        )
    }

    fn new(
        r: &'a Request,
        http: &'a HttpSummary,
        detail: &'a HttpDetail,
        post_data: Option<HarPostData<'a>>,
        content: HarContent<'a>,
    ) -> Self {
        Self {
            started_date_time: iso_time(r.time),
            time: r.duration,
            request: HarRequest {
                method: &http.method,
                url: &http.url,
                http_version: "HTTP/1.1",
                cookies: [],
                headers: HarHeaders(&detail.request_headers),
                query_string: HarQueryString(&http.url),
                headers_size: -1,
                body_size: http.request_size,
                post_data,
            },
            response: HarResponse {
                status: http.status.unwrap_or(0),
                status_text: http.error.as_deref().unwrap_or(""),
                http_version: "HTTP/1.1",
                cookies: [],
                headers: HarHeaders(&detail.response_headers),
                content,
                redirect_url: "",
                headers_size: -1,
                body_size: http.response_size,
            },
            cache: HarEmpty {},
            timings: HarTimings {
                send: 0,
                wait: r.duration,
                receive: 0,
            },
            connection: &r.connection,
            comment: HarRuleComment(&r.rule, &r.chain),
        }
    }
}

fn har_post_data_placeholder(detail: &HttpDetail) -> Option<HarPostData<'_>> {
    if detail.request_body.size == 0 {
        return None;
    }
    let mime_type = header(&detail.request_headers, "content-type").unwrap_or_default();
    let comment = (!detail.request_body.bytes.is_empty()).then_some(OMITTED_BODY_COMMENT);
    Some(HarPostData {
        mime_type,
        text: Cow::Borrowed(""),
        comment,
    })
}

fn har_content_placeholder(detail: &HttpDetail) -> HarContent<'_> {
    let body = &detail.response_body;
    let mime_type = header(&detail.response_headers, "content-type").unwrap_or_default();
    if body.bytes.is_empty() {
        HarContent {
            size: body.size,
            mime_type,
            text: Some(Cow::Borrowed("")),
            encoding: None,
            comment: body.truncated().then_some(TRUNCATED_BODY_COMMENT),
        }
    } else {
        HarContent {
            size: body.size,
            mime_type,
            text: None,
            encoding: None,
            comment: Some(OMITTED_BODY_COMMENT),
        }
    }
}

fn fit_body_for_har<'a, T: Serialize>(
    body: &'a Body,
    headers: &'a [(String, String)],
    remaining_body_bytes: &mut Option<usize>,
    placeholder: T,
    build_candidate: impl FnOnce(RenderedText<'a>) -> T,
) -> serde_json::Result<T> {
    if *remaining_body_bytes == Some(0) {
        return Ok(placeholder);
    }
    let rem_opt = *remaining_body_bytes;
    let (decoded, _) = decode_body(body, headers, rem_opt);
    let DecodedBody::Bytes(bytes) = decoded else {
        return Ok(placeholder);
    };
    // Serialized text/base64 is always >= raw byte length, and the omitted
    // comment placeholder only saves <= 47 bytes, so larger bodies cannot fit.
    if let Some(rem) = rem_opt
        && bytes.len() > rem.saturating_add(64)
    {
        return Ok(placeholder);
    }
    let candidate = build_candidate(render_bytes(bytes, headers));
    if let Some(rem) = remaining_body_bytes.as_mut() {
        let extra = json_byte_len(&candidate)?.saturating_sub(json_byte_len(&placeholder)?);
        if extra > *rem {
            return Ok(placeholder);
        }
        *rem -= extra;
    }
    Ok(candidate)
}

fn har_post_data_for_export<'a>(
    detail: &'a HttpDetail,
    remaining_body_bytes: &mut Option<usize>,
) -> serde_json::Result<Option<HarPostData<'a>>> {
    let Some(placeholder) = har_post_data_placeholder(detail) else {
        return Ok(None);
    };
    if detail.request_body.bytes.is_empty() {
        return Ok(Some(placeholder));
    }
    let mime_type = placeholder.mime_type;
    fit_body_for_har(
        &detail.request_body,
        &detail.request_headers,
        remaining_body_bytes,
        placeholder,
        |rendered| HarPostData {
            mime_type,
            text: match rendered {
                RenderedText::Text(text) => text,
                RenderedText::Base64(data) => Cow::Owned(data),
            },
            comment: None,
        },
    )
    .map(Some)
}

fn har_content_for_export<'a>(
    detail: &'a HttpDetail,
    remaining_body_bytes: &mut Option<usize>,
) -> serde_json::Result<HarContent<'a>> {
    let placeholder = har_content_placeholder(detail);
    if detail.response_body.bytes.is_empty() {
        return Ok(placeholder);
    }
    let body = &detail.response_body;
    let mime_type = placeholder.mime_type;
    fit_body_for_har(
        body,
        &detail.response_headers,
        remaining_body_bytes,
        placeholder,
        |rendered| {
            let (text, encoding) = match rendered {
                RenderedText::Text(text) => (Some(text), None),
                RenderedText::Base64(data) => (Some(Cow::Owned(data)), Some("base64")),
            };
            HarContent {
                size: body.size,
                mime_type,
                text,
                encoding,
                comment: body.truncated().then_some(TRUNCATED_BODY_COMMENT),
            }
        },
    )
}

fn har_headers(headers: &[(String, String)]) -> Value {
    json!(
        headers
            .iter()
            .map(|(name, value)| json!({"name": name, "value": value}))
            .collect::<Vec<_>>()
    )
}

/// A body as HAR content: decoded text, or base64.
fn har_content(body: &Body, headers: &[(String, String)]) -> Value {
    let shown = render(body, headers);
    let mut content = json!({
        "size": body.size,
        "mimeType": header(headers, "content-type").unwrap_or_default(),
    });
    if let Some(text) = shown.get("text") {
        content["text"] = text.clone();
    } else if let Some(data) = shown.get("base64") {
        content["text"] = data.clone();
        content["encoding"] = json!("base64");
    }
    if body.truncated() {
        content["comment"] = json!(TRUNCATED_BODY_COMMENT);
    }
    content
}

fn har_entry(r: &Request, http: &HttpSummary, detail: &HttpDetail) -> Value {
    let query: Vec<Value> = http
        .url
        .split_once('?')
        .map(|(_, query)| {
            query
                .split('&')
                .filter(|pair| !pair.is_empty())
                .map(|pair| {
                    let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                    json!({"name": name, "value": value})
                })
                .collect()
        })
        .unwrap_or_default();
    let mut request = json!({
        "method": http.method,
        "url": http.url,
        "httpVersion": "HTTP/1.1",
        "cookies": [],
        "headers": har_headers(&detail.request_headers),
        "queryString": query,
        "headersSize": -1,
        "bodySize": http.request_size,
    });
    if detail.request_body.size > 0 {
        let content = har_content(&detail.request_body, &detail.request_headers);
        request["postData"] = json!({
            "mimeType": content["mimeType"],
            "text": content.get("text").cloned().unwrap_or_default(),
        });
    }
    json!({
        "startedDateTime": iso_time(r.time),
        "time": r.duration,
        "request": request,
        "response": {
            "status": http.status.unwrap_or(0),
            "statusText": http.error.clone().unwrap_or_default(),
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": har_headers(&detail.response_headers),
            "content": har_content(&detail.response_body, &detail.response_headers),
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": http.response_size,
        },
        "cache": {},
        "timings": {"send": 0, "wait": r.duration, "receive": 0},
        "connection": r.connection,
        "comment": format!("{} -> {}", r.rule, r.chain),
    })
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
}

enum DecodedBody<'a> {
    Bytes(Cow<'a, [u8]>),
    ExceededLimit,
}

enum RenderedText<'a> {
    Text(Cow<'a, str>),
    Base64(String),
}

fn decode_body<'a>(
    body: &'a Body,
    headers: &[(String, String)],
    limit: Option<usize>,
) -> (DecodedBody<'a>, bool) {
    if !body.bytes.is_empty()
        && let Some(encoding) = header(headers, "content-encoding")
    {
        let cap = limit
            .map(|rem| rem.min(DECODED_CAP as usize) as u64 + 1)
            .unwrap_or(DECODED_CAP);
        if let Some(plain) = decode_with(encoding, &body.bytes, cap) {
            if limit.is_some_and(|rem| plain.len() > rem) {
                return (DecodedBody::ExceededLimit, true);
            }
            return (DecodedBody::Bytes(Cow::Owned(plain)), true);
        }
    }
    (
        DecodedBody::Bytes(Cow::Borrowed(body.bytes.as_slice())),
        false,
    )
}

fn is_textual_content_type(content_type: &str) -> bool {
    content_type.starts_with("text/")
        || [
            "json",
            "xml",
            "javascript",
            "x-www-form-urlencoded",
            "graphql",
        ]
        .iter()
        .any(|t| content_type.contains(t))
}

fn render_bytes<'a>(bytes: Cow<'a, [u8]>, headers: &[(String, String)]) -> RenderedText<'a> {
    let textual = is_textual_content_type(header(headers, "content-type").unwrap_or_default());
    match bytes {
        Cow::Borrowed(slice) => match std::str::from_utf8(slice) {
            Ok(text) => RenderedText::Text(Cow::Borrowed(text)),
            // A truncated body may end inside a character.
            Err(error) if error.valid_up_to() + 4 > slice.len() || textual => {
                RenderedText::Text(Cow::Owned(String::from_utf8_lossy(slice).into_owned()))
            }
            Err(_) => RenderedText::Base64(STANDARD.encode(slice)),
        },
        Cow::Owned(vec) => match String::from_utf8(vec) {
            Ok(text) => RenderedText::Text(Cow::Owned(text)),
            Err(error) => {
                let valid_up_to = error.utf8_error().valid_up_to();
                let vec = error.into_bytes();
                if valid_up_to + 4 > vec.len() || textual {
                    RenderedText::Text(Cow::Owned(String::from_utf8_lossy(&vec).into_owned()))
                } else {
                    RenderedText::Base64(STANDARD.encode(&vec))
                }
            }
        },
    }
}

struct HeaderTuples<'a>(&'a [(String, String)]);

impl Serialize for HeaderTuples<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for (name, value) in self.0 {
            seq.serialize_element(&(name.as_str(), value.as_str()))?;
        }
        seq.end()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RenderedBody<'a> {
    size: u64,
    truncated: bool,
    decoded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    base64: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DetailView<'a> {
    #[serde(flatten)]
    summary: &'a Request,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_headers: Option<HeaderTuples<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_headers: Option<HeaderTuples<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_body: Option<RenderedBody<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<RenderedBody<'a>>,
}

fn render_body_with_cap<'a>(
    body: &'a Body,
    headers: &'a [(String, String)],
    decoded_cap: u64,
) -> RenderedBody<'a> {
    let mut decode_truncated = false;
    let (bytes, decoded) = if !body.bytes.is_empty()
        && let Some(encoding) = header(headers, "content-encoding")
        && let Some(mut plain) = decode_with(encoding, &body.bytes, decoded_cap + 1)
    {
        if plain.len() as u64 > decoded_cap {
            plain.truncate(decoded_cap as usize);
            decode_truncated = true;
        }
        (Cow::Owned(plain), true)
    } else {
        (Cow::Borrowed(body.bytes.as_slice()), false)
    };
    let (text, base64) = match render_bytes(bytes, headers) {
        RenderedText::Text(text) => (Some(text), None),
        RenderedText::Base64(data) => (None, Some(data)),
    };
    RenderedBody {
        size: body.size,
        truncated: body.truncated() || decode_truncated,
        decoded,
        text,
        base64,
    }
}

/// A body for the apps: decompressed per Content-Encoding, then as text when
/// it reads as text, else base64.
fn render(body: &Body, headers: &[(String, String)]) -> Value {
    serde_json::to_value(render_body_with_cap(body, headers, DECODED_CAP))
        .expect("RenderedBody must serialize")
}

/// The whole decoded body, or `None` when a coding is unknown, the data is
/// bad or it decodes to more than `limit` bytes.
pub(crate) fn decode_limited(encoding: &str, bytes: &[u8], limit: usize) -> Option<Vec<u8>> {
    let plain = decode_with(encoding, bytes, limit as u64 + 1)?;
    (plain.len() <= limit).then_some(plain)
}

fn decode_with(encoding: &str, bytes: &[u8], cap: u64) -> Option<Vec<u8>> {
    let mut data = Cow::Borrowed(bytes);
    let mut changed = false;
    for coding in encoding.rsplit(',').map(|c| c.trim().to_ascii_lowercase()) {
        let mut out = Vec::new();
        let reader: Box<dyn Read + '_> = match coding.as_str() {
            "" | "identity" => continue,
            "gzip" | "x-gzip" => Box::new(flate2::read::MultiGzDecoder::new(data.as_ref())),
            "deflate" => {
                // Usually zlib-wrapped, sometimes raw.
                if data.first().is_some_and(|b| b & 0x0f == 8) {
                    Box::new(flate2::read::ZlibDecoder::new(data.as_ref()))
                } else {
                    Box::new(flate2::read::DeflateDecoder::new(data.as_ref()))
                }
            }
            "br" => Box::new(brotli::Decompressor::new(data.as_ref(), 4096)),
            "zstd" => Box::new(zstd::stream::read::Decoder::new(data.as_ref()).ok()?),
            _ => return None,
        };
        if reader.take(cap).read_to_end(&mut out).is_err() {
            return None;
        }
        if out.is_empty() && !data.is_empty() {
            return None;
        }
        data = Cow::Owned(out);
        changed = true;
    }
    changed.then(|| data.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn summary(host: &str) -> Request {
        Request {
            id: 0,
            time: 0,
            network: "tcp".into(),
            source: String::new(),
            host: host.into(),
            port: 443,
            rule: "Match".into(),
            chain: "DIRECT".into(),
            status: "closed".into(),
            duration: 0,
            upload: 0,
            download: 0,
            connection: String::new(),
            reason: None,
            requests: 0,
            http: None,
        }
    }

    #[test]
    fn keeps_the_newest_entries_within_limits() {
        let requests = Requests {
            log: Mutex::default(),
            limits: Limits {
                entries: 3,
                body_bytes: 10,
                body_cap: 8,
                header_bytes: 0,
                decoded_cap: DECODED_CAP,
            },
            capture_budget: None,
            rewrite_budget: None,
        };
        for n in 0..5 {
            requests.push(summary(&format!("{n}.test")), None);
        }
        let (all, next) = requests.list(0, 100);
        assert_eq!(
            all.iter().map(|r| r.host.as_str()).collect::<Vec<_>>(),
            ["2.test", "3.test", "4.test"]
        );
        assert_eq!(next, 5);
        assert!(requests.list(5, 100).0.is_empty());
        assert_eq!(requests.list(3, 100).0[0].id, 4);
        // Bodies beyond the byte limit push old entries out.
        let mut body = Body::default();
        body.push(b"0123456789abcdef", 8);
        assert_eq!((body.bytes.len(), body.size), (8, 16));
        for host in ["a.test", "b.test"] {
            let mut response_body = Body::default();
            response_body.push(b"0123456789abcdef", 8);
            requests.push(
                summary(host),
                Some(HttpDetail {
                    response_body,
                    ..Default::default()
                }),
            );
        }
        let (all, _) = requests.list(0, 100);
        assert_eq!(all.len(), 1);
        let shown = requests.detail(all[0].id).unwrap();
        assert_eq!(shown["responseBody"]["text"], "01234567");
        assert_eq!(shown["responseBody"]["truncated"], true);
        // CSV: one line per entry, quoted when needed, formulas defused.
        let mut tricky = summary("x.test");
        tricky.reason = Some("=1+1, \"q\"".into());
        requests.push(tricky, None);
        let csv = requests.export_csv();
        assert!(csv.starts_with("id,time,kind,"));
        let expected = format!("{q}'=1+1, {q}{q}q{q}{q}{q}", q = '"');
        assert!(csv.contains(&expected), "{csv}");
        requests.clear();
        assert!(requests.list(0, 100).0.is_empty());
    }

    #[test]
    fn bodies_are_decompressed_for_display() {
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(br#"{"ad":true}"#).unwrap();
        let body = Body {
            size: 0,
            bytes: gzip.finish().unwrap(),
            ..Default::default()
        };
        let headers = vec![
            ("Content-Encoding".to_owned(), "gzip".to_owned()),
            ("Content-Type".to_owned(), "application/json".to_owned()),
        ];
        let shown = render(&body, &headers);
        assert_eq!(shown["text"], r#"{"ad":true}"#);
        assert_eq!(shown["decoded"], true);
        let binary = Body {
            size: 4,
            bytes: vec![0xff, 0xfe, 0x00, 0x01, 0x80, 0x80, 0x80, 0x80, 0x80],
            ..Default::default()
        };
        assert_eq!(
            render(&binary, &[])["base64"],
            STANDARD.encode(&binary.bytes)
        );
    }

    #[test]
    fn exports_http_requests_as_har() {
        assert_eq!(iso_time(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_time(1_794_295_701_123), "2026-11-10T07:28:21.123Z");
        assert_eq!(iso_time(951_782_400_000), "2000-02-29T00:00:00.000Z");
        let requests = Requests::new(false);
        requests.push(summary("closed.test"), None);
        let mut request = summary("ads.test");
        request.status = "http".into();
        request.time = 0;
        request.http = Some(HttpSummary {
            method: "POST".into(),
            url: "https://ads.test/t?a=1&b".into(),
            decrypted: true,
            status: Some(204),
            request_size: 3,
            ..Default::default()
        });
        let mut body = Body::default();
        body.push(b"k=v", 100);
        requests.push(
            request,
            Some(HttpDetail {
                request_headers: vec![("Host".into(), "ads.test".into())],
                request_body: body,
                ..Default::default()
            }),
        );
        let har = requests.export_har();
        let entries = har["log"]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry["request"]["method"], "POST");
        assert_eq!(entry["request"]["queryString"][1]["name"], "b");
        assert_eq!(entry["request"]["postData"]["text"], "k=v");
        assert_eq!(entry["request"]["headers"][0]["value"], "ads.test");
        assert_eq!(entry["response"]["status"], 204);
        assert_eq!(entry["startedDateTime"], "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn capture_budget_counts_in_flight_bodies_and_retained_snapshots() {
        let mut requests = Requests::new(true);
        requests.capture_budget = Some(Arc::new(Semaphore::new(12)));
        let mut in_flight = Body::default();
        requests.capture(&mut in_flight, b"12345678", 8);
        let mut response = Body::default();
        requests.capture(&mut response, b"abcdef", 8);
        assert_eq!(response.bytes, b"abcd");
        assert_eq!(response.size, 6);
        requests.push(
            summary("a.test"),
            Some(HttpDetail {
                response_body: response,
                ..Default::default()
            }),
        );
        let snapshot = requests.snapshot();
        requests.relieve_memory();
        let mut next = Body::default();
        requests.capture(&mut next, b"next", 8);
        assert!(next.bytes.is_empty(), "export still owns the old body");
        drop(snapshot);
        drop(in_flight);
        requests.capture(&mut next, b"more", 8);
        assert!(
            next.bytes.is_empty(),
            "never splice a body after omitted bytes"
        );
        assert_eq!(next.size, 8);
        let mut fresh = Body::default();
        requests.capture(&mut fresh, b"fresh", 8);
        assert_eq!(fresh.bytes, b"fresh");
    }

    #[test]
    fn relieve_memory_drops_bodies_but_keeps_summaries_and_headers() {
        let requests = Requests::new(true);
        let mut req_body = Body::default();
        req_body.push(b"hello-req", 1024);
        let mut resp_body = Body::default();
        resp_body.push(b"hello-resp", 1024);
        let mut req = summary("ads.test");
        req.status = "http".into();
        requests.push(
            req,
            Some(HttpDetail {
                request_headers: vec![("Host".into(), "ads.test".into())],
                response_headers: vec![("Content-Type".into(), "text/plain".into())],
                request_body: req_body,
                response_body: resp_body,
            }),
        );
        assert!(requests.log.lock().unwrap().body_bytes > 0);
        requests.relieve_memory();
        assert_eq!(requests.log.lock().unwrap().body_bytes, 0);
        let (all, _) = requests.list(0, 10);
        assert_eq!(all.len(), 1);
        let detail = requests.detail(all[0].id).unwrap();
        assert_eq!(detail["requestHeaders"][0][1], "ads.test");
        assert_eq!(detail["responseHeaders"][0][1], "text/plain");
        assert_eq!(detail["requestBody"]["text"], "");
        assert_eq!(detail["requestBody"]["truncated"], true);
        assert_eq!(detail["requestBody"]["size"], 9);
        assert_eq!(detail["responseBody"]["size"], 10);
    }

    #[test]
    fn reserve_body_budget_is_independent_of_capture_budget() {
        let desktop = Requests::new(false);
        assert_eq!(desktop.captured_bytes(), 0);
        assert!(desktop.reserve_body_budget(0).unwrap().is_none());
        assert!(desktop.reserve_body_budget(1024).unwrap().is_none());
        assert!(desktop.reserve_body_budget(usize::MAX).unwrap().is_none());
        assert_eq!(desktop.captured_bytes(), 0);

        let hosted = Requests::new(true);
        assert_eq!(hosted.captured_bytes(), 0);
        assert!(hosted.reserve_body_budget(0).unwrap().is_none());
        assert_eq!(hosted.captured_bytes(), 0);

        let mut captured = Body::default();
        let captured_chunk = vec![b'a'; HOSTED_CAPTURE_BYTES];
        hosted.capture(&mut captured, &captured_chunk, captured_chunk.len());
        assert_eq!(captured.bytes.len(), HOSTED_CAPTURE_BYTES);
        assert_eq!(hosted.captured_bytes(), HOSTED_CAPTURE_BYTES);

        // Full capture budget must not block rewrite body reservation.
        let reserved = hosted
            .reserve_body_budget(HOSTED_CAPTURE_BYTES)
            .expect("rewrite budget should be independent of capture budget")
            .expect("nonzero hosted reservation should hold a permit");
        assert!(hosted.reserve_body_budget(1).is_err());
        assert!(hosted.reserve_body_budget(0).unwrap().is_none());

        drop(reserved);
        let full = hosted
            .reserve_body_budget(HOSTED_CAPTURE_BYTES)
            .expect("full rewrite budget should be restored after drop")
            .expect("full hosted reservation should hold a permit");
        drop(full);
        drop(captured);
        assert_eq!(hosted.captured_bytes(), 0);
    }

    #[test]
    fn decode_limited_rejects_truncated_gzip() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"hello world from clyntis").unwrap();
        let compressed = encoder.finish().unwrap();
        assert_eq!(
            decode_limited("gzip", &compressed, 1024).as_deref(),
            Some(b"hello world from clyntis".as_slice())
        );
        let truncated = &compressed[..compressed.len() - 4];
        assert_eq!(decode_limited("gzip", truncated, 1024), None);
    }

    #[allow(clippy::too_many_arguments)]
    fn push_http_exchange(
        requests: &Requests,
        host: &str,
        method: &str,
        url: &str,
        status: u16,
        request_headers: Vec<(&str, &str)>,
        request_payload: &[u8],
        response_headers: Vec<(&str, &str)>,
        response_payload: &[u8],
    ) {
        let mut request_body = Body::default();
        if !request_payload.is_empty() {
            let cap = requests.body_cap(None);
            requests.capture(&mut request_body, request_payload, cap);
        }
        let resp_ct = response_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| *v);
        let mut response_body = Body::default();
        if !response_payload.is_empty() {
            let cap = requests.body_cap(resp_ct);
            requests.capture(&mut response_body, response_payload, cap);
        }
        let mut req = summary(host);
        req.status = "http".into();
        req.connection = format!("conn-{host}");
        req.duration = 42;
        req.http = Some(HttpSummary {
            method: method.into(),
            url: url.into(),
            decrypted: true,
            status: Some(status),
            content_type: resp_ct.map(str::to_owned),
            request_size: request_body.size,
            response_size: response_body.size,
            ..Default::default()
        });
        requests.push(
            req,
            Some(HttpDetail {
                request_headers: request_headers
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect(),
                response_headers: response_headers
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect(),
                request_body,
                response_body,
            }),
        );
    }

    fn gzip_compress(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn hosted_har_export_enforces_limit_and_preserves_metadata() {
        let requests = Requests::new(true);
        push_http_exchange(
            &requests,
            "first.test",
            "POST",
            "https://first.test/submit?k=1&flag",
            201,
            vec![("Host", "first.test"), ("Content-Type", "text/plain")],
            b"small-req",
            vec![("Content-Type", "text/plain"), ("X-Resp", "first")],
            b"small-resp",
        );
        let large_req = vec![b'q'; 600];
        let large_resp = vec![b'r'; 2000];
        push_http_exchange(
            &requests,
            "second.test",
            "PUT",
            "https://second.test/upload?token=abc",
            200,
            vec![("Host", "second.test"), ("Content-Type", "text/plain")],
            &large_req,
            vec![("Content-Type", "application/json"), ("X-Resp", "second")],
            &large_resp,
        );
        // Binary body where 4/3x base64 expansion pushes serialized size over small remaining budgets.
        let binary_resp: Vec<u8> = (0..180).map(|i| ((i * 37) as u8) | 0x80).collect();
        push_http_exchange(
            &requests,
            "third.test",
            "GET",
            "https://third.test/bin",
            200,
            vec![("Host", "third.test")],
            b"",
            vec![("Content-Type", "application/octet-stream")],
            &binary_resp,
        );
        // Control bytes whose raw length is < remaining budget (120), but \u0000 JSON escaping
        // expands 6x and exceeds the budget.
        push_http_exchange(
            &requests,
            "fourth.test",
            "GET",
            "https://fourth.test/esc",
            200,
            vec![("Host", "fourth.test")],
            b"",
            vec![("Content-Type", "text/plain")],
            &[0u8; 40],
        );

        let snapshot = requests.snapshot();
        let mut counter = ByteCounter(0);
        write_har_prefix(&mut counter).unwrap();
        for entry in &snapshot {
            counter.0 += json_byte_len(&HarEntry::without_bodies(
                &entry.summary,
                entry.summary.http.as_ref().unwrap(),
                entry.detail.as_ref().unwrap(),
            ))
            .unwrap();
        }
        let metadata_only_len = counter.0 + snapshot.len() - 1 + HAR_LOG_SUFFIX.len();
        // Enough room for entry 1's small request+response bodies, not entry 2's 600B/2000B bodies,
        // entry 3's 240B base64 body, or entry 4's 240B JSON-escaped body.
        let limit = metadata_only_len + 120;
        let bytes = requests.export_har_with_limit(Some(limit)).unwrap();
        assert!(bytes.len() <= limit, "len {} > {}", bytes.len(), limit);

        let har: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(har["log"]["version"], "1.2");
        assert_eq!(har["log"]["creator"]["name"], "Clyntis");
        assert!(har["log"]["pages"].as_array().unwrap().is_empty());
        let entries = har["log"]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 4);

        // Entry 1 bodies fit.
        assert_eq!(entries[0]["request"]["method"], "POST");
        assert_eq!(
            entries[0]["request"]["url"],
            "https://first.test/submit?k=1&flag"
        );
        assert_eq!(entries[0]["request"]["queryString"][0]["name"], "k");
        assert_eq!(entries[0]["request"]["postData"]["text"], "small-req");
        assert_eq!(entries[0]["response"]["status"], 201);
        assert_eq!(entries[0]["response"]["headers"][1]["value"], "first");
        assert_eq!(entries[0]["response"]["content"]["text"], "small-resp");
        assert!(entries[0]["response"]["content"].get("comment").is_none());

        // Entry 2 bodies overflow and are omitted while keeping metadata.
        assert_eq!(entries[1]["request"]["method"], "PUT");
        assert_eq!(entries[1]["request"]["bodySize"], 600);
        assert_eq!(entries[1]["request"]["postData"]["mimeType"], "text/plain");
        assert_eq!(entries[1]["request"]["postData"]["text"], "");
        assert_eq!(
            entries[1]["request"]["postData"]["comment"],
            OMITTED_BODY_COMMENT
        );
        assert_eq!(entries[1]["response"]["status"], 200);
        assert_eq!(entries[1]["response"]["bodySize"], 2000);
        assert_eq!(entries[1]["response"]["headers"][1]["value"], "second");
        assert_eq!(entries[1]["response"]["content"]["size"], 2000);
        assert_eq!(
            entries[1]["response"]["content"]["mimeType"],
            "application/json"
        );
        assert!(entries[1]["response"]["content"].get("text").is_none());
        assert!(entries[1]["response"]["content"].get("encoding").is_none());
        assert_eq!(
            entries[1]["response"]["content"]["comment"],
            OMITTED_BODY_COMMENT
        );

        // Entry 3 base64 and Entry 4 JSON-escaped bodies overflow and are omitted.
        assert_eq!(entries[2]["request"]["url"], "https://third.test/bin");
        assert!(entries[2]["request"].get("postData").is_none());
        assert_eq!(entries[2]["response"]["content"]["size"], 180);
        assert!(entries[2]["response"]["content"].get("text").is_none());
        assert_eq!(
            entries[2]["response"]["content"]["comment"],
            OMITTED_BODY_COMMENT
        );
        assert_eq!(entries[3]["request"]["url"], "https://fourth.test/esc");
        assert_eq!(entries[3]["response"]["content"]["size"], 40);
        assert!(entries[3]["response"]["content"].get("text").is_none());
        assert_eq!(
            entries[3]["response"]["content"]["comment"],
            OMITTED_BODY_COMMENT
        );
    }

    #[test]
    fn hosted_har_export_omits_compressible_gzip_without_inflating() {
        let requests = Requests::new(true);
        push_http_exchange(
            &requests,
            "small.test",
            "GET",
            "https://small.test/ok",
            200,
            vec![("Host", "small.test")],
            b"",
            vec![("Content-Type", "text/plain")],
            b"ok",
        );
        let compressed = gzip_compress(&vec![b'Z'; 512 * 1024]);
        assert!(compressed.len() < 4096);
        push_http_exchange(
            &requests,
            "gzip.test",
            "GET",
            "https://gzip.test/payload",
            200,
            vec![("Host", "gzip.test")],
            b"",
            vec![("Content-Type", "text/plain"), ("Content-Encoding", "gzip")],
            &compressed,
        );

        let limit = 4096;
        let bytes = requests.export_har_with_limit(Some(limit)).unwrap();
        assert!(bytes.len() <= limit);

        let har: Value = serde_json::from_slice(&bytes).unwrap();
        let entries = har["log"]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["response"]["content"]["text"], "ok");
        assert_eq!(entries[1]["request"]["url"], "https://gzip.test/payload");
        assert_eq!(entries[1]["response"]["status"], 200);
        assert_eq!(entries[1]["response"]["content"]["size"], compressed.len());
        assert!(entries[1]["response"]["content"].get("text").is_none());
        assert_eq!(
            entries[1]["response"]["content"]["comment"],
            OMITTED_BODY_COMMENT
        );
    }

    #[test]
    fn hosted_har_export_drops_older_entries_when_metadata_exceeds_limit() {
        let requests = Requests::new(true);
        let long_header = "x".repeat(60 << 10);
        for i in 0..40 {
            push_http_exchange(
                &requests,
                "older.test",
                "GET",
                &format!("https://older.test/{i}"),
                200,
                vec![("Host", "older.test")],
                b"",
                vec![("X-Large", &long_header)],
                b"",
            );
        }
        push_http_exchange(
            &requests,
            "cleared.test",
            "POST",
            "https://cleared.test/a",
            200,
            vec![("Host", "cleared.test"), ("Content-Type", "text/plain")],
            b"cleared-req",
            vec![("Content-Type", "text/plain")],
            b"cleared-resp",
        );
        requests.relieve_memory();
        push_http_exchange(
            &requests,
            "kept.test",
            "POST",
            "https://kept.test/b?x=1",
            202,
            vec![("Host", "kept.test"), ("Content-Type", "application/json")],
            b"{\"a\":1}",
            vec![("Content-Type", "application/json"), ("X-Id", "99")],
            b"{\"b\":2}",
        );

        let bytes = requests.export_har_json().unwrap();
        assert!(bytes.len() <= HOSTED_HAR_BYTES);
        assert!(bytes.capacity() <= HOSTED_HAR_BYTES);
        assert!(requests.export_har_with_limit(Some(64)).is_err());
        let har: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(har["log"]["version"], "1.2");
        assert!(har["log"]["comment"].as_str().unwrap().contains("omitted"));
        let entries = har["log"]["entries"].as_array().unwrap();
        assert!((3..42).contains(&entries.len()));
        assert_ne!(entries[0]["request"]["url"], "https://older.test/0");
        let entries = &entries[entries.len() - 2..];

        // Relieved entry keeps pre-existing empty/truncated HAR behavior.
        assert_eq!(entries[0]["request"]["url"], "https://cleared.test/a");
        assert_eq!(entries[0]["request"]["postData"]["text"], "");
        assert!(entries[0]["request"]["postData"].get("comment").is_none());
        assert_eq!(entries[0]["response"]["content"]["text"], "");
        assert_eq!(entries[0]["response"]["content"]["size"], 12);
        assert_eq!(
            entries[0]["response"]["content"]["comment"],
            TRUNCATED_BODY_COMMENT
        );

        // The newest entry retains its metadata and small bodies.
        assert_eq!(entries[1]["request"]["method"], "POST");
        assert_eq!(entries[1]["request"]["url"], "https://kept.test/b?x=1");
        assert_eq!(entries[1]["request"]["queryString"][0]["value"], "1");
        assert_eq!(
            entries[1]["request"]["postData"]["mimeType"],
            "application/json"
        );
        assert_eq!(entries[1]["request"]["postData"]["text"], "{\"a\":1}");
        assert_eq!(entries[1]["response"]["status"], 202);
        assert_eq!(entries[1]["response"]["headers"][1]["value"], "99");
        assert_eq!(entries[1]["response"]["content"]["size"], 7);
        assert_eq!(entries[1]["response"]["content"]["text"], "{\"b\":2}");
    }

    #[test]
    fn hosted_default_har_export_stays_within_two_mib_for_compressible_bodies() {
        let requests = Requests::new(true);
        // ~100 KiB incompressible prefix + 1 MiB zeros -> ~102 KiB gzipped (< 128 KiB body_cap),
        // decompressing to > 1.1 MiB each. 9 entries store ~920 KiB compressed (<= 1 MiB log cap)
        // and > 9.9 MiB decompressed (> 8 MiB).
        let mut raw = Vec::with_capacity(100 * 1024 + (1 << 20));
        let mut state: u32 = 0x1234_5678;
        for _ in 0..(100 * 1024) {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            raw.push((state & 0x3f) as u8 + b'!');
        }
        raw.resize(raw.len() + (1 << 20), b'0');
        let compressed = gzip_compress(&raw);
        assert!(compressed.len() < HOSTED.body_cap);
        assert!(compressed.len() * 9 < HOSTED.body_bytes);

        for i in 0..9 {
            push_http_exchange(
                &requests,
                &format!("h{i}.test"),
                "GET",
                &format!("https://h{i}.test/data"),
                200,
                vec![("Host", "h.test")],
                b"",
                vec![("Content-Type", "text/plain"), ("Content-Encoding", "gzip")],
                &compressed,
            );
        }
        assert_eq!(requests.list(0, 100).0.len(), 9);

        let json_bytes = requests.export_har_json().unwrap();
        assert!(
            json_bytes.len() <= HOSTED_HAR_BYTES,
            "hosted HAR {} exceeded {}",
            json_bytes.len(),
            HOSTED_HAR_BYTES
        );
        let har: Value = serde_json::from_slice(&json_bytes).unwrap();
        let entries = har["log"]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 9);
        assert!(
            entries
                .iter()
                .any(|e| e["response"]["content"]["comment"] == OMITTED_BODY_COMMENT)
        );
        for entry in entries {
            let content = &entry["response"]["content"];
            assert_eq!(content["size"], compressed.len());
            if content.get("text").is_none() {
                assert_eq!(content["comment"], OMITTED_BODY_COMMENT);
            }
        }

        let har_value = requests.export_har();
        assert_eq!(har_value["log"]["entries"].as_array().unwrap().len(), 9);
        assert!(serde_json::to_vec(&har_value).unwrap().len() <= HOSTED_HAR_BYTES);
    }

    #[test]
    fn desktop_har_export_remains_unbounded() {
        let requests = Requests::new(false);
        let body_a = vec![b'a'; 1536 << 10];
        let body_b = vec![b'b'; 1536 << 10];
        push_http_exchange(
            &requests,
            "desk1.test",
            "POST",
            "https://desk1.test/a?q=1",
            200,
            vec![("Host", "desk1.test"), ("Content-Type", "text/plain")],
            b"req-body",
            vec![("Content-Type", "text/plain")],
            &body_a,
        );
        push_http_exchange(
            &requests,
            "desk2.test",
            "GET",
            "https://desk2.test/b",
            200,
            vec![("Host", "desk2.test")],
            b"",
            vec![("Content-Type", "text/plain")],
            &body_b,
        );

        let har = requests.export_har();
        let json_bytes = requests.export_har_json().unwrap();
        assert!(json_bytes.len() > HOSTED_HAR_BYTES);
        assert!(json_bytes.contains(&b'\n'));
        let entries = har["log"]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0]["response"]["content"]["text"]
                .as_str()
                .unwrap()
                .len(),
            body_a.len()
        );
        assert_eq!(
            entries[1]["response"]["content"]["text"]
                .as_str()
                .unwrap()
                .len(),
            body_b.len()
        );
        let streamed: Value =
            serde_json::from_slice(&requests.export_har_with_limit(None).unwrap()).unwrap();
        assert_eq!(streamed, har);
    }

    #[test]
    fn hosted_header_budget_decoded_cap_and_csv_limit_bound_memory() {
        let requests = Requests::new(true);

        // 1. Hosted detail view caps decompressed bodies at HOSTED_DECODED_CAP (512 KiB)
        // and marks the body truncated rather than expanding up to 4 MiB.
        let huge_plain = vec![b'z'; (HOSTED_DECODED_CAP as usize) + 128 * 1024];
        let compressed = gzip_compress(&huge_plain);
        assert!(compressed.len() < HOSTED.body_cap);
        push_http_exchange(
            &requests,
            "bomb.test",
            "GET",
            "https://bomb.test/gzip",
            200,
            vec![("Host", "bomb.test")],
            b"",
            vec![("Content-Type", "text/plain"), ("Content-Encoding", "gzip")],
            &compressed,
        );
        let id = requests.list(0, 10).0[0].id;
        let detail = requests.detail(id).unwrap();
        let resp_body = &detail["responseBody"];
        assert_eq!(resp_body["decoded"], true);
        assert_eq!(resp_body["truncated"], true);
        assert_eq!(
            resp_body["text"].as_str().unwrap().len(),
            HOSTED_DECODED_CAP as usize
        );

        // 2. Hosted header budget (2 MiB) evicts older entries with large headers
        // even when entry count (< 500) and body bytes (0) are small.
        requests.clear();
        let large_header_val = "h".repeat(32 * 1024);
        for i in 0..80 {
            push_http_exchange(
                &requests,
                &format!("hdr{i}.test"),
                "GET",
                &format!("https://hdr{i}.test/path"),
                200,
                vec![("Host", "hdr.test"), ("X-Huge-Req", &large_header_val)],
                b"",
                vec![("X-Huge-Resp", &large_header_val)],
                b"",
            );
        }
        let log_guard = requests.log.lock().unwrap();
        assert!(
            log_guard.header_bytes <= HOSTED.header_bytes,
            "header_bytes {} exceeded {}",
            log_guard.header_bytes,
            HOSTED.header_bytes
        );
        assert!(log_guard.entries.len() < 80);
        drop(log_guard);

        // 3. Hosted CSV export enforces HOSTED_HAR_BYTES and keeps newest entries in order.
        let small_csv = requests.export_csv_with_limit(Some(512));
        assert!(small_csv.len() <= 512, "csv len {}", small_csv.len());
        let lines: Vec<&str> = small_csv.lines().collect();
        assert!(lines[0].starts_with("id,time,kind,"));
        assert!(lines.len() >= 2);
        assert!(lines.last().unwrap().contains("hdr79.test"));
    }
}
