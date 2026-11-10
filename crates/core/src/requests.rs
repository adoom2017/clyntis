//! The request log: recent connections (refused ones too) and the HTTP
//! requests read from decrypted or plain HTTP connections, for finding what
//! an app loads, ads among it. Memory only, bounded by entries and by body
//! bytes; the apps poll it with the last id they have.
use crate::{RouteDecision, traffic};
use base64::{Engine, engine::general_purpose::STANDARD};
use clyntis_protocol::Target;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    io::Read,
    sync::{Arc, Mutex, atomic::Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

/// Limits on what the log keeps.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub(crate) entries: usize,
    /// All kept bodies together.
    pub(crate) body_bytes: usize,
    /// One body; the rest of a longer body is counted but not kept.
    pub(crate) body_cap: usize,
}
const DESKTOP: Limits = Limits {
    entries: 5000,
    body_bytes: 64 << 20,
    body_cap: 2 << 20,
};
/// The iOS tunnel lives within about 50 MiB.
const HOSTED: Limits = Limits {
    entries: 500,
    body_bytes: 2 << 20,
    body_cap: 128 << 10,
};
/// A decoded body shown to the apps stops here.
const DECODED_CAP: u64 = 4 << 20;

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
}

/// Headers and the kept part of the bodies, as sent (still compressed).
#[derive(Clone, Debug, Default)]
pub(crate) struct HttpDetail {
    pub(crate) request_headers: Vec<(String, String)>,
    pub(crate) response_headers: Vec<(String, String)>,
    pub(crate) request_body: Body,
    pub(crate) response_body: Body,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Body {
    pub(crate) bytes: Vec<u8>,
    /// Bytes seen, kept or not.
    pub(crate) size: u64,
}
impl Body {
    pub(crate) fn push(&mut self, bytes: &[u8], cap: usize) {
        self.size += bytes.len() as u64;
        let room = cap.saturating_sub(self.bytes.len());
        self.bytes
            .extend_from_slice(&bytes[..bytes.len().min(room)]);
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
}

#[derive(Default)]
struct Log {
    entries: VecDeque<Arc<Entry>>,
    next: u64,
    body_bytes: usize,
}

pub struct Requests {
    log: Mutex<Log>,
    limits: Limits,
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
        }
    }
    pub(crate) fn body_cap(&self) -> usize {
        self.limits.body_cap
    }
    fn push(&self, mut summary: Request, mut detail: Option<HttpDetail>) {
        if let Some(detail) = &mut detail {
            detail.request_body.bytes.shrink_to_fit();
            detail.response_body.bytes.shrink_to_fit();
        }
        let mut log = self.log.lock().unwrap();
        log.next += 1;
        summary.id = log.next;
        let entry = Arc::new(Entry { summary, detail });
        log.body_bytes += entry.body_bytes();
        log.entries.push_back(entry);
        while log.entries.len() > self.limits.entries
            || (log.body_bytes > self.limits.body_bytes && log.entries.len() > 1)
        {
            if let Some(old) = log.entries.pop_front() {
                log.body_bytes -= old.body_bytes();
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
        let entry = {
            let log = self.log.lock().unwrap();
            let index = log
                .entries
                .binary_search_by_key(&id, |e| e.summary.id)
                .ok()?;
            log.entries[index].clone()
        };
        let mut value = serde_json::to_value(&entry.summary).ok()?;
        if let Some(detail) = &entry.detail {
            let headers = |list: &[(String, String)]| {
                list.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>()
            };
            value["requestHeaders"] = json!(headers(&detail.request_headers));
            value["responseHeaders"] = json!(headers(&detail.response_headers));
            value["requestBody"] = render(&detail.request_body, &detail.request_headers);
            value["responseBody"] = render(&detail.response_body, &detail.response_headers);
        }
        Some(value)
    }
    fn snapshot(&self) -> Vec<Arc<Entry>> {
        self.log.lock().unwrap().entries.iter().cloned().collect()
    }
    /// The HTTP requests as an HTTP Archive (HAR 1.2), which Charles,
    /// Proxyman and browser developer tools open. Bodies are the kept part,
    /// decompressed; connections without HTTP are left out (see
    /// [`Requests::export_csv`]).
    pub fn export_har(&self) -> Value {
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
    /// Every entry, one line each, as CSV with a header line.
    pub fn export_csv(&self) -> String {
        let mut out = String::from(
            "id,time,kind,network,source,host,port,method,url,status,content_type,rule,chain,upload,download,duration_ms,reason\n",
        );
        for entry in self.snapshot() {
            let r = &entry.summary;
            let http = r.http.as_ref();
            let fields = [
                r.id.to_string(),
                iso_time(r.time),
                r.status.clone(),
                r.network.clone(),
                r.source.clone(),
                r.host.clone(),
                r.port.to_string(),
                http.map(|h| h.method.clone()).unwrap_or_default(),
                http.map(|h| h.url.clone()).unwrap_or_default(),
                http.and_then(|h| h.status)
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
                http.and_then(|h| h.content_type.clone())
                    .unwrap_or_default(),
                r.rule.clone(),
                r.chain.clone(),
                r.upload.to_string(),
                r.download.to_string(),
                r.duration.to_string(),
                http.and_then(|h| h.error.clone())
                    .or_else(|| r.reason.clone())
                    .unwrap_or_default(),
            ];
            let line: Vec<String> = fields.iter().map(|f| csv_field(f)).collect();
            out.push_str(&line.join(","));
            out.push('\n');
        }
        out
    }
    pub fn clear(&self) {
        let mut log = self.log.lock().unwrap();
        log.entries.clear();
        log.body_bytes = 0;
    }
}

fn csv_field(value: &str) -> String {
    // A leading =, +, - or @ would run as a formula in a spreadsheet.
    let value = if value.starts_with(['=', '+', '-', '@']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value
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
        content["comment"] = json!("truncated: only the beginning was kept");
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

/// A body for the apps: decompressed per Content-Encoding, then as text when
/// it reads as text, else base64.
fn render(body: &Body, headers: &[(String, String)]) -> Value {
    let mut bytes = std::borrow::Cow::Borrowed(body.bytes.as_slice());
    let mut decoded = false;
    if let Some(encoding) = header(headers, "content-encoding")
        && let Some(plain) = decode(encoding, &body.bytes)
    {
        bytes = plain.into();
        decoded = true;
    }
    let content_type = header(headers, "content-type").unwrap_or_default();
    let textual = content_type.starts_with("text/")
        || [
            "json",
            "xml",
            "javascript",
            "x-www-form-urlencoded",
            "graphql",
        ]
        .iter()
        .any(|t| content_type.contains(t));
    let mut value = json!({
        "size": body.size,
        "truncated": body.truncated(),
        "decoded": decoded,
    });
    match std::str::from_utf8(&bytes) {
        Ok(text) => value["text"] = json!(text),
        // A truncated body may end inside a character.
        Err(error) if error.valid_up_to() + 4 > bytes.len() || textual => {
            value["text"] = json!(String::from_utf8_lossy(&bytes))
        }
        Err(_) => value["base64"] = json!(STANDARD.encode(&bytes)),
    }
    value
}

/// Undoes Content-Encoding (the last coding listed was applied last); `None`
/// when a coding is unknown or nothing came out. A truncated body decodes
/// as far as it goes.
fn decode(encoding: &str, bytes: &[u8]) -> Option<Vec<u8>> {
    let mut data = bytes.to_vec();
    let mut changed = false;
    for coding in encoding.rsplit(',').map(|c| c.trim().to_ascii_lowercase()) {
        let mut out = Vec::new();
        let reader: Box<dyn Read + '_> = match coding.as_str() {
            "" | "identity" => continue,
            "gzip" | "x-gzip" => Box::new(flate2::read::MultiGzDecoder::new(data.as_slice())),
            "deflate" => {
                // Usually zlib-wrapped, sometimes raw.
                if data.first().is_some_and(|b| b & 0x0f == 8) {
                    Box::new(flate2::read::ZlibDecoder::new(data.as_slice()))
                } else {
                    Box::new(flate2::read::DeflateDecoder::new(data.as_slice()))
                }
            }
            "br" => Box::new(brotli::Decompressor::new(data.as_slice(), 4096)),
            "zstd" => Box::new(zstd::stream::read::Decoder::new(data.as_slice()).ok()?),
            _ => return None,
        };
        let _ = reader.take(DECODED_CAP).read_to_end(&mut out);
        if out.is_empty() && !data.is_empty() {
            return None;
        }
        data = out;
        changed = true;
    }
    changed.then_some(data)
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
            },
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
        let detail = HttpDetail {
            response_body: body,
            ..Default::default()
        };
        requests.push(summary("a.test"), Some(detail.clone()));
        requests.push(summary("b.test"), Some(detail));
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
}
