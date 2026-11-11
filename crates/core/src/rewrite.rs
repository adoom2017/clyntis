//! Rewriting decrypted HTTP with modules (see `clyntis_config::rewrite`):
//! compiled rules, the actions that need no script, and counters.
use clyntis_config::{
    rewrite::{Action, DomainKind, HeaderOp, Mock, MockBody, Module, Phase, Reject, TINY_GIF},
    rule::{DomainSet, DomainSetBuilder},
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

/// One module as loaded, for status displays.
#[derive(Clone, Debug, Serialize)]
pub struct ModuleInfo {
    pub name: String,
    /// The module's own `#!name`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub rules: usize,
    pub scripts: usize,
    pub hostnames: usize,
    /// Domain rules that reject.
    pub reject: usize,
    /// Lines skipped: not understood, or patterns that do not compile.
    pub skipped: Vec<Skipped>,
    /// Scripts or response files that could not be downloaded.
    pub missing: Vec<String>,
    /// When the module file was downloaded (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Skipped {
    pub line: usize,
    pub text: String,
}

/// A rule ready to match.
pub(crate) struct Compiled {
    pub(crate) module: String,
    pub(crate) line: usize,
    pub(crate) phase: Phase,
    pattern: fancy_regex::Regex,
    pub(crate) action: Action,
    /// Compiled regexes of body and header rewrites, in order.
    extra: Vec<fancy_regex::Regex>,
    /// The compiled filter of a jq rewrite.
    pub(crate) jq: Option<crate::jq::Filter>,
}
impl Compiled {
    /// `kind (module)`, for the request log.
    pub(crate) fn label(&self) -> String {
        format!("{} ({})", self.action.kind(), self.module)
    }
}

/// The compiled modules of a snapshot.
pub struct Rewriter {
    rules: Vec<Compiled>,
    /// Rules whose pattern the `regex` crate compiles, matched in one pass;
    /// `fancy` lists the others (lookaround and the like).
    set: regex::RegexSet,
    set_index: Vec<usize>,
    fancy: Vec<usize>,
    pub(crate) hostnames: Vec<String>,
    reject: DomainSet,
    pub modules: Vec<ModuleInfo>,
    /// Downloaded scripts and response bodies by URL.
    files: HashMap<String, PathBuf>,
}

/// A module's rules, its name, and where its downloads went.
pub(crate) struct Loaded {
    pub(crate) name: String,
    pub(crate) module: Module,
    pub(crate) files: HashMap<String, PathBuf>,
    pub(crate) missing: Vec<String>,
    pub(crate) updated: Option<u64>,
}

impl Rewriter {
    /// Compiles the modules in order; `failed` are modules that could not be
    /// loaded at all (name, error).
    pub(crate) fn new(loaded: Vec<Loaded>, failed: Vec<(String, Option<u64>, String)>) -> Self {
        let mut rules = Vec::new();
        let mut hostnames = Vec::new();
        let mut reject = DomainSetBuilder::default();
        let mut modules = Vec::new();
        let mut files = HashMap::new();
        for loaded in loaded {
            let module = loaded.module;
            let mut skipped: Vec<Skipped> = module
                .skipped
                .iter()
                .map(|(line, text)| Skipped {
                    line: *line,
                    text: text.clone(),
                })
                .collect();
            let mut count = 0;
            let mut scripts = 0;
            for rule in module.rules {
                match compile(&loaded.name, rule) {
                    Ok(compiled) => {
                        // A rule whose file is missing cannot act.
                        let file = match &compiled.action {
                            Action::Script(script) => Some(&script.url),
                            Action::Mock(Mock {
                                body: MockBody::Remote(url),
                                ..
                            }) => Some(url),
                            _ => None,
                        };
                        if file.is_some_and(|url| !loaded.files.contains_key(url)) {
                            continue;
                        }
                        if matches!(compiled.action, Action::Script(_)) {
                            scripts += 1;
                        }
                        count += 1;
                        rules.push(compiled);
                    }
                    Err((line, text)) => skipped.push(Skipped { line, text }),
                }
            }
            for (kind, value) in &module.reject {
                match kind {
                    DomainKind::Exact => reject.exact(value),
                    DomainKind::Suffix => reject.suffix(value),
                    DomainKind::Keyword => reject.keyword(value),
                }
            }
            hostnames.extend(module.hostnames.iter().cloned());
            files.extend(loaded.files);
            modules.push(ModuleInfo {
                name: loaded.name,
                title: module.name,
                description: module.description,
                rules: count,
                scripts,
                hostnames: module.hostnames.len(),
                reject: module.reject.len(),
                skipped,
                missing: loaded.missing,
                updated: loaded.updated,
                error: None,
            });
        }
        for (name, updated, error) in failed {
            modules.push(ModuleInfo {
                name,
                title: None,
                description: None,
                rules: 0,
                scripts: 0,
                hostnames: 0,
                reject: 0,
                skipped: vec![],
                missing: vec![],
                updated,
                error: Some(error),
            });
        }
        let (mut set_patterns, mut set_index, mut fancy) = (Vec::new(), Vec::new(), Vec::new());
        for (index, rule) in rules.iter().enumerate() {
            let source = rule.pattern.as_str();
            if regex::Regex::new(source).is_ok() {
                set_patterns.push(source.to_owned());
                set_index.push(index);
            } else {
                fancy.push(index);
            }
        }
        let set = regex::RegexSet::new(&set_patterns).unwrap_or_else(|_| {
            // Too large together: match each one instead.
            fancy.append(&mut set_index);
            fancy.sort_unstable();
            regex::RegexSet::empty()
        });
        Self {
            rules,
            set,
            set_index,
            fancy,
            hostnames,
            reject: reject.build(),
            modules,
            files,
        }
    }

    /// The rules of `phase` that match `url`, in module order.
    pub(crate) fn matching(&self, phase: Phase, url: &str) -> Vec<usize> {
        let mut found: Vec<usize> = self
            .set
            .matches(url)
            .into_iter()
            .map(|i| self.set_index[i])
            .chain(
                self.fancy
                    .iter()
                    .copied()
                    .filter(|&i| self.rules[i].pattern.is_match(url).unwrap_or(false)),
            )
            .filter(|&i| self.rules[i].phase == phase)
            .collect();
        found.sort_unstable();
        found
    }
    pub(crate) fn rule(&self, index: usize) -> &Compiled {
        &self.rules[index]
    }
    pub(crate) fn file(&self, url: &str) -> Option<&PathBuf> {
        self.files.get(url)
    }
    /// Whether a module's domain rule rejects `host`.
    pub fn rejects(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.');
        !self.reject.is_empty() && self.reject.matches(&host.to_ascii_lowercase())
    }
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

fn compile(module: &str, rule: clyntis_config::rewrite::Rule) -> Result<Compiled, (usize, String)> {
    let failed = |what: &str| (rule.line, format!("{what}: {}", rule.pattern));
    let pattern = fancy_regex::Regex::new(&rule.pattern).map_err(|_| failed("bad pattern"))?;
    let extra = match &rule.action {
        Action::BodyReplace(pairs) => pairs
            .iter()
            .map(|(regex, _)| fancy_regex::Regex::new(regex))
            .collect::<Result<_, _>>()
            .map_err(|_| failed("bad body regex"))?,
        Action::Header(HeaderOp::ReplaceRegex(_, regex, _)) => {
            vec![fancy_regex::Regex::new(regex).map_err(|_| failed("bad header regex"))?]
        }
        _ => vec![],
    };
    let jq = match &rule.action {
        Action::Jq(code) => Some(
            crate::jq::Filter::compile(code)
                .map_err(|error| (rule.line, format!("{error}: {code}")))?,
        ),
        _ => None,
    };
    Ok(Compiled {
        module: module.to_owned(),
        line: rule.line,
        phase: rule.phase,
        pattern,
        action: rule.action,
        extra,
        jq,
    })
}

/// A JavaScript replacement (`$1`, `$&`) in the `regex` crate's syntax.
fn replacement(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('$') => {
                chars.next();
                out.push_str("$$");
            }
            Some('&') => {
                chars.next();
                out.push_str("${0}");
            }
            Some(d) if d.is_ascii_digit() => {
                let mut digits = String::new();
                while let Some(d) = chars.peek().filter(|d| d.is_ascii_digit()) {
                    digits.push(*d);
                    chars.next();
                }
                out.push_str(&format!("${{{digits}}}"));
            }
            Some('{') | Some('<') => out.push('$'),
            _ => out.push_str("$$"),
        }
    }
    out
}

/// An answer made here instead of the server's.
#[derive(Clone, Debug, Default)]
pub(crate) struct Answer {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}
impl Answer {
    fn new(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        let mut headers = vec![];
        if !content_type.is_empty() {
            headers.push(("Content-Type".into(), content_type.into()));
        }
        Self {
            status,
            headers,
            body,
        }
    }
    /// The response on the wire, with its length.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {} {}\r\n", self.status, reason(self.status)).into_bytes();
        for (name, value) in &self.headers {
            if is_framing(name) {
                continue;
            }
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", self.body.len()).as_bytes());
        out.extend_from_slice(&self.body);
        out
    }
}

fn is_framing(name: &str) -> bool {
    name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("transfer-encoding")
}

pub(crate) fn reason(status: u16) -> &'static str {
    http::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("OK")
}

/// What a rule that answers the request does: `None` drops the connection.
pub(crate) fn answer(rewriter: &Rewriter, rule: &Compiled, url: &str) -> Option<Answer> {
    Some(match &rule.action {
        Action::Reject(reject) => match reject {
            Reject::NotFound => Answer::new(404, "text/plain", vec![]),
            Reject::Empty => Answer::new(200, "text/plain", vec![]),
            Reject::Image => Answer::new(200, "image/gif", TINY_GIF.to_vec()),
            Reject::Dict => Answer::new(200, "application/json", b"{}".to_vec()),
            Reject::Array => Answer::new(200, "application/json", b"[]".to_vec()),
            Reject::Drop => return None,
        },
        Action::Redirect { status, location } => {
            let location = rule
                .pattern
                .replace(url, replacement(location).as_str())
                .into_owned();
            let mut answer = Answer::new(*status, "", vec![]);
            answer.headers.push(("Location".into(), location));
            answer
        }
        Action::Mock(mock) => {
            let body = match &mock.body {
                MockBody::Inline(bytes) => bytes.clone(),
                MockBody::Remote(url) => rewriter
                    .file(url)
                    .and_then(|path| std::fs::read(path).ok())
                    .unwrap_or_default(),
            };
            let mut answer = Answer::new(mock.status, &mock.content_type, body);
            answer.headers.extend(mock.headers.iter().cloned());
            answer
        }
        _ => Answer::new(404, "", vec![]),
    })
}

pub(crate) fn find<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Applies a header rewrite. Framing headers are left alone: the relay
/// sets them.
pub(crate) fn apply_header(rule: &Compiled, headers: &mut Vec<(String, String)>) {
    let Action::Header(op) = &rule.action else {
        return;
    };
    match op {
        HeaderOp::Add(name, value) if !is_framing(name) => {
            headers.push((name.clone(), value.clone()));
        }
        HeaderOp::Delete(name) if !is_framing(name) => {
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        }
        HeaderOp::Replace(name, value) if !is_framing(name) => {
            for (k, v) in headers.iter_mut() {
                if k.eq_ignore_ascii_case(name) {
                    *v = value.clone();
                }
            }
        }
        HeaderOp::ReplaceRegex(name, _, with) if !is_framing(name) => {
            let regex = &rule.extra[0];
            for (k, v) in headers.iter_mut() {
                if k.eq_ignore_ascii_case(name) {
                    *v = regex
                        .replace_all(v, replacement(with).as_str())
                        .into_owned();
                }
            }
        }
        _ => {}
    }
}

/// Applies a body or JSON rewrite to a decoded body; false when it does not
/// apply (not text, or not JSON).
pub(crate) fn apply_body(rule: &Compiled, body: &mut Vec<u8>) -> bool {
    match &rule.action {
        Action::BodyReplace(pairs) => {
            let Ok(text) = std::str::from_utf8(body) else {
                return false;
            };
            let mut text = text.to_owned();
            for ((_, with), regex) in pairs.iter().zip(&rule.extra) {
                text = regex
                    .replace_all(&text, replacement(with).as_str())
                    .into_owned();
            }
            *body = text.into_bytes();
            true
        }
        Action::JsonDelete(paths) => edit_json(body, |value| {
            for path in paths {
                delete_path(value, &segments(path));
            }
        }),
        Action::JsonSet(pairs) => edit_json(body, |value| {
            for (path, raw) in pairs {
                // A value that is not JSON is a string.
                let new = serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.clone()));
                set_path(value, &segments(path), new);
            }
        }),
        _ => false,
    }
}

fn edit_json(body: &mut Vec<u8>, edit: impl FnOnce(&mut Value)) -> bool {
    let Ok(mut value) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    edit(&mut value);
    match serde_json::to_vec(&value) {
        Ok(bytes) => {
            *body = bytes;
            true
        }
        Err(_) => false,
    }
}

#[derive(Debug, PartialEq)]
enum Segment {
    Key(String),
    Index(usize),
    /// Every element: `[]` or `[*]`.
    Each,
}

/// `a.b[0].c`, `a[].b`, `a.*.b` → segments.
fn segments(path: &str) -> Vec<Segment> {
    let mut out = Vec::new();
    for part in path.split('.') {
        let (key, mut rest) = match part.find('[') {
            Some(i) => (&part[..i], &part[i..]),
            None => (part, ""),
        };
        if key == "*" {
            out.push(Segment::Each);
        } else if !key.is_empty() {
            out.push(Segment::Key(key.to_owned()));
        }
        while let Some(end) = rest.find(']') {
            let inner = rest[1..end].trim();
            out.push(match inner {
                "" | "*" => Segment::Each,
                n => match n.parse() {
                    Ok(index) => Segment::Index(index),
                    Err(_) => Segment::Key(n.trim_matches(['"', '\'']).to_owned()),
                },
            });
            rest = &rest[end + 1..];
        }
    }
    out
}

fn delete_path(value: &mut Value, path: &[Segment]) {
    let Some((last, parents)) = path.split_last() else {
        return;
    };
    if parents.is_empty() {
        match (last, value) {
            (Segment::Key(key), Value::Object(map)) => {
                map.remove(key);
            }
            (Segment::Index(index), Value::Array(items)) if *index < items.len() => {
                items.remove(*index);
            }
            (Segment::Each, Value::Array(items)) => items.clear(),
            (Segment::Each, Value::Object(map)) => map.clear(),
            _ => {}
        }
        return;
    }
    for child in children(value, &parents[0]) {
        delete_path(child, &path[1..]);
    }
}

fn set_path(value: &mut Value, path: &[Segment], new: Value) {
    let Some((first, rest)) = path.split_first() else {
        *value = new;
        return;
    };
    if rest.is_empty() {
        match (first, value) {
            (Segment::Key(key), Value::Object(map)) => {
                map.insert(key.clone(), new);
            }
            (Segment::Index(index), Value::Array(items)) if *index < items.len() => {
                items[*index] = new;
            }
            (Segment::Each, Value::Array(items)) => {
                for item in items {
                    *item = new.clone();
                }
            }
            _ => {}
        }
        return;
    }
    for child in children(value, first) {
        set_path(child, rest, new.clone());
    }
}

fn children<'a>(value: &'a mut Value, segment: &Segment) -> Vec<&'a mut Value> {
    match (segment, value) {
        (Segment::Key(key), Value::Object(map)) => map.get_mut(key).into_iter().collect(),
        (Segment::Index(index), Value::Array(items)) => items.get_mut(*index).into_iter().collect(),
        (Segment::Each, Value::Array(items)) => items.iter_mut().collect(),
        (Segment::Each, Value::Object(map)) => map.values_mut().collect(),
        _ => vec![],
    }
}

const RECENT: usize = 100;
const TRACKED: usize = 500;

#[derive(Clone, Debug, Serialize)]
struct Hit {
    time: u64,
    url: String,
    action: String,
    module: String,
}

/// Counters since the core started.
#[derive(Default)]
pub struct Stats {
    total: AtomicU64,
    modules: Mutex<HashMap<String, u64>>,
    recent: Mutex<VecDeque<Hit>>,
}
impl Stats {
    pub(crate) fn record(&self, rule: &Compiled, url: &str) {
        self.total.fetch_add(1, Ordering::Relaxed);
        {
            let mut modules = self.modules.lock().unwrap();
            if let Some(count) = modules.get_mut(&rule.module) {
                *count += 1;
            } else if modules.len() < TRACKED {
                modules.insert(rule.module.clone(), 1);
            }
        }
        let mut recent = self.recent.lock().unwrap();
        if recent.len() == RECENT {
            recent.pop_back();
        }
        recent.push_front(Hit {
            time: crate::requests::now_ms() / 1000,
            url: url.chars().take(300).collect(),
            action: rule.action.kind(),
            module: rule.module.clone(),
        });
    }
    pub(crate) fn snapshot(&self) -> Value {
        json!({
            "total": self.total.load(Ordering::Relaxed),
            "hits": *self.modules.lock().unwrap(),
            "recent": self.recent.lock().unwrap().iter().cloned().collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clyntis_config::rewrite::parse_module;

    fn rewriter(text: &str) -> Rewriter {
        Rewriter::new(
            vec![Loaded {
                name: "test".into(),
                module: parse_module(text),
                files: HashMap::new(),
                missing: vec![],
                updated: None,
            }],
            vec![],
        )
    }

    #[tokio::test]
    async fn matches_rules_in_order_and_answers() {
        let rewriter = rewriter(
            r#"[URL Rewrite]
^https?:\/\/a\.test\/ad - reject-dict
^https?:\/\/a\.test\/(?!keep)x - reject-img
^http:\/\/old\.test\/(.*) https://new.test/$1x 302
[Rule]
DOMAIN-SUFFIX,ads.test,REJECT
[Header Rewrite]
^https://a\.test/ header-replace-regex User-Agent (\w+)/1 $1/2
[Body Rewrite]
http-response ^https://a\.test/feed "ad":true "ad":false
http-response-jq ^https://a\.test/feed 'del(.list[].ad, .banner)'
"#,
        );
        assert_eq!(rewriter.rule_count(), 6);
        assert!(rewriter.modules[0].skipped.is_empty());
        assert!(rewriter.rejects("x.ads.test") && !rewriter.rejects("a.test"));
        let hits = rewriter.matching(Phase::Request, "https://a.test/ad?x=1");
        assert_eq!(hits.len(), 2);
        let first = rewriter.rule(hits[0]);
        let answer = answer(&rewriter, first, "https://a.test/ad?x=1").unwrap();
        assert_eq!((answer.status, answer.body.as_slice()), (200, &b"{}"[..]));
        assert!(
            rewriter
                .matching(Phase::Request, "https://a.test/keepx")
                .len()
                == 1
        );
        assert_eq!(
            rewriter.matching(Phase::Request, "https://a.test/x").len(),
            2
        );

        let redirect = rewriter.matching(Phase::Request, "http://old.test/p?q");
        let answer =
            super::answer(&rewriter, rewriter.rule(redirect[0]), "http://old.test/p?q").unwrap();
        assert_eq!(answer.status, 302);
        assert_eq!(
            find(&answer.headers, "location"),
            Some("https://new.test/p?qx")
        );
        assert!(String::from_utf8(answer.encode()).unwrap().starts_with(
            "HTTP/1.1 302 Found\r\nLocation: https://new.test/p?qx\r\nContent-Length: 0\r\n\r\n"
        ));

        let header = rewriter.matching(Phase::Request, "https://a.test/feed");
        let mut headers = vec![("user-agent".to_owned(), "App/1 (x)".to_owned())];
        apply_header(rewriter.rule(*header.last().unwrap()), &mut headers);
        assert_eq!(headers[0].1, "App/2 (x)");

        let body_rules = rewriter.matching(Phase::Response, "https://a.test/feed");
        assert_eq!(body_rules.len(), 2);
        let mut body =
            br#"{"list":[{"ad":true,"id":1}],"banner":{"x":1},"keep":"\"ad\":true"}"#.to_vec();
        for rule in &body_rules {
            let rule = rewriter.rule(*rule);
            match &rule.jq {
                Some(filter) => body = filter.apply(body).await.unwrap(),
                None => assert!(apply_body(rule, &mut body)),
            }
        }
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"list": [{"id": 1}], "keep": "\"ad\":true"})
        );
    }

    #[test]
    fn json_paths_and_replacements() {
        assert_eq!(replacement("$1-$12$$x$&"), "${1}-${12}$$x${0}");
        assert_eq!(
            segments("a.b[0][].c"),
            vec![
                Segment::Key("a".into()),
                Segment::Key("b".into()),
                Segment::Index(0),
                Segment::Each,
                Segment::Key("c".into())
            ]
        );
        let mut value = json!({"data": {"items": [{"ad": 1, "id": 1}, {"ad": 2}], "show": true}});
        set_path(&mut value, &segments("data.show"), json!(false));
        set_path(&mut value, &segments("data.items[].ad"), json!(0));
        delete_path(&mut value, &segments("data.items[1]"));
        assert_eq!(
            value,
            json!({"data": {"items": [{"ad": 0, "id": 1}], "show": false}})
        );
        let mut text = b"not json".to_vec();
        let rewriter = rewriter("[Rewrite]\n^https://a\\.test/ response-body-json-del a\n");
        assert!(!apply_body(rewriter.rule(0), &mut text));
    }
}
