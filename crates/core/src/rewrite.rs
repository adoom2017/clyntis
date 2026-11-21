//! Rewriting decrypted HTTP with modules (see `clyntis_config::rewrite`):
//! compiled rules, the actions that need no script, and counters.
use clyntis_config::{
    rewrite::{
        Action, Condition, DomainKind, HeaderOp, MatchOp, Mock, MockBody, Module, Phase, Reject,
        TINY_GIF,
    },
    rule::{DomainSet, DomainSetBuilder},
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{
        Arc, LazyLock, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
};

#[derive(Clone, Copy)]
struct PatternLimits {
    batch_limit: usize,
    set_limit: usize,
    cache_limit: usize,
    bucket_cache_limit: usize,
    rule_cache_limit: usize,
}

const DESKTOP_LIMITS: PatternLimits = PatternLimits {
    batch_limit: 256,
    set_limit: 2 << 20,
    cache_limit: 64 << 10,
    bucket_cache_limit: 256,
    rule_cache_limit: 256,
};

const HOSTED_LIMITS: PatternLimits = PatternLimits {
    batch_limit: 64,
    set_limit: 512 << 10,
    cache_limit: 16 << 10,
    bucket_cache_limit: 24,
    rule_cache_limit: 32,
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
    #[serde(rename = "updateError", skip_serializing_if = "Option::is_none")]
    pub update_error: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Skipped {
    pub line: usize,
    pub text: String,
}

/// A validated rule whose regex engines are compiled lazily on first match.
pub(crate) struct Compiled {
    pub(crate) module: String,
    pub(crate) line: usize,
    pub(crate) phase: Phase,
    pattern_source: String,
    batchable: bool,
    conditions: Vec<Condition>,
    pub(crate) pipe_continuation: bool,
    pub(crate) action: Action,
}

impl Compiled {
    /// `kind (module)`, for the request log.
    pub(crate) fn label(&self) -> String {
        format!("{} ({})", self.action.kind(), self.module)
    }
}

enum UrlPattern {
    Regular(regex::Regex),
    Fancy(fancy_regex::Regex),
}
impl UrlPattern {
    fn is_match(&self, url: &str) -> bool {
        match self {
            Self::Regular(regex) => regex.is_match(url),
            Self::Fancy(regex) => regex.is_match(url).unwrap_or(false),
        }
    }
    fn replace<'a>(&self, url: &'a str, replacement: &str) -> std::borrow::Cow<'a, str> {
        match self {
            Self::Regular(regex) => regex.replace(url, replacement),
            Self::Fancy(regex) => regex.replace(url, replacement),
        }
    }
}

fn match_op(
    op: &MatchOp,
    compiled_regex: Option<&fancy_regex::Regex>,
    value: Option<&str>,
) -> bool {
    match op {
        MatchOp::Equals(expected) => value.is_some_and(|v| v == expected),
        MatchOp::NotEquals(expected) => value != Some(expected.as_str()),
        MatchOp::Regex(_) => compiled_regex
            .is_some_and(|regex| value.is_some_and(|v| regex.is_match(v).unwrap_or(false))),
    }
}

/// The compiled modules of a snapshot.
pub struct Rewriter {
    compiled: Arc<CompiledRules>,
    pub(crate) hostnames: Vec<String>,
    pub modules: Vec<ModuleInfo>,
    /// Downloaded scripts and response bodies, pinned to this snapshot.
    files: HashMap<String, Arc<RewriteFile>>,
}

struct CompiledRules {
    rules: Vec<Compiled>,
    limits: PatternLimits,
    /// Conservative host-suffix buckets (`>= 2` DNS labels); compiled lazily on demand.
    host_buckets: HashMap<String, Vec<usize>>,
    /// Rules that cannot be tied to a required host suffix; checked for every URL.
    global_rules: Vec<usize>,
    reject: Vec<(String, DomainSet)>,
    cache: Mutex<MatcherCache>,
}

#[derive(Default)]
struct MatcherCache {
    global: Option<Arc<CompiledBucket>>,
    hosts: HashMap<String, Arc<CompiledBucket>>,
    rule_extras: HashMap<usize, Arc<RuleRuntime>>,
}

struct CompiledBucket {
    request: PhaseMatchers,
    response: PhaseMatchers,
}

impl CompiledBucket {
    fn phase(&self, phase: Phase) -> &PhaseMatchers {
        match phase {
            Phase::Request => &self.request,
            Phase::Response => &self.response,
        }
    }
}

#[derive(Default)]
struct PhaseMatchers {
    sets: Vec<PatternSet>,
    fancy: Vec<(usize, UrlPattern)>,
}

#[derive(Default)]
struct RuleRuntime {
    pattern: Option<UrlPattern>,
    condition_regexes: Vec<fancy_regex::Regex>,
    extra: Vec<fancy_regex::Regex>,
    jq: Option<crate::jq::Filter>,
}

/// Pinned runtimes for every stage in a rule group that requires a [`RuleRuntime`].
pub(crate) struct CachedGroup(Vec<(usize, Arc<RuleRuntime>)>);

impl CachedGroup {
    fn get(&self, index: usize) -> Option<&RuleRuntime> {
        self.0
            .iter()
            .find(|(i, _)| *i == index)
            .map(|(_, runtime)| runtime.as_ref())
    }
}

const STALE_TMP_AGE: std::time::Duration = std::time::Duration::from_secs(600);

static SNAPSHOT_LOCKS: LazyLock<Mutex<HashMap<PathBuf, Weak<std::fs::File>>>> =
    LazyLock::new(Default::default);

fn snapshot_lock(snapshot_dir: &Path) -> std::io::Result<Arc<std::fs::File>> {
    let lock_dir = snapshot_dir.parent().unwrap_or(snapshot_dir);
    let lock_path = lock_dir.join(".snapshots.lock");
    let mut locks = SNAPSHOT_LOCKS.lock().unwrap();
    locks.retain(|_, weak| weak.strong_count() > 0);
    if let Some(lock) = locks.get(&lock_path).and_then(Weak::upgrade) {
        return Ok(lock);
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    file.lock_shared()?;
    let lock = Arc::new(file);
    locks.insert(lock_path, Arc::downgrade(&lock));
    Ok(lock)
}

fn is_uuid_artifact(path: &Path, extension: &str) -> bool {
    path.extension().and_then(|ext| ext.to_str()) == Some(extension)
        && path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| stem.rsplit('.').next())
            .is_some_and(|suffix| uuid::Uuid::parse_str(suffix).is_ok())
}

/// Removes aged `.tmp` files and orphaned `.snapshot` files left in `directory`
/// by prior abnormal exits, without disturbing active downloads or live
/// snapshots held by any running instance in this or another process.
pub(crate) fn clean_stale_files(directory: &Path) {
    let snapshot_dir = directory.join("rewrite/files");
    let snapshot_guard = if snapshot_dir.is_dir() {
        let lock_path = snapshot_dir
            .parent()
            .unwrap_or(&snapshot_dir)
            .join(".snapshots.lock");
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .ok()
            .and_then(|file| file.try_lock().ok().map(|()| file))
    } else {
        None
    };

    let mut dirs = vec![directory.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if file_type.is_dir() {
                dirs.push(path);
            } else if file_type.is_file() {
                let stale_tmp = is_uuid_artifact(&path, "tmp")
                    && entry
                        .metadata()
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age >= STALE_TMP_AGE);
                let stale_snapshot = snapshot_guard.is_some()
                    && dir == snapshot_dir
                    && is_uuid_artifact(&path, "snapshot");
                if stale_tmp || stale_snapshot {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }
}

/// A hard link keeps the snapshot's bytes alive when the URL cache is replaced.
pub(crate) struct RewriteFile {
    path: PathBuf,
    _lock: Arc<std::fs::File>,
}
impl RewriteFile {
    pub(crate) fn pin(cache: &Path) -> std::io::Result<Arc<Self>> {
        let lock = snapshot_lock(cache.parent().unwrap_or_else(|| Path::new(".")))?;
        let path = cache.with_extension(format!("{}.snapshot", uuid::Uuid::new_v4()));
        std::fs::hard_link(cache, &path)?;
        Ok(Arc::new(Self { path, _lock: lock }))
    }
}
impl Drop for RewriteFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

struct PatternSet {
    set: regex::RegexSet,
    indices: Vec<usize>,
}

fn compile_fancy(
    source: &str,
    limits: PatternLimits,
) -> std::result::Result<fancy_regex::Regex, fancy_regex::Error> {
    fancy_regex::RegexBuilder::new(source)
        .delegate_dfa_size_limit(limits.cache_limit)
        .build()
}

fn compile_single_pattern(source: &str, limits: PatternLimits) -> Option<UrlPattern> {
    if let Ok(regex) = regex::RegexBuilder::new(source)
        .dfa_size_limit(limits.cache_limit)
        .build()
    {
        return Some(UrlPattern::Regular(regex));
    }
    compile_fancy(source, limits).ok().map(UrlPattern::Fancy)
}

/// Flush while compiling, so a large module never holds every individual
/// regex alongside its combined sets. A failed batch retains its matchers.
fn flush_patterns(
    rules: &[Compiled],
    indices: &mut Vec<usize>,
    sets: &mut Vec<PatternSet>,
    fancy: &mut Vec<(usize, UrlPattern)>,
    limits: PatternLimits,
) {
    if indices.is_empty() {
        return;
    }
    let patterns = indices.iter().map(|&i| rules[i].pattern_source.as_str());
    match regex::RegexSetBuilder::new(patterns)
        .size_limit(limits.set_limit)
        .dfa_size_limit(limits.cache_limit)
        .build()
    {
        Ok(set) => {
            sets.push(PatternSet {
                set,
                indices: std::mem::take(indices),
            });
        }
        Err(_) if indices.len() > 1 => {
            // One expensive pattern must not make all the others keep their
            // individual regexes. Split until the remaining batches fit.
            let mut rest = indices.split_off(indices.len() / 2);
            flush_patterns(rules, indices, sets, fancy, limits);
            flush_patterns(rules, &mut rest, sets, fancy, limits);
        }
        Err(_) => {
            let i = indices[0];
            if let Some(pattern) = compile_single_pattern(&rules[i].pattern_source, limits) {
                fancy.push((i, pattern));
            }
            indices.clear();
        }
    }
}

fn compile_phase(
    rules: &[Compiled],
    indices: &[usize],
    phase: Phase,
    limits: PatternLimits,
) -> PhaseMatchers {
    let mut sets = Vec::new();
    let mut fancy = Vec::new();
    let mut batch = Vec::new();
    for &index in indices {
        let rule = &rules[index];
        if rule.phase != phase {
            continue;
        }
        if rule.batchable {
            batch.push(index);
            if batch.len() == limits.batch_limit {
                flush_patterns(rules, &mut batch, &mut sets, &mut fancy, limits);
            }
        } else if let Some(pattern) = compile_single_pattern(&rule.pattern_source, limits) {
            fancy.push((index, pattern));
        }
    }
    flush_patterns(rules, &mut batch, &mut sets, &mut fancy, limits);
    PhaseMatchers { sets, fancy }
}

fn compile_bucket(rules: &[Compiled], indices: &[usize], limits: PatternLimits) -> CompiledBucket {
    CompiledBucket {
        request: compile_phase(rules, indices, Phase::Request, limits),
        response: compile_phase(rules, indices, Phase::Response, limits),
    }
}

fn compile_rule_runtime(rule: &Compiled, limits: PatternLimits) -> RuleRuntime {
    let pattern = matches!(rule.action, Action::Redirect { .. } | Action::UrlReplace(_))
        .then(|| compile_single_pattern(&rule.pattern_source, limits))
        .flatten();
    let condition_regexes = rule
        .conditions
        .iter()
        .filter_map(|cond| match cond {
            Condition::RequestHeader {
                op: MatchOp::Regex(source),
                ..
            }
            | Condition::ResponseHeader {
                op: MatchOp::Regex(source),
                ..
            } => compile_fancy(source, limits).ok(),
            _ => None,
        })
        .collect();
    let extra = match &rule.action {
        Action::BodyReplace(pairs) => pairs
            .iter()
            .filter_map(|(source, _)| compile_fancy(source, limits).ok())
            .collect(),
        Action::Header(HeaderOp::ReplaceRegex(_, source, _)) => {
            compile_fancy(source, limits).ok().into_iter().collect()
        }
        _ => Vec::new(),
    };
    let jq = match &rule.action {
        Action::Jq(code) => crate::jq::Filter::compile(code).ok(),
        _ => None,
    };
    RuleRuntime {
        pattern,
        condition_regexes,
        extra,
        jq,
    }
}

/// Extracts `host` (lowercased, without port or trailing dot) from an HTTP(S) URL.
fn extract_url_host(url: &str) -> Option<String> {
    let rest = if url
        .get(..8)
        .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
    {
        &url[8..]
    } else if url
        .get(..7)
        .is_some_and(|s| s.eq_ignore_ascii_case("http://"))
    {
        &url[7..]
    } else {
        return None;
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(bracketed) = host_port.strip_prefix('[') {
        bracketed.split(']').next()?
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    let host = host.trim_end_matches('.');
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn has_top_level_alternation(pattern: &str) -> bool {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ClassState {
        None,
        FirstAfterOpen,
        FirstAfterCaret,
        Body,
    }
    let mut chars = pattern.chars();
    let mut depth = 0usize;
    let mut class = ClassState::None;
    while let Some(c) = chars.next() {
        if class != ClassState::None {
            if c == '\\' {
                let _ = chars.next();
                class = ClassState::Body;
            } else if class == ClassState::FirstAfterOpen && c == '^' {
                class = ClassState::FirstAfterCaret;
            } else if c == ']'
                && !matches!(
                    class,
                    ClassState::FirstAfterOpen | ClassState::FirstAfterCaret
                )
            {
                class = ClassState::None;
            } else {
                class = ClassState::Body;
            }
            continue;
        }
        match c {
            '\\' => {
                let _ = chars.next();
            }
            '[' => class = ClassState::FirstAfterOpen,
            '(' => depth += 1,
            ')' => {
                let Some(next) = depth.checked_sub(1) else {
                    return true;
                };
                depth = next;
            }
            '|' if depth == 0 => return true,
            _ => {}
        }
    }
    depth != 0 || class != ClassState::None
}

fn is_optional_quantifier(rest: &str) -> bool {
    if rest.starts_with('?') || rest.starts_with('*') {
        return true;
    }
    if let Some(after) = rest.strip_prefix('{') {
        let trimmed = after.trim_start();
        if trimmed.starts_with(',') {
            return true;
        }
        let digits: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() && digits.chars().all(|c| c == '0') {
            return true;
        }
    }
    false
}

fn skip_quantifier(rest: &str) -> Option<usize> {
    let bytes = rest.as_bytes();
    let base = match *bytes.first()? {
        b'?' | b'*' | b'+' => 1,
        b'{' => {
            let rel_close = rest[1..].find('}')?;
            let inner = &rest[1..1 + rel_close];
            if inner.is_empty()
                || !inner
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b == b',' || b == b' ')
            {
                return None;
            }
            1 + rel_close + 1
        }
        _ => return None,
    };
    let modifier = usize::from(matches!(bytes.get(base), Some(b'?' | b'+')));
    Some(base + modifier)
}

/// Finds the matching `]` for a class beginning with `[` at `s[0]`, returning the
/// index right after `]`.
fn scan_char_class(s: &str) -> Option<usize> {
    let mut i = 1;
    let bytes = s.as_bytes();
    if bytes.get(i) == Some(&b'^') {
        i += 1;
    }
    let mut first = true;
    while i < bytes.len() {
        let ch = s[i..].chars().next()?;
        if ch == '\\' {
            i += 1;
            let esc = s[i..].chars().next()?;
            i += esc.len_utf8();
            first = false;
            continue;
        }
        if ch == '[' && s[i..].starts_with("[:") {
            let rel_end = s[i + 2..].find(":]")?;
            i += 2 + rel_end + 2;
            first = false;
            continue;
        }
        if ch == ']' && !first {
            return Some(i + 1);
        }
        i += ch.len_utf8();
        first = false;
    }
    None
}

fn is_delim_class(body: &str) -> bool {
    if body.is_empty() || body.starts_with('^') {
        return false;
    }
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        let item = if c == '\\' {
            let Some(esc) = chars.next() else {
                return false;
            };
            esc
        } else {
            c
        };
        if !matches!(item, '/' | ':' | '?') {
            return false;
        }
    }
    true
}

fn find_host_expr(rest: &str) -> Option<&str> {
    if is_optional_quantifier(rest) || rest.starts_with('+') {
        return None;
    }
    let mut i = 0usize;
    let mut depth = 0usize;
    while i < rest.len() {
        let ch = rest[i..].chars().next()?;
        match ch {
            '\\' => {
                let esc = rest[i + 1..].chars().next()?;
                let after = i + 1 + esc.len_utf8();
                if depth == 0 && matches!(esc, '/' | ':' | '?') {
                    return (!is_optional_quantifier(&rest[after..])).then_some(&rest[..i]);
                }
                i = after;
            }
            '(' => {
                depth += 1;
                i += 1;
            }
            ')' => {
                depth = depth.checked_sub(1)?;
                i += 1;
            }
            '[' => {
                let after = i + scan_char_class(&rest[i..])?;
                let body = &rest[i + 1..after - 1];
                if depth == 0 && is_delim_class(body) {
                    return (!is_optional_quantifier(&rest[after..])).then_some(&rest[..i]);
                }
                i = after;
            }
            '/' | ':' | '$' if depth == 0 => {
                let after = i + 1;
                return (!is_optional_quantifier(&rest[after..])).then_some(&rest[..i]);
            }
            '|' if depth == 0 => return None,
            _ => i += ch.len_utf8(),
        }
    }
    None
}

/// Ensures every character `expr` can consume stays inside the URL authority
/// (cannot match `/`, `?`, `#`, `@`, `:`, or line breaks).
fn stays_in_authority(expr: &str) -> bool {
    let mut i = 0usize;
    while i < expr.len() {
        let ch = expr[i..].chars().next().unwrap();
        match ch {
            '\\' => {
                let Some(esc) = expr[i + 1..].chars().next() else {
                    return false;
                };
                if !matches!(
                    esc,
                    'w' | 'd' | '.' | '-' | '_' | '(' | ')' | '[' | ']' | '\\'
                ) {
                    return false;
                }
                i += 1 + esc.len_utf8();
            }
            '[' => {
                let Some(len) = scan_char_class(&expr[i..]) else {
                    return false;
                };
                let body = &expr[i + 1..i + len - 1];
                if !char_class_stays_in_authority(body) {
                    return false;
                }
                i += len;
            }
            '(' => {
                if expr[i..].starts_with("(?") && !expr[i..].starts_with("(?:") {
                    return false;
                }
                i += if expr[i..].starts_with("(?:") { 3 } else { 1 };
            }
            '{' => {
                let Some(len) = skip_quantifier(&expr[i..]) else {
                    return false;
                };
                i += len;
            }
            ')' | '|' | '*' | '+' | '?' | '_' | '-' => i += 1,
            c if c.is_ascii_alphanumeric() => i += 1,
            _ => return false,
        }
    }
    true
}

fn char_class_stays_in_authority(body: &str) -> bool {
    if body.is_empty() || body.starts_with('^') {
        return false;
    }
    let mut items = Vec::new();
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let Some(esc) = chars.next() else {
                    return false;
                };
                match esc {
                    'w' | 'd' => items.push(None),
                    '.' | '-' | '_' => items.push(Some(esc)),
                    _ => return false,
                }
            }
            '-' => {
                let Some(Some(lo)) = items.last().copied() else {
                    items.push(Some('-'));
                    continue;
                };
                let Some(next) = chars.next() else {
                    items.push(Some('-'));
                    continue;
                };
                let hi = if next == '\\' {
                    let Some(esc) = chars.next() else {
                        return false;
                    };
                    if !matches!(esc, '.' | '-' | '_') {
                        return false;
                    }
                    esc
                } else {
                    next
                };
                let valid_range = lo <= hi
                    && ((lo.is_ascii_lowercase() && hi.is_ascii_lowercase())
                        || (lo.is_ascii_uppercase() && hi.is_ascii_uppercase())
                        || (lo.is_ascii_digit() && hi.is_ascii_digit()));
                if !valid_range {
                    return false;
                }
                items.pop();
                items.push(None);
            }
            c if c.is_ascii_alphanumeric() || matches!(c, '_' | '.') => items.push(Some(c)),
            _ => return false,
        }
    }
    true
}

#[derive(Clone, Copy)]
enum LiteralAtom {
    Char(char),
    Dot,
}

fn trailing_literals(host_expr: &str) -> Option<(usize, Vec<LiteralAtom>)> {
    let mut i = 0usize;
    let mut depth = 0usize;
    let mut lit_start = 0usize;
    let mut literals = Vec::new();
    while i < host_expr.len() {
        let ch = host_expr[i..].chars().next()?;
        match ch {
            '\\' => {
                let esc = host_expr[i + 1..].chars().next()?;
                let end = i + 1 + esc.len_utf8();
                if let Some(q) = skip_quantifier(&host_expr[end..]) {
                    i = end + q;
                    lit_start = i;
                    literals.clear();
                    continue;
                }
                if depth == 0 && (esc == '.' || esc == '-') {
                    if literals.is_empty() {
                        lit_start = i;
                    }
                    literals.push(if esc == '.' {
                        LiteralAtom::Dot
                    } else {
                        LiteralAtom::Char('-')
                    });
                } else {
                    lit_start = end;
                    literals.clear();
                }
                i = end;
            }
            '(' => {
                depth += 1;
                i += 1;
                lit_start = i;
                literals.clear();
            }
            ')' => {
                depth = depth.checked_sub(1)?;
                i += 1;
                if let Some(q) = skip_quantifier(&host_expr[i..]) {
                    i += q;
                }
                lit_start = i;
                literals.clear();
            }
            '[' => {
                let len = scan_char_class(&host_expr[i..])?;
                i += len;
                if let Some(q) = skip_quantifier(&host_expr[i..]) {
                    i += q;
                }
                lit_start = i;
                literals.clear();
            }
            c if depth == 0 && (c.is_ascii_alphanumeric() || c == '-') => {
                let end = i + c.len_utf8();
                if let Some(q) = skip_quantifier(&host_expr[end..]) {
                    i = end + q;
                    lit_start = i;
                    literals.clear();
                    continue;
                }
                if literals.is_empty() {
                    lit_start = i;
                }
                literals.push(LiteralAtom::Char(c.to_ascii_lowercase()));
                i = end;
            }
            _ => {
                let end = i + ch.len_utf8();
                if let Some(q) = skip_quantifier(&host_expr[end..]) {
                    i = end + q;
                } else {
                    i = end;
                }
                lit_start = i;
                literals.clear();
            }
        }
    }
    (depth == 0 && !literals.is_empty()).then_some((lit_start, literals))
}

fn ends_with_literal_dot(s: &str) -> bool {
    trailing_literals(s).is_some_and(|(_, atoms)| matches!(atoms.last(), Some(LiteralAtom::Dot)))
}

fn split_top_level_branches(s: &str) -> Option<Vec<&str>> {
    let mut branches = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut depth = 0usize;
    while i < s.len() {
        let ch = s[i..].chars().next()?;
        match ch {
            '\\' => {
                let esc = s[i + 1..].chars().next()?;
                i += 1 + esc.len_utf8();
            }
            '[' => i += scan_char_class(&s[i..])?,
            '(' => {
                depth += 1;
                i += 1;
            }
            ')' => {
                depth = depth.checked_sub(1)?;
                i += 1;
            }
            '|' if depth == 0 => {
                branches.push(&s[start..i]);
                i += 1;
                start = i;
            }
            _ => i += ch.len_utf8(),
        }
    }
    if depth != 0 {
        return None;
    }
    branches.push(&s[start..]);
    Some(branches)
}

fn ends_with_dot_terminated_group(prefix: &str) -> bool {
    let mut base = prefix;
    // Strip one trailing quantifier (e.g. `?`, `*`, `+`, `{1,2}`, `*?`).
    if base.ends_with("??") || base.ends_with("*?") || base.ends_with("+?") {
        base = &base[..base.len() - 2];
    } else if matches!(base.as_bytes().last(), Some(b'?' | b'*' | b'+')) {
        base = &base[..base.len() - 1];
    } else if base.ends_with('}')
        && let Some(open_brace) = base.rfind('{')
        && skip_quantifier(&base[open_brace..]).is_some_and(|len| open_brace + len == base.len())
    {
        base = &base[..open_brace];
    }
    if !base.ends_with(')') {
        return false;
    }
    let mut stack = Vec::new();
    let mut open_idx = None;
    let mut i = 0usize;
    while i < base.len() {
        let Some(ch) = base[i..].chars().next() else {
            return false;
        };
        match ch {
            '\\' => {
                let Some(esc) = base[i + 1..].chars().next() else {
                    return false;
                };
                i += 1 + esc.len_utf8();
            }
            '[' => {
                let Some(len) = scan_char_class(&base[i..]) else {
                    return false;
                };
                i += len;
            }
            '(' => {
                stack.push(i);
                i += 1;
            }
            ')' => {
                let Some(start) = stack.pop() else {
                    return false;
                };
                if i + 1 == base.len() {
                    open_idx = Some(start);
                    break;
                }
                i += 1;
            }
            _ => i += ch.len_utf8(),
        }
    }
    let Some(open_idx) = open_idx else {
        return false;
    };
    if open_idx > 0 && !ends_with_literal_dot(&base[..open_idx]) {
        return false;
    }
    let mut inner = &base[open_idx + 1..base.len() - 1];
    if let Some(rest) = inner.strip_prefix("?:") {
        inner = rest;
    } else if inner.starts_with('?') {
        return false;
    }
    let Some(branches) = split_top_level_branches(inner) else {
        return false;
    };
    !branches.is_empty() && branches.into_iter().all(ends_with_literal_dot)
}

fn is_valid_dns_suffix(suffix: &str) -> bool {
    let mut count = 0usize;
    for label in suffix.split('.') {
        count += 1;
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return false;
        }
    }
    count >= 2
}

/// Conservatively extracts a required host suffix (`>= 2` DNS labels) from a URL
/// rewrite pattern so matching only touches rules that could match the request host.
/// Returns `None` unless every match is guaranteed to end with that host suffix.
fn extract_required_host_suffix(pattern: &str) -> Option<String> {
    if has_top_level_alternation(pattern) {
        return None;
    }
    let mut rest = pattern;
    while let Some(after_open) = rest.strip_prefix("(?") {
        if matches!(
            after_open.as_bytes().first(),
            Some(b':' | b'=' | b'!' | b'<')
        ) {
            break;
        }
        let close = after_open.find(')')?;
        let flags = &after_open[..close];
        if flags.is_empty()
            || !flags
                .bytes()
                .all(|b| matches!(b, b'i' | b's' | b'u' | b'U' | b'-'))
        {
            return None;
        }
        rest = &after_open[close + 1..];
    }
    let rest = rest.strip_prefix('^')?;
    if !rest
        .get(..4)
        .is_some_and(|s| s.eq_ignore_ascii_case("http"))
    {
        return None;
    }
    let mut rest = &rest[4..];
    for prefix in ["(?:s)?", "(?:S)?", "(s)?", "(S)?", "s?", "S?", "s", "S"] {
        if let Some(next) = rest.strip_prefix(prefix) {
            rest = next;
            break;
        }
    }
    rest = rest
        .strip_prefix("\\:")
        .or_else(|| rest.strip_prefix(':'))?;
    rest = rest
        .strip_prefix("\\/\\/")
        .or_else(|| rest.strip_prefix("//"))?;
    let host_expr = find_host_expr(rest)?;
    let (lit_start, atoms) = trailing_literals(host_expr)?;
    let prefix = &host_expr[..lit_start];
    if !stays_in_authority(prefix) {
        return None;
    }
    let suffix: String = atoms
        .iter()
        .map(|atom| match atom {
            LiteralAtom::Char(c) => *c,
            LiteralAtom::Dot => '.',
        })
        .collect();
    let candidate = if prefix.is_empty() {
        suffix.as_str()
    } else if matches!(atoms.first(), Some(LiteralAtom::Dot)) {
        &suffix[1..]
    } else if ends_with_dot_terminated_group(prefix) {
        suffix.as_str()
    } else {
        let dot = suffix.find('.')?;
        &suffix[dot + 1..]
    };
    is_valid_dns_suffix(candidate).then(|| candidate.to_owned())
}

/// A module's rules, its name, and where its downloads went.
pub(crate) struct Loaded {
    pub(crate) name: String,
    pub(crate) module: Module,
    pub(crate) files: HashMap<String, Arc<RewriteFile>>,
    pub(crate) missing: Vec<String>,
    pub(crate) updated: Option<u64>,
}

impl Rewriter {
    /// Compiles the modules in order; `failed` are modules that could not be
    /// loaded at all (name, error).
    #[cfg(test)]
    pub(crate) fn new(loaded: Vec<Loaded>, failed: Vec<(String, Option<u64>, String)>) -> Self {
        Self::new_hosted(loaded, failed, false)
    }

    pub(crate) fn new_hosted(
        loaded: Vec<Loaded>,
        failed: Vec<(String, Option<u64>, String)>,
        hosted: bool,
    ) -> Self {
        let limits = if hosted {
            HOSTED_LIMITS
        } else {
            DESKTOP_LIMITS
        };
        let mut rules = Vec::new();
        let mut host_buckets: HashMap<String, Vec<usize>> = HashMap::new();
        let mut global_rules = Vec::new();
        let mut hostnames = Vec::new();
        let mut reject = Vec::new();
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
            let mut failed_line: Option<usize> = None;
            for rule in module.rules {
                let line = rule.line;
                let is_continuation = rule.pipe_continuation;
                if is_continuation && failed_line == Some(line) {
                    continue;
                }
                if !is_continuation {
                    failed_line = None;
                }
                if !rule_has_file(&rule, |url| loaded.files.contains_key(url)) {
                    if !is_continuation {
                        failed_line = Some(line);
                    }
                    continue;
                }
                match validate_rule(&loaded.name, rule, limits) {
                    Ok(compiled) => {
                        if matches!(compiled.action, Action::Script(_)) {
                            scripts += 1;
                        }
                        count += 1;
                        let index = rules.len();
                        match extract_required_host_suffix(&compiled.pattern_source) {
                            Some(suffix) => host_buckets.entry(suffix).or_default().push(index),
                            None => global_rules.push(index),
                        }
                        rules.push(compiled);
                    }
                    Err((line, text)) => {
                        if !is_continuation {
                            failed_line = Some(line);
                        }
                        skipped.push(Skipped { line, text });
                    }
                }
            }
            if !module.reject.is_empty() {
                let mut module_reject = DomainSetBuilder::default();
                for (kind, value) in &module.reject {
                    match kind {
                        DomainKind::Exact => module_reject.exact(value),
                        DomainKind::Suffix => module_reject.suffix(value),
                        DomainKind::Keyword => module_reject.keyword(value),
                    }
                }
                reject.push((loaded.name.clone(), module_reject.build()));
            }
            hostnames.extend(
                module
                    .hostnames
                    .iter()
                    .filter(|h| count > 0 || h.starts_with('-'))
                    .cloned(),
            );
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
                update_error: None,
            });
        }
        modules.extend(failed.into_iter().map(failed_module));
        Self {
            compiled: Arc::new(CompiledRules {
                rules,
                limits,
                host_buckets,
                global_rules,
                reject,
                cache: Mutex::default(),
            }),
            hostnames,
            modules,
            files,
        }
    }

    /// Sources and file availability are unchanged. Update download status and
    /// file versions without compiling a second copy of the active matchers.
    pub(crate) fn reloaded(
        &self,
        loaded: Vec<Loaded>,
        failed: Vec<(String, Option<u64>, String)>,
    ) -> Self {
        let mut modules: Vec<_> = self
            .modules
            .iter()
            .filter(|module| module.error.is_none())
            .cloned()
            .collect();
        let mut files = HashMap::new();
        for (info, loaded) in modules.iter_mut().zip(loaded) {
            info.updated = loaded.updated;
            info.missing = loaded.missing;
            files.extend(loaded.files);
        }
        modules.extend(failed.into_iter().map(failed_module));
        Self {
            compiled: self.compiled.clone(),
            hostnames: self.hostnames.clone(),
            modules,
            files,
        }
    }

    #[cfg(test)]
    pub(crate) fn shares_rules(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.compiled, &other.compiled)
    }

    #[cfg(test)]
    pub(crate) fn cached_bucket_count(&self) -> usize {
        let cache = self.compiled.cache.lock().unwrap();
        usize::from(cache.global.is_some()) + cache.hosts.len()
    }

    #[cfg(test)]
    pub(crate) fn cached_rule_runtime_count(&self) -> usize {
        self.compiled.cache.lock().unwrap().rule_extras.len()
    }

    fn global_bucket(&self, allow_compile: bool) -> Option<Arc<CompiledBucket>> {
        if self.compiled.global_rules.is_empty() {
            return None;
        }
        if let Some(bucket) = &self.compiled.cache.lock().unwrap().global {
            return Some(bucket.clone());
        }
        if !allow_compile {
            return None;
        }
        let built = Arc::new(compile_bucket(
            &self.compiled.rules,
            &self.compiled.global_rules,
            self.compiled.limits,
        ));
        let mut cache = self.compiled.cache.lock().unwrap();
        Some(cache.global.get_or_insert(built).clone())
    }

    fn host_bucket(&self, suffix: &str, allow_compile: bool) -> Option<Arc<CompiledBucket>> {
        let indices = self.compiled.host_buckets.get(suffix)?;
        if let Some(bucket) = self.compiled.cache.lock().unwrap().hosts.get(suffix) {
            return Some(bucket.clone());
        }
        if !allow_compile {
            return None;
        }
        let built = Arc::new(compile_bucket(
            &self.compiled.rules,
            indices,
            self.compiled.limits,
        ));
        let mut cache = self.compiled.cache.lock().unwrap();
        if let Some(existing) = cache.hosts.get(suffix) {
            return Some(existing.clone());
        }
        if cache.hosts.len() >= self.compiled.limits.bucket_cache_limit {
            cache.hosts.clear();
        }
        cache.hosts.insert(suffix.to_owned(), built.clone());
        Some(built)
    }

    fn rule_runtime(&self, index: usize, allow_compile: bool) -> Option<Arc<RuleRuntime>> {
        if let Some(runtime) = self.compiled.cache.lock().unwrap().rule_extras.get(&index) {
            return Some(runtime.clone());
        }
        if !allow_compile {
            return None;
        }
        let built = Arc::new(compile_rule_runtime(
            &self.compiled.rules[index],
            self.compiled.limits,
        ));
        let mut cache = self.compiled.cache.lock().unwrap();
        if let Some(existing) = cache.rule_extras.get(&index) {
            return Some(existing.clone());
        }
        if cache.rule_extras.len() >= self.compiled.limits.rule_cache_limit {
            cache.rule_extras.clear();
        }
        cache.rule_extras.insert(index, built.clone());
        Some(built)
    }

    fn action_needs_runtime(&self, index: usize) -> bool {
        matches!(
            self.rule(index).action,
            Action::Redirect { .. }
                | Action::UrlReplace(_)
                | Action::Header(HeaderOp::ReplaceRegex(_, _, _))
                | Action::BodyReplace(_)
                | Action::Jq(_)
        )
    }

    /// Returns pinned runtimes for every stage in `group` that requires a
    /// [`RuleRuntime`], or `None` if any required stage is not cached.
    pub(crate) fn cached_group_runtimes(&self, group: &[usize]) -> Option<CachedGroup> {
        let mut pinned = Vec::new();
        let cache = self.compiled.cache.lock().unwrap();
        for &index in group {
            if !self.action_needs_runtime(index) {
                continue;
            }
            let runtime = cache.rule_extras.get(&index)?;
            pinned.push((index, runtime.clone()));
        }
        Some(CachedGroup(pinned))
    }

    /// Hold the runtimes before any stage mutates the message or awaits I/O.
    pub(crate) fn prepare_group_runtimes(
        &self,
        group: &[usize],
        allow_compile: bool,
    ) -> Option<CachedGroup> {
        if !allow_compile {
            return self.cached_group_runtimes(group);
        }
        let mut pinned = Vec::new();
        for &index in group {
            if self.action_needs_runtime(index) {
                pinned.push((index, self.rule_runtime(index, true)?));
            }
        }
        Some(CachedGroup(pinned))
    }

    fn with_runtime<R>(
        &self,
        index: usize,
        allow_compile: bool,
        pinned: Option<&CachedGroup>,
        f: impl FnOnce(&RuleRuntime) -> R,
    ) -> Option<R> {
        if let Some(runtime) = pinned.and_then(|group| group.get(index)) {
            return Some(f(runtime));
        }
        self.rule_runtime(index, allow_compile).as_deref().map(f)
    }

    /// Drops cached lazily-compiled regex sets, patterns, and jq filters under
    /// memory pressure. Rules remain validated and recompile on demand.
    pub(crate) fn relieve_memory(&self) {
        let mut cache = self.compiled.cache.lock().unwrap();
        cache.global = None;
        cache.hosts.clear();
        cache.hosts.shrink_to_fit();
        cache.rule_extras.clear();
        cache.rule_extras.shrink_to_fit();
    }

    /// The rules of `phase` that match `url`, in module order.
    #[cfg(test)]
    pub(crate) fn matching(&self, phase: Phase, url: &str) -> Vec<usize> {
        self.matching_with(phase, url, true)
    }

    /// The rules of `phase` that match `url`, skipping uncached buckets when
    /// `allow_compile` is `false`.
    pub(crate) fn matching_with(&self, phase: Phase, url: &str, allow_compile: bool) -> Vec<usize> {
        let mut found = Vec::new();
        let collect = |bucket: &CompiledBucket, out: &mut Vec<usize>| {
            let matchers = bucket.phase(phase);
            for batch in &matchers.sets {
                out.extend(batch.set.matches(url).into_iter().map(|i| batch.indices[i]));
            }
            for (index, pattern) in &matchers.fancy {
                if pattern.is_match(url) {
                    out.push(*index);
                }
            }
        };
        if let Some(global) = self.global_bucket(allow_compile) {
            collect(&global, &mut found);
        }
        if !self.compiled.host_buckets.is_empty()
            && let Some(host) = extract_url_host(url)
        {
            let mut cursor = host.as_str();
            while let Some(dot) = cursor.find('.') {
                if let Some(bucket) = self.host_bucket(cursor, allow_compile) {
                    collect(&bucket, &mut found);
                }
                cursor = &cursor[dot + 1..];
            }
        }
        found.sort_unstable();
        found
    }

    #[cfg(test)]
    pub(crate) fn matches_conditions(
        &self,
        index: usize,
        method: &str,
        request_headers: &[(String, String)],
        response_status: Option<u16>,
        response_headers: &[(String, String)],
    ) -> bool {
        self.matches_conditions_with(
            index,
            method,
            request_headers,
            response_status,
            response_headers,
            true,
        )
    }

    pub(crate) fn matches_conditions_with(
        &self,
        index: usize,
        method: &str,
        request_headers: &[(String, String)],
        response_status: Option<u16>,
        response_headers: &[(String, String)],
        allow_compile: bool,
    ) -> bool {
        let rule = self.rule(index);
        let has_regex = rule.conditions.iter().any(|cond| {
            matches!(
                cond,
                Condition::RequestHeader {
                    op: MatchOp::Regex(_),
                    ..
                } | Condition::ResponseHeader {
                    op: MatchOp::Regex(_),
                    ..
                }
            )
        });
        let runtime = if has_regex {
            let Some(runtime) = self.rule_runtime(index, allow_compile) else {
                return false;
            };
            Some(runtime)
        } else {
            None
        };
        let mut regex_idx = 0usize;
        rule.conditions.iter().all(|cond| match cond {
            Condition::Method { equals, value } => method.eq_ignore_ascii_case(value) == *equals,
            Condition::Status { equals, value } => {
                response_status.is_some_and(|s| (s == *value) == *equals)
            }
            Condition::RequestHeader { name, op } => {
                let regex = if matches!(op, MatchOp::Regex(_)) {
                    let r = runtime
                        .as_ref()
                        .and_then(|rt| rt.condition_regexes.get(regex_idx));
                    regex_idx += 1;
                    r
                } else {
                    None
                };
                match_op(op, regex, find(request_headers, name))
            }
            Condition::ResponseHeader { name, op } => {
                let regex = if matches!(op, MatchOp::Regex(_)) {
                    let r = runtime
                        .as_ref()
                        .and_then(|rt| rt.condition_regexes.get(regex_idx));
                    regex_idx += 1;
                    r
                } else {
                    None
                };
                match_op(op, regex, find(response_headers, name))
            }
        })
    }

    #[cfg(test)]
    pub(crate) fn jq(&self, index: usize) -> Option<crate::jq::Filter> {
        self.jq_with(index, true, None)
    }

    pub(crate) fn jq_with(
        &self,
        index: usize,
        allow_compile: bool,
        pinned: Option<&CachedGroup>,
    ) -> Option<crate::jq::Filter> {
        if !matches!(self.rule(index).action, Action::Jq(_)) {
            return None;
        }
        self.with_runtime(index, allow_compile, pinned, |runtime| runtime.jq.clone())?
    }

    pub(crate) fn rule(&self, index: usize) -> &Compiled {
        &self.compiled.rules[index]
    }
    pub(crate) fn file(&self, url: &str) -> Option<&PathBuf> {
        self.files.get(url).map(|file| &file.path)
    }
    /// Which module's domain rule rejects `host`, if any.
    pub fn rejecting_module(&self, host: &str) -> Option<&str> {
        if self.compiled.reject.is_empty() {
            return None;
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.compiled
            .reject
            .iter()
            .find(|(_, set)| !set.is_empty() && set.matches(&host))
            .map(|(module, _)| module.as_str())
    }
    /// Whether a module's domain rule rejects `host`.
    pub fn rejects(&self, host: &str) -> bool {
        self.rejecting_module(host).is_some()
    }
    /// Total domain-level reject rules across all loaded modules.
    pub fn reject_count(&self) -> usize {
        self.modules.iter().map(|m| m.reject).sum()
    }
    pub fn rule_count(&self) -> usize {
        self.compiled.rules.len()
    }
}

fn failed_module((name, updated, error): (String, Option<u64>, String)) -> ModuleInfo {
    ModuleInfo {
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
        update_error: None,
    }
}

fn validate_rule(
    module: &str,
    rule: clyntis_config::rewrite::Rule,
    limits: PatternLimits,
) -> Result<Compiled, (usize, String)> {
    let failed = |what: &str| (rule.line, format!("{what}: {}", rule.pattern));
    let batchable = if regex::RegexBuilder::new(&rule.pattern)
        .size_limit(limits.set_limit)
        .dfa_size_limit(limits.cache_limit)
        .build()
        .is_ok()
    {
        true
    } else if regex::RegexBuilder::new(&rule.pattern)
        .dfa_size_limit(limits.cache_limit)
        .build()
        .is_ok()
    {
        false
    } else {
        compile_fancy(&rule.pattern, limits).map_err(|_| failed("bad pattern"))?;
        false
    };
    for cond in &rule.conditions {
        let op = match cond {
            Condition::RequestHeader { op, .. } | Condition::ResponseHeader { op, .. } => op,
            _ => continue,
        };
        if let MatchOp::Regex(source) = op {
            compile_fancy(source, limits).map_err(|_| failed("bad condition regex"))?;
        }
    }
    match &rule.action {
        Action::BodyReplace(pairs) => {
            for (source, _) in pairs {
                compile_fancy(source, limits).map_err(|_| failed("bad body regex"))?;
            }
        }
        Action::Header(HeaderOp::ReplaceRegex(_, source, _)) => {
            compile_fancy(source, limits).map_err(|_| failed("bad header regex"))?;
        }
        Action::Jq(code) => {
            crate::jq::Filter::compile(code)
                .map_err(|error| (rule.line, format!("{error}: {code}")))?;
        }
        _ => {}
    }
    Ok(Compiled {
        module: module.to_owned(),
        line: rule.line,
        phase: rule.phase,
        pattern_source: rule.pattern,
        batchable,
        conditions: rule.conditions,
        pipe_continuation: rule.pipe_continuation,
        action: rule.action,
    })
}

fn rule_has_file(rule: &clyntis_config::rewrite::Rule, has_file: impl Fn(&str) -> bool) -> bool {
    match &rule.action {
        Action::Script(script) => has_file(&script.url),
        Action::Mock(Mock {
            body: MockBody::Remote(url),
            ..
        }) => has_file(url),
        _ => true,
    }
}

/// Counts how many rules in `module` compile cleanly (used before committing a
/// downloaded module update so an incompatible upgrade does not replace a
/// working cached module).
pub(crate) fn compilable_rule_count(module: &Module) -> usize {
    runnable_rule_count(module, |_| true)
}

/// Counts how many rules in `module` both compile cleanly and have their
/// dependent script/mock files available. If the leading stage of a piped line
/// fails to load, the entire pipe line is excluded.
pub(crate) fn runnable_rule_count(module: &Module, has_file: impl Fn(&str) -> bool) -> usize {
    let mut count = 0;
    let mut failed_line: Option<usize> = None;
    for rule in &module.rules {
        if rule.pipe_continuation && failed_line == Some(rule.line) {
            continue;
        }
        if !rule.pipe_continuation {
            failed_line = None;
        }
        if rule_has_file(rule, &has_file)
            && validate_rule("", (*rule).clone(), DESKTOP_LIMITS).is_ok()
        {
            count += 1;
        } else if !rule.pipe_continuation {
            failed_line = Some(rule.line);
        }
    }
    count
}

/// Applies a `url.replace` rule to `url`.
#[cfg(test)]
pub(crate) fn replace_url(rewriter: &Rewriter, index: usize, url: &str) -> Option<String> {
    replace_url_with(rewriter, index, url, true, None)
}

/// Applies a `url.replace` rule to `url`, returning `None` if uncached when
/// `allow_compile` is `false`.
pub(crate) fn replace_url_with(
    rewriter: &Rewriter,
    index: usize,
    url: &str,
    allow_compile: bool,
    pinned: Option<&CachedGroup>,
) -> Option<String> {
    let Action::UrlReplace(target) = &rewriter.rule(index).action else {
        return None;
    };
    rewriter.with_runtime(index, allow_compile, pinned, |runtime| {
        let pattern = runtime.pattern.as_ref()?;
        Some(
            pattern
                .replace(url, replacement(target).as_str())
                .into_owned(),
        )
    })?
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
    pub(crate) file: Option<PathBuf>,
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
            file: None,
        }
    }
    /// The response on the wire, with its length.
    pub(crate) fn encode_head(&self, length: u64) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {} {}\r\n", self.status, reason(self.status)).into_bytes();
        for (name, value) in &self.headers {
            if is_framing(name) {
                continue;
            }
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        if !(100..200).contains(&self.status) && !matches!(self.status, 204 | 304) {
            out.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out
    }
}

pub(crate) fn is_framing(name: &str) -> bool {
    name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("transfer-encoding")
}

pub(crate) fn reason(status: u16) -> &'static str {
    http::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("OK")
}

/// Outcome of evaluating a rule that answers a request directly.
#[derive(Clone, Debug)]
pub(crate) enum AnswerOutcome {
    Answer(Answer),
    Drop,
    Skip,
}

/// What a rule that answers the request does: `None` drops the connection.
#[cfg(test)]
pub(crate) fn answer(rewriter: &Rewriter, index: usize, url: &str) -> Option<Answer> {
    match answer_with(rewriter, index, url, true, None) {
        AnswerOutcome::Answer(answer) => Some(answer),
        AnswerOutcome::Drop | AnswerOutcome::Skip => None,
    }
}

/// What a rule that answers the request does, returning `Skip` when a redirect
/// pattern is not cached and `allow_compile` is `false`.
pub(crate) fn answer_with(
    rewriter: &Rewriter,
    index: usize,
    url: &str,
    allow_compile: bool,
    pinned: Option<&CachedGroup>,
) -> AnswerOutcome {
    let rule = rewriter.rule(index);
    match &rule.action {
        Action::Reject(reject) => AnswerOutcome::Answer(match reject {
            Reject::NotFound => Answer::new(404, "text/plain", vec![]),
            Reject::Empty => Answer::new(200, "text/plain", vec![]),
            Reject::Image => Answer::new(200, "image/gif", TINY_GIF.to_vec()),
            Reject::Dict => Answer::new(200, "application/json", b"{}".to_vec()),
            Reject::Array => Answer::new(200, "application/json", b"[]".to_vec()),
            Reject::Drop => return AnswerOutcome::Drop,
        }),
        Action::Redirect { status, location } => rewriter
            .with_runtime(index, allow_compile, pinned, |runtime| {
                let Some(pattern) = runtime.pattern.as_ref() else {
                    return AnswerOutcome::Skip;
                };
                let location = pattern
                    .replace(url, replacement(location).as_str())
                    .into_owned();
                let mut answer = Answer::new(*status, "", vec![]);
                answer.headers.push(("Location".into(), location));
                AnswerOutcome::Answer(answer)
            })
            .unwrap_or(AnswerOutcome::Skip),
        Action::Mock(mock) => {
            let mut answer = Answer::new(mock.status, &mock.content_type, Vec::new());
            match &mock.body {
                MockBody::Inline(bytes) => answer.body = bytes.clone(),
                MockBody::Remote(file_url) => {
                    let Some(path) = rewriter.file(file_url) else {
                        return AnswerOutcome::Drop;
                    };
                    answer.file = Some(path.clone());
                }
            }
            answer.headers.extend(mock.headers.iter().cloned());
            AnswerOutcome::Answer(answer)
        }
        _ => AnswerOutcome::Answer(Answer::new(404, "", vec![])),
    }
}

pub(crate) fn find<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Applies a header rewrite. Framing headers are left alone: the relay
/// sets them.
#[cfg(test)]
pub(crate) fn apply_header(rewriter: &Rewriter, index: usize, headers: &mut Vec<(String, String)>) {
    let _ = apply_header_with(rewriter, index, headers, true, None);
}

/// Applies a header rewrite, returning `false` when framing/non-header or when
/// `ReplaceRegex` requires compiling an uncached runtime with `allow_compile == false`.
pub(crate) fn apply_header_with(
    rewriter: &Rewriter,
    index: usize,
    headers: &mut Vec<(String, String)>,
    allow_compile: bool,
    pinned: Option<&CachedGroup>,
) -> bool {
    let Action::Header(op) = &rewriter.rule(index).action else {
        return false;
    };
    match op {
        HeaderOp::Add(name, value) if !is_framing(name) => {
            headers.push((name.clone(), value.clone()));
            true
        }
        HeaderOp::Set(name, value) if !is_framing(name) => {
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
            headers.push((name.clone(), value.clone()));
            true
        }
        HeaderOp::Delete(name) if !is_framing(name) => {
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
            true
        }
        HeaderOp::Replace(name, value) if !is_framing(name) => {
            for (k, v) in headers.iter_mut() {
                if k.eq_ignore_ascii_case(name) {
                    *v = value.clone();
                }
            }
            true
        }
        HeaderOp::ReplaceRegex(name, _, with) if !is_framing(name) => rewriter
            .with_runtime(index, allow_compile, pinned, |runtime| {
                let Some(regex) = runtime.extra.first() else {
                    return false;
                };
                for (k, v) in headers.iter_mut() {
                    if k.eq_ignore_ascii_case(name) {
                        *v = regex
                            .replace_all(v, replacement(with).as_str())
                            .into_owned();
                    }
                }
                true
            })
            .unwrap_or(false),
        _ => false,
    }
}

/// Applies a body or JSON rewrite to a decoded body; false when it does not
/// apply (not text, or not JSON).
#[cfg(test)]
pub(crate) fn apply_body(rewriter: &Rewriter, index: usize, body: &mut Vec<u8>) -> bool {
    apply_body_with(rewriter, index, body, true, None)
}

/// Applies a body or JSON rewrite to a decoded body, returning `false` if a
/// `BodyReplace` runtime is uncached when `allow_compile` is `false`.
pub(crate) fn apply_body_with(
    rewriter: &Rewriter,
    index: usize,
    body: &mut Vec<u8>,
    allow_compile: bool,
    pinned: Option<&CachedGroup>,
) -> bool {
    match &rewriter.rule(index).action {
        Action::BodyReplace(pairs) => {
            let Ok(text) = std::str::from_utf8(body) else {
                return false;
            };
            let Some(updated) = rewriter.with_runtime(index, allow_compile, pinned, |runtime| {
                let mut text = text.to_owned();
                for ((_, with), regex) in pairs.iter().zip(&runtime.extra) {
                    text = regex
                        .replace_all(&text, replacement(with).as_str())
                        .into_owned();
                }
                text.into_bytes()
            }) else {
                return false;
            };
            *body = updated;
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
    rejects: AtomicU64,
    rewrites: AtomicU64,
    modules: Mutex<HashMap<String, u64>>,
    recent: Mutex<VecDeque<Hit>>,
}
impl Stats {
    pub(crate) fn record(&self, rule: &Compiled, url: &str) {
        self.record_action(&rule.module, rule.action.kind(), url);
    }
    pub(crate) fn record_action(&self, module: &str, action: impl Into<String>, url: &str) {
        let action = action.into();
        self.total.fetch_add(1, Ordering::Relaxed);
        if action.starts_with("reject") || action == "module-reject" {
            self.rejects.fetch_add(1, Ordering::Relaxed);
        } else {
            self.rewrites.fetch_add(1, Ordering::Relaxed);
        }
        {
            let mut modules = self.modules.lock().unwrap();
            if let Some(count) = modules.get_mut(module) {
                *count += 1;
            } else if modules.len() < TRACKED {
                modules.insert(module.to_owned(), 1);
            }
        }
        let mut recent = self.recent.lock().unwrap();
        if recent.len() == RECENT {
            recent.pop_back();
        }
        recent.push_front(Hit {
            time: crate::requests::now_ms() / 1000,
            url: url.chars().take(300).collect(),
            action,
            module: module.to_owned(),
        });
    }
    pub(crate) fn snapshot(&self) -> Value {
        json!({
            "total": self.total.load(Ordering::Relaxed),
            "rejects": self.rejects.load(Ordering::Relaxed),
            "rewrites": self.rewrites.load(Ordering::Relaxed),
            "hits": *self.modules.lock().unwrap(),
            "recent": self.recent.lock().unwrap().iter().cloned().collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clyntis_config::rewrite::parse_module;

    #[test]
    fn oversized_pattern_batches_split_and_retain_individual_fallbacks() {
        let rewriter = rewriter(
            "[URL Rewrite]\n^https://a\\.test/a{100000}$ - reject\n^https://a\\.test/a{35000}$ - reject\n^https://a\\.test/b{35000}$ - reject\n^https://a\\.test/small$ - reject\n",
        );
        assert_eq!(rewriter.rule_count(), 4);
        assert_eq!(
            rewriter.matching(Phase::Request, "https://a.test/small"),
            [3]
        );
        {
            let cache = rewriter.compiled.cache.lock().unwrap();
            let bucket = cache.hosts.get("a.test").unwrap();
            assert_eq!(
                bucket
                    .request
                    .fancy
                    .iter()
                    .map(|(i, _)| *i)
                    .collect::<Vec<_>>(),
                [0]
            );
            assert!(bucket.request.sets.len() >= 2);
        }
        let url = format!("https://a.test/{}", "a".repeat(100000));
        assert_eq!(rewriter.matching(Phase::Request, &url), [0]);
        let medium = format!("https://a.test/{}", "a".repeat(35000));
        assert_eq!(rewriter.matching(Phase::Request, &medium), [1]);
        let other = format!("https://a.test/{}", "b".repeat(35000));
        assert_eq!(rewriter.matching(Phase::Request, &other), [2]);
    }

    #[test]
    fn large_body_and_header_regexes_retain_compatibility() {
        let rewriter = rewriter(
            "[Body Rewrite]\nhttp-response ^https://a\\.test/ ^a{100000}$ ok\n[Header Rewrite]\n^https://a\\.test/ header-replace-regex X-Test ^a{100000}$ ok\n",
        );
        assert_eq!(rewriter.rule_count(), 2);
        assert!(rewriter.modules[0].skipped.is_empty());
        let mut body = "a".repeat(100000).into_bytes();
        assert!(apply_body(&rewriter, 0, &mut body));
        assert_eq!(body, b"ok");
        let mut headers = vec![("x-test".to_owned(), "a".repeat(100000))];
        apply_header(&rewriter, 1, &mut headers);
        assert_eq!(headers[0].1, "ok");
    }

    #[test]
    fn batched_patterns_preserve_order_phases_unicode_and_redirect_captures() {
        let mut text = String::new();
        for i in 0..300 {
            let pattern = if i % 17 == 0 {
                format!(r"^https://a\.test/(?!keep)(shared|item{i})/(\w+)$")
            } else {
                format!(r"^https://a\.test/(shared|item{i})/(\w+)$")
            };
            let line = match i % 3 {
                0 => format!("[URL Rewrite]\n{pattern} https://new.test/$1/$2 302\n"),
                1 => format!("[URL Rewrite]\n{pattern} - reject\n"),
                _ => format!("[Body Rewrite]\nhttp-response {pattern} ad yes\n"),
            };
            text.push_str(&line);
        }
        let module = parse_module(&text);
        assert_eq!(module.rules.len(), 300);
        let expected = module.rules.clone();
        let rewriter = rewriter(&text);
        assert_eq!(rewriter.rule_count(), expected.len());
        for url in [
            "https://a.test/shared/中文",
            "https://a.test/item257/test",
            "https://a.test/keep/x",
        ] {
            for phase in [Phase::Request, Phase::Response] {
                let reference: Vec<_> = expected
                    .iter()
                    .enumerate()
                    .filter_map(|(i, rule)| {
                        (rule.phase == phase
                            && fancy_regex::Regex::new(&rule.pattern)
                                .unwrap()
                                .is_match(url)
                                .unwrap())
                        .then_some(i)
                    })
                    .collect();
                assert_eq!(rewriter.matching(phase, url), reference, "{url} {phase:?}");
            }
        }
        for index in [0, 3] {
            let answer = answer(&rewriter, index, "https://a.test/shared/中文").unwrap();
            assert_eq!(
                find(&answer.headers, "location"),
                Some("https://new.test/shared/中文")
            );
        }
    }

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
        assert_eq!(rewriter.reject_count(), 1);
        assert_eq!(rewriter.rejecting_module("x.ads.test"), Some("test"));
        assert_eq!(rewriter.rejecting_module("a.test"), None);
        assert!(rewriter.modules[0].skipped.is_empty());
        assert!(rewriter.rejects("x.ads.test") && !rewriter.rejects("a.test"));
        let stats = Stats::default();
        stats.record_action("test", "module-reject", "x.ads.test");
        stats.record(rewriter.rule(0), "https://a.test/ad");
        stats.record(rewriter.rule(3), "https://a.test/feed");
        let snapshot = stats.snapshot();
        assert_eq!(snapshot["total"], 3);
        assert_eq!(snapshot["rejects"], 2);
        assert_eq!(snapshot["rewrites"], 1);
        assert_eq!(snapshot["hits"]["test"], 3);
        assert_eq!(snapshot["recent"][0]["action"], "header");
        assert_eq!(snapshot["recent"][2]["action"], "module-reject");
        let hits = rewriter.matching(Phase::Request, "https://a.test/ad?x=1");
        assert_eq!(hits.len(), 2);
        let answer = answer(&rewriter, hits[0], "https://a.test/ad?x=1").unwrap();
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
        let answer = super::answer(&rewriter, redirect[0], "http://old.test/p?q").unwrap();
        assert_eq!(answer.status, 302);
        assert_eq!(
            find(&answer.headers, "location"),
            Some("https://new.test/p?qx")
        );
        assert!(String::from_utf8(answer.encode_head(0)).unwrap().starts_with(
            "HTTP/1.1 302 Found\r\nLocation: https://new.test/p?qx\r\nContent-Length: 0\r\n\r\n"
        ));

        let header = rewriter.matching(Phase::Request, "https://a.test/feed");
        let mut headers = vec![("user-agent".to_owned(), "App/1 (x)".to_owned())];
        apply_header(&rewriter, *header.last().unwrap(), &mut headers);
        assert_eq!(headers[0].1, "App/2 (x)");

        let body_rules = rewriter.matching(Phase::Response, "https://a.test/feed");
        assert_eq!(body_rules.len(), 2);
        let mut body =
            br#"{"list":[{"ad":true,"id":1}],"banner":{"x":1},"keep":"\"ad\":true"}"#.to_vec();
        for rule_idx in &body_rules {
            match rewriter.jq(*rule_idx) {
                Some(filter) => body = filter.apply(Arc::new(body), None).await.unwrap(),
                None => assert!(apply_body(&rewriter, *rule_idx, &mut body)),
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
        assert!(!apply_body(&rewriter, 0, &mut text));
    }

    #[test]
    fn empty_rule_module_keeps_only_excluded_hostnames() {
        let rewriter = Rewriter::new(
            vec![Loaded {
                name: "empty".into(),
                module: clyntis_config::rewrite::Module {
                    hostnames: vec!["decrypt.test".into(), "-skip.test".into()],
                    ..Default::default()
                },
                files: HashMap::new(),
                missing: vec![],
                updated: None,
            }],
            vec![],
        );
        assert_eq!(rewriter.hostnames, vec!["-skip.test".to_owned()]);
    }

    #[test]
    fn header_set_conditions_and_url_replace_work() {
        let text = r#"
[Rewrite]
request if ${url} ~= /^https:\/\/a\.test\/old\/(.*)/i as m && ${request.method} == "POST" then url.replace("https://a.test/new/${m.1}")
request if ${url} ~= /^https:\/\/a\.test\/h$/ then header.set("X-Set", "1") | header.replace("User-Agent", /Bot\/\d+/, "App/2") | header.del("X-Drop")
response if ${url} ~= /^https:\/\/a\.test\/r$/ && ${response.status} == 200 && ${response.header["Content-Type"]} ~= /^application\/json/i then response.header.set("X-Json", "yes")
"#;
        let module = clyntis_config::rewrite::parse_module(text);
        assert!(module.skipped.is_empty());
        assert_eq!(compilable_rule_count(&module), 5);
        let rw = rewriter(text);

        assert!(rw.matches_conditions(0, "POST", &[], None, &[]));
        assert!(!rw.matches_conditions(0, "GET", &[], None, &[]));
        assert_eq!(
            replace_url(&rw, 0, "https://a.test/old/item?k=1").as_deref(),
            Some("https://a.test/new/item?k=1")
        );

        let mut headers = vec![
            ("User-Agent".into(), "Bot/99".into()),
            ("X-Drop".into(), "gone".into()),
        ];
        apply_header(&rw, 1, &mut headers);
        apply_header(&rw, 2, &mut headers);
        apply_header(&rw, 3, &mut headers);
        assert_eq!(find(&headers, "X-Set"), Some("1"));
        assert_eq!(find(&headers, "User-Agent"), Some("App/2"));
        assert_eq!(find(&headers, "X-Drop"), None);

        let json_headers = vec![(
            "Content-Type".into(),
            "application/json; charset=utf-8".into(),
        )];
        assert!(rw.matches_conditions(4, "GET", &[], Some(200), &json_headers));
        assert!(!rw.matches_conditions(4, "GET", &[], Some(404), &json_headers));
        assert!(!rw.matches_conditions(4, "GET", &[], Some(200), &[]));

        // If the leading stage of a piped line fails to compile, the entire pipe
        // is non-runnable so its continuations are neither counted nor compiled.
        let bad_pipe = r#"
[Rewrite]
request if ${url} ~= /^https:\/\/a\.test\/p$/ && ${request.header["X-H"]} ~= /(unclosed/ then header.set("X-A", "1") | header.del("Cookie")
[MITM]
hostname = a.test
"#;
        let module = clyntis_config::rewrite::parse_module(bad_pipe);
        assert!(module.skipped.is_empty(), "{:?}", module.skipped);
        assert_eq!(module.rules.len(), 2);
        assert_eq!(compilable_rule_count(&module), 0);
        let compiled = Rewriter::new(
            vec![Loaded {
                name: "badpipe".into(),
                module,
                files: HashMap::new(),
                missing: vec![],
                updated: None,
            }],
            vec![],
        );
        assert_eq!(compiled.rule_count(), 0);
        assert!(compiled.hostnames.is_empty());
    }

    #[test]
    fn extract_required_host_suffix_handles_common_and_edge_cases() {
        let cases = [
            (
                r"^https?:\/\/www\.google\.com\/search",
                Some("www.google.com"),
            ),
            (r"^https://(www\.)?example\.com/ad", Some("example.com")),
            (
                r"^https?://(?:[a-z0-9-]+\.)*bilibili\.com/x/v2",
                Some("bilibili.com"),
            ),
            (r"^https?://[a-z]+api\.bilibili\.com/", Some("bilibili.com")),
            (
                r"(?i)^https:\/\/api\.Example\.com\?a=1",
                Some("api.example.com"),
            ),
            (r"^https://a\.b\.test:8443/v1", Some("a.b.test")),
            (r"^https://a\.b\.test$", Some("a.b.test")),
            (r"^https://a\.b\.test[\/?:]x", Some("a.b.test")),
            (r"^https://(m\.|www\.)?a\.test\/", Some("a.test")),
            (r"^https://([a-z0-9-]+\.)+a\.test\/", Some("a.test")),
            (r"https://a\.test/ad", None),
            (r"^https://a\.test/ad|^https://b\.test/ad", None),
            (r"(?m)^https://a\.test/ad", None),
            (r"(?x)^https://a\.test/ad", None),
            (r"^https://a\.test/?", None),
            (r"^https://a\.test\/?foo", None),
            (r"^https://a.test/ad", None),
            (r"^https://[^/]+\.a\.test/ad", None),
            (r"^https://.*?\.a\.test/ad", None),
            (r"^https://(a\.|b)?example\.com/", None),
            (r"^https://example\.com", None),
            (r"^https://[a-z]+\.com/", None),
        ];
        for (pattern, expected) in cases {
            assert_eq!(
                extract_required_host_suffix(pattern).as_deref(),
                expected,
                "pattern: {pattern}"
            );
        }
    }

    #[tokio::test]
    async fn hosted_rewriter_buckets_lazily_matches_identically_and_relieves_memory() {
        let mut text = String::new();
        for i in 0..1600 {
            let host = format!("svc{}.example.test", i % 40);
            match i % 4 {
                0 => text.push_str(&format!(
                    "[URL Rewrite]\n^https://{}/ad/{i}$ - reject-dict\n",
                    host.replace('.', r"\.")
                )),
                1 => text.push_str(&format!(
                    "[URL Rewrite]\n^https://{}/old/{i}/(.*)$ https://{}/new/$1 302\n",
                    host.replace('.', r"\."),
                    host
                )),
                2 => text.push_str(&format!(
                    "[Body Rewrite]\nhttp-response ^https://{}/(?!keep)feed/{i}$ \"ad\":true \"ad\":false\n",
                    host.replace('.', r"\.")
                )),
                _ => text.push_str(&format!(
                    "[Rewrite]\nresponse if ${{url}} ~= /^https:\\/\\/.*{i}\\/jq$/ then response.json.jq(`.drop |= not`)\n"
                )),
            }
        }
        let module = parse_module(&text);
        let expected = module.rules.clone();
        let rewriter = Rewriter::new_hosted(
            vec![Loaded {
                name: "large".into(),
                module,
                files: HashMap::new(),
                missing: vec![],
                updated: None,
            }],
            vec![],
            true,
        );
        assert_eq!(rewriter.rule_count(), 1600);
        // Zero compiled buckets or rule runtimes at construction time.
        {
            let cache = rewriter.compiled.cache.lock().unwrap();
            assert!(cache.global.is_none());
            assert!(cache.hosts.is_empty());
            assert!(cache.rule_extras.is_empty());
        }

        let probe_urls = [
            "https://svc0.example.test/ad/0",
            "https://svc1.example.test/old/1/abc",
            "https://svc2.example.test/feed/2",
            "https://svc2.example.test/keepfeed/2",
            "https://other.test/3/jq",
        ];
        let check_all = || {
            for url in probe_urls {
                for phase in [Phase::Request, Phase::Response] {
                    let reference: Vec<_> = expected
                        .iter()
                        .enumerate()
                        .filter_map(|(i, rule)| {
                            (rule.phase == phase
                                && fancy_regex::Regex::new(&rule.pattern)
                                    .unwrap()
                                    .is_match(url)
                                    .unwrap())
                            .then_some(i)
                        })
                        .collect();
                    assert_eq!(rewriter.matching(phase, url), reference, "{url} {phase:?}");
                }
            }
        };
        check_all();
        assert_eq!(
            answer(&rewriter, 1, "https://svc1.example.test/old/1/abc")
                .and_then(|a| find(&a.headers, "location").map(str::to_owned)),
            Some("https://svc1.example.test/new/abc".into())
        );
        let mut body = br#"{"ad":true}"#.to_vec();
        assert!(apply_body(&rewriter, 2, &mut body));
        assert_eq!(body, br#"{"ad":false}"#);
        let jq_out = rewriter
            .jq(3)
            .unwrap()
            .apply(Arc::new(br#"{"drop":false}"#.to_vec()), None)
            .await
            .unwrap();
        assert_eq!(jq_out, br#"{"drop":true}"#);

        // Relieving memory clears all cached matchers and runtime entries.
        rewriter.relieve_memory();
        {
            let cache = rewriter.compiled.cache.lock().unwrap();
            assert!(cache.global.is_none());
            assert!(cache.hosts.is_empty());
            assert!(cache.rule_extras.is_empty());
        }

        // Matching and rewriting seamlessly recompile only what is used afterward.
        check_all();
        let mut body2 = br#"{"ad":true}"#.to_vec();
        assert!(apply_body(&rewriter, 2, &mut body2));
        assert_eq!(body2, br#"{"ad":false}"#);
    }

    #[tokio::test]
    async fn allow_compile_false_uses_cached_and_skips_uncached_without_recompiling() {
        let text = r#"
[URL Rewrite]
^https://a\.test/old/(.*)$ https://a.test/new/$1 302
^https://a\.test/drop$ - reject-drop
^https://a\.test/dict$ - reject-dict
[Rewrite]
request if ${url} ~= /^https:\/\/a\.test\/url\/(.*)/ as m && ${request.method} == "POST" && ${request.header["X-Regex"]} ~= /^ok-\d+$/ then url.replace("https://a.test/replaced/${m.1}")
request if ${url} ~= /^https:\/\/a\.test\/nonregex$/ && ${request.method} == "POST" && ${request.header["X-Mode"]} == "fast" then header.set("X-Set", "1")
[Header Rewrite]
^https://a\.test/ header-replace-regex User-Agent (\w+)/1 $1/2
^https://a\.test/ header-add Content-Length 999
[Body Rewrite]
http-response ^https://a\.test/body$ "ad":true "ad":false
[Rewrite]
response if ${url} ~= /^https:\/\/.*\/jq$/ then response.json.jq(`.drop |= not`)
[URL Rewrite]
^https://b\.test/cold$ - reject-dict
"#;
        let module = parse_module(text);
        assert!(module.skipped.is_empty(), "{:?}", module.skipped);
        let rewriter = Rewriter::new_hosted(
            vec![Loaded {
                name: "test".into(),
                module,
                files: HashMap::new(),
                missing: vec![],
                updated: None,
            }],
            vec![],
            true,
        );
        assert_eq!(rewriter.rule_count(), 10);
        assert_eq!(rewriter.cached_bucket_count(), 0);
        assert_eq!(rewriter.cached_rule_runtime_count(), 0);

        // Warm up host bucket `a.test` and global bucket, leaving `b.test` cold.
        assert_eq!(
            rewriter.matching(Phase::Request, "https://a.test/dict"),
            vec![2, 5, 6]
        );
        assert_eq!(
            rewriter.matching(Phase::Response, "https://other.test/jq"),
            vec![8]
        );
        assert_eq!(rewriter.cached_bucket_count(), 2);

        // Warm up rule runtimes for rules 0, 3, 5, 7, 8.
        assert!(matches!(
            answer_with(&rewriter, 0, "https://a.test/old/x", true, None),
            AnswerOutcome::Answer(_)
        ));
        assert!(rewriter.matches_conditions(
            3,
            "POST",
            &[("X-Regex".into(), "ok-1".into())],
            None,
            &[],
        ));
        let mut warm_headers = vec![("User-Agent".into(), "App/1".into())];
        apply_header(&rewriter, 5, &mut warm_headers);
        let mut warm_body = br#"{"ad":true}"#.to_vec();
        assert!(apply_body(&rewriter, 7, &mut warm_body));
        assert!(rewriter.jq(8).is_some());

        let buckets_before = rewriter.cached_bucket_count();
        let runtimes_before = rewriter.cached_rule_runtime_count();
        assert_eq!(buckets_before, 2);
        assert_eq!(runtimes_before, 5);

        // Cold bucket `b.test` must be skipped when allow_compile == false.
        assert!(
            rewriter
                .matching_with(Phase::Request, "https://b.test/cold", false)
                .is_empty()
        );
        assert_eq!(rewriter.cached_bucket_count(), buckets_before);

        // Cached buckets and runtimes still match & apply when allow_compile == false.
        assert_eq!(
            rewriter.matching_with(Phase::Request, "https://a.test/old/abc", false),
            vec![0, 5, 6]
        );
        assert_eq!(
            rewriter.matching_with(Phase::Response, "https://a.test/body", false),
            vec![7]
        );
        assert_eq!(
            rewriter.matching_with(Phase::Response, "https://a.test/jq", false),
            vec![8]
        );
        assert!(rewriter.matches_conditions_with(
            3,
            "POST",
            &[("X-Regex".into(), "ok-42".into())],
            None,
            &[],
            false,
        ));
        assert!(!rewriter.matches_conditions_with(
            3,
            "POST",
            &[("X-Regex".into(), "nope".into())],
            None,
            &[],
            false,
        ));
        assert_eq!(
            replace_url_with(&rewriter, 3, "https://a.test/url/hello", false, None).as_deref(),
            Some("https://a.test/replaced/hello")
        );
        match answer_with(&rewriter, 0, "https://a.test/old/abc", false, None) {
            AnswerOutcome::Answer(ans) => {
                assert_eq!(ans.status, 302);
                assert_eq!(
                    find(&ans.headers, "location"),
                    Some("https://a.test/new/abc")
                );
            }
            other => panic!("expected Answer, got {other:?}"),
        }
        assert!(matches!(
            answer_with(&rewriter, 1, "https://a.test/drop", false, None),
            AnswerOutcome::Drop
        ));
        match answer_with(&rewriter, 2, "https://a.test/dict", false, None) {
            AnswerOutcome::Answer(ans) => assert_eq!(ans.body, b"{}"),
            other => panic!("expected Answer, got {other:?}"),
        }

        let mut cached_headers = vec![("User-Agent".into(), "App/1".into())];
        assert!(apply_header_with(
            &rewriter,
            5,
            &mut cached_headers,
            false,
            None
        ));
        assert_eq!(cached_headers[0].1, "App/2");
        assert!(!apply_header_with(
            &rewriter,
            6,
            &mut cached_headers,
            false,
            None
        ));
        assert!(!apply_header_with(
            &rewriter,
            0,
            &mut cached_headers,
            false,
            None
        ));
        assert_eq!(cached_headers.len(), 1);

        let mut cached_body = br#"{"ad":true}"#.to_vec();
        assert!(apply_body_with(&rewriter, 7, &mut cached_body, false, None));
        assert_eq!(cached_body, br#"{"ad":false}"#);

        let filter = rewriter.jq_with(8, false, None).expect("cached jq filter");
        let jq_out = filter
            .apply(Arc::new(br#"{"drop":false}"#.to_vec()), None)
            .await
            .unwrap();
        assert_eq!(jq_out, br#"{"drop":true}"#);

        assert_eq!(rewriter.cached_bucket_count(), buckets_before);
        assert_eq!(rewriter.cached_rule_runtime_count(), runtimes_before);

        // Relieve memory and verify allow_compile == false never recompiles.
        rewriter.relieve_memory();
        assert_eq!(rewriter.cached_bucket_count(), 0);
        assert_eq!(rewriter.cached_rule_runtime_count(), 0);

        assert!(
            rewriter
                .matching_with(Phase::Request, "https://a.test/old/abc", false)
                .is_empty()
        );
        assert!(
            rewriter
                .matching_with(Phase::Response, "https://a.test/body", false)
                .is_empty()
        );
        assert!(
            rewriter
                .matching_with(Phase::Response, "https://other.test/jq", false)
                .is_empty()
        );
        assert!(!rewriter.matches_conditions_with(
            3,
            "POST",
            &[("X-Regex".into(), "ok-42".into())],
            None,
            &[],
            false,
        ));
        // Non-regex conditions still evaluate without compiling a RuleRuntime.
        assert!(rewriter.matches_conditions_with(
            4,
            "POST",
            &[("X-Mode".into(), "fast".into())],
            None,
            &[],
            false,
        ));
        assert!(!rewriter.matches_conditions_with(
            4,
            "GET",
            &[("X-Mode".into(), "fast".into())],
            None,
            &[],
            false,
        ));
        assert!(replace_url_with(&rewriter, 3, "https://a.test/url/hello", false, None).is_none());
        assert!(matches!(
            answer_with(&rewriter, 0, "https://a.test/old/abc", false, None),
            AnswerOutcome::Skip
        ));
        assert!(matches!(
            answer_with(&rewriter, 1, "https://a.test/drop", false, None),
            AnswerOutcome::Drop
        ));
        assert!(matches!(
            answer_with(&rewriter, 2, "https://a.test/dict", false, None),
            AnswerOutcome::Answer(_)
        ));

        let mut uncached_headers = vec![("User-Agent".into(), "App/1".into())];
        assert!(!apply_header_with(
            &rewriter,
            5,
            &mut uncached_headers,
            false,
            None
        ));
        assert_eq!(
            uncached_headers,
            vec![("User-Agent".into(), "App/1".into())]
        );
        // Non-regex header op still applies without RuleRuntime.
        assert!(apply_header_with(
            &rewriter,
            4,
            &mut uncached_headers,
            false,
            None
        ));
        assert_eq!(find(&uncached_headers, "X-Set"), Some("1"));

        let mut uncached_body = br#"{"ad":true}"#.to_vec();
        assert!(!apply_body_with(
            &rewriter,
            7,
            &mut uncached_body,
            false,
            None
        ));
        assert_eq!(uncached_body, br#"{"ad":true}"#);

        assert!(rewriter.jq_with(8, false, None).is_none());

        assert_eq!(rewriter.cached_bucket_count(), 0);
        assert_eq!(rewriter.cached_rule_runtime_count(), 0);
    }

    #[tokio::test]
    async fn cached_group_runtimes_preflights_and_pins_across_memory_relief() {
        let text = r#"
[Rewrite]
request if ${url} ~= /^https:\/\/a\.test\/pipe\/(.*)$/ then url.replace("https://a.test/rewritten") | header.replace("X-Test", /^old-/, "new-")
request if ${url} ~= /^https:\/\/a\.test\/set-pipe$/ then header.set("X-Set", "1") | header.replace("X-Test", /^old-/, "new-")
response if ${url} ~= /^https:\/\/a\.test\/resp-pipe$/ then header.set("X-Resp", "1") | response.body.replace("ad", "ok") | response.json.jq(`.drop |= not`)
[URL Rewrite]
^https://a\.test/redir/(.*)$ https://a.test/dest/$1 302
[Rewrite]
response if ${url} ~= /^https:\/\/a\.test\/simple$/ then response.header.delete("X-Drop") | response.json.delete("ad")
"#;
        let module = parse_module(text);
        assert!(module.skipped.is_empty(), "{:?}", module.skipped);
        let rewriter = Rewriter::new_hosted(
            vec![Loaded {
                name: "test".into(),
                module,
                files: HashMap::new(),
                missing: vec![],
                updated: None,
            }],
            vec![],
            true,
        );
        // Rules:
        // 0: UrlReplace (needs runtime), 1: Header ReplaceRegex (needs runtime)
        // 2: Header Set (no), 3: Header ReplaceRegex (needs runtime)
        // 4: Header Set (no), 5: BodyReplace (needs runtime), 6: Jq (needs runtime)
        // 7: Redirect (needs runtime)
        // 8: Header Delete (no), 9: JsonDelete (no)
        assert_eq!(rewriter.rule_count(), 10);
        assert!(rewriter.action_needs_runtime(0));
        assert!(rewriter.action_needs_runtime(1));
        assert!(!rewriter.action_needs_runtime(2));
        assert!(rewriter.action_needs_runtime(3));
        assert!(!rewriter.action_needs_runtime(4));
        assert!(rewriter.action_needs_runtime(5));
        assert!(rewriter.action_needs_runtime(6));
        assert!(rewriter.action_needs_runtime(7));
        assert!(!rewriter.action_needs_runtime(8));
        assert!(!rewriter.action_needs_runtime(9));

        // Group needing no runtimes returns Some even with empty cache.
        assert!(rewriter.cached_group_runtimes(&[8, 9]).is_some());
        assert_eq!(rewriter.cached_rule_runtime_count(), 0);

        // Mixed hot/cold: warm Stage 0 (url.replace) only, leave Stage 1 (header.replace) cold.
        assert_eq!(
            replace_url(&rewriter, 0, "https://a.test/pipe/1").as_deref(),
            Some("https://a.test/rewritten")
        );
        assert_eq!(rewriter.cached_rule_runtime_count(), 1);
        assert!(rewriter.cached_group_runtimes(&[0, 1]).is_none());
        // Stage 2 needs no runtime, Stage 3 is cold -> None without compiling.
        assert!(rewriter.cached_group_runtimes(&[2, 3]).is_none());
        assert_eq!(rewriter.cached_rule_runtime_count(), 1);

        // Warm Stage 1, Stage 3, Stage 5, Stage 6, Stage 7.
        let mut headers = vec![("X-Test".into(), "old-1".into())];
        apply_header(&rewriter, 1, &mut headers);
        apply_header(&rewriter, 3, &mut headers);
        let mut body = br#"{"drop":false,"ad":1}"#.to_vec();
        assert!(apply_body(&rewriter, 5, &mut body));
        // Response group [4, 5, 6] is still missing Jq stage 6.
        assert!(rewriter.cached_group_runtimes(&[4, 5, 6]).is_none());
        assert!(rewriter.jq(6).is_some());
        assert!(answer(&rewriter, 7, "https://a.test/redir/x").is_some());

        let pinned_req = rewriter
            .cached_group_runtimes(&[0, 1])
            .expect("both stages cached");
        let pinned_set = rewriter
            .cached_group_runtimes(&[2, 3])
            .expect("runtime stage cached");
        let pinned_resp = rewriter
            .cached_group_runtimes(&[4, 5, 6])
            .expect("all runtime stages cached");
        let pinned_redir = rewriter
            .cached_group_runtimes(&[7])
            .expect("redirect runtime cached");

        // Clear all caches; pinned groups still execute with allow_compile == false
        // and never recompile into the cache.
        rewriter.relieve_memory();
        assert_eq!(rewriter.cached_bucket_count(), 0);
        assert_eq!(rewriter.cached_rule_runtime_count(), 0);

        assert_eq!(
            replace_url_with(
                &rewriter,
                0,
                "https://a.test/pipe/abc",
                false,
                Some(&pinned_req)
            )
            .as_deref(),
            Some("https://a.test/rewritten")
        );
        let mut h1 = vec![("X-Test".into(), "old-a".into())];
        assert!(apply_header_with(
            &rewriter,
            1,
            &mut h1,
            false,
            Some(&pinned_req)
        ));
        assert_eq!(h1[0].1, "new-a");

        let mut h2 = vec![("X-Test".into(), "old-b".into())];
        assert!(apply_header_with(
            &rewriter,
            2,
            &mut h2,
            false,
            Some(&pinned_set)
        ));
        assert!(apply_header_with(
            &rewriter,
            3,
            &mut h2,
            false,
            Some(&pinned_set)
        ));
        assert_eq!(find(&h2, "X-Set"), Some("1"));
        assert_eq!(find(&h2, "X-Test"), Some("new-b"));

        let mut resp_body = br#"{"drop":false,"tag":"ad"}"#.to_vec();
        assert!(apply_body_with(
            &rewriter,
            5,
            &mut resp_body,
            false,
            Some(&pinned_resp)
        ));
        assert_eq!(resp_body, br#"{"drop":false,"tag":"ok"}"#);
        let filter = rewriter
            .jq_with(6, false, Some(&pinned_resp))
            .expect("pinned jq filter");
        let jq_out = filter.apply(Arc::new(resp_body), None).await.unwrap();
        assert_eq!(jq_out, br#"{"drop":true,"tag":"ok"}"#);

        match answer_with(
            &rewriter,
            7,
            "https://a.test/redir/done",
            false,
            Some(&pinned_redir),
        ) {
            AnswerOutcome::Answer(ans) => {
                assert_eq!(ans.status, 302);
                assert_eq!(
                    find(&ans.headers, "location"),
                    Some("https://a.test/dest/done")
                );
            }
            other => panic!("expected Answer, got {other:?}"),
        }

        assert_eq!(rewriter.cached_bucket_count(), 0);
        assert_eq!(rewriter.cached_rule_runtime_count(), 0);
    }
}
