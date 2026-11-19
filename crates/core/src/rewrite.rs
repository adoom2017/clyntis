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

const PATTERN_BATCH_LIMIT: usize = 256;
const PATTERN_SET_LIMIT: usize = 2 << 20;
const PATTERN_CACHE_LIMIT: usize = 64 << 10;

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

/// A rule ready to match.
pub(crate) struct Compiled {
    pub(crate) module: String,
    pub(crate) line: usize,
    pub(crate) phase: Phase,
    /// Retained after construction only for lookaround, set-build fallbacks
    /// and redirect/url-replace captures. Other patterns live only in the
    /// batched sets.
    pattern: Option<UrlPattern>,
    conditions: Vec<CompiledCondition>,
    pub(crate) pipe_continuation: bool,
    pub(crate) action: Action,
    /// Compiled regexes of body and header rewrites, in order.
    extra: Vec<fancy_regex::Regex>,
    /// The compiled filter of a jq rewrite.
    pub(crate) jq: Option<crate::jq::Filter>,
}

enum CompiledCondition {
    Method { equals: bool, value: String },
    Status { equals: bool, value: u16 },
    RequestHeader { name: String, op: CompiledMatchOp },
    ResponseHeader { name: String, op: CompiledMatchOp },
}

enum CompiledMatchOp {
    Equals(String),
    NotEquals(String),
    Regex(fancy_regex::Regex),
}

impl CompiledMatchOp {
    fn matches(&self, value: Option<&str>) -> bool {
        match self {
            Self::Equals(expected) => value.is_some_and(|v| v == expected),
            Self::NotEquals(expected) => value != Some(expected.as_str()),
            Self::Regex(regex) => value.is_some_and(|v| regex.is_match(v).unwrap_or(false)),
        }
    }
}

enum UrlPattern {
    /// Validated, but not retained as a second compiled regex while its set
    /// is being built. Redirects keep captures in `Regular` instead.
    Source(String),
    Regular(regex::Regex),
    Fancy(fancy_regex::Regex),
}
impl UrlPattern {
    fn as_str(&self) -> &str {
        match self {
            Self::Source(source) => source,
            Self::Regular(regex) => regex.as_str(),
            Self::Fancy(regex) => regex.as_str(),
        }
    }
    fn is_match(&self, url: &str) -> bool {
        match self {
            Self::Source(_) => unreachable!("source patterns are compiled before matching"),
            Self::Regular(regex) => regex.is_match(url),
            Self::Fancy(regex) => regex.is_match(url).unwrap_or(false),
        }
    }
    fn replace<'a>(&self, url: &'a str, replacement: &str) -> std::borrow::Cow<'a, str> {
        match self {
            Self::Source(_) => unreachable!("redirect patterns retain captures"),
            Self::Regular(regex) => regex.replace(url, replacement),
            Self::Fancy(regex) => regex.replace(url, replacement),
        }
    }
}
impl Compiled {
    /// `kind (module)`, for the request log.
    pub(crate) fn label(&self) -> String {
        format!("{} ({})", self.action.kind(), self.module)
    }

    pub(crate) fn matches_conditions(
        &self,
        method: &str,
        request_headers: &[(String, String)],
        response_status: Option<u16>,
        response_headers: &[(String, String)],
    ) -> bool {
        self.conditions.iter().all(|cond| match cond {
            CompiledCondition::Method { equals, value } => {
                method.eq_ignore_ascii_case(value) == *equals
            }
            CompiledCondition::Status { equals, value } => {
                response_status.is_some_and(|s| (s == *value) == *equals)
            }
            CompiledCondition::RequestHeader { name, op } => {
                op.matches(find(request_headers, name))
            }
            CompiledCondition::ResponseHeader { name, op } => {
                op.matches(find(response_headers, name))
            }
        })
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
    /// Small sets bound compilation peaks in the iOS tunnel. `fancy` lists
    /// the rules that must be matched individually.
    sets: Vec<PatternSet>,
    fancy: Vec<usize>,
    reject: Vec<(String, DomainSet)>,
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

/// Flush while compiling, so a large module never holds every individual
/// regex alongside its combined sets. A failed batch retains its matchers.
fn flush_patterns(
    rules: &mut [Compiled],
    indices: &mut Vec<usize>,
    sets: &mut Vec<PatternSet>,
    fancy: &mut Vec<usize>,
) {
    if indices.is_empty() {
        return;
    }
    let patterns = indices
        .iter()
        .map(|&i| rules[i].pattern.as_ref().unwrap().as_str());
    match regex::RegexSetBuilder::new(patterns)
        .size_limit(PATTERN_SET_LIMIT)
        .dfa_size_limit(PATTERN_CACHE_LIMIT)
        .build()
    {
        Ok(set) => {
            for &i in indices.iter() {
                if !matches!(
                    rules[i].action,
                    Action::Redirect { .. } | Action::UrlReplace(_)
                ) {
                    rules[i].pattern = None;
                }
            }
            sets.push(PatternSet {
                set,
                indices: std::mem::take(indices),
            });
        }
        Err(_) if indices.len() > 1 => {
            // One expensive pattern must not make all the others keep their
            // individual regexes. Split until the remaining batches fit.
            let mut rest = indices.split_off(indices.len() / 2);
            flush_patterns(rules, indices, sets, fancy);
            flush_patterns(rules, &mut rest, sets, fancy);
        }
        Err(_) => {
            let i = indices[0];
            if let Some(UrlPattern::Source(source)) = &rules[i].pattern {
                let regex = regex::RegexBuilder::new(source)
                    .dfa_size_limit(PATTERN_CACHE_LIMIT)
                    .build()
                    .expect("pattern was validated before batching");
                rules[i].pattern = Some(UrlPattern::Regular(regex));
            }
            fancy.append(indices);
        }
    }
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
    pub(crate) fn new(loaded: Vec<Loaded>, failed: Vec<(String, Option<u64>, String)>) -> Self {
        let mut rules = Vec::new();
        let (mut sets, mut batch, mut fancy) = (Vec::new(), Vec::new(), Vec::new());
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
                match compile(&loaded.name, rule) {
                    Ok((compiled, batchable)) => {
                        if matches!(compiled.action, Action::Script(_)) {
                            scripts += 1;
                        }
                        count += 1;
                        let index = rules.len();
                        if batchable {
                            batch.push(index);
                        } else {
                            fancy.push(index);
                        }
                        rules.push(compiled);
                        if batch.len() == PATTERN_BATCH_LIMIT {
                            flush_patterns(&mut rules, &mut batch, &mut sets, &mut fancy);
                        }
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
        flush_patterns(&mut rules, &mut batch, &mut sets, &mut fancy);
        Self {
            compiled: Arc::new(CompiledRules {
                rules,
                sets,
                fancy,
                reject,
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

    /// The rules of `phase` that match `url`, in module order.
    pub(crate) fn matching(&self, phase: Phase, url: &str) -> Vec<usize> {
        let mut found: Vec<usize> = self
            .compiled
            .sets
            .iter()
            .flat_map(|batch| batch.set.matches(url).into_iter().map(|i| batch.indices[i]))
            .chain(self.compiled.fancy.iter().copied().filter(|&i| {
                self.compiled.rules[i]
                    .pattern
                    .as_ref()
                    .is_some_and(|pattern| pattern.is_match(url))
            }))
            .filter(|&i| self.compiled.rules[i].phase == phase)
            .collect();
        found.sort_unstable();
        found
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

fn compile(
    module: &str,
    rule: clyntis_config::rewrite::Rule,
) -> Result<(Compiled, bool), (usize, String)> {
    let failed = |what: &str| (rule.line, format!("{what}: {}", rule.pattern));
    let regex = |source: &str| {
        fancy_regex::RegexBuilder::new(source)
            .delegate_dfa_size_limit(PATTERN_CACHE_LIMIT)
            .build()
    };
    let (pattern, batchable) = match regex::RegexBuilder::new(&rule.pattern)
        .size_limit(PATTERN_SET_LIMIT)
        .dfa_size_limit(PATTERN_CACHE_LIMIT)
        .build()
    {
        Ok(regex)
            if matches!(
                rule.action,
                Action::Redirect { .. } | Action::UrlReplace(_)
            ) =>
        {
            (UrlPattern::Regular(regex), true)
        }
        Ok(_) => (UrlPattern::Source(rule.pattern.clone()), true),
        Err(_) => match regex::RegexBuilder::new(&rule.pattern)
            .dfa_size_limit(PATTERN_CACHE_LIMIT)
            .build()
        {
            Ok(regex) => (UrlPattern::Regular(regex), false),
            Err(_) => (
                UrlPattern::Fancy(regex(&rule.pattern).map_err(|_| failed("bad pattern"))?),
                false,
            ),
        },
    };
    let compile_op = |op: MatchOp| -> Result<CompiledMatchOp, (usize, String)> {
        Ok(match op {
            MatchOp::Equals(v) => CompiledMatchOp::Equals(v),
            MatchOp::NotEquals(v) => CompiledMatchOp::NotEquals(v),
            MatchOp::Regex(source) => {
                CompiledMatchOp::Regex(regex(&source).map_err(|_| failed("bad condition regex"))?)
            }
        })
    };
    let conditions = rule
        .conditions
        .into_iter()
        .map(|cond| {
            Ok(match cond {
                Condition::Method { equals, value } => CompiledCondition::Method { equals, value },
                Condition::Status { equals, value } => CompiledCondition::Status { equals, value },
                Condition::RequestHeader { name, op } => CompiledCondition::RequestHeader {
                    name,
                    op: compile_op(op)?,
                },
                Condition::ResponseHeader { name, op } => CompiledCondition::ResponseHeader {
                    name,
                    op: compile_op(op)?,
                },
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let extra = match &rule.action {
        Action::BodyReplace(pairs) => pairs
            .iter()
            .map(|(source, _)| regex(source))
            .collect::<Result<_, _>>()
            .map_err(|_| failed("bad body regex"))?,
        Action::Header(HeaderOp::ReplaceRegex(_, source, _)) => {
            vec![regex(source).map_err(|_| failed("bad header regex"))?]
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
    Ok((
        Compiled {
            module: module.to_owned(),
            line: rule.line,
            phase: rule.phase,
            pattern: Some(pattern),
            conditions,
            pipe_continuation: rule.pipe_continuation,
            action: rule.action,
            extra,
            jq,
        },
        batchable,
    ))
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
        if rule_has_file(rule, &has_file) && compile("", (*rule).clone()).is_ok() {
            count += 1;
        } else if !rule.pipe_continuation {
            failed_line = Some(rule.line);
        }
    }
    count
}

/// Applies a `url.replace` rule to `url`.
pub(crate) fn replace_url(rule: &Compiled, url: &str) -> Option<String> {
    let Action::UrlReplace(target) = &rule.action else {
        return None;
    };
    let pattern = rule.pattern.as_ref()?;
    Some(
        pattern
            .replace(url, replacement(target).as_str())
            .into_owned(),
    )
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
                .as_ref()
                .expect("redirect patterns retain captures")
                .replace(url, replacement(location).as_str())
                .into_owned();
            let mut answer = Answer::new(*status, "", vec![]);
            answer.headers.push(("Location".into(), location));
            answer
        }
        Action::Mock(mock) => {
            let mut answer = Answer::new(mock.status, &mock.content_type, Vec::new());
            match &mock.body {
                MockBody::Inline(bytes) => answer.body = bytes.clone(),
                MockBody::Remote(url) => answer.file = Some(rewriter.file(url)?.clone()),
            }
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
        HeaderOp::Set(name, value) if !is_framing(name) => {
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
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
        assert_eq!(rewriter.compiled.fancy, [0]);
        assert!(rewriter.compiled.sets.len() >= 2);
        assert_eq!(
            rewriter.matching(Phase::Request, "https://a.test/small"),
            [3]
        );
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
        assert!(apply_body(rewriter.rule(0), &mut body));
        assert_eq!(body, b"ok");
        let mut headers = vec![("x-test".to_owned(), "a".repeat(100000))];
        apply_header(rewriter.rule(1), &mut headers);
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
            let answer = answer(
                &rewriter,
                rewriter.rule(index),
                "https://a.test/shared/中文",
            )
            .unwrap();
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
        assert!(String::from_utf8(answer.encode_head(0)).unwrap().starts_with(
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

        let url_rule = rw.rule(0);
        assert!(url_rule.matches_conditions("POST", &[], None, &[]));
        assert!(!url_rule.matches_conditions("GET", &[], None, &[]));
        assert_eq!(
            replace_url(url_rule, "https://a.test/old/item?k=1").as_deref(),
            Some("https://a.test/new/item?k=1")
        );

        let mut headers = vec![
            ("User-Agent".into(), "Bot/99".into()),
            ("X-Drop".into(), "gone".into()),
        ];
        apply_header(rw.rule(1), &mut headers);
        apply_header(rw.rule(2), &mut headers);
        apply_header(rw.rule(3), &mut headers);
        assert_eq!(find(&headers, "X-Set"), Some("1"));
        assert_eq!(find(&headers, "User-Agent"), Some("App/2"));
        assert_eq!(find(&headers, "X-Drop"), None);

        let resp_rule = rw.rule(4);
        let json_headers = vec![("Content-Type".into(), "application/json; charset=utf-8".into())];
        assert!(resp_rule.matches_conditions("GET", &[], Some(200), &json_headers));
        assert!(!resp_rule.matches_conditions("GET", &[], Some(404), &json_headers));
        assert!(!resp_rule.matches_conditions("GET", &[], Some(200), &[]));

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
}
