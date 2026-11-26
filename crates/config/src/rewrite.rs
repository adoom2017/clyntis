//! Rewriting decrypted HTTP to remove ads: modules in the Surge (`.sgmodule`),
//! Loon (`.plugin`) and Quantumult X (rewrite snippet) formats, subscribed by
//! URL or written by hand. Their URL rewrites (reject, redirect, local
//! responses), header and body rewrites and scripts act on the requests of
//! decrypted hosts; their MITM host names join the hosts to decrypt, and the
//! domain rules that reject join ad blocking. The apps write the `rewrite`
//! section from their settings (see `overrides`).
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// The configuration section.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Rewrite {
    pub enable: bool,
    /// Subscribed modules, in order: earlier modules' URL rewrites win.
    pub modules: Vec<Source>,
    /// A module written by hand, in any of the formats; it comes first.
    pub custom: String,
    /// Seconds between module and script updates.
    pub interval: u64,
}
impl Default for Rewrite {
    fn default() -> Self {
        Self {
            enable: false,
            modules: Vec::new(),
            custom: String::new(),
            interval: 86_400,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Source {
    pub name: String,
    pub url: String,
}
impl Source {
    /// The cache file, inside the configuration directory.
    pub fn file_name(&self) -> String {
        format!(
            "rewrite/{}-{}.module",
            safe_name(&self.name),
            url_hash(&self.url)
        )
    }
}

/// The name a custom module gets in status and logs.
pub const CUSTOM: &str = "custom";
const CUSTOM_LIMIT: usize = 256 << 10;

fn safe_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// A downloaded script or local response body: cached by its URL.
pub fn cache_file(url: &str) -> String {
    format!("rewrite/files/{}", url_hash(url))
}

fn url_hash(url: &str) -> String {
    use sha1::Digest;
    let digest = sha1::Sha1::digest(url.as_bytes());
    digest.iter().take(10).map(|b| format!("{b:02x}")).collect()
}

impl Rewrite {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.interval >= 3600,
            "rewrite.interval must be at least 3600 seconds"
        );
        ensure!(
            self.custom.len() <= CUSTOM_LIMIT,
            "rewrite.custom is too long"
        );
        let mut names = std::collections::HashSet::new();
        for module in &self.modules {
            ensure!(
                !module.name.trim().is_empty()
                    && module.name.len() <= 64
                    && module.name != CUSTOM
                    && names.insert(safe_name(&module.name)),
                "rewrite module names must be non-empty, unique and at most 64 bytes"
            );
            ensure!(
                module.url.starts_with("https://") || module.url.starts_with("http://"),
                "rewrite module {}: url must be http(s)",
                module.name
            );
        }
        Ok(())
    }
}

/// What the apps store: modules (each can be turned off) and the custom one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub modules: Vec<ModuleSetting>,
    pub custom: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModuleSetting {
    pub name: String,
    pub url: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}
fn yes() -> bool {
    true
}
impl Settings {
    pub fn to_config(&self) -> Result<Rewrite> {
        let rewrite = Rewrite {
            enable: self.enabled,
            modules: self
                .modules
                .iter()
                .filter(|m| m.enabled)
                .map(|m| Source {
                    name: m.name.trim().to_owned(),
                    url: m.url.trim().to_owned(),
                })
                .collect(),
            custom: self.custom.clone(),
            ..Rewrite::default()
        };
        rewrite.validate()?;
        Ok(rewrite)
    }
}

// ---------------------------------------------------------------------------
// Modules.

/// One parsed module. Patterns are regular expressions, not yet compiled.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Module {
    /// `#!name=`.
    pub name: Option<String>,
    pub description: Option<String>,
    /// Hosts to decrypt, as in `mitm.hostname` (`-` excludes).
    pub hostnames: Vec<String>,
    pub rules: Vec<Rule>,
    /// Domain rules that reject: DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD.
    pub reject: Vec<(DomainKind, String)>,
    /// Lines that were not understood, with their line numbers.
    pub skipped: Vec<(usize, String)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainKind {
    Exact,
    Suffix,
    Keyword,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Request,
    Response,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// A regular expression the full URL must match.
    pub pattern: String,
    pub phase: Phase,
    /// Additional conditions (method, status, headers) that must all hold.
    pub conditions: Vec<Condition>,
    /// True for subsequent stages of a piped `a | b` DSL rule: runs iff the
    /// leading stage on the same `(module, line)` matched its conditions.
    pub pipe_continuation: bool,
    pub action: Action,
    /// Its line in the module, for status and the request log.
    pub line: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Condition {
    Method { equals: bool, value: String },
    Status { equals: bool, value: u16 },
    RequestHeader { name: String, op: MatchOp },
    ResponseHeader { name: String, op: MatchOp },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatchOp {
    Equals(String),
    NotEquals(String),
    Regex(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Reject(Reject),
    /// `$1`… in the location refer to the pattern's groups.
    Redirect {
        status: u16,
        location: String,
    },
    /// Transparently rewrites the outbound request URL (same-origin path/query).
    UrlReplace(String),
    Header(HeaderOp),
    /// Regex and replacement pairs, applied in order to the body as text.
    BodyReplace(Vec<(String, String)>),
    /// JSON paths to delete (`a.b`, `a[0]`, `a[].b`).
    JsonDelete(Vec<String>),
    /// JSON paths and the JSON values to put there.
    JsonSet(Vec<(String, String)>),
    /// A jq filter applied to the JSON body; its first output replaces it.
    Jq(String),
    Mock(Mock),
    Script(Script),
}
impl Action {
    /// A short name for the request log.
    pub fn kind(&self) -> String {
        match self {
            Action::Reject(reject) => reject.name().into(),
            Action::Redirect { status, .. } => status.to_string(),
            Action::UrlReplace(_) => "url".into(),
            Action::Header(_) => "header".into(),
            Action::BodyReplace(_) => "body".into(),
            Action::JsonDelete(_) | Action::JsonSet(_) => "json".into(),
            Action::Jq(_) => "jq".into(),
            Action::Mock(_) => "mock".into(),
            Action::Script(script) => format!("script {}", script.name),
        }
    }
    /// Whether it needs the whole body of its phase.
    pub fn needs_body(&self) -> bool {
        match self {
            Action::BodyReplace(_) | Action::JsonDelete(_) | Action::JsonSet(_) | Action::Jq(_) => {
                true
            }
            Action::Script(script) => script.requires_body,
            _ => false,
        }
    }
    /// Whether it answers the request itself.
    pub fn answers(&self) -> bool {
        matches!(
            self,
            Action::Reject(_) | Action::Redirect { .. } | Action::Mock(_)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// HTTP 404.
    NotFound,
    /// HTTP 200, empty.
    Empty,
    /// HTTP 200, a 1×1 GIF.
    Image,
    /// HTTP 200, `{}`.
    Dict,
    /// HTTP 200, `[]`.
    Array,
    /// The connection is closed.
    Drop,
}
impl Reject {
    fn parse(word: &str) -> Option<Self> {
        Some(match word.to_ascii_lowercase().as_str() {
            "reject" => Reject::NotFound,
            "reject-200" => Reject::Empty,
            "reject-img" | "reject-tinygif" => Reject::Image,
            "reject-dict" => Reject::Dict,
            "reject-array" => Reject::Array,
            "reject-drop" | "reject-no-drop" => Reject::Drop,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Reject::NotFound => "reject",
            Reject::Empty => "reject-200",
            Reject::Image => "reject-img",
            Reject::Dict => "reject-dict",
            Reject::Array => "reject-array",
            Reject::Drop => "reject-drop",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderOp {
    Add(String, String),
    /// Sets a header, replacing existing values or inserting if absent.
    Set(String, String),
    Delete(String),
    /// Replaces the value of a header that is present.
    Replace(String, String),
    /// Rewrites the value of a header that is present: regex, replacement.
    ReplaceRegex(String, String, String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mock {
    pub status: u16,
    pub content_type: String,
    pub body: MockBody,
    pub headers: Vec<(String, String)>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MockBody {
    Inline(Vec<u8>),
    /// Downloaded like scripts.
    Remote(String),
}

/// A 1×1 transparent GIF.
pub const TINY_GIF: &[u8] = &[
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x01, 0x44, 0x00, 0x3b,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScriptArgument {
    Text(String),
    Object(Vec<(String, ScriptValue)>),
}
impl Default for ScriptArgument {
    fn default() -> Self {
        Self::Text(String::new())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScriptValue {
    Bool(bool),
    Number(String),
    String(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Script {
    pub name: String,
    /// http(s) URL of the script.
    pub url: String,
    pub requires_body: bool,
    /// The body as bytes (`Uint8Array`) instead of text.
    pub binary: bool,
    /// Larger bodies skip the script; `None` for the default.
    pub max_size: Option<u64>,
    /// Seconds.
    pub timeout: Option<u64>,
    pub argument: ScriptArgument,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    /// Before any section, or one this parser only knows to skip.
    None,
    Ignored,
    Rule,
    UrlRewrite,
    HeaderRewrite,
    BodyRewrite,
    MapLocal,
    Script,
    Mitm,
    /// Loon `[Rewrite]`, Quantumult X `[rewrite_local]`.
    Rewrite,
    Argument,
}

const SKIPPED_KEPT: usize = 50;
const RULES_LIMIT: usize = 10_000;

/// Parses a module. Lines that are not understood are reported, never fatal:
/// modules are written for other apps and use features this one lacks.
pub fn parse_module(text: &str) -> Module {
    let args = collect_arguments(text);
    let text = substitute_arguments(text, &args);
    let mut module = Module::default();
    let mut section = Section::None;
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let line = raw.trim();
        if let Some(meta) = line.strip_prefix("#!") {
            if let Some((key, value)) = meta.split_once('=') {
                match key.trim() {
                    "name" => module.name = Some(value.trim().to_owned()),
                    "desc" => module.description = Some(value.trim().to_owned()),
                    _ => {}
                }
            }
            continue;
        }
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with("//")
            || line.starts_with(';')
        {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = match line[1..line.len() - 1]
                .trim()
                .to_ascii_lowercase()
                .replace('_', " ")
                .as_str()
            {
                "rule" | "filter local" => Section::Rule,
                "url rewrite" => Section::UrlRewrite,
                "header rewrite" => Section::HeaderRewrite,
                "body rewrite" => Section::BodyRewrite,
                "map local" => Section::MapLocal,
                "script" => Section::Script,
                "mitm" => Section::Mitm,
                "rewrite" | "rewrite local" => Section::Rewrite,
                "argument" => Section::Argument,
                _ => Section::Ignored,
            };
            continue;
        }
        if module.rules.len() >= RULES_LIMIT {
            break;
        }
        // Quantumult X snippets often have no sections at all.
        let section = if section == Section::None {
            if line.to_ascii_lowercase().starts_with("hostname") {
                Section::Mitm
            } else {
                Section::Rewrite
            }
        } else {
            section
        };
        let parsed: Result<(), Option<String>> = match section {
            Section::Ignored | Section::Argument | Section::None => Ok(()),
            Section::Mitm => {
                mitm_line(line, &mut module.hostnames);
                Ok(())
            }
            Section::Rule => rule_line(line, &mut module.reject).map_err(|()| None),
            _ if is_dsl_rule(line) => match dsl_line(line, number, &args) {
                Ok(rules) => {
                    module.rules.extend(rules);
                    Ok(())
                }
                Err(reason) => Err(Some(reason)),
            },
            Section::Script => script_line(line, number)
                .map(|rule| module.rules.extend(rule))
                .map_err(|()| None),
            _ => rewrite_line(section, line, number)
                .map(|rule| module.rules.push(rule))
                .map_err(|()| None),
        };
        if let Err(reason) = parsed
            && module.skipped.len() < SKIPPED_KEPT
        {
            let text = match reason {
                Some(reason) => format!("{reason}: {}", line.chars().take(160).collect::<String>()),
                None => line.chars().take(200).collect(),
            };
            module.skipped.push((number, text));
        }
    }
    module
}

fn collect_arguments(text: &str) -> Vec<(String, ScriptValue)> {
    let mut values = Vec::new();
    let mut in_argument = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(arguments) = line.strip_prefix("#!arguments=") {
            for item in split_outside_quotes(arguments, ',') {
                if let Some((key, value)) = item.split_once(':') {
                    values.push((
                        key.trim().into(),
                        ScriptValue::String(unquote(value.trim()).into()),
                    ));
                }
            }
        } else if line.starts_with('[') {
            in_argument = line.eq_ignore_ascii_case("[argument]");
        } else if in_argument && let Some((key, rest)) = line.split_once('=') {
            // `name = switch,true,false,tag=…` / `name = input,"value",tag=…`:
            // the default is the first value.
            let fields = split_outside_quotes(rest, ',');
            if let (Some(kind), Some(value)) = (fields.first(), fields.get(1)) {
                let raw = unquote(value.trim());
                let kind = kind.trim().to_ascii_lowercase();
                let declared_type = fields[2..]
                    .iter()
                    .filter_map(|f| f.split_once('='))
                    .find(|(k, _)| k.trim().eq_ignore_ascii_case("type"))
                    .map(|(_, v)| unquote(v.trim()).to_ascii_lowercase());
                let typed = if kind == "switch"
                    || matches!(declared_type.as_deref(), Some("bool" | "boolean"))
                {
                    ScriptValue::Bool(raw.eq_ignore_ascii_case("true"))
                } else if (kind == "number"
                    || matches!(
                        declared_type.as_deref(),
                        Some("number" | "int" | "integer" | "float" | "double")
                    ))
                    && raw.parse::<f64>().is_ok()
                {
                    ScriptValue::Number(raw.into())
                } else {
                    ScriptValue::String(raw.into())
                };
                values.push((key.trim().into(), typed));
            }
        }
    }
    values
}

fn script_value_text(value: &ScriptValue) -> &str {
    match value {
        ScriptValue::Bool(true) => "true",
        ScriptValue::Bool(false) => "false",
        ScriptValue::Number(n) | ScriptValue::String(n) => n.as_str(),
    }
}

/// Fills `{{{name}}}` everywhere and Loon 3.5+ `${name}` outside object
/// literals `{...}` (which `dsl_line` resolves with full types).
fn substitute_arguments<'a>(
    text: &'a str,
    values: &[(String, ScriptValue)],
) -> std::borrow::Cow<'a, str> {
    if values.is_empty() || (!text.contains("{{{") && !text.contains("${")) {
        return text.into();
    }
    let mut out = text.to_owned();
    if out.contains("{{{") {
        for (key, value) in values {
            out = out.replace(&format!("{{{{{{{key}}}}}}}"), script_value_text(value));
        }
    }
    if out.contains("${") {
        let mut replaced = String::with_capacity(out.len());
        let bytes = out.as_bytes();
        let mut i = 0;
        let mut brace_depth = 0usize;
        while i < bytes.len() {
            if bytes[i] == b'$'
                && bytes.get(i + 1) == Some(&b'{')
                && let Some(rel_end) = out[i + 2..].find('}')
            {
                let name = &out[i + 2..i + 2 + rel_end];
                if brace_depth == 0
                    && let Some((_, value)) = values.iter().find(|(k, _)| k == name)
                {
                    replaced.push_str(script_value_text(value));
                } else {
                    replaced.push_str(&out[i..i + 3 + rel_end]);
                }
                i += 3 + rel_end;
                continue;
            }
            if bytes[i] == b'{' {
                brace_depth += 1;
            } else if bytes[i] == b'}' {
                brace_depth = brace_depth.saturating_sub(1);
            } else if bytes[i] == b'\n' {
                brace_depth = 0;
            }
            let ch = out[i..].chars().next().unwrap();
            replaced.push(ch);
            i += ch.len_utf8();
        }
        out = replaced;
    }
    out.into()
}

fn strip_mitm_port(host: &str) -> &str {
    if host.starts_with('[') {
        if let Some(end) = host.find(']') {
            let after = &host[end + 1..];
            if let Some(port) = after.strip_prefix(':')
                && !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit())
                && port.parse::<u16>().is_ok()
            {
                return &host[..=end];
            }
        }
        return host;
    }
    if let Some((name, port)) = host.rsplit_once(':')
        && !name.is_empty()
        && !name.contains(':')
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u16>().is_ok()
    {
        return name;
    }
    host
}

fn push_mitm_host(item: &str, hosts: &mut Vec<String>) {
    let host = item
        .trim()
        .trim_start_matches("%APPEND%")
        .trim_start_matches("%INSERT%")
        .trim();
    let host = strip_mitm_port(host);
    if !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('%')
        && !host.chars().any(char::is_whitespace)
        && !host.contains('=')
    {
        hosts.push(host.to_ascii_lowercase());
    }
}

fn mitm_line(line: &str, hosts: &mut Vec<String>) {
    let Some((key, value)) = line.split_once('=') else {
        return;
    };
    if !key.trim().eq_ignore_ascii_case("hostname") {
        return;
    }
    for item in value.split(',') {
        if let Some((left, right)) = item.split_once('=') {
            let left = left.trim();
            let prefix_end = left.len().saturating_sub(8);
            if left.len() > 8
                && left.is_char_boundary(prefix_end)
                && left[prefix_end..].eq_ignore_ascii_case("hostname")
            {
                push_mitm_host(&left[..prefix_end], hosts);
                push_mitm_host(right, hosts);
            }
            continue;
        }
        push_mitm_host(item, hosts);
    }
}

fn rule_line(line: &str, reject: &mut Vec<(DomainKind, String)>) -> Result<(), ()> {
    let fields: Vec<&str> = line.split(',').map(str::trim).collect();
    let (Some(kind), Some(value), Some(policy)) = (fields.first(), fields.get(1), fields.get(2))
    else {
        return Err(());
    };
    if !policy.to_ascii_lowercase().starts_with("reject") {
        // Rules for other policies route traffic; that is the profile's job.
        return Ok(());
    }
    let kind = match kind.to_ascii_uppercase().as_str() {
        "DOMAIN" | "HOST" => DomainKind::Exact,
        "DOMAIN-SUFFIX" | "HOST-SUFFIX" => DomainKind::Suffix,
        "DOMAIN-KEYWORD" | "HOST-KEYWORD" => DomainKind::Keyword,
        // Rejecting QUIC and the like is done for decrypted hosts anyway.
        _ => return Ok(()),
    };
    if value.is_empty() {
        return Err(());
    }
    reject.push((kind, value.to_ascii_lowercase()));
    Ok(())
}

/// Splits on whitespace. A token, or a `key=` value, that starts with a
/// quote whose closing quote ends the token is quoted (`\"` escapes the
/// quote); the quotes are removed. Other quotes are kept: `"ad":true`.
fn tokens(line: &str) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }
        let mut token = String::new();
        while i < chars.len() && !chars[i].is_whitespace() {
            let c = chars[i];
            if (c == '"' || c == '\'')
                && (token.is_empty() || token.ends_with('='))
                && let Some(close) = closing(&chars, i)
            {
                let mut j = i + 1;
                while j < close {
                    if chars[j] == '\\' && chars.get(j + 1) == Some(&c) {
                        j += 1;
                    }
                    token.push(chars[j]);
                    j += 1;
                }
                i = close + 1;
                continue;
            }
            token.push(c);
            i += 1;
        }
        out.push(token);
    }
    out
}

/// The quote closing the one at `open`, when whitespace or the end follows.
fn closing(chars: &[char], open: usize) -> Option<usize> {
    let quote = chars[open];
    let mut j = open + 1;
    while j < chars.len() {
        if chars[j] == '\\' && chars.get(j + 1) == Some(&quote) {
            j += 2;
            continue;
        }
        if chars[j] == quote {
            return chars
                .get(j + 1)
                .is_none_or(|c| c.is_whitespace())
                .then_some(j);
        }
        j += 1;
    }
    None
}

fn unquote(value: &str) -> &str {
    let value = value.trim();
    for quote in ['"', '\''] {
        if value.len() >= 2 && value.starts_with(quote) && value.ends_with(quote) {
            return &value[1..value.len() - 1];
        }
    }
    value
}

fn split_outside_quotes(text: &str, separator: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for c in text.chars() {
        match quote {
            Some(q) if c == q => {
                quote = None;
                current.push(c);
            }
            Some(_) => current.push(c),
            None if c == '"' || c == '\'' => {
                quote = Some(c);
                current.push(c);
            }
            None if c == separator => out.push(std::mem::take(&mut current)),
            None => current.push(c),
        }
    }
    out.push(current);
    out
}

/// `key=value` options after the fixed tokens.
fn options(tokens: &[String]) -> Vec<(String, String)> {
    tokens
        .iter()
        .filter_map(|t| t.split_once('='))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.to_owned()))
        .collect()
}
fn option<'a>(options: &'a [(String, String)], key: &str) -> Option<&'a str> {
    options
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}
fn truthy(value: Option<&str>) -> bool {
    value.is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
}

fn phase_prefix(token: &str) -> Option<(Phase, bool)> {
    Some(match token.to_ascii_lowercase().as_str() {
        "http-request" => (Phase::Request, false),
        "http-response" => (Phase::Response, false),
        "http-request-jq" => (Phase::Request, true),
        "http-response-jq" => (Phase::Response, true),
        _ => return None,
    })
}

fn rewrite_line(section: Section, line: &str, number: usize) -> Result<Rule, ()> {
    let mut tokens = tokens(line);
    let rule = |pattern: String, phase, action| {
        Ok(Rule {
            pattern,
            phase,
            conditions: Vec::new(),
            pipe_continuation: false,
            action,
            line: number,
        })
    };
    match section {
        Section::HeaderRewrite => {
            let phase = match tokens.first().and_then(|t| phase_prefix(t)) {
                Some((phase, false)) => {
                    tokens.remove(0);
                    phase
                }
                Some(_) => return Err(()),
                None => Phase::Request,
            };
            let pattern = take(&mut tokens)?;
            let op = take(&mut tokens)?;
            rule(pattern, phase, Action::Header(header_op(&op, tokens)?))
        }
        Section::BodyRewrite => {
            let (phase, jq) = tokens.first().and_then(|t| phase_prefix(t)).ok_or(())?;
            tokens.remove(0);
            let pattern = take(&mut tokens)?;
            if jq {
                return rule(pattern, phase, Action::Jq(jq_filter(&tokens)?));
            }
            rule(pattern, phase, Action::BodyReplace(pairs(tokens)?))
        }
        Section::MapLocal => {
            let pattern = take(&mut tokens)?;
            rule(pattern, Phase::Request, Action::Mock(mock(&tokens)?))
        }
        _ => {
            let pattern = take(&mut tokens)?;
            // Quantumult X: `pattern url action …`.
            if tokens.first().is_some_and(|t| t == "url") {
                tokens.remove(0);
            }
            let word = tokens.first().ok_or(())?.to_ascii_lowercase();
            if let Some(reject) = Reject::parse(&word) {
                return rule(pattern, Phase::Request, Action::Reject(reject));
            }
            if let Some(action) = keyword_action(&word, &tokens[1..], number)? {
                return rule(pattern, action.0, action.1);
            }
            // Surge `[URL Rewrite]`: `pattern replacement type`.
            if tokens.len() >= 2 {
                let kind = tokens[1].to_ascii_lowercase();
                if let Some(reject) = Reject::parse(&kind) {
                    return rule(pattern, Phase::Request, Action::Reject(reject));
                }
                if let Ok(status @ (301 | 302 | 307 | 308)) = kind.parse::<u16>() {
                    return rule(
                        pattern,
                        Phase::Request,
                        Action::Redirect {
                            status,
                            location: tokens[0].clone(),
                        },
                    );
                }
            }
            Err(())
        }
    }
}

fn take(tokens: &mut Vec<String>) -> Result<String, ()> {
    if tokens.is_empty() {
        Err(())
    } else {
        Ok(tokens.remove(0))
    }
}

/// Loon and Quantumult X actions named by a keyword after the pattern.
fn keyword_action(
    word: &str,
    rest: &[String],
    number: usize,
) -> Result<Option<(Phase, Action)>, ()> {
    let response = word.starts_with("response-");
    let phase = if response {
        Phase::Response
    } else {
        Phase::Request
    };
    let first = || rest.first().cloned().ok_or(());
    Ok(Some(match word {
        "301" | "302" | "307" | "308" => (
            Phase::Request,
            Action::Redirect {
                status: word.parse().map_err(|_| ())?,
                location: first()?,
            },
        ),
        "header-add"
        | "header-del"
        | "header-replace"
        | "header-replace-regex"
        | "response-header-add"
        | "response-header-del"
        | "response-header-replace"
        | "response-header-replace-regex" => (
            phase,
            Action::Header(header_op(
                word.trim_start_matches("response-"),
                rest.to_vec(),
            )?),
        ),
        "request-header" | "response-header" => {
            // Quantumult X: `request-header regex request-header replacement`.
            let (pattern_tokens, rep_tokens) =
                if let Some(pos) = rest.iter().position(|t| t == word) {
                    (&rest[..pos], &rest[pos + 1..])
                } else if rest.len() >= 2 {
                    (&rest[..1], &rest[1..])
                } else {
                    return Err(());
                };
            (
                phase,
                Action::Header(qx_header_op(pattern_tokens, rep_tokens)?),
            )
        }
        "response-body-replace-regex"
        | "request-body-replace-regex"
        | "response-body"
        | "request-body" => {
            // Quantumult X: `response-body regex response-body replacement`
            // and `request-body regex request-body replacement`.
            let rest: Vec<String> = rest
                .iter()
                .filter(|t| *t != "response-body" && *t != "request-body")
                .cloned()
                .collect();
            (
                if word.starts_with("request-body") {
                    Phase::Request
                } else {
                    Phase::Response
                },
                Action::BodyReplace(pairs(rest)?),
            )
        }
        "response-body-json-del" | "request-body-json-del" => (
            if response {
                Phase::Response
            } else {
                Phase::Request
            },
            Action::JsonDelete(
                rest.iter()
                    .map(|p| json_path(p))
                    .collect::<Result<_, _>>()?,
            ),
        ),
        "response-body-json-replace"
        | "response-body-json-add"
        | "request-body-json-replace"
        | "request-body-json-add" => {
            ensure_pairs(rest)?;
            (
                if response {
                    Phase::Response
                } else {
                    Phase::Request
                },
                Action::JsonSet(
                    rest.chunks(2)
                        .map(|p| Ok((json_path(&p[0])?, p[1].clone())))
                        .collect::<Result<_, ()>>()?,
                ),
            )
        }
        "response-body-json-jq" | "request-body-json-jq" => (
            if response {
                Phase::Response
            } else {
                Phase::Request
            },
            Action::Jq(jq_filter(rest)?),
        ),
        "mock-response-body" => (Phase::Request, Action::Mock(mock(rest)?)),
        "script-response-body"
        | "script-request-body"
        | "script-response-header"
        | "script-request-header"
        | "script-echo-response" => {
            let url = first()?;
            let opts = options(&rest[1..]);
            let phase = if word.contains("response") && word != "script-echo-response" {
                Phase::Response
            } else {
                Phase::Request
            };
            let number_option =
                |key| option(&opts, key).and_then(|v: &str| v.trim().parse::<u64>().ok());
            let name = option(&opts, "tag")
                .filter(|t| !t.is_empty())
                .map_or_else(|| script_name(&url, number), str::to_owned);
            (
                phase,
                Action::Script(Script {
                    name,
                    url: remote(url)?,
                    requires_body: word.ends_with("-body")
                        || truthy(option(&opts, "requires-body")),
                    binary: truthy(option(&opts, "binary-body-mode")),
                    max_size: number_option("max-size").filter(|s| *s > 0),
                    timeout: number_option("timeout").filter(|t| *t > 0),
                    argument: ScriptArgument::Text(
                        option(&opts, "argument").unwrap_or("").to_owned(),
                    ),
                }),
            )
        }
        _ => return Ok(None),
    }))
}

fn ensure_pairs(rest: &[String]) -> Result<(), ()> {
    if rest.is_empty() || !rest.len().is_multiple_of(2) {
        Err(())
    } else {
        Ok(())
    }
}

fn pairs(rest: Vec<String>) -> Result<Vec<(String, String)>, ()> {
    ensure_pairs(&rest)?;
    Ok(rest
        .chunks(2)
        .map(|p| (p[0].clone(), p[1].clone()))
        .collect())
}

fn qx_strip_header_framing(text: &str) -> &str {
    text.trim_start_matches(r"(\r\n)")
        .trim_start_matches(r"\r\n")
        .trim_start_matches('^')
        .trim_end_matches(r"(\r\n)")
        .trim_end_matches(r"\r\n")
        .trim_end_matches('$')
}

fn qx_header_op(pattern_tokens: &[String], rep_tokens: &[String]) -> Result<HeaderOp, ()> {
    if pattern_tokens.is_empty() {
        return Err(());
    }
    let pattern_joined = pattern_tokens.join(" ");
    let pattern = qx_strip_header_framing(&pattern_joined);
    let (name, val_regex) = pattern.split_once(':').ok_or(())?;
    let name = name.trim();
    if name.is_empty() || name.chars().any(char::is_whitespace) {
        return Err(());
    }
    let val_regex = val_regex.trim_start_matches(r"\s*").trim_start();
    let val_regex = if val_regex.is_empty() {
        ".*"
    } else {
        val_regex
    };
    let rep_joined = rep_tokens.join(" ");
    let rep = qx_strip_header_framing(&rep_joined);
    if rep.is_empty() {
        return Ok(HeaderOp::Delete(name.to_owned()));
    }
    if let Some((rep_name, rep_val)) = rep.split_once(':')
        && rep_name.trim().eq_ignore_ascii_case(name)
    {
        return Ok(HeaderOp::ReplaceRegex(
            name.to_owned(),
            val_regex.to_owned(),
            rep_val.trim_start().to_owned(),
        ));
    }
    Err(())
}

fn header_op(op: &str, mut args: Vec<String>) -> Result<HeaderOp, ()> {
    let name = take(&mut args)?;
    let rest = args.join(" ");
    Ok(match op.to_ascii_lowercase().as_str() {
        "header-add" => HeaderOp::Add(name, rest),
        "header-del" => HeaderOp::Delete(name),
        "header-replace" => HeaderOp::Replace(name, rest),
        "header-replace-regex" => {
            let regex = take(&mut args)?;
            HeaderOp::ReplaceRegex(name, regex, args.join(" "))
        }
        _ => return Err(()),
    })
}

/// `$.a.b`, `a.b[0]`, `.a[].b` → `a.b`, `a.b[0]`, `a[].b`.
fn json_path(path: &str) -> Result<String, ()> {
    let path = path.trim();
    let path = path
        .strip_prefix("$.")
        .or_else(|| path.strip_prefix('.'))
        .unwrap_or(path);
    if path.is_empty() || path.contains(char::is_whitespace) {
        return Err(());
    }
    Ok(path.trim_end_matches('?').replace("[]?", "[]"))
}

/// A jq filter given after the pattern, usually quoted as one token.
fn jq_filter(tokens: &[String]) -> Result<String, ()> {
    let filter = tokens.join(" ");
    let filter = unquote(filter.trim()).trim();
    if filter.is_empty() || filter.starts_with("jq-path=") {
        // A filter in a separate file is not supported.
        return Err(());
    }
    Ok(filter.to_owned())
}

fn mock_content_type(kind: &str) -> Result<&'static str, ()> {
    Ok(match kind {
        "tiny-gif" | "gif" => "image/gif",
        "base64" => "application/octet-stream",
        "json" => "application/json",
        "html" => "text/html; charset=utf-8",
        "css" => "text/css",
        "javascript" => "application/javascript",
        "text" => "text/plain; charset=utf-8",
        _ => return Err(()),
    })
}

fn mock_from_parts(
    kind: &str,
    data: &str,
    status: u16,
    force_base64: bool,
    content_type_override: Option<&str>,
    headers: Vec<(String, String)>,
) -> Result<Mock, ()> {
    if !(100..=599).contains(&status) {
        return Err(());
    }
    let kind = kind.to_ascii_lowercase();
    let default_type = mock_content_type(&kind)?;
    let (content_type, body) = match kind.as_str() {
        "tiny-gif" | "gif" if data.is_empty() || kind == "tiny-gif" => {
            ("image/gif", MockBody::Inline(TINY_GIF.to_vec()))
        }
        _ if force_base64 || matches!(kind.as_str(), "base64" | "gif") => {
            use base64::Engine;
            let content_type = if kind == "gif" {
                "application/octet-stream"
            } else {
                default_type
            };
            if data.starts_with("http://") || data.starts_with("https://") {
                (content_type, MockBody::Remote(data.into()))
            } else {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .map_err(|_| ())?;
                (content_type, MockBody::Inline(bytes))
            }
        }
        _ => {
            if data.starts_with("http://") || data.starts_with("https://") {
                (default_type, MockBody::Remote(data.into()))
            } else {
                (default_type, MockBody::Inline(data.as_bytes().to_vec()))
            }
        }
    };
    Ok(Mock {
        status,
        content_type: content_type_override.unwrap_or(content_type).to_owned(),
        body,
        headers,
    })
}

fn mock(tokens: &[String]) -> Result<Mock, ()> {
    let options = options(tokens);
    let kind = option(&options, "data-type").unwrap_or("text");
    let status = option(&options, "status-code")
        .map(|s| s.parse::<u16>().map_err(|_| ()))
        .transpose()?
        .unwrap_or(200);
    let data = option(&options, "data").unwrap_or("");
    let mut headers = Vec::new();
    if let Some(list) = option(&options, "header") {
        for item in list.split('|') {
            if let Some((name, value)) = item.split_once(':') {
                headers.push((name.trim().to_owned(), value.trim().to_owned()));
            }
        }
    }
    mock_from_parts(
        kind,
        data,
        status,
        false,
        option(&options, "content-type"),
        headers,
    )
}

fn remote(url: String) -> Result<String, ()> {
    if url.starts_with("https://") || url.starts_with("http://") {
        Ok(url)
    } else {
        // Local files of another app.
        Err(())
    }
}

fn script_name(url: &str, number: usize) -> String {
    url.rsplit('/')
        .next()
        .filter(|n| !n.is_empty())
        .map_or_else(
            || format!("line {number}"),
            |n| n.trim_end_matches(".js").to_owned(),
        )
}

fn build_script(
    phase: Phase,
    pattern: String,
    conditions: Vec<Condition>,
    url: String,
    options: &[(String, String)],
    argument: Option<ScriptArgument>,
    number: usize,
) -> Result<Option<Rule>, ()> {
    if option(options, "enable").is_some_and(|v| v.eq_ignore_ascii_case("false")) {
        return Ok(None);
    }
    let url = remote(url)?;
    let name = option(options, "tag")
        .filter(|t| !t.is_empty())
        .map_or_else(|| script_name(&url, number), str::to_owned);
    let number_option = |key| option(options, key).and_then(|v: &str| v.trim().parse::<u64>().ok());
    Ok(Some(Rule {
        pattern,
        phase,
        conditions,
        pipe_continuation: false,
        action: Action::Script(Script {
            name,
            url,
            requires_body: truthy(option(options, "requires-body")),
            binary: truthy(option(options, "binary-body-mode")),
            max_size: number_option("max-size").filter(|s| *s > 0),
            timeout: number_option("timeout").filter(|t| *t > 0),
            argument: argument.unwrap_or_else(|| {
                ScriptArgument::Text(option(options, "argument").unwrap_or("").to_owned())
            }),
        }),
        line: number,
    }))
}

/// Surge: `name = type=http-response,pattern=…,script-path=…,requires-body=1`.
/// Loon: `http-response pattern script-path=…, requires-body=true, tag=name`.
/// Other script types (cron, generic, dns…) are skipped quietly.
fn script_line(line: &str, number: usize) -> Result<Option<Rule>, ()> {
    let is_loon = line
        .split_once(char::is_whitespace)
        .is_some_and(|(head, rest)| {
            (head.eq_ignore_ascii_case("http-request")
                || head.eq_ignore_ascii_case("http-response"))
                && !rest.trim_start().starts_with('=')
        });
    let (phase, pattern, options) = if is_loon {
        let (head, rest) = line.split_once(char::is_whitespace).ok_or(())?;
        let rest = rest.trim_start();
        // The pattern runs to the first whitespace; options follow,
        // separated by commas.
        let (pattern, options) = rest.split_once(char::is_whitespace).ok_or(())?;
        let options = split_outside_quotes(options, ',')
            .into_iter()
            .filter_map(|o| {
                o.split_once('=')
                    .map(|(k, v)| (k.trim().to_ascii_lowercase(), unquote(v).to_owned()))
            })
            .collect::<Vec<_>>();
        let phase = phase_prefix(head).ok_or(())?.0;
        (phase, pattern.to_owned(), options)
    } else {
        let (name, rest) = line.split_once('=').ok_or(())?;
        let mut options: Vec<(String, String)> = split_outside_quotes(rest, ',')
            .into_iter()
            .filter_map(|o| {
                o.split_once('=')
                    .map(|(k, v)| (k.trim().to_ascii_lowercase(), unquote(v).to_owned()))
            })
            .collect();
        let kind = option(&options, "type").unwrap_or("").to_ascii_lowercase();
        let Some((phase, false)) = phase_prefix(&kind) else {
            return Ok(None);
        };
        let pattern = option(&options, "pattern").ok_or(())?.to_owned();
        options.push(("tag".into(), name.trim().to_owned()));
        (phase, pattern, options)
    };
    let url = option(&options, "script-path").ok_or(())?.to_owned();
    build_script(phase, pattern, Vec::new(), url, &options, None, number)
}

fn is_dsl_rule(line: &str) -> bool {
    strip_dsl_phase(line).is_some()
}

fn strip_dsl_phase(line: &str) -> Option<(Phase, &str)> {
    let rest = line.trim_start();
    let (phase, after) = if rest
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("request"))
    {
        (Phase::Request, &rest[7..])
    } else if rest
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case("response"))
    {
        (Phase::Response, &rest[8..])
    } else {
        return None;
    };
    let after = after
        .strip_prefix(|c: char| c.is_ascii_whitespace())?
        .trim_start();
    if !after.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("if")) {
        return None;
    }
    let cond = after[2..]
        .strip_prefix(|c: char| c.is_ascii_whitespace())?
        .trim_start();
    Some((phase, cond))
}

fn skip_quoted(bytes: &[u8], i: usize) -> Option<usize> {
    let quote = *bytes.get(i)?;
    if !matches!(quote, b'"' | b'\'' | b'`') {
        return None;
    }
    let mut j = i + 1;
    while j < bytes.len() {
        if quote != b'`' && bytes[j] == b'\\' {
            j += 2;
            continue;
        }
        if bytes[j] == quote {
            return Some(j + 1);
        }
        j += 1;
    }
    None
}

fn skip_regex(bytes: &[u8], i: usize) -> Option<usize> {
    if bytes.get(i) != Some(&b'/') || bytes.get(i + 1) == Some(&b'/') {
        return None;
    }
    let mut j = i + 1;
    let mut in_class = false;
    while j < bytes.len() {
        match bytes[j] {
            b'\\' => j += 2,
            b'[' => {
                in_class = true;
                j += 1;
            }
            b']' if in_class => {
                in_class = false;
                j += 1;
            }
            b'/' if !in_class => {
                j += 1;
                while j < bytes.len() && bytes[j].is_ascii_alphabetic() {
                    j += 1;
                }
                return Some(j);
            }
            _ => j += 1,
        }
    }
    None
}

fn regex_allowed_before(bytes: &[u8], i: usize) -> bool {
    let mut k = i;
    while k > 0 && bytes[k - 1].is_ascii_whitespace() {
        k -= 1;
    }
    k == 0 || matches!(bytes[k - 1], b'(' | b',' | b'=' | b'~' | b'[' | b'|')
}

fn split_dsl_then(s: &str) -> Option<(&str, &str)> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(next) = skip_quoted(bytes, i) {
            i = next;
            continue;
        }
        if bytes[i] == b'/'
            && regex_allowed_before(bytes, i)
            && let Some(next) = skip_regex(bytes, i)
        {
            i = next;
            continue;
        }
        if bytes[i].is_ascii_whitespace() {
            let ws_start = i;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if s.get(i..i + 4)
                .is_some_and(|w| w.eq_ignore_ascii_case("then"))
                && bytes.get(i + 4).is_some_and(u8::is_ascii_whitespace)
            {
                let after = s[i + 4..].trim_start();
                return Some((&s[..ws_start], after));
            }
            continue;
        }
        i += 1;
    }
    None
}

fn split_top_level(s: &str, sep: u8) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    let mut depth = 0usize;
    while i < bytes.len() {
        if let Some(next) = skip_quoted(bytes, i) {
            i = next;
            continue;
        }
        if bytes[i] == b'/'
            && regex_allowed_before(bytes, i)
            && let Some(next) = skip_regex(bytes, i)
        {
            i = next;
            continue;
        }
        match bytes[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b if b == sep && depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    out.push(&s[start..]);
    out
}

fn escape_regex(literal: &str) -> String {
    let mut out = String::with_capacity(literal.len());
    for c in literal.chars() {
        if matches!(
            c,
            '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn parse_regex_literal(s: &str) -> Result<(String, &str), String> {
    let s = s.trim_start();
    let end = skip_regex(s.as_bytes(), 0).ok_or_else(|| "invalid regex literal".to_owned())?;
    let mut slash = end;
    while slash > 1 && s.as_bytes()[slash - 1].is_ascii_alphabetic() {
        slash -= 1;
    }
    if slash <= 1 || s.as_bytes()[slash - 1] != b'/' {
        return Err("invalid regex literal".to_owned());
    }
    let body = &s[1..slash - 1];
    let flags = &s[slash..end];
    if body.is_empty() {
        return Err("empty regex literal".to_owned());
    }
    let (mut has_i, mut has_m, mut has_s) = (false, false, false);
    for flag in flags.chars() {
        match flag {
            'i' => has_i = true,
            'm' => has_m = true,
            's' => has_s = true,
            'g' => {}
            other => return Err(format!("unsupported regex flag '{other}'")),
        }
    }
    let mut inline = String::new();
    if has_i {
        inline.push('i');
    }
    if has_m {
        inline.push('m');
    }
    if has_s {
        inline.push('s');
    }
    let prefix = (!inline.is_empty()).then(|| format!("(?{inline})"));
    let pattern = match prefix {
        Some(prefix) if !body.starts_with(&prefix) => format!("{prefix}{body}"),
        _ => body.to_owned(),
    };
    Ok((pattern, &s[end..]))
}

fn parse_string_literal(s: &str) -> Result<String, ()> {
    let s = s.trim();
    let bytes = s.as_bytes();
    if skip_quoted(bytes, 0) != Some(s.len()) {
        return Err(());
    }
    let quote = bytes[0];
    let inner = &s[1..s.len() - 1];
    if quote == b'`' || !inner.contains('\\') {
        return Ok(inner.to_owned());
    }
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\'
            && let Some(&next) = chars.peek()
            && matches!(next, '\\' | '"' | '\'')
        {
            out.push(next);
            chars.next();
            continue;
        }
        out.push(c);
    }
    Ok(out)
}

fn parse_dsl_value(s: &str) -> Result<String, ()> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(());
    }
    if matches!(trimmed.as_bytes().first(), Some(b'"' | b'\'' | b'`')) {
        parse_string_literal(trimmed)
    } else {
        Ok(trimmed.to_owned())
    }
}

fn parse_dsl_string_list(s: &str) -> Result<Vec<String>, ()> {
    let trimmed = s.trim();
    if let Some(inner) = trimmed.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        let mut out = Vec::new();
        for item in split_top_level(inner, b',') {
            let item = item.trim();
            if !item.is_empty() {
                out.push(parse_string_literal(item)?);
            }
        }
        if out.is_empty() {
            return Err(());
        }
        Ok(out)
    } else {
        Ok(vec![parse_string_literal(trimmed)?])
    }
}

fn split_top_level_op<'a>(s: &'a str, op: &[u8; 2]) -> Vec<&'a str> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    let mut depth = 0usize;
    while i < bytes.len() {
        if let Some(next) = skip_quoted(bytes, i) {
            i = next;
            continue;
        }
        if bytes[i] == b'/'
            && regex_allowed_before(bytes, i)
            && let Some(next) = skip_regex(bytes, i)
        {
            i = next;
            continue;
        }
        match bytes[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            _ if depth == 0 && bytes.get(i..i + 2) == Some(op.as_slice()) => {
                out.push(&s[start..i]);
                i += 2;
                start = i;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    out.push(&s[start..]);
    out
}

fn parse_header_condition_target(expr: &str) -> Option<(bool, String)> {
    let (is_response, rest) = if let Some(rest) = expr
        .strip_prefix("${request.headers")
        .or_else(|| expr.strip_prefix("${request.header"))
    {
        (false, rest)
    } else if let Some(rest) = expr
        .strip_prefix("${response.headers")
        .or_else(|| expr.strip_prefix("${response.header"))
    {
        (true, rest)
    } else {
        return None;
    };
    let rest = rest.strip_suffix('}')?;
    let name = if let Some(inner) = rest.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        parse_string_literal(inner).ok()?
    } else if let Some(dot) = rest.strip_prefix('.') {
        dot.trim().to_owned()
    } else {
        return None;
    };
    (!name.is_empty()).then_some((is_response, name))
}

fn parse_match_op(rest: &str) -> Result<MatchOp, String> {
    let rest = rest.trim_start();
    if let Some(rhs) = rest.strip_prefix("~=") {
        let (pattern, tail) = parse_regex_literal(rhs)?;
        if !tail.trim().is_empty() {
            return Err("unexpected tokens after regex condition".to_owned());
        }
        Ok(MatchOp::Regex(pattern))
    } else if let Some(rhs) = rest.strip_prefix("==") {
        let value = parse_dsl_value(rhs).map_err(|()| "invalid == condition value".to_owned())?;
        Ok(MatchOp::Equals(value))
    } else if let Some(rhs) = rest.strip_prefix("!=") {
        let value = parse_dsl_value(rhs).map_err(|()| "invalid != condition value".to_owned())?;
        Ok(MatchOp::NotEquals(value))
    } else {
        Err(format!("unsupported condition operator: {rest}"))
    }
}

fn parse_dsl_condition(cond: &str) -> Result<(String, Option<&str>, Vec<Condition>), String> {
    let cond = cond.trim();
    if split_top_level_op(cond, b"||").len() > 1 {
        return Err("unsupported logical OR condition".to_owned());
    }
    let mut pattern: Option<String> = None;
    let mut alias: Option<&str> = None;
    let mut conditions = Vec::new();

    for clause in split_top_level_op(cond, b"&&") {
        let clause = clause.trim();
        if clause.is_empty() {
            return Err("empty condition clause".to_owned());
        }
        if let Some(rest) = clause.strip_prefix("${url}") {
            let rest = rest.trim_start();
            if pattern.is_some() {
                return Err("duplicate ${url} condition".to_owned());
            }
            if let Some(rhs) = rest.strip_prefix("~=") {
                let (pat, tail) = parse_regex_literal(rhs)?;
                let tail = tail.trim();
                let found_alias = if tail.is_empty() {
                    None
                } else {
                    let after_as = tail
                        .get(..2)
                        .filter(|w| w.eq_ignore_ascii_case("as"))
                        .and_then(|_| tail[2..].strip_prefix(|c: char| c.is_ascii_whitespace()))
                        .ok_or_else(|| format!("invalid capture alias: {tail}"))?
                        .trim();
                    if after_as.is_empty() || after_as.contains(char::is_whitespace) {
                        return Err(format!("invalid capture alias: {tail}"));
                    }
                    Some(after_as)
                };
                pattern = Some(pat);
                alias = found_alias;
            } else if let Some(rhs) = rest.strip_prefix("==") {
                let exact = parse_string_literal(rhs)
                    .map_err(|()| "invalid ${url} == literal".to_owned())?;
                if exact.is_empty() {
                    return Err("empty ${url} == literal".to_owned());
                }
                pattern = Some(format!("^{}$", escape_regex(&exact)));
            } else {
                return Err(format!("unsupported ${{url}} operator: {clause}"));
            }
            continue;
        }
        if let Some(rest) = clause.strip_prefix("${request.method}") {
            let rest = rest.trim_start();
            let (equals, rhs) = if let Some(rhs) = rest.strip_prefix("==") {
                (true, rhs)
            } else if let Some(rhs) = rest.strip_prefix("!=") {
                (false, rhs)
            } else {
                return Err(format!("unsupported method condition: {clause}"));
            };
            let value =
                parse_dsl_value(rhs).map_err(|()| format!("invalid method condition: {clause}"))?;
            conditions.push(Condition::Method { equals, value });
            continue;
        }
        if let Some(rest) = clause
            .strip_prefix("${response.status}")
            .or_else(|| clause.strip_prefix("${response.statusCode}"))
        {
            let rest = rest.trim_start();
            let (equals, rhs) = if let Some(rhs) = rest.strip_prefix("==") {
                (true, rhs)
            } else if let Some(rhs) = rest.strip_prefix("!=") {
                (false, rhs)
            } else {
                return Err(format!("unsupported status condition: {clause}"));
            };
            let value = parse_dsl_value(rhs)
                .ok()
                .and_then(|v| v.parse::<u16>().ok())
                .filter(|s| (100..=599).contains(s))
                .ok_or_else(|| format!("invalid status condition: {clause}"))?;
            conditions.push(Condition::Status { equals, value });
            continue;
        }
        if let Some(close) = clause.find('}')
            && let Some((is_response, name)) = parse_header_condition_target(&clause[..=close])
        {
            let op = parse_match_op(&clause[close + 1..])?;
            conditions.push(if is_response {
                Condition::ResponseHeader { name, op }
            } else {
                Condition::RequestHeader { name, op }
            });
            continue;
        }
        return Err(format!("unsupported condition: {clause}"));
    }

    let pattern = pattern.ok_or_else(|| "missing ${url} condition".to_owned())?;
    Ok((pattern, alias, conditions))
}

fn parse_dsl_call(stage: &str) -> Result<(&str, Vec<&str>, &str), String> {
    let stage = stage.trim();
    let open = stage
        .find('(')
        .ok_or_else(|| format!("expected action call: {stage}"))?;
    let func = stage[..open].trim();
    if func.is_empty() {
        return Err(format!("empty action name: {stage}"));
    }
    let bytes = stage.as_bytes();
    let mut i = open + 1;
    let mut depth = 1usize;
    let mut close = None;
    while i < bytes.len() {
        if let Some(next) = skip_quoted(bytes, i) {
            i = next;
            continue;
        }
        if bytes[i] == b'/'
            && regex_allowed_before(bytes, i)
            && let Some(next) = skip_regex(bytes, i)
        {
            i = next;
            continue;
        }
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            _ => {}
        }
        i += 1;
    }
    let close = close.ok_or_else(|| format!("unclosed action call: {stage}"))?;
    let args_str = stage[open + 1..close].trim();
    let args = if args_str.is_empty() {
        Vec::new()
    } else {
        split_top_level(args_str, b',')
            .into_iter()
            .map(str::trim)
            .collect()
    };
    Ok((func, args, stage[close + 1..].trim()))
}

fn apply_capture_alias(location: String, alias: Option<&str>) -> String {
    let Some(alias) = alias else {
        return location;
    };
    let mut out = location;
    for n in 1..=9 {
        out = out.replace(&format!("${{{alias}.{n}}}"), &format!("${n}"));
    }
    out
}

fn parse_dsl_typed_value(
    raw: &str,
    arg_defs: &[(String, ScriptValue)],
) -> Result<ScriptValue, String> {
    let trimmed = raw.trim();
    if let Some(name) = trimmed.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
        return arg_defs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .ok_or_else(|| format!("unknown script argument '${{{name}}}'"));
    }
    if matches!(trimmed.as_bytes().first(), Some(b'"' | b'\'' | b'`')) {
        return parse_string_literal(trimmed)
            .map(ScriptValue::String)
            .map_err(|()| format!("invalid script argument string: {trimmed}"));
    }
    if trimmed.eq_ignore_ascii_case("true") {
        return Ok(ScriptValue::Bool(true));
    }
    if trimmed.eq_ignore_ascii_case("false") {
        return Ok(ScriptValue::Bool(false));
    }
    if trimmed.parse::<f64>().is_ok() {
        return Ok(ScriptValue::Number(trimmed.to_owned()));
    }
    Ok(ScriptValue::String(trimmed.to_owned()))
}

fn parse_dsl_script_argument(
    raw: &str,
    arg_defs: &[(String, ScriptValue)],
) -> Result<ScriptArgument, String> {
    let trimmed = raw.trim();
    if let Some(inner) = trimmed.strip_prefix('{').and_then(|r| r.strip_suffix('}')) {
        let mut entries = Vec::new();
        for item in split_top_level(inner, b',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            if let Some(name) = item.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
                let value = arg_defs
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.clone())
                    .ok_or_else(|| format!("unknown script argument '${{{name}}}'"))?;
                entries.push((name.to_owned(), value));
            } else if let Some((k, v)) = item.split_once(':').or_else(|| item.split_once('=')) {
                let key = unquote(k.trim()).to_owned();
                if key.is_empty() {
                    return Err(format!("empty script argument key: {item}"));
                }
                entries.push((key, parse_dsl_typed_value(v, arg_defs)?));
            } else {
                return Err(format!("invalid script argument entry: {item}"));
            }
        }
        Ok(ScriptArgument::Object(entries))
    } else {
        parse_string_literal(trimmed)
            .map(ScriptArgument::Text)
            .map_err(|()| format!("invalid script argument: {trimmed}"))
    }
}

type PipedHeaders = (Option<String>, Vec<(String, String)>);

fn dsl_pipe_headers(stages: &[&str]) -> Result<PipedHeaders, String> {
    let mut content_type = None;
    let mut headers = Vec::new();
    for stage in stages {
        let (func, args, after) = parse_dsl_call(stage)?;
        if !after.is_empty() || args.len() != 2 {
            return Err(format!("invalid piped header action: {stage}"));
        }
        if !matches!(
            func.to_ascii_lowercase().as_str(),
            "response.header.set"
                | "response.header.add"
                | "request.header.set"
                | "request.header.add"
                | "header.set"
                | "header.add"
        ) {
            return Err(format!("unsupported piped action after mock: {func}"));
        }
        let name =
            parse_string_literal(args[0]).map_err(|()| "invalid piped header name".to_owned())?;
        let value =
            parse_string_literal(args[1]).map_err(|()| "invalid piped header value".to_owned())?;
        if name.eq_ignore_ascii_case("content-type") {
            content_type = Some(value);
        } else {
            headers.push((name, value));
        }
    }
    Ok((content_type, headers))
}

fn parse_dsl_status(raw: &str) -> Result<u16, String> {
    let status = parse_dsl_value(raw)
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|s| (100..=599).contains(s))
        .ok_or_else(|| format!("invalid HTTP status code: {raw}"))?;
    Ok(status)
}

#[allow(clippy::too_many_arguments)]
fn parse_dsl_single_action(
    default_phase: Phase,
    pattern: &str,
    alias: Option<&str>,
    conditions: &[Condition],
    stage: &str,
    pipe_tail: &[&str],
    number: usize,
    arg_defs: &[(String, ScriptValue)],
) -> Result<Option<Rule>, String> {
    let (func, args, after) = parse_dsl_call(stage)?;
    let func_lower = func.to_ascii_lowercase();

    if func_lower == "script" {
        if !pipe_tail.is_empty() || args.is_empty() || args.len() > 2 {
            return Err("invalid script(...) arguments".to_owned());
        }
        let url =
            parse_string_literal(args[0]).map_err(|()| "invalid script URL literal".to_owned())?;
        let argument = args
            .get(1)
            .map(|raw| parse_dsl_script_argument(raw, arg_defs))
            .transpose()?;
        let options = if after.is_empty() {
            Vec::new()
        } else {
            let rest = after
                .get(..4)
                .filter(|w| w.eq_ignore_ascii_case("with"))
                .and_then(|_| after[4..].strip_prefix(|c: char| c.is_ascii_whitespace()))
                .ok_or_else(|| format!("invalid script options: {after}"))?;
            split_outside_quotes(rest, ',')
                .into_iter()
                .filter_map(|o| {
                    o.split_once('=').map(|(k, v)| {
                        (
                            k.trim().to_ascii_lowercase().replace('_', "-"),
                            unquote(v).to_owned(),
                        )
                    })
                })
                .collect()
        };
        return build_script(
            default_phase,
            pattern.to_owned(),
            conditions.to_vec(),
            url,
            &options,
            argument,
            number,
        )
        .map_err(|()| "invalid script URL".to_owned());
    }

    if !after.is_empty() {
        return Err(format!("unexpected trailing tokens: {after}"));
    }

    let make = |phase, action| {
        Ok(Some(Rule {
            pattern: pattern.to_owned(),
            phase,
            conditions: conditions.to_vec(),
            pipe_continuation: false,
            action,
            line: number,
        }))
    };

    match func_lower.as_str() {
        "reject" => {
            if args.len() > 2 {
                return Err("reject expects at most 2 arguments".to_owned());
            }
            let status = match args.first() {
                Some(raw) => parse_dsl_status(raw)?,
                None => 404,
            };
            let body = args
                .get(1)
                .map(|raw| parse_string_literal(raw))
                .transpose()
                .map_err(|()| "invalid reject body literal".to_owned())?;
            match (status, body) {
                (404, None) => make(Phase::Request, Action::Reject(Reject::NotFound)),
                (200, None) => make(Phase::Request, Action::Reject(Reject::Empty)),
                (status, body) => make(
                    Phase::Request,
                    Action::Mock(Mock {
                        status,
                        content_type: "text/plain; charset=utf-8".into(),
                        body: MockBody::Inline(body.unwrap_or_default().into_bytes()),
                        headers: Vec::new(),
                    }),
                ),
            }
        }
        "reject_200" | "reject-200" => {
            let status = args
                .first()
                .map(|s| parse_dsl_status(s))
                .transpose()?
                .unwrap_or(200);
            if status == 200 {
                make(Phase::Request, Action::Reject(Reject::Empty))
            } else {
                make(
                    Phase::Request,
                    Action::Mock(Mock {
                        status,
                        content_type: "text/plain; charset=utf-8".into(),
                        body: MockBody::Inline(Vec::new()),
                        headers: Vec::new(),
                    }),
                )
            }
        }
        "reject_video" | "reject-video" => Err("unsupported action: reject_video".to_owned()),
        "reject_img" | "reject-img" | "reject_tinygif" | "reject-tinygif" => {
            let status = args
                .first()
                .map(|s| parse_dsl_status(s))
                .transpose()?
                .unwrap_or(200);
            if status == 200 {
                make(Phase::Request, Action::Reject(Reject::Image))
            } else {
                make(
                    Phase::Request,
                    Action::Mock(Mock {
                        status,
                        content_type: "image/gif".into(),
                        body: MockBody::Inline(TINY_GIF.to_vec()),
                        headers: Vec::new(),
                    }),
                )
            }
        }
        "reject_dict" | "reject-dict" => {
            let status = args
                .first()
                .map(|s| parse_dsl_status(s))
                .transpose()?
                .unwrap_or(200);
            if status == 200 {
                make(Phase::Request, Action::Reject(Reject::Dict))
            } else {
                make(
                    Phase::Request,
                    Action::Mock(Mock {
                        status,
                        content_type: "application/json".into(),
                        body: MockBody::Inline(b"{}".to_vec()),
                        headers: Vec::new(),
                    }),
                )
            }
        }
        "reject_array" | "reject-array" => {
            let status = args
                .first()
                .map(|s| parse_dsl_status(s))
                .transpose()?
                .unwrap_or(200);
            if status == 200 {
                make(Phase::Request, Action::Reject(Reject::Array))
            } else {
                make(
                    Phase::Request,
                    Action::Mock(Mock {
                        status,
                        content_type: "application/json".into(),
                        body: MockBody::Inline(b"[]".to_vec()),
                        headers: Vec::new(),
                    }),
                )
            }
        }
        "reject_drop" | "reject-drop" | "reject_no_drop" | "reject-no-drop" => {
            make(Phase::Request, Action::Reject(Reject::Drop))
        }
        "redirect" => {
            if args.len() != 2 {
                return Err("redirect expects 2 arguments".to_owned());
            }
            let status = parse_dsl_status(args[0])?;
            if !matches!(status, 301 | 302 | 307 | 308) {
                return Err(format!("unsupported redirect status {status}"));
            }
            let location = apply_capture_alias(
                parse_string_literal(args[1])
                    .map_err(|()| "invalid redirect location".to_owned())?,
                alias,
            );
            make(Phase::Request, Action::Redirect { status, location })
        }
        "url.replace" => {
            if args.len() != 1 {
                return Err("url.replace expects 1 argument".to_owned());
            }
            let location = apply_capture_alias(
                parse_string_literal(args[0])
                    .map_err(|()| "invalid url.replace target".to_owned())?,
                alias,
            );
            make(Phase::Request, Action::UrlReplace(location))
        }
        "response.body.mock" => {
            if args.len() < 2 || args.len() > 4 {
                return Err("response.body.mock expects 2..=4 arguments".to_owned());
            }
            let kind =
                parse_string_literal(args[0]).map_err(|()| "invalid mock data type".to_owned())?;
            let data = parse_string_literal(args[1])
                .map_err(|()| "invalid mock body literal".to_owned())?;
            let status = args
                .get(2)
                .map(|s| parse_dsl_status(s))
                .transpose()?
                .unwrap_or(200);
            let is_base64 = args
                .get(3)
                .is_some_and(|s| parse_dsl_value(s).is_ok_and(|v| v.eq_ignore_ascii_case("true")));
            let (content_type_override, headers) = dsl_pipe_headers(pipe_tail)?;
            let mock = mock_from_parts(
                &kind,
                &data,
                status,
                is_base64,
                content_type_override.as_deref(),
                headers,
            )
            .map_err(|()| "invalid mock response definition".to_owned())?;
            make(Phase::Request, Action::Mock(mock))
        }
        "response.body.mock_file" => {
            if args.len() < 2 || args.len() > 3 {
                return Err("response.body.mock_file expects 2..=3 arguments".to_owned());
            }
            let kind = parse_string_literal(args[0])
                .map_err(|()| "invalid mock_file data type".to_owned())?
                .to_ascii_lowercase();
            let url = remote(
                parse_string_literal(args[1]).map_err(|()| "invalid mock_file URL".to_owned())?,
            )
            .map_err(|()| "mock_file URL must be http(s)".to_owned())?;
            let status = args
                .get(2)
                .map(|s| parse_dsl_status(s))
                .transpose()?
                .unwrap_or(200);
            let default_type =
                mock_content_type(&kind).map_err(|()| format!("unsupported mock type '{kind}'"))?;
            let (content_type_override, headers) = dsl_pipe_headers(pipe_tail)?;
            make(
                Phase::Request,
                Action::Mock(Mock {
                    status,
                    content_type: content_type_override.unwrap_or_else(|| default_type.to_owned()),
                    body: MockBody::Remote(url),
                    headers,
                }),
            )
        }
        "response.json.jq" | "request.json.jq" => {
            if args.len() != 1 {
                return Err("json.jq expects 1 argument".to_owned());
            }
            let phase = if func_lower.starts_with("request.") {
                Phase::Request
            } else {
                Phase::Response
            };
            let filter =
                parse_string_literal(args[0]).map_err(|()| "invalid jq literal".to_owned())?;
            let filter = filter.trim();
            if filter.is_empty() {
                return Err("empty jq filter".to_owned());
            }
            make(phase, Action::Jq(filter.to_owned()))
        }
        "response.json.delete" | "request.json.delete" => {
            if args.len() != 1 {
                return Err("json.delete expects 1 argument".to_owned());
            }
            let phase = if func_lower.starts_with("request.") {
                Phase::Request
            } else {
                Phase::Response
            };
            let paths = parse_dsl_string_list(args[0])
                .map_err(|()| "invalid json.delete paths".to_owned())?
                .into_iter()
                .map(|p| json_path(&p))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|()| "invalid json path".to_owned())?;
            make(phase, Action::JsonDelete(paths))
        }
        "response.json.replace"
        | "response.json.add"
        | "request.json.replace"
        | "request.json.add" => {
            if args.len() != 2 {
                return Err("json.replace/add expects 2 arguments".to_owned());
            }
            let phase = if func_lower.starts_with("request.") {
                Phase::Request
            } else {
                Phase::Response
            };
            let pairs = if args[0].trim().starts_with('[') {
                let paths = parse_dsl_string_list(args[0])
                    .map_err(|()| "invalid json path list".to_owned())?;
                let inner_vals = args[1]
                    .trim()
                    .strip_prefix('[')
                    .and_then(|r| r.strip_suffix(']'))
                    .ok_or_else(|| "expected JSON value array".to_owned())?;
                let vals = split_top_level(inner_vals, b',')
                    .into_iter()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(parse_dsl_value)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|()| "invalid JSON value".to_owned())?;
                if paths.len() != vals.len() {
                    return Err("json path and value arrays differ in length".to_owned());
                }
                paths
                    .into_iter()
                    .zip(vals)
                    .map(|(p, v)| Ok((json_path(&p)?, v)))
                    .collect::<Result<Vec<_>, ()>>()
                    .map_err(|()| "invalid json path".to_owned())?
            } else {
                vec![(
                    json_path(
                        &parse_string_literal(args[0])
                            .map_err(|()| "invalid json path literal".to_owned())?,
                    )
                    .map_err(|()| "invalid json path".to_owned())?,
                    parse_dsl_value(args[1]).map_err(|()| "invalid json value".to_owned())?,
                )]
            };
            make(phase, Action::JsonSet(pairs))
        }
        "response.body.replace" | "request.body.replace" => {
            if args.len() != 2 {
                return Err("body.replace expects 2 arguments".to_owned());
            }
            let phase = if func_lower.starts_with("request.") {
                Phase::Request
            } else {
                Phase::Response
            };
            let regex = if args[0].trim_start().starts_with('/') {
                let (pattern, tail) = parse_regex_literal(args[0])?;
                if !tail.trim().is_empty() {
                    return Err("unexpected tokens after body.replace regex".to_owned());
                }
                pattern
            } else {
                parse_string_literal(args[0])
                    .map_err(|()| "invalid body.replace target".to_owned())?
            };
            let replacement = parse_string_literal(args[1])
                .map_err(|()| "invalid body.replace replacement".to_owned())?;
            make(phase, Action::BodyReplace(vec![(regex, replacement)]))
        }
        op if op.starts_with("request.header.")
            || op.starts_with("response.header.")
            || op.starts_with("header.") =>
        {
            let (phase, action) = if let Some(action) = op.strip_prefix("request.header.") {
                (Phase::Request, action)
            } else if let Some(action) = op.strip_prefix("response.header.") {
                (Phase::Response, action)
            } else {
                (default_phase, op.strip_prefix("header.").unwrap())
            };
            let header_op = match action {
                "add" => {
                    if args.len() != 2 {
                        return Err("header.add expects 2 arguments".to_owned());
                    }
                    HeaderOp::Add(
                        parse_string_literal(args[0])
                            .map_err(|()| "invalid header name".to_owned())?,
                        parse_string_literal(args[1])
                            .map_err(|()| "invalid header value".to_owned())?,
                    )
                }
                "set" => {
                    if args.len() != 2 {
                        return Err("header.set expects 2 arguments".to_owned());
                    }
                    HeaderOp::Set(
                        parse_string_literal(args[0])
                            .map_err(|()| "invalid header name".to_owned())?,
                        parse_string_literal(args[1])
                            .map_err(|()| "invalid header value".to_owned())?,
                    )
                }
                "replace" if args.len() == 2 => HeaderOp::Replace(
                    parse_string_literal(args[0]).map_err(|()| "invalid header name".to_owned())?,
                    parse_string_literal(args[1])
                        .map_err(|()| "invalid header value".to_owned())?,
                ),
                "replace" | "replace_regex" if args.len() == 3 => {
                    let pattern = if args[1].trim_start().starts_with('/') {
                        let (p, tail) = parse_regex_literal(args[1])?;
                        if !tail.trim().is_empty() {
                            return Err("unexpected tokens after header.replace regex".to_owned());
                        }
                        p
                    } else {
                        parse_string_literal(args[1])
                            .map_err(|()| "invalid header.replace regex".to_owned())?
                    };
                    HeaderOp::ReplaceRegex(
                        parse_string_literal(args[0])
                            .map_err(|()| "invalid header name".to_owned())?,
                        pattern,
                        parse_string_literal(args[2])
                            .map_err(|()| "invalid header replacement".to_owned())?,
                    )
                }
                "del" | "delete" => {
                    if args.len() != 1 {
                        return Err("header.del expects 1 argument".to_owned());
                    }
                    HeaderOp::Delete(
                        parse_string_literal(args[0])
                            .map_err(|()| "invalid header name".to_owned())?,
                    )
                }
                _ => return Err(format!("unsupported header action: {op}")),
            };
            make(phase, Action::Header(header_op))
        }
        other => Err(format!("unsupported action: {other}")),
    }
}

fn dsl_line(
    line: &str,
    number: usize,
    arg_defs: &[(String, ScriptValue)],
) -> Result<Vec<Rule>, String> {
    let (default_phase, rest) =
        strip_dsl_phase(line).ok_or_else(|| "invalid DSL prefix".to_owned())?;
    let (cond, action_str) =
        split_dsl_then(rest).ok_or_else(|| "missing 'then' clause".to_owned())?;
    let (pattern, alias, conditions) = parse_dsl_condition(cond)?;
    let stages = split_top_level(action_str, b'|');
    let first_stage = stages
        .first()
        .ok_or_else(|| "missing action after 'then'".to_owned())?;
    let (first_func, _, _) = parse_dsl_call(first_stage)?;
    let first_lower = first_func.to_ascii_lowercase();

    if stages.len() > 1
        && matches!(
            first_lower.as_str(),
            "response.body.mock" | "response.body.mock_file"
        )
    {
        return parse_dsl_single_action(
            default_phase,
            &pattern,
            alias,
            &conditions,
            first_stage,
            &stages[1..],
            number,
            arg_defs,
        )
        .map(|rule| rule.into_iter().collect());
    }

    let mut rules = Vec::with_capacity(stages.len());
    for (idx, stage) in stages.iter().enumerate() {
        let stage_conditions = if idx == 0 { conditions.as_slice() } else { &[] };
        if let Some(mut rule) = parse_dsl_single_action(
            default_phase,
            &pattern,
            alias,
            stage_conditions,
            stage,
            &[],
            number,
            arg_defs,
        )? {
            if idx > 0 {
                if rules
                    .first()
                    .is_some_and(|first: &Rule| first.phase != rule.phase)
                {
                    return Err("mixed request/response phases in piped action".to_owned());
                }
                rule.pipe_continuation = true;
            }
            rules.push(rule);
        }
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_surge_modules() {
        let module = parse_module(
            r#"#!name=Ads
#!desc=Removes ads
#!arguments=hide:true
[Rule]
DOMAIN,ad.example.com,REJECT
DOMAIN-SUFFIX,track.test,REJECT-DROP
DOMAIN,keep.test,DIRECT
AND,((DOMAIN,x.test),(PROTOCOL,QUIC)),REJECT
[URL Rewrite]
^https?:\/\/api\.test\/ad - reject
^https?:\/\/api\.test\/splash - reject-dict
^http:\/\/old\.test\/(.*) https://new.test/$1 302
[Header Rewrite]
http-request ^https://api\.test/ header-del X-Ad
^https://api\.test/ header-add X-Flag {{{hide}}}
[Body Rewrite]
http-response ^https://api\.test/feed "ad":true "ad":false
http-response-jq ^https://api\.test/home 'del(.data.banner, .data.list[].ad)'
[Map Local]
^https://api\.test/config data-type=json data="{\"ads\":[]}" status-code=200 header="X-A:1|X-B:2"
^https://img\.test/ad data-type=tiny-gif data=""
[Script]
feed = type=http-response,pattern=^https://api\.test/feed,requires-body=1,max-size=0,script-path=https://cdn.test/feed.js,argument="a=1,b=2"
cron = type=cron,cronexp="0 * * * *",script-path=https://cdn.test/cron.js
[MITM]
hostname = %APPEND% api.test, *.img.test, -skip.test
"#,
        );
        assert_eq!(module.name.as_deref(), Some("Ads"));
        assert_eq!(module.skipped, vec![]);
        assert_eq!(
            module.reject,
            vec![
                (DomainKind::Exact, "ad.example.com".into()),
                (DomainKind::Suffix, "track.test".into())
            ]
        );
        assert_eq!(module.hostnames, ["api.test", "*.img.test", "-skip.test"]);
        let actions: Vec<_> = module.rules.iter().map(|r| &r.action).collect();
        assert_eq!(actions[0], &Action::Reject(Reject::NotFound));
        assert_eq!(actions[1], &Action::Reject(Reject::Dict));
        assert_eq!(
            actions[2],
            &Action::Redirect {
                status: 302,
                location: "https://new.test/$1".into()
            }
        );
        assert_eq!(actions[3], &Action::Header(HeaderOp::Delete("X-Ad".into())));
        assert_eq!(
            actions[4],
            &Action::Header(HeaderOp::Add("X-Flag".into(), "true".into()))
        );
        assert_eq!(
            actions[5],
            &Action::BodyReplace(vec![("\"ad\":true".into(), "\"ad\":false".into())])
        );
        assert_eq!(
            actions[6],
            &Action::Jq("del(.data.banner, .data.list[].ad)".into())
        );
        let Action::Mock(mock) = actions[7] else {
            panic!()
        };
        assert_eq!(mock.body, MockBody::Inline(br#"{"ads":[]}"#.to_vec()));
        assert_eq!(mock.content_type, "application/json");
        assert_eq!(mock.headers.len(), 2);
        let Action::Mock(gif) = actions[8] else {
            panic!()
        };
        assert_eq!(gif.body, MockBody::Inline(TINY_GIF.to_vec()));
        let Action::Script(script) = actions[9] else {
            panic!()
        };
        assert_eq!(module.rules[9].phase, Phase::Response);
        assert_eq!(script.name, "feed");
        assert!(script.requires_body && !script.binary);
        assert_eq!(script.argument, ScriptArgument::Text("a=1,b=2".into()));
        assert_eq!(module.rules.len(), 10);
    }

    #[test]
    fn parses_loon_plugins_and_quantumult_snippets() {
        let module = parse_module(
            r#"#!name=Loon
[Argument]
mode = select,"lite","full",tag=Mode
[Rewrite]
^https?:\/\/a\.test\/ad reject-200
^https?:\/\/a\.test\/img reject-img
^https?:\/\/a\.test\/list response-body-json-del data.ads $.data.banner
^https?:\/\/a\.test\/cfg response-body-json-replace data.show false
^https?:\/\/a\.test\/r 302 https://b.test/
^https?:\/\/a\.test\/h response-header-del X-Ad
^https?:\/\/a\.test\/mock mock-response-body data-type=text data="ok" status-code=201
^https?:\/\/a\.test\/what unknown-action
[Script]
http-response ^https?:\/\/a\.test\/feed script-path=https://cdn.test/f.js, requires-body=true, binary-body-mode=true, timeout=20, tag=Feed, argument=[{{{mode}}}]
http-request ^https?:\/\/a\.test\/off script-path=https://cdn.test/o.js, enable=false
[MitM]
hostname = a.test
"#,
        );
        assert_eq!(module.skipped.len(), 1);
        assert_eq!(module.skipped[0].0, 12);
        let actions: Vec<_> = module.rules.iter().map(|r| r.action.clone()).collect();
        assert_eq!(actions[0], Action::Reject(Reject::Empty));
        assert_eq!(actions[1], Action::Reject(Reject::Image));
        assert_eq!(
            actions[2],
            Action::JsonDelete(vec!["data.ads".into(), "data.banner".into()])
        );
        assert_eq!(
            actions[3],
            Action::JsonSet(vec![("data.show".into(), "false".into())])
        );
        assert_eq!(module.rules[5].phase, Phase::Response);
        let Action::Mock(mock) = &actions[6] else {
            panic!()
        };
        assert_eq!(mock.status, 201);
        let Action::Script(script) = &actions[7] else {
            panic!()
        };
        assert_eq!(script.name, "Feed");
        assert!(script.binary && script.requires_body);
        assert_eq!(script.timeout, Some(20));
        assert_eq!(script.argument, ScriptArgument::Text("[lite]".into()));
        assert_eq!(module.rules.len(), 8);
        assert_eq!(module.hostnames, ["a.test"]);

        let quantumult = parse_module(
            "hostname = q.test\n\
             ^https?:\\/\\/q\\.test\\/ad url reject-dict\n\
             ^https?:\\/\\/q\\.test\\/feed url script-response-body https://cdn.test/q.js\n",
        );
        assert_eq!(quantumult.hostnames, ["q.test"]);
        assert_eq!(quantumult.rules[0].action, Action::Reject(Reject::Dict));
        let Action::Script(script) = &quantumult.rules[1].action else {
            panic!()
        };
        assert!(script.requires_body);
        assert_eq!(quantumult.rules[1].phase, Phase::Response);
    }

    #[test]
    fn settings_keep_enabled_modules() {
        let settings = Settings {
            enabled: true,
            modules: vec![
                ModuleSetting {
                    name: "a".into(),
                    url: "https://a.test/a.sgmodule".into(),
                    enabled: true,
                },
                ModuleSetting {
                    name: "b".into(),
                    url: "https://a.test/b.plugin".into(),
                    enabled: false,
                },
            ],
            custom: String::new(),
        };
        let config = settings.to_config().unwrap();
        assert_eq!(config.modules.len(), 1);
        assert!(
            Settings {
                modules: vec![ModuleSetting {
                    name: "x".into(),
                    url: "file:///etc/passwd".into(),
                    enabled: true
                }],
                ..Settings::default()
            }
            .to_config()
            .is_err()
        );
        assert_eq!(
            cache_file("https://a.test/x.js").len(),
            "rewrite/files/".len() + 20
        );
    }

    #[test]
    fn parses_loon_dsl_modules() {
        let module = parse_module(
            r#"#!name=LoonDSL
[Argument]
on_flag = switch,true,false,tag=On
off_flag = switch,false,true,tag=Off
mode = select,"show","hide",tag=Mode
filter_flag = switch,true,tag=Filter
[Rewrite]
request if ${url} ~= /^https?:\/\/a\.test\/r404$/i then reject(404)
request if ${url} ~= /^https?:\/\/a\.test\/r200$/i then reject(200)
request if ${url} ~= /^https?:\/\/a\.test\/r451$/i then reject(451, "blocked")
request if ${url} ~= /^https?:\/\/a\.test\/rdict$/i then reject_dict(200)
request if ${url} ~= /^https?:\/\/a\.test\/rdict403$/i then reject_dict(403)
request if ${url} ~= /^https?:\/\/a\.test\/rimg$/i then reject_img(200)
request if ${url} ~= /^(http:\/\/a\.test\/topic\?ad=)false(&x=\d)$/i as urlMatch then redirect(302, "${urlMatch.1}true${urlMatch.2}")
request if ${url} ~= /^https:\/\/a\.test\/(.*)&p=iphone/i as m then url.replace("https://a.test/${m.1}&p=ipad")
response if ${url} == "https://grpc.a.test/Method" then response.body.mock("text", "AAAA", 200, true) | response.header.set("grpc-status", "0")
response if ${url} ~= /^https?:\/\/a\.test\/mockfile/i then response.body.mock_file("json", "https://cdn.test/mock.json", 200)
response if ${url} ~= /^https:\/\/a\.test\/jq\?/ && ${response.status} == 200 then response.json.jq(`.dns[]? |= (.ips = [] | .ttl = 86400)`)
response if ${url} ~= /^https:\/\/a\.test\/del$/i then response.json.delete(["a.b", "c"])
response if ${url} ~= /^https:\/\/a\.test\/jset$/i then response.json.replace(["x", "y"], [false, null])
response if ${url} ~= /^https:\/\/a\.test\/brep$/i then response.body.replace(/^ad$/ms, "no")
request if ${url} ~= /^https:\/\/a\.test\/hdr$/ && ${request.method} == "POST" && ${request.header["X-In"]} == "1" then header.set("X-Out", "2") | header.replace("User-Agent", /Bot\/\d+/, "App/1") | header.del("X-Drop")
request if ${url} ~= /^https:\/\/a\.test\/vid$/ then reject_video()
request if ${url} ~= /^https:\/\/a\.test\/badflag$/u then reject(404)
request if ${url} ~= /^https:\/\/a\.test\/or$/ || ${request.method} == "GET" then reject(404)
[Script]
response if ${url} ~= /^https:\/\/a\.test\/s$/i then script("https://cdn.test/s.js", {${mode}, ${filter_flag}, level: 123}) with enable=${on_flag}, tag="S", timeout=10, requires_body=true, binary_body_mode=true
request if ${url} ~= /^https:\/\/a\.test\/off$/i then script("https://cdn.test/off.js") with enable=${off_flag}, tag="Off"
[MITM]
hostname = a.test, first.test.comhostname = second.test.com, -skip.test.com
"#,
        );
        assert_eq!(module.skipped.len(), 3);
        assert!(
            module.skipped[0]
                .1
                .contains("unsupported action: reject_video")
        );
        assert!(module.skipped[1].1.contains("unsupported regex flag 'u'"));
        assert!(
            module.skipped[2]
                .1
                .contains("unsupported logical OR condition")
        );
        assert_eq!(
            module.hostnames,
            [
                "a.test",
                "first.test.com",
                "second.test.com",
                "-skip.test.com"
            ]
        );
        assert_eq!(module.rules.len(), 18);
        let actions: Vec<_> = module.rules.iter().map(|r| &r.action).collect();
        assert_eq!(module.rules[0].pattern, r"(?i)^https?:\/\/a\.test\/r404$");
        assert_eq!(actions[0], &Action::Reject(Reject::NotFound));
        assert_eq!(actions[1], &Action::Reject(Reject::Empty));
        assert_eq!(
            actions[2],
            &Action::Mock(Mock {
                status: 451,
                content_type: "text/plain; charset=utf-8".into(),
                body: MockBody::Inline(b"blocked".to_vec()),
                headers: vec![],
            })
        );
        assert_eq!(actions[3], &Action::Reject(Reject::Dict));
        assert_eq!(
            actions[4],
            &Action::Mock(Mock {
                status: 403,
                content_type: "application/json".into(),
                body: MockBody::Inline(b"{}".to_vec()),
                headers: vec![],
            })
        );
        assert_eq!(actions[5], &Action::Reject(Reject::Image));
        assert_eq!(
            actions[6],
            &Action::Redirect {
                status: 302,
                location: "$1true$2".into(),
            }
        );
        assert_eq!(
            actions[7],
            &Action::UrlReplace("https://a.test/$1&p=ipad".into())
        );
        assert_eq!(module.rules[8].pattern, r"^https://grpc\.a\.test/Method$");
        let Action::Mock(grpc_mock) = actions[8] else {
            panic!()
        };
        assert_eq!(grpc_mock.status, 200);
        assert_eq!(grpc_mock.body, MockBody::Inline(vec![0, 0, 0]));
        assert_eq!(grpc_mock.headers, vec![("grpc-status".into(), "0".into())]);
        let Action::Mock(file_mock) = actions[9] else {
            panic!()
        };
        assert_eq!(
            file_mock.body,
            MockBody::Remote("https://cdn.test/mock.json".into())
        );
        assert_eq!(
            module.rules[10].conditions,
            vec![Condition::Status {
                equals: true,
                value: 200
            }]
        );
        assert_eq!(
            actions[10],
            &Action::Jq(".dns[]? |= (.ips = [] | .ttl = 86400)".into())
        );
        assert_eq!(
            actions[11],
            &Action::JsonDelete(vec!["a.b".into(), "c".into()])
        );
        assert_eq!(
            actions[12],
            &Action::JsonSet(vec![
                ("x".into(), "false".into()),
                ("y".into(), "null".into()),
            ])
        );
        assert_eq!(
            actions[13],
            &Action::BodyReplace(vec![("(?ms)^ad$".into(), "no".into())])
        );
        assert_eq!(
            module.rules[14].conditions,
            vec![
                Condition::Method {
                    equals: true,
                    value: "POST".into()
                },
                Condition::RequestHeader {
                    name: "X-In".into(),
                    op: MatchOp::Equals("1".into())
                }
            ]
        );
        assert_eq!(
            actions[14],
            &Action::Header(HeaderOp::Set("X-Out".into(), "2".into()))
        );
        assert_eq!(
            actions[15],
            &Action::Header(HeaderOp::ReplaceRegex(
                "User-Agent".into(),
                r"Bot\/\d+".into(),
                "App/1".into()
            ))
        );
        assert_eq!(
            actions[16],
            &Action::Header(HeaderOp::Delete("X-Drop".into()))
        );
        assert_eq!(module.rules[17].phase, Phase::Response);
        let Action::Script(script) = actions[17] else {
            panic!()
        };
        assert_eq!(script.name, "S");
        assert_eq!(script.url, "https://cdn.test/s.js");
        assert_eq!(
            script.argument,
            ScriptArgument::Object(vec![
                ("mode".into(), ScriptValue::String("show".into())),
                ("filter_flag".into(), ScriptValue::Bool(true)),
                ("level".into(), ScriptValue::Number("123".into())),
            ])
        );
        assert_eq!(script.timeout, Some(10));
        assert!(script.requires_body && script.binary);
    }

    #[test]
    fn parses_mitm_ports_qx_body_header_and_surge_http_prefixed_script() {
        let module = parse_module(
            r#"[Rewrite]
^https://a\.test/req url request-body "a":1 request-body "a":0
^https://a\.test/hdr url request-header (\r\n)User-Agent:.* request-header (\r\n)User-Agent: Custom
^https://a\.test/del url response-header (\r\n)X-Ad:.* response-header
^https://a\.test/js url script-response-body https://cdn.test/b.js binary-body-mode=true timeout=15 max-size=65536
[Script]
http-request-rewrite = type=http-response,pattern=^https://a\.test/s,requires-body=1,script-path=https://cdn.test/s.js
[MITM]
hostname = %APPEND% api.test:443, *.img.test:8443, zero.test:0, [2001:db8::1]:443, 2001:db8::2
"#,
        );
        assert!(module.skipped.is_empty(), "{:?}", module.skipped);
        assert_eq!(
            module.hostnames,
            [
                "api.test",
                "*.img.test",
                "zero.test",
                "[2001:db8::1]",
                "2001:db8::2"
            ]
        );
        assert_eq!(module.rules[0].phase, Phase::Request);
        assert_eq!(
            module.rules[0].action,
            Action::BodyReplace(vec![("\"a\":1".into(), "\"a\":0".into())])
        );
        assert_eq!(module.rules[1].phase, Phase::Request);
        assert_eq!(
            module.rules[1].action,
            Action::Header(HeaderOp::ReplaceRegex(
                "User-Agent".into(),
                ".*".into(),
                "Custom".into()
            ))
        );
        assert_eq!(module.rules[2].phase, Phase::Response);
        assert_eq!(
            module.rules[2].action,
            Action::Header(HeaderOp::Delete("X-Ad".into()))
        );
        let Action::Script(qx_script) = &module.rules[3].action else {
            panic!()
        };
        assert!(qx_script.binary && qx_script.requires_body);
        assert_eq!(qx_script.timeout, Some(15));
        assert_eq!(qx_script.max_size, Some(65536));
        assert_eq!(module.rules[4].phase, Phase::Response);
        let Action::Script(surge_script) = &module.rules[4].action else {
            panic!()
        };
        assert_eq!(surge_script.name, "http-request-rewrite");
    }
}
