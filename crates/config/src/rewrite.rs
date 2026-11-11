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
        format!("rewrite/{}.module", safe_name(&self.name))
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
    use sha1::Digest;
    let digest = sha1::Sha1::digest(url.as_bytes());
    let hex: String = digest.iter().take(10).map(|b| format!("{b:02x}")).collect();
    format!("rewrite/files/{hex}")
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
                    && names.insert(module.file_name()),
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
    pub action: Action,
    /// Its line in the module, for status and the request log.
    pub line: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Reject(Reject),
    /// `$1`… in the location refer to the pattern's groups.
    Redirect {
        status: u16,
        location: String,
    },
    Header(HeaderOp),
    /// Regex and replacement pairs, applied in order to the body as text.
    BodyReplace(Vec<(String, String)>),
    /// JSON paths to delete (`a.b`, `a[0]`, `a[].b`).
    JsonDelete(Vec<String>),
    /// JSON paths and the JSON values to put there.
    JsonSet(Vec<(String, String)>),
    Mock(Mock),
    Script(Script),
}
impl Action {
    /// A short name for the request log.
    pub fn kind(&self) -> String {
        match self {
            Action::Reject(reject) => reject.name().into(),
            Action::Redirect { status, .. } => status.to_string(),
            Action::Header(_) => "header".into(),
            Action::BodyReplace(_) => "body".into(),
            Action::JsonDelete(_) | Action::JsonSet(_) => "json".into(),
            Action::Mock(_) => "mock".into(),
            Action::Script(script) => format!("script {}", script.name),
        }
    }
    /// Whether it needs the whole body of its phase.
    pub fn needs_body(&self) -> bool {
        match self {
            Action::BodyReplace(_) | Action::JsonDelete(_) | Action::JsonSet(_) => true,
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
            "reject-200" | "reject-video" => Reject::Empty,
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
    pub argument: String,
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
    let text = substitute_arguments(text);
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
        let parsed = match section {
            Section::Ignored | Section::Argument | Section::None => Ok(()),
            Section::Mitm => {
                mitm_line(line, &mut module.hostnames);
                Ok(())
            }
            Section::Rule => rule_line(line, &mut module.reject),
            Section::Script => script_line(line, number).map(|rule| module.rules.extend(rule)),
            _ => rewrite_line(section, line, number).map(|rule| module.rules.push(rule)),
        };
        if parsed.is_err() && module.skipped.len() < SKIPPED_KEPT {
            module
                .skipped
                .push((number, line.chars().take(200).collect()));
        }
    }
    module
}

/// Fills `{{{name}}}` with the defaults of Surge `#!arguments=` and Loon
/// `[Argument]`.
fn substitute_arguments(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.contains("{{{") {
        return text.into();
    }
    let mut values: Vec<(String, String)> = Vec::new();
    let mut in_argument = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(arguments) = line.strip_prefix("#!arguments=") {
            for item in split_outside_quotes(arguments, ',') {
                if let Some((key, value)) = item.split_once(':') {
                    values.push((key.trim().into(), unquote(value.trim()).into()));
                }
            }
        } else if line.starts_with('[') {
            in_argument = line.eq_ignore_ascii_case("[argument]");
        } else if in_argument && let Some((key, rest)) = line.split_once('=') {
            // `name = switch,true,false,tag=…` / `name = input,"value",tag=…`:
            // the default is the first value.
            let fields = split_outside_quotes(rest, ',');
            if let Some(value) = fields.get(1) {
                values.push((key.trim().into(), unquote(value.trim()).into()));
            }
        }
    }
    let mut out = text.to_owned();
    for (key, value) in values {
        out = out.replace(&format!("{{{{{{{key}}}}}}}"), &value);
    }
    out.into()
}

fn mitm_line(line: &str, hosts: &mut Vec<String>) {
    let Some((key, value)) = line.split_once('=') else {
        return;
    };
    if !key.trim().eq_ignore_ascii_case("hostname") {
        return;
    }
    for host in value.split(',') {
        let host = host
            .trim()
            .trim_start_matches("%APPEND%")
            .trim_start_matches("%INSERT%")
            .trim();
        if !host.is_empty() && host.len() <= 253 && !host.starts_with('%') {
            hosts.push(host.to_ascii_lowercase());
        }
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
                let filter = tokens.join(" ");
                return rule(pattern, phase, Action::JsonDelete(jq_delete(&filter)?));
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
        "response-body-replace-regex" | "request-body-replace-regex" | "response-body" => {
            // Quantumult X: `response-body regex response-body replacement`.
            let rest: Vec<String> = rest
                .iter()
                .filter(|t| *t != "response-body")
                .cloned()
                .collect();
            (
                if word == "request-body-replace-regex" {
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
        "mock-response-body" => (Phase::Request, Action::Mock(mock(rest)?)),
        "script-response-body"
        | "script-request-body"
        | "script-response-header"
        | "script-request-header"
        | "script-echo-response" => {
            let url = first()?;
            let phase = if word.contains("response") && word != "script-echo-response" {
                Phase::Response
            } else {
                Phase::Request
            };
            (
                phase,
                Action::Script(Script {
                    name: script_name(&url, number),
                    url: remote(url)?,
                    requires_body: word.ends_with("-body"),
                    binary: false,
                    max_size: None,
                    timeout: None,
                    argument: String::new(),
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

/// The one jq form that is common in ad modules: `del(.a, .b.c)`.
fn jq_delete(filter: &str) -> Result<Vec<String>, ()> {
    let filter = unquote(filter.trim());
    let inner = filter
        .strip_prefix("del(")
        .and_then(|f| f.strip_suffix(')'))
        .ok_or(())?;
    inner
        .split(',')
        .map(|p| {
            let p = p.trim();
            if !p.starts_with('.') || p.contains(['(', '|', ' ', '"']) {
                return Err(());
            }
            json_path(p)
        })
        .collect()
}

fn mock(tokens: &[String]) -> Result<Mock, ()> {
    let options = options(tokens);
    let kind = option(&options, "data-type")
        .unwrap_or("text")
        .to_ascii_lowercase();
    let status = option(&options, "status-code")
        .map(|s| s.parse::<u16>().map_err(|_| ()))
        .transpose()?
        .unwrap_or(200);
    if !(100..=599).contains(&status) {
        return Err(());
    }
    let data = option(&options, "data").unwrap_or("");
    let (content_type, body) = match kind.as_str() {
        "tiny-gif" | "gif" if data.is_empty() || kind == "tiny-gif" => {
            ("image/gif", MockBody::Inline(TINY_GIF.to_vec()))
        }
        "base64" | "gif" => {
            use base64::Engine;
            if data.starts_with("http://") || data.starts_with("https://") {
                ("application/octet-stream", MockBody::Remote(data.into()))
            } else {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .map_err(|_| ())?;
                ("application/octet-stream", MockBody::Inline(bytes))
            }
        }
        "json" | "text" | "html" | "css" | "javascript" => {
            let content_type = match kind.as_str() {
                "json" => "application/json",
                "html" => "text/html; charset=utf-8",
                "css" => "text/css",
                "javascript" => "application/javascript",
                _ => "text/plain; charset=utf-8",
            };
            if data.starts_with("http://") || data.starts_with("https://") {
                (content_type, MockBody::Remote(data.into()))
            } else {
                (content_type, MockBody::Inline(data.as_bytes().to_vec()))
            }
        }
        _ => return Err(()),
    };
    let mut headers = Vec::new();
    if let Some(list) = option(&options, "header") {
        for item in list.split('|') {
            if let Some((name, value)) = item.split_once(':') {
                headers.push((name.trim().to_owned(), value.trim().to_owned()));
            }
        }
    }
    Ok(Mock {
        status,
        content_type: option(&options, "content-type")
            .unwrap_or(content_type)
            .to_owned(),
        body,
        headers,
    })
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

/// Surge: `name = type=http-response,pattern=…,script-path=…,requires-body=1`.
/// Loon: `http-response pattern script-path=…, requires-body=true, tag=name`.
/// Other script types (cron, generic, dns…) are skipped quietly.
fn script_line(line: &str, number: usize) -> Result<Option<Rule>, ()> {
    let lower = line.to_ascii_lowercase();
    let (phase, pattern, options) =
        if lower.starts_with("http-request") || lower.starts_with("http-response") {
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
    if option(&options, "enable").is_some_and(|v| v.eq_ignore_ascii_case("false")) {
        return Ok(None);
    }
    let url = option(&options, "script-path").ok_or(())?.to_owned();
    let url = remote(url)?;
    let name = option(&options, "tag")
        .filter(|t| !t.is_empty())
        .map_or_else(|| script_name(&url, number), str::to_owned);
    let number_option =
        |key| option(&options, key).and_then(|v: &str| v.trim().parse::<u64>().ok());
    Ok(Some(Rule {
        pattern,
        phase,
        action: Action::Script(Script {
            name,
            url,
            requires_body: truthy(option(&options, "requires-body")),
            binary: truthy(option(&options, "binary-body-mode")),
            max_size: number_option("max-size").filter(|s| *s > 0),
            timeout: number_option("timeout").filter(|t| *t > 0),
            argument: option(&options, "argument").unwrap_or("").to_owned(),
        }),
        line: number,
    }))
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
            &Action::JsonDelete(vec!["data.banner".into(), "data.list[].ad".into()])
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
        assert_eq!(script.argument, "a=1,b=2");
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
        assert_eq!(script.argument, "[lite]");
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
}
