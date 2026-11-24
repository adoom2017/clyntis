//! Share-link parser and minimal profile builder (`vless://`, `hysteria2://`, `hy2://`).
//!
//! Parses single links, multi-line lists, or Base64-encoded subscriptions into
//! minimal `proxies:` YAML profiles that rely on `auto` GeoIP/GeoSite routing.

use crate::auto::{AutoRouting, is_routable, should_auto_route};
use crate::{Config, Proxy, ProxyKind};
use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use std::collections::{BTreeMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSummary {
    pub name: String,
    pub kind: String,
    pub server: String,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedLink {
    pub line: usize,
    pub scheme: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodesImport {
    pub yaml: String,
    pub nodes: Vec<NodeSummary>,
    pub skipped: Vec<SkippedLink>,
    pub auto_routing: AutoRouting,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileNodes {
    pub is_auto: bool,
    pub auto_routing: Option<AutoRouting>,
    pub nodes: Vec<NodeSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodesExport {
    pub text: String,
    pub count: usize,
    pub encrypted: bool,
}

/// Decodes percent-encoded UTF-8 (`%XX` and `+` in query values).
fn percent_decode(input: &str, plus_as_space: bool) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' if plus_as_space => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

struct ParsedUri<'a> {
    scheme: String,
    userinfo: String,
    host: String,
    port: u16,
    query: BTreeMap<String, String>,
    fragment: Option<String>,
    _marker: std::marker::PhantomData<&'a str>,
}

fn split_uri(raw: &str) -> Result<ParsedUri<'_>> {
    let (scheme_raw, rest) = raw
        .split_once("://")
        .context("missing URI scheme (expected vless:// or hysteria2://)")?;
    let scheme = scheme_raw.trim().to_ascii_lowercase();
    ensure!(!scheme.is_empty(), "empty URI scheme");

    let (before_frag, fragment) = match rest.split_once('#') {
        Some((head, frag)) => {
            let decoded = percent_decode(frag.trim(), false);
            let decoded = decoded.trim().to_owned();
            (head, (!decoded.is_empty()).then_some(decoded))
        }
        None => (rest, None),
    };

    let (before_query, query_raw) = match before_frag.split_once('?') {
        Some((head, q)) => (head, q),
        None => (before_frag, ""),
    };

    let (userinfo_raw, hostport_and_path) = before_query
        .rsplit_once('@')
        .context("missing user credential before '@'")?;
    let userinfo = percent_decode(userinfo_raw, false);
    ensure!(!userinfo.is_empty(), "empty user credential");

    // Strip optional path after authority (e.g. `host:443/`).
    let hostport = hostport_and_path
        .split('/')
        .next()
        .unwrap_or(hostport_and_path);
    let default_hy2_port = matches!(scheme.as_str(), "hysteria2" | "hy2");

    let (host, port_str) = if let Some(rest) = hostport.strip_prefix('[') {
        let (addr, after) = rest
            .split_once(']')
            .context("unclosed IPv6 bracket in host")?;
        let port = if after.is_empty() && default_hy2_port {
            "443"
        } else {
            after
                .strip_prefix(':')
                .context("missing port after IPv6 host")?
        };
        (addr.trim().to_owned(), port.trim())
    } else if let Some((addr, port)) = hostport.rsplit_once(':') {
        (addr.trim().to_owned(), port.trim())
    } else if default_hy2_port {
        (hostport.trim().to_owned(), "443")
    } else {
        bail!("missing port");
    };
    ensure!(!host.is_empty(), "empty server host");
    let port: u16 = port_str.parse().context("invalid port number")?;
    ensure!(port > 0, "port must be 1..65535");

    let mut query = BTreeMap::new();
    for pair in query_raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(k, true).to_ascii_lowercase();
        let val = percent_decode(v, true);
        if !key.is_empty() {
            query.insert(key, val);
        }
    }

    Ok(ParsedUri {
        scheme,
        userinfo,
        host,
        port,
        query,
        fragment,
        _marker: std::marker::PhantomData,
    })
}

fn is_truthy(val: Option<&String>) -> bool {
    val.is_some_and(|v| {
        let v = v.trim();
        v == "1" || v.eq_ignore_ascii_case("true")
    })
}

fn valid_fingerprint(fp: &str) -> bool {
    matches!(
        fp,
        "firefox"
            | "chrome"
            | "safari"
            | "ios"
            | "android"
            | "edge"
            | "360"
            | "qq"
            | "random"
            | "randomized"
    )
}

fn dedup_name(preferred: String, used: &mut HashSet<String>) -> String {
    let base = preferred.trim();
    let base = if base.is_empty() { "Node" } else { base };
    if used.insert(base.to_owned()) {
        return base.to_owned();
    }
    for i in 2.. {
        let candidate = format!("{base} ({i})");
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }
    unreachable!()
}

fn parse_vless_mapping(uri: &ParsedUri<'_>, name: String) -> Result<(Mapping, NodeSummary)> {
    let mut map = Mapping::new();
    map.insert(Value::from("name"), Value::from(name.clone()));
    map.insert(Value::from("type"), Value::from("vless"));
    map.insert(Value::from("server"), Value::from(uri.host.clone()));
    map.insert(Value::from("port"), Value::from(uri.port));
    map.insert(Value::from("uuid"), Value::from(uri.userinfo.clone()));
    map.insert(Value::from("udp"), Value::from(true));

    let security = uri
        .query
        .get("security")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();

    let has_pbk = uri.query.get("pbk").is_some_and(|v| !v.trim().is_empty());
    if security == "reality" || has_pbk {
        let pbk = uri
            .query
            .get("pbk")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .context("REALITY node missing public-key (pbk)")?;
        map.insert(Value::from("tls"), Value::from(true));
        let mut reality = Mapping::new();
        reality.insert(Value::from("public-key"), Value::from(pbk));
        if let Some(sid) = uri
            .query
            .get("sid")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            reality.insert(Value::from("short-id"), Value::from(sid));
        }
        map.insert(Value::from("reality-opts"), Value::Mapping(reality));
    } else if security == "tls" {
        map.insert(Value::from("tls"), Value::from(true));
    }

    if is_truthy(
        uri.query
            .get("allowinsecure")
            .or_else(|| uri.query.get("insecure")),
    ) {
        map.insert(Value::from("skip-cert-verify"), Value::from(true));
    }

    if let Some(sni) = uri
        .query
        .get("sni")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        map.insert(Value::from("servername"), Value::from(sni));
    }

    if let Some(fp) = uri
        .query
        .get("fp")
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| valid_fingerprint(s))
    {
        map.insert(Value::from("client-fingerprint"), Value::from(fp));
    }

    if let Some(alpn) = uri.query.get("alpn").filter(|s| !s.trim().is_empty()) {
        let list: Vec<Value> = alpn
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(Value::from)
            .collect();
        if !list.is_empty() {
            map.insert(Value::from("alpn"), Value::Sequence(list));
        }
    }

    let net = uri
        .query
        .get("type")
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "tcp".into());
    ensure!(
        matches!(net.as_str(), "tcp" | "ws" | "grpc"),
        "unsupported VLESS transport {net}"
    );
    map.insert(Value::from("network"), Value::from(net.clone()));

    if let Some(flow) = uri.query.get("flow").map(|s| s.trim()) {
        let normalized = flow.strip_suffix("-udp443").unwrap_or(flow);
        if normalized == "xtls-rprx-vision" && net == "tcp" {
            map.insert(Value::from("flow"), Value::from("xtls-rprx-vision"));
        }
    }

    if net == "ws" {
        let mut ws = Mapping::new();
        let path = uri
            .query
            .get("path")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("/");
        ws.insert(Value::from("path"), Value::from(path));
        if let Some(host) = uri
            .query
            .get("host")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            let mut headers = Mapping::new();
            headers.insert(Value::from("Host"), Value::from(host));
            ws.insert(Value::from("headers"), Value::Mapping(headers));
        }
        map.insert(Value::from("ws-opts"), Value::Mapping(ws));
    } else if net == "grpc"
        && let Some(service) = uri
            .query
            .get("servicename")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
    {
        let mut grpc = Mapping::new();
        grpc.insert(Value::from("grpc-service-name"), Value::from(service));
        map.insert(Value::from("grpc-opts"), Value::Mapping(grpc));
    }

    if uri
        .query
        .get("packetencoding")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("xudp"))
    {
        map.insert(Value::from("packet-encoding"), Value::from("xudp"));
    }

    let summary = NodeSummary {
        name,
        kind: "vless".into(),
        server: uri.host.clone(),
        port: uri.port,
    };
    Ok((map, summary))
}

fn parse_hysteria2_mapping(uri: &ParsedUri<'_>, name: String) -> Result<(Mapping, NodeSummary)> {
    let mut map = Mapping::new();
    map.insert(Value::from("name"), Value::from(name.clone()));
    map.insert(Value::from("type"), Value::from("hysteria2"));
    map.insert(Value::from("server"), Value::from(uri.host.clone()));
    map.insert(Value::from("port"), Value::from(uri.port));
    map.insert(Value::from("password"), Value::from(uri.userinfo.clone()));
    map.insert(Value::from("udp"), Value::from(true));

    if let Some(sni) = uri
        .query
        .get("sni")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        map.insert(Value::from("sni"), Value::from(sni));
    }
    if is_truthy(
        uri.query
            .get("insecure")
            .or_else(|| uri.query.get("allowinsecure")),
    ) {
        map.insert(Value::from("skip-cert-verify"), Value::from(true));
    }
    if let Some(obfs) = uri
        .query
        .get("obfs")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("none"))
    {
        map.insert(Value::from("obfs"), Value::from(obfs.to_ascii_lowercase()));
    }
    if let Some(obfs_pw) = uri
        .query
        .get("obfs-password")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        map.insert(Value::from("obfs-password"), Value::from(obfs_pw));
    }
    if let Some(mport) = uri
        .query
        .get("mport")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        map.insert(Value::from("ports"), Value::from(mport));
    }
    if let Some(alpn) = uri.query.get("alpn").filter(|s| !s.trim().is_empty()) {
        let list: Vec<Value> = alpn
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(Value::from)
            .collect();
        if !list.is_empty() {
            map.insert(Value::from("alpn"), Value::Sequence(list));
        }
    }
    for (qkey, ykey) in [("upmbps", "up"), ("downmbps", "down")] {
        if let Some(raw) = uri
            .query
            .get(qkey)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            let formatted = if raw.chars().all(|c| c.is_ascii_digit()) {
                format!("{raw} Mbps")
            } else {
                raw.to_owned()
            };
            map.insert(Value::from(ykey), Value::from(formatted));
        }
    }

    let summary = NodeSummary {
        name,
        kind: "hysteria2".into(),
        server: uri.host.clone(),
        port: uri.port,
    };
    Ok((map, summary))
}

fn expand_input_lines(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let decoded = if !trimmed.contains("://") {
        let compact: String = trimmed
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&compact)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&compact))
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&compact))
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&compact));
        bytes
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .filter(|text| text.contains("://"))
    } else {
        None
    };
    let source = decoded.as_deref().unwrap_or(trimmed);
    source.lines().map(|l| l.trim().to_owned()).collect()
}

fn parse_links_into(
    raw: &str,
    used_names: &mut HashSet<String>,
) -> Result<(Vec<Value>, Vec<NodeSummary>, Vec<SkippedLink>)> {
    let lines = expand_input_lines(raw);
    ensure!(!lines.is_empty(), "no node links found");

    let mut proxy_values = Vec::new();
    let mut nodes = Vec::new();
    let mut skipped = Vec::new();

    for (idx, line) in lines.into_iter().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let scheme = line
            .split_once("://")
            .map(|(s, _)| s.trim().to_ascii_lowercase())
            .unwrap_or_else(|| "unknown".into());
        let parsed = match split_uri(&line) {
            Ok(uri) => uri,
            Err(err) => {
                skipped.push(SkippedLink {
                    line: idx + 1,
                    scheme,
                    reason: format!("{err:#}"),
                });
                continue;
            }
        };
        let default_name = format!("{}:{}", parsed.host, parsed.port);
        let preferred_name = parsed.fragment.clone().unwrap_or(default_name);
        let name = dedup_name(preferred_name, used_names);

        let result = match parsed.scheme.as_str() {
            "vless" => parse_vless_mapping(&parsed, name.clone()),
            "hysteria2" | "hy2" => parse_hysteria2_mapping(&parsed, name.clone()),
            other => {
                used_names.remove(&name);
                skipped.push(SkippedLink {
                    line: idx + 1,
                    scheme: other.to_owned(),
                    reason: format!(
                        "unsupported protocol \"{other}\" (supports vless, hysteria2/hy2)"
                    ),
                });
                continue;
            }
        };

        match result {
            Ok((mapping, summary)) => {
                let yaml_val = Value::Mapping(mapping);
                // Validate this single proxy mapping immediately via Config::parse.
                let mut probe = Mapping::new();
                probe.insert(
                    Value::from("proxies"),
                    Value::Sequence(vec![yaml_val.clone()]),
                );
                let probe_str = serde_yaml::to_string(&Value::Mapping(probe))?;
                if let Err(err) = Config::parse(probe_str.as_bytes()) {
                    used_names.remove(&name);
                    skipped.push(SkippedLink {
                        line: idx + 1,
                        scheme: parsed.scheme,
                        reason: format!("{err:#}"),
                    });
                    continue;
                }
                proxy_values.push(yaml_val);
                nodes.push(summary);
            }
            Err(err) => {
                used_names.remove(&name);
                skipped.push(SkippedLink {
                    line: idx + 1,
                    scheme: parsed.scheme,
                    reason: format!("{err:#}"),
                });
            }
        }
    }

    if nodes.is_empty() {
        if let Some(first) = skipped.first() {
            bail!("no usable nodes found ({}: {})", first.scheme, first.reason);
        }
        bail!("no usable nodes found");
    }

    Ok((proxy_values, nodes, skipped))
}

fn summarize_proxy(p: &Proxy) -> NodeSummary {
    let kind = match p.kind {
        ProxyKind::Vless => "vless",
        ProxyKind::Hysteria2 => "hysteria2",
        ProxyKind::Trojan => "trojan",
        ProxyKind::Tailscale => "tailscale",
    };
    NodeSummary {
        name: p.name.clone(),
        kind: kind.into(),
        server: p.server.clone(),
        port: p.port,
    }
}

fn seed_reserved_names(used: &mut HashSet<String>) {
    used.insert("DIRECT".into());
    used.insert("REJECT".into());
    used.insert("GLOBAL".into());
}

fn percent_encode(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
    out
}

fn format_host(server: &str) -> String {
    if server.contains(':') && !server.starts_with('[') {
        format!("[{server}]")
    } else {
        server.to_owned()
    }
}

fn proxy_to_uri(proxy: &Proxy) -> Result<Option<String>> {
    match proxy.kind {
        ProxyKind::Vless => {
            let uuid = proxy.uuid.context("VLESS node missing uuid")?;
            let network = if proxy.network.is_empty() {
                "tcp"
            } else {
                proxy.network.as_str()
            };
            let mut query = vec![
                "encryption=none".to_owned(),
                format!("type={}", percent_encode(network)),
            ];
            if !proxy.flow.is_empty() && network == "tcp" {
                query.push(format!("flow={}", percent_encode(&proxy.flow)));
            }
            if let Some(reality) = &proxy.reality_opts {
                query.push("security=reality".to_owned());
                query.push(format!("pbk={}", percent_encode(&reality.public_key)));
                if !reality.short_id.is_empty() {
                    query.push(format!("sid={}", percent_encode(&reality.short_id)));
                }
            } else if proxy.tls {
                query.push("security=tls".to_owned());
            } else {
                query.push("security=none".to_owned());
            }
            if let Some(sni) = proxy
                .servername
                .as_deref()
                .or(proxy.sni.as_deref())
                .filter(|s| !s.is_empty())
            {
                query.push(format!("sni={}", percent_encode(sni)));
            }
            if let Some(fp) = proxy
                .client_fingerprint
                .as_deref()
                .filter(|s| !s.is_empty())
            {
                query.push(format!("fp={}", percent_encode(fp)));
            }
            if !proxy.alpn.is_empty() {
                query.push(format!("alpn={}", percent_encode(&proxy.alpn.join(","))));
            }
            if proxy.skip_cert_verify {
                query.push("allowInsecure=1".to_owned());
            }
            if network == "ws" {
                query.push(format!("path={}", percent_encode(&proxy.ws_opts.path)));
                if let Some(host) = proxy
                    .ws_opts
                    .headers
                    .get("Host")
                    .or_else(|| proxy.ws_opts.headers.get("host"))
                    .filter(|s| !s.is_empty())
                {
                    query.push(format!("host={}", percent_encode(host)));
                }
            } else if network == "grpc" && !proxy.grpc_opts.grpc_service_name.is_empty() {
                query.push(format!(
                    "serviceName={}",
                    percent_encode(&proxy.grpc_opts.grpc_service_name)
                ));
            }
            if proxy.xudp
                || proxy
                    .packet_encoding
                    .as_deref()
                    .is_some_and(|s| s.eq_ignore_ascii_case("xudp"))
            {
                query.push("packetEncoding=xudp".to_owned());
            }
            Ok(Some(format!(
                "vless://{uuid}@{}:{}?{}#{}",
                format_host(&proxy.server),
                proxy.port,
                query.join("&"),
                percent_encode(&proxy.name)
            )))
        }
        ProxyKind::Hysteria2 => {
            let pw = if !proxy.password.is_empty() {
                &proxy.password
            } else {
                &proxy.auth_str
            };
            ensure!(!pw.is_empty(), "Hysteria2 node missing password");
            let mut query = Vec::new();
            if let Some(sni) = proxy
                .sni
                .as_deref()
                .or(proxy.servername.as_deref())
                .filter(|s| !s.is_empty())
            {
                query.push(format!("sni={}", percent_encode(sni)));
            }
            if proxy.skip_cert_verify {
                query.push("insecure=1".to_owned());
            }
            if let Some(obfs) = proxy
                .obfs
                .as_deref()
                .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("none"))
            {
                query.push(format!("obfs={}", percent_encode(obfs)));
                if !proxy.obfs_password.is_empty() {
                    query.push(format!(
                        "obfs-password={}",
                        percent_encode(&proxy.obfs_password)
                    ));
                }
            }
            if let Some(ports) = proxy.ports.as_deref().filter(|s| !s.is_empty()) {
                query.push(format!("mport={}", percent_encode(ports)));
            }
            if !proxy.alpn.is_empty() {
                query.push(format!("alpn={}", percent_encode(&proxy.alpn.join(","))));
            }
            if let Some(up) = proxy.up.as_deref().filter(|s| !s.is_empty()) {
                query.push(format!("upmbps={}", percent_encode(up)));
            }
            if let Some(down) = proxy.down.as_deref().filter(|s| !s.is_empty()) {
                query.push(format!("downmbps={}", percent_encode(down)));
            }
            let qs = if query.is_empty() {
                String::new()
            } else {
                format!("?{}", query.join("&"))
            };
            Ok(Some(format!(
                "hy2://{}@{}:{}{qs}#{}",
                percent_encode(pw),
                format_host(&proxy.server),
                proxy.port,
                percent_encode(&proxy.name)
            )))
        }
        ProxyKind::Trojan | ProxyKind::Tailscale => Ok(None),
    }
}

/// Exports VLESS and Hysteria2 nodes from a YAML configuration as share links,
/// optionally encrypted in Clyntis v2 Base64 format when `password` is given.
pub fn export_links(yaml: &str, password: Option<&str>) -> Result<NodesExport> {
    let cfg = Config::parse(yaml.as_bytes())?;
    let mut uris = Vec::new();
    for proxy in &cfg.proxies {
        if let Some(uri) = proxy_to_uri(proxy)? {
            uris.push(uri);
        }
    }
    ensure!(
        !uris.is_empty(),
        "no exportable VLESS or Hysteria2 nodes found"
    );
    let count = uris.len();
    let plain = zeroize::Zeroizing::new(uris.join("\n"));
    match password.filter(|p| !p.is_empty()) {
        Some(pw) => {
            let text = crate::crypto::encrypt(plain.as_bytes(), pw)?;
            Ok(NodesExport {
                text,
                count,
                encrypted: true,
            })
        }
        None => Ok(NodesExport {
            text: (*plain).clone(),
            count,
            encrypted: false,
        }),
    }
}

/// Returns true when `raw` looks like Clyntis v2 (`CLYNTISE`) encrypted Base64 text.
pub fn is_encrypted_links(raw: &str) -> bool {
    let compact: String = raw
        .trim()
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if compact.len() < 24 || compact.contains("://") {
        return false;
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&compact)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&compact))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&compact))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&compact));
    bytes.is_ok_and(|b| b.starts_with(b"CLYNTISE"))
}

fn decrypt_if_needed(raw: &str, password: Option<&str>) -> Result<zeroize::Zeroizing<String>> {
    if let Some(pw) = password.filter(|p| !p.is_empty()) {
        let compact = zeroize::Zeroizing::new(
            raw.chars()
                .filter(|c| !c.is_ascii_whitespace())
                .collect::<String>(),
        );
        let bytes = crate::crypto::decrypt(compact.as_bytes(), pw)?;
        let text = String::from_utf8(bytes.to_vec())
            .map_err(|_| anyhow::anyhow!("wrong password or corrupted encrypted node links"))?;
        Ok(zeroize::Zeroizing::new(text))
    } else if is_encrypted_links(raw) {
        bail!("encrypted node links require a password");
    } else {
        Ok(zeroize::Zeroizing::new(raw.to_owned()))
    }
}

/// Parses one or more share links (or Base64 subscription text) into a minimal
/// auto-routed YAML configuration.
pub fn import_links(text: &str, mode: AutoRouting) -> Result<NodesImport> {
    import_links_with_password(text, mode, None)
}

/// Parses share links, Base64 subscriptions, or Clyntis-encrypted links into a
/// minimal auto-routed YAML configuration.
pub fn import_links_with_password(
    text: &str,
    mode: AutoRouting,
    password: Option<&str>,
) -> Result<NodesImport> {
    let decrypted = decrypt_if_needed(text, password)?;
    let mut used = HashSet::new();
    seed_reserved_names(&mut used);
    let (proxy_values, nodes, skipped) = parse_links_into(&decrypted, &mut used)?;
    let mut root = Mapping::new();
    root.insert(Value::from("auto-routing"), Value::from(mode.as_str()));
    root.insert(Value::from("proxies"), Value::Sequence(proxy_values));
    let yaml = serde_yaml::to_string(&Value::Mapping(root))?;
    Config::parse(yaml.as_bytes())?;
    Ok(NodesImport {
        yaml,
        nodes,
        skipped,
        auto_routing: mode,
    })
}

/// Inspects an existing profile's YAML to report its nodes and whether it uses
/// automatic GeoIP/GeoSite routing.
pub fn inspect_profile(yaml: &str) -> Result<ProfileNodes> {
    let cfg = Config::parse(yaml.as_bytes())?;
    let doc: Value = serde_yaml::from_str(yaml)?;
    let map = doc
        .as_mapping()
        .context("configuration must be a YAML mapping")?;
    let is_auto = should_auto_route(map, &cfg.proxies);
    Ok(ProfileNodes {
        is_auto,
        auto_routing: is_auto.then_some(cfg.auto_routing),
        nodes: cfg.proxies.iter().map(summarize_proxy).collect(),
    })
}

/// Appends parsed share links to an existing YAML configuration's `proxies:`.
pub fn append_links(existing_yaml: &str, text: &str) -> Result<NodesImport> {
    append_links_with_password(existing_yaml, text, None)
}

/// Appends share links (or Clyntis-encrypted links when `password` is provided)
/// to an existing YAML configuration's `proxies:`.
pub fn append_links_with_password(
    existing_yaml: &str,
    text: &str,
    password: Option<&str>,
) -> Result<NodesImport> {
    let decrypted = decrypt_if_needed(text, password)?;
    let cfg = Config::parse(existing_yaml.as_bytes())?;
    let mut doc: Value = serde_yaml::from_str(existing_yaml)?;
    let map = doc
        .as_mapping_mut()
        .context("configuration must be a YAML mapping")?;
    let mut used: HashSet<String> = cfg.proxies.iter().map(|p| p.name.clone()).collect();
    seed_reserved_names(&mut used);
    let (new_values, nodes, skipped) = parse_links_into(&decrypted, &mut used)?;

    let existing_seq = map
        .entry(Value::from("proxies"))
        .or_insert_with(|| Value::Sequence(Vec::new()))
        .as_sequence_mut()
        .context("proxies must be a YAML sequence")?;
    existing_seq.extend(new_values);

    let yaml = serde_yaml::to_string(&doc)?;
    let updated = Config::parse(yaml.as_bytes())?;
    Ok(NodesImport {
        yaml,
        nodes,
        skipped,
        auto_routing: updated.auto_routing,
    })
}

/// Removes named nodes from `proxies:` and/or updates `auto-routing` mode.
pub fn update_nodes(
    existing_yaml: &str,
    remove_names: &[String],
    auto_routing: Option<AutoRouting>,
) -> Result<String> {
    let cfg = Config::parse(existing_yaml.as_bytes())?;
    let mut doc: Value = serde_yaml::from_str(existing_yaml)?;
    let map = doc
        .as_mapping_mut()
        .context("configuration must be a YAML mapping")?;
    let is_auto = should_auto_route(map, &cfg.proxies);

    if !remove_names.is_empty() {
        let remove: HashSet<&str> = remove_names.iter().map(String::as_str).collect();
        let seq = map
            .get_mut(Value::from("proxies"))
            .and_then(Value::as_sequence_mut)
            .context("configuration has no proxies")?;
        seq.retain(|item| {
            item.get("name")
                .and_then(Value::as_str)
                .is_none_or(|name| !remove.contains(name))
        });
        if is_auto {
            let remaining: Vec<Proxy> = serde_yaml::from_value(Value::Sequence(seq.clone()))?;
            ensure!(
                remaining.iter().any(is_routable),
                "at least one node must remain in an auto-routed profile"
            );
        }
    }

    if let Some(mode) = auto_routing
        && !map.contains_key(Value::from("rules"))
    {
        map.insert(Value::from("auto-routing"), Value::from(mode.as_str()));
    }

    let yaml = serde_yaml::to_string(&doc)?;
    Config::parse(yaml.as_bytes())?;
    Ok(yaml)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VLESS_REALITY: &str = "vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.apple.com&fp=chrome&pbk=e06Qm75__kTEZaIgA31gjuNYl9Me-XLwf3SJLLD3PxM&sid=a1b2&type=tcp#US%20Node";
    const VLESS_WS: &str = "vless://22222222-2222-4222-8222-222222222222@[2001:db8::1]:8443?security=tls&type=ws&path=%2Fws&host=cdn.example.com&alpn=http/1.1#IPv6-WS";
    const HY2_LINK: &str = "hy2://my%3Apass@hy.example.com:443?sni=hy.example.com&obfs=salamander&obfs-password=secret&mport=20000-30000&insecure=1#HY2";

    #[test]
    fn parses_vless_reality_ws_and_hysteria2_links() {
        let input = format!("{VLESS_REALITY}\n{VLESS_WS}\n{HY2_LINK}");
        let res = import_links(&input, AutoRouting::Whitelist).unwrap();
        assert!(res.skipped.is_empty());
        assert_eq!(res.nodes.len(), 3);
        assert_eq!(res.nodes[0].name, "US Node");
        assert_eq!(res.nodes[1].name, "IPv6-WS");
        assert_eq!(res.nodes[2].name, "HY2");

        let cfg = Config::parse(res.yaml.as_bytes()).unwrap();
        assert_eq!(cfg.proxies.len(), 3);
        assert_eq!(cfg.proxies[0].flow, "xtls-rprx-vision");
        assert_eq!(cfg.proxies[0].servername.as_deref(), Some("www.apple.com"));
        assert!(cfg.proxies[0].reality_opts.is_some());
        assert_eq!(cfg.proxies[1].network, "ws");
        assert_eq!(cfg.proxies[1].ws_opts.path, "/ws");
        assert_eq!(cfg.proxies[2].kind, ProxyKind::Hysteria2);
        assert_eq!(cfg.proxies[2].password, "my:pass");
        assert_eq!(cfg.proxies[2].ports.as_deref(), Some("20000-30000"));
        assert!(cfg.proxies[2].skip_cert_verify);
    }

    #[test]
    fn decodes_base64_and_skips_unsupported_schemes() {
        let raw =
            format!("{VLESS_REALITY}\nss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#SS\n{HY2_LINK}");
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
        let res = import_links(&encoded, AutoRouting::Blacklist).unwrap();
        assert_eq!(res.nodes.len(), 2);
        assert_eq!(res.skipped.len(), 1);
        assert_eq!(res.skipped[0].scheme, "ss");
        assert_eq!(res.auto_routing, AutoRouting::Blacklist);

        let cfg = Config::parse(res.yaml.as_bytes()).unwrap();
        assert_eq!(cfg.auto_routing, AutoRouting::Blacklist);
        assert_eq!(cfg.rules.last().map(String::as_str), Some("MATCH,DIRECT"));
    }

    #[test]
    fn inspect_append_and_update_nodes_round_trip() {
        let initial = import_links(VLESS_REALITY, AutoRouting::Whitelist).unwrap();
        let info = inspect_profile(&initial.yaml).unwrap();
        assert!(info.is_auto);
        assert_eq!(info.auto_routing, Some(AutoRouting::Whitelist));
        assert_eq!(info.nodes.len(), 1);

        let appended = append_links(&initial.yaml, HY2_LINK).unwrap();
        let info2 = inspect_profile(&appended.yaml).unwrap();
        assert_eq!(info2.nodes.len(), 2);

        // Removing the last node is refused; removing one and switching mode succeeds.
        assert!(update_nodes(&appended.yaml, &["US Node".into(), "HY2".into()], None).is_err());
        let updated = update_nodes(
            &appended.yaml,
            &["US Node".into()],
            Some(AutoRouting::Blacklist),
        )
        .unwrap();
        let info3 = inspect_profile(&updated).unwrap();
        assert_eq!(info3.nodes.len(), 1);
        assert_eq!(info3.nodes[0].name, "HY2");
        assert_eq!(info3.auto_routing, Some(AutoRouting::Blacklist));
    }

    #[test]
    fn skips_secret_leak_in_error_reason_and_rejects_empty_input() {
        assert!(import_links("   \n# comment\n", AutoRouting::Whitelist).is_err());
        let bad = "vmess://eyJhZGQiOiIxLjEuMS4xIn0=";
        let err = import_links(bad, AutoRouting::Whitelist).unwrap_err();
        assert!(err.to_string().contains("vmess"));
    }

    #[test]
    fn handles_hy2_default_port_slash_password_case_obfs_and_reserved_names() {
        let link = "hy2://pa/ss@hy.example.com/?obfs=Salamander&obfs-password=sec#DIRECT";
        let res = import_links(link, AutoRouting::Whitelist).unwrap();
        assert!(res.skipped.is_empty());
        assert_eq!(res.nodes.len(), 1);
        assert_eq!(res.nodes[0].name, "DIRECT (2)");
        assert_eq!(res.nodes[0].port, 443);

        let cfg = Config::parse(res.yaml.as_bytes()).unwrap();
        assert_eq!(cfg.proxies[0].name, "DIRECT (2)");
        assert_eq!(cfg.proxies[0].port, 443);
        assert_eq!(cfg.proxies[0].password, "pa/ss");
        assert_eq!(cfg.proxies[0].obfs.as_deref(), Some("salamander"));
    }

    #[test]
    fn exports_plaintext_and_encrypted_links_with_lossless_roundtrip() {
        let input = format!("{VLESS_REALITY}\n{VLESS_WS}\n{HY2_LINK}");
        let imported = import_links(&input, AutoRouting::Whitelist).unwrap();

        let plain = export_links(&imported.yaml, None).unwrap();
        assert!(!plain.encrypted);
        assert_eq!(plain.count, 3);
        assert!(!is_encrypted_links(&plain.text));
        let reimported = import_links(&plain.text, AutoRouting::Whitelist).unwrap();
        assert_eq!(reimported.nodes, imported.nodes);

        let enc = export_links(&imported.yaml, Some("node-secret-pw")).unwrap();
        assert!(enc.encrypted);
        assert_eq!(enc.count, 3);
        assert!(is_encrypted_links(&enc.text));
        assert!(!enc.text.contains("vless://"));
        assert!(!enc.text.contains("hy2://"));
        assert!(!enc.text.contains("example.com"));

        // Missing or wrong password must fail cleanly.
        assert!(
            import_links_with_password(&enc.text, AutoRouting::Whitelist, None)
                .unwrap_err()
                .to_string()
                .contains("password")
        );
        assert!(
            import_links_with_password(&enc.text, AutoRouting::Whitelist, Some("wrong-pw"))
                .is_err()
        );

        // Line-wrapped ciphertext decrypts cleanly in both import and append.
        let wrapped = enc
            .text
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let decrypted =
            import_links_with_password(&wrapped, AutoRouting::Blacklist, Some("node-secret-pw"))
                .unwrap();
        assert_eq!(decrypted.nodes.len(), 3);
        assert_eq!(decrypted.auto_routing, AutoRouting::Blacklist);

        let single = import_links(VLESS_REALITY, AutoRouting::Whitelist).unwrap();
        let appended =
            append_links_with_password(&single.yaml, &wrapped, Some("node-secret-pw")).unwrap();
        assert_eq!(appended.nodes.len(), 3);
    }
}
