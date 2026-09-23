//! Immutable routing snapshots. A failed refresh leaves the active snapshot intact.
use anyhow::{Context, Result, bail, ensure};
use meta_config::{
    Config, RuleProvider,
    rule::{DomainSet, IpMatcher, IpSet, Matcher, Rule},
};
use prost::Message;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

const LIMIT: usize = 128 * 1024 * 1024;
#[derive(Default)]
pub struct Resources {
    matchers: HashMap<(String, String), Matcher>,
}
impl Resources {
    pub fn bind(&self, matcher: &Matcher) -> Result<Matcher> {
        matcher.bind(&|m| {
            let key = match m {
                Matcher::GeoIp(v) => ("geoip", v),
                Matcher::GeoSite(v) => ("geosite", v),
                Matcher::RuleSet(v) => ("rule-set", v),
                _ => unreachable!(),
            };
            self.matchers
                .get(&(key.0.into(), key.1.clone()))
                .cloned()
                .context("referenced routing data is not loaded")
        })
    }
    pub fn rules(&self, raw: &[String]) -> Result<Vec<Rule>> {
        raw.iter()
            .map(|s| {
                let mut r = Rule::parse(s)?;
                r.matcher = self.bind(&r.matcher)?;
                Ok(r)
            })
            .collect()
    }
    pub async fn load(
        config: &Config,
        resolver: &crate::dns::Resolver,
        hooks: &meta_platform::Hooks,
        refresh: bool,
    ) -> Result<Self> {
        let mut refs = vec![];
        for rule in &config.rules {
            Rule::parse(rule)?.matcher.references(&mut refs);
        }
        for key in config
            .dns
            .nameserver_policy
            .keys()
            .chain(config.dns.fake_ip_filter.iter())
        {
            if let Some(tags) = key.strip_prefix("geosite:") {
                for tag in tags.split(',') {
                    refs.push(("geosite".into(), tag.to_ascii_lowercase()));
                }
            }
            if let Some(tags) = key.strip_prefix("rule-set:") {
                for tag in tags.split(',') {
                    refs.push(("rule-set".into(), tag.into()));
                }
            }
        }
        let mut pending = vec![];
        let mut providers = HashMap::new();
        for (name, p) in &config.rule_providers {
            let payload = if p.kind == "inline" {
                p.payload.clone()
            } else {
                let path = asset_path(&config.directory, &p.path)?;
                let data = asset(
                    &path,
                    &p.url,
                    if p.kind == "http" {
                        Some(p.interval)
                    } else {
                        None
                    },
                    refresh,
                    resolver,
                    hooks,
                    &mut pending,
                )
                .await?;
                parse_payload(&data, &p.format)?
            };
            let matcher = provider_matcher(p, &payload)?;
            matcher.references(&mut refs);
            providers.insert(name.clone(), matcher);
        }
        let mut out = Self::default();
        let mut seen = HashSet::new();
        refs.retain(|r| seen.insert(r.clone()));
        let ip_refs: Vec<_> = refs
            .iter()
            .filter(|r| r.0 == "geoip")
            .map(|r| r.1.clone())
            .collect();
        if !ip_refs.is_empty() {
            if config.geodata_mode {
                let path = config.directory.join("geoip.dat");
                let data = asset(
                    &path,
                    &config.geox_url.geoip,
                    geo_interval(config),
                    refresh,
                    resolver,
                    hooks,
                    &mut pending,
                )
                .await?;
                let list = GeoIpList::decode(data.as_slice()).context("invalid geoip.dat")?;
                for tag in ip_refs {
                    let (key, inverse) = tag
                        .strip_prefix('!')
                        .map_or((tag.as_str(), false), |s| (s, true));
                    let entry = list
                        .entry
                        .iter()
                        .find(|e| e.country_code.eq_ignore_ascii_case(key))
                        .context("GEOIP category missing from data")?;
                    let nets = entry
                        .cidr
                        .iter()
                        .map(|c| {
                            let ip = match c.ip.len() {
                                4 => IpAddr::from(<[u8; 4]>::try_from(c.ip.as_slice())?),
                                16 => IpAddr::from(<[u8; 16]>::try_from(c.ip.as_slice())?),
                                _ => bail!("invalid GeoIP address"),
                            };
                            Ok(ipnet::IpNet::new(ip, u8::try_from(c.prefix)?)?)
                        })
                        .collect::<Result<Vec<_>>>()?;
                    out.matchers.insert(
                        ("geoip".into(), tag),
                        Matcher::Nets(Arc::new(IpSet::new(nets, entry.inverse_match ^ inverse))),
                    );
                }
            } else {
                let path = config.directory.join("Country.mmdb");
                let data = asset(
                    &path,
                    &config.geox_url.mmdb,
                    geo_interval(config),
                    refresh,
                    resolver,
                    hooks,
                    &mut pending,
                )
                .await?;
                let db =
                    Arc::new(maxminddb::Reader::from_source(data).context("invalid Country.mmdb")?);
                for tag in ip_refs {
                    if tag == "private" {
                        let nets = [
                            "0.0.0.0/8",
                            "10.0.0.0/8",
                            "100.64.0.0/10",
                            "127.0.0.0/8",
                            "169.254.0.0/16",
                            "172.16.0.0/12",
                            "192.168.0.0/16",
                            "::/128",
                            "::1/128",
                            "fc00::/7",
                            "fe80::/10",
                        ]
                        .into_iter()
                        .map(str::parse)
                        .collect::<std::result::Result<Vec<_>, _>>()?;
                        out.matchers.insert(
                            ("geoip".into(), tag),
                            Matcher::Nets(Arc::new(IpSet::new(nets, false))),
                        );
                    } else {
                        out.matchers.insert(
                            ("geoip".into(), tag.clone()),
                            Matcher::ExternalIp(Arc::new(Country {
                                db: db.clone(),
                                tag,
                            })),
                        );
                    }
                }
            }
        }
        let site_refs: Vec<_> = refs
            .iter()
            .filter(|r| r.0 == "geosite")
            .map(|r| r.1.clone())
            .collect();
        if !site_refs.is_empty() {
            let path = config.directory.join("geosite.dat");
            let data = asset(
                &path,
                &config.geox_url.geosite,
                geo_interval(config),
                refresh,
                resolver,
                hooks,
                &mut pending,
            )
            .await?;
            let list = GeoSiteList::decode(data.as_slice()).context("invalid geosite.dat")?;
            for tag in site_refs {
                let parts: Vec<_> = tag.split('@').collect();
                let entry = list
                    .entry
                    .iter()
                    .find(|e| e.country_code.eq_ignore_ascii_case(parts[0]))
                    .context("GEOSITE category missing from data")?;
                let mut set = DomainSet::default();
                for d in &entry.domain {
                    if !parts[1..].iter().all(|attr| {
                        let (name, inverse) =
                            attr.strip_prefix('!').map_or((*attr, false), |v| (v, true));
                        d.attribute.iter().any(|a| a.key.eq_ignore_ascii_case(name)) ^ inverse
                    }) {
                        continue;
                    }
                    let value = d.value.trim_end_matches('.').to_ascii_lowercase();
                    match d.kind {
                        0 => set.keywords.push(value),
                        1 => set.regex.push(meta_config::rule::compile_regex(&d.value)?),
                        2 => {
                            set.suffix.insert(value);
                        }
                        3 => {
                            set.exact.insert(value);
                        }
                        _ => bail!("invalid geosite domain type"),
                    }
                }
                out.matchers
                    .insert(("geosite".into(), tag), Matcher::Domains(Arc::new(set)));
            }
        }
        // Classical providers can refer to geo data, but not recursively to providers.
        for (name, m) in providers {
            let bound = out.bind(&m)?;
            out.matchers.insert(("rule-set".into(), name), bound);
        }
        out.rules(&config.rules)?;
        for (path, data) in pending {
            atomic_write(&path, &data)?;
        }
        Ok(out)
    }
}
fn geo_interval(c: &Config) -> Option<u64> {
    Some(if c.geo_auto_update {
        c.geo_update_interval.saturating_mul(3600)
    } else {
        0
    })
}
pub fn asset_path(root: &Path, path: &str) -> Result<PathBuf> {
    ensure!(!path.is_empty(), "resource path is required");
    let p = Path::new(path);
    Ok(if p.is_absolute() {
        p.into()
    } else {
        root.join(p)
    })
}
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(data)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}
async fn asset(
    path: &Path,
    url: &str,
    interval: Option<u64>,
    refresh: bool,
    resolver: &crate::dns::Resolver,
    hooks: &meta_platform::Hooks,
    pending: &mut Vec<(PathBuf, Vec<u8>)>,
) -> Result<Vec<u8>> {
    let meta = std::fs::metadata(path).ok();
    let expired = refresh
        && interval.is_some_and(|v| v > 0)
        && meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .is_none_or(|age| age >= Duration::from_secs(interval.unwrap_or(0)));
    if let Some(meta) = meta
        && !expired
    {
        ensure!(meta.len() <= LIMIT as u64, "resource exceeds size limit");
        return Ok(std::fs::read(path)?);
    }
    ensure!(
        interval.is_some() && !url.is_empty(),
        "local routing resource is missing"
    );
    let data = download(url, resolver, hooks)
        .await
        .context("routing resource download failed")?;
    pending.push((path.into(), data.clone()));
    Ok(data)
}
pub async fn download(
    url: &str,
    resolver: &crate::dns::Resolver,
    hooks: &meta_platform::Hooks,
) -> Result<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(60), async {
        use http_body_util::{BodyExt, Empty, Limited};
        let mut url = url.to_owned();
        for _ in 0..6 {
            let uri: http::Uri = url.parse().context("invalid resource URL")?;
            let scheme = uri.scheme_str().unwrap_or("");
            ensure!(
                scheme == "https" || scheme == "http",
                "resource URL must use HTTP(S)"
            );
            let target =
                meta_protocol::Target::from_uri(&uri, if scheme == "https" { 443 } else { 80 })?;
            let addresses = resolver.lookup(&target.host, target.port).await?;
            let mut connected = None;
            for addr in addresses {
                if let Ok(Ok(s)) = tokio::time::timeout(
                    Duration::from_secs(5),
                    meta_platform::tcp_connect(addr, &**hooks),
                )
                .await
                {
                    connected = Some(s);
                    break;
                }
            }
            let socket = connected.context("cannot connect to resource server")?;
            let stream: meta_protocol::BoxStream = if scheme == "https" {
                meta_protocol::tls::SecureConnector::new(resolver.clock())
                    .connect(
                        Box::new(socket),
                        &meta_protocol::tls::TlsConnectConfig {
                            server_name: target.host,
                            alpn: vec!["http/1.1".into()],
                            verify_cert: true,
                            fingerprint: meta_protocol::tls::TlsFingerprint::Native,
                            reality: None,
                        },
                    )
                    .await?
            } else {
                Box::new(socket)
            };
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
            let _driver = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(connection));
            let request = http::Request::get(uri.path_and_query().map_or("/", |v| v.as_str()))
                .header(
                    http::header::HOST,
                    uri.authority()
                        .context("missing resource authority")?
                        .as_str(),
                )
                .header(http::header::USER_AGENT, "clyntis")
                .body(Empty::<bytes::Bytes>::new())?;
            let response = sender.send_request(request).await?;
            if response.status().is_redirection() {
                let location = response
                    .headers()
                    .get(http::header::LOCATION)
                    .context("redirect lacks location")?
                    .to_str()?;
                url = if location.starts_with('/') {
                    format!("{scheme}://{}{location}", uri.authority().unwrap())
                } else {
                    location.into()
                };
                ensure!(
                    scheme != "https" || url.starts_with("https://"),
                    "HTTPS resource downgrade refused"
                );
                continue;
            }
            ensure!(
                response.status().is_success(),
                "resource HTTP request failed"
            );
            let body = Limited::new(response.into_body(), LIMIT)
                .collect()
                .await
                .map_err(|_| anyhow::anyhow!("resource body failed or exceeded limit"))?
                .to_bytes();
            return Ok(body.to_vec());
        }
        bail!("too many resource redirects")
    })
    .await?
}
fn parse_payload(data: &[u8], format: &str) -> Result<Vec<String>> {
    match format {
        "yaml" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Payload {
                payload: Vec<String>,
            }
            Ok(serde_yaml::from_slice::<Payload>(data)?.payload)
        }
        "text" => Ok(std::str::from_utf8(data)?
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
            .map(str::to_owned)
            .collect()),
        _ => bail!("unsupported rule provider format"),
    }
}
fn provider_matcher(p: &RuleProvider, payload: &[String]) -> Result<Matcher> {
    ensure!(payload.len() <= 2_000_000, "too many provider rules");
    let mut nodes = vec![];
    for value in payload {
        let m = match p.behavior.as_str() {
            "domain" => meta_config::rule::domain_pattern(value)?,
            "ipcidr" => Matcher::Net(value.parse()?),
            "classical" => Matcher::parse_condition(value)?,
            _ => bail!("unsupported provider behavior"),
        };
        let mut refs = vec![];
        m.references(&mut refs);
        ensure!(
            !refs.iter().any(|r| r.0 == "rule-set"),
            "nested RULE-SET is not permitted in classical providers"
        );
        nodes.push(m);
    }
    Ok(Matcher::Or(nodes.into()))
}
struct Country {
    db: Arc<maxminddb::Reader<Vec<u8>>>,
    tag: String,
}
impl std::fmt::Debug for Country {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MMDB country matcher")
    }
}
impl IpMatcher for Country {
    fn matches(&self, ip: IpAddr) -> bool {
        let (tag, inverse) = self
            .tag
            .strip_prefix('!')
            .map_or((self.tag.as_str(), false), |v| (v, true));
        let code = self
            .db
            .lookup::<maxminddb::geoip2::Country<'_>>(ip)
            .ok()
            .flatten()
            .and_then(|c| c.country.and_then(|v| v.iso_code));
        code.is_some_and(|c| c.eq_ignore_ascii_case(tag)) ^ inverse
    }
}

#[derive(Clone, PartialEq, Message)]
struct GeoIpList {
    #[prost(message, repeated, tag = "1")]
    entry: Vec<GeoIp>,
}
#[derive(Clone, PartialEq, Message)]
struct GeoIp {
    #[prost(string, tag = "1")]
    country_code: String,
    #[prost(message, repeated, tag = "2")]
    cidr: Vec<Cidr>,
    #[prost(bool, tag = "3")]
    inverse_match: bool,
}
#[derive(Clone, PartialEq, Message)]
struct Cidr {
    #[prost(bytes = "vec", tag = "1")]
    ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    prefix: u32,
}
#[derive(Clone, PartialEq, Message)]
struct GeoSiteList {
    #[prost(message, repeated, tag = "1")]
    entry: Vec<GeoSite>,
}
#[derive(Clone, PartialEq, Message)]
struct GeoSite {
    #[prost(string, tag = "1")]
    country_code: String,
    #[prost(message, repeated, tag = "2")]
    domain: Vec<Domain>,
}
#[derive(Clone, PartialEq, Message)]
struct Domain {
    #[prost(int32, tag = "1")]
    kind: i32,
    #[prost(string, tag = "2")]
    value: String,
    #[prost(message, repeated, tag = "3")]
    attribute: Vec<Attribute>,
}
#[derive(Clone, PartialEq, Message)]
struct Attribute {
    #[prost(string, tag = "1")]
    key: String,
    #[prost(bool, tag = "2")]
    bool_value: bool,
    #[prost(int64, tag = "3")]
    int_value: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn geo_provider_and_atomic_failure() {
        let dir = std::env::temp_dir().join(format!("meta-geo-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut c = Config {
            directory: dir.clone(),
            geodata_mode: true,
            rules: vec![
                "GEOSITE,TEST@cn,REJECT".into(),
                "GEOIP,ZZ,DIRECT,no-resolve".into(),
                "RULE-SET,local,REJECT".into(),
            ],
            ..Config::default()
        };
        let ip = GeoIpList {
            entry: vec![GeoIp {
                country_code: "ZZ".into(),
                cidr: vec![Cidr {
                    ip: vec![10, 0, 0, 0],
                    prefix: 8,
                }],
                inverse_match: false,
            }],
        };
        std::fs::write(dir.join("geoip.dat"), ip.encode_to_vec()).unwrap();
        let site = GeoSiteList {
            entry: vec![GeoSite {
                country_code: "test".into(),
                domain: vec![
                    Domain {
                        kind: 2,
                        value: "example.test".into(),
                        attribute: vec![Attribute {
                            key: "cn".into(),
                            bool_value: true,
                            int_value: 0,
                        }],
                    },
                    Domain {
                        kind: 3,
                        value: "excluded.test".into(),
                        attribute: vec![],
                    },
                ],
            }],
        };
        std::fs::write(dir.join("geosite.dat"), site.encode_to_vec()).unwrap();
        c.rule_providers.insert(
            "local".into(),
            RuleProvider {
                kind: "inline".into(),
                payload: vec!["+.blocked.test".into()],
                ..RuleProvider::default()
            },
        );
        let hooks: meta_platform::Hooks = Arc::new(meta_platform::DefaultHooks);
        let dns = crate::dns::Resolver::new(c.dns.clone(), hooks.clone());
        let resources = Resources::load(&c, &dns, &hooks, false).await.unwrap();
        let rules = resources.rules(&c.rules).unwrap();
        assert!(rules[0].matches("www.example.test", None, 443, "tcp"));
        assert!(!rules[0].matches("excluded.test", None, 443, "tcp"));
        assert!(rules[1].matches("", Some("10.1.1.1".parse().unwrap()), 80, "tcp"));
        assert!(rules[2].matches("blocked.test", None, 80, "tcp"));
        let core = crate::Core::new(c.clone(), hooks.clone()).unwrap();
        core.prepare_resources(false).await.unwrap();
        assert_eq!(
            core.route(
                &meta_protocol::Target::new("www.example.test", 443).unwrap(),
                "tcp"
            )
            .await
            .unwrap(),
            "REJECT"
        );
        assert_eq!(
            core.route(&meta_protocol::Target::new("10.1.1.1", 80).unwrap(), "tcp")
                .await
                .unwrap(),
            "DIRECT"
        );
        assert_eq!(
            core.route(
                &meta_protocol::Target::new("blocked.test", 80).unwrap(),
                "tcp"
            )
            .await
            .unwrap(),
            "REJECT"
        );
        std::fs::write(dir.join("geosite.dat"), [255]).unwrap();
        assert!(Resources::load(&c, &dns, &hooks, false).await.is_err());
        assert!(rules[0].matches("example.test", None, 443, "tcp"));
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn http_provider_refresh_rejects_bad_replacement() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = std::env::temp_dir().join(format!("meta-refresh-{}", uuid::Uuid::new_v4()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for body in [
                "payload:\n- '+.first.test'\n",
                "payload:\n- '+.second.test'\n",
                "invalid: broken",
            ] {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut request = vec![];
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(s.read_u8().await.unwrap());
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                s.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let mut c = Config {
            directory: dir.clone(),
            rules: vec!["RULE-SET,test,REJECT".into()],
            ..Config::default()
        };
        c.rule_providers.insert(
            "test".into(),
            RuleProvider {
                path: "provider.yaml".into(),
                url: format!("http://{address}/rules"),
                interval: 1,
                ..RuleProvider::default()
            },
        );
        let hooks: meta_platform::Hooks = Arc::new(meta_platform::DefaultHooks);
        let core = crate::Core::new(c, hooks).unwrap();
        core.prepare_resources(false).await.unwrap();
        let target = |s| meta_protocol::Target::new(s, 80).unwrap();
        assert_eq!(
            core.route(&target("first.test"), "tcp").await.unwrap(),
            "REJECT"
        );
        let path = dir.join("provider.yaml");
        let expire = || {
            let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            file.set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::SystemTime::now() - Duration::from_secs(2)),
            )
            .unwrap();
        };
        expire();
        core.prepare_resources(true).await.unwrap();
        assert_eq!(
            core.route(&target("first.test"), "tcp").await.unwrap(),
            "DIRECT"
        );
        assert_eq!(
            core.route(&target("second.test"), "tcp").await.unwrap(),
            "REJECT"
        );
        let good = std::fs::read(&path).unwrap();
        expire();
        assert!(core.prepare_resources(true).await.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), good);
        assert_eq!(
            core.route(&target("second.test"), "tcp").await.unwrap(),
            "REJECT"
        );
        server.await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}
