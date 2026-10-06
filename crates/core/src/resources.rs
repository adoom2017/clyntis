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
    /// Copies the `kind` matchers for every tag in `tags` into `out` when this
    /// snapshot has all of them; matchers share their data through `Arc`.
    fn reuse(&self, kind: &str, tags: &[String], out: &mut Resources) -> bool {
        let found: Option<Vec<_>> = tags
            .iter()
            .map(|tag| {
                let key = (kind.to_owned(), tag.clone());
                self.matchers.get(&key).map(|m| (key, m.clone()))
            })
            .collect();
        let Some(found) = found else { return false };
        out.matchers.extend(found);
        true
    }
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
    /// `previous` is the active snapshot: geo matchers whose data file did not
    /// change are reused instead of rebuilt, so a rule-provider refresh does not
    /// briefly hold two copies of large geosite sets.
    pub async fn load(
        config: &Config,
        resolver: &crate::dns::Resolver,
        hooks: &meta_platform::Hooks,
        refresh: bool,
        previous: &Resources,
    ) -> Result<Self> {
        // Rebuilding geo data while the old snapshot is alive doubles its memory,
        // which the ~50 MiB iOS tunnel extension cannot afford; there, the host
        // refreshes geo files before each start (meta_prefetch_resources_v1).
        let geo_refresh =
            refresh && !(config.internal_host_packet_io && !previous.matchers.is_empty());
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
        let mut pending = Staged::default();
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
                parse_payload(&read_limited(&data)?, &p.format)?
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
                    geo_refresh,
                    resolver,
                    hooks,
                    &mut pending,
                )
                .await?;
                if data == path && previous.reuse("geoip", &ip_refs, &mut out) {
                    // Unchanged file: the matchers were carried over.
                } else {
                    let wanted: HashSet<String> = ip_refs
                        .iter()
                        .map(|tag| tag.trim_start_matches('!').to_ascii_lowercase())
                        .collect();
                    let list = wire::read_entries(&data, |code| {
                        wanted.contains(&code.to_ascii_lowercase())
                    })
                    .and_then(|entries| {
                        entries
                            .iter()
                            .map(|bytes| Ok(GeoIp::decode(bytes.as_slice())?))
                            .collect::<Result<Vec<_>>>()
                    })
                    .context("invalid geoip.dat")?;
                    for tag in ip_refs {
                        let (key, inverse) = tag
                            .strip_prefix('!')
                            .map_or((tag.as_str(), false), |s| (s, true));
                        let entry = list
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
                            Matcher::Nets(Arc::new(IpSet::new(
                                nets,
                                entry.inverse_match ^ inverse,
                            ))),
                        );
                    }
                }
            } else {
                let path = config.directory.join("Country.mmdb");
                let data = asset(
                    &path,
                    &config.geox_url.mmdb,
                    geo_interval(config),
                    geo_refresh,
                    resolver,
                    hooks,
                    &mut pending,
                )
                .await?;
                let db = Arc::new(
                    maxminddb::Reader::from_source(read_limited(&data)?)
                        .context("invalid Country.mmdb")?,
                );
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
                geo_refresh,
                resolver,
                hooks,
                &mut pending,
            )
            .await?;
            if data == path && previous.reuse("geosite", &site_refs, &mut out) {
                // Unchanged file: the matchers were carried over.
            } else {
                let wanted: HashSet<String> = site_refs
                    .iter()
                    .map(|tag| tag.split('@').next().unwrap_or("").to_ascii_lowercase())
                    .collect();
                // Keep entries as raw bytes and decode one domain at a time: large
                // categories (cn, geolocation-!cn) would otherwise exist twice, as
                // decoded structs and as the resulting domain set.
                let mut entries = HashMap::new();
                let raw =
                    wire::read_entries(&data, |code| wanted.contains(&code.to_ascii_lowercase()))
                        .context("invalid geosite.dat")?;
                for bytes in &raw {
                    let bytes = bytes.as_slice();
                    let mut code = String::new();
                    wire::each_field(bytes, 1, |value| {
                        code = std::str::from_utf8(value)?.to_ascii_lowercase();
                        Ok(())
                    })
                    .context("invalid geosite.dat")?;
                    entries.insert(code, bytes);
                }
                for tag in site_refs {
                    let parts: Vec<_> = tag.split('@').collect();
                    let entry = *entries
                        .get(&parts[0].to_ascii_lowercase())
                        .context("GEOSITE category missing from data")?;
                    let mut set = DomainSet::default();
                    wire::each_field(entry, 2, |bytes| {
                        let d = Domain::decode(bytes).context("invalid geosite.dat")?;
                        if !parts[1..].iter().all(|attr| {
                            let (name, inverse) =
                                attr.strip_prefix('!').map_or((*attr, false), |v| (v, true));
                            d.attribute.iter().any(|a| a.key.eq_ignore_ascii_case(name)) ^ inverse
                        }) {
                            return Ok(());
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
                        Ok(())
                    })?;
                    set.exact.shrink_to_fit();
                    set.suffix.shrink_to_fit();
                    out.matchers
                        .insert(("geosite".into(), tag), Matcher::Domains(Arc::new(set)));
                }
            }
        }
        // Classical providers can refer to geo data, but not recursively to providers.
        for (name, m) in providers {
            let bound = out.bind(&m)?;
            out.matchers.insert(("rule-set".into(), name), bound);
        }
        out.rules(&config.rules)?;
        pending.commit()?;
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
    pending: &mut Staged,
) -> Result<PathBuf> {
    let meta = std::fs::metadata(path).ok();
    let expired = refresh
        && interval.is_some_and(|v| v > 0)
        && meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .is_none_or(|age| age >= Duration::from_secs(interval.unwrap_or(0)));
    if let Some(meta) = &meta
        && !expired
    {
        ensure!(meta.len() <= LIMIT as u64, "resource exceeds size limit");
        return Ok(path.into());
    }
    ensure!(
        interval.is_some() && !url.is_empty(),
        "local routing resource is missing"
    );
    let (temp, mut file) = pending.create(path)?;
    let result = download(url, resolver, hooks, &mut file)
        .await
        .and_then(|_| Ok(file.sync_all()?))
        .with_context(|| {
            format!(
                "routing resource download failed ({})",
                path.file_name().unwrap_or_default().to_string_lossy()
            )
        });
    match result {
        Ok(()) => Ok(temp),
        // An expired file is still usable: stay on it rather than fail.
        Err(error) if meta.is_some() => {
            pending.discard(&temp);
            tracing::warn!(error = %format!("{error:#}"), "keeping the current routing resource");
            Ok(path.into())
        }
        Err(error) => Err(error),
    }
}

fn read_limited(path: &Path) -> Result<Vec<u8>> {
    ensure!(
        std::fs::metadata(path)?.len() <= LIMIT as u64,
        "resource exceeds size limit"
    );
    Ok(std::fs::read(path)?)
}

/// Downloads stream straight to disk under a temporary name (so a 16 MiB
/// geoip.dat is never held in memory) and replace the real files only after
/// the whole snapshot loaded. Dropping without `commit` removes the temporary
/// files, so a failed load never changes the files on disk.
#[derive(Default)]
struct Staged {
    files: Vec<(PathBuf, PathBuf)>,
}
impl Staged {
    fn create(&mut self, path: &Path) -> Result<(PathBuf, std::fs::File)> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        self.files.push((temp.clone(), path.into()));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        Ok((temp, file))
    }
    fn discard(&mut self, temp: &Path) {
        self.files.retain(|(staged, _)| staged != temp);
        let _ = std::fs::remove_file(temp);
    }
    fn commit(mut self) -> Result<()> {
        for (temp, path) in std::mem::take(&mut self.files) {
            std::fs::rename(&temp, &path)?;
        }
        Ok(())
    }
}
impl Drop for Staged {
    fn drop(&mut self) {
        for (temp, _) in &self.files {
            let _ = std::fs::remove_file(temp);
        }
    }
}

/// Minimal protobuf reader for geoip.dat/geosite.dat. Both are a list of
/// entries (field 1) that each start with a country code (field 1). Decoding
/// only the referenced entries keeps memory to a few MiB instead of building
/// every country's data, which matters inside the 50 MiB iOS tunnel extension.
mod wire {
    use anyhow::{Result, bail, ensure};

    fn varint(buf: &[u8], pos: &mut usize) -> Result<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            ensure!(*pos < buf.len(), "truncated protobuf varint");
            let byte = buf[*pos];
            *pos += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        bail!("protobuf varint too long")
    }

    /// Next field as (number, wire type, payload for length-delimited fields).
    fn field<'a>(buf: &'a [u8], pos: &mut usize) -> Result<(u64, u8, &'a [u8])> {
        let key = varint(buf, pos)?;
        let (number, wire) = (key >> 3, (key & 7) as u8);
        let start = *pos;
        let len = match wire {
            0 => {
                varint(buf, pos)?;
                return Ok((number, wire, &buf[start..*pos]));
            }
            1 => 8,
            2 => usize::try_from(varint(buf, pos)?)?,
            5 => 4,
            _ => bail!("unsupported protobuf wire type {wire}"),
        };
        let start = *pos;
        let end = start.checked_add(len).filter(|&end| end <= buf.len());
        let Some(end) = end else {
            bail!("truncated protobuf field")
        };
        *pos = end;
        Ok((number, wire, &buf[start..end]))
    }

    /// Calls `each` with the payload of every length-delimited `number` field.
    pub fn each_field(
        buf: &[u8],
        number: u64,
        mut each: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let mut pos = 0;
        while pos < buf.len() {
            let (n, wire, value) = field(buf, &mut pos)?;
            if n == number && wire == 2 {
                each(value)?;
            }
        }
        Ok(())
    }

    fn read_varint(reader: &mut impl std::io::Read) -> Result<Option<u64>> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let mut byte = [0u8];
            if reader.read(&mut byte)? == 0 {
                ensure!(shift == 0, "truncated protobuf varint");
                return Ok(None);
            }
            value |= u64::from(byte[0] & 0x7f) << shift;
            if byte[0] & 0x80 == 0 {
                return Ok(Some(value));
            }
        }
        bail!("protobuf varint too long")
    }

    /// Raw bytes of every top-level entry whose country code satisfies `wanted`.
    /// Streams the file: only an entry's first bytes are read to find its code,
    /// and unwanted entries are skipped with a seek.
    pub fn read_entries(
        path: &std::path::Path,
        wanted: impl Fn(&str) -> bool,
    ) -> Result<Vec<Vec<u8>>> {
        use std::io::Read;
        let mut reader = std::io::BufReader::with_capacity(64 * 1024, std::fs::File::open(path)?);
        let mut out = Vec::new();
        while let Some(key) = read_varint(&mut reader)? {
            ensure!(key & 7 == 2, "unexpected protobuf wire type in list");
            let len = usize::try_from(read_varint(&mut reader)?.unwrap_or(0))?;
            ensure!(len <= 128 * 1024 * 1024, "protobuf entry too large");
            // A country code is a few bytes; 256 covers it with room to spare.
            let mut entry = vec![0; len.min(256)];
            reader.read_exact(&mut entry)?;
            let mut pos = 0;
            let code = loop {
                if pos >= entry.len() {
                    break None;
                }
                match field(&entry, &mut pos) {
                    Ok((1, 2, value)) => break Some(std::str::from_utf8(value)?.to_owned()),
                    Ok(_) => continue,
                    Err(_) => break None, // field runs past the prefix
                }
            };
            let keep = key >> 3 == 1 && code.as_deref().is_none_or(&wanted);
            if keep {
                let prefix = entry.len();
                entry.resize(len, 0);
                reader.read_exact(&mut entry[prefix..])?;
                // Fall back to a full parse when the code was not in the prefix.
                if code.is_none() {
                    let mut matched = false;
                    each_field(&entry, 1, |value| {
                        matched |= wanted(std::str::from_utf8(value)?);
                        Ok(())
                    })?;
                    if !matched {
                        continue;
                    }
                }
                out.push(entry);
            } else {
                reader.seek_relative(i64::try_from(len - entry.len())?)?;
            }
        }
        Ok(out)
    }
}
#[derive(Clone, Copy)]
struct Timeouts {
    /// Waiting for the server: DNS, TCP, TLS and response headers.
    response: Duration,
    /// A body that delivers no data for this long is treated as stalled.
    idle: Duration,
    /// Hard cap so a trickling server cannot hold startup forever.
    total: Duration,
}
/// TCP connect plus TLS handshake for one server address.
const PER_ADDRESS_TIMEOUT: Duration = Duration::from_secs(10);
const TIMEOUTS: Timeouts = Timeouts {
    // Room to try three addresses before giving up on the response.
    response: Duration::from_secs(40),
    idle: Duration::from_secs(30),
    total: Duration::from_secs(300),
};

/// Large files (geoip.dat is ~16 MiB) may legitimately take minutes on a slow
/// link, so only lack of progress fails a download, not its total duration.
/// Writes the body to `sink` as it arrives and returns its length.
pub async fn download(
    url: &str,
    resolver: &crate::dns::Resolver,
    hooks: &meta_platform::Hooks,
    sink: &mut (dyn std::io::Write + Send),
) -> Result<usize> {
    download_with(url, resolver, hooks, TIMEOUTS, sink).await
}
async fn download_with(
    url: &str,
    resolver: &crate::dns::Resolver,
    hooks: &meta_platform::Hooks,
    timeouts: Timeouts,
    sink: &mut (dyn std::io::Write + Send),
) -> Result<usize> {
    tokio::time::timeout(timeouts.total, async {
        use http_body_util::{BodyExt, Empty};
        let mut url = url.to_owned();
        for _ in 0..6 {
            let uri: http::Uri = url.parse().context("invalid resource URL")?;
            let scheme = uri.scheme_str().unwrap_or("").to_owned();
            ensure!(
                scheme == "https" || scheme == "http",
                "resource URL must use HTTP(S)"
            );
            let (response, driver) = tokio::time::timeout(timeouts.response, async {
                let target = meta_protocol::Target::from_uri(
                    &uri,
                    if scheme == "https" { 443 } else { 80 },
                )?;
                let addresses = resolver.lookup(&target.host, target.port).await?;
                // CDNs return several addresses and one can accept TCP yet stall
                // the TLS handshake on a lossy route; bound each address and move on.
                let (mut stream, mut failure) = (None, None);
                for addr in addresses {
                    let attempt = tokio::time::timeout(PER_ADDRESS_TIMEOUT, async {
                        let socket = tokio::time::timeout(
                            Duration::from_secs(5),
                            meta_platform::tcp_connect(addr, &**hooks),
                        )
                        .await
                        .map_err(|_| anyhow::anyhow!("TCP connect to {addr} timed out"))??;
                        let stream: meta_protocol::BoxStream = if scheme == "https" {
                            meta_protocol::tls::SecureConnector::new(resolver.clock())
                                .connect(
                                    Box::new(socket),
                                    &meta_protocol::tls::TlsConnectConfig {
                                        server_name: target.host.clone(),
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
                        anyhow::Ok(stream)
                    })
                    .await;
                    match attempt {
                        Ok(Ok(connected)) => {
                            stream = Some(connected);
                            break;
                        }
                        Ok(Err(error)) => failure = Some(error),
                        Err(_) => {
                            failure = Some(anyhow::anyhow!("handshake with {addr} timed out"))
                        }
                    }
                }
                let stream = match stream {
                    Some(stream) => stream,
                    None => {
                        let error = failure.unwrap_or_else(|| anyhow::anyhow!("no address"));
                        return Err(error.context("cannot connect to resource server"));
                    }
                };
                let (mut sender, connection) =
                    hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                        .await?;
                let driver = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(connection));
                let request = http::Request::get(uri.path_and_query().map_or("/", |v| v.as_str()))
                    .header(
                        http::header::HOST,
                        uri.authority()
                            .context("missing resource authority")?
                            .as_str(),
                    )
                    .header(http::header::USER_AGENT, "clyntis")
                    .body(Empty::<bytes::Bytes>::new())?;
                anyhow::Ok((sender.send_request(request).await?, driver))
            })
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "resource server did not respond within {}s",
                    timeouts.response.as_secs()
                )
            })??;
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
            let mut body = response.into_body();
            let mut received = 0usize;
            loop {
                let frame = tokio::time::timeout(timeouts.idle, body.frame())
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "resource download stalled: no data for {:.0}s after {} bytes",
                            timeouts.idle.as_secs_f32(),
                            received
                        )
                    })?;
                let Some(frame) = frame else { break };
                let frame = frame.map_err(|_| anyhow::anyhow!("resource body failed"))?;
                if let Some(chunk) = frame.data_ref() {
                    ensure!(
                        received + chunk.len() <= LIMIT,
                        "resource exceeds size limit"
                    );
                    sink.write_all(chunk)?;
                    received += chunk.len();
                }
            }
            drop(driver);
            return Ok(received);
        }
        bail!("too many resource redirects")
    })
    .await
    .map_err(|_| anyhow::anyhow!("resource download exceeded {}s", timeouts.total.as_secs()))?
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

#[cfg(test)] // Only used to encode test fixtures; loading decodes entries lazily.
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
#[cfg(test)] // Only used to encode test fixtures; loading decodes entries lazily.
#[derive(Clone, PartialEq, Message)]
struct GeoSiteList {
    #[prost(message, repeated, tag = "1")]
    entry: Vec<GeoSite>,
}
#[cfg(test)] // Only used to encode test fixtures; domains are decoded one by one.
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
    /// Serves a body in timed chunks: (delay before chunk, bytes).
    async fn slow_server(chunks: Vec<(u64, &'static [u8])>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let _ = socket.read(&mut request).await;
            let total: usize = chunks.iter().map(|(_, c)| c.len()).sum();
            socket
                .write_all(format!("HTTP/1.1 200 OK\r\ncontent-length: {total}\r\n\r\n").as_bytes())
                .await
                .unwrap();
            for (delay, chunk) in chunks {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                if socket.write_all(chunk).await.is_err() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        format!("http://{address}/data")
    }
    fn short() -> Timeouts {
        Timeouts {
            response: Duration::from_secs(2),
            idle: Duration::from_millis(500),
            total: Duration::from_secs(10),
        }
    }
    #[test]
    fn read_entries_streams_only_the_wanted_categories() {
        let site = |code: &str, domains: usize| GeoSite {
            country_code: code.into(),
            domain: (0..domains)
                .map(|i| Domain {
                    kind: 2,
                    value: format!("{code}{i}.test"),
                    attribute: vec![],
                })
                .collect(),
        };
        // A large unwanted entry first, so skipping must seek past it.
        let list = GeoSiteList {
            entry: vec![site("big", 5000), site("CN", 3), site("other", 10)],
        };
        let path = std::env::temp_dir().join(format!("meta-geosite-{}.dat", uuid::Uuid::new_v4()));
        std::fs::write(&path, list.encode_to_vec()).unwrap();
        let entries = wire::read_entries(&path, |code| code.eq_ignore_ascii_case("cn")).unwrap();
        assert_eq!(entries.len(), 1);
        let decoded = GeoSite::decode(entries[0].as_slice()).unwrap();
        assert_eq!(decoded.country_code, "CN");
        assert_eq!(decoded.domain.len(), 3);
        assert!(wire::read_entries(&path, |_| false).unwrap().is_empty());
        std::fs::remove_file(path).unwrap();
    }
    /// A geosite.dat with one "test" category, expired, whose update URL points
    /// at a listener that counts connection attempts and never answers.
    async fn expired_geosite(
        host_packet_io: bool,
    ) -> (Config, Arc<std::sync::atomic::AtomicUsize>) {
        let dir = std::env::temp_dir().join(format!("meta-reuse-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let list = GeoSiteList {
            entry: vec![GeoSite {
                country_code: "test".into(),
                domain: vec![Domain {
                    kind: 2,
                    value: "example.test".into(),
                    attribute: vec![],
                }],
            }],
        };
        let path = dir.join("geosite.dat");
        std::fs::write(&path, list.encode_to_vec()).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::SystemTime::now() - Duration::from_secs(7200)),
            )
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = attempts.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(socket); // fails the download
            }
        });
        let mut config = Config {
            directory: dir,
            rules: vec!["GEOSITE,test,REJECT".into()],
            geo_auto_update: true,
            geo_update_interval: 1,
            internal_host_packet_io: host_packet_io,
            ..Config::default()
        };
        config.geox_url.geosite = format!("http://{address}/geosite.dat");
        (config, attempts)
    }
    fn domains(resources: &Resources) -> Arc<DomainSet> {
        match resources.matchers.get(&("geosite".into(), "test".into())) {
            Some(Matcher::Domains(set)) => set.clone(),
            _ => panic!("geosite matcher missing"),
        }
    }

    #[tokio::test]
    async fn unchanged_geo_data_is_reused_and_failed_updates_keep_the_file() {
        let (config, attempts) = expired_geosite(false).await;
        let dns =
            crate::dns::Resolver::new(Default::default(), Arc::new(meta_platform::DefaultHooks));
        let hooks: meta_platform::Hooks = Arc::new(meta_platform::DefaultHooks);
        let first = Resources::load(&config, &dns, &hooks, false, &Resources::default())
            .await
            .unwrap();
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 0);
        // Desktop refresh tries the expired file, fails, and keeps the local copy;
        // the unchanged file means the old matcher is reused, not rebuilt.
        let second = Resources::load(&config, &dns, &hooks, true, &first)
            .await
            .unwrap();
        assert!(attempts.load(std::sync::atomic::Ordering::SeqCst) > 0);
        assert!(Arc::ptr_eq(&domains(&first), &domains(&second)));
        assert!(domains(&second).matches("www.example.test"));
        std::fs::remove_dir_all(&config.directory).unwrap();
    }

    #[tokio::test]
    async fn hosted_tunnels_refresh_geo_data_only_at_start() {
        let (config, attempts) = expired_geosite(true).await;
        let dns =
            crate::dns::Resolver::new(Default::default(), Arc::new(meta_platform::DefaultHooks));
        let hooks: meta_platform::Hooks = Arc::new(meta_platform::DefaultHooks);
        // Start: no previous snapshot, so the expired file is checked (and kept on failure).
        let first = Resources::load(&config, &dns, &hooks, true, &Resources::default())
            .await
            .unwrap();
        let at_start = attempts.load(std::sync::atomic::Ordering::SeqCst);
        assert!(at_start > 0);
        // While running: no download, the matcher is carried over.
        let second = Resources::load(&config, &dns, &hooks, true, &first)
            .await
            .unwrap();
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), at_start);
        assert!(Arc::ptr_eq(&domains(&first), &domains(&second)));
        std::fs::remove_dir_all(&config.directory).unwrap();
    }

    #[tokio::test]
    async fn slow_but_steady_download_outlives_the_idle_timeout() {
        let resolver =
            crate::dns::Resolver::new(Default::default(), Arc::new(meta_platform::DefaultHooks));
        let hooks: meta_platform::Hooks = Arc::new(meta_platform::DefaultHooks);
        // Takes ~1.5s in total, three times the idle limit, but never pauses for long.
        let url = slow_server((0..6).map(|_| (250, &b"chunk"[..])).collect()).await;
        let mut data = Vec::new();
        let received = download_with(&url, &resolver, &hooks, short(), &mut data)
            .await
            .unwrap();
        assert_eq!(data, b"chunk".repeat(6));
        assert_eq!(received, data.len());
    }
    #[tokio::test]
    async fn stalled_download_reports_progress_instead_of_a_bare_deadline() {
        let resolver =
            crate::dns::Resolver::new(Default::default(), Arc::new(meta_platform::DefaultHooks));
        let hooks: meta_platform::Hooks = Arc::new(meta_platform::DefaultHooks);
        let url = slow_server(vec![(0, b"partial"), (3000, b"rest")]).await;
        let error = download_with(&url, &resolver, &hooks, short(), &mut Vec::new())
            .await
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("stalled") && message.contains("after 7 bytes"),
            "{message}"
        );
    }
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
        let resources = Resources::load(&c, &dns, &hooks, false, &Resources::default())
            .await
            .unwrap();
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
        assert!(
            Resources::load(&c, &dns, &hooks, false, &Resources::default())
                .await
                .is_err()
        );
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
