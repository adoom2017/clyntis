//! Immutable routing snapshots. A failed refresh leaves the active snapshot intact.
use anyhow::{Context, Result, bail, ensure};
use clyntis_config::{
    Config, RuleProvider,
    rule::{DomainSetBuilder, IpMatcher, IpSet, Matcher, Rule},
};
use prost::Message;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

const MODULE_LIMIT: usize = 2 << 20;
const HOSTED_MOCK_LIMIT: usize = 2 << 20;
const HOSTED_LIMIT: usize = 16 * 1024 * 1024;
const LIMIT: usize = 128 * 1024 * 1024;

const fn rewrite_mock_limit(hosted: bool) -> usize {
    if hosted { HOSTED_MOCK_LIMIT } else { LIMIT }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoadMode {
    /// Explicit prefetch/validation: all routing data must be usable.
    Required,
    /// Startup: read local files only; unavailable resources never block it.
    Cached,
    /// Running: fetch independently, keeping usable data on each failure.
    Available,
}
#[derive(Default)]
pub struct Resources {
    partial: bool,
    routing_incomplete: AtomicBool,
    matchers: HashMap<(String, String), Matcher>,
    /// Geo categories already confirmed absent from the current geo file on disk.
    missing_geo: HashSet<(String, String)>,
    /// 64-bit content hash of each loaded geo category's raw protobuf entry,
    /// so `geo-auto-update` can reuse unchanged `Arc<DomainSet>` / `Arc<IpSet>`.
    geo_hashes: HashMap<(String, String), u64>,
    /// Shared MMDB reader for `Country.mmdb` so dynamic GeoIP rules do not reload it.
    mmdb: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
    /// Ad blocking lists, when `adblock.enable`.
    pub adblock: Option<Arc<crate::adblock::Filter>>,
    /// Rewrite modules, when `rewrite.enable`.
    pub rewrite: Option<Arc<crate::rewrite::Rewriter>>,
    /// What the file-backed providers and the ad blocking lists were built
    /// from: a refresh that finds the same contents reuses them instead of
    /// parsing again while the active snapshot still holds the old copy.
    providers: HashMap<String, (ProviderSource, Matcher)>,
    adblock_sources: Vec<ListSource>,
    adblock_cache: HashMap<(String, String, Stamp), CachedAdblockList>,
    rewrite_sources: Option<RewriteSource>,
}
/// Lightweight marker for an adblock list cached by `(url, format, stamp)`
/// so partial refreshes reuse the on-disk binary cache without pinning
/// duplicate `DomainSetBuilder` / `Vec<IpNet>` copies in memory.
#[derive(Clone, Copy)]
struct CachedAdblockList;
/// What the rewrite modules were compiled from.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RewriteSource {
    custom: String,
    modules: Vec<(clyntis_config::rewrite::Source, Option<Stamp>)>,
    // Availability affects which rules compile; file bytes are rebound on reload.
    files: Vec<(String, bool)>,
}

/// A file's length and SHA-256: unchanged contents, whatever the mtime (a
/// periodic download of the same list replaces the file).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Stamp {
    len: u64,
    digest: [u8; 32],
}
impl Stamp {
    fn of(path: &Path) -> Result<Self> {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        let len = std::io::copy(&mut std::fs::File::open(path)?, &mut hasher)?;
        Ok(Self {
            len,
            digest: hasher.finalize().into(),
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProviderSource {
    behavior: String,
    format: String,
    stamp: Stamp,
}
/// One configured list and its contents; `None` when it could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ListSource {
    list: clyntis_config::adblock::List,
    stamp: Option<Stamp>,
}
impl Resources {
    fn clone_snapshot(&self) -> Self {
        Self {
            partial: self.partial,
            routing_incomplete: AtomicBool::new(self.routing_incomplete()),
            matchers: self.matchers.clone(),
            missing_geo: self.missing_geo.clone(),
            geo_hashes: self.geo_hashes.clone(),
            mmdb: self.mmdb.clone(),
            adblock: self.adblock.clone(),
            rewrite: self.rewrite.clone(),
            providers: self.providers.clone(),
            adblock_sources: self.adblock_sources.clone(),
            adblock_cache: self.adblock_cache.clone(),
            rewrite_sources: self.rewrite_sources.clone(),
        }
    }
    fn routing_incomplete(&self) -> bool {
        self.routing_incomplete.load(Ordering::Relaxed)
    }
    pub(crate) fn mark_incomplete(&self) {
        self.routing_incomplete.store(true, Ordering::Relaxed);
    }
    /// A failed geo file must not prevent other resources from being applied.
    fn recover_geo(
        &mut self,
        result: Result<()>,
        kind: &str,
        tags: &[String],
        previous: &Self,
    ) -> Result<()> {
        if let Err(error) = result {
            if !self.partial {
                return Err(error);
            }
            self.mark_incomplete();
            tracing::warn!(resource = kind, error = %format!("{error:#}"), "routing data unavailable; retaining cached rules or skipping");
            if kind == "geoip" {
                self.mmdb = previous.mmdb.clone();
            }
            for tag in tags {
                let key = (kind.to_owned(), tag.clone());
                self.matchers.remove(&key);
                self.missing_geo.remove(&key);
                if let Some(matcher) = previous.matchers.get(&key) {
                    self.matchers.insert(key, matcher.clone());
                } else if previous.missing_geo.contains(&key) {
                    self.missing_geo.insert(key);
                }
            }
        }
        Ok(())
    }
    /// Copies the `kind` matchers for every tag in `tags` into `out` when this
    /// snapshot has all of them; matchers share their data through `Arc`.
    fn reuse(&self, kind: &str, tags: &[String], out: &mut Resources) -> bool {
        let mut found = Vec::with_capacity(tags.len());
        let mut missing = Vec::new();
        for tag in tags {
            let key = (kind.to_owned(), tag.clone());
            if let Some(m) = self.matchers.get(&key) {
                found.push((key, m.clone()));
            } else if self.missing_geo.contains(&key) {
                missing.push(key);
            } else {
                return false;
            }
        }
        out.matchers.extend(found);
        out.missing_geo.extend(missing);
        for ((k, c), h) in &self.geo_hashes {
            if k == kind {
                out.geo_hashes.insert((k.clone(), c.clone()), *h);
            }
        }
        if kind == "geoip" {
            out.mmdb = self.mmdb.clone();
        }
        true
    }
    pub fn incomplete(&self) -> bool {
        self.routing_incomplete()
            || self
                .adblock
                .as_ref()
                .is_some_and(|f| f.lists.iter().any(|l| l.error.is_some()))
            || self.rewrite.as_ref().is_some_and(|r| {
                r.modules
                    .iter()
                    .any(|m| m.error.is_some() || !m.missing.is_empty())
            })
    }
    /// Whether DNS policies, fake-IP filters and ad-blocking sets are unchanged
    /// from `other`, so a retry that added nothing does not wipe the DNS cache.
    pub(crate) fn shares_dns(&self, other: &Self) -> bool {
        let is_dns = |((kind, _), _): &(&(String, String), &Matcher)| {
            kind == "geosite" || kind == "rule-set"
        };
        let count = |res: &Self| res.matchers.iter().filter(is_dns).count();
        self.partial == other.partial
            && count(self) == count(other)
            && self.matchers.iter().filter(is_dns).all(|(key, matcher)| {
                other
                    .matchers
                    .get(key)
                    .is_some_and(|other| same_matcher(matcher, other))
            })
            && match (&self.adblock, &other.adblock) {
                (None, None) => true,
                (Some(a), Some(b)) => a.shares_lists(b),
                _ => false,
            }
    }
    /// Loads any newly-referenced GeoIP/GeoSite categories from local cache, or
    /// marks the snapshot incomplete if a required geo file is absent.
    pub(crate) fn with_cached_geo(
        self: &Arc<Self>,
        config: &Config,
        raw_rules: &[String],
    ) -> Arc<Self> {
        let mut refs = Vec::new();
        for rule in raw_rules {
            if let Ok(parsed) = Rule::parse(rule) {
                parsed.matcher.references(&mut refs);
            }
        }
        let mut seen = HashSet::new();
        refs.retain(|r| seen.insert(r.clone()));
        let missing_ip: Vec<_> = refs
            .iter()
            .filter(|(kind, tag)| {
                kind == "geoip"
                    && !self.matchers.contains_key(&(kind.clone(), tag.clone()))
                    && !self.missing_geo.contains(&(kind.clone(), tag.clone()))
            })
            .map(|(_, tag)| tag.clone())
            .collect();
        let missing_site: Vec<_> = refs
            .iter()
            .filter(|(kind, tag)| {
                kind == "geosite"
                    && !self.matchers.contains_key(&(kind.clone(), tag.clone()))
                    && !self.missing_geo.contains(&(kind.clone(), tag.clone()))
            })
            .map(|(_, tag)| tag.clone())
            .collect();
        if missing_ip.is_empty() && missing_site.is_empty() {
            return self.clone();
        }
        let mut out = self.clone_snapshot();
        if !missing_ip.is_empty() {
            let path = config.directory.join(if config.geodata_mode {
                "geoip.dat"
            } else {
                "Country.mmdb"
            });
            if !path.exists()
                || populate_geoip(
                    &path,
                    config.geodata_mode,
                    &missing_ip,
                    self,
                    true,
                    &mut out,
                )
                .is_err()
            {
                out.mark_incomplete();
            }
        }
        if !missing_site.is_empty() {
            let path = config.directory.join("geosite.dat");
            if !path.exists() || populate_geosite(&path, &missing_site, self, &mut out).is_err() {
                out.mark_incomplete();
            }
        }
        Arc::new(out)
    }
    pub fn bind(&self, matcher: &Matcher) -> Result<Matcher> {
        match self.bind_required(matcher) {
            Ok(bound) => Ok(bound),
            // Disable the WHOLE condition, including NOT and compound rules.
            // Replacing only a missing child with false could turn NOT into true.
            Err(_) if self.partial => Ok(Matcher::Or(Arc::from([]))),
            Err(error) => Err(error),
        }
    }
    fn bind_required(&self, matcher: &Matcher) -> Result<Matcher> {
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
        hooks: &clyntis_platform::Hooks,
        refresh: bool,
        previous: &Resources,
        via: Option<&crate::Core>,
    ) -> Result<Self> {
        Self::load_with(
            config,
            resolver,
            hooks,
            refresh,
            previous,
            via,
            LoadMode::Required,
        )
        .await
    }
    pub(crate) async fn load_with(
        config: &Config,
        resolver: &crate::dns::Resolver,
        hooks: &clyntis_platform::Hooks,
        refresh: bool,
        previous: &Resources,
        via: Option<&crate::Core>,
        mode: LoadMode,
    ) -> Result<Self> {
        if mode == LoadMode::Cached {
            crate::rewrite::clean_stale_files(&config.directory);
        }
        let proxy = via.and_then(|core| core.resource_proxy().map(|name| (core, name)));
        let limit = if config.internal_host_packet_io {
            HOSTED_LIMIT
        } else {
            LIMIT
        };
        let fetch = Fetch {
            limit,
            resolver,
            hooks,
            proxy: proxy.as_ref().map(|(core, name)| (*core, name.as_str())),
            download: mode != LoadMode::Cached,
        };
        let refresh = refresh && fetch.download;
        // Unchanged geo data shares its compiled sets with the live snapshot.
        let geo_refresh = refresh;
        let mut refs = references(config)?;
        let mut providers = HashMap::new();
        let mut out = Self {
            partial: mode != LoadMode::Required,
            ..Self::default()
        };
        for (name, p) in &config.rule_providers {
            let mut staged = Staged::default();
            let loaded: Result<Matcher> = async {
                let matcher = if p.kind == "inline" {
                    provider_matcher(p, &p.payload)?
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
                        &fetch,
                        &mut staged,
                    )
                    .await?;
                    let stamp = Stamp::of(&data)?;
                    let source = ProviderSource {
                        behavior: p.behavior.clone(),
                        format: p.format.clone(),
                        stamp,
                    };
                    let matcher = match previous.providers.get(name) {
                        Some((built, matcher)) if *built == source => matcher.clone(),
                        _ => load_provider_matcher_cached(p, &data, Some((&path, stamp)))?,
                    };
                    staged.commit()?;
                    out.providers
                        .insert(name.clone(), (source, matcher.clone()));
                    matcher
                };
                Ok(matcher)
            }
            .await;
            let matcher = match loaded {
                Ok(matcher) => matcher,
                Err(error) if mode != LoadMode::Required => {
                    if p.kind == "http" {
                        out.mark_incomplete();
                    }
                    tracing::warn!(provider = %name, error = %format!("{error:#}"), "rule provider unavailable; retaining cached rules or skipping");
                    let Some((source, matcher)) = previous.providers.get(name) else {
                        continue;
                    };
                    out.providers
                        .insert(name.clone(), (source.clone(), matcher.clone()));
                    matcher.clone()
                }
                Err(error) => return Err(error),
            };
            matcher.references(&mut refs);
            providers.insert(name.clone(), matcher);
        }
        let mut seen = HashSet::new();
        refs.retain(|r| seen.insert(r.clone()));
        let ip_refs: Vec<_> = refs
            .iter()
            .filter(|r| r.0 == "geoip")
            .map(|r| r.1.clone())
            .collect();
        if !ip_refs.is_empty() {
            let mut staged = Staged::default();
            let result: Result<()> = async {
                let path = config.directory.join(if config.geodata_mode {
                    "geoip.dat"
                } else {
                    "Country.mmdb"
                });
                let url = if config.geodata_mode {
                    &config.geox_url.geoip
                } else {
                    &config.geox_url.mmdb
                };
                let data = asset(
                    &path,
                    url,
                    geo_interval(config),
                    geo_refresh,
                    &fetch,
                    &mut staged,
                )
                .await?;
                if data == path && previous.reuse("geoip", &ip_refs, &mut out) {
                    // Unchanged file: the matchers were carried over.
                    staged.commit()?;
                } else {
                    populate_geoip(
                        &data,
                        config.geodata_mode,
                        &ip_refs,
                        previous,
                        data == path,
                        &mut out,
                    )?;
                    staged.commit()?;
                }
                Ok(())
            }
            .await;
            out.recover_geo(result, "geoip", &ip_refs, previous)?;
        }
        let site_refs: Vec<_> = refs
            .iter()
            .filter(|r| r.0 == "geosite")
            .map(|r| r.1.clone())
            .collect();
        if !site_refs.is_empty() {
            let mut staged = Staged::default();
            let result: Result<()> = async {
                let path = config.directory.join("geosite.dat");
                let data = asset(
                    &path,
                    &config.geox_url.geosite,
                    geo_interval(config),
                    geo_refresh,
                    &fetch,
                    &mut staged,
                )
                .await?;
                if data == path && previous.reuse("geosite", &site_refs, &mut out) {
                    // Unchanged file: the matchers were carried over.
                    staged.commit()?;
                } else {
                    populate_geosite(&data, &site_refs, previous, &mut out)?;
                    staged.commit()?;
                }
                Ok(())
            }
            .await;
            out.recover_geo(result, "geosite", &site_refs, previous)?;
        }
        // Classical providers can refer to geo data, but not recursively to providers.
        for (name, m) in providers {
            match out.bind_required(&m) {
                Ok(bound) => {
                    out.matchers.insert(("rule-set".into(), name), bound);
                }
                Err(_) if out.partial => {}
                Err(error) => return Err(error),
            }
        }
        out.rules(&config.rules)?;
        (out.adblock, out.adblock_sources, out.adblock_cache) =
            adblock(config, refresh, &fetch, previous).await;
        (out.rewrite, out.rewrite_sources) = rewrite(config, refresh, &fetch, previous).await;
        Ok(out)
    }
}

fn same_matcher(a: &Matcher, b: &Matcher) -> bool {
    match (a, b) {
        (Matcher::Domain(a), Matcher::Domain(b))
        | (Matcher::Suffix(a), Matcher::Suffix(b))
        | (Matcher::Subdomain(a), Matcher::Subdomain(b))
        | (Matcher::Keyword(a), Matcher::Keyword(b))
        | (Matcher::Network(a), Matcher::Network(b))
        | (Matcher::GeoIp(a), Matcher::GeoIp(b))
        | (Matcher::GeoSite(a), Matcher::GeoSite(b))
        | (Matcher::RuleSet(a), Matcher::RuleSet(b)) => a == b,
        (Matcher::Glob(a), Matcher::Glob(b)) | (Matcher::Wildcard(a), Matcher::Wildcard(b)) => {
            a == b
        }
        (Matcher::Regex(a), Matcher::Regex(b)) => a.as_str() == b.as_str(),
        (Matcher::Net(a), Matcher::Net(b)) => a == b,
        (Matcher::Port(a), Matcher::Port(b)) => a == b,
        (Matcher::Ports(a), Matcher::Ports(b)) => a == b,
        (Matcher::OnNetwork(a), Matcher::OnNetwork(b)) => Arc::ptr_eq(a, b),
        (Matcher::And(a), Matcher::And(b)) | (Matcher::Or(a), Matcher::Or(b)) => {
            Arc::ptr_eq(a, b)
                || (a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| same_matcher(x, y)))
        }
        (Matcher::Not(a), Matcher::Not(b)) | (Matcher::NoResolve(a), Matcher::NoResolve(b)) => {
            Arc::ptr_eq(a, b) || same_matcher(a, b)
        }
        (Matcher::Domains(a), Matcher::Domains(b)) => Arc::ptr_eq(a, b),
        (Matcher::Nets(a), Matcher::Nets(b)) => Arc::ptr_eq(a, b),
        (Matcher::ExternalIp(a), Matcher::ExternalIp(b)) => Arc::ptr_eq(a, b),
        (Matcher::All, Matcher::All) => true,
        _ => false,
    }
}

fn geo_entry_hash(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

fn populate_geoip(
    data: &Path,
    geodata_mode: bool,
    ip_refs: &[String],
    previous: &Resources,
    reuse_db: bool,
    out: &mut Resources,
) -> Result<()> {
    if geodata_mode {
        let mut by_code: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, tag) in ip_refs.iter().enumerate() {
            let code = tag.trim_start_matches('!').to_ascii_lowercase();
            by_code.entry(code).or_default().push(idx);
        }
        let mut seen: HashSet<String> = HashSet::with_capacity(by_code.len());
        wire::stream_entries(
            data,
            |code| by_code.contains_key(&code.to_ascii_lowercase()),
            |code, entry| {
                let code_lower = code.to_ascii_lowercase();
                let Some(indices) = by_code.get(&code_lower) else {
                    return Ok(());
                };
                if !seen.insert(code_lower.clone()) {
                    return Ok(());
                }
                let hash = geo_entry_hash(entry);
                let hash_key = ("geoip".to_owned(), code_lower);
                let prev_unchanged = previous.geo_hashes.get(&hash_key) == Some(&hash);
                out.geo_hashes.insert(hash_key, hash);

                let mut decoded: Option<(Vec<ipnet::IpNet>, bool)> = None;
                for &idx in indices {
                    let tag = &ip_refs[idx];
                    let key_pair = ("geoip".to_owned(), tag.clone());
                    if prev_unchanged && let Some(prev_matcher) = previous.matchers.get(&key_pair) {
                        out.missing_geo.remove(&key_pair);
                        out.matchers.insert(key_pair, prev_matcher.clone());
                        continue;
                    }
                    let (nets, entry_inverse) = match &decoded {
                        Some(d) => d,
                        None => {
                            let mut nets = Vec::new();
                            let mut entry_inverse = false;
                            wire::each_raw_field(entry, |number, wire_type, value| {
                                match number {
                                    1 => ensure!(wire_type == 2, "invalid geoip.dat"),
                                    2 => {
                                        ensure!(wire_type == 2, "invalid geoip.dat");
                                        nets.push(decode_geoip_cidr(value)?);
                                    }
                                    3 => {
                                        ensure!(wire_type == 0, "invalid geoip.dat");
                                        entry_inverse = wire::decode_varint(value)? != 0;
                                    }
                                    _ => {}
                                }
                                Ok(())
                            })?;
                            decoded.insert((nets, entry_inverse))
                        }
                    };
                    let inverse = tag.starts_with('!');
                    out.missing_geo.remove(&key_pair);
                    out.matchers.insert(
                        key_pair,
                        Matcher::Nets(Arc::new(IpSet::new(
                            nets.iter().copied(),
                            *entry_inverse ^ inverse,
                        ))),
                    );
                }
                Ok(())
            },
        )
        .context("invalid geoip.dat")?;

        for (code, indices) in &by_code {
            if seen.contains(code) {
                continue;
            }
            for &idx in indices {
                let tag = &ip_refs[idx];
                if !out.partial {
                    bail!("GEOIP category missing from data");
                }
                tracing::warn!(
                    resource = "geoip",
                    tag = %tag,
                    "GEOIP category missing from data; retaining cached rules or skipping"
                );
                let key_pair = ("geoip".to_owned(), tag.clone());
                if let Some(matcher) = previous.matchers.get(&key_pair) {
                    out.matchers.insert(key_pair, matcher.clone());
                } else {
                    out.missing_geo.insert(key_pair);
                }
            }
        }
    } else {
        let db = if reuse_db {
            out.mmdb.as_ref().or(previous.mmdb.as_ref()).cloned()
        } else {
            None
        };
        let db = match db {
            Some(db) => db,
            None => Arc::new(
                maxminddb::Reader::from_source(read_limited(data)?)
                    .context("invalid Country.mmdb")?,
            ),
        };
        out.mmdb = Some(db.clone());
        for tag in ip_refs {
            let key_pair = ("geoip".to_owned(), tag.clone());
            out.missing_geo.remove(&key_pair);
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
                out.matchers
                    .insert(key_pair, Matcher::Nets(Arc::new(IpSet::new(nets, false))));
            } else {
                out.matchers.insert(
                    key_pair,
                    Matcher::ExternalIp(Arc::new(Country {
                        db: db.clone(),
                        tag: tag.clone(),
                    })),
                );
            }
        }
    }
    Ok(())
}

fn populate_geosite(
    data: &Path,
    site_refs: &[String],
    previous: &Resources,
    out: &mut Resources,
) -> Result<()> {
    let mut by_code: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, tag) in site_refs.iter().enumerate() {
        let code = tag.split('@').next().unwrap_or("").to_ascii_lowercase();
        by_code.entry(code).or_default().push(idx);
    }
    let mut seen: HashSet<String> = HashSet::with_capacity(by_code.len());
    wire::stream_entries(
        data,
        |code| by_code.contains_key(&code.to_ascii_lowercase()),
        |code, entry| {
            let code_lower = code.to_ascii_lowercase();
            let Some(indices) = by_code.get(&code_lower) else {
                return Ok(());
            };
            if !seen.insert(code_lower.clone()) {
                return Ok(());
            }
            let hash = geo_entry_hash(entry);
            let hash_key = ("geosite".to_owned(), code_lower);
            let prev_unchanged = previous.geo_hashes.get(&hash_key) == Some(&hash);
            out.geo_hashes.insert(hash_key, hash);

            for &idx in indices {
                let tag = &site_refs[idx];
                let key_pair = ("geosite".to_owned(), tag.clone());
                if prev_unchanged && let Some(prev_matcher) = previous.matchers.get(&key_pair) {
                    out.missing_geo.remove(&key_pair);
                    out.matchers.insert(key_pair, prev_matcher.clone());
                    continue;
                }
                let mut parts = tag.split('@');
                let _ = parts.next();
                let attrs: Vec<_> = parts.collect();
                let mut set = DomainSetBuilder::default();
                if attrs.is_empty() {
                    wire::each_field(entry, 2, |bytes| {
                        let mut kind: i32 = 0;
                        let mut value: &str = "";
                        wire::each_raw_field(bytes, |number, wire_type, val| {
                            match number {
                                1 => {
                                    ensure!(wire_type == 0, "invalid geosite.dat");
                                    kind = i32::try_from(wire::decode_varint(val)?)?;
                                }
                                2 => {
                                    ensure!(wire_type == 2, "invalid geosite.dat");
                                    value =
                                        std::str::from_utf8(val).context("invalid geosite.dat")?;
                                }
                                _ => {}
                            }
                            Ok(())
                        })?;
                        match kind {
                            0 => set.keyword(value),
                            1 => set.regex(value)?,
                            2 => set.suffix(value),
                            3 => set.exact(value),
                            _ => bail!("invalid geosite domain type"),
                        }
                        Ok(())
                    })?;
                } else {
                    wire::each_field(entry, 2, |bytes| {
                        let d = Domain::decode(bytes).context("invalid geosite.dat")?;
                        if !attrs.iter().all(|attr| {
                            let (name, inverse) =
                                attr.strip_prefix('!').map_or((*attr, false), |v| (v, true));
                            d.attribute.iter().any(|a| a.key.eq_ignore_ascii_case(name)) ^ inverse
                        }) {
                            return Ok(());
                        }
                        match d.kind {
                            0 => set.keyword(&d.value),
                            1 => set.regex(&d.value)?,
                            2 => set.suffix(&d.value),
                            3 => set.exact(&d.value),
                            _ => bail!("invalid geosite domain type"),
                        }
                        Ok(())
                    })?;
                }
                out.missing_geo.remove(&key_pair);
                out.matchers
                    .insert(key_pair, Matcher::Domains(Arc::new(set.build())));
            }
            Ok(())
        },
    )
    .context("invalid geosite.dat")?;

    for (code, indices) in &by_code {
        if seen.contains(code) {
            continue;
        }
        for &idx in indices {
            let tag = &site_refs[idx];
            if !out.partial {
                bail!("GEOSITE category missing from data");
            }
            tracing::warn!(
                resource = "geosite",
                tag = %tag,
                "GEOSITE category missing from data; retaining cached rules or skipping"
            );
            let key_pair = ("geosite".to_owned(), tag.clone());
            if let Some(matcher) = previous.matchers.get(&key_pair) {
                out.matchers.insert(key_pair, matcher.clone());
            } else {
                out.missing_geo.insert(key_pair);
            }
        }
    }
    Ok(())
}

/// Loads the ad blocking lists. A list that cannot be fetched or parsed is
/// reported and left out: blocking must never stop the core from starting.
/// Lists whose contents did not change since `previous` keep its compiled
/// sets: rebuilding ~100,000 domains next to the live copy every refresh
/// costs the iOS tunnel several MiB of its ~50 MiB.
async fn adblock(
    config: &Config,
    refresh: bool,
    fetch: &Fetch<'_>,
    previous: &Resources,
) -> (
    Option<Arc<crate::adblock::Filter>>,
    Vec<ListSource>,
    HashMap<(String, String, Stamp), CachedAdblockList>,
) {
    let settings = &config.adblock;
    // Without lists the built-in endpoints and QUIC fallback still apply.
    if !settings.enable {
        return (None, vec![], HashMap::new());
    }
    struct Resolved {
        data: Result<PathBuf>,
        stamp: Option<Stamp>,
        updated: Option<u64>,
    }
    let mut resolved = Vec::new();
    let mut sources = Vec::new();
    for list in &settings.lists {
        let path = config.directory.join(list.file_name());
        let mut staged = Staged::default();
        let data: Result<PathBuf> = async {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            asset(
                &path,
                &list.url,
                Some(settings.interval),
                refresh,
                fetch,
                &mut staged,
            )
            .await
        }
        .await;
        // A fresh download is still staged under a temporary name: it was
        // updated now. Otherwise the cached file's time.
        let updated = if data.as_ref().is_ok_and(|data| *data != path) {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
        } else {
            std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        }
        .map(|d| d.as_secs());
        let committed = data.and_then(|data| {
            let stamp = Stamp::of(&data)?;
            staged.commit()?;
            Ok((path, stamp))
        });
        let stamp = committed.as_ref().ok().map(|(_, stamp)| *stamp);
        sources.push(ListSource {
            list: list.clone(),
            stamp,
        });
        resolved.push(Resolved {
            data: committed.map(|(path, _)| path),
            stamp,
            updated,
        });
    }
    if let Some(active) = &previous.adblock
        && previous.adblock_sources == sources
        && active
            .lists
            .iter()
            .zip(&resolved)
            .all(|(info, resolved)| info.error.is_none() || resolved.data.is_err())
    {
        let lists = active
            .lists
            .iter()
            .zip(&resolved)
            .map(|(info, resolved)| {
                if let Err(error) = &resolved.data {
                    tracing::warn!(list = %info.name, error = %format!("{error:#}"), "ad blocking list unavailable");
                }
                crate::adblock::ListInfo {
                    updated: resolved.updated,
                    error: resolved.data.as_ref().err().map(|error| format!("{error:#}")),
                    ..info.clone()
                }
            })
            .collect();
        tracing::debug!("ad blocking lists unchanged; reusing them");
        return (
            Some(Arc::new(active.with_lists(settings, lists))),
            sources,
            previous.adblock_cache.clone(),
        );
    }
    let mut block = clyntis_config::rule::DomainSetBuilder::default();
    let mut allow = clyntis_config::rule::DomainSetBuilder::default();
    let mut addresses = Vec::new();
    let mut lists = Vec::new();
    let mut next_cache = HashMap::new();
    for (list, resolved) in settings.lists.iter().zip(resolved) {
        let key = resolved
            .stamp
            .map(|stamp| (list.url.clone(), list.format.clone(), stamp));
        let path = config.directory.join(list.file_name());
        let cache_path = rule_cache::cache_path(&path);
        let config_hash = rule_cache::hash_strs(&[list.format.as_str()]);
        let loaded = match (
            resolved.data,
            key.as_ref()
                .and_then(|k| previous.adblock_cache.get(k).map(|c| (k, c))),
        ) {
            (Ok(data), Some((cache_key, _cached))) => {
                let res = load_or_parse_adblock_list(
                    &data,
                    &cache_path,
                    resolved.stamp,
                    config_hash,
                    &list.format,
                    fetch.limit,
                    &mut block,
                    &mut allow,
                    &mut addresses,
                );
                if let Ok(entries) = res {
                    let _ = entries;
                    next_cache.insert(cache_key.clone(), CachedAdblockList);
                }
                res
            }
            (Ok(data), None) => {
                let res = load_or_parse_adblock_list(
                    &data,
                    &cache_path,
                    resolved.stamp,
                    config_hash,
                    &list.format,
                    fetch.limit,
                    &mut block,
                    &mut allow,
                    &mut addresses,
                );
                if let (Ok(_), Some(cache_key)) = (&res, key) {
                    next_cache.insert(cache_key, CachedAdblockList);
                }
                res
            }
            (Err(error), _) => Err(error),
        };
        let info = match loaded {
            Ok(entries) => crate::adblock::ListInfo {
                name: list.name.clone(),
                entries,
                updated: resolved.updated,
                error: None,
            },
            Err(error) => {
                tracing::warn!(list = %list.name, error = %format!("{error:#}"), "ad blocking list unavailable");
                crate::adblock::ListInfo {
                    name: list.name.clone(),
                    entries: 0,
                    updated: resolved.updated,
                    error: Some(format!("{error:#}")),
                }
            }
        };
        lists.push(info);
    }
    let filter =
        crate::adblock::Filter::new(block.build(), allow.build(), addresses, settings, lists);
    tracing::info!(
        entries = filter.entries(),
        lists = filter.lists.len(),
        "ad blocking enabled"
    );
    (Some(Arc::new(filter)), sources, next_cache)
}
#[allow(clippy::too_many_arguments)]
fn load_or_parse_adblock_list(
    data: &Path,
    cache_path: &Path,
    stamp: Option<Stamp>,
    config_hash: u64,
    format: &str,
    limit: usize,
    block: &mut DomainSetBuilder,
    allow: &mut DomainSetBuilder,
    addresses: &mut Vec<ipnet::IpNet>,
) -> Result<usize> {
    if let Some(stamp) = stamp
        && let Some(entries) =
            rule_cache::load_adblock(cache_path, stamp, config_hash, block, allow, addresses)
    {
        return Ok(entries);
    }
    let prev_addrs = addresses.len();
    let buf = std::cell::RefCell::new(Vec::new());
    let mut block_rec = rule_cache::AdblockDomainRecorder {
        target: block,
        allow: false,
        buf: &buf,
    };
    let mut allow_rec = rule_cache::AdblockDomainRecorder {
        target: allow,
        allow: true,
        buf: &buf,
    };
    let entries = clyntis_config::adblock::parse_list_file_into(
        data,
        format,
        &mut block_rec,
        &mut allow_rec,
        addresses,
        limit,
    )?;
    if let Some(stamp) = stamp {
        let mut buf = buf.into_inner();
        rule_cache::append_ips(&mut buf, &addresses[prev_addrs..]);
        let _ = rule_cache::write_adblock(cache_path, stamp, config_hash, entries, &buf);
    }
    Ok(entries)
}

/// Loads the rewrite modules and downloads their scripts and response
/// files. Like ad blocking lists, a module that cannot be loaded is reported
/// and left out.
async fn rewrite(
    config: &Config,
    refresh: bool,
    fetch: &Fetch<'_>,
    previous: &Resources,
) -> (Option<Arc<crate::rewrite::Rewriter>>, Option<RewriteSource>) {
    use clyntis_config::rewrite::{Action, Mock, MockBody, parse_module};
    use futures_util::StreamExt;
    let settings = &config.rewrite;
    if !settings.enable {
        return (None, None);
    }
    let hosted = config.internal_host_packet_io;
    let mut parsed: Vec<(
        String,
        clyntis_config::rewrite::Module,
        Option<u64>,
        Option<crate::rewrite::RuleValidations>,
    )> = Vec::new();
    let mut failed = Vec::new();
    let mut module_sources = Vec::new();
    let mut update_errors = HashMap::new();
    struct PendingCommit {
        staged: Staged,
        path: PathBuf,
        source_index: usize,
        parsed_index: usize,
    }
    let mut pending_commits = Vec::new();
    let file_mtime = |path: &Path| {
        std::fs::metadata(path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
    };
    if !settings.custom.trim().is_empty() {
        parsed.push((
            clyntis_config::rewrite::CUSTOM.to_owned(),
            parse_module(&settings.custom),
            None,
            None,
        ));
    }
    for source in &settings.modules {
        let path = config.directory.join(source.file_name());
        // Rewrite caches are independent of the routing snapshot. Preserve
        // completed downloads even if another script stalls or loading stops;
        // updates over an existing cache defer commit until dependent files
        // are checked so missing scripts cannot wipe a working cached module.
        let mut staged = Staged::default();
        let data = asset(
            &path,
            &source.url,
            Some(settings.interval),
            refresh,
            &Fetch {
                limit: MODULE_LIMIT,
                ..*fetch
            },
            &mut staged,
        )
        .await;
        let mut staged = Some(staged);
        let loaded = data.and_then(|data| {
            match read_module(&data) {
                Ok(module) => {
                    let mut validations = None;
                    if data != path
                        && path.is_file()
                        && (!module.skipped.is_empty() || !module.rules.is_empty())
                    {
                        let mut candidate_validations =
                            crate::rewrite::RuleValidations::new(module.rules.len(), hosted);
                        if !crate::rewrite::has_compilable_rule(
                            &module,
                            &mut candidate_validations,
                        ) && let Ok(cached) = read_module(&path)
                        {
                            let mut cached_validations =
                                crate::rewrite::RuleValidations::new(cached.rules.len(), hosted);
                            if crate::rewrite::has_compilable_rule(
                                &cached,
                                &mut cached_validations,
                            ) {
                                let error = "updated module has no runnable rules";
                                tracing::warn!(module = %source.name, "{error}; keeping cached rules");
                                update_errors.insert(source.name.clone(), error.into());
                                return Ok((
                                    cached,
                                    Stamp::of(&path)?,
                                    None,
                                    Some(cached_validations),
                                ));
                            }
                        }
                        validations = Some(candidate_validations);
                    }
                    let stamp = Stamp::of(&data)?;
                    if data == path
                        && let (Some(before), Some(active)) =
                            (&previous.rewrite_sources, &previous.rewrite)
                        && before.modules.iter().any(|(old, cached)| {
                            old == source && cached.as_ref() == Some(&stamp)
                        })
                        && let Some(error) = active
                            .modules
                            .iter()
                            .find(|module| module.name == source.name)
                            .and_then(|module| module.update_error.as_ref())
                    {
                        update_errors.insert(source.name.clone(), error.clone());
                    }
                    let deferred = if data != path && path.is_file() {
                        staged.take()
                    } else {
                        if let Some(staged) = staged.take() {
                            staged.commit()?;
                        }
                        None
                    };
                    Ok((module, stamp, deferred, validations))
                }
                Err(error) if data != path && path.is_file() => {
                    tracing::warn!(module = %source.name, %error, "invalid module update; keeping cached rules");
                    update_errors.insert(source.name.clone(), format!("{error:#}"));
                    Ok((read_module(&path)?, Stamp::of(&path)?, None, None))
                }
                Err(error) => Err(error),
            }
        });
        let updated = file_mtime(&path);
        match loaded {
            Ok((module, stamp, deferred, validations)) => {
                let source_index = module_sources.len();
                let parsed_index = parsed.len();
                module_sources.push((source.clone(), Some(stamp)));
                parsed.push((source.name.clone(), module, updated, validations));
                if let Some(staged) = deferred {
                    pending_commits.push(PendingCommit {
                        staged,
                        path,
                        source_index,
                        parsed_index,
                    });
                }
            }
            Err(error) => {
                module_sources.push((source.clone(), None));
                tracing::warn!(module = %source.name, error = %format!("{error:#}"), "rewrite module unavailable");
                failed.push((source.name.clone(), updated, format!("{error:#}")));
            }
        }
    }
    // Scripts and response files, each once, several at a time.
    let script_limit = crate::script::source_limit(hosted);
    let mock_limit = rewrite_mock_limit(hosted);
    let urls = rewrite_file_urls(
        parsed.iter().map(|(_, module, _, _)| module),
        script_limit,
        mock_limit,
    );
    enum DownloadFile {
        Ready(Arc<crate::rewrite::RewriteFile>),
        Deferred(PathBuf, Staged),
    }
    let downloads: Vec<(String, Result<DownloadFile>)> =
        futures_util::stream::iter(urls.into_iter().map(|(url, limit)| async move {
            let path = config
                .directory
                .join(clyntis_config::rewrite::cache_file(&url));
            let mut staged = Staged::default();
            let result = asset(
                &path,
                &url,
                Some(settings.interval),
                refresh,
                &Fetch { limit, ..*fetch },
                &mut staged,
            )
            .await
            .and_then(|data| {
                if data != path && path.is_file() {
                    Ok(DownloadFile::Deferred(path, staged))
                } else {
                    staged.commit()?;
                    Ok(DownloadFile::Ready(crate::rewrite::RewriteFile::pin(
                        &path,
                    )?))
                }
            });
            (url, result)
        }))
        .buffered(2)
        .collect()
        .await;
    let mut files = std::collections::HashMap::new();
    let mut deferred_files = std::collections::HashMap::new();
    let mut missing = Vec::new();
    let mut file_sources = Vec::new();
    for (url, result) in downloads {
        match result {
            Ok(DownloadFile::Ready(path)) => {
                file_sources.push((url.clone(), true));
                files.insert(url, path);
            }
            Ok(DownloadFile::Deferred(path, staged)) => {
                deferred_files.insert(url, (path, staged));
            }
            Err(error) => {
                file_sources.push((url.clone(), false));
                tracing::warn!(url = %url, error = %format!("{error:#}"), "rewrite script unavailable");
                missing.push(url);
            }
        }
    }
    let mut publish_urls = std::collections::HashSet::new();
    let deferred_indices: std::collections::HashSet<usize> =
        pending_commits.iter().map(|p| p.parsed_index).collect();
    for (idx, (_, module, _, _)) in parsed.iter().enumerate() {
        if !deferred_indices.contains(&idx) {
            publish_urls.extend(
                rewrite_file_urls(std::iter::once(module), script_limit, mock_limit).into_keys(),
            );
        }
    }
    let mut kept_cached_urls = std::collections::BTreeMap::new();
    for pending in pending_commits {
        let name = parsed[pending.parsed_index].0.clone();
        let dropped_to_zero = {
            let entry = &mut parsed[pending.parsed_index];
            let candidate = &entry.1;
            if candidate.rules.is_empty() && candidate.skipped.is_empty() {
                false
            } else {
                let validations = entry.3.get_or_insert_with(|| {
                    crate::rewrite::RuleValidations::new(candidate.rules.len(), hosted)
                });
                !crate::rewrite::has_runnable_rule(candidate, validations, |u| {
                    files.contains_key(u) || deferred_files.contains_key(u)
                })
            }
        };
        let mut kept_cached = false;
        if dropped_to_zero && let Ok(cached) = read_module(&pending.path) {
            let mut cached_pins = HashMap::new();
            let mut cached_urls = Vec::new();
            for (url, limit) in
                rewrite_file_urls(std::iter::once(&cached), script_limit, mock_limit)
            {
                cached_urls.push((url.clone(), limit));
                if files.contains_key(&url) {
                    continue;
                }
                let file_path = config
                    .directory
                    .join(clyntis_config::rewrite::cache_file(&url));
                if std::fs::metadata(&file_path).is_ok_and(|m| m.len() <= limit as u64)
                    && let Ok(pinned) = crate::rewrite::RewriteFile::pin(&file_path)
                {
                    cached_pins.insert(url, pinned);
                }
            }
            let mut cached_validations =
                crate::rewrite::RuleValidations::new(cached.rules.len(), hosted);
            if crate::rewrite::has_runnable_rule(&cached, &mut cached_validations, |u| {
                files.contains_key(u) || cached_pins.contains_key(u)
            }) {
                let error = "updated module has no runnable rules";
                tracing::warn!(module = %name, "{error}; keeping cached rules");
                update_errors.insert(name.clone(), error.into());
                for (url, limit) in cached_urls {
                    kept_cached_urls
                        .entry(url)
                        .and_modify(|prev: &mut usize| *prev = (*prev).min(limit))
                        .or_insert(limit);
                }
                parsed[pending.parsed_index].1 = cached;
                parsed[pending.parsed_index].2 = file_mtime(&pending.path);
                parsed[pending.parsed_index].3 = Some(cached_validations);
                module_sources[pending.source_index].1 = Stamp::of(&pending.path).ok();
                kept_cached = true;
            }
        }
        if !kept_cached {
            let candidate_urls = rewrite_file_urls(
                std::iter::once(&parsed[pending.parsed_index].1),
                script_limit,
                mock_limit,
            );
            publish_urls.extend(candidate_urls.into_keys());
            if let Err(error) = pending.staged.commit() {
                tracing::warn!(module = %name, %error, "failed to commit updated module");
            } else {
                parsed[pending.parsed_index].2 = file_mtime(&pending.path);
                module_sources[pending.source_index].1 = Stamp::of(&pending.path).ok();
            }
        }
    }
    for (url, (path, staged)) in deferred_files {
        // Keep shared cached scripts untouched on disk when any rolled-back module still relies on them.
        if !publish_urls.contains(&url) || kept_cached_urls.contains_key(&url) {
            continue;
        }
        match staged
            .commit()
            .and_then(|()| crate::rewrite::RewriteFile::pin(&path).map_err(anyhow::Error::from))
        {
            Ok(pinned) => {
                file_sources.push((url.clone(), true));
                files.insert(url, pinned);
            }
            Err(error) => {
                file_sources.push((url.clone(), false));
                tracing::warn!(url = %url, error = %format!("{error:#}"), "rewrite script unavailable");
                missing.push(url);
            }
        }
    }
    for (url, limit) in kept_cached_urls {
        if files.contains_key(&url) {
            continue;
        }
        let file_path = config
            .directory
            .join(clyntis_config::rewrite::cache_file(&url));
        if std::fs::metadata(&file_path).is_ok_and(|m| m.len() <= limit as u64)
            && let Ok(pinned) = crate::rewrite::RewriteFile::pin(&file_path)
        {
            file_sources.push((url.clone(), true));
            files.insert(url, pinned);
        } else {
            file_sources.push((url.clone(), false));
            missing.push(url);
        }
    }
    file_sources.sort_by(|a, b| a.0.cmp(&b.0));
    let source = RewriteSource {
        custom: settings.custom.clone(),
        modules: module_sources,
        files: file_sources,
    };
    let loaded_with_validations: Vec<(
        crate::rewrite::Loaded,
        Option<crate::rewrite::RuleValidations>,
    )> = parsed
        .into_iter()
        .map(|(name, module, updated, validations)| {
            let mut own = std::collections::HashMap::new();
            let mut own_missing = Vec::new();
            for rule in &module.rules {
                let url = match &rule.action {
                    Action::Script(script) => &script.url,
                    Action::Mock(Mock {
                        body: MockBody::Remote(url),
                        ..
                    }) => url,
                    _ => continue,
                };
                match files.get(url) {
                    Some(path) => {
                        own.insert(url.clone(), path.clone());
                    }
                    None if missing.contains(url) && !own_missing.contains(url) => {
                        own_missing.push(url.clone())
                    }
                    None => {}
                }
            }
            (
                crate::rewrite::Loaded {
                    name,
                    module,
                    files: own,
                    missing: own_missing,
                    updated,
                },
                validations,
            )
        })
        .collect();
    let mut rewriter = if let (Some(active), Some(before)) =
        (&previous.rewrite, &previous.rewrite_sources)
        && *before == source
    {
        tracing::debug!("rewrite modules unchanged; reusing compiled rules");
        active.reloaded(
            loaded_with_validations
                .into_iter()
                .map(|(loaded, _)| loaded)
                .collect(),
            failed,
        )
    } else {
        crate::rewrite::Rewriter::new_hosted_with_validations(
            loaded_with_validations,
            failed,
            hosted,
        )
    };
    for module in &mut rewriter.modules {
        module.update_error = update_errors.remove(&module.name);
    }
    tracing::info!(
        rules = rewriter.rule_count(),
        modules = rewriter.modules.len(),
        hostnames = rewriter.hostnames.len(),
        "rewrite modules loaded"
    );
    (Some(Arc::new(rewriter)), Some(source))
}
fn read_module(path: &Path) -> Result<clyntis_config::rewrite::Module> {
    let data = read_with_limit(path, MODULE_LIMIT)?;
    let text = std::str::from_utf8(&data)?
        .trim_start_matches('\u{feff}')
        .trim();
    ensure!(
        !text.is_empty() && !text.starts_with('<'),
        "not a rewrite module"
    );
    let module = clyntis_config::rewrite::parse_module(text);
    ensure!(
        !module.rules.is_empty()
            || !module.reject.is_empty()
            || (module.skipped.is_empty()
                && (!module.hostnames.is_empty() || module.name.is_some())),
        "no recognizable module content"
    );
    Ok(module)
}

fn collect_rewrite_file_urls(
    module: &clyntis_config::rewrite::Module,
    script_limit: usize,
    mock_limit: usize,
    urls: &mut std::collections::BTreeMap<String, usize>,
) {
    use clyntis_config::rewrite::{Action, Mock, MockBody};
    for rule in &module.rules {
        let (url, limit) = match &rule.action {
            Action::Script(script) => (&script.url, script_limit),
            Action::Mock(Mock {
                body: MockBody::Remote(url),
                ..
            }) => (url, mock_limit),
            _ => continue,
        };
        let limit_for_url = urls.entry(url.clone()).or_insert(limit);
        *limit_for_url = (*limit_for_url).min(limit);
    }
}

fn rewrite_file_urls<'a>(
    modules: impl IntoIterator<Item = &'a clyntis_config::rewrite::Module>,
    script_limit: usize,
    mock_limit: usize,
) -> std::collections::BTreeMap<String, usize> {
    let mut urls = std::collections::BTreeMap::new();
    for module in modules {
        collect_rewrite_file_urls(module, script_limit, mock_limit, &mut urls);
    }
    urls
}
/// Past its update interval (`interval` seconds, 0 or `None` never expires).
fn expired(meta: Option<&std::fs::Metadata>, interval: Option<u64>) -> bool {
    interval.is_some_and(|v| v > 0)
        && meta
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .is_none_or(|age| age >= Duration::from_secs(interval.unwrap_or(0)))
}

/// Resources referenced by rules and DNS policy, before rule providers add theirs.
fn references(config: &Config) -> Result<Vec<(String, String)>> {
    let mut refs = vec![];
    for rule in &config.rules {
        Rule::parse(rule)?.matcher.references(&mut refs);
    }
    for key in config
        .dns
        .nameserver_policy
        .keys()
        .chain(config.dns.fake_ip_filter.iter())
        .chain(
            config
                .network_overrides
                .iter()
                .flat_map(|network| network.nameserver_policy.keys()),
        )
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
    Ok(refs)
}

/// State of the files a profile references, worst first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Freshness {
    Current,
    /// Present but past an update interval: usable until replaced.
    Expired,
    /// Some file is missing or unusable; fetch it after connecting.
    Missing,
}

fn contains_geo_token(line: &[u8], tag: &[u8]) -> bool {
    let start = line
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(line.len());
    let trimmed = &line[start..];
    let trimmed = trimmed.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(trimmed);
    if trimmed.is_empty() || trimmed[0] == b'#' {
        return false;
    }
    let mut i = 0;
    while i + tag.len() < trimmed.len() {
        if &trimmed[i..i + tag.len()] == tag {
            let boundary_before = i == 0
                || matches!(
                    trimmed[i - 1],
                    b' ' | b'\t' | b'\'' | b'"' | b'(' | b'[' | b','
                );
            if boundary_before {
                let mut after = i + tag.len();
                while after < trimmed.len() && matches!(trimmed[after], b' ' | b'\t') {
                    after += 1;
                }
                if after < trimmed.len() && trimmed[after] == b',' {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

fn scan_classical_geo_file(
    path: &Path,
    want_geoip: bool,
    want_geosite: bool,
    needs_geoip: &mut bool,
    needs_geosite: &mut bool,
) -> Result<()> {
    use std::io::{BufRead, BufReader, Read};
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::with_capacity(16 * 1024, file.take(LIMIT as u64));
    let mut line = Vec::with_capacity(256);
    loop {
        if (!want_geoip || *needs_geoip) && (!want_geosite || *needs_geosite) {
            break;
        }
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        if want_geoip && !*needs_geoip && contains_geo_token(&line, b"GEOIP") {
            *needs_geoip = true;
        }
        if want_geosite && !*needs_geosite && contains_geo_token(&line, b"GEOSITE") {
            *needs_geosite = true;
        }
    }
    Ok(())
}

/// The state of every referenced file. Cheap: no geo data is parsed, domain and
/// ipcidr providers are only stat'd, and classical providers are lightly
/// scanned for GEOIP/GEOSITE references only when those files could change the
/// result.
pub fn freshness(config: &Config) -> Result<Freshness> {
    let refs = references(config)?;
    let mut needs_geoip = refs.iter().any(|r| r.0 == "geoip");
    let mut needs_geosite = refs.iter().any(|r| r.0 == "geosite");
    let mut state = Freshness::Current;
    let probe =
        |path: &Path, interval: Option<u64>, limit: Option<usize>| match std::fs::metadata(path) {
            Err(_) => Freshness::Missing,
            Ok(meta) if limit.is_some_and(|limit| exceeds_limit(&meta, limit)) => {
                Freshness::Missing
            }
            Ok(meta) if expired(Some(&meta), interval) => Freshness::Expired,
            Ok(_) => Freshness::Current,
        };
    let check =
        |state: &mut Freshness, path: &Path, interval: Option<u64>, limit: Option<usize>| {
            let found = probe(path, interval, limit);
            *state = (*state).max(found);
            found
        };
    let interval = geo_interval(config);
    let geoip_path = config.directory.join(if config.geodata_mode {
        "geoip.dat"
    } else {
        "Country.mmdb"
    });
    let geosite_path = config.directory.join("geosite.dat");
    for p in config.rule_providers.values() {
        let file_path = if p.kind == "inline" {
            None
        } else {
            let path = asset_path(&config.directory, &p.path)?;
            if check(
                &mut state,
                &path,
                (p.kind == "http").then_some(p.interval),
                None,
            ) == Freshness::Missing
            {
                continue;
            }
            Some(path)
        };
        if p.behavior != "classical" {
            continue;
        }
        let want_geoip = !needs_geoip && probe(&geoip_path, interval, None) > state;
        let want_geosite = !needs_geosite && probe(&geosite_path, interval, None) > state;
        if !want_geoip && !want_geosite {
            continue;
        }
        match file_path {
            None => {
                for line in &p.payload {
                    let bytes = line.as_bytes();
                    if want_geoip && !needs_geoip && contains_geo_token(bytes, b"GEOIP") {
                        needs_geoip = true;
                    }
                    if want_geosite && !needs_geosite && contains_geo_token(bytes, b"GEOSITE") {
                        needs_geosite = true;
                    }
                    if (!want_geoip || needs_geoip) && (!want_geosite || needs_geosite) {
                        break;
                    }
                }
            }
            Some(path) => {
                let _ = scan_classical_geo_file(
                    &path,
                    want_geoip,
                    want_geosite,
                    &mut needs_geoip,
                    &mut needs_geosite,
                );
            }
        }
    }
    if config.adblock.enable {
        for list in &config.adblock.lists {
            check(
                &mut state,
                &config.directory.join(list.file_name()),
                Some(config.adblock.interval),
                None,
            );
        }
    }
    if config.rewrite.enable {
        let mut present_modules = Vec::new();
        for module in &config.rewrite.modules {
            let path = config.directory.join(module.file_name());
            if check(&mut state, &path, Some(config.rewrite.interval), None) != Freshness::Missing {
                present_modules.push(path);
            }
        }
        if state < Freshness::Missing {
            let hosted = config.internal_host_packet_io;
            let script_limit = crate::script::source_limit(hosted);
            let mock_limit = rewrite_mock_limit(hosted);
            let mut urls = std::collections::BTreeMap::new();
            if !config.rewrite.custom.trim().is_empty() {
                let module = clyntis_config::rewrite::parse_module(&config.rewrite.custom);
                collect_rewrite_file_urls(&module, script_limit, mock_limit, &mut urls);
            }
            for path in present_modules {
                if let Ok(module) = read_module(&path) {
                    collect_rewrite_file_urls(&module, script_limit, mock_limit, &mut urls);
                }
            }
            for (url, limit) in urls {
                if check(
                    &mut state,
                    &config
                        .directory
                        .join(clyntis_config::rewrite::cache_file(&url)),
                    Some(config.rewrite.interval),
                    Some(limit),
                ) == Freshness::Missing
                {
                    break;
                }
            }
        }
    }
    if needs_geoip {
        check(&mut state, &geoip_path, interval, None);
    }
    if needs_geosite {
        check(&mut state, &geosite_path, interval, None);
    }
    Ok(state)
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
fn exceeds_limit(meta: &std::fs::Metadata, limit: usize) -> bool {
    meta.len() > limit as u64
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct HttpCacheMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_modified: Option<String>,
}

enum DownloadOutcome {
    NotModified,
    Downloaded { bytes: usize, meta: HttpCacheMeta },
}

fn http_meta_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.meta", path.display()))
}

fn read_http_meta(path: &Path) -> Option<HttpCacheMeta> {
    let bytes = std::fs::read(http_meta_path(path)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_http_meta(path: &Path, meta: &HttpCacheMeta) {
    let meta_path = http_meta_path(path);
    if meta.etag.is_none() && meta.last_modified.is_none() {
        let _ = std::fs::remove_file(meta_path);
        return;
    }
    if let Ok(bytes) = serde_json::to_vec(meta) {
        let _ = atomic_write(&meta_path, &bytes);
    }
}

async fn asset(
    path: &Path,
    url: &str,
    interval: Option<u64>,
    refresh: bool,
    fetch: &Fetch<'_>,
    pending: &mut Staged,
) -> Result<PathBuf> {
    let meta = std::fs::metadata(path).ok();
    let oversized = meta
        .as_ref()
        .is_some_and(|meta| exceeds_limit(meta, fetch.limit));
    let remote = interval.is_some() && !url.is_empty();
    let refresh_cache = refresh && (expired(meta.as_ref(), interval) || (oversized && remote));
    if meta.is_some() && !refresh_cache {
        ensure!(!oversized, "resource exceeds size limit");
        return Ok(path.into());
    }
    ensure!(remote, "local routing resource is missing");
    ensure!(
        fetch.download,
        "routing resource is not cached; download deferred until connected"
    );
    let condition = if meta.is_some() && !oversized {
        read_http_meta(path)
    } else {
        None
    };
    let (temp, mut file) = pending.create(path)?;
    // Resource hosts (jsDelivr, GitHub) are often unreachable directly from
    // the networks that need the proxy in the first place: use it first.
    let mut result = download_conditional(
        url,
        fetch.resolver,
        fetch.hooks,
        fetch.proxy,
        TIMEOUTS,
        fetch.limit,
        condition.as_ref(),
        &mut file,
    )
    .await;
    if let (Err(error), Some((_, name))) = (&result, fetch.proxy) {
        tracing::warn!(
            error = %format!("{error:#}"),
            proxy = name,
            "routing resource download through the proxy failed; retrying directly"
        );
        use std::io::Seek;
        file.set_len(0)?;
        file.rewind()?;
        result = download_conditional(
            url,
            fetch.resolver,
            fetch.hooks,
            None,
            TIMEOUTS,
            fetch.limit,
            condition.as_ref(),
            &mut file,
        )
        .await;
    }
    let result = result
        .and_then(|outcome| {
            if matches!(outcome, DownloadOutcome::Downloaded { .. }) {
                file.sync_all()?;
            }
            Ok(outcome)
        })
        .with_context(|| {
            format!(
                "routing resource download failed ({})",
                path.file_name().unwrap_or_default().to_string_lossy()
            )
        });
    match result {
        Ok(DownloadOutcome::NotModified) => {
            pending.discard(&temp);
            if let Ok(existing) = std::fs::OpenOptions::new().write(true).open(path) {
                let _ = existing.set_modified(std::time::SystemTime::now());
            }
            tracing::debug!(
                file = %path.file_name().unwrap_or_default().to_string_lossy(),
                "routing resource not modified (304)"
            );
            Ok(path.into())
        }
        Ok(DownloadOutcome::Downloaded {
            bytes,
            meta: http_meta,
        }) => {
            write_http_meta(path, &http_meta);
            tracing::info!(
                file = %path.file_name().unwrap_or_default().to_string_lossy(),
                bytes,
                had_cached_file = meta.is_some(),
                "routing resource downloaded"
            );
            Ok(temp)
        }
        // An expired file is still usable: stay on it rather than fail.
        Err(error) if meta.is_some() && !oversized => {
            pending.discard(&temp);
            tracing::warn!(error = %format!("{error:#}"), "keeping the current routing resource");
            Ok(path.into())
        }
        Err(error) => {
            pending.discard(&temp);
            Err(error)
        }
    }
}

/// How routing resources are fetched: through `proxy` first, then direct.
#[derive(Clone, Copy)]
struct Fetch<'a> {
    resolver: &'a crate::dns::Resolver,
    hooks: &'a clyntis_platform::Hooks,
    proxy: Option<(&'a crate::Core, &'a str)>,
    download: bool,
    limit: usize,
}

fn read_limited(path: &Path) -> Result<Vec<u8>> {
    read_with_limit(path, LIMIT)
}
fn read_with_limit(path: &Path, limit: usize) -> Result<Vec<u8>> {
    ensure!(
        std::fs::metadata(path)?.len() <= limit as u64,
        "resource exceeds size limit"
    );
    Ok(std::fs::read(path)?)
}

/// Downloads stream straight to disk under a temporary name (so a 16 MiB
/// geoip.dat is never held in memory). Routing files commit after validation;
/// independent rewrite caches commit per download. Dropping without `commit`
/// removes the temporary files.
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
        for (temp, path) in &self.files {
            std::fs::rename(temp, path)
                .with_context(|| format!("cannot commit routing resource {}", path.display()))?;
            tracing::debug!(file = %path.display(), "routing resource cached");
        }
        self.files.clear();
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

    /// Calls `each` with `(field_number, wire_type, raw_bytes)` for every field.
    pub fn each_raw_field<'a>(
        buf: &'a [u8],
        mut each: impl FnMut(u64, u8, &'a [u8]) -> Result<()>,
    ) -> Result<()> {
        let mut pos = 0;
        while pos < buf.len() {
            let (n, wire, value) = field(buf, &mut pos)?;
            each(n, wire, value)?;
        }
        Ok(())
    }

    /// Decodes a varint field payload returned by [`each_raw_field`].
    pub fn decode_varint(buf: &[u8]) -> Result<u64> {
        let mut pos = 0;
        varint(buf, &mut pos)
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

    /// Streams every top-level entry whose country code satisfies `wanted`,
    /// reusing a single scratch buffer so only one entry is in memory at once.
    pub fn stream_entries(
        path: &std::path::Path,
        wanted: impl Fn(&str) -> bool,
        mut on_entry: impl FnMut(&str, &[u8]) -> Result<()>,
    ) -> Result<()> {
        use std::io::Read;
        let mut reader = std::io::BufReader::with_capacity(64 * 1024, std::fs::File::open(path)?);
        let mut entry = Vec::new();
        let mut code_buf = String::new();
        while let Some(key) = read_varint(&mut reader)? {
            ensure!(key & 7 == 2, "unexpected protobuf wire type in list");
            let len = usize::try_from(read_varint(&mut reader)?.unwrap_or(0))?;
            ensure!(len <= 128 * 1024 * 1024, "protobuf entry too large");
            // A country code is a few bytes; 256 covers it with room to spare.
            let prefix = len.min(256);
            entry.clear();
            entry.resize(prefix, 0);
            reader.read_exact(&mut entry)?;
            let mut pos = 0;
            code_buf.clear();
            let mut has_code = false;
            loop {
                if pos >= entry.len() {
                    break;
                }
                match field(&entry, &mut pos) {
                    Ok((1, 2, value)) => {
                        code_buf.push_str(std::str::from_utf8(value)?);
                        has_code = true;
                        break;
                    }
                    Ok(_) => continue,
                    Err(_) => break, // field runs past the prefix
                }
            }
            let keep = key >> 3 == 1 && (!has_code || wanted(&code_buf));
            if keep {
                entry.resize(len, 0);
                reader.read_exact(&mut entry[prefix..])?;
                // Fall back to a full parse when the code was not in the prefix.
                if !has_code {
                    each_field(&entry, 1, |value| {
                        code_buf.clear();
                        code_buf.push_str(std::str::from_utf8(value)?);
                        has_code = true;
                        Ok(())
                    })?;
                    if !has_code || !wanted(&code_buf) {
                        continue;
                    }
                }
                on_entry(&code_buf, &entry)?;
            } else {
                reader.seek_relative(i64::try_from(len - prefix)?)?;
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn read_entries(
        path: &std::path::Path,
        wanted: impl Fn(&str) -> bool,
    ) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        stream_entries(path, wanted, |_, entry| {
            out.push(entry.to_vec());
            Ok(())
        })?;
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
/// Connects directly, or through the named proxy or group when `via` is set.
#[cfg_attr(not(test), allow(dead_code))]
async fn download_with(
    url: &str,
    resolver: &crate::dns::Resolver,
    hooks: &clyntis_platform::Hooks,
    via: Option<(&crate::Core, &str)>,
    timeouts: Timeouts,
    limit: usize,
    sink: &mut (dyn std::io::Write + Send),
) -> Result<usize> {
    match download_conditional(url, resolver, hooks, via, timeouts, limit, None, sink).await? {
        DownloadOutcome::Downloaded { bytes, .. } => Ok(bytes),
        DownloadOutcome::NotModified => bail!("unexpected 304 without conditional headers"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn download_conditional(
    url: &str,
    resolver: &crate::dns::Resolver,
    hooks: &clyntis_platform::Hooks,
    via: Option<(&crate::Core, &str)>,
    timeouts: Timeouts,
    limit: usize,
    condition: Option<&HttpCacheMeta>,
    sink: &mut (dyn std::io::Write + Send),
) -> Result<DownloadOutcome> {
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
                let target = clyntis_protocol::Target::from_uri(
                    &uri,
                    if scheme == "https" { 443 } else { 80 },
                )?;
                let stream: clyntis_protocol::BoxStream = if let Some((core, name)) = via {
                    let (tunnel, _) = core.dial(&target, Some(name)).await?;
                    if scheme == "https" {
                        clyntis_protocol::tls::SecureConnector::new(resolver.clock())
                            .connect(
                                tunnel,
                                &clyntis_protocol::tls::TlsConnectConfig {
                                    server_name: target.host.clone(),
                                    alpn: vec!["http/1.1".into()],
                                    verify_cert: true,
                                    fingerprint: clyntis_protocol::tls::TlsFingerprint::Native,
                                    reality: None,
                                },
                            )
                            .await?
                    } else {
                        tunnel
                    }
                } else {
                    let addresses = resolver.lookup(&target.host, target.port).await?;
                    // CDNs return several addresses and one can accept TCP yet stall
                    // the TLS handshake on a lossy route; bound each address and move on.
                    let (mut stream, mut failure) = (None, None);
                    for addr in addresses {
                        let attempt = tokio::time::timeout(PER_ADDRESS_TIMEOUT, async {
                            let socket = tokio::time::timeout(
                                Duration::from_secs(5),
                                clyntis_platform::tcp_connect(addr, &**hooks),
                            )
                            .await
                            .map_err(|_| anyhow::anyhow!("TCP connect to {addr} timed out"))??;
                            let stream: clyntis_protocol::BoxStream = if scheme == "https" {
                                clyntis_protocol::tls::SecureConnector::new(resolver.clock())
                                    .connect(
                                        Box::new(socket),
                                        &clyntis_protocol::tls::TlsConnectConfig {
                                            server_name: target.host.clone(),
                                            alpn: vec!["http/1.1".into()],
                                            verify_cert: true,
                                            fingerprint:
                                                clyntis_protocol::tls::TlsFingerprint::Native,
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
                    match stream {
                        Some(stream) => stream,
                        None => {
                            let error = failure.unwrap_or_else(|| anyhow::anyhow!("no address"));
                            return Err(error.context("cannot connect to resource server"));
                        }
                    }
                };
                let (mut sender, connection) =
                    hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                        .await?;
                let driver = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(connection));
                let mut builder =
                    http::Request::get(uri.path_and_query().map_or("/", |v| v.as_str()))
                        .header(
                            http::header::HOST,
                            uri.authority()
                                .context("missing resource authority")?
                                .as_str(),
                        )
                        .header(http::header::USER_AGENT, "clyntis");
                if let Some(cond) = condition {
                    if let Some(etag) = &cond.etag {
                        builder = builder.header(http::header::IF_NONE_MATCH, etag.as_str());
                    }
                    if let Some(last_modified) = &cond.last_modified {
                        builder =
                            builder.header(http::header::IF_MODIFIED_SINCE, last_modified.as_str());
                    }
                }
                let request = builder.body(Empty::<bytes::Bytes>::new())?;
                anyhow::Ok((sender.send_request(request).await?, driver))
            })
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "resource server did not respond within {}s",
                    timeouts.response.as_secs()
                )
            })??;
            if response.status() == http::StatusCode::NOT_MODIFIED {
                drop(driver);
                return Ok(DownloadOutcome::NotModified);
            }
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
            let meta = HttpCacheMeta {
                etag: response
                    .headers()
                    .get(http::header::ETAG)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned),
                last_modified: response
                    .headers()
                    .get(http::header::LAST_MODIFIED)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned),
            };
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
                        received + chunk.len() <= limit,
                        "resource exceeds size limit"
                    );
                    sink.write_all(chunk)?;
                    received += chunk.len();
                }
            }
            drop(driver);
            return Ok(DownloadOutcome::Downloaded {
                bytes: received,
                meta,
            });
        }
        bail!("too many resource redirects")
    })
    .await
    .map_err(|_| anyhow::anyhow!("resource download exceeded {}s", timeouts.total.as_secs()))?
}
fn decode_geoip_cidr(bytes: &[u8]) -> Result<ipnet::IpNet> {
    let mut ip: Option<IpAddr> = None;
    let mut prefix: u32 = 0;
    wire::each_raw_field(bytes, |number, wire_type, value| {
        match number {
            1 => {
                ensure!(wire_type == 2, "invalid geoip.dat");
                ip = Some(match value.len() {
                    4 => IpAddr::from(<[u8; 4]>::try_from(value)?),
                    16 => IpAddr::from(<[u8; 16]>::try_from(value)?),
                    _ => bail!("invalid GeoIP address"),
                });
            }
            2 => {
                ensure!(wire_type == 0, "invalid geoip.dat");
                prefix = u32::try_from(wire::decode_varint(value)?)?;
            }
            _ => {}
        }
        Ok(())
    })?;
    let Some(ip) = ip else {
        bail!("invalid GeoIP address");
    };
    Ok(ipnet::IpNet::new(ip, u8::try_from(prefix)?)?)
}

#[cfg_attr(not(test), allow(dead_code))]
fn load_provider_matcher(p: &RuleProvider, path: &Path) -> Result<Matcher> {
    load_provider_matcher_cached(p, path, None)
}

fn load_provider_matcher_cached(
    p: &RuleProvider,
    path: &Path,
    cache: Option<(&Path, Stamp)>,
) -> Result<Matcher> {
    let config_hash = rule_cache::hash_strs(&[p.behavior.as_str(), p.format.as_str()]);
    if let Some((final_path, stamp)) = cache {
        let cache_path = rule_cache::cache_path(final_path);
        if let Some(matcher) = rule_cache::load_provider(&cache_path, stamp, config_hash) {
            return Ok(matcher);
        }
    }
    let mut builder = if cache.is_some() {
        ProviderMatcherBuilder::with_cache(&p.behavior)
    } else {
        ProviderMatcherBuilder::new(&p.behavior)
    };
    match p.format.as_str() {
        "text" => {
            use std::io::{BufRead, BufReader};
            ensure!(
                std::fs::metadata(path)?.len() <= LIMIT as u64,
                "resource exceeds size limit"
            );
            let mut reader = BufReader::with_capacity(64 * 1024, std::fs::File::open(path)?);
            let mut line = String::new();
            let mut read_bytes = 0usize;
            loop {
                line.clear();
                let n = reader.read_line(&mut line)?;
                if n == 0 {
                    break;
                }
                read_bytes = read_bytes.saturating_add(n);
                ensure!(read_bytes <= LIMIT, "resource exceeds size limit");
                let value = line.trim();
                if value.is_empty() || value.starts_with('#') {
                    continue;
                }
                builder.push(value)?;
            }
        }
        "yaml" => {
            ensure!(
                std::fs::metadata(path)?.len() <= LIMIT as u64,
                "resource exceeds size limit"
            );
            let reader = std::io::BufReader::with_capacity(64 * 1024, std::fs::File::open(path)?);
            serde::de::DeserializeSeed::deserialize(
                YamlPayloadSeed(&mut builder),
                serde_yaml::Deserializer::from_reader(reader),
            )?;
        }
        _ => bail!("unsupported rule provider format"),
    }
    let (matcher, cache_buf) = builder.build_with_cache();
    if let (Some((final_path, stamp)), Some(buf)) = (cache, cache_buf) {
        let _ = rule_cache::write_provider(
            &rule_cache::cache_path(final_path),
            stamp,
            config_hash,
            &buf,
        );
    }
    Ok(matcher)
}

struct YamlPayloadSeed<'a, 'b>(&'a mut ProviderMatcherBuilder<'b>);
impl<'de> serde::de::DeserializeSeed<'de> for YamlPayloadSeed<'_, '_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}
impl<'de> serde::de::Visitor<'de> for YamlPayloadSeed<'_, '_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a rule-provider mapping with a payload sequence")
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = false;
        while let Some(key) = map.next_key::<String>()? {
            if key == "payload" {
                if seen {
                    return Err(serde::de::Error::duplicate_field("payload"));
                }
                seen = true;
                map.next_value_seed(YamlPayloadSeqSeed(self.0))?;
            } else {
                return Err(serde::de::Error::unknown_field(&key, &["payload"]));
            }
        }
        if !seen {
            return Err(serde::de::Error::missing_field("payload"));
        }
        Ok(())
    }
}

struct YamlPayloadSeqSeed<'a, 'b>(&'a mut ProviderMatcherBuilder<'b>);
impl<'de> serde::de::DeserializeSeed<'de> for YamlPayloadSeqSeed<'_, '_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(self)
    }
}
impl<'de> serde::de::Visitor<'de> for YamlPayloadSeqSeed<'_, '_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a sequence of rule strings")
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq
            .next_element_seed(YamlPayloadItemSeed(self.0))?
            .is_some()
        {}
        Ok(())
    }
}

struct YamlPayloadItemSeed<'a, 'b>(&'a mut ProviderMatcherBuilder<'b>);
impl<'de> serde::de::DeserializeSeed<'de> for YamlPayloadItemSeed<'_, '_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_str(self)
    }
}
impl<'de> serde::de::Visitor<'de> for YamlPayloadItemSeed<'_, '_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a rule string")
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<(), E> {
        self.0.push(v).map_err(serde::de::Error::custom)
    }
}

struct ProviderMatcherBuilder<'a> {
    behavior: &'a str,
    count: usize,
    domains: DomainSetBuilder,
    nets: Vec<ipnet::IpNet>,
    nodes: Vec<Matcher>,
    cache_buf: Option<Vec<u8>>,
}

impl<'a> ProviderMatcherBuilder<'a> {
    fn new(behavior: &'a str) -> Self {
        Self {
            behavior,
            count: 0,
            domains: DomainSetBuilder::default(),
            nets: Vec::new(),
            nodes: Vec::new(),
            cache_buf: None,
        }
    }

    fn with_cache(behavior: &'a str) -> Self {
        Self {
            cache_buf: Some(Vec::new()),
            ..Self::new(behavior)
        }
    }

    fn push(&mut self, value: &str) -> Result<()> {
        self.count += 1;
        ensure!(self.count <= 2_000_000, "too many provider rules");
        match self.behavior {
            "domain" => {
                self.domains.pattern(value)?;
                if let Some(buf) = &mut self.cache_buf {
                    rule_cache::push_str(buf, rule_cache::TAG_BLOCK_PATTERN, value);
                }
            }
            "ipcidr" => {
                let net: ipnet::IpNet = value.parse()?;
                self.nets.push(net);
                if let Some(buf) = &mut self.cache_buf {
                    rule_cache::push_ip(buf, net);
                }
            }
            "classical" => {
                let m = Matcher::parse_condition(value)?;
                let mut refs = vec![];
                m.references(&mut refs);
                ensure!(
                    !refs.iter().any(|r| r.0 == "rule-set"),
                    "nested RULE-SET is not permitted in classical providers"
                );
                match m {
                    Matcher::Net(net) => {
                        self.nets.push(net);
                        if let Some(buf) = &mut self.cache_buf {
                            rule_cache::push_ip(buf, net);
                        }
                    }
                    m => {
                        if let Some(buf) = &mut self.cache_buf {
                            rule_cache::record_matcher(buf, &m, value);
                        }
                        self.nodes.extend(self.domains.absorb(m));
                    }
                }
            }
            _ => bail!("unsupported provider behavior"),
        }
        Ok(())
    }

    fn build(self) -> Matcher {
        self.build_with_cache().0
    }

    fn build_with_cache(mut self) -> (Matcher, Option<Vec<u8>>) {
        let domains = self.domains.build();
        if !domains.is_empty() {
            self.nodes.insert(0, Matcher::Domains(Arc::new(domains)));
        }
        if !self.nets.is_empty() {
            self.nodes
                .insert(0, Matcher::Nets(Arc::new(IpSet::new(self.nets, false))));
        }
        (Matcher::Or(self.nodes.into()), self.cache_buf)
    }
}

/// Versioned binary rule cache (SRS-like) on disk for compiled `ProviderMatcher`
/// and `adblock` domain+IP sets so cold starts deserialize without re-parsing
/// text, YAML, or AdGuard lists.
mod rule_cache {
    use super::{Stamp, atomic_write};
    use anyhow::{Result, bail, ensure};
    use clyntis_config::{
        adblock::DomainTarget,
        rule::{DomainSetBuilder, IpSet, Matcher},
    };
    use std::{
        io::{BufReader, Read},
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        path::{Path, PathBuf},
        sync::Arc,
    };

    const MAGIC: &[u8; 4] = b"CLRS";
    const VERSION: u16 = 1;
    const KIND_PROVIDER: u8 = 1;
    const KIND_ADBLOCK: u8 = 2;

    pub const TAG_BLOCK_EXACT: u8 = 1;
    pub const TAG_BLOCK_SUFFIX: u8 = 2;
    pub const TAG_BLOCK_SUBDOMAIN: u8 = 3;
    pub const TAG_BLOCK_GLOB: u8 = 4;
    pub const TAG_BLOCK_KEYWORD: u8 = 5;
    pub const TAG_BLOCK_PATTERN: u8 = 6;
    pub const TAG_BLOCK_REGEX: u8 = 7;
    pub const TAG_ALLOW_EXACT: u8 = 8;
    pub const TAG_ALLOW_SUFFIX: u8 = 9;
    pub const TAG_ALLOW_SUBDOMAIN: u8 = 10;
    pub const TAG_ALLOW_KEYWORD: u8 = 11;
    pub const TAG_ALLOW_PATTERN: u8 = 12;
    pub const TAG_IPV4: u8 = 13;
    pub const TAG_IPV6: u8 = 14;
    pub const TAG_OTHER_RULE: u8 = 15;

    pub fn cache_path(path: &Path) -> PathBuf {
        PathBuf::from(format!("{}.rcache", path.display()))
    }

    pub fn hash_strs(parts: &[&str]) -> u64 {
        let mut h = 0xcbf29ce484222325u64;
        for part in parts {
            for &b in part.as_bytes() {
                h ^= u64::from(b);
                h = h.wrapping_mul(0x100000001b3);
            }
            h ^= 0xff;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }

    pub fn push_str(buf: &mut Vec<u8>, tag: u8, s: &str) {
        let Ok(len) = u32::try_from(s.len()) else {
            return;
        };
        buf.push(tag);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(s.as_bytes());
    }

    pub fn push_ip(buf: &mut Vec<u8>, net: ipnet::IpNet) {
        match net {
            ipnet::IpNet::V4(v4) => {
                buf.push(TAG_IPV4);
                buf.extend_from_slice(&v4.addr().octets());
                buf.push(v4.prefix_len());
            }
            ipnet::IpNet::V6(v6) => {
                buf.push(TAG_IPV6);
                buf.extend_from_slice(&v6.addr().octets());
                buf.push(v6.prefix_len());
            }
        }
    }

    pub fn append_ips(buf: &mut Vec<u8>, nets: &[ipnet::IpNet]) {
        for &net in nets {
            push_ip(buf, net);
        }
    }

    pub fn record_matcher(buf: &mut Vec<u8>, m: &Matcher, raw: &str) {
        match m {
            Matcher::Domain(d) => push_str(buf, TAG_BLOCK_EXACT, d),
            Matcher::Suffix(d) => push_str(buf, TAG_BLOCK_SUFFIX, d),
            Matcher::Subdomain(d) => push_str(buf, TAG_BLOCK_SUBDOMAIN, d),
            Matcher::Glob(g) => push_str(buf, TAG_BLOCK_GLOB, g),
            Matcher::Keyword(k) => push_str(buf, TAG_BLOCK_KEYWORD, k),
            Matcher::Regex(r) => push_str(buf, TAG_BLOCK_REGEX, r.as_str()),
            _ => push_str(buf, TAG_OTHER_RULE, raw),
        }
    }

    pub struct AdblockDomainRecorder<'a> {
        pub target: &'a mut DomainSetBuilder,
        pub allow: bool,
        pub buf: &'a std::cell::RefCell<Vec<u8>>,
    }

    impl DomainTarget for AdblockDomainRecorder<'_> {
        fn exact(&mut self, domain: &str) {
            self.target.exact(domain);
            push_str(
                &mut self.buf.borrow_mut(),
                if self.allow {
                    TAG_ALLOW_EXACT
                } else {
                    TAG_BLOCK_EXACT
                },
                domain,
            );
        }
        fn suffix(&mut self, domain: &str) {
            self.target.suffix(domain);
            push_str(
                &mut self.buf.borrow_mut(),
                if self.allow {
                    TAG_ALLOW_SUFFIX
                } else {
                    TAG_BLOCK_SUFFIX
                },
                domain,
            );
        }
        fn subdomain(&mut self, domain: &str) {
            self.target.subdomain(domain);
            push_str(
                &mut self.buf.borrow_mut(),
                if self.allow {
                    TAG_ALLOW_SUBDOMAIN
                } else {
                    TAG_BLOCK_SUBDOMAIN
                },
                domain,
            );
        }
        fn keyword(&mut self, keyword: &str) {
            self.target.keyword(keyword);
            push_str(
                &mut self.buf.borrow_mut(),
                if self.allow {
                    TAG_ALLOW_KEYWORD
                } else {
                    TAG_BLOCK_KEYWORD
                },
                keyword,
            );
        }
        fn pattern(&mut self, pattern: &str) -> Result<()> {
            self.target.pattern(pattern)?;
            push_str(
                &mut self.buf.borrow_mut(),
                if self.allow {
                    TAG_ALLOW_PATTERN
                } else {
                    TAG_BLOCK_PATTERN
                },
                pattern,
            );
            Ok(())
        }
    }

    fn write_header(
        out: &mut Vec<u8>,
        kind: u8,
        stamp: Stamp,
        config_hash: u64,
        entries: Option<u64>,
    ) {
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&stamp.len.to_le_bytes());
        out.extend_from_slice(&stamp.digest);
        out.extend_from_slice(&config_hash.to_le_bytes());
        out.push(kind);
        if let Some(entries) = entries {
            out.extend_from_slice(&entries.to_le_bytes());
        }
    }

    pub fn write_provider(path: &Path, stamp: Stamp, config_hash: u64, body: &[u8]) -> Result<()> {
        let mut out = Vec::with_capacity(55 + body.len());
        write_header(&mut out, KIND_PROVIDER, stamp, config_hash, None);
        out.extend_from_slice(body);
        atomic_write(path, &out)
    }

    pub fn write_adblock(
        path: &Path,
        stamp: Stamp,
        config_hash: u64,
        entries: usize,
        body: &[u8],
    ) -> Result<()> {
        let mut out = Vec::with_capacity(63 + body.len());
        write_header(
            &mut out,
            KIND_ADBLOCK,
            stamp,
            config_hash,
            Some(u64::try_from(entries)?),
        );
        out.extend_from_slice(body);
        atomic_write(path, &out)
    }

    fn read_header(
        reader: &mut impl Read,
        expected_kind: u8,
        stamp: Stamp,
        config_hash: u64,
    ) -> Result<Option<usize>> {
        let mut hdr = [0u8; 55];
        reader.read_exact(&mut hdr)?;
        ensure!(&hdr[0..4] == MAGIC, "bad rule cache magic");
        let version = u16::from_le_bytes([hdr[4], hdr[5]]);
        ensure!(version == VERSION, "unsupported rule cache version");
        let len = u64::from_le_bytes(hdr[6..14].try_into().unwrap());
        ensure!(len == stamp.len, "rule cache stamp length mismatch");
        ensure!(hdr[14..46] == stamp.digest, "rule cache stamp mismatch");
        let hash = u64::from_le_bytes(hdr[46..54].try_into().unwrap());
        ensure!(hash == config_hash, "rule cache config mismatch");
        ensure!(hdr[54] == expected_kind, "rule cache kind mismatch");
        if expected_kind == KIND_ADBLOCK {
            let mut entries_buf = [0u8; 8];
            reader.read_exact(&mut entries_buf)?;
            Ok(Some(usize::try_from(u64::from_le_bytes(entries_buf))?))
        } else {
            Ok(None)
        }
    }

    fn read_str<'a>(reader: &mut impl Read, scratch: &'a mut Vec<u8>) -> Result<&'a str> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let len = usize::try_from(u32::from_le_bytes(len_buf))?;
        ensure!(len <= 65536, "rule cache string too long");
        scratch.resize(len, 0);
        reader.read_exact(scratch)?;
        Ok(std::str::from_utf8(scratch)?)
    }

    fn read_tag(reader: &mut impl Read) -> Result<Option<u8>> {
        let mut tag = [0u8];
        match reader.read(&mut tag)? {
            0 => Ok(None),
            1 => Ok(Some(tag[0])),
            _ => unreachable!(),
        }
    }

    pub fn load_provider(path: &Path, stamp: Stamp, config_hash: u64) -> Option<Matcher> {
        load_provider_inner(path, stamp, config_hash).ok()
    }

    fn load_provider_inner(path: &Path, stamp: Stamp, config_hash: u64) -> Result<Matcher> {
        let mut reader = BufReader::with_capacity(64 * 1024, std::fs::File::open(path)?);
        read_header(&mut reader, KIND_PROVIDER, stamp, config_hash)?;
        let mut domains = DomainSetBuilder::default();
        let mut nets = Vec::new();
        let mut nodes = Vec::new();
        let mut scratch = Vec::with_capacity(256);
        while let Some(tag) = read_tag(&mut reader)? {
            match tag {
                TAG_BLOCK_EXACT => domains.exact(read_str(&mut reader, &mut scratch)?),
                TAG_BLOCK_SUFFIX => domains.suffix(read_str(&mut reader, &mut scratch)?),
                TAG_BLOCK_SUBDOMAIN => domains.subdomain(read_str(&mut reader, &mut scratch)?),
                TAG_BLOCK_GLOB => {
                    let s = read_str(&mut reader, &mut scratch)?;
                    let _ = domains.absorb(Matcher::Glob(s.into()));
                }
                TAG_BLOCK_KEYWORD => domains.keyword(read_str(&mut reader, &mut scratch)?),
                TAG_BLOCK_PATTERN => domains.pattern(read_str(&mut reader, &mut scratch)?)?,
                TAG_BLOCK_REGEX => domains.regex(read_str(&mut reader, &mut scratch)?)?,
                TAG_IPV4 => {
                    let mut buf = [0u8; 5];
                    reader.read_exact(&mut buf)?;
                    let addr = Ipv4Addr::from(<[u8; 4]>::try_from(&buf[..4]).unwrap());
                    nets.push(ipnet::IpNet::new(IpAddr::V4(addr), buf[4])?);
                }
                TAG_IPV6 => {
                    let mut buf = [0u8; 17];
                    reader.read_exact(&mut buf)?;
                    let addr = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[..16]).unwrap());
                    nets.push(ipnet::IpNet::new(IpAddr::V6(addr), buf[16])?);
                }
                TAG_OTHER_RULE => {
                    let raw = read_str(&mut reader, &mut scratch)?;
                    nodes.push(Matcher::parse_condition(raw)?);
                }
                _ => bail!("unknown rule cache tag {tag}"),
            }
        }
        let domains = domains.build();
        if !domains.is_empty() {
            nodes.insert(0, Matcher::Domains(Arc::new(domains)));
        }
        if !nets.is_empty() {
            nodes.insert(0, Matcher::Nets(Arc::new(IpSet::new(nets, false))));
        }
        Ok(Matcher::Or(nodes.into()))
    }

    pub fn load_adblock(
        path: &Path,
        stamp: Stamp,
        config_hash: u64,
        block: &mut DomainSetBuilder,
        allow: &mut DomainSetBuilder,
        addresses: &mut Vec<ipnet::IpNet>,
    ) -> Option<usize> {
        load_adblock_inner(path, stamp, config_hash, block, allow, addresses).ok()
    }

    fn load_adblock_inner(
        path: &Path,
        stamp: Stamp,
        config_hash: u64,
        block: &mut DomainSetBuilder,
        allow: &mut DomainSetBuilder,
        addresses: &mut Vec<ipnet::IpNet>,
    ) -> Result<usize> {
        let mut reader = BufReader::with_capacity(64 * 1024, std::fs::File::open(path)?);
        let entries =
            read_header(&mut reader, KIND_ADBLOCK, stamp, config_hash)?.unwrap_or_default();
        let mut scratch = Vec::with_capacity(256);
        while let Some(tag) = read_tag(&mut reader)? {
            match tag {
                TAG_BLOCK_EXACT => block.exact(read_str(&mut reader, &mut scratch)?),
                TAG_BLOCK_SUFFIX => block.suffix(read_str(&mut reader, &mut scratch)?),
                TAG_BLOCK_SUBDOMAIN => block.subdomain(read_str(&mut reader, &mut scratch)?),
                TAG_BLOCK_KEYWORD => block.keyword(read_str(&mut reader, &mut scratch)?),
                TAG_BLOCK_PATTERN => block.pattern(read_str(&mut reader, &mut scratch)?)?,
                TAG_ALLOW_EXACT => allow.exact(read_str(&mut reader, &mut scratch)?),
                TAG_ALLOW_SUFFIX => allow.suffix(read_str(&mut reader, &mut scratch)?),
                TAG_ALLOW_SUBDOMAIN => allow.subdomain(read_str(&mut reader, &mut scratch)?),
                TAG_ALLOW_KEYWORD => allow.keyword(read_str(&mut reader, &mut scratch)?),
                TAG_ALLOW_PATTERN => allow.pattern(read_str(&mut reader, &mut scratch)?)?,
                TAG_IPV4 => {
                    let mut buf = [0u8; 5];
                    reader.read_exact(&mut buf)?;
                    let addr = Ipv4Addr::from(<[u8; 4]>::try_from(&buf[..4]).unwrap());
                    addresses.push(ipnet::IpNet::new(IpAddr::V4(addr), buf[4])?);
                }
                TAG_IPV6 => {
                    let mut buf = [0u8; 17];
                    reader.read_exact(&mut buf)?;
                    let addr = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[..16]).unwrap());
                    addresses.push(ipnet::IpNet::new(IpAddr::V6(addr), buf[16])?);
                }
                _ => bail!("unknown adblock cache tag {tag}"),
            }
        }
        Ok(entries)
    }
}

/// Domain conditions (all of a `domain` provider, and DOMAIN/DOMAIN-SUFFIX/
/// DOMAIN-KEYWORD/DOMAIN-REGEX lines of a `classical` one) go into one compact
/// [`DomainSet`] and CIDRs into one [`IpSet`], instead of one matcher per line
/// scanned in order. A provider matches when any entry does, so grouping keeps
/// the result.
fn provider_matcher(p: &RuleProvider, payload: &[String]) -> Result<Matcher> {
    ensure!(payload.len() <= 2_000_000, "too many provider rules");
    let mut builder = ProviderMatcherBuilder::new(&p.behavior);
    for value in payload {
        builder.push(value)?;
    }
    Ok(builder.build())
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
#[cfg(test)] // Only used to encode test fixtures; entries and CIDRs are decoded lazily.
#[derive(Clone, PartialEq, Message)]
struct GeoIp {
    #[prost(string, tag = "1")]
    country_code: String,
    #[prost(message, repeated, tag = "2")]
    cidr: Vec<Cidr>,
    #[prost(bool, tag = "3")]
    inverse_match: bool,
}
#[cfg(test)] // Only used to encode test fixtures; CIDRs are decoded lazily.
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

    async fn load_rewrites(
        config: &Config,
        previous: &Resources,
        refresh: bool,
        mode: LoadMode,
    ) -> Resources {
        let hooks: clyntis_platform::Hooks = Arc::new(clyntis_platform::DefaultHooks);
        let dns = crate::dns::Resolver::new(Default::default(), hooks.clone());
        Resources::load_with(config, &dns, &hooks, refresh, previous, None, mode)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn invalid_module_update_preserves_cache_and_new_url_does_not_reuse_it() {
        use axum::{Router, routing::get};
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/module", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/module", get(|| async { "<html>maintenance</html>" })),
            )
            .await
            .unwrap()
        });
        let mut config = Config::parse(
            format!("rewrite:\n  enable: true\n  modules: [{{name: ads, url: '{url}'}}]\n")
                .as_bytes(),
        )
        .unwrap();
        config.directory = dir.clone();
        let path = dir.join(config.rewrite.modules[0].file_name());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let old = "[URL Rewrite]\n/ad - reject";
        std::fs::write(&path, old).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH)
            .unwrap();
        let refreshed =
            load_rewrites(&config, &Resources::default(), true, LoadMode::Available).await;
        let r = refreshed.rewrite.as_ref().unwrap();
        assert_eq!(r.rule_count(), 1);
        assert!(r.modules[0].update_error.is_some());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), old);
        config.rewrite.custom = "[URL Rewrite]\n/custom - reject".into();
        let reloaded = load_rewrites(&config, &refreshed, false, LoadMode::Available).await;
        let reloaded_module = &reloaded.rewrite.as_ref().unwrap().modules[1];
        assert_eq!(reloaded_module.name, "ads");
        assert_eq!(reloaded_module.update_error, r.modules[0].update_error);
        config.rewrite.custom.clear();
        let restarted =
            load_rewrites(&config, &Resources::default(), false, LoadMode::Cached).await;
        assert_eq!(restarted.rewrite.unwrap().rule_count(), 1);
        config.rewrite.modules[0].url.push_str("?new");
        let switched = load_rewrites(&config, &reloaded, false, LoadMode::Cached).await;
        let switched = switched.rewrite.unwrap();
        assert_eq!(switched.rule_count(), 0);
        assert!(switched.modules[0].update_error.is_none());
        server.abort();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn incompatible_module_update_with_hostnames_preserves_cache_and_allows_explicit_empty() {
        use axum::{Router, routing::get};
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route(
                        "/broken",
                        get(|| async {
                            "[Rewrite]\nrequest if ${url} ~= /ad/ then unknown_action()\n[MITM]\nhostname = a.test\n"
                        }),
                    )
                    .route(
                        "/empty",
                        get(|| async { "#!name=ads\n[MITM]\nhostname = a.test\n" }),
                    ),
            )
            .await
            .unwrap()
        });
        let mut config = Config::parse(
            format!("rewrite:\n  enable: true\n  modules: [{{name: ads, url: '{base}/broken'}}]\n")
                .as_bytes(),
        )
        .unwrap();
        config.directory = dir.clone();
        let path = dir.join(config.rewrite.modules[0].file_name());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let old = "[URL Rewrite]\n/ad - reject\n[MITM]\nhostname = a.test\n";
        std::fs::write(&path, old).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH)
            .unwrap();
        let refreshed =
            load_rewrites(&config, &Resources::default(), true, LoadMode::Available).await;
        let r = refreshed.rewrite.as_ref().unwrap();
        assert_eq!(r.rule_count(), 1);
        assert!(r.modules[0].update_error.is_some());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), old);

        // An explicitly emptied valid module (no skipped lines) is allowed to update.
        config.rewrite.modules[0].url = format!("{base}/empty");
        let empty_path = dir.join(config.rewrite.modules[0].file_name());
        std::fs::write(&empty_path, old).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&empty_path)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH)
            .unwrap();
        let emptied =
            load_rewrites(&config, &Resources::default(), true, LoadMode::Available).await;
        let r = emptied.rewrite.as_ref().unwrap();
        assert_eq!(r.rule_count(), 0);
        assert!(r.modules[0].update_error.is_none());
        server.abort();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn module_update_with_missing_script_dependency_preserves_cache() {
        use axum::{Router, http::StatusCode, routing::get};
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let v1_script_url = format!("{base}/v1.js");
        let v2_script_url = format!("{base}/missing.js");
        let v2_module = format!(
            "[Script]\nresponse if ${{url}} ~= /^https:\\/\\/a\\.test\\/ad/ then script(\"{v2_script_url}\")\n[MITM]\nhostname = a.test\n"
        );
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/module", get(move || async move { v2_module }))
                    .route("/missing.js", get(|| async { StatusCode::NOT_FOUND })),
            )
            .await
            .unwrap()
        });
        let mut config = Config::parse(
            format!("rewrite:\n  enable: true\n  modules: [{{name: ads, url: '{base}/module'}}]\n")
                .as_bytes(),
        )
        .unwrap();
        config.directory = dir.clone();
        let mod_path = dir.join(config.rewrite.modules[0].file_name());
        std::fs::create_dir_all(mod_path.parent().unwrap()).unwrap();
        let v1_module = format!(
            "[Script]\nresponse if ${{url}} ~= /^https:\\/\\/a\\.test\\/ad/ then script(\"{v1_script_url}\")\n[MITM]\nhostname = a.test\n"
        );
        std::fs::write(&mod_path, &v1_module).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&mod_path)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH)
            .unwrap();
        let v1_script_path = dir.join(clyntis_config::rewrite::cache_file(&v1_script_url));
        std::fs::create_dir_all(v1_script_path.parent().unwrap()).unwrap();
        std::fs::write(&v1_script_path, "$done({});").unwrap();

        let refreshed =
            load_rewrites(&config, &Resources::default(), true, LoadMode::Available).await;
        let r = refreshed.rewrite.as_ref().unwrap();
        assert_eq!(r.rule_count(), 1);
        assert!(r.modules[0].update_error.is_some());
        assert_eq!(std::fs::read_to_string(&mod_path).unwrap(), v1_module);

        let restarted =
            load_rewrites(&config, &Resources::default(), false, LoadMode::Cached).await;
        assert_eq!(restarted.rewrite.unwrap().rule_count(), 1);
        server.abort();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn shared_script_rollback_keeps_cached_script_version() {
        use axum::{Router, http::StatusCode, routing::get};
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let shared_url = format!("{base}/shared.js");
        let missing_url = format!("{base}/missing.js");
        let mod_a_v2 = format!(
            "#!name=a-v2\n[Script]\nresponse if ${{url}} ~= /^https:\\/\\/a\\.test\\/ad/ then script(\"{missing_url}\")\n[MITM]\nhostname = a.test\n"
        );
        let mod_b_v2 = format!(
            "#!name=b-v2\n[Script]\nresponse if ${{url}} ~= /^https:\\/\\/b\\.test\\/ad/ then script(\"{shared_url}\")\n[MITM]\nhostname = b.test\n"
        );
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/mod_a", get(move || async move { mod_a_v2 }))
                    .route("/mod_b", get(move || async move { mod_b_v2 }))
                    .route("/shared.js", get(|| async { "v2" }))
                    .route("/missing.js", get(|| async { StatusCode::NOT_FOUND })),
            )
            .await
            .unwrap()
        });
        let mut config = Config::parse(
            format!(
                "rewrite:\n  enable: true\n  modules:\n    - {{name: a, url: '{base}/mod_a'}}\n    - {{name: b, url: '{base}/mod_b'}}\n"
            )
            .as_bytes(),
        )
        .unwrap();
        config.directory = dir.clone();

        let mod_a_path = dir.join(config.rewrite.modules[0].file_name());
        let mod_b_path = dir.join(config.rewrite.modules[1].file_name());
        std::fs::create_dir_all(mod_a_path.parent().unwrap()).unwrap();
        let mod_a_v1 = format!(
            "#!name=a-v1\n[Script]\nresponse if ${{url}} ~= /^https:\\/\\/a\\.test\\/ad/ then script(\"{shared_url}\")\n[MITM]\nhostname = a.test\n"
        );
        let mod_b_v1 = format!(
            "#!name=b-v1\n[Script]\nresponse if ${{url}} ~= /^https:\\/\\/b\\.test\\/ad/ then script(\"{shared_url}\")\n[MITM]\nhostname = b.test\n"
        );
        for (p, body) in [(&mod_a_path, &mod_a_v1), (&mod_b_path, &mod_b_v1)] {
            std::fs::write(p, body).unwrap();
            std::fs::File::options()
                .write(true)
                .open(p)
                .unwrap()
                .set_modified(std::time::UNIX_EPOCH)
                .unwrap();
        }
        let shared_path = dir.join(clyntis_config::rewrite::cache_file(&shared_url));
        std::fs::create_dir_all(shared_path.parent().unwrap()).unwrap();
        std::fs::write(&shared_path, "v1").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&shared_path)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH)
            .unwrap();

        let refreshed =
            load_rewrites(&config, &Resources::default(), true, LoadMode::Available).await;
        let r = refreshed.rewrite.as_ref().unwrap();
        assert!(r.modules[0].update_error.is_some());
        assert!(r.modules[1].update_error.is_none());
        assert_eq!(std::fs::read_to_string(&shared_path).unwrap(), "v1");
        assert_eq!(
            std::fs::read_to_string(r.file(&shared_url).unwrap()).unwrap(),
            "v1"
        );

        let restarted =
            load_rewrites(&config, &Resources::default(), false, LoadMode::Cached).await;
        let rr = restarted.rewrite.as_ref().unwrap();
        assert_eq!(rr.modules[0].title.as_deref(), Some("a-v1"));
        assert_eq!(
            std::fs::read_to_string(rr.file(&shared_url).unwrap()).unwrap(),
            "v1"
        );
        server.abort();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn canceled_refresh_keeps_active_script_and_response_versions() {
        use axum::{Router, http::StatusCode, routing::get};
        let dir = std::env::temp_dir().join(format!("meta-rewrite-pin-{}", uuid::Uuid::new_v4()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let fast_url = format!("{base}/fast");
        let slow_url = format!("{base}/slow");
        let first = format!(
            "#!name=v1\n[Script]\nfast = type=http-response,pattern=^https://test/fast,script-path={fast_url},argument=v1\n[Map Local]\n^https://test/body data-type=text data={fast_url}\n"
        );
        let second = format!(
            "#!name=v2\n[Script]\nfast = type=http-response,pattern=^https://test/fast,script-path={fast_url},argument=v2\nslow = type=http-response,pattern=^https://test/slow,script-path={slow_url}\n"
        );
        let fast_served = Arc::new(tokio::sync::Notify::new());
        let fast_served_route = fast_served.clone();
        let finish_slow = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finish_slow_route = finish_slow.clone();
        let app = Router::new()
            .route("/module", get(move || async move { second }))
            .route(
                "/fast",
                get(move || async move {
                    fast_served_route.notify_one();
                    "v2"
                }),
            )
            .route(
                "/slow",
                get(move || async move {
                    if finish_slow_route.load(std::sync::atomic::Ordering::Relaxed) {
                        (StatusCode::NOT_FOUND, "")
                    } else {
                        std::future::pending::<(StatusCode, &'static str)>().await
                    }
                }),
            );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut config = Config::parse(
            format!("rewrite:\n  enable: true\n  interval: 3600\n  modules: [{{name: test, url: '{base}/module'}}]\n").as_bytes(),
        ).unwrap();
        config.directory = dir.clone();
        let module_path = dir.join(config.rewrite.modules[0].file_name());
        let cache_path = dir.join(clyntis_config::rewrite::cache_file(&fast_url));
        std::fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
        std::fs::write(&module_path, first).unwrap();
        std::fs::write(&cache_path, "v1").unwrap();
        let previous = load_rewrites(&config, &Resources::default(), false, LoadMode::Cached).await;
        let active = previous.rewrite.as_ref().unwrap().clone();
        let pinned = active.file(&fast_url).unwrap().clone();
        for path in [&module_path, &cache_path] {
            std::fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_times(
                    std::fs::FileTimes::new()
                        .set_modified(std::time::SystemTime::now() - Duration::from_secs(7200)),
                )
                .unwrap();
        }
        let updated_config = config.clone();
        let refresh = tokio::spawn(async move {
            load_rewrites(&updated_config, &previous, true, LoadMode::Available).await
        });
        tokio::time::timeout(Duration::from_secs(3), fast_served.notified())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!refresh.is_finished());
        let during_refresh = std::fs::read_to_string(&pinned).unwrap();
        refresh.abort();
        let _ = refresh.await;
        assert_eq!(during_refresh, "v1");
        assert_eq!(active.modules[0].title.as_deref(), Some("v1"));
        assert_eq!(std::fs::read_to_string(&pinned).unwrap(), "v1");
        let rule = active.matching(clyntis_config::rewrite::Phase::Request, "https://test/body")[0];
        assert_eq!(
            std::fs::read(
                crate::rewrite::answer(&active, rule, "https://test/body")
                    .unwrap()
                    .file
                    .unwrap()
            )
            .unwrap(),
            b"v1"
        );
        // Canceling mid-refresh must leave the complete v1 version on disk
        // (never v1 module + v2 script).
        let restarted =
            load_rewrites(&config, &Resources::default(), false, LoadMode::Cached).await;
        let rolled_back = restarted.rewrite.as_ref().unwrap();
        assert_eq!(rolled_back.modules[0].title.as_deref(), Some("v1"));
        assert_eq!(
            std::fs::read_to_string(rolled_back.file(&fast_url).unwrap()).unwrap(),
            "v1"
        );
        assert!(rolled_back.modules[0].missing.is_empty());
        drop(restarted);

        // Once all downloads conclude (even with /slow 404), v2 commits atomically
        // while `active` still reads v1 through its pinned hard link.
        finish_slow.store(true, std::sync::atomic::Ordering::Relaxed);
        let published =
            load_rewrites(&config, &Resources::default(), true, LoadMode::Available).await;
        let latest = published.rewrite.as_ref().unwrap();
        assert_eq!(latest.modules[0].title.as_deref(), Some("v2"));
        assert_eq!(
            std::fs::read_to_string(latest.file(&fast_url).unwrap()).unwrap(),
            "v2"
        );
        assert_eq!(latest.modules[0].missing, [slow_url]);
        assert_eq!(std::fs::read_to_string(&pinned).unwrap(), "v1");
        server.abort();
        let _ = server.await;
        drop(published);
        drop(active);
        assert!(
            !pinned.exists(),
            "the final snapshot owner releases its hard link"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn unchanged_rules_rebind_refreshed_files() {
        use axum::{Router, routing::get};
        let dir =
            std::env::temp_dir().join(format!("meta-rewrite-rebind-{}", uuid::Uuid::new_v4()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/script", listener.local_addr().unwrap());
        let app = Router::new().route("/script", get(|| async { "v2" }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let config = Config {
            directory: dir.clone(),
            rewrite: clyntis_config::rewrite::Rewrite {
                enable: true,
                interval: 3600,
                custom: format!(
                    "[Script]\nfast = type=http-response,pattern=^https://test/fast,script-path={url}\n"
                ),
                ..Default::default()
            },
            ..Default::default()
        };
        let cache = dir.join(clyntis_config::rewrite::cache_file(&url));
        std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
        std::fs::write(&cache, "v1").unwrap();
        let first = load_rewrites(&config, &Resources::default(), false, LoadMode::Cached).await;
        std::fs::File::options()
            .write(true)
            .open(&cache)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::SystemTime::now() - Duration::from_secs(7200)),
            )
            .unwrap();
        let second = load_rewrites(&config, &first, true, LoadMode::Available).await;
        let before = first.rewrite.as_ref().unwrap();
        let after = second.rewrite.as_ref().unwrap();
        assert!(before.shares_rules(after));
        assert_eq!(
            std::fs::read_to_string(before.file(&url).unwrap()).unwrap(),
            "v1"
        );
        assert_eq!(
            std::fs::read_to_string(after.file(&url).unwrap()).unwrap(),
            "v2"
        );
        server.abort();
        let _ = server.await;
        drop((first, second));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn rewrite_downloads_survive_cancellation_and_restart_with_a_stalled_script() {
        use axum::{Router, routing::get};
        let dir = std::env::temp_dir().join(format!("meta-rewrite-cache-{}", uuid::Uuid::new_v4()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let fast_url = format!("{base}/fast");
        let slow_url = format!("{base}/slow");
        let module = format!(
            "[URL Rewrite]\n^https://example\\.test/ad - reject\n[Script]\nfast = type=http-response,pattern=^https://example\\.test/fast,script-path={fast_url}\nslow = type=http-response,pattern=^https://example\\.test/slow,script-path={slow_url}\n"
        );
        let app = Router::new()
            .route("/module", get(move || async move { module }))
            .route("/fast", get(|| async { "$done({body: 'cached'});" }))
            .route("/slow", get(std::future::pending::<&'static str>));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut config = Config::parse(
            format!(
                "rewrite:\n  enable: true\n  modules: [{{name: test, url: '{base}/module'}}]\n"
            )
            .as_bytes(),
        )
        .unwrap();
        config.directory = dir.clone();
        let core =
            crate::Core::new(config.clone(), Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        let load = tokio::spawn(async move { core.prepare_resources(false).await });
        let fast_path = dir.join(clyntis_config::rewrite::cache_file(&fast_url));
        let completed = tokio::time::timeout(Duration::from_secs(3), async {
            while !fast_path.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        // Cancel before the slow script completes, just as stopping the VPN
        // cancels its background refresh. Always stop the tasks on failure too.
        assert!(!load.is_finished());
        load.abort();
        let _ = load.await;
        server.abort();
        let _ = server.await;
        completed.expect("completed rewrite downloads must commit before their stalled sibling");
        assert!(dir.join(config.rewrite.modules[0].file_name()).exists());
        assert_eq!(
            std::fs::read_to_string(&fast_path).unwrap(),
            "$done({body: 'cached'});"
        );
        let files: Vec<_> = std::fs::read_dir(dir.join("rewrite/files"))
            .unwrap()
            .collect();
        assert_eq!(
            files.len(),
            1,
            "cancellation must clean up the unfinished download"
        );

        // A fresh process can use the downloaded rules without the server.
        let hooks: clyntis_platform::Hooks = Arc::new(clyntis_platform::DefaultHooks);
        let dns = crate::dns::Resolver::new(Default::default(), hooks.clone());
        let restarted = Resources::load_with(
            &config,
            &dns,
            &hooks,
            false,
            &Resources::default(),
            None,
            LoadMode::Cached,
        )
        .await
        .unwrap();
        let module = &restarted.rewrite.as_ref().unwrap().modules[0];
        assert!(module.error.is_none());
        assert_eq!(module.rules, 2);
        assert_eq!(module.scripts, 1);
        assert_eq!(module.missing, vec![slow_url]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn rewrite_retry_replaces_deferred_error_and_recovers_from_cache() {
        let dir = std::env::temp_dir().join(format!("meta-retry-{}", uuid::Uuid::new_v4()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/module", listener.local_addr().unwrap());
        drop(listener);
        let mut config = Config::parse(
            format!("rewrite:\n  enable: true\n  modules: [{{name: test, url: '{url}'}}]\n")
                .as_bytes(),
        )
        .unwrap();
        config.directory = dir.clone();
        config.rewrite.custom = "[URL Rewrite]\n^https://example\\.test/ad - reject\n".into();
        let hooks: clyntis_platform::Hooks = Arc::new(clyntis_platform::DefaultHooks);
        let dns = crate::dns::Resolver::new(Default::default(), hooks.clone());
        let cached = Resources::load_with(
            &config,
            &dns,
            &hooks,
            false,
            &Resources::default(),
            None,
            LoadMode::Cached,
        )
        .await
        .unwrap();
        let error = |resources: &Resources| {
            resources
                .rewrite
                .as_ref()
                .unwrap()
                .modules
                .iter()
                .find(|module| module.name == "test")
                .unwrap()
                .error
                .clone()
                .unwrap()
        };
        assert!(error(&cached).contains("download deferred"));
        let retried = Resources::load_with(
            &config,
            &dns,
            &hooks,
            false,
            &cached,
            None,
            LoadMode::Available,
        )
        .await
        .unwrap();
        assert!(error(&retried).contains("routing resource download failed"));
        assert!(!error(&retried).contains("download deferred"));
        assert!(retried.incomplete());
        let before = cached.rewrite.as_ref().unwrap();
        let after = retried.rewrite.as_ref().unwrap();
        assert!(before.shares_rules(after));
        assert_eq!(after.rule_count(), 1);
        assert_eq!(
            after.matching(
                clyntis_config::rewrite::Phase::Request,
                "https://example.test/ad"
            ),
            [0]
        );
        assert!(error(&cached).contains("download deferred"));
        let repeated = load_rewrites(&config, &retried, false, LoadMode::Available).await;
        assert!(after.shares_rules(repeated.rewrite.as_ref().unwrap()));
        std::fs::write(
            dir.join(config.rewrite.modules[0].file_name()),
            "[URL Rewrite]\n^https://example\\.test/ad - reject\n",
        )
        .unwrap();
        let recovered = Resources::load_with(
            &config,
            &dns,
            &hooks,
            false,
            &retried,
            None,
            LoadMode::Available,
        )
        .await
        .unwrap();
        assert!(!recovered.incomplete());
        assert!(!after.shares_rules(recovered.rewrite.as_ref().unwrap()));
        assert!(
            recovered.rewrite.as_ref().unwrap().modules[1]
                .error
                .is_none()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn cold_start_downloads_via_proxy_and_applies_resources_without_reconnecting() {
        use clyntis_protocol::Target;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = std::env::temp_dir().join(format!("meta-cold-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let site = GeoSiteList {
            entry: vec![GeoSite {
                country_code: "test".into(),
                domain: vec![Domain {
                    kind: 2,
                    value: "site.test".into(),
                    attribute: vec![],
                }],
            }],
        }
        .encode_to_vec();
        let ip = GeoIpList {
            entry: vec![GeoIp {
                country_code: "ZZ".into(),
                cidr: vec![Cidr {
                    ip: vec![192, 0, 2, 0],
                    prefix: 24,
                }],
                inverse_match: false,
            }],
        }
        .encode_to_vec();
        let files: HashMap<&str, Vec<u8>> = HashMap::from([
            ("/site", site),
            ("/ip", ip),
            ("/provider", b"provider.test\n".to_vec()),
            // A malformed provider must not roll back the successful resources.
            ("/bad", b"not-a-yaml-payload".to_vec()),
            ("/ads", b"0.0.0.0 ads.test\n".to_vec()),
            ("/module", br"[Map Local]
^https://rewrite\.test/ad data-type=text data=http://resources.invalid/body
[Script]
ads = type=http-response,pattern=^https://rewrite\.test/script,requires-body=true,script-path=http://resources.invalid/script
[MITM]
hostname = rewrite.test
".to_vec()),
            ("/script", b"$done({body: 'blocked'});".to_vec()),
            ("/body", b"blocked".to_vec()),
        ]);
        let calls = Arc::new(AtomicUsize::new(0));
        let requests = calls.clone();
        // A VLESS outbound serving a hostname which cannot resolve directly.
        let server = tokio::spawn(async move {
            let mut handlers = tokio::task::JoinSet::new();
            while let Ok((mut socket, _)) = listener.accept().await {
                let files = files.clone();
                let requests = requests.clone();
                handlers.spawn(async move {
                    let mut header = [0; 19];
                    socket.read_exact(&mut header).await.unwrap();
                    assert_eq!(&header[17..], &[0, 1]);
                    assert_eq!(socket.read_u16().await.unwrap(), 80);
                    assert_eq!(socket.read_u8().await.unwrap(), 2);
                    let n = socket.read_u8().await.unwrap();
                    let mut host = vec![0; n as usize];
                    socket.read_exact(&mut host).await.unwrap();
                    assert_eq!(host, b"resources.invalid");
                    let mut request = vec![];
                    while !request.ends_with(b"\r\n\r\n") {
                        request.push(socket.read_u8().await.unwrap());
                    }
                    requests.fetch_add(1, Ordering::SeqCst);
                    let request = String::from_utf8(request).unwrap();
                    let path = request.split_whitespace().nth(1).unwrap();
                    let body = &files[path];
                    socket.write_all(&[0, 0]).await.unwrap();
                    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
                    socket.write_all(body).await.unwrap();
                });
            }
        });
        let yaml = format!(
            r#"
proxies:
  - {{name: node, type: vless, server: 127.0.0.1, port: {port}, uuid: 11111111-1111-4111-8111-111111111111}}
proxy-groups:
  - {{name: Proxy, type: select, proxies: [DIRECT, node]}}
profile: {{store-selected: true}}
geodata-mode: true
geox-url: {{geoip: 'http://resources.invalid/ip', geosite: 'http://resources.invalid/site'}}
rule-providers:
  remote: {{type: http, url: 'http://resources.invalid/provider', path: provider.txt, behavior: domain, format: text}}
  broken: {{type: http, url: 'http://resources.invalid/bad', path: bad.yaml, behavior: domain, format: yaml}}
adblock:
  enable: true
  lists: [{{name: ads, url: 'http://resources.invalid/ads', format: hosts}}]
rewrite:
  enable: true
  modules: [{{name: ads, url: 'http://resources.invalid/module'}}]
dns:
  enhanced-mode: fake-ip
  nameserver-policy:
    'geosite:test': [1.1.1.1]
    'rule-set:remote': [1.1.1.1]
  fake-ip-filter: ['geosite:test', 'rule-set:remote']
rules:
  - GEOSITE,test,REJECT
  - GEOIP,ZZ,REJECT,no-resolve
  - RULE-SET,remote,REJECT
  - DOMAIN,local.test,REJECT
  - MATCH,Proxy
"#
        );
        let mut config = Config::parse(yaml.as_bytes()).unwrap();
        config.directory = dir.clone();
        let dns = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream = dns.local_addr().unwrap().to_string();
        for servers in config.dns.nameserver_policy.values_mut() {
            *servers = clyntis_config::Strings::Many(vec![upstream.clone()]);
        }
        let dns_server = tokio::spawn(async move {
            use hickory_proto::{
                op::Message,
                rr::{RData, Record, rdata::A},
            };
            for _ in 0..2 {
                let mut bytes = [0; 4096];
                let (len, peer) = dns.recv_from(&mut bytes).await.unwrap();
                let mut message = Message::from_vec(&bytes[..len]).unwrap();
                let name = message.queries()[0].name().clone();
                message.set_message_type(hickory_proto::op::MessageType::Response);
                message.add_answer(Record::from_rdata(
                    name,
                    30,
                    RData::A(A("203.0.113.22".parse().unwrap())),
                ));
                dns.send_to(&message.to_vec().unwrap(), peer).await.unwrap();
            }
        });
        // Resource downloads must use the restored selection, not DIRECT.
        std::fs::write(
            dir.join(".meta-profile.json"),
            br#"{"selection":{"Proxy":"node"}}"#,
        )
        .unwrap();
        let core = crate::Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        let running = tokio::time::timeout(Duration::from_secs(1), core.start())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0, "startup must not download");
        assert!(core.resources_incomplete());
        let query = |host: &str| {
            let mut message = hickory_proto::op::Message::new();
            message.set_id(7).add_query(hickory_proto::op::Query::query(
                hickory_proto::rr::Name::from_ascii(host).unwrap(),
                hickory_proto::rr::RecordType::A,
            ));
            message.to_vec().unwrap()
        };
        let answer_ip = |bytes: Vec<u8>| {
            let message = hickory_proto::op::Message::from_vec(&bytes).unwrap();
            message.answers()[0].data().ip_addr().unwrap()
        };
        let fake = answer_ip(core.resolver.answer(&query("site.test")).await.unwrap());
        assert!(core.resolver.original(fake).is_some());
        let route = |host: &str| Target::new(host, 443).unwrap();
        assert_eq!(
            core.route(&route("local.test"), "tcp").await.unwrap(),
            "REJECT"
        );
        for host in ["site.test", "provider.test", "192.0.2.7", "ads.test"] {
            assert_eq!(core.route(&route(host), "tcp").await.unwrap(), "node");
        }
        // Allow the actual background worker to run; no manual prepare/restart.
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if core
                    .rewriter()
                    .is_some_and(|r| r.modules.iter().any(|m| m.rules == 2))
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        for host in ["site.test", "provider.test", "192.0.2.7", "ads.test"] {
            assert_eq!(
                core.route(&route(host), "tcp").await.unwrap(),
                "REJECT",
                "{host}"
            );
        }
        assert!(core.resources_incomplete(), "bad provider remains pending");
        assert!(
            !dir.join("bad.yaml").exists(),
            "invalid downloads must not be committed"
        );
        assert!(dir.join("geosite.dat").exists());
        let rewriter = core.rewriter().unwrap();
        assert!(rewriter.hostnames.iter().any(|h| h == "rewrite.test"));
        assert_eq!(
            rewriter
                .matching(
                    clyntis_config::rewrite::Phase::Request,
                    "https://rewrite.test/ad"
                )
                .len(),
            1
        );
        assert!(rewriter.file("http://resources.invalid/script").is_some());
        // Both fake-IP filters and nameserver policies now use the new sets.
        for host in ["site.test", "provider.test"] {
            let response =
                tokio::time::timeout(Duration::from_secs(1), core.resolver.answer(&query(host)))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(
                answer_ip(response),
                "203.0.113.22".parse::<IpAddr>().unwrap()
            );
        }
        assert!(rewriter.file("http://resources.invalid/body").is_some());
        assert_eq!(calls.load(Ordering::SeqCst), 8);
        running.shutdown().await;
        server.abort();
        dns_server.await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_resources_disable_entire_negated_and_compound_conditions() {
        let resources = Resources {
            partial: true,
            ..Resources::default()
        };
        for condition in [
            "NOT,((GEOSITE,missing)),REJECT",
            "OR,((DOMAIN,local.test),(RULE-SET,missing)),REJECT",
            "AND,((DOMAIN,local.test),(NOT,((GEOIP,ZZ)))),REJECT",
        ] {
            let rule = resources.rules(&[condition.into()]).unwrap().remove(0);
            assert!(
                !rule.matches("local.test", Some("192.0.2.7".parse().unwrap()), 443, "tcp"),
                "{condition}"
            );
        }
        assert!(
            resources
                .rules(&["DOMAIN,local.test,REJECT".into()])
                .unwrap()[0]
                .matches("local.test", None, 443, "tcp")
        );
    }

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
    fn providers_group_domains_and_cidrs_without_changing_matches() {
        let provider = |behavior: &str| RuleProvider {
            behavior: behavior.into(),
            ..RuleProvider::default()
        };
        let payload = |lines: &[&str]| lines.iter().map(|l| l.to_string()).collect::<Vec<_>>();
        let domain = provider_matcher(
            &provider("domain"),
            &payload(&["+.ads.test", ".sub.test", "exact.test", "*.wild.test"]),
        )
        .unwrap();
        let eval = |m: &Matcher, host: &str, ip: Option<IpAddr>, port: u16| {
            m.evaluate(host, ip, port, "tcp", false)
        };
        for (host, expected) in [
            ("ads.test", true),
            ("x.ads.test", true),
            ("sub.test", false),
            ("x.sub.test", true),
            ("exact.test", true),
            ("a.wild.test", true),
            ("other.test", false),
        ] {
            assert_eq!(eval(&domain, host, None, 443), Some(expected), "{host}");
        }
        let classical = provider_matcher(
            &provider("classical"),
            &payload(&[
                "DOMAIN-SUFFIX,ads.test",
                "DOMAIN,exact.test",
                "IP-CIDR,10.0.0.0/8",
                "DST-PORT,8443",
            ]),
        )
        .unwrap();
        assert_eq!(eval(&classical, "x.ads.test", None, 443), Some(true));
        assert_eq!(eval(&classical, "exact.test", None, 443), Some(true));
        assert_eq!(
            eval(&classical, "n.test", Some("10.1.2.3".parse().unwrap()), 443),
            Some(true)
        );
        assert_eq!(eval(&classical, "n.test", None, 8443), Some(true));
        assert_eq!(
            eval(&classical, "n.test", Some("8.8.8.8".parse().unwrap()), 443),
            Some(false)
        );
        let ipcidr = provider_matcher(&provider("ipcidr"), &payload(&["192.168.0.0/16"])).unwrap();
        assert_eq!(
            eval(&ipcidr, "h", Some("192.168.1.1".parse().unwrap()), 1),
            Some(true)
        );
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
    fn domains(resources: &Resources) -> Arc<clyntis_config::rule::DomainSet> {
        match resources.matchers.get(&("geosite".into(), "test".into())) {
            Some(Matcher::Domains(set)) => set.clone(),
            _ => panic!("geosite matcher missing"),
        }
    }

    #[tokio::test]
    async fn unchanged_geo_data_is_reused_and_failed_updates_keep_the_file() {
        let (config, attempts) = expired_geosite(false).await;
        let dns =
            crate::dns::Resolver::new(Default::default(), Arc::new(clyntis_platform::DefaultHooks));
        let hooks: clyntis_platform::Hooks = Arc::new(clyntis_platform::DefaultHooks);
        let first = Resources::load(&config, &dns, &hooks, false, &Resources::default(), None)
            .await
            .unwrap();
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 0);
        // Desktop refresh tries the expired file, fails, and keeps the local copy;
        // the unchanged file means the old matcher is reused, not rebuilt.
        let second = Resources::load(&config, &dns, &hooks, true, &first, None)
            .await
            .unwrap();
        assert!(attempts.load(std::sync::atomic::Ordering::SeqCst) > 0);
        assert!(Arc::ptr_eq(&domains(&first), &domains(&second)));
        assert!(domains(&second).matches("www.example.test"));
        std::fs::remove_dir_all(&config.directory).unwrap();
    }

    #[tokio::test]
    async fn unchanged_providers_and_adblock_lists_are_reused() {
        let dir = std::env::temp_dir().join(format!("meta-reuse-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("adblock")).unwrap();
        std::fs::write(dir.join("ads.txt"), "ads.test\n").unwrap();
        std::fs::write(
            dir.join("adblock/list.list"),
            "payload:\n  - '+.one.test'\n",
        )
        .unwrap();
        let mut config = Config::parse(
            b"rule-providers:\n  ads: {type: file, path: ads.txt, behavior: domain, format: text}\nadblock:\n  enable: true\n  lists: [{name: list, url: 'https://example.invalid/l.yaml'}]\nrules: ['RULE-SET,ads,REJECT', 'MATCH,DIRECT']\n",
        )
        .unwrap();
        config.directory = dir.clone();
        let dns =
            crate::dns::Resolver::new(Default::default(), Arc::new(clyntis_platform::DefaultHooks));
        let hooks: clyntis_platform::Hooks = Arc::new(clyntis_platform::DefaultHooks);
        let load = |previous| Resources::load(&config, &dns, &hooks, false, previous, None);
        let provider = |r: &Resources| match &r.providers["ads"].1 {
            Matcher::Or(nodes) => match &nodes[0] {
                Matcher::Domains(set) => set.clone(),
                _ => panic!("provider domains missing"),
            },
            _ => panic!("provider matcher missing"),
        };
        let filter = |r: &Resources| r.adblock.clone().unwrap();
        let empty = Resources::default();
        let first = load(&empty).await.unwrap();
        let second = load(&first).await.unwrap();
        assert!(Arc::ptr_eq(&provider(&first), &provider(&second)));
        assert!(filter(&first).shares_lists(&filter(&second)));
        assert_eq!(filter(&second).lists[0].entries, 1);
        // Same contents rewritten (a periodic download): still reused.
        std::fs::write(dir.join("ads.txt"), "ads.test\n").unwrap();
        let third = load(&second).await.unwrap();
        assert!(Arc::ptr_eq(&provider(&second), &provider(&third)));
        // Changed contents are rebuilt.
        std::fs::write(dir.join("ads.txt"), "other.test\n").unwrap();
        std::fs::write(
            dir.join("adblock/list.list"),
            "payload:\n  - '+.two.test'\n",
        )
        .unwrap();
        let fourth = load(&third).await.unwrap();
        assert!(!Arc::ptr_eq(&provider(&third), &provider(&fourth)));
        assert!(provider(&fourth).matches("other.test") && !provider(&fourth).matches("ads.test"));
        assert!(!filter(&third).shares_lists(&filter(&fourth)));
        assert!(filter(&fourth).blocks("x.two.test") && !filter(&fourth).blocks("x.one.test"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn freshness_reports_missing_then_expired_files() {
        let dir = std::env::temp_dir().join(format!("meta-fresh-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut config = Config::parse(
            b"geo-auto-update: true\ngeo-update-interval: 24\nrule-providers:\n  ads: {type: http, url: 'https://example.com/ads.txt', path: ads.txt, interval: 3600, behavior: domain, format: text}\nrules: ['GEOSITE,cn,DIRECT', 'RULE-SET,ads,REJECT', 'MATCH,DIRECT']\n",
        )
        .unwrap();
        config.directory = dir.clone();
        assert_eq!(freshness(&config).unwrap(), Freshness::Missing);
        std::fs::write(dir.join("ads.txt"), "ads.test\n").unwrap();
        // geosite.dat is still missing.
        assert_eq!(freshness(&config).unwrap(), Freshness::Missing);
        std::fs::write(dir.join("geosite.dat"), b"").unwrap();
        assert_eq!(freshness(&config).unwrap(), Freshness::Current);
        // A provider past its interval is usable but due for a refresh.
        let old = std::time::SystemTime::now() - Duration::from_secs(7200);
        std::fs::File::options()
            .write(true)
            .open(dir.join("ads.txt"))
            .unwrap()
            .set_modified(old)
            .unwrap();
        assert_eq!(freshness(&config).unwrap(), Freshness::Expired);
        // geoip.dat is not referenced, so its absence does not matter.
        assert!(!dir.join("geoip.dat").exists());
        let _ = std::fs::remove_dir_all(dir);
    }
    #[tokio::test]
    async fn hosted_tunnels_can_refresh_geo_data_while_running() {
        let (config, attempts) = expired_geosite(true).await;
        let dns =
            crate::dns::Resolver::new(Default::default(), Arc::new(clyntis_platform::DefaultHooks));
        let hooks: clyntis_platform::Hooks = Arc::new(clyntis_platform::DefaultHooks);
        // Start: no previous snapshot, so the expired file is checked (and kept on failure).
        let first = Resources::load(&config, &dns, &hooks, true, &Resources::default(), None)
            .await
            .unwrap();
        let at_start = attempts.load(std::sync::atomic::Ordering::SeqCst);
        assert!(at_start > 0);
        // While running: updates are attempted too; failed updates reuse the set.
        let second = Resources::load(&config, &dns, &hooks, true, &first, None)
            .await
            .unwrap();
        assert!(attempts.load(std::sync::atomic::Ordering::SeqCst) > at_start);
        assert!(Arc::ptr_eq(&domains(&first), &domains(&second)));
        std::fs::remove_dir_all(&config.directory).unwrap();
    }

    fn proxy_core(rules: &str, groups: &str) -> Arc<crate::Core> {
        let yaml = format!(
            "proxies:\n  - {{name: node, type: vless, server: example.com, port: 443, uuid: 11111111-1111-4111-8111-111111111111, network: tcp}}\nproxy-groups:\n{groups}rules:\n{rules}"
        );
        let config = Config::parse(yaml.as_bytes()).unwrap();
        crate::Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap()
    }

    #[test]
    fn resource_proxy_follows_match_then_first_group_and_never_direct() {
        let groups = "  - {name: Proxy, type: select, proxies: [node, DIRECT]}\n  - {name: Home, type: select, proxies: [DIRECT]}\n";
        let core = proxy_core("  - DOMAIN,x.test,Home\n  - MATCH,Proxy\n", groups);
        assert_eq!(core.resource_proxy().as_deref(), Some("Proxy"));
        // MATCH to DIRECT: fall back to the first group.
        let core = proxy_core("  - MATCH,DIRECT\n", groups);
        assert_eq!(core.resource_proxy().as_deref(), Some("Proxy"));
        // Every candidate resolves to DIRECT: no proxy fallback.
        let core = proxy_core(
            "  - MATCH,Home\n",
            "  - {name: Home, type: select, proxies: [DIRECT]}\n",
        );
        assert_eq!(core.resource_proxy(), None);
    }

    #[tokio::test]
    async fn download_can_route_through_a_core_outbound() {
        let core = proxy_core(
            "  - MATCH,DIRECT\n",
            "  - {name: Proxy, type: select, proxies: [node]}\n",
        );
        let url = slow_server(vec![(0, &b"through-core"[..])]).await;
        let resolver =
            crate::dns::Resolver::new(Default::default(), Arc::new(clyntis_platform::DefaultHooks));
        let hooks: clyntis_platform::Hooks = Arc::new(clyntis_platform::DefaultHooks);
        let mut data = Vec::new();
        // DIRECT stands in for a proxy here: the request goes through Core::dial.
        download_with(
            &url,
            &resolver,
            &hooks,
            Some((&core, "DIRECT")),
            short(),
            LIMIT,
            &mut data,
        )
        .await
        .unwrap();
        assert_eq!(data, b"through-core");
    }

    #[tokio::test]
    async fn slow_but_steady_download_outlives_the_idle_timeout() {
        let resolver =
            crate::dns::Resolver::new(Default::default(), Arc::new(clyntis_platform::DefaultHooks));
        let hooks: clyntis_platform::Hooks = Arc::new(clyntis_platform::DefaultHooks);
        // Takes ~1.5s in total, three times the idle limit, but never pauses for long.
        let url = slow_server((0..6).map(|_| (250, &b"chunk"[..])).collect()).await;
        let mut data = Vec::new();
        let received = download_with(&url, &resolver, &hooks, None, short(), LIMIT, &mut data)
            .await
            .unwrap();
        assert_eq!(data, b"chunk".repeat(6));
        assert_eq!(received, data.len());
    }
    #[tokio::test]
    async fn stalled_download_reports_progress_instead_of_a_bare_deadline() {
        let resolver =
            crate::dns::Resolver::new(Default::default(), Arc::new(clyntis_platform::DefaultHooks));
        let hooks: clyntis_platform::Hooks = Arc::new(clyntis_platform::DefaultHooks);
        let url = slow_server(vec![(0, b"partial"), (3000, b"rest")]).await;
        let error = download_with(
            &url,
            &resolver,
            &hooks,
            None,
            short(),
            LIMIT,
            &mut Vec::new(),
        )
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
        let hooks: clyntis_platform::Hooks = Arc::new(clyntis_platform::DefaultHooks);
        let dns = crate::dns::Resolver::new(c.dns.clone(), hooks.clone());
        let resources = Resources::load(&c, &dns, &hooks, false, &Resources::default(), None)
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
                &clyntis_protocol::Target::new("www.example.test", 443).unwrap(),
                "tcp"
            )
            .await
            .unwrap(),
            "REJECT"
        );
        assert_eq!(
            core.route(
                &clyntis_protocol::Target::new("10.1.1.1", 80).unwrap(),
                "tcp"
            )
            .await
            .unwrap(),
            "DIRECT"
        );
        assert_eq!(
            core.route(
                &clyntis_protocol::Target::new("blocked.test", 80).unwrap(),
                "tcp"
            )
            .await
            .unwrap(),
            "REJECT"
        );
        std::fs::write(dir.join("geosite.dat"), [255]).unwrap();
        assert!(
            Resources::load(&c, &dns, &hooks, false, &Resources::default(), None)
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
        let hooks: clyntis_platform::Hooks = Arc::new(clyntis_platform::DefaultHooks);
        let core = crate::Core::new(c, hooks).unwrap();
        core.prepare_resources(false).await.unwrap();
        let target = |s| clyntis_protocol::Target::new(s, 80).unwrap();
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

    #[tokio::test]
    async fn stale_snapshots_and_temps_are_cleaned_at_start_while_live_ones_stay() {
        let dir = std::env::temp_dir().join(format!("meta-clean-{}", uuid::Uuid::new_v4()));
        let url = "https://example.test/script.js";
        let cache = dir.join(clyntis_config::rewrite::cache_file(url));
        std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
        std::fs::write(&cache, "$done({});").unwrap();
        let config = Config {
            directory: dir.clone(),
            rewrite: clyntis_config::rewrite::Rewrite {
                enable: true,
                custom: format!(
                    "[Script]\ntest = type=http-response,pattern=^https://a\\.test/,script-path={url}\n"
                ),
                ..Default::default()
            },
            ..Config::default()
        };
        let first = load_rewrites(&config, &Resources::default(), false, LoadMode::Cached).await;
        let live_snapshot = first.rewrite.as_ref().unwrap().file(url).unwrap().clone();
        let orphan_snapshot = cache.with_extension(format!("{}.snapshot", uuid::Uuid::new_v4()));
        let active_tmp = cache.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let stale_tmp = dir.join(format!("geoip.{}.tmp", uuid::Uuid::new_v4()));
        std::fs::write(&orphan_snapshot, "stale").unwrap();
        std::fs::write(&active_tmp, "active").unwrap();
        std::fs::write(&stale_tmp, "stale").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&stale_tmp)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::SystemTime::now() - Duration::from_secs(700)),
            )
            .unwrap();

        // While `first` holds a live snapshot, another start must keep active
        // `.tmp` files and must not touch `.snapshot` files.
        let second = load_rewrites(&config, &Resources::default(), false, LoadMode::Cached).await;
        assert!(active_tmp.exists());
        assert!(orphan_snapshot.exists());
        assert!(!stale_tmp.exists());
        assert!(live_snapshot.exists());
        assert!(second.rewrite.as_ref().unwrap().file(url).unwrap().exists());
        drop(first);
        drop(second);
        assert!(!live_snapshot.exists());

        // Once no instance holds snapshots, a startup cleans orphaned `.snapshot`s.
        let third = load_rewrites(&config, &Resources::default(), false, LoadMode::Cached).await;
        assert!(!orphan_snapshot.exists());
        assert!(active_tmp.exists());
        drop(third);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn missing_geo_category_preserves_siblings_and_commits_geo_file() {
        use axum::{Router, routing::get};
        let dir = std::env::temp_dir().join(format!("meta-geo-partial-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let site = GeoSiteList {
            entry: vec![GeoSite {
                country_code: "cn".into(),
                domain: vec![Domain {
                    kind: 2,
                    value: "example.test".into(),
                    attribute: vec![],
                }],
            }],
        }
        .encode_to_vec();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/geosite.dat", listener.local_addr().unwrap());
        let app = Router::new().route("/geosite.dat", get(move || async move { site }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut config = Config {
            directory: dir.clone(),
            rules: vec![
                "GEOSITE,cn,REJECT".into(),
                "GEOSITE,nonexistent,REJECT".into(),
                "MATCH,DIRECT".into(),
            ],
            ..Config::default()
        };
        config.geox_url.geosite = url;

        let first = load_rewrites(&config, &Resources::default(), false, LoadMode::Available).await;
        assert!(!first.incomplete());
        assert!(dir.join("geosite.dat").exists());
        let rules = first.rules(&config.rules).unwrap();
        assert!(rules[0].matches("www.example.test", None, 443, "tcp"));
        assert!(!rules[1].matches("www.example.test", None, 443, "tcp"));

        let second = load_rewrites(&config, &first, false, LoadMode::Available).await;
        assert!(!second.incomplete());
        let set = |res: &Resources| match res.matchers.get(&("geosite".into(), "cn".into())) {
            Some(Matcher::Domains(set)) => set.clone(),
            _ => panic!("cn matcher missing"),
        };
        assert!(Arc::ptr_eq(&set(&first), &set(&second)));
        server.abort();
        let _ = server.await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn partial_adblock_failure_reuses_unchanged_lists_and_updates_error() {
        let dir = std::env::temp_dir().join(format!("meta-adblock-reuse-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("adblock")).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed = format!("http://{}/bad.list", listener.local_addr().unwrap());
        drop(listener);
        let config = Config::parse(
            format!(
                "adblock:\n  enable: true\n  lists:\n    - {{name: good, url: 'https://example.invalid/good.yaml'}}\n    - {{name: bad, url: '{closed}'}}\n"
            )
            .as_bytes(),
        )
        .unwrap();
        let mut config = config;
        config.directory = dir.clone();
        std::fs::write(
            dir.join("adblock/good.list"),
            "payload:\n  - '+.ads.test'\n",
        )
        .unwrap();

        let first = load_rewrites(&config, &Resources::default(), false, LoadMode::Cached).await;
        let first_filter = first.adblock.as_ref().unwrap();
        assert!(
            first_filter.lists[1]
                .error
                .as_deref()
                .unwrap()
                .contains("download deferred")
        );

        let second = load_rewrites(&config, &first, false, LoadMode::Available).await;
        let second_filter = second.adblock.as_ref().unwrap();
        assert!(first_filter.shares_lists(second_filter));
        assert_eq!(second_filter.lists[0].entries, 1);
        assert!(
            second_filter.lists[1]
                .error
                .as_deref()
                .unwrap()
                .contains("routing resource download failed")
        );
        assert!(second_filter.blocks("x.ads.test"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn noop_resource_retry_preserves_dns_cache() {
        use hickory_proto::{
            op::Message,
            rr::{RData, Record, rdata::A},
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = std::env::temp_dir().join(format!("meta-dns-cache-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bad_url = format!("http://{}/bad.txt", listener.local_addr().unwrap());
        drop(listener);
        let dns_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream = dns_socket.local_addr().unwrap().to_string();
        let dns_calls = Arc::new(AtomicUsize::new(0));
        let calls = dns_calls.clone();
        let dns_server = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = dns_socket.recv_from(&mut buf).await {
                calls.fetch_add(1, Ordering::SeqCst);
                let mut msg = Message::from_vec(&buf[..len]).unwrap();
                let name = msg.queries()[0].name().clone();
                msg.set_message_type(hickory_proto::op::MessageType::Response);
                msg.add_answer(Record::from_rdata(
                    name,
                    300,
                    RData::A(A("203.0.113.50".parse().unwrap())),
                ));
                dns_socket
                    .send_to(&msg.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let yaml = format!(
            "dns:\n  nameserver: ['{upstream}']\nrule-providers:\n  missing: {{type: http, url: '{bad_url}', path: missing.txt, behavior: domain, format: text}}\nrules: ['RULE-SET,missing,REJECT', 'MATCH,DIRECT']\n"
        );
        let mut config = Config::parse(yaml.as_bytes()).unwrap();
        config.directory = dir.clone();
        config.dns.ipv6 = false;
        let core = crate::Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        core.prepare_resources_with(false, LoadMode::Cached)
            .await
            .unwrap();
        assert!(core.resources_incomplete());
        assert_eq!(
            core.resolver.lookup("cached.test", 443).await.unwrap()[0].to_string(),
            "203.0.113.50:443"
        );
        assert_eq!(dns_calls.load(Ordering::SeqCst), 1);

        core.prepare_resources_with(false, LoadMode::Available)
            .await
            .unwrap();
        assert!(core.resources_incomplete());
        assert_eq!(
            core.resolver.lookup("cached.test", 443).await.unwrap()[0].to_string(),
            "203.0.113.50:443"
        );
        assert_eq!(
            dns_calls.load(Ordering::SeqCst),
            1,
            "unchanged failed retry must not clear the DNS cache"
        );
        dns_server.abort();
        let _ = dns_server.await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn hosted_refresh_replaces_a_recent_oversized_script_cache() {
        use axum::{Router, routing::get};
        let dir = std::env::temp_dir().join(format!("meta-fresh-script-{}", uuid::Uuid::new_v4()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let script_url = format!("http://{}/ad.js", listener.local_addr().unwrap());
        let script = "$done({});";
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/ad.js", get(move || async move { script })),
            )
            .await
            .unwrap()
        });
        let config = Config {
            directory: dir.clone(),
            internal_host_packet_io: true,
            rewrite: clyntis_config::rewrite::Rewrite {
                enable: true,
                interval: 3600,
                custom: format!(
                    "[Script]\nad = type=http-response,pattern=^https://a\\.test/,script-path={script_url}\n"
                ),
                ..Default::default()
            },
            ..Config::default()
        };
        let path = dir.join(clyntis_config::rewrite::cache_file(&script_url));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::File::create(&path)
            .unwrap()
            .set_len(crate::script::source_limit(true) as u64 + 1)
            .unwrap();
        assert_eq!(freshness(&config).unwrap(), Freshness::Missing);
        let cached =
            load_rewrites(&config, &Resources::default(), false, LoadMode::Available).await;
        assert!(cached.rewrite.as_ref().unwrap().file(&script_url).is_none());
        let refreshed = load_rewrites(&config, &cached, true, LoadMode::Available).await;
        assert!(
            refreshed
                .rewrite
                .as_ref()
                .unwrap()
                .file(&script_url)
                .is_some()
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), script);
        assert_eq!(freshness(&config).unwrap(), Freshness::Current);
        server.abort();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn freshness_checks_rewrite_scripts_and_update_policy_loads_cached_geo() {
        let dir = std::env::temp_dir().join(format!("meta-fresh-policy-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let script_url = "https://example.test/ad.js";
        let mut config = Config {
            directory: dir.clone(),
            rewrite: clyntis_config::rewrite::Rewrite {
                enable: true,
                interval: 3600,
                custom: format!(
                    "[Script]\nad = type=http-response,pattern=^https://a\\.test/,script-path={script_url}\n"
                ),
                ..Default::default()
            },
            rules: vec!["MATCH,DIRECT".into()],
            ..Config::default()
        };
        assert_eq!(freshness(&config).unwrap(), Freshness::Missing);
        let script_path = dir.join(clyntis_config::rewrite::cache_file(script_url));
        std::fs::create_dir_all(script_path.parent().unwrap()).unwrap();
        std::fs::write(&script_path, "$done({});").unwrap();
        assert_eq!(freshness(&config).unwrap(), Freshness::Current);
        std::fs::File::options()
            .write(true)
            .open(&script_path)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::SystemTime::now() - Duration::from_secs(7200)),
            )
            .unwrap();
        assert_eq!(freshness(&config).unwrap(), Freshness::Expired);

        let site = GeoSiteList {
            entry: vec![GeoSite {
                country_code: "cn".into(),
                domain: vec![Domain {
                    kind: 2,
                    value: "cn.test".into(),
                    attribute: vec![],
                }],
            }],
        }
        .encode_to_vec();
        std::fs::write(dir.join("geosite.dat"), site).unwrap();
        config.rewrite.enable = false;
        let core = crate::Core::new(config, Arc::new(clyntis_platform::DefaultHooks)).unwrap();
        let running = core.start().await.unwrap();
        core.update_policy(
            None,
            Some(vec!["GEOSITE,cn,REJECT".into(), "MATCH,DIRECT".into()]),
        )
        .unwrap();
        assert!(!core.resources_incomplete());
        assert_eq!(
            core.route(
                &clyntis_protocol::Target::new("sub.cn.test", 443).unwrap(),
                "tcp"
            )
            .await
            .unwrap(),
            "REJECT"
        );
        running.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn freshness_skips_domain_provider_parsing_scans_classical_and_caps_hosted_mock() {
        let dir = std::env::temp_dir().join(format!("meta-fresh-light-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut config = Config::parse(
            b"geodata-mode: true\nrule-providers:\n  dom: {type: file, path: dom.yaml, behavior: domain, format: yaml}\n  ip: {type: file, path: ip.txt, behavior: ipcidr, format: text}\n  cls: {type: file, path: cls.yaml, behavior: classical, format: yaml}\nrules: ['RULE-SET,dom,DIRECT', 'RULE-SET,ip,DIRECT', 'RULE-SET,cls,DIRECT', 'MATCH,DIRECT']\n",
        )
        .unwrap();
        config.directory = dir.clone();
        // Domain and ipcidr providers are stat'd without parsing YAML/text contents.
        std::fs::write(dir.join("dom.yaml"), b":::not valid yaml:::").unwrap();
        std::fs::write(dir.join("ip.txt"), b"not-a-cidr\n").unwrap();
        std::fs::write(
            dir.join("cls.yaml"),
            b"payload:\n  - DOMAIN-SUFFIX,example.com\n  - 'AND,((GEOIP,CN),(DST-PORT,443))'\n",
        )
        .unwrap();
        // Classical provider references GEOIP, so missing geoip.dat is detected.
        assert_eq!(freshness(&config).unwrap(), Freshness::Missing);
        std::fs::write(dir.join("geoip.dat"), b"").unwrap();
        assert_eq!(freshness(&config).unwrap(), Freshness::Current);

        // Hosted mode caps MockBody::Remote downloads to 2 MiB.
        let mock_module = clyntis_config::rewrite::parse_module(
            "[Map Local]\n^https://a\\.test/mock$ data=https://cdn.test/mock.json\n",
        );
        let hosted_urls = rewrite_file_urls(
            std::iter::once(&mock_module),
            crate::script::source_limit(true),
            rewrite_mock_limit(true),
        );
        assert_eq!(
            hosted_urls.get("https://cdn.test/mock.json"),
            Some(&HOSTED_MOCK_LIMIT)
        );
        let desktop_urls = rewrite_file_urls(
            std::iter::once(&mock_module),
            crate::script::source_limit(false),
            rewrite_mock_limit(false),
        );
        assert_eq!(desktop_urls.get("https://cdn.test/mock.json"), Some(&LIMIT));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn populate_geoip_decodes_cidrs_lazily_including_v6_and_inverse() {
        let dir = std::env::temp_dir().join(format!("meta-geoip-lazy-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let data = dir.join("geoip.dat");
        let list = GeoIpList {
            entry: vec![
                GeoIp {
                    country_code: "CN".into(),
                    cidr: vec![
                        Cidr {
                            ip: vec![1, 2, 3, 0],
                            prefix: 24,
                        },
                        Cidr {
                            ip: "2400:3200::"
                                .parse::<std::net::Ipv6Addr>()
                                .unwrap()
                                .octets()
                                .to_vec(),
                            prefix: 32,
                        },
                    ],
                    inverse_match: false,
                },
                GeoIp {
                    country_code: "INV".into(),
                    cidr: vec![Cidr {
                        ip: vec![10, 0, 0, 0],
                        prefix: 8,
                    }],
                    inverse_match: true,
                },
            ],
        }
        .encode_to_vec();
        std::fs::write(&data, list).unwrap();

        let previous = Resources::default();
        let mut out = Resources::default();
        populate_geoip(
            &data,
            true,
            &["cn".into(), "!cn".into(), "inv".into()],
            &previous,
            false,
            &mut out,
        )
        .unwrap();

        let v4_cn: IpAddr = "1.2.3.4".parse().unwrap();
        let v6_cn: IpAddr = "2400:3200::1".parse().unwrap();
        let other: IpAddr = "8.8.8.8".parse().unwrap();
        let priv_v4: IpAddr = "10.1.2.3".parse().unwrap();

        let cn = out.matchers.get(&("geoip".into(), "cn".into())).unwrap();
        let not_cn = out.matchers.get(&("geoip".into(), "!cn".into())).unwrap();
        let inv = out.matchers.get(&("geoip".into(), "inv".into())).unwrap();
        assert_eq!(cn.evaluate("", Some(v4_cn), 0, "", false), Some(true));
        assert_eq!(cn.evaluate("", Some(v6_cn), 0, "", false), Some(true));
        assert_eq!(cn.evaluate("", Some(other), 0, "", false), Some(false));
        assert_eq!(not_cn.evaluate("", Some(v4_cn), 0, "", false), Some(false));
        assert_eq!(not_cn.evaluate("", Some(other), 0, "", false), Some(true));
        assert_eq!(inv.evaluate("", Some(priv_v4), 0, "", false), Some(false));
        assert_eq!(inv.evaluate("", Some(other), 0, "", false), Some(true));

        // Re-populating from a new file where "CN" has identical bytes reuses the Arc<IpSet>.
        let data2 = dir.join("geoip2.dat");
        std::fs::copy(&data, &data2).unwrap();
        let mut out2 = Resources::default();
        populate_geoip(
            &data2,
            true,
            &["cn".into(), "!cn".into(), "inv".into()],
            &out,
            false,
            &mut out2,
        )
        .unwrap();
        match (
            out.matchers.get(&("geoip".into(), "cn".into())),
            out2.matchers.get(&("geoip".into(), "cn".into())),
        ) {
            (Some(Matcher::Nets(a)), Some(Matcher::Nets(b))) => assert!(Arc::ptr_eq(a, b)),
            _ => panic!("expected Matcher::Nets for cn"),
        }

        // Streaming YAML provider matcher handles payload sequence and rejects unknown fields.
        let yaml_path = dir.join("provider.yaml");
        std::fs::write(
            &yaml_path,
            "payload:\n  - '+.example.com'\n  - 'sub.test'\n",
        )
        .unwrap();
        let p = RuleProvider {
            kind: "file".into(),
            behavior: "domain".into(),
            format: "yaml".into(),
            path: yaml_path.to_string_lossy().into_owned(),
            url: String::new(),
            interval: 3600,
            payload: vec![],
        };
        let m = load_provider_matcher(&p, &yaml_path).unwrap();
        assert_eq!(
            m.evaluate("a.example.com", None, 443, "tcp", false),
            Some(true)
        );
        assert_eq!(m.evaluate("sub.test", None, 443, "tcp", false), Some(true));
        assert_eq!(
            m.evaluate("other.test", None, 443, "tcp", false),
            Some(false)
        );

        let bad_yaml = dir.join("bad.yaml");
        std::fs::write(&bad_yaml, "payload:\n  - 'a.com'\nextra: 1\n").unwrap();
        assert!(load_provider_matcher(&p, &bad_yaml).is_err());

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn binary_rule_cache_roundtrips_providers_and_adblock() {
        let dir = std::env::temp_dir().join(format!("meta-rcache-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        // Classical YAML provider with domains, regex, CIDRs, and port matcher.
        let yaml_path = dir.join("classical.yaml");
        std::fs::write(
            &yaml_path,
            "payload:\n  - DOMAIN,exact.test\n  - DOMAIN-SUFFIX,sfx.test\n  - DOMAIN-KEYWORD,kw\n  - IP-CIDR,192.0.2.0/24\n  - IP-CIDR6,2001:db8::/32\n  - DST-PORT,8443\n",
        )
        .unwrap();
        let p = RuleProvider {
            kind: "file".into(),
            behavior: "classical".into(),
            format: "yaml".into(),
            path: yaml_path.to_string_lossy().into_owned(),
            url: String::new(),
            interval: 3600,
            payload: vec![],
        };
        let stamp = Stamp::of(&yaml_path).unwrap();
        let m1 = load_provider_matcher_cached(&p, &yaml_path, Some((&yaml_path, stamp))).unwrap();
        assert_eq!(
            m1.evaluate("exact.test", None, 443, "tcp", false),
            Some(true)
        );
        assert_eq!(
            m1.evaluate("a.sfx.test", None, 443, "tcp", false),
            Some(true)
        );
        assert_eq!(m1.evaluate("mykw.org", None, 443, "tcp", false), Some(true));
        assert_eq!(
            m1.evaluate("", Some("192.0.2.5".parse().unwrap()), 443, "tcp", false),
            Some(true)
        );
        assert_eq!(
            m1.evaluate("", Some("2001:db8::1".parse().unwrap()), 443, "tcp", false),
            Some(true)
        );
        assert_eq!(
            m1.evaluate("other.test", None, 8443, "tcp", false),
            Some(true)
        );
        assert_eq!(
            m1.evaluate("other.test", None, 80, "tcp", false),
            Some(false)
        );

        // Corrupt the YAML source without changing its stamp? We can verify the binary cache
        // actually serves the second load by overwriting the YAML file with invalid YAML while
        // passing the original stamp directly to `rule_cache::load_provider`.
        let cache_file = rule_cache::cache_path(&yaml_path);
        assert!(cache_file.exists());
        let config_hash = rule_cache::hash_strs(&[p.behavior.as_str(), p.format.as_str()]);
        let m2 = rule_cache::load_provider(&cache_file, stamp, config_hash).unwrap();
        assert_eq!(
            m2.evaluate("exact.test", None, 443, "tcp", false),
            Some(true)
        );
        assert_eq!(
            m2.evaluate("a.sfx.test", None, 443, "tcp", false),
            Some(true)
        );
        assert_eq!(
            m2.evaluate("", Some("192.0.2.5".parse().unwrap()), 443, "tcp", false),
            Some(true)
        );
        assert_eq!(
            m2.evaluate("other.test", None, 8443, "tcp", false),
            Some(true)
        );
        // Wrong config hash or stamp misses the cache cleanly.
        assert!(rule_cache::load_provider(&cache_file, stamp, config_hash ^ 1).is_none());

        // Adblock binary cache roundtrip (domains + allow + IPv4/IPv6).
        let ad_path = dir.join("ads.list");
        let ad_cache = rule_cache::cache_path(&ad_path);
        let ad_stamp = Stamp {
            len: 42,
            digest: [7u8; 32],
        };
        let ad_hash = rule_cache::hash_strs(&["clash"]);
        let mut block = DomainSetBuilder::default();
        let mut allow = DomainSetBuilder::default();
        let mut addrs = Vec::new();
        let buf = std::cell::RefCell::new(Vec::new());
        {
            let mut br = rule_cache::AdblockDomainRecorder {
                target: &mut block,
                allow: false,
                buf: &buf,
            };
            clyntis_config::adblock::DomainTarget::suffix(&mut br, "ad.example");
        }
        {
            let mut ar = rule_cache::AdblockDomainRecorder {
                target: &mut allow,
                allow: true,
                buf: &buf,
            };
            clyntis_config::adblock::DomainTarget::suffix(&mut ar, "ok.ad.example");
        }
        let mut buf = buf.into_inner();
        addrs.push("203.0.113.0/24".parse().unwrap());
        rule_cache::append_ips(&mut buf, &addrs);
        rule_cache::write_adblock(&ad_cache, ad_stamp, ad_hash, 3, &buf).unwrap();

        let mut b2 = DomainSetBuilder::default();
        let mut a2 = DomainSetBuilder::default();
        let mut ips2 = Vec::new();
        let entries =
            rule_cache::load_adblock(&ad_cache, ad_stamp, ad_hash, &mut b2, &mut a2, &mut ips2)
                .unwrap();
        assert_eq!(entries, 3);
        let (b2, a2) = (b2.build(), a2.build());
        assert!(b2.matches("x.ad.example") && a2.matches("ok.ad.example"));
        assert_eq!(
            ips2,
            vec!["203.0.113.0/24".parse::<ipnet::IpNet>().unwrap()]
        );

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn conditional_download_sends_etag_and_handles_304() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let req_log = requests.clone();
        let server = tokio::spawn(async move {
            for idx in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                req_log.lock().unwrap().push(req.clone());
                if idx == 0 {
                    let body = b"cached-payload";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"v1\"\r\nLast-Modified: Wed, 21 Oct 2015 07:28:00 GMT\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(resp.as_bytes()).await.unwrap();
                    stream.write_all(body).await.unwrap();
                } else {
                    let resp =
                        "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n";
                    stream.write_all(resp.as_bytes()).await.unwrap();
                }
            }
        });

        let dir = std::env::temp_dir().join(format!("meta-304-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("list.txt");
        let url = format!("http://{addr}/list.txt");
        let resolver =
            crate::dns::Resolver::new(Default::default(), Arc::new(clyntis_platform::DefaultHooks));
        let hooks: clyntis_platform::Hooks = Arc::new(clyntis_platform::DefaultHooks);
        let fetch = Fetch {
            resolver: &resolver,
            hooks: &hooks,
            proxy: None,
            download: true,
            limit: LIMIT,
        };

        // First fetch: 200 OK writes temp file and `.meta` sidecar.
        let mut staged1 = Staged::default();
        let p1 = asset(&target, &url, Some(3600), true, &fetch, &mut staged1)
            .await
            .unwrap();
        assert_ne!(p1, target);
        staged1.commit().unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"cached-payload");
        let saved_meta = read_http_meta(&target).unwrap();
        assert_eq!(saved_meta.etag.as_deref(), Some("\"v1\""));
        assert_eq!(
            saved_meta.last_modified.as_deref(),
            Some("Wed, 21 Oct 2015 07:28:00 GMT")
        );

        // Backdate mtime so `asset()` treats it as expired and revalidates.
        let old_time = std::time::SystemTime::now() - Duration::from_secs(7200);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&target)
            .unwrap()
            .set_modified(old_time)
            .unwrap();

        // Second fetch: sends If-None-Match & If-Modified-Since, receives 304, updates mtime, keeps file.
        let mut staged2 = Staged::default();
        let p2 = asset(&target, &url, Some(3600), true, &fetch, &mut staged2)
            .await
            .unwrap();
        server.await.unwrap();
        let logged = requests.lock().unwrap();
        assert_eq!(logged.len(), 2, "requests: {logged:?}");
        let second_lower = logged[1].to_ascii_lowercase();
        assert!(
            second_lower.contains("if-none-match: \"v1\""),
            "{}",
            logged[1]
        );
        assert!(
            second_lower.contains("if-modified-since: wed, 21 oct 2015 07:28:00 gmt"),
            "{}",
            logged[1]
        );
        assert_eq!(p2, target);
        assert_eq!(std::fs::read(&target).unwrap(), b"cached-payload");
        let new_mtime = std::fs::metadata(&target).unwrap().modified().unwrap();
        assert!(
            new_mtime > old_time,
            "expected mtime to advance: old={old_time:?}, new={new_mtime:?}"
        );

        std::fs::remove_dir_all(dir).unwrap();
    }
}
