use crate::{Connection, Core};
use anyhow::{Result, ensure};
use async_trait::async_trait;
use clyntis_protocol::{Datagram, Target};
use serde::Serialize;
use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Notify,
    time::Instant,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostTraffic {
    pub host: String,
    pub upload: u64,
    pub download: u64,
    pub active_connections: usize,
    pub total_connections: u64,
    pub chains: Vec<String>,
    pub rule: String,
    pub last_seen: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionTraffic {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub network: String,
    pub chains: Vec<String>,
    pub rule: String,
    pub source: String,
    pub upload: u64,
    pub download: u64,
    pub start: u64,
    pub duration: u64,
    pub active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficDetails {
    pub since: u64,
    pub upload_total: u64,
    pub download_total: u64,
    pub active_connections: usize,
    pub total_connections: u64,
    /// Retained hosts with traffic or active connections (exact session total
    /// when `hosts_evicted` is `false`).
    pub total_hosts: usize,
    pub hosts_evicted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_host: Option<String>,
    pub matching_active_connections: usize,
    pub matching_closed_connections: u64,
    pub retained_closed_connections: usize,
    pub closed_connection_cap: usize,
    pub hosts: Vec<HostTraffic>,
    pub other_upload: u64,
    pub other_download: u64,
    pub other_connections: u64,
    pub connections: Vec<ConnectionTraffic>,
}

impl TrafficDetails {
    fn trim_hosts_half(&mut self) -> bool {
        if self.hosts.is_empty() {
            return false;
        }
        let next_len = self.hosts.len() / 2;
        for overflow in self.hosts.drain(next_len..) {
            self.other_upload = self.other_upload.saturating_add(overflow.upload);
            self.other_download = self.other_download.saturating_add(overflow.download);
            self.other_connections = self
                .other_connections
                .saturating_add(overflow.total_connections);
        }
        true
    }

    fn trim_connections_preserving_active(&mut self) -> bool {
        if self.connections.is_empty() {
            return false;
        }
        let closed_count = self.connections.iter().filter(|c| !c.active).count();
        if closed_count > 0 {
            let keep_closed = closed_count / 2;
            let mut kept_closed = 0usize;
            self.connections.retain(|c| {
                if c.active {
                    return true;
                }
                if kept_closed < keep_closed {
                    kept_closed += 1;
                    true
                } else {
                    false
                }
            });
            return true;
        }
        let next_len = self.connections.len() / 2;
        self.connections.truncate(next_len);
        true
    }

    /// Serializes to JSON, shrinking payload size to fit within `max_bytes`.
    /// Global views trim connections (dropping closed before active) then
    /// hosts; host drill-downs trim global hosts first so the drilled-down
    /// host keeps its active connections. Trimmed hosts fold into `other_*`.
    pub fn to_capped_json_vec(&self, max_bytes: usize) -> serde_json::Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() <= max_bytes {
            return Ok(bytes);
        }
        drop(bytes);
        let mut capped = self.clone();
        if capped.connection_host.is_some() {
            while capped.trim_hosts_half() {
                let candidate = serde_json::to_vec(&capped)?;
                if candidate.len() <= max_bytes {
                    return Ok(candidate);
                }
            }
            while capped.trim_connections_preserving_active() {
                let candidate = serde_json::to_vec(&capped)?;
                if candidate.len() <= max_bytes {
                    return Ok(candidate);
                }
            }
        } else {
            while capped.trim_connections_preserving_active() {
                let candidate = serde_json::to_vec(&capped)?;
                if candidate.len() <= max_bytes {
                    return Ok(candidate);
                }
            }
            while capped.trim_hosts_half() {
                let candidate = serde_json::to_vec(&capped)?;
                if candidate.len() <= max_bytes {
                    return Ok(candidate);
                }
            }
        }
        serde_json::to_vec(&capped)
    }
}

#[derive(Clone, Copy, Debug)]
struct LedgerLimits {
    max_hosts: usize,
    max_candidates: usize,
    max_closed: usize,
    snapshot_hosts: usize,
    snapshot_active: usize,
    snapshot_closed: usize,
}

const DESKTOP_LIMITS: LedgerLimits = LedgerLimits {
    max_hosts: 3072,
    max_candidates: 1024,
    max_closed: 500,
    snapshot_hosts: 200,
    snapshot_active: 200,
    snapshot_closed: 200,
};

const HOSTED_LIMITS: LedgerLimits = LedgerLimits {
    max_hosts: 768,
    max_candidates: 256,
    max_closed: 150,
    snapshot_hosts: 80,
    snapshot_active: 50,
    snapshot_closed: 50,
};

#[derive(Clone, Debug)]
struct ClosedHost {
    host: String,
    upload: u64,
    download: u64,
    connections: u64,
    chains: Vec<String>,
    rule: String,
    last_seen: u64,
    last_seq: u64,
}

pub(crate) struct Ledger {
    active: HashMap<String, Arc<State>>,
    closed_hosts: HashMap<String, ClosedHost>,
    candidate_hosts: HashMap<String, ClosedHost>,
    hosts_evicted: bool,
    closed_upload: u64,
    closed_download: u64,
    closed_count: u64,
    other_upload: u64,
    other_download: u64,
    other_connections: u64,
    closed_connections: Vec<ConnectionTraffic>,
    limits: LedgerLimits,
    since: u64,
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn insert_host_or_accumulate(
    entry: &mut ClosedHost,
    upload: u64,
    download: u64,
    last_seen: u64,
    seq: u64,
    chains: &[String],
    rule: &str,
) {
    entry.upload = entry.upload.saturating_add(upload);
    entry.download = entry.download.saturating_add(download);
    entry.connections = entry.connections.saturating_add(1);
    if last_seen >= entry.last_seen {
        entry.chains = chains.to_vec();
        entry.rule = rule.to_owned();
        entry.last_seen = last_seen;
    }
    entry.last_seq = seq;
}

impl Ledger {
    pub(crate) fn new(hosted: bool) -> Self {
        Self::with_limits(if hosted {
            HOSTED_LIMITS
        } else {
            DESKTOP_LIMITS
        })
    }

    fn with_limits(limits: LedgerLimits) -> Self {
        Self {
            active: HashMap::new(),
            closed_hosts: HashMap::new(),
            candidate_hosts: HashMap::new(),
            hosts_evicted: false,
            closed_upload: 0,
            closed_download: 0,
            closed_count: 0,
            other_upload: 0,
            other_download: 0,
            other_connections: 0,
            closed_connections: Vec::new(),
            limits,
            since: now_unix_secs(),
        }
    }

    pub(crate) fn insert_active(&mut self, state: Arc<State>) -> Result<()> {
        ensure!(self.active.len() < 4096, "connection limit reached");
        self.active.insert(state.info.id.clone(), state);
        Ok(())
    }

    pub(crate) fn remove_and_record(&mut self, state: &State) {
        if self.active.remove(&state.info.id).is_none() {
            return;
        }
        let upload = state.upload.load(Ordering::Relaxed);
        let download = state.download.load(Ordering::Relaxed);
        let total = upload.saturating_add(download);
        let lifetime = state.lifetime();
        let duration = lifetime.as_millis() as u64;
        let last_seen = state.started_unix.saturating_add(lifetime.as_secs());

        self.closed_upload = self.closed_upload.saturating_add(upload);
        self.closed_download = self.closed_download.saturating_add(download);
        self.closed_count = self.closed_count.saturating_add(1);
        let seq = self.closed_count;

        let host = normalize_host(&state.info.metadata.host);
        if let Some(entry) = self.closed_hosts.get_mut(&host) {
            insert_host_or_accumulate(
                entry,
                upload,
                download,
                last_seen,
                seq,
                &state.info.chains,
                &state.info.rule,
            );
        } else if self.closed_hosts.len() < self.limits.max_hosts {
            self.closed_hosts.insert(
                host.clone(),
                ClosedHost {
                    host,
                    upload,
                    download,
                    connections: 1,
                    chains: state.info.chains.clone(),
                    rule: state.info.rule.clone(),
                    last_seen,
                    last_seq: seq,
                },
            );
        } else if self.limits.max_candidates == 0 {
            if total == 0 {
                self.other_connections = self.other_connections.saturating_add(1);
            } else {
                let min_key = self
                    .closed_hosts
                    .iter()
                    .min_by_key(|(_, entry)| {
                        (entry.upload.saturating_add(entry.download), entry.last_seq)
                    })
                    .map(|(k, entry)| (k.clone(), entry.upload.saturating_add(entry.download)));
                if let Some((evict_key, min_total)) = min_key
                    && total > min_total
                    && let Some(evicted) = self.closed_hosts.remove(&evict_key)
                {
                    self.other_upload = self.other_upload.saturating_add(evicted.upload);
                    self.other_download = self.other_download.saturating_add(evicted.download);
                    self.other_connections =
                        self.other_connections.saturating_add(evicted.connections);
                    if evicted.upload.saturating_add(evicted.download) > 0 {
                        self.hosts_evicted = true;
                    }
                    self.closed_hosts.insert(
                        host.clone(),
                        ClosedHost {
                            host,
                            upload,
                            download,
                            connections: 1,
                            chains: state.info.chains.clone(),
                            rule: state.info.rule.clone(),
                            last_seen,
                            last_seq: seq,
                        },
                    );
                } else {
                    self.other_upload = self.other_upload.saturating_add(upload);
                    self.other_download = self.other_download.saturating_add(download);
                    self.other_connections = self.other_connections.saturating_add(1);
                    self.hosts_evicted = true;
                }
            }
        } else {
            let cand_total = if let Some(entry) = self.candidate_hosts.get_mut(&host) {
                insert_host_or_accumulate(
                    entry,
                    upload,
                    download,
                    last_seen,
                    seq,
                    &state.info.chains,
                    &state.info.rule,
                );
                Some(entry.upload.saturating_add(entry.download))
            } else if total == 0 && self.candidate_hosts.len() >= self.limits.max_candidates {
                self.other_connections = self.other_connections.saturating_add(1);
                None
            } else {
                if self.candidate_hosts.len() >= self.limits.max_candidates
                    && let Some(evict_key) = self
                        .candidate_hosts
                        .iter()
                        .min_by_key(|(_, entry)| {
                            (entry.last_seq, entry.upload.saturating_add(entry.download))
                        })
                        .map(|(k, _)| k.clone())
                    && let Some(evicted) = self.candidate_hosts.remove(&evict_key)
                {
                    self.other_upload = self.other_upload.saturating_add(evicted.upload);
                    self.other_download = self.other_download.saturating_add(evicted.download);
                    self.other_connections =
                        self.other_connections.saturating_add(evicted.connections);
                    if evicted.upload.saturating_add(evicted.download) > 0 {
                        self.hosts_evicted = true;
                    }
                }
                self.candidate_hosts.insert(
                    host.clone(),
                    ClosedHost {
                        host: host.clone(),
                        upload,
                        download,
                        connections: 1,
                        chains: state.info.chains.clone(),
                        rule: state.info.rule.clone(),
                        last_seen,
                        last_seq: seq,
                    },
                );
                Some(total)
            };

            if let Some(cand_total) = cand_total {
                let min_closed = self
                    .closed_hosts
                    .iter()
                    .min_by_key(|(_, entry)| {
                        (entry.upload.saturating_add(entry.download), entry.last_seq)
                    })
                    .map(|(k, entry)| (k.clone(), entry.upload.saturating_add(entry.download)));
                if let Some((demote_key, min_closed_total)) = min_closed
                    && cand_total > min_closed_total
                    && let Some(promoted) = self.candidate_hosts.remove(&host)
                    && let Some(demoted) = self.closed_hosts.remove(&demote_key)
                {
                    self.closed_hosts.insert(host, promoted);
                    self.candidate_hosts.insert(demote_key, demoted);
                }
            }
        }

        if total > 0 && self.limits.max_closed > 0 {
            let slot = if self.closed_connections.len() < self.limits.max_closed {
                Some(None)
            } else {
                self.closed_connections
                    .iter()
                    .enumerate()
                    .map(|(idx, c)| (idx, (c.upload.saturating_add(c.download), c.start)))
                    .min_by_key(|(_, key)| *key)
                    .filter(|(_, min_key)| (total, state.started_unix) > *min_key)
                    .map(|(min_idx, _)| Some(min_idx))
            };
            if let Some(replace_idx) = slot {
                let record = ConnectionTraffic {
                    id: state.info.id.clone(),
                    host: state.info.metadata.host.clone(),
                    port: state.info.metadata.port,
                    network: state.info.network.clone(),
                    chains: state.info.chains.clone(),
                    rule: state.info.rule.clone(),
                    source: state.info.source.clone(),
                    upload,
                    download,
                    start: state.started_unix,
                    duration,
                    active: false,
                };
                match replace_idx {
                    None => self.closed_connections.push(record),
                    Some(min_idx) => self.closed_connections[min_idx] = record,
                }
            }
        }
    }

    pub(crate) fn active_snapshots(&self) -> Vec<Connection> {
        self.active.values().map(|s| s.snapshot()).collect()
    }

    pub(crate) fn active_count(&self) -> usize {
        self.active.len()
    }

    pub(crate) fn active_cancel(&self, id: &str) -> Option<tokio_util::sync::CancellationToken> {
        self.active.get(id).map(|s| s.info.cancel.clone())
    }

    /// Cancels every active connection in place, without cloning
    /// [`Connection`] snapshots. Returns how many were signalled.
    pub fn cancel_all(&self) -> usize {
        for state in self.active.values() {
            state.info.cancel.cancel();
        }
        self.active.len()
    }

    /// Counts open connections per proxy chain name, without cloning
    /// [`Connection`] snapshots.
    pub fn active_chain_counts(&self) -> HashMap<String, usize> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for state in self.active.values() {
            for chain in &state.info.chains {
                if let Some(count) = counts.get_mut(chain.as_str()) {
                    *count += 1;
                } else {
                    counts.insert(chain.clone(), 1);
                }
            }
        }
        counts
    }

    /// Drops retained closed-connection history and returns spare capacity
    /// to the allocator under memory pressure. Aggregate byte totals are
    /// folded into `other_*` so session totals stay reconciled.
    pub fn relieve_memory(&mut self) {
        for (_, entry) in self
            .closed_hosts
            .drain()
            .chain(self.candidate_hosts.drain())
        {
            self.other_upload = self.other_upload.saturating_add(entry.upload);
            self.other_download = self.other_download.saturating_add(entry.download);
            self.other_connections = self.other_connections.saturating_add(entry.connections);
            if entry.upload.saturating_add(entry.download) > 0 {
                self.hosts_evicted = true;
            }
        }
        self.closed_hosts.shrink_to_fit();
        self.candidate_hosts.shrink_to_fit();
        self.closed_connections = Vec::new();
        self.active.shrink_to_fit();
    }

    pub(crate) fn details(&self, host_filter: Option<&str>) -> TrafficDetails {
        let connection_host = host_filter
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(normalize_host);

        let mut active_upload: u64 = 0;
        let mut active_download: u64 = 0;
        let mut active_conns = Vec::new();

        let mut merged_hosts: HashMap<String, HostTraffic> = self
            .closed_hosts
            .iter()
            .chain(self.candidate_hosts.iter())
            .map(|(key, entry)| {
                (
                    key.clone(),
                    HostTraffic {
                        host: entry.host.clone(),
                        upload: entry.upload,
                        download: entry.download,
                        active_connections: 0,
                        total_connections: entry.connections,
                        chains: entry.chains.clone(),
                        rule: entry.rule.clone(),
                        last_seen: entry.last_seen,
                    },
                )
            })
            .collect();

        for state in self.active.values() {
            let info = state.snapshot();
            let active_ms = state.active.load(Ordering::Relaxed);
            let duration = state.lifetime().as_millis() as u64;
            let snap_last_seen = state.started_unix.saturating_add(active_ms / 1000);

            active_upload = active_upload.saturating_add(info.upload);
            active_download = active_download.saturating_add(info.download);

            let key = normalize_host(&info.metadata.host);
            let matches_filter = connection_host
                .as_deref()
                .is_none_or(|target| target == key);

            match merged_hosts.get_mut(&key) {
                Some(entry) => {
                    entry.upload = entry.upload.saturating_add(info.upload);
                    entry.download = entry.download.saturating_add(info.download);
                    let had_active = entry.active_connections > 0;
                    entry.active_connections += 1;
                    entry.total_connections = entry.total_connections.saturating_add(1);
                    if !had_active || snap_last_seen >= entry.last_seen {
                        entry.chains = info.chains.clone();
                        entry.rule = info.rule.clone();
                    }
                    entry.last_seen = entry.last_seen.max(snap_last_seen);
                }
                None => {
                    merged_hosts.insert(
                        key.clone(),
                        HostTraffic {
                            host: key,
                            upload: info.upload,
                            download: info.download,
                            active_connections: 1,
                            total_connections: 1,
                            chains: info.chains.clone(),
                            rule: info.rule.clone(),
                            last_seen: snap_last_seen,
                        },
                    );
                }
            }

            if matches_filter {
                active_conns.push(ConnectionTraffic {
                    id: info.id,
                    host: info.metadata.host,
                    port: info.metadata.port,
                    network: info.network,
                    chains: info.chains,
                    rule: info.rule,
                    source: info.source,
                    upload: info.upload,
                    download: info.download,
                    start: state.started_unix,
                    duration,
                    active: true,
                });
            }
        }

        let upload_total = self.closed_upload.saturating_add(active_upload);
        let download_total = self.closed_download.saturating_add(active_download);
        let active_connections = self.active.len();
        let total_connections = self.closed_count.saturating_add(active_connections as u64);

        let mut other_upload = self.other_upload;
        let mut other_download = self.other_download;
        let mut other_connections = self.other_connections;

        let mut hosts = Vec::with_capacity(merged_hosts.len());
        for (_, entry) in merged_hosts {
            if entry.upload.saturating_add(entry.download) > 0 || entry.active_connections > 0 {
                hosts.push(entry);
            } else {
                other_connections = other_connections.saturating_add(entry.total_connections);
            }
        }

        let total_hosts = hosts.len();
        hosts.sort_by(|a, b| {
            b.upload
                .saturating_add(b.download)
                .cmp(&a.upload.saturating_add(a.download))
                .then_with(|| b.active_connections.cmp(&a.active_connections))
                .then_with(|| b.last_seen.cmp(&a.last_seen))
                .then_with(|| a.host.cmp(&b.host))
        });

        if hosts.len() > self.limits.snapshot_hosts {
            for overflow in hosts.drain(self.limits.snapshot_hosts..) {
                other_upload = other_upload.saturating_add(overflow.upload);
                other_download = other_download.saturating_add(overflow.download);
                other_connections = other_connections.saturating_add(overflow.total_connections);
            }
        }

        let matching_active_connections = active_conns.len();
        active_conns.sort_by(|a, b| {
            b.upload
                .saturating_add(b.download)
                .cmp(&a.upload.saturating_add(a.download))
                .then_with(|| b.start.cmp(&a.start))
                .then_with(|| a.id.cmp(&b.id))
        });
        active_conns.truncate(self.limits.snapshot_active);

        let mut closed_conns: Vec<ConnectionTraffic> = self
            .closed_connections
            .iter()
            .filter(|c| {
                connection_host
                    .as_deref()
                    .is_none_or(|target| normalize_host(&c.host) == target)
            })
            .cloned()
            .collect();
        let retained_closed_connections = closed_conns.len();
        let matching_closed_connections = match connection_host.as_deref() {
            Some(target) => self
                .closed_hosts
                .get(target)
                .or_else(|| self.candidate_hosts.get(target))
                .map_or(0, |h| h.connections)
                .max(retained_closed_connections as u64),
            None => self.closed_count,
        };
        closed_conns.sort_by(|a, b| {
            b.upload
                .saturating_add(b.download)
                .cmp(&a.upload.saturating_add(a.download))
                .then_with(|| b.start.cmp(&a.start))
                .then_with(|| a.id.cmp(&b.id))
        });
        closed_conns.truncate(self.limits.snapshot_closed);

        let mut connections = Vec::with_capacity(active_conns.len() + closed_conns.len());
        connections.extend(active_conns);
        connections.extend(closed_conns);
        connections.sort_by(|a, b| {
            b.upload
                .saturating_add(b.download)
                .cmp(&a.upload.saturating_add(a.download))
                .then_with(|| b.active.cmp(&a.active))
                .then_with(|| b.start.cmp(&a.start))
                .then_with(|| a.id.cmp(&b.id))
        });

        TrafficDetails {
            since: self.since,
            upload_total,
            download_total,
            active_connections,
            total_connections,
            total_hosts,
            hosts_evicted: self.hosts_evicted,
            connection_host,
            matching_active_connections,
            matching_closed_connections,
            retained_closed_connections,
            closed_connection_cap: self.limits.max_closed,
            hosts,
            other_upload,
            other_download,
            other_connections,
            connections,
        }
    }
}

pub(crate) struct State {
    info: Connection,
    upload: AtomicU64,
    download: AtomicU64,
    started_unix: u64,
    created: Instant,
    /// Milliseconds after `created` when bytes last moved either way.
    active: AtomicU64,
    /// One side of a TCP relay reached EOF; `ended` wakes [`idle_expired`].
    half_closed: AtomicBool,
    ended: Notify,
    /// Why the relay ended, for the request log.
    reason: Mutex<Option<String>>,
    /// HTTP requests recorded on this connection after decryption.
    pub(crate) exchanges: AtomicU32,
    /// Where the connection is recorded once it ends: when the last holder
    /// lets go, after the relay noted why it ended.
    log: Arc<crate::requests::Requests>,
}
impl Drop for State {
    fn drop(&mut self) {
        let log = self.log.clone();
        log.finished(self);
    }
}
impl State {
    /// Time since the connection was tracked.
    pub(crate) fn lifetime(&self) -> Duration {
        self.created.elapsed()
    }
    /// How long no bytes moved either way.
    fn quiet(&self) -> Duration {
        self.created
            .elapsed()
            .saturating_sub(Duration::from_millis(self.active.load(Ordering::Relaxed)))
    }
    fn mark_eof(&self) {
        if !self.half_closed.swap(true, Ordering::Relaxed) {
            self.ended.notify_one();
        }
    }
    pub(crate) fn set_reason(&self, reason: &str) {
        *self.reason.lock().unwrap() = Some(reason.to_owned());
    }
    pub(crate) fn reason(&self) -> Option<String> {
        self.reason.lock().unwrap().clone()
    }
    pub(crate) fn snapshot(&self) -> Connection {
        let mut info = self.info.clone();
        info.upload = self.upload.load(Ordering::Relaxed);
        info.download = self.download.load(Ordering::Relaxed);
        info
    }
}
pub(crate) struct Tracker {
    core: Arc<Core>,
    pub(crate) state: Arc<State>,
}
impl Tracker {
    pub(crate) fn new(
        core: Arc<Core>,
        target: Target,
        routed: crate::Routed,
        network: &str,
    ) -> Result<Self> {
        ensure!(!core.stop.is_cancelled(), "core stopped");
        let started_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let info = Connection {
            id: uuid::Uuid::new_v4().to_string(),
            metadata: target,
            network: network.into(),
            chains: vec![routed.node],
            rule: routed.rule,
            source: routed.source,
            upload: 0,
            download: 0,
            start: started_unix.to_string(),
            cancel: core.stop.child_token(),
        };
        let state = Arc::new(State {
            info,
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            started_unix,
            created: Instant::now(),
            active: AtomicU64::new(0),
            half_closed: AtomicBool::new(false),
            ended: Notify::new(),
            reason: Mutex::new(None),
            exchanges: AtomicU32::new(0),
            log: core.requests.clone(),
        });
        core.traffic.lock().unwrap().insert_active(state.clone())?;
        Ok(Self { core, state })
    }
    pub(crate) fn cancel(&self) -> tokio_util::sync::CancellationToken {
        self.state.info.cancel.clone()
    }
    fn record(&self, upload: bool, n: usize) {
        if n == 0 {
            return;
        }
        let (local, total) = if upload {
            (&self.state.upload, &self.core.upload)
        } else {
            (&self.state.download, &self.core.download)
        };
        local.fetch_add(n as u64, Ordering::Relaxed);
        total.fetch_add(n as u64, Ordering::Relaxed);
        self.state.active.store(
            self.state.created.elapsed().as_millis() as u64,
            Ordering::Relaxed,
        );
    }
}
impl Drop for Tracker {
    fn drop(&mut self) {
        self.core
            .traffic
            .lock()
            .unwrap()
            .remove_and_record(&self.state);
    }
}
pub(crate) struct Stream<S> {
    pub(crate) inner: S,
    pub(crate) tracker: Tracker,
}
impl<S: AsyncRead + Unpin> AsyncRead for Stream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let room = buf.remaining() > 0;
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        this.tracker.record(false, n);
        if room && n == 0 && matches!(result, Poll::Ready(Ok(()))) {
            this.tracker.state.mark_eof();
        }
        result
    }
}

/// The local side of a TCP relay: reports its EOF to the connection's
/// [`State`] so a half-closed relay can be timed out.
pub(crate) struct EofWatch<S> {
    pub(crate) inner: S,
    pub(crate) state: Arc<State>,
}
impl<S: AsyncRead + Unpin> AsyncRead for EofWatch<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let room = buf.remaining() > 0;
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if room && buf.filled().len() == before && matches!(result, Poll::Ready(Ok(()))) {
            this.state.mark_eof();
        }
        result
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for EofWatch<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Idle limits for a TCP relay: no bytes either way for `idle`, or for
/// `half_closed` once one side reached EOF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RelayLimits {
    pub(crate) idle: Duration,
    pub(crate) half_closed: Duration,
}

/// Resolves with the limit that ran out. Sleeps until the earliest moment it
/// could, so a quiet relay costs one timer, not a periodic wakeup.
pub(crate) async fn idle_expired(state: &State, limits: RelayLimits) -> &'static str {
    loop {
        let (limit, reason) = if state.half_closed.load(Ordering::Relaxed) {
            (limits.half_closed, "half-closed")
        } else {
            (limits.idle, "idle")
        };
        let quiet = state.quiet();
        if quiet >= limit {
            return reason;
        }
        tokio::select! {
            _ = tokio::time::sleep(limit - quiet) => {}
            _ = state.ended.notified() => {}
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Stream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(n)) = result {
            this.tracker.record(true, n);
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub(crate) struct PacketSession {
    pub(crate) inner: Arc<dyn Datagram>,
    pub(crate) tracker: Tracker,
}
#[async_trait]
impl Datagram for PacketSession {
    async fn send(&self, target: &Target, bytes: &[u8]) -> Result<()> {
        tokio::select! {
            biased;
            _=self.tracker.state.info.cancel.cancelled()=>anyhow::bail!("UDP connection closed"),
            result=tokio::time::timeout(Duration::from_secs(20),self.inner.send(target,bytes))=>result??,
        }
        self.tracker.record(true, bytes.len());
        Ok(())
    }
    async fn recv(&self) -> Result<(Target, Vec<u8>)> {
        let packet = tokio::select! {
            biased;
            _=self.tracker.state.info.cancel.cancelled()=>anyhow::bail!("UDP connection closed"),
            result=tokio::time::timeout(Duration::from_secs(120),self.inner.recv())=>result??,
        };
        self.tracker.record(false, packet.1.len());
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state(
        log: Arc<crate::requests::Requests>,
        id: &str,
        host: &str,
        port: u16,
        chain: &str,
        rule: &str,
        started_unix: u64,
        upload: u64,
        download: u64,
    ) -> Arc<State> {
        Arc::new(State {
            info: Connection {
                id: id.into(),
                metadata: Target::new(host, port).unwrap(),
                network: "tcp".into(),
                chains: vec![chain.into()],
                rule: rule.into(),
                source: "127.0.0.1".into(),
                upload: 0,
                download: 0,
                start: started_unix.to_string(),
                cancel: tokio_util::sync::CancellationToken::new(),
            },
            upload: AtomicU64::new(upload),
            download: AtomicU64::new(download),
            started_unix,
            created: Instant::now(),
            active: AtomicU64::new(0),
            half_closed: AtomicBool::new(false),
            ended: Notify::new(),
            reason: Mutex::new(None),
            exchanges: AtomicU32::new(0),
            log,
        })
    }

    fn assert_reconciled(details: &TrafficDetails) {
        let host_upload: u64 = details.hosts.iter().map(|h| h.upload).sum();
        let host_download: u64 = details.hosts.iter().map(|h| h.download).sum();
        let host_conns: u64 = details.hosts.iter().map(|h| h.total_connections).sum();
        assert_eq!(host_upload + details.other_upload, details.upload_total);
        assert_eq!(
            host_download + details.other_download,
            details.download_total
        );
        assert_eq!(
            host_conns + details.other_connections,
            details.total_connections
        );
    }

    #[test]
    fn ledger_merges_active_and_closed_hosts_with_normalization() {
        let log = Arc::new(crate::requests::Requests::new(false));
        let mut ledger = Ledger::new(false);

        let closed = make_state(
            log.clone(),
            "c1",
            "GitHub.com.",
            443,
            "ProxyA",
            "DomainSuffix(github.com)",
            100,
            200,
            800,
        );
        ledger.insert_active(closed.clone()).unwrap();
        ledger.remove_and_record(&closed);
        // Removing twice is idempotent and does not double-count.
        ledger.remove_and_record(&closed);

        let active = make_state(
            log,
            "c2",
            "github.com",
            443,
            "ProxyB",
            "Match",
            200,
            50,
            400,
        );
        ledger.insert_active(active).unwrap();

        let details = ledger.details(None);
        assert_eq!(details.upload_total, 250);
        assert_eq!(details.download_total, 1200);
        assert_eq!(details.active_connections, 1);
        assert_eq!(details.total_connections, 2);
        assert_eq!(details.total_hosts, 1);
        assert!(!details.hosts_evicted);
        assert_eq!(details.connection_host, None);
        assert_eq!(details.matching_active_connections, 1);
        assert_eq!(details.matching_closed_connections, 1);
        assert_eq!(details.retained_closed_connections, 1);
        assert_reconciled(&details);

        let host = &details.hosts[0];
        assert_eq!(host.host, "github.com");
        assert_eq!(host.upload, 250);
        assert_eq!(host.download, 1200);
        assert_eq!(host.active_connections, 1);
        assert_eq!(host.total_connections, 2);
        assert_eq!(host.chains, vec!["ProxyB"]);
        assert_eq!(host.rule, "Match");

        assert_eq!(details.connections.len(), 2);
        assert_eq!(details.connections[0].id, "c1");
        assert!(!details.connections[0].active);
        assert_eq!(details.connections[1].id, "c2");
        assert!(details.connections[1].active);
    }

    #[test]
    fn ledger_evicts_and_truncates_with_exact_byte_reconciliation() {
        let log = Arc::new(crate::requests::Requests::new(false));
        let mut ledger = Ledger::with_limits(LedgerLimits {
            max_hosts: 3,
            max_candidates: 0,
            max_closed: 2,
            snapshot_hosts: 2,
            snapshot_active: 10,
            snapshot_closed: 2,
        });

        // Three closed hosts fill max_hosts=3.
        for (idx, (host, up, down)) in [
            ("small.test", 10u64, 20u64),
            ("medium.test", 50, 150),
            ("large.test", 300, 700),
        ]
        .into_iter()
        .enumerate()
        {
            let s = make_state(
                log.clone(),
                &format!("c{idx}"),
                host,
                443,
                "DIRECT",
                "Match",
                100 + idx as u64,
                up,
                down,
            );
            ledger.insert_active(s.clone()).unwrap();
            ledger.remove_and_record(&s);
        }

        // Larger closed host evicts `small.test` into other_*.
        let huge = make_state(
            log.clone(),
            "c3",
            "huge.test",
            443,
            "DIRECT",
            "Match",
            110,
            500,
            1500,
        );
        ledger.insert_active(huge.clone()).unwrap();
        ledger.remove_and_record(&huge);

        // Smaller closed host than remaining minimum (medium=200) goes straight to other_*.
        let tiny = make_state(
            log.clone(),
            "c4",
            "tiny.test",
            443,
            "DIRECT",
            "Match",
            111,
            5,
            5,
        );
        ledger.insert_active(tiny.clone()).unwrap();
        ledger.remove_and_record(&tiny);

        // Zero-byte closed connection folds into other_connections cleanly.
        let zero = make_state(
            log.clone(),
            "c5",
            "zero.test",
            80,
            "DIRECT",
            "Match",
            112,
            0,
            0,
        );
        ledger.insert_active(zero.clone()).unwrap();
        ledger.remove_and_record(&zero);

        let details = ledger.details(None);
        assert_reconciled(&details);
        assert!(details.hosts_evicted);
        assert_eq!(details.total_hosts, 3); // large, huge, medium (zero folded into other_connections)
        assert_eq!(details.hosts.len(), 2); // truncated by snapshot_hosts=2
        assert_eq!(details.hosts[0].host, "huge.test");
        assert_eq!(details.hosts[1].host, "large.test");
        // other = small(10+20) + tiny(5+5) + truncated medium(50+150) + zero(0+0)
        assert_eq!(details.other_upload, 65);
        assert_eq!(details.other_download, 175);
        assert_eq!(details.other_connections, 4);
        assert_eq!(details.upload_total, 865);
        assert_eq!(details.download_total, 2375);

        // closed_connections retains the top 2 by traffic (huge=2000, large=1000).
        assert_eq!(details.connections.len(), 2);
        assert_eq!(details.connections[0].id, "c3");
        assert_eq!(details.connections[1].id, "c2");
    }

    #[test]
    fn ledger_host_drilldown_filters_before_truncating() {
        let log = Arc::new(crate::requests::Requests::new(false));
        let mut ledger = Ledger::with_limits(LedgerLimits {
            max_hosts: 32,
            max_candidates: 16,
            max_closed: 32,
            snapshot_hosts: 20,
            snapshot_active: 5,
            snapshot_closed: 3,
        });

        for i in 0..20 {
            let s = make_state(
                log.clone(),
                &format!("big-{i}"),
                "big.test",
                443,
                "ProxyA",
                "Match",
                1000 + i,
                1000,
                9000,
            );
            ledger.insert_active(s).unwrap();
        }
        for i in 0..15 {
            let s = make_state(
                log.clone(),
                &format!("chat-active-{i}"),
                "chat.test",
                443,
                "ProxyA",
                "Match",
                2000 + i,
                10 + i,
                90,
            );
            ledger.insert_active(s).unwrap();
        }
        for i in 0..10 {
            let s = make_state(
                log.clone(),
                &format!("chat-closed-{i}"),
                "Chat.Test.",
                443,
                "ProxyA",
                "Match",
                500 + i,
                5 + i,
                20,
            );
            ledger.insert_active(s.clone()).unwrap();
            ledger.remove_and_record(&s);
        }

        let global = ledger.details(None);
        assert_eq!(global.connection_host, None);
        assert_eq!(global.matching_active_connections, 35);
        assert_eq!(global.matching_closed_connections, 10);
        assert_eq!(global.retained_closed_connections, 10);
        // Top 5 global active connections are all big.test; zero chat.test active in global slice.
        assert_eq!(
            global
                .connections
                .iter()
                .filter(|c| c.active && c.host == "chat.test")
                .count(),
            0
        );

        let drill = ledger.details(Some("Chat.Test."));
        assert_eq!(drill.connection_host.as_deref(), Some("chat.test"));
        assert_eq!(drill.matching_active_connections, 15);
        assert_eq!(drill.matching_closed_connections, 10);
        assert_eq!(drill.retained_closed_connections, 10);
        assert_eq!(drill.connections.iter().filter(|c| c.active).count(), 5);
        assert_eq!(drill.connections.iter().filter(|c| !c.active).count(), 3);
        assert!(
            drill
                .connections
                .iter()
                .all(|c| normalize_host(&c.host) == "chat.test")
        );
    }

    #[test]
    fn ledger_candidate_tier_promotes_accumulated_multi_connection_host() {
        let log = Arc::new(crate::requests::Requests::new(false));
        let mut ledger = Ledger::with_limits(LedgerLimits {
            max_hosts: 2,
            max_candidates: 2,
            max_closed: 50,
            snapshot_hosts: 10,
            snapshot_active: 10,
            snapshot_closed: 10,
        });

        for (id, host, bytes) in [("a", "a.test", 500u64), ("b", "b.test", 400u64)] {
            let s = make_state(log.clone(), id, host, 443, "DIRECT", "Match", 100, 0, bytes);
            ledger.insert_active(s.clone()).unwrap();
            ledger.remove_and_record(&s);
        }

        // 10 x 100B connections to burst.test (each individually < 400B threshold).
        for i in 0..10 {
            let s = make_state(
                log.clone(),
                &format!("burst-{i}"),
                "burst.test",
                443,
                "DIRECT",
                "Match",
                200 + i,
                0,
                100,
            );
            ledger.insert_active(s.clone()).unwrap();
            ledger.remove_and_record(&s);
        }

        let mid = ledger.details(None);
        assert!(!mid.hosts_evicted);
        assert_reconciled(&mid);
        assert_eq!(mid.hosts[0].host, "burst.test");
        assert_eq!(mid.hosts[0].download, 1000);
        assert!(
            mid.hosts
                .iter()
                .any(|h| h.host == "b.test" && h.download == 400)
        );

        // Add 2 more candidate hosts so LRU candidate eviction actually occurs.
        for (id, host, bytes) in [("x", "x.test", 50u64), ("y", "y.test", 60u64)] {
            let s = make_state(log.clone(), id, host, 443, "DIRECT", "Match", 300, 0, bytes);
            ledger.insert_active(s.clone()).unwrap();
            ledger.remove_and_record(&s);
        }

        let after = ledger.details(None);
        assert!(after.hosts_evicted);
        assert_reconciled(&after);
        assert_eq!(after.hosts[0].host, "burst.test");
        assert_eq!(after.hosts[0].download, 1000);
    }

    #[test]
    fn traffic_details_capped_json_shrinks_within_budget_and_reconciles() {
        let log = Arc::new(crate::requests::Requests::new(false));
        let mut ledger = Ledger::new(false);
        for i in 0..40 {
            let s = make_state(
                log.clone(),
                &format!("conn-{i}"),
                &format!("host-{i:02}.example.test"),
                443,
                "ProxyLongChain",
                "DomainSuffix(example.test)",
                1000 + i,
                100 + i,
                1000 + i * 10,
            );
            ledger.insert_active(s).unwrap();
        }
        let full = ledger.details(None);
        let bytes = full.to_capped_json_vec(800).unwrap();
        assert!(
            bytes.len() <= 800,
            "encoded length {} exceeded 800",
            bytes.len()
        );
        let decoded: TrafficDetails = serde_json::from_slice(&bytes).unwrap();
        assert_reconciled(&decoded);
    }

    #[test]
    fn traffic_details_drilldown_cap_trims_hosts_and_closed_before_active() {
        let log = Arc::new(crate::requests::Requests::new(false));
        let mut ledger = Ledger::new(false);

        for i in 0..50 {
            let s = make_state(
                log.clone(),
                &format!("other-{i}"),
                &format!("other-{i:02}.example.test"),
                443,
                "ProxyLongChain",
                "DomainSuffix(example.test)",
                1000 + i,
                100 + i,
                500 + i,
            );
            ledger.insert_active(s.clone()).unwrap();
            ledger.remove_and_record(&s);
        }

        for i in 0..12 {
            let s = make_state(
                log.clone(),
                &format!("chat-closed-{i}"),
                "chat.test",
                443,
                "ProxyA",
                "Match",
                1100 + i,
                1000,
                5000,
            );
            ledger.insert_active(s.clone()).unwrap();
            ledger.remove_and_record(&s);
        }

        for i in 0..4 {
            let s = make_state(
                log.clone(),
                &format!("chat-active-{i}"),
                "chat.test",
                443,
                "ProxyA",
                "Match",
                1200 + i,
                5,
                5,
            );
            ledger.insert_active(s).unwrap();
        }

        let drill = ledger.details(Some("chat.test"));
        assert_eq!(drill.connections.len(), 16);

        // Construct exact budget boundaries from serialized variants:
        // Case A fits all 16 chat.test connections once hosts are trimmed down.
        let mut hosts_halved = drill.clone();
        assert!(hosts_halved.trim_hosts_half());
        let cap_keep_all_conns = serde_json::to_vec(&hosts_halved).unwrap().len();

        let bytes_a = drill.to_capped_json_vec(cap_keep_all_conns).unwrap();
        assert!(bytes_a.len() <= cap_keep_all_conns);
        let decoded_a: TrafficDetails = serde_json::from_slice(&bytes_a).unwrap();
        assert_reconciled(&decoded_a);
        assert!(decoded_a.hosts.len() < drill.hosts.len());
        assert_eq!(decoded_a.connections.len(), 16);
        assert_eq!(decoded_a.connections.iter().filter(|c| c.active).count(), 4);

        // Case B forces connection trimming after hosts are empty; all 4 small active connections must survive.
        let mut active_only_no_hosts = drill.clone();
        while active_only_no_hosts.trim_hosts_half() {}
        while active_only_no_hosts.connections.iter().any(|c| !c.active) {
            assert!(active_only_no_hosts.trim_connections_preserving_active());
        }
        let min_active_bytes = serde_json::to_vec(&active_only_no_hosts).unwrap().len();
        let cap_keep_active_only = min_active_bytes + 120;

        let bytes_b = drill.to_capped_json_vec(cap_keep_active_only).unwrap();
        assert!(bytes_b.len() <= cap_keep_active_only);
        let decoded_b: TrafficDetails = serde_json::from_slice(&bytes_b).unwrap();
        assert_reconciled(&decoded_b);
        assert!(decoded_b.hosts.is_empty());
        assert_eq!(decoded_b.connections.iter().filter(|c| c.active).count(), 4);
        assert!(
            decoded_b.connections.iter().filter(|c| !c.active).count() < 12,
            "expected closed connections to be trimmed before active"
        );
    }

    #[test]
    fn ledger_cancel_all_and_active_chain_counts() {
        let log = Arc::new(crate::requests::Requests::new(false));
        let mut ledger = Ledger::new(false);
        let a = make_state(
            log.clone(),
            "a",
            "a.test",
            443,
            "ProxyA",
            "Match",
            1,
            10,
            20,
        );
        let b = make_state(
            log.clone(),
            "b",
            "b.test",
            443,
            "ProxyA",
            "Match",
            2,
            30,
            40,
        );
        let c = make_state(log, "c", "c.test", 443, "DIRECT", "Match", 3, 50, 60);
        ledger.insert_active(a.clone()).unwrap();
        ledger.insert_active(b.clone()).unwrap();
        ledger.insert_active(c.clone()).unwrap();

        let counts = ledger.active_chain_counts();
        assert_eq!(counts.get("ProxyA"), Some(&2));
        assert_eq!(counts.get("DIRECT"), Some(&1));

        assert_eq!(ledger.cancel_all(), 3);
        assert!(a.info.cancel.is_cancelled());
        assert!(b.info.cancel.is_cancelled());
        assert!(c.info.cancel.is_cancelled());
    }

    #[test]
    fn ledger_relieve_memory_reconciles_totals() {
        let log = Arc::new(crate::requests::Requests::new(false));
        let mut ledger = Ledger::with_limits(LedgerLimits {
            max_hosts: 2,
            max_candidates: 2,
            max_closed: 2,
            snapshot_hosts: 10,
            snapshot_active: 10,
            snapshot_closed: 10,
        });
        for i in 0..4 {
            let s = make_state(
                log.clone(),
                &format!("closed-{i}"),
                &format!("host-{i}.test"),
                443,
                "Proxy",
                "Match",
                100 + i,
                100,
                200,
            );
            ledger.insert_active(s.clone()).unwrap();
            ledger.remove_and_record(&s);
        }
        let active = make_state(log, "live", "live.test", 443, "Proxy", "Match", 200, 50, 75);
        ledger.insert_active(active).unwrap();

        let before = ledger.details(None);
        ledger.relieve_memory();
        let after = ledger.details(None);

        assert_eq!(after.upload_total, before.upload_total);
        assert_eq!(after.download_total, before.download_total);
        assert_eq!(after.total_connections, before.total_connections);
        assert_eq!(after.active_connections, 1);
        assert_eq!(after.retained_closed_connections, 0);
        assert_reconciled(&after);
    }
}
