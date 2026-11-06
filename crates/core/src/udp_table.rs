//! UDP bookkeeping for the TUN loop: sessions (one per source and target),
//! the target sockets they share, and why a new one is refused.
//!
//! Admission order for a datagram that has no session yet: the memory guard
//! (ordinary sessions only), then the session budget (a few sessions stay
//! reserved for hijacked DNS so data flows cannot starve name lookups). A
//! target socket is admitted when its first datagram arrives; with the
//! sockets all taken, one without sessions and idle for `REUSE_AFTER` is
//! reclaimed before the target is refused.
use super::Flow;
use smoltcp::{iface::SocketHandle, iface::SocketSet, wire::IpEndpoint};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{sync::mpsc, time::Instant};

/// Sessions only hijacked DNS may use once data flows fill the rest.
pub(super) const DNS_RESERVE: usize = 16;
/// Target sockets DNS may use beyond the budget (a resolver the data flows
/// never touched still answers).
pub(super) const DNS_PORT_RESERVE: usize = 4;
/// A target without sessions keeps its socket this long for replies still
/// in flight before another target may take the slot.
pub(super) const REUSE_AFTER: Duration = Duration::from_secs(2);
/// One ICMP error per refused flow and window: enough for the app to give up
/// or fall back, without answering every retransmission.
pub(super) const REFUSAL_NOTICE_EVERY: Duration = Duration::from_secs(1);

pub(super) struct UdpFlow {
    pub(super) input: mpsc::Sender<Vec<u8>>,
    pub(super) task: tokio::task::AbortHandle,
    /// Tells this session's completion and replies from a later session that
    /// reuses the same source and target.
    pub(super) generation: u64,
    dns: bool,
}

pub(super) struct UdpPort {
    pub(super) handle: SocketHandle,
    pub(super) last: Instant,
    sessions: usize,
    dns: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Refusal {
    /// The memory guard refuses new flows.
    Memory,
    /// Every session slot is in use.
    Sessions,
    /// Every target socket is in use by sessions or recent traffic.
    Ports,
}

/// Datagrams dropped or refused, by where, since the TUN started. Session
/// tasks hold a reference to count their own drops.
#[derive(Default, Debug)]
pub(super) struct Drops {
    pub(super) memory: AtomicU64,
    pub(super) sessions: AtomicU64,
    pub(super) ports: AtomicU64,
    /// A session's upload queue (16 datagrams) was full.
    pub(super) input_full: AtomicU64,
    /// The shared reply queue to the TUN loop was full.
    pub(super) reply_full: AtomicU64,
    /// smoltcp could not queue a reply on the target socket.
    pub(super) socket_full: AtomicU64,
    /// Hijacked DNS queries the resolver failed or did not answer in time.
    /// Logged as a periodic summary: one line per failure floods the log,
    /// none left resolver outages invisible at the info level.
    pub(super) dns_failed: AtomicU64,
    pub(super) dns_timed_out: AtomicU64,
    pub(super) last_dns_error: std::sync::Mutex<Option<String>>,
}
impl Drops {
    pub(super) fn dns_failure(&self, error: Option<&anyhow::Error>) {
        match error {
            Some(error) => {
                self.dns_failed.fetch_add(1, Ordering::Relaxed);
                *self.last_dns_error.lock().unwrap() = Some(format!("{error:#}"));
            }
            None => {
                self.dns_timed_out.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub(super) fn refused(&self, refusal: Refusal) {
        match refusal {
            Refusal::Memory => &self.memory,
            Refusal::Sessions => &self.sessions,
            Refusal::Ports => &self.ports,
        }
        .fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn snapshot(&self) -> [u64; 8] {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        [
            load(&self.memory),
            load(&self.sessions),
            load(&self.ports),
            load(&self.input_full),
            load(&self.reply_full),
            load(&self.socket_full),
            clyntis_protocol::drops::XUDP_INBOX_FULL.load(Ordering::Relaxed),
            clyntis_protocol::drops::HYSTERIA2_INBOX_FULL.load(Ordering::Relaxed),
        ]
    }
}

pub(super) struct UdpTable {
    pub(super) flows: HashMap<Flow, UdpFlow>,
    pub(super) ports: HashMap<IpEndpoint, UdpPort>,
    max_sessions: usize,
    max_ports: usize,
    dns_sessions: usize,
    next_generation: u64,
    noticed: HashMap<Flow, Instant>,
}

impl UdpTable {
    pub(super) fn new(max_sessions: usize, max_ports: usize) -> Self {
        Self {
            flows: HashMap::new(),
            ports: HashMap::new(),
            max_sessions,
            max_ports,
            dns_sessions: 0,
            next_generation: 0,
            noticed: HashMap::new(),
        }
    }

    /// A socket for `target`, made by `socket` when it has none. With every
    /// socket in use, an idle one without sessions is reclaimed first.
    pub(super) fn admit_port(
        &mut self,
        target: IpEndpoint,
        dns: bool,
        shedding: bool,
        now: Instant,
        sockets: &mut SocketSet<'static>,
        socket: impl FnOnce() -> smoltcp::socket::udp::Socket<'static>,
    ) -> Result<(), Refusal> {
        if self.ports.contains_key(&target) {
            return Ok(());
        }
        if shedding && !dns {
            return Err(Refusal::Memory);
        }
        let limit = self.max_ports + if dns { DNS_PORT_RESERVE } else { 0 };
        if self.ports.len() >= limit && !self.reclaim_port(now, sockets) {
            return Err(Refusal::Ports);
        }
        self.ports.insert(
            target,
            UdpPort {
                handle: sockets.add(socket()),
                last: now,
                sessions: 0,
                dns,
            },
        );
        Ok(())
    }

    /// Frees the least recently used socket without sessions, idle for
    /// `REUSE_AFTER`; never one a live session or a DNS reserve slot uses.
    fn reclaim_port(&mut self, now: Instant, sockets: &mut SocketSet<'static>) -> bool {
        let candidate = self
            .ports
            .iter()
            .filter(|(_, port)| {
                port.sessions == 0 && !port.dns && now.duration_since(port.last) >= REUSE_AFTER
            })
            .min_by_key(|(_, port)| port.last)
            .map(|(endpoint, _)| *endpoint);
        let Some(endpoint) = candidate else {
            return false;
        };
        let port = self.ports.remove(&endpoint).unwrap();
        sockets.remove(port.handle);
        true
    }

    /// Whether `flow` may have a new session (`Ok(false)`: it has one).
    pub(super) fn admit_session(
        &self,
        flow: &Flow,
        dns: bool,
        shedding: bool,
    ) -> Result<bool, Refusal> {
        if self.flows.contains_key(flow) {
            return Ok(false);
        }
        // DNS keeps working under memory pressure: its sessions are small,
        // short (15 s idle) and every other flow needs names.
        if shedding && !dns {
            return Err(Refusal::Memory);
        }
        let used = self.flows.len();
        let limit = if dns {
            self.max_sessions
        } else {
            self.max_sessions.saturating_sub(DNS_RESERVE)
        };
        let counted = if dns { used } else { used - self.dns_sessions };
        if counted >= limit || used >= self.max_sessions {
            return Err(Refusal::Sessions);
        }
        Ok(true)
    }

    /// Records a new session; its target socket must exist.
    pub(super) fn insert(
        &mut self,
        flow: Flow,
        dns: bool,
        input: mpsc::Sender<Vec<u8>>,
        task: impl FnOnce(u64) -> tokio::task::AbortHandle,
    ) -> u64 {
        self.next_generation += 1;
        let generation = self.next_generation;
        if let Some(port) = self.ports.get_mut(&flow.target) {
            port.sessions += 1;
        }
        if dns {
            self.dns_sessions += 1;
        }
        self.flows.insert(
            flow,
            UdpFlow {
                input,
                task: task(generation),
                generation,
                dns,
            },
        );
        generation
    }

    /// A session task finished. A stale completion (the flow already has a
    /// newer session) changes nothing.
    pub(super) fn ended(&mut self, flow: &Flow, generation: u64) -> bool {
        if self
            .flows
            .get(flow)
            .is_none_or(|f| f.generation != generation)
        {
            return false;
        }
        self.remove(flow);
        true
    }

    fn remove(&mut self, flow: &Flow) -> Option<UdpFlow> {
        let state = self.flows.remove(flow)?;
        if state.dns {
            self.dns_sessions -= 1;
        }
        if let Some(port) = self.ports.get_mut(&flow.target) {
            port.sessions = port.sessions.saturating_sub(1);
            // Replies may still be in flight: the slot is reusable after
            // REUSE_AFTER from now, not from the session's last datagram.
            port.last = port.last.max(Instant::now());
        }
        Some(state)
    }

    /// Whether a reply from `generation` belongs to an older session than the
    /// flow's current one. Replies of a session that just ended, with nothing
    /// newer on its source and target, are still delivered.
    pub(super) fn superseded(&self, flow: &Flow, generation: u64) -> bool {
        self.flows
            .get(flow)
            .is_some_and(|f| f.generation != generation)
    }

    /// Whether a refused flow gets an ICMP error now (at most once a window).
    pub(super) fn notice(&mut self, flow: Flow, now: Instant) -> bool {
        match self.noticed.get(&flow) {
            Some(at) if now.duration_since(*at) < REFUSAL_NOTICE_EVERY => false,
            _ => {
                self.noticed.insert(flow, now);
                true
            }
        }
    }

    /// Drops sockets idle past `idle` with their sessions, and old notices.
    pub(super) fn expire(
        &mut self,
        idle: Duration,
        now: Instant,
        sockets: &mut SocketSet<'static>,
    ) {
        let stale: Vec<IpEndpoint> = self
            .ports
            .iter()
            .filter(|(_, port)| now.duration_since(port.last) > idle)
            .map(|(endpoint, _)| *endpoint)
            .collect();
        for endpoint in stale {
            let flows: Vec<Flow> = self
                .flows
                .keys()
                .filter(|flow| flow.target == endpoint)
                .copied()
                .collect();
            for flow in flows {
                if let Some(state) = self.remove(&flow) {
                    state.task.abort();
                }
            }
            if let Some(port) = self.ports.remove(&endpoint) {
                sockets.remove(port.handle);
            }
        }
        self.noticed
            .retain(|_, at| now.duration_since(*at) < REFUSAL_NOTICE_EVERY);
    }

    /// Ends every session (connected or still dialing) and frees every
    /// socket. Returns how many sessions and sockets were released.
    pub(super) fn purge(&mut self, sockets: &mut SocketSet<'static>) -> (usize, usize) {
        let sessions = self.flows.len();
        for (_, state) in self.flows.drain() {
            state.task.abort();
        }
        self.dns_sessions = 0;
        let ports = self.ports.len();
        for (_, port) in self.ports.drain() {
            sockets.remove(port.handle);
        }
        (sessions, ports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::{socket::udp, wire::IpAddress};

    /// Room for a few data sessions besides the DNS reserve.
    const SESSIONS: usize = DNS_RESERVE + 8;

    fn endpoint(last: u8, port: u16) -> IpEndpoint {
        IpEndpoint::new(IpAddress::v4(203, 0, 113, last), port)
    }
    fn flow(source_port: u16, target: IpEndpoint) -> Flow {
        Flow {
            source: IpEndpoint::new(IpAddress::v4(198, 18, 0, 2), source_port),
            target,
            tcp: false,
        }
    }
    fn socket() -> udp::Socket<'static> {
        let buffer = || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 1], vec![0; 64]);
        udp::Socket::new(buffer(), buffer())
    }
    fn task() -> tokio::task::AbortHandle {
        tokio::spawn(std::future::pending::<()>()).abort_handle()
    }
    fn open(table: &mut UdpTable, flow: Flow, dns: bool) -> u64 {
        let (input, _) = mpsc::channel(1);
        table.insert(flow, dns, input, |_| task())
    }

    #[tokio::test]
    async fn a_full_table_reuses_idle_targets_but_never_live_ones() {
        let mut sockets = SocketSet::new(vec![]);
        let mut table = UdpTable::new(SESSIONS, 2);
        let start = Instant::now();
        let (live, idle, new) = (endpoint(1, 443), endpoint(2, 443), endpoint(3, 443));
        for target in [live, idle] {
            table
                .admit_port(target, false, false, start, &mut sockets, socket)
                .unwrap();
        }
        open(&mut table, flow(40000, live), false);
        let ended = open(&mut table, flow(40001, idle), false);
        assert!(table.ended(&flow(40001, idle), ended));
        // The ended session's replies get REUSE_AFTER before the slot moves on.
        assert_eq!(
            table.admit_port(new, false, false, Instant::now(), &mut sockets, socket),
            Err(Refusal::Ports)
        );
        let later = Instant::now() + REUSE_AFTER;
        table
            .admit_port(new, false, false, later, &mut sockets, socket)
            .unwrap();
        assert!(table.ports.contains_key(&live) && !table.ports.contains_key(&idle));
        open(&mut table, flow(40002, new), false);
        // Every slot now carries a session: nothing is taken from it.
        assert_eq!(
            table.admit_port(
                endpoint(4, 443),
                false,
                false,
                later + REUSE_AFTER,
                &mut sockets,
                socket
            ),
            Err(Refusal::Ports)
        );
    }

    #[tokio::test]
    async fn data_flows_leave_room_for_dns() {
        let mut table = UdpTable::new(DNS_RESERVE + 2, 4);
        let target = endpoint(1, 443);
        let dns = endpoint(53, 53);
        for port in 0..2 {
            let flow = flow(40000 + port, target);
            assert_eq!(table.admit_session(&flow, false, false), Ok(true));
            open(&mut table, flow, false);
        }
        assert_eq!(
            table.admit_session(&flow(40100, target), false, false),
            Err(Refusal::Sessions)
        );
        for port in 0..DNS_RESERVE as u16 {
            let flow = flow(50000 + port, dns);
            assert_eq!(table.admit_session(&flow, true, false), Ok(true));
            open(&mut table, flow, true);
        }
        assert_eq!(
            table.admit_session(&flow(51000, dns), true, false),
            Err(Refusal::Sessions)
        );
        // An existing session is never refused, whatever the budget.
        assert_eq!(
            table.admit_session(&flow(40000, target), false, false),
            Ok(false)
        );
    }

    #[tokio::test]
    async fn memory_pressure_refuses_new_sessions_on_known_targets_too() {
        let mut sockets = SocketSet::new(vec![]);
        let mut table = UdpTable::new(SESSIONS, 4);
        let target = endpoint(1, 443);
        table
            .admit_port(target, false, false, Instant::now(), &mut sockets, socket)
            .unwrap();
        open(&mut table, flow(40000, target), false);
        assert_eq!(
            table.admit_session(&flow(40000, target), false, true),
            Ok(false)
        );
        assert_eq!(
            table.admit_session(&flow(40001, target), false, true),
            Err(Refusal::Memory)
        );
        assert_eq!(
            table.admit_port(
                endpoint(2, 443),
                false,
                true,
                Instant::now(),
                &mut sockets,
                socket
            ),
            Err(Refusal::Memory)
        );
        // Name lookups go on.
        let dns = endpoint(53, 53);
        table
            .admit_port(dns, true, true, Instant::now(), &mut sockets, socket)
            .unwrap();
        assert_eq!(table.admit_session(&flow(50000, dns), true, true), Ok(true));
    }

    #[tokio::test]
    async fn a_stale_completion_or_reply_does_not_touch_a_newer_session() {
        let mut sockets = SocketSet::new(vec![]);
        let mut table = UdpTable::new(SESSIONS, 4);
        let target = endpoint(1, 443);
        table
            .admit_port(target, false, false, Instant::now(), &mut sockets, socket)
            .unwrap();
        let reused = flow(40000, target);
        let old = open(&mut table, reused, false);
        assert!(table.ended(&reused, old));
        let new = open(&mut table, reused, false);
        assert!(
            !table.ended(&reused, old),
            "an old completion removed the new session"
        );
        assert!(table.superseded(&reused, old) && !table.superseded(&reused, new));
        assert_eq!(table.ports[&target].sessions, 1);
        table.ended(&reused, new);
        assert!(
            !table.superseded(&reused, new),
            "the last session's replies still go out"
        );
        assert_eq!(table.ports[&target].sessions, 0);
    }

    #[tokio::test]
    async fn purging_releases_sessions_and_sockets() {
        let mut sockets = SocketSet::new(vec![]);
        let mut table = UdpTable::new(SESSIONS, 4);
        for last in 1..=3 {
            let target = endpoint(last, 443);
            table
                .admit_port(target, false, false, Instant::now(), &mut sockets, socket)
                .unwrap();
            open(&mut table, flow(40000, target), false);
        }
        assert_eq!(table.purge(&mut sockets), (3, 3));
        assert!(table.flows.is_empty() && table.ports.is_empty());
        assert_eq!(sockets.iter().count(), 0);
        assert_eq!(
            table.admit_session(&flow(40000, endpoint(1, 443)), false, false),
            Ok(true)
        );
    }

    #[test]
    fn refusals_are_noticed_at_most_once_a_window() {
        let mut table = UdpTable::new(1, 1);
        let refused = flow(40000, endpoint(1, 443));
        let start = Instant::now();
        assert!(table.notice(refused, start));
        assert!(!table.notice(refused, start + Duration::from_millis(500)));
        assert!(table.notice(refused, start + REFUSAL_NOTICE_EVERY));
    }
}
