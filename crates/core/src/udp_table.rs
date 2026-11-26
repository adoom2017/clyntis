//! UDP bookkeeping for the TUN loop: sessions (one per source and target),
//! and why a new one is refused.
//!
//! Admission order for a datagram that has no session yet: the memory guard
//! (ordinary sessions only), then the session budget (a few sessions stay
//! reserved for hijacked DNS so data flows cannot starve name lookups).
use super::Flow;
use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{sync::mpsc, time::Instant};

/// Sessions only hijacked DNS may use once data flows fill the rest.
pub(super) const DNS_RESERVE: usize = 16;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Refusal {
    /// The memory guard refuses new flows.
    Memory,
    /// Every session slot is in use.
    Sessions,
}

/// Datagrams dropped or refused, by where, since the TUN started. Session
/// tasks hold a reference to count their own drops.
#[derive(Default, Debug)]
pub(super) struct Drops {
    pub(super) memory: AtomicU64,
    pub(super) sessions: AtomicU64,
    /// A session's upload queue was full.
    pub(super) input_full: AtomicU64,
    /// The shared reply queue to the TUN loop was full.
    pub(super) reply_full: AtomicU64,
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
        }
        .fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn snapshot(&self) -> [u64; 6] {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        [
            load(&self.memory),
            load(&self.sessions),
            load(&self.input_full),
            load(&self.reply_full),
            clyntis_protocol::drops::XUDP_INBOX_FULL.load(Ordering::Relaxed),
            clyntis_protocol::drops::HYSTERIA2_INBOX_FULL.load(Ordering::Relaxed),
        ]
    }
}

pub(super) struct UdpTable {
    pub(super) flows: HashMap<Flow, UdpFlow>,
    max_sessions: usize,
    dns_sessions: usize,
    next_generation: u64,
    noticed: HashMap<Flow, Instant>,
}

impl UdpTable {
    pub(super) fn new(max_sessions: usize) -> Self {
        Self {
            flows: HashMap::new(),
            max_sessions,
            dns_sessions: 0,
            next_generation: 0,
            noticed: HashMap::new(),
        }
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

    /// Records a new session.
    pub(super) fn insert(
        &mut self,
        flow: Flow,
        dns: bool,
        input: mpsc::Sender<Vec<u8>>,
        task: impl FnOnce(u64) -> tokio::task::AbortHandle,
    ) -> u64 {
        self.next_generation += 1;
        let generation = self.next_generation;
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

    /// Drops old refusal notices.
    pub(super) fn expire(&mut self, now: Instant) {
        self.noticed
            .retain(|_, at| now.duration_since(*at) < REFUSAL_NOTICE_EVERY);
    }

    /// Ends every session (connected or still dialing). Returns how many
    /// sessions were released.
    pub(super) fn purge(&mut self) -> usize {
        let sessions = self.flows.len();
        for (_, state) in self.flows.drain() {
            state.task.abort();
        }
        self.dns_sessions = 0;
        sessions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::{IpAddress, IpEndpoint};

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
    fn task() -> tokio::task::AbortHandle {
        tokio::spawn(std::future::pending::<()>()).abort_handle()
    }
    fn open(table: &mut UdpTable, flow: Flow, dns: bool) -> u64 {
        let (input, _) = mpsc::channel(1);
        table.insert(flow, dns, input, |_| task())
    }

    #[tokio::test]
    async fn data_flows_leave_room_for_dns() {
        let mut table = UdpTable::new(DNS_RESERVE + 2);
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
        let mut table = UdpTable::new(SESSIONS);
        let target = endpoint(1, 443);
        open(&mut table, flow(40000, target), false);
        assert_eq!(
            table.admit_session(&flow(40000, target), false, true),
            Ok(false)
        );
        assert_eq!(
            table.admit_session(&flow(40001, target), false, true),
            Err(Refusal::Memory)
        );
        // Name lookups go on.
        let dns = endpoint(53, 53);
        assert_eq!(table.admit_session(&flow(50000, dns), true, true), Ok(true));
    }

    #[tokio::test]
    async fn a_stale_completion_or_reply_does_not_touch_a_newer_session() {
        let mut table = UdpTable::new(SESSIONS);
        let target = endpoint(1, 443);
        let reused = flow(40000, target);
        let old = open(&mut table, reused, false);
        assert!(table.ended(&reused, old));
        let new = open(&mut table, reused, false);
        assert!(
            !table.ended(&reused, old),
            "an old completion removed the new session"
        );
        assert!(table.superseded(&reused, old) && !table.superseded(&reused, new));
        table.ended(&reused, new);
        assert!(
            !table.superseded(&reused, new),
            "the last session's replies still go out"
        );
    }

    #[tokio::test]
    async fn purging_releases_sessions() {
        let mut table = UdpTable::new(SESSIONS);
        for last in 1..=3 {
            let target = endpoint(last, 443);
            open(&mut table, flow(40000, target), false);
        }
        assert_eq!(table.purge(), 3);
        assert!(table.flows.is_empty());
        assert_eq!(
            table.admit_session(&flow(40000, endpoint(1, 443)), false, false),
            Ok(true)
        );
    }

    #[test]
    fn refusals_are_noticed_at_most_once_a_window() {
        let mut table = UdpTable::new(1);
        let refused = flow(40000, endpoint(1, 443));
        let start = Instant::now();
        assert!(table.notice(refused, start));
        assert!(!table.notice(refused, start + Duration::from_millis(500)));
        assert!(table.notice(refused, start + REFUSAL_NOTICE_EVERY));
    }
}
