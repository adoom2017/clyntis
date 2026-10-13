//! Hysteria's Brutal congestion control: send at the agreed rate whatever the
//! loss, sizing the window from the RTT and inflating it by the loss rate.
//! Until authentication settles on Brutal, the connection runs BBR.

use quinn::congestion::{BbrConfig, Controller, ControllerFactory};
use quinn_proto::RttEstimator;
use std::{
    any::Any,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

/// Seconds of ack and loss history the ack rate is computed over.
const SLOTS: usize = 5;
/// Below this many samples the loss rate is too noisy to act on.
const MIN_SAMPLES: u64 = 50;
/// Hysteria never assumes more than 20% loss when inflating the window.
const MIN_ACK_RATE: f64 = 0.8;
/// quinn paces from window / RTT; the margin absorbs ack delay jitter.
const WINDOW_GAIN: f64 = 1.5;

/// Shared with the connection's controller: 0 keeps BBR, otherwise Brutal at
/// this many bytes per second.
#[derive(Clone, Debug, Default)]
pub struct Rate(Arc<AtomicU64>);
impl Rate {
    pub fn set(&self, bytes_per_second: u64) {
        self.0.store(bytes_per_second, Ordering::Relaxed);
    }
    fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

pub struct Factory {
    pub rate: Rate,
}
impl ControllerFactory for Factory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Adaptive {
            rate: self.rate.clone(),
            bbr: Arc::new(BbrConfig::default()).build(now, current_mtu),
            brutal: Brutal::new(current_mtu),
        })
    }
}

/// BBR until a Brutal rate is set, then Brutal. Both see every event so the
/// switch needs no warm-up.
struct Adaptive {
    rate: Rate,
    bbr: Box<dyn Controller>,
    brutal: Brutal,
}
impl Controller for Adaptive {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.bbr.on_sent(now, bytes, last_packet_number);
    }
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.bbr.on_ack(now, sent, bytes, app_limited, rtt);
        self.brutal.on_ack(now, bytes, rtt.get());
    }
    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.bbr
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }
    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.bbr
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
        self.brutal.on_loss(now, lost_bytes);
    }
    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.bbr.on_mtu_update(new_mtu);
        self.brutal.mtu = u64::from(new_mtu);
    }
    fn window(&self) -> u64 {
        match self.rate.get() {
            0 => self.bbr.window(),
            rate => self.brutal.window(rate),
        }
    }
    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            rate: self.rate.clone(),
            bbr: self.bbr.clone_box(),
            brutal: self.brutal.clone(),
        })
    }
    fn initial_window(&self) -> u64 {
        self.bbr.initial_window()
    }
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[derive(Clone)]
struct Brutal {
    mtu: u64,
    rtt: Option<Duration>,
    start: Option<Instant>,
    /// (second, acked bytes, lost bytes), indexed by second modulo SLOTS.
    slots: [(u64, u64, u64); SLOTS],
}
impl Brutal {
    fn new(mtu: u16) -> Self {
        Self {
            mtu: u64::from(mtu),
            rtt: None,
            start: None,
            slots: [(u64::MAX, 0, 0); SLOTS],
        }
    }
    fn slot(&mut self, now: Instant) -> &mut (u64, u64, u64) {
        let second = now.duration_since(*self.start.get_or_insert(now)).as_secs();
        let slot = &mut self.slots[(second % SLOTS as u64) as usize];
        if slot.0 != second {
            *slot = (second, 0, 0);
        }
        slot
    }
    fn on_ack(&mut self, now: Instant, bytes: u64, rtt: Duration) {
        self.rtt = Some(rtt);
        self.slot(now).1 += bytes;
    }
    fn on_loss(&mut self, now: Instant, bytes: u64) {
        self.slot(now).2 += bytes;
    }
    fn ack_rate(&self) -> f64 {
        let newest = self
            .slots
            .iter()
            .filter(|s| s.0 != u64::MAX)
            .map(|s| s.0)
            .max();
        let Some(newest) = newest else { return 1.0 };
        let (acked, lost) = self
            .slots
            .iter()
            .filter(|s| s.0 != u64::MAX && newest - s.0 < SLOTS as u64)
            .fold((0, 0), |(a, l), s| (a + s.1, l + s.2));
        let samples = (acked + lost) / self.mtu.max(1);
        if samples < MIN_SAMPLES {
            return 1.0;
        }
        (acked as f64 / (acked + lost) as f64).max(MIN_ACK_RATE)
    }
    fn window(&self, rate: u64) -> u64 {
        let floor = 10 * self.mtu;
        let Some(rtt) = self.rtt else {
            return floor.max(rate / 10);
        };
        let window = rate as f64 * rtt.as_secs_f64() * WINDOW_GAIN / self.ack_rate();
        (window as u64).max(floor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_follows_rate_rtt_and_loss() {
        let start = Instant::now();
        let mut brutal = Brutal::new(1200);
        // Before any RTT sample: a tenth of a second at the rate.
        assert_eq!(brutal.window(10_000_000), 1_000_000);
        brutal.on_ack(start, 1200 * 100, Duration::from_millis(100));
        assert_eq!(brutal.window(10_000_000), 1_500_000);
        // 11 lost of 111 inflates the window to make up for it.
        brutal.on_loss(start, 1200 * 11);
        assert_eq!(brutal.window(10_000_000), 1_665_000);
        // Loss beyond 20% is capped.
        brutal.on_loss(start, 1200 * 1000);
        assert_eq!(brutal.window(10_000_000), 1_875_000);
        // History older than the slots is forgotten.
        brutal.on_ack(
            start + Duration::from_secs(SLOTS as u64 + 1),
            1200 * 100,
            Duration::from_millis(100),
        );
        assert_eq!(brutal.window(10_000_000), 1_500_000);
        // The window never drops under ten packets.
        assert_eq!(brutal.window(1), 12_000);
    }
}
