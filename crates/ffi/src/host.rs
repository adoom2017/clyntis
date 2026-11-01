use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use clyntis_core::{Core, Running};
use clyntis_platform::{PacketIo, PlatformHooks};
use std::{
    cell::Cell,
    ffi::c_void,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};
use tokio::sync::mpsc;

type Protect = unsafe extern "C" fn(*mut c_void, u64) -> i32;
type Notify = unsafe extern "C" fn(*mut c_void);
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MetaHooksV1 {
    pub size: u32,
    pub version: u32,
    pub context: *mut c_void,
    pub protect_socket: Option<Protect>,
    pub packet_ready: Option<Notify>,
}
#[derive(Clone, Debug, Default)]
pub(crate) struct HostHooks {
    context: usize,
    protect: Option<Protect>,
    notify: Option<Notify>,
}
impl HostHooks {
    pub(crate) fn new(hooks: MetaHooksV1) -> Result<Self> {
        ensure!(
            hooks.version == 1 && hooks.size as usize == std::mem::size_of::<MetaHooksV1>(),
            "unsupported host hooks version/size"
        );
        Ok(Self {
            context: hooks.context as usize,
            protect: hooks.protect_socket,
            notify: hooks.packet_ready,
        })
    }
}
thread_local! { static CALLBACK: Cell<bool> = const { Cell::new(false) }; }
pub(crate) fn check_lifecycle() -> Result<()> {
    ensure!(
        !CALLBACK.with(Cell::get),
        "lifecycle calls cannot reenter from host callbacks"
    );
    Ok(())
}
struct Scope(bool);
impl Scope {
    fn enter() -> Self {
        Self(CALLBACK.with(|flag| flag.replace(true)))
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        CALLBACK.with(|flag| flag.set(self.0));
    }
}
impl PlatformHooks for HostHooks {
    fn protect_socket(&self, socket: &socket2::Socket) -> Result<()> {
        let Some(callback) = self.protect else {
            return Ok(());
        };
        #[cfg(windows)]
        let raw = {
            use std::os::windows::io::AsRawSocket;
            socket.as_raw_socket()
        };
        #[cfg(unix)]
        let raw = {
            use std::os::fd::AsRawFd;
            socket.as_raw_fd() as u64
        };
        let _scope = Scope::enter();
        // The host borrows this socket and keeps context live until shutdown.
        ensure!(
            unsafe { callback(self.context as *mut c_void, raw) } == 0,
            "host rejected socket protection"
        );
        Ok(())
    }
}
struct HostPackets {
    input: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    output: mpsc::Sender<Vec<u8>>,
    hooks: HostHooks,
    wake: Arc<PacketWake>,
}

/// Coalesces packet_ready: after one notification the host drains until
/// META_WOULD_BLOCK, and only a packet queued after that notifies again.
/// Notifying every packet queued one drain task per packet on iOS.
#[derive(Default)]
pub(crate) struct PacketWake(AtomicBool);
impl PacketWake {
    /// A packet was queued: whether to notify the host.
    pub(crate) fn queued(&self) -> bool {
        !self.0.swap(true, Ordering::AcqRel)
    }
    /// The host found the queue empty. The caller must check the queue once
    /// more afterwards: a packet queued just before saw the flag still set
    /// and did not notify. The swap (not a store) synchronizes with that
    /// sender, so its packet is visible to the check.
    pub(crate) fn emptied(&self) {
        self.0.swap(false, Ordering::AcqRel);
    }
    /// The check after `emptied` found a packet: the host is still draining.
    pub(crate) fn draining(&self) {
        self.0.store(true, Ordering::Release);
    }
}
#[async_trait]
impl PacketIo for HostPackets {
    async fn recv(&self, packet: &mut [u8]) -> Result<usize> {
        let bytes = self
            .input
            .lock()
            .await
            .recv()
            .await
            .context("host packet channel closed")?;
        ensure!(bytes.len() <= packet.len(), "host packet buffer too small");
        packet[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }
    async fn send(&self, packet: &[u8]) -> Result<()> {
        self.output.send(packet.to_vec()).await?;
        if !self.wake.queued() {
            return Ok(());
        }
        if let Some(notify) = self.hooks.notify {
            let _scope = Scope::enter();
            // The nonblocking packet reader may be called from this notification.
            unsafe {
                notify(self.hooks.context as *mut c_void);
            }
        }
        Ok(())
    }
}
pub(crate) struct PacketsOut {
    pub(crate) receiver: mpsc::Receiver<Vec<u8>>,
    pub(crate) pending: Option<Vec<u8>>,
    pub(crate) wake: Arc<PacketWake>,
}
impl PacketsOut {
    /// Makes `pending` the next packet; false when the queue is empty, which
    /// re-arms packet_ready.
    pub(crate) fn fill(&mut self) -> Result<bool> {
        if self.pending.is_some() {
            return Ok(true);
        }
        let packet = match self.receiver.try_recv() {
            Ok(packet) => packet,
            Err(mpsc::error::TryRecvError::Empty) => {
                #[cfg(test)]
                if wake_tests::WIDEN_RACE.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_micros(50));
                }
                // Re-arm, then look again: a packet queued while the flag
                // was still set did not notify.
                self.wake.emptied();
                match self.receiver.try_recv() {
                    Ok(packet) => {
                        self.wake.draining();
                        packet
                    }
                    Err(mpsc::error::TryRecvError::Empty) => return Ok(false),
                    Err(_) => anyhow::bail!("packet channel closed"),
                }
            }
            Err(_) => anyhow::bail!("packet channel closed"),
        };
        self.pending = Some(packet);
        Ok(true)
    }
}
enum Command {
    Start(std::sync::mpsc::SyncSender<Result<(), String>>),
    Probe(
        String,
        u64,
        std::sync::mpsc::SyncSender<Result<u64, String>>,
    ),
    TestRoute(
        clyntis_protocol::Target,
        String,
        std::sync::mpsc::SyncSender<Result<clyntis_core::RouteTest, String>>,
    ),
    DnsLeakTest(std::sync::mpsc::SyncSender<Result<clyntis_core::DnsLeakTest, String>>),
    #[cfg(target_os = "android")]
    SetFd(
        std::os::fd::OwnedFd,
        std::sync::mpsc::SyncSender<Result<(), String>>,
    ),
}
pub(crate) struct Handle {
    pub(crate) core: Arc<Core>,
    commands: mpsc::Sender<Command>,
    network: tokio::sync::watch::Sender<u64>,
    worker: Mutex<Option<JoinHandle<()>>>,
    pub(crate) packet_input: Option<mpsc::Sender<Vec<u8>>>,
    pub(crate) packet_output: Mutex<PacketsOut>,
    packet_queue_enabled: Arc<AtomicBool>,
}
impl Handle {
    pub(crate) fn new(id: u64, config: clyntis_config::Config, hooks: HostHooks) -> Result<Self> {
        #[cfg(target_os = "android")]
        ensure!(
            hooks.protect.is_some(),
            "Android host must provide socket protection"
        );
        let core = Core::new(config, Arc::new(hooks.clone()))?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let (commands, mut receiver) = mpsc::channel::<Command>(4);
        // Network changes bypass the bounded command queue: a full queue or a
        // slow reply made the host treat a change as fatal. Changes made
        // while one is handled collapse into the next.
        let (network, mut network_changes) = tokio::sync::watch::channel(0u64);
        let (input_sender, input_receiver) = mpsc::channel(256);
        let (output_sender, output_receiver) = mpsc::channel(256);
        let wake = Arc::new(PacketWake::default());
        let packet_input = core.config.tun.enable.then_some(input_sender);
        let packet_queue_enabled = Arc::new(AtomicBool::new(core.config.tun.enable));
        #[cfg(target_os = "android")]
        let queue_enabled = packet_queue_enabled.clone();
        let packets = core.config.tun.enable.then(|| {
            Arc::new(HostPackets {
                input: tokio::sync::Mutex::new(input_receiver),
                output: output_sender,
                hooks,
                wake: wake.clone(),
            }) as Arc<dyn PacketIo>
        });
        let owner = core.clone();
        let worker = std::thread::Builder::new()
            .name(format!("meta-host-{id}"))
            .spawn(move || {
                runtime.block_on(async {
                #[cfg(target_os = "android")]
                let mut packets = packets;
                let mut running: Option<Running> = None;
                loop {
                    tokio::select! {
                        biased;
                        _ = owner.stop.cancelled() => break,
                        changed = network_changes.changed() => match changed {
                            Ok(()) => owner.network_changed().await,
                            Err(_) => break,
                        },
                        command = receiver.recv() => match command {
                            Some(Command::Start(reply)) => {
                                let result = match owner.start_with_packets(packets.clone()).await {
                                    Ok(value) => { running = Some(value); Ok(()) },
                                    Err(error) => Err(format!("{error:#}")),
                                };
                                let _ = reply.send(result);
                            },
                            // Probes run concurrently; the worker keeps serving commands.
                            Some(Command::Probe(name, timeout, reply)) => {
                                let core = owner.clone();
                                tokio::spawn(async move {
                                    let url = "https://www.gstatic.com/generate_204";
                                    let result = core
                                        .probe(&name, url, Duration::from_millis(timeout))
                                        .await
                                        .map_err(|e| format!("{e:#}"));
                                    let _ = reply.send(result);
                                });
                            },
                            // Like probes: a rule may need a DNS lookup.
                            Some(Command::TestRoute(target, network, reply)) => {
                                let core = owner.clone();
                                tokio::spawn(async move {
                                    let result = core
                                        .test_route(&target, &network)
                                        .await
                                        .map_err(|e| format!("{e:#}"));
                                    let _ = reply.send(result);
                                });
                            },
                            Some(Command::DnsLeakTest(reply)) => {
                                let core = owner.clone();
                                tokio::spawn(async move {
                                    let result = core
                                        .dns_leak_test()
                                        .await
                                        .map_err(|e| format!("{e:#}"));
                                    let _ = reply.send(result);
                                });
                            },
                            #[cfg(target_os = "android")]
                            Some(Command::SetFd(fd, reply)) => {
                                let result = if running.is_some() || !owner.config.tun.enable {
                                    Err("TUN fd must be set before start with tun.enable=true".into())
                                } else {
                                    match clyntis_platform::native::NativeTun::from_owned_fd(fd) {
                                        Ok(device) => {
                                            queue_enabled.store(false, Ordering::Release);
                                            packets = Some(Arc::new(device));
                                            Ok(())
                                        },
                                        Err(error) => Err(format!("{error:#}")),
                                    }
                                };
                                let _ = reply.send(result);
                            },
                            None => break,
                        },
                    }
                }
                if let Some(running) = running { running.shutdown().await; }
            });
                // Runtime drop joins workers: no callback survives stop/destroy.
                drop(runtime);
            })?;
        Ok(Self {
            core,
            commands,
            network,
            worker: Mutex::new(Some(worker)),
            packet_input,
            packet_queue_enabled,
            packet_output: Mutex::new(PacketsOut {
                receiver: output_receiver,
                pending: None,
                wake,
            }),
        })
    }
    pub(crate) fn start(&self) -> Result<()> {
        // Start may still fetch missing routing resources; their downloads are
        // bounded by progress timeouts, so allow far more than other commands.
        self.command_within(Command::Start, Duration::from_secs(120))
    }
    pub(crate) fn check_packet_queue(&self) -> Result<()> {
        ensure!(
            self.packet_queue_enabled.load(Ordering::Acquire),
            "host packet queue unavailable: TUN is disabled or uses an Android fd"
        );
        Ok(())
    }
    /// Measures `name` like the desktop's delay test; blocks the caller.
    pub(crate) fn probe(&self, name: &str, timeout_ms: u64) -> Result<u64> {
        let (reply, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .try_send(Command::Probe(name.to_owned(), timeout_ms, reply))
            .map_err(|_| anyhow::anyhow!("core worker is busy or stopped"))?;
        result
            .recv_timeout(Duration::from_millis(timeout_ms + 5_000))
            .map_err(|_| anyhow::anyhow!("core worker did not answer"))?
            .map_err(|e| anyhow::anyhow!(e))
    }
    /// Routes `target` like a new connection; blocks the caller while a rule
    /// resolves the name.
    pub(crate) fn test_route(
        &self,
        target: clyntis_protocol::Target,
        network: &str,
    ) -> Result<clyntis_core::RouteTest> {
        let (reply, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .try_send(Command::TestRoute(target, network.to_owned(), reply))
            .map_err(|_| anyhow::anyhow!("core worker is busy or stopped"))?;
        result
            .recv_timeout(Duration::from_secs(15))
            .map_err(|_| anyhow::anyhow!("core worker did not answer"))?
            .map_err(|e| anyhow::anyhow!(e))
    }
    /// The online DNS leak test; blocks the caller for up to ~30 seconds.
    pub(crate) fn dns_leak_test(&self) -> Result<clyntis_core::DnsLeakTest> {
        let (reply, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .try_send(Command::DnsLeakTest(reply))
            .map_err(|_| anyhow::anyhow!("core worker is busy or stopped"))?;
        result
            .recv_timeout(Duration::from_secs(40))
            .map_err(|_| anyhow::anyhow!("core worker did not answer"))?
            .map_err(|e| anyhow::anyhow!(e))
    }
    /// Queues a network change for the worker and returns at once; changes
    /// queued while one is handled are handled together.
    pub(crate) fn network_changed(&self) -> Result<()> {
        check_lifecycle()?;
        ensure!(!self.core.stop.is_cancelled(), "core is stopped");
        self.network
            .send_modify(|count| *count = count.wrapping_add(1));
        Ok(())
    }
    #[cfg(target_os = "android")]
    pub(crate) fn set_fd(&self, fd: std::os::fd::OwnedFd) -> Result<()> {
        self.command(|reply| Command::SetFd(fd, reply))
    }
    #[cfg(target_os = "android")]
    fn command(
        &self,
        make: impl FnOnce(std::sync::mpsc::SyncSender<Result<(), String>>) -> Command,
    ) -> Result<()> {
        self.command_within(make, Duration::from_secs(30))
    }
    fn command_within(
        &self,
        make: impl FnOnce(std::sync::mpsc::SyncSender<Result<(), String>>) -> Command,
        timeout: Duration,
    ) -> Result<()> {
        check_lifecycle()?;
        ensure!(!self.core.stop.is_cancelled(), "core is stopped");
        let (reply, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .try_send(make(reply))
            .context("core command queue closed or full")?;
        match result.recv_timeout(timeout) {
            Ok(result) => result.map_err(anyhow::Error::msg),
            Err(error) => {
                self.core.stop.cancel();
                Err(error.into())
            }
        }
    }
    pub(crate) fn shutdown(&self) -> Result<()> {
        check_lifecycle()?;
        self.core.stop.cancel();
        let mut worker = self.worker.lock().unwrap();
        if let Some(worker) = worker.take() {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("core worker panicked"))?;
        }
        Ok(())
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[cfg(test)]
mod wake_tests {
    use super::*;

    /// Pauses `fill` between finding the queue empty and re-arming, so a
    /// packet arrives in that window: the case that loses a wakeup.
    pub(super) static WIDEN_RACE: AtomicBool = AtomicBool::new(false);

    /// Short bursts from a sender while the host drains only when notified:
    /// the last packet of each burst lands near the re-arm. Every burst must
    /// arrive (no lost wakeup), with fewer notifications than packets.
    #[test]
    fn coalesced_notifications_never_lose_the_last_packet() {
        const ROUNDS: usize = 300;
        const BURST: usize = 3;
        WIDEN_RACE.store(true, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel::<Vec<u8>>(256);
        let wake = Arc::new(PacketWake::default());
        let mut queue = PacketsOut {
            receiver,
            pending: None,
            wake: wake.clone(),
        };
        let (notify, notified) = std::sync::mpsc::channel::<()>();
        let (next, rounds) = std::sync::mpsc::channel::<()>();
        let producer = std::thread::spawn(move || {
            for _ in 0..ROUNDS {
                for _ in 0..BURST {
                    sender.blocking_send(vec![0]).unwrap();
                    if wake.queued() {
                        notify.send(()).unwrap();
                    }
                }
                if rounds.recv().is_err() {
                    return;
                }
            }
        });
        let mut notifications = 0;
        for round in 0..ROUNDS {
            let mut received = 0;
            while received < BURST {
                notified
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap_or_else(|_| panic!("lost a wakeup in round {round}"));
                notifications += 1;
                // What meta_read_packet_v1 does for the host: drain to empty.
                while queue.fill().unwrap() {
                    queue.pending.take();
                    received += 1;
                }
            }
            next.send(()).unwrap();
        }
        WIDEN_RACE.store(false, Ordering::Relaxed);
        producer.join().unwrap();
        assert!(
            notifications < ROUNDS * BURST,
            "{notifications} notifications"
        );
    }
}
