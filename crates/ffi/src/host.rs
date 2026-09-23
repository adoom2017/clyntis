use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use meta_core::{Core, Running};
use meta_platform::{PacketIo, PlatformHooks};
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
}
enum Command {
    Start(std::sync::mpsc::SyncSender<Result<(), String>>),
    NetworkChanged(std::sync::mpsc::SyncSender<Result<(), String>>),
    #[cfg(target_os = "android")]
    SetFd(
        std::os::fd::OwnedFd,
        std::sync::mpsc::SyncSender<Result<(), String>>,
    ),
}
pub(crate) struct Handle {
    pub(crate) core: Arc<Core>,
    commands: mpsc::Sender<Command>,
    worker: Mutex<Option<JoinHandle<()>>>,
    pub(crate) packet_input: Option<mpsc::Sender<Vec<u8>>>,
    pub(crate) packet_output: Mutex<PacketsOut>,
    packet_queue_enabled: Arc<AtomicBool>,
}
impl Handle {
    pub(crate) fn new(id: u64, config: meta_config::Config, hooks: HostHooks) -> Result<Self> {
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
        let (input_sender, input_receiver) = mpsc::channel(256);
        let (output_sender, output_receiver) = mpsc::channel(256);
        let packet_input = core.config.tun.enable.then_some(input_sender);
        let packet_queue_enabled = Arc::new(AtomicBool::new(core.config.tun.enable));
        #[cfg(target_os = "android")]
        let queue_enabled = packet_queue_enabled.clone();
        let packets = core.config.tun.enable.then(|| {
            Arc::new(HostPackets {
                input: tokio::sync::Mutex::new(input_receiver),
                output: output_sender,
                hooks,
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
                        command = receiver.recv() => match command {
                            Some(Command::Start(reply)) => {
                                let result = match owner.start_with_packets(packets.clone()).await {
                                    Ok(value) => { running = Some(value); Ok(()) },
                                    Err(error) => Err(format!("{error:#}")),
                                };
                                let _ = reply.send(result);
                            },
                            Some(Command::NetworkChanged(reply)) => {
                                owner.network_changed().await;
                                let _ = reply.send(Ok(()));
                            },
                            #[cfg(target_os = "android")]
                            Some(Command::SetFd(fd, reply)) => {
                                let result = if running.is_some() || !owner.config.tun.enable {
                                    Err("TUN fd must be set before start with tun.enable=true".into())
                                } else {
                                    match meta_platform::native::NativeTun::from_owned_fd(fd) {
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
            worker: Mutex::new(Some(worker)),
            packet_input,
            packet_queue_enabled,
            packet_output: Mutex::new(PacketsOut {
                receiver: output_receiver,
                pending: None,
            }),
        })
    }
    pub(crate) fn start(&self) -> Result<()> {
        self.command(Command::Start)
    }
    pub(crate) fn check_packet_queue(&self) -> Result<()> {
        ensure!(
            self.packet_queue_enabled.load(Ordering::Acquire),
            "host packet queue unavailable: TUN is disabled or uses an Android fd"
        );
        Ok(())
    }
    pub(crate) fn network_changed(&self) -> Result<()> {
        self.command(Command::NetworkChanged)
    }
    #[cfg(target_os = "android")]
    pub(crate) fn set_fd(&self, fd: std::os::fd::OwnedFd) -> Result<()> {
        self.command(|reply| Command::SetFd(fd, reply))
    }
    fn command(
        &self,
        make: impl FnOnce(std::sync::mpsc::SyncSender<Result<(), String>>) -> Command,
    ) -> Result<()> {
        check_lifecycle()?;
        ensure!(!self.core.stop.is_cancelled(), "core is stopped");
        let (reply, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .try_send(make(reply))
            .context("core command queue closed or full")?;
        match result.recv_timeout(Duration::from_secs(30)) {
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
