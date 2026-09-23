use crate::PacketIo;
#[cfg(not(target_os = "android"))]
use anyhow::Context;
use anyhow::{Result, ensure};
use async_trait::async_trait;

pub struct NativeTun {
    device: tun_rs::AsyncDevice,
}
impl NativeTun {
    #[cfg(not(target_os = "android"))]
    pub fn open(name: &str, mtu: u16, ipv6: bool) -> Result<Self> {
        ensure!((1280..=9000).contains(&mtu), "TUN MTU must be 1280..9000");
        let mut builder = tun_rs::DeviceBuilder::new()
            .mtu(mtu)
            .ipv4("198.18.0.1", 32, None);
        if ipv6 {
            builder = builder.ipv6("fdfe:dcba:9876::1", 128);
        }
        #[cfg(target_os = "macos")]
        if name != "clyntis" {
            builder = builder.name(name);
        }
        #[cfg(not(target_os = "macos"))]
        {
            builder = builder.name(name);
        }
        #[cfg(windows)]
        {
            builder = builder.wintun_log(false);
        }
        Ok(Self { device: builder.build_async().context("cannot open TUN; desktop systems require administrator/root privileges and Windows requires wintun.dll")? })
    }
    #[cfg(not(target_os = "android"))]
    pub fn name(&self) -> Result<String> {
        Ok(self.device.name()?)
    }
    #[cfg(not(target_os = "android"))]
    pub fn index(&self) -> Result<u32> {
        Ok(self.device.if_index()?)
    }
    /// The descriptor must be an exclusively owned, configured layer-3 TUN fd.
    /// Ownership transfers even if conversion fails. Call within a Tokio runtime.
    #[cfg(unix)]
    pub fn from_owned_fd(fd: std::os::fd::OwnedFd) -> Result<Self> {
        use std::os::fd::IntoRawFd;
        // tun-rs takes ownership of the descriptor and closes it on drop/error.
        Ok(Self {
            device: unsafe { tun_rs::AsyncDevice::from_fd(fd.into_raw_fd()) }?,
        })
    }
}
#[async_trait]
impl PacketIo for NativeTun {
    async fn recv(&self, packet: &mut [u8]) -> Result<usize> {
        Ok(self.device.recv(packet).await?)
    }
    async fn send(&self, packet: &[u8]) -> Result<()> {
        ensure!(
            self.device.send(packet).await? == packet.len(),
            "short TUN packet write"
        );
        Ok(())
    }
}
