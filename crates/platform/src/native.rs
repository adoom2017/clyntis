use crate::PacketIo;
#[cfg(not(target_os = "android"))]
use anyhow::Context;
use anyhow::{Result, ensure};
use async_trait::async_trait;

pub struct NativeTun {
    device: tun_rs::AsyncDevice,
}

#[cfg(windows)]
fn windows_local_discovery_packet(packet: &[u8]) -> bool {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => {
            let destination =
                std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            destination.is_multicast() || destination.is_broadcast()
        }
        Some(6) if packet.len() >= 40 => packet[24] == 0xff,
        _ => false,
    }
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
    /// Assigns another IPv4 address (/32, point-to-point on macOS) so local
    /// programs see it in `getifaddrs`. It goes with the interface when the
    /// process exits.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub fn add_alias(&self, address: std::net::Ipv4Addr) -> Result<()> {
        Ok(self.device.add_address_v4(address, 32u8)?)
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub fn remove_alias(&self, address: std::net::Ipv4Addr) -> Result<()> {
        Ok(self.device.remove_address(address.into())?)
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
        #[cfg(windows)]
        loop {
            let size = self.device.recv(packet).await?;
            // Apps also advertise on the Wintun interface (e.g. Steam's
            // ff02::1:27036 discovery). This is local-link traffic, not a
            // proxy flow. Re-sending it can select Wintun again and recurse;
            // IP_UNICAST_IF does not select the multicast interface.
            if !windows_local_discovery_packet(&packet[..size]) {
                return Ok(size);
            }
        }
        #[cfg(not(windows))]
        {
            Ok(self.device.recv(packet).await?)
        }
    }
    async fn send(&self, packet: &[u8]) -> Result<()> {
        ensure!(
            self.device.send(packet).await? == packet.len(),
            "short TUN packet write"
        );
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::windows_local_discovery_packet;

    fn ipv4(destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0; 28];
        packet[0] = 0x45;
        packet[9] = 17;
        packet[16..20].copy_from_slice(&destination);
        packet[22..24].copy_from_slice(&27036u16.to_be_bytes());
        packet
    }

    fn ipv6(destination: &str) -> Vec<u8> {
        let mut packet = vec![0; 48];
        packet[0] = 0x60;
        packet[6] = 17;
        packet[24..40]
            .copy_from_slice(&destination.parse::<std::net::Ipv6Addr>().unwrap().octets());
        packet[42..44].copy_from_slice(&27036u16.to_be_bytes());
        packet
    }

    #[test]
    fn steam_discovery_and_mdns_stay_out_of_windows_proxy_flows() {
        for packet in [
            ipv4([255, 255, 255, 255]),
            ipv4([224, 0, 0, 251]),
            ipv6("ff02::1"),
            ipv6("ff02::fb"),
        ] {
            assert!(windows_local_discovery_packet(&packet));
        }
    }

    #[test]
    fn unicast_steam_dns_and_fake_ip_traffic_reaches_the_core() {
        for packet in [
            ipv4([103, 28, 54, 101]),
            ipv4([192, 168, 2, 1]),
            ipv4([28, 0, 0, 2]),
            ipv6("2404:3fc0:a:100::4"),
            ipv6("fdfe:dcba:9876::2"),
        ] {
            assert!(!windows_local_discovery_packet(&packet));
        }
        for packet in [vec![], vec![0x45; 19], vec![0x60; 39], vec![0xff; 40]] {
            assert!(!windows_local_discovery_packet(&packet));
        }
    }
}
