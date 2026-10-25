//! `type: tailscale` proxies: one userspace Tailscale node per proxy, whose
//! control and DERP connections go out like the core's own (physical egress,
//! or `dialer-proxy`).
use crate::Core;
use anyhow::{Context, Result};
use clyntis_config::{Proxy, ProxyKind};
use clyntis_protocol::{
    BoxStream, Target,
    tls::{SecureConnector, TlsConnectConfig, TlsFingerprint},
};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Weak},
};

/// Any public address: only used to pick the egress, never contacted.
const PROBE: &str = "1.1.1.1:3478";

struct CoreDialer {
    core: Weak<Core>,
    via: Option<String>,
}

#[async_trait::async_trait]
impl clyntis_tailscale::Dialer for CoreDialer {
    async fn connect_tcp(&self, host: &str, port: u16) -> Result<BoxStream> {
        let core = self.core.upgrade().context("proxy core stopped")?;
        let target = Target::new(host, port)?;
        match &self.via {
            Some(via) => Ok(core.dial_inner(&target, Some(via), "tcp").await?.0),
            None => Ok(Box::new(core.raw_tcp(&target).await?)),
        }
    }
    async fn connect_tls(&self, host: &str, port: u16) -> Result<BoxStream> {
        let tcp = self.connect_tcp(host, port).await?;
        let clock = self
            .core
            .upgrade()
            .context("proxy core stopped")?
            .clock
            .clone();
        SecureConnector::new(clock)
            .connect(
                tcp,
                &TlsConnectConfig {
                    server_name: host.into(),
                    alpn: vec!["http/1.1".into()],
                    verify_cert: true,
                    fingerprint: TlsFingerprint::Native,
                    reality: None,
                },
            )
            .await
    }
    async fn bind_udp(&self) -> Result<tokio::net::UdpSocket> {
        let core = self.core.upgrade().context("proxy core stopped")?;
        // Bound like the core's own UDP: outside the TUN, on the physical exit.
        clyntis_platform::udp_bind_for("0.0.0.0:0".parse()?, Some(PROBE.parse()?), &*core.hooks)
    }
    async fn local_ipv4(&self) -> Option<IpAddr> {
        let core = self.core.upgrade()?;
        let socket = clyntis_platform::udp_bind_for(
            "0.0.0.0:0".parse().ok()?,
            PROBE.parse().ok(),
            &*core.hooks,
        )
        .ok()?;
        // Connecting a UDP socket sends nothing; it only selects the source.
        socket.connect(PROBE).await.ok()?;
        let ip = socket.local_addr().ok()?.ip();
        let tun = "198.18.0.0/15".parse::<ipnet::IpNet>().ok()?;
        (!ip.is_loopback() && !ip.is_unspecified() && !tun.contains(&ip)).then_some(ip)
    }
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        let core = self.core.upgrade().context("proxy core stopped")?;
        Ok(core
            .resolver
            .lookup(host, 0)
            .await?
            .into_iter()
            .map(|a| a.ip())
            .collect())
    }
}

/// `{os}` and `{device}` in a configured hostname, so one profile shared by
/// several devices gives each its own node name instead of the control
/// server numbering copies of one (`name-1`, `name-2`). `{device}` is the
/// device's host name, or the OS where it has none worth using.
fn expand_hostname(template: &str, os: &str, device: Option<&str>) -> String {
    let device = device
        .map(dns_label)
        .filter(|name| !name.is_empty() && name != "localhost")
        .unwrap_or_else(|| os.to_owned());
    let mut name = dns_label(&template.replace("{os}", os).replace("{device}", &device));
    name.truncate(63);
    name.trim_end_matches('-').to_owned()
}

/// Lowercase letters, digits and single hyphens from the first label of `name`.
fn dns_label(name: &str) -> String {
    let mut label = String::new();
    for c in name.split('.').next().unwrap_or_default().chars() {
        if c.is_ascii_alphanumeric() {
            label.push(c.to_ascii_lowercase());
        } else if !label.is_empty() && !label.ends_with('-') {
            label.push('-');
        }
    }
    label.trim_end_matches('-').to_owned()
}

fn device_name() -> Option<String> {
    #[cfg(target_vendor = "apple")]
    {
        let mut buffer = [0u8; 256];
        // SAFETY: gethostname writes at most `len` bytes into the buffer.
        let result = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
        if result != 0 {
            return None;
        }
        let end = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
        Some(String::from_utf8_lossy(&buffer[..end]).into_owned())
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").ok()
    }
    #[cfg(not(any(target_vendor = "apple", windows)))]
    {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()
            .map(|name| name.trim().to_owned())
    }
}

fn os() -> &'static str {
    if cfg!(target_os = "ios") {
        "iOS"
    } else if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(windows) {
        "windows"
    } else {
        "linux"
    }
}

fn options(core: &Core, proxy: &Proxy) -> clyntis_tailscale::Options {
    let t = &proxy.tailscale;
    let folder: String = proxy
        .name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let dir = match &t.state_dir {
        Some(dir) => core.config.directory.join(dir),
        None => core.config.directory.join("tailscale").join(folder),
    };
    clyntis_tailscale::Options {
        name: proxy.name.clone(),
        auth_key: t.auth_key.clone(),
        hostname: expand_hostname(
            t.hostname.as_deref().unwrap_or("clyntis-{os}"),
            &os().to_ascii_lowercase(),
            device_name().as_deref(),
        ),
        control_url: t
            .control_url
            .clone()
            .unwrap_or_else(|| "https://controlplane.tailscale.com".into()),
        state_path: dir.join("state.json"),
        ephemeral: t.ephemeral,
        accept_routes: t.accept_routes.unwrap_or(false),
        exit_node: t.exit_node.clone(),
        os: os().into(),
    }
}

/// Starts a node for every tailscale proxy; they stop with the core.
pub(crate) fn start(core: &Arc<Core>) -> Result<HashMap<String, clyntis_tailscale::Node>> {
    let mut nodes = HashMap::new();
    for proxy in core
        .config
        .proxies
        .iter()
        .filter(|p| p.kind == ProxyKind::Tailscale)
    {
        let dialer = Arc::new(CoreDialer {
            core: Arc::downgrade(core),
            via: proxy.dialer_proxy.clone(),
        });
        let node = clyntis_tailscale::Node::start(options(core, proxy), dialer, core.stop.clone())
            .with_context(|| format!("cannot start Tailscale proxy {}", proxy.name))?;
        nodes.insert(proxy.name.clone(), node);
    }
    if !nodes.is_empty() {
        let names: Vec<clyntis_tailscale::Node> = nodes.values().cloned().collect();
        core.resolver
            .set_tailnet_names(Some(Arc::new(move |host: &str| {
                names.iter().find_map(|n| n.resolve(host))
            })));
    }
    Ok(nodes)
}

#[cfg(test)]
mod tests {
    use super::expand_hostname;

    #[test]
    fn hostnames_differ_per_device_and_stay_dns_labels() {
        assert_eq!(expand_hostname("clyntis-{os}", "ios", None), "clyntis-ios");
        assert_eq!(
            expand_hostname("{device}-clyntis", "macos", Some("Shens-MacBook-Pro.local")),
            "shens-macbook-pro-clyntis"
        );
        // No usable device name: the OS stands in.
        assert_eq!(expand_hostname("{device}", "ios", Some("localhost")), "ios");
        assert_eq!(
            expand_hostname("{device}", "windows", Some("..")),
            "windows"
        );
        assert_eq!(expand_hostname("Home_Mac", "macos", None), "home-mac");
        let long = "a".repeat(70);
        assert_eq!(expand_hostname(&long, "linux", None).len(), 63);
    }
}
