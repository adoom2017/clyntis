//! Shared desktop lifecycle. Each process runs a single core (and logging subscriber).
pub mod logging;
#[cfg(target_os = "macos")]
use anyhow::ensure;
use anyhow::{Context, Result};
use meta_config::Config;
#[cfg(target_os = "macos")]
use meta_config::ProxyKind;
use meta_core::Core;
use meta_platform::{
    DefaultHooks,
    desktop::{DesktopTun, Options},
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub struct RuntimeReady {
    pub controller: Option<SocketAddr>,
}

pub fn recover(directory: &std::path::Path) -> Result<()> {
    // Attempt both journals even when one recovery fails.
    let routes = meta_platform::desktop::recover(directory);
    #[cfg(target_os = "macos")]
    let dns = meta_platform::macos_dns::recover(directory);
    routes?;
    #[cfg(target_os = "macos")]
    dns?;
    Ok(())
}

fn dns_server_ip(server: &str) -> Option<IpAddr> {
    let authority = server.split_once("://").map_or(server, |(_, rest)| rest);
    let authority = authority.split('/').next()?;
    authority
        .parse::<IpAddr>()
        .ok()
        .or_else(|| authority.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
}

fn physical_dns_upstreams(dns: &meta_config::Dns) -> Vec<IpAddr> {
    let mut addresses: Vec<_> = dns
        .nameserver
        .iter()
        .chain(&dns.default_nameserver)
        .chain(&dns.proxy_server_nameserver)
        .cloned()
        .chain(
            dns.nameserver_policy
                .values()
                .flat_map(|servers| servers.values()),
        )
        .filter_map(|server| dns_server_ip(&server))
        .filter(|ip| match ip {
            IpAddr::V4(ip) => {
                !ip.is_private()
                    && !ip.is_loopback()
                    && !ip.is_link_local()
                    && !ip.is_multicast()
                    && !ip.is_unspecified()
            }
            IpAddr::V6(_) => false,
        })
        .collect();
    addresses.sort();
    addresses.dedup();
    addresses
}

#[cfg(target_os = "macos")]
fn best_egress_index(public_scores: &[usize], proxy_scores: &[usize]) -> Option<usize> {
    public_scores
        .iter()
        .zip(proxy_scores)
        .enumerate()
        .max_by_key(|(index, (public, proxy))| {
            (**public > 0, **proxy, **public, std::cmp::Reverse(*index))
        })
        .filter(|(_, (public, proxy))| **public > 0 || **proxy > 0)
        .map(|(index, _)| index)
}

#[cfg(target_os = "macos")]
pub async fn public_egress_targets() -> Vec<SocketAddr> {
    use std::time::Duration;

    match tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::lookup_host(("example.com", 443)),
    )
    .await
    {
        Ok(Ok(addresses)) => addresses.filter(SocketAddr::is_ipv4).take(2).collect(),
        _ => Vec::new(),
    }
}

#[cfg(target_os = "macos")]
async fn verify_macos_system_dns(dns: &meta_config::Dns) -> Result<()> {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    if dns.enhanced_mode != "fake-ip" {
        return Ok(());
    }
    for attempt in 0..3 {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let host = format!("clyntis-{nonce}-{attempt}.example.com");
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::lookup_host((host.as_str(), 80)),
        )
        .await;
        if let Ok(Ok(addresses)) = result {
            let addresses: Vec<_> = addresses.collect();
            tracing::debug!(host = %host, ?addresses, "macOS system DNS verification result");
            if addresses.iter().any(|address| match address.ip() {
                IpAddr::V4(ip) => dns.fake_ip_range.contains(&ip),
                IpAddr::V6(_) => false,
            }) {
                tracing::info!("macOS system DNS verified through Clyntis fake-IP resolver");
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    tracing::warn!(
        "macOS system DNS verification did not return a Clyntis fake-IP; DNS takeover is unverified; inspect scutil --dns for the default and scoped resolvers"
    );
    Ok(())
}

#[cfg(target_os = "macos")]
pub async fn detect_macos_egress(
    config: &Config,
    public_targets: &[SocketAddr],
    phase: &str,
) -> Result<Option<String>> {
    use meta_platform::desktop::{EgressHooks, Network, ipv4_egress_candidates};
    use std::time::Duration;

    if config.tun.interface.is_some() || !config.tun.auto_detect_interface {
        return Ok(None);
    }
    let candidates = ipv4_egress_candidates()?;
    if candidates.is_empty() {
        return Ok(None);
    }
    let mut proxy_targets: Vec<SocketAddr> = config
        .proxies
        .iter()
        // Probe only supported TCP outbounds. Hysteria2 uses UDP/QUIC;
        // a TCP refusal on its port says nothing about egress reachability.
        .filter(|proxy| proxy.kind == ProxyKind::Vless)
        .filter_map(|proxy| {
            proxy
                .server
                .parse::<std::net::Ipv4Addr>()
                .ok()
                .map(|ip| SocketAddr::new(ip.into(), proxy.port))
        })
        .collect();
    proxy_targets.sort();
    proxy_targets.dedup();
    proxy_targets.truncate(8);
    if proxy_targets.is_empty() {
        proxy_targets = physical_dns_upstreams(&config.dns)
            .into_iter()
            .map(|ip| SocketAddr::new(ip, 53))
            .take(4)
            .collect();
    }
    if proxy_targets.is_empty() && public_targets.is_empty() {
        return Ok(None);
    }
    let mut attempts = tokio::task::JoinSet::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let hooks = Arc::new(EgressHooks::new(Network {
            ipv4: Some(candidate.clone()),
            ..Network::default()
        }));
        for (target, public) in proxy_targets
            .iter()
            .copied()
            .map(|target| (target, false))
            .chain(public_targets.iter().copied().map(|target| (target, true)))
        {
            let hooks = hooks.clone();
            attempts.spawn(async move {
                let result = tokio::time::timeout(
                    Duration::from_secs(3),
                    meta_platform::tcp_connect(target, &*hooks),
                )
                .await;
                (index, public, matches!(result, Ok(Ok(_))))
            });
        }
    }
    let mut proxy_scores = vec![0usize; candidates.len()];
    let mut public_scores = vec![0usize; candidates.len()];
    while let Some(result) = attempts.join_next().await {
        let (index, public, connected) = result?;
        if public {
            public_scores[index] += usize::from(connected);
        } else {
            proxy_scores[index] += usize::from(connected);
        }
    }
    for (index, candidate) in candidates.iter().enumerate() {
        eprintln!(
            "macOS physical egress candidate ({phase}): {} public={}/{} proxy={}/{}",
            candidate.name,
            public_scores[index],
            public_targets.len(),
            proxy_scores[index],
            proxy_targets.len()
        );
    }
    let selected = best_egress_index(&public_scores, &proxy_scores);
    if let Some(index) = selected {
        eprintln!(
            "macOS physical egress selected ({phase}): {} (public: {}/{}, proxy: {}/{})",
            candidates[index].name,
            public_scores[index],
            public_targets.len(),
            proxy_scores[index],
            proxy_targets.len()
        );
    } else {
        eprintln!("macOS physical egress probe ({phase}) found no reachable targets");
    }
    Ok(selected.map(|index| candidates[index].name.clone()))
}

pub async fn run(
    config: Config,
    stop: CancellationToken,
    ready: Option<oneshot::Sender<RuntimeReady>>,
) -> Result<()> {
    let directory = config.directory.clone();
    eprintln!(
        "TLS backend: BoringSSL; default client fingerprint: {}",
        config.global_client_fingerprint
    );
    if config.tun.enable {
        eprintln!(
            "Compatibility: TUN uses the native Rust/smoltcp stack; stack labels do not select a Go gVisor implementation."
        );
    }
    #[cfg(target_os = "macos")]
    let automatic_dns = config.tun.auto_route && config.tun.auto_dns && config.dns.enable;
    let upstream_dns = if config.dns.enable {
        physical_dns_upstreams(&config.dns)
    } else {
        Vec::new()
    };
    #[cfg(target_os = "macos")]
    let public_targets = if config.tun.enable {
        public_egress_targets().await
    } else {
        Vec::new()
    };
    #[cfg(target_os = "macos")]
    let detected_interface = if config.tun.enable {
        detect_macos_egress(&config, &public_targets, "before TUN").await?
    } else {
        None
    };
    #[cfg(not(target_os = "macos"))]
    let detected_interface: Option<String> = None;
    let selected_interface = config
        .tun
        .interface
        .as_deref()
        .or(detected_interface.as_deref());
    let open_tun = |interface: Option<&str>| {
        DesktopTun::open(Options {
            name: &config.tun.device,
            mtu: config.tun.mtu,
            ipv6: config.ipv6,
            auto_route: config.tun.auto_route,
            interface,
            exclusions: &config.tun.route_exclude_address,
            capture_dns: !cfg!(target_os = "macos") && !config.tun.dns_hijack.is_empty(),
            upstream_dns: &upstream_dns,
            directory: &directory,
        })
    };
    let mut desktop = if config.tun.enable {
        Some(open_tun(selected_interface)?)
    } else {
        None
    };
    #[cfg(target_os = "macos")]
    if config.tun.enable && config.tun.auto_detect_interface && config.tun.interface.is_none() {
        let after = detect_macos_egress(&config, &public_targets, "after TUN")
            .await?
            .context(
                "no physical egress reachable after TUN routing; set tun.interface explicitly",
            )?;
        let current = desktop
            .as_ref()
            .and_then(|tun| tun.hooks.network().ipv4)
            .map(|interface| interface.name);
        if current.as_deref() != Some(after.as_str()) {
            let mut previous = desktop.take().unwrap();
            previous.restore()?;
            drop(previous);
            desktop = Some(open_tun(Some(&after))?);
            let verified =
                detect_macos_egress(&config, &public_targets, "after TUN reselection").await?;
            ensure!(
                verified.as_deref() == Some(after.as_str()),
                "physical egress changed during TUN setup; set tun.interface explicitly"
            );
        }
    }
    let hooks: meta_platform::Hooks = desktop
        .as_ref()
        .map(|d| d.hooks.clone() as meta_platform::Hooks)
        .unwrap_or_else(|| Arc::new(DefaultHooks));
    let packets = desktop
        .as_ref()
        .map(|d| d.device.clone() as Arc<dyn meta_platform::PacketIo>);
    let core = Core::new(config, hooks)?;
    logging::init(&core.config.log, &directory, core.events.clone())?;
    if core.config.log.log_path.is_empty() {
        eprintln!("Logging: {} to stderr", core.config.log.log_level);
    } else {
        eprintln!(
            "Logging: {} to {}",
            core.config.log.log_level,
            directory.join(&core.config.log.log_path).display()
        );
    }
    tracing::debug!(
        tun = core.config.tun.enable,
        auto_route = core.config.tun.auto_route,
        auto_dns = core.config.tun.auto_dns,
        dns = core.config.dns.enable,
        dns_listen = %core.config.dns.listen,
        "proxy runtime configuration"
    );
    if let Some(tun) = &desktop {
        let network = tun.hooks.network();
        tracing::info!(
            device = %tun.device.name()?,
            ipv4_exit = ?network.ipv4,
            ipv6_exit = ?network.ipv6,
            "TUN routing initialized"
        );
    }
    #[cfg(target_os = "macos")]
    if core.config.tun.enable && !automatic_dns {
        tracing::info!("macOS system DNS preserved");
    }
    #[cfg(target_os = "macos")]
    let mut system_dns_address = if automatic_dns {
        let interface = desktop
            .as_ref()
            .and_then(|tun| tun.hooks.network().ipv4)
            .context("automatic DNS requires an IPv4 physical exit")?;
        Some(meta_platform::desktop::local_ipv4_address(&interface)?)
    } else {
        None
    };
    #[cfg(target_os = "macos")]
    let mut running = core
        .start_with_packets_and_system_dns(
            packets,
            system_dns_address.map(|address| std::net::SocketAddr::new(address.into(), 53)),
        )
        .await
        .context("cannot start proxy core")?;
    #[cfg(not(target_os = "macos"))]
    let running = core
        .start_with_packets(packets)
        .await
        .context("cannot start proxy core")?;
    #[cfg(target_os = "macos")]
    let mut system_dns = if core.config.tun.enable
        && core.config.tun.auto_route
        && core.config.tun.auto_dns
        && core.config.dns.enable
    {
        let interface = desktop
            .as_ref()
            .and_then(|tun| tun.hooks.network().ipv4)
            .context("automatic DNS requires an IPv4 physical exit")?;
        let server = system_dns_address.context("automatic DNS address missing")?;
        let dns = meta_platform::macos_dns::MacDns::start(&directory, &interface.name, server)?;
        tracing::info!(interface = %interface.name, %server, "macOS system DNS configured");
        Some(dns)
    } else {
        None
    };
    #[cfg(target_os = "macos")]
    if system_dns.is_some() {
        verify_macos_system_dns(&core.config.dns).await?;
    }
    tracing::info!(addresses = ?running.addresses, "proxy core started");
    if let Some(ready) = ready {
        let _ = ready.send(RuntimeReady {
            controller: running.controller_address,
        });
    }
    let mut refresh = tokio::time::interval(std::time::Duration::from_secs(3));
    #[cfg(target_os = "macos")]
    let mut next_egress_probe = tokio::time::Instant::now();
    let result: Result<()> = async { loop {
            tokio::select! {
                _ = stop.cancelled() => break Ok(()),
                _ = core.stop.cancelled() => break Err(anyhow::anyhow!("proxy core stopped unexpectedly")),
                _ = refresh.tick(), if desktop.is_some() => {
                    #[cfg(target_os = "macos")]
                    let selected = if tokio::time::Instant::now() >= next_egress_probe {
                        next_egress_probe = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
                        match detect_macos_egress(&core.config, &public_targets, "network refresh").await {
                            Ok(selected) => selected,
                            Err(error) => { tracing::warn!(%error, "physical egress detection failed; retrying"); None }
                        }
                    } else { None };
                    #[cfg(not(target_os = "macos"))]
                    let selected: Option<String> = None;
                    let changed = if let Some(interface) = selected {
                        desktop.as_mut().unwrap().select_interface(&interface)
                    } else {
                        desktop.as_mut().unwrap().refresh()
                    };
                    match changed {
                        Ok(true) => {
                            #[cfg(target_os = "macos")]
                            if let Some(dns) = &mut system_dns {
                                let interface = desktop.as_ref().and_then(|tun| tun.hooks.network().ipv4).context("automatic DNS lost its IPv4 physical exit")?;
                                let address = meta_platform::desktop::local_ipv4_address(&interface)?;
                                if Some(address) != system_dns_address {
                                    running.rebind_system_dns(std::net::SocketAddr::new(address.into(), 53)).await?;
                                    system_dns_address = Some(address);
                                }
                                dns.refresh(&interface.name, address)?;
                                tracing::debug!(interface = %interface.name, "macOS system DNS checked after network change");
                            }
                            core.network_changed().await;
                            tracing::info!(network = ?desktop.as_ref().unwrap().hooks.network(), "physical egress changed; sessions closed for reconnect");
                        },
                        Ok(false) => {},
                        Err(error) => break Err(error.context("cannot update TUN routing")),
                    }
                },
            }
        } }.await;
    let mut cleanup = Ok(());
    #[cfg(target_os = "macos")]
    if let Some(dns) = &mut system_dns {
        cleanup = dns.restore();
    }
    running.shutdown().await;
    if let Some(desktop) = &mut desktop {
        let restored = desktop.restore();
        if cleanup.is_ok() {
            cleanup = restored;
        }
    }
    tracing::info!("proxy core stopped");
    result.and(cleanup)
}

#[cfg(test)]
mod dns_route_tests {
    use super::*;

    #[test]
    fn physical_upstreams_include_literal_public_dns_only() {
        let mut dns = meta_config::Dns {
            nameserver: vec!["223.5.5.5".into(), "udp://119.29.29.29:53".into()],
            default_nameserver: vec!["223.5.5.5".into()],
            proxy_server_nameserver: vec!["https://doh.pub/dns-query".into()],
            ..meta_config::Dns::default()
        };
        dns.nameserver_policy.insert(
            "*.example.com".into(),
            meta_config::Strings::Many(vec![
                "https://223.6.6.6/dns-query".into(),
                "192.168.2.50".into(),
            ]),
        );
        assert_eq!(
            physical_dns_upstreams(&dns),
            vec![
                "119.29.29.29".parse::<IpAddr>().unwrap(),
                "223.5.5.5".parse::<IpAddr>().unwrap(),
                "223.6.6.6".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn reachable_public_egress_beats_proxy_only_interface() {
        assert_eq!(best_egress_index(&[0, 1], &[2, 1]), Some(1));
        assert_eq!(best_egress_index(&[1, 1], &[0, 2]), Some(1));
        assert_eq!(best_egress_index(&[0, 0], &[1, 1]), Some(0));
        assert_eq!(best_egress_index(&[0, 0], &[0, 0]), None);
    }
}
