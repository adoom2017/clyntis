//! Shared desktop lifecycle. Each process runs a single core (and logging subscriber).
pub mod logging;
#[cfg(target_os = "macos")]
use anyhow::ensure;
use anyhow::{Context, Result};
use clyntis_config::Config;
#[cfg(target_os = "macos")]
use clyntis_config::ProxyKind;
use clyntis_core::Core;
use clyntis_platform::{
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

/// Load routing resources into `config.directory`, downloading only missing files.
/// Runs without TUN or listeners, so hosts can fetch resources over the ordinary
/// network before a TUN session takes over routing.
pub async fn prefetch_resources(mut config: Config) -> Result<()> {
    config.tun.enable = false;
    Core::new(config, Arc::new(DefaultHooks))?
        .prepare_resources(false)
        .await
}

pub fn recover(directory: &std::path::Path) -> Result<()> {
    // Attempt both journals even when one recovery fails.
    let routes = clyntis_platform::desktop::recover(directory);
    #[cfg(target_os = "macos")]
    let dns = clyntis_platform::macos_dns::recover(directory);
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

/// Reports the network behind the physical exit (the default interface
/// without a TUN) to the core for its `network-overrides`, when it differs
/// from the last report. The Wi-Fi name is not read on desktops: macOS and
/// Windows only give it to apps with location access.
fn report_network(
    core: &Core,
    exit: Option<&clyntis_platform::desktop::ExitInterface>,
    last: &mut Option<clyntis_platform::desktop::NetworkFacts>,
) {
    if core.config.networks.is_empty() {
        return;
    }
    let facts = clyntis_platform::desktop::network_facts(exit);
    if last.as_ref() == Some(&facts) {
        return;
    }
    let info = clyntis_config::network::NetworkInfo {
        kind: facts.kind.map(Into::into),
        ssid: None,
        addresses: facts.addresses.clone(),
        gateways: facts.gateways.clone(),
    };
    *last = Some(facts);
    if let Err(error) = core.set_network(info) {
        tracing::warn!(error = %format!("{error:#}"), "network overrides not applied");
    }
}

fn physical_dns_upstreams(
    dns: &clyntis_config::Dns,
    overrides: &[clyntis_config::network::NetworkOverride],
) -> Vec<IpAddr> {
    let mut addresses: Vec<_> = dns
        .nameserver
        .iter()
        .chain(&dns.default_nameserver)
        .chain(&dns.proxy_server_nameserver)
        .cloned()
        .chain(
            dns.nameserver_policy
                .values()
                .chain(overrides.iter().flat_map(|o| o.nameserver_policy.values()))
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
/// The best reachable egress: internet access first, then proxies reached,
/// then a wired link over Wi-Fi. `current` is kept unless another candidate
/// ranks higher on those: one lost public probe must not switch interfaces,
/// since every switch closes all sessions and the next probe would usually
/// switch straight back.
fn best_egress_index(
    public_scores: &[usize],
    proxy_scores: &[usize],
    wired: &[bool],
    current: Option<usize>,
) -> Option<usize> {
    let rank = |index: usize| {
        (
            public_scores[index] > 0,
            proxy_scores[index],
            wired.get(index).copied().unwrap_or(false),
        )
    };
    let best = (0..public_scores.len())
        .filter(|&index| public_scores[index] > 0 || proxy_scores[index] > 0)
        .max_by_key(|&index| (rank(index), public_scores[index], std::cmp::Reverse(index)))?;
    match current {
        Some(current) if current < public_scores.len() && rank(current) >= rank(best) => {
            Some(current)
        }
        _ => Some(best),
    }
}

/// Interfaces that recently lost their default route, kept out of egress
/// probes for a while: a flapping cable or dock must not pull every session
/// back onto it each time it comes up. Repeated losses double the wait.
#[cfg(target_os = "macos")]
#[derive(Default)]
struct EgressCooldowns(
    std::collections::HashMap<String, (std::time::Instant, std::time::Duration)>,
);

#[cfg(target_os = "macos")]
impl EgressCooldowns {
    const FIRST: std::time::Duration = std::time::Duration::from_secs(30);
    const LONGEST: std::time::Duration = std::time::Duration::from_secs(300);

    /// Records a loss and returns how long the interface stays out.
    fn lost(&mut self, interface: &str, now: std::time::Instant) -> std::time::Duration {
        let period = match self.0.get(interface) {
            // Lost again soon after it was allowed back: it is still flapping.
            Some(&(until, period)) if now < until + period * 2 => (period * 2).min(Self::LONGEST),
            _ => Self::FIRST,
        };
        self.0.insert(interface.to_owned(), (now + period, period));
        period
    }

    fn active(&mut self, now: std::time::Instant) -> Vec<String> {
        self.0
            .retain(|_, (until, period)| now < *until + *period * 2);
        self.0
            .iter()
            .filter(|(_, (until, _))| now < *until)
            .map(|(name, _)| name.clone())
            .collect()
    }
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
async fn verify_macos_system_dns(dns: &clyntis_config::Dns) -> Result<()> {
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
    current: Option<&str>,
    avoid: &[String],
) -> Result<Option<String>> {
    use clyntis_platform::desktop::{EgressHooks, Network, ipv4_egress_candidates};
    use std::time::Duration;

    if config.tun.interface.is_some() || !config.tun.auto_detect_interface {
        return Ok(None);
    }
    let mut candidates = ipv4_egress_candidates()?;
    // Interfaces that just went away stay out while another one is up.
    if candidates.iter().any(|c| !avoid.contains(&c.name)) {
        candidates.retain(|c| !avoid.contains(&c.name));
    }
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
        proxy_targets = physical_dns_upstreams(&config.dns, &config.network_overrides)
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
                    clyntis_platform::tcp_connect(target, &*hooks),
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
    let current = current.and_then(|name| candidates.iter().position(|c| c.name == name));
    let wired: Vec<bool> = candidates
        .iter()
        .map(|candidate| clyntis_platform::desktop::is_wired(candidate.index))
        .collect();
    let selected = best_egress_index(&public_scores, &proxy_scores, &wired, current);
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
        physical_dns_upstreams(&config.dns, &config.network_overrides)
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
        detect_macos_egress(&config, &public_targets, "before TUN", None, &[]).await?
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
            replaceable_interface: config.tun.interface.is_none(),
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
        let after = detect_macos_egress(&config, &public_targets, "after TUN", None, &[])
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
                detect_macos_egress(&config, &public_targets, "after TUN reselection", None, &[])
                    .await?;
            ensure!(
                verified.as_deref() == Some(after.as_str()),
                "physical egress changed during TUN setup; set tun.interface explicitly"
            );
        }
    }
    let hooks: clyntis_platform::Hooks = desktop
        .as_ref()
        .map(|d| d.hooks.clone() as clyntis_platform::Hooks)
        .unwrap_or_else(|| Arc::new(DefaultHooks));
    let packets = desktop
        .as_ref()
        .map(|d| d.device.clone() as Arc<dyn clyntis_platform::PacketIo>);
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
        Some(clyntis_platform::desktop::local_ipv4_address(&interface)?)
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
        let dns = clyntis_platform::macos_dns::MacDns::start(&directory, &interface.name, server)?;
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
    let mut reported = None;
    report_network(
        &core,
        desktop
            .as_ref()
            .and_then(|tun| tun.hooks.network().ipv4)
            .as_ref(),
        &mut reported,
    );
    #[cfg(target_os = "macos")]
    let mut next_egress_probe = tokio::time::Instant::now();
    #[cfg(target_os = "macos")]
    let (mut dns_pending, mut dns_waiting) = (false, false);
    #[cfg(target_os = "macos")]
    let mut cooldowns = EgressCooldowns::default();
    let result: Result<()> = async { loop {
            tokio::select! {
                _ = stop.cancelled() => break Ok(()),
                _ = core.stop.cancelled() => break Err(anyhow::anyhow!("proxy core stopped unexpectedly")),
                _ = refresh.tick(), if desktop.is_some() || !core.config.networks.is_empty() => {
                    if desktop.is_none() {
                        report_network(&core, None, &mut reported);
                        continue;
                    }
                    #[cfg(target_os = "macos")]
                    let selected = if tokio::time::Instant::now() >= next_egress_probe {
                        next_egress_probe = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
                        let current = desktop.as_ref().and_then(|tun| tun.hooks.network().ipv4).map(|exit| exit.name);
                        let avoid = cooldowns.active(std::time::Instant::now());
                        match detect_macos_egress(&core.config, &public_targets, "network refresh", current.as_deref(), &avoid).await {
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
                    #[cfg(target_os = "macos")]
                    if let Some(lost) = desktop.as_mut().unwrap().take_lost_interface() {
                        let period = cooldowns.lost(&lost, std::time::Instant::now());
                        // Probe the replacement on the next tick, not in 15 s.
                        next_egress_probe = tokio::time::Instant::now();
                        tracing::warn!(
                            interface = %lost,
                            replacement = ?desktop.as_ref().unwrap().hooks.network().ipv4.map(|exit| exit.name),
                            cooldown_secs = period.as_secs(),
                            "egress interface went away; using the current system exit"
                        );
                    }
                    // Also when only the address or gateway behind the same
                    // exit changed (another Wi-Fi on the same interface).
                    report_network(&core, desktop.as_ref().and_then(|tun| tun.hooks.network().ipv4).as_ref(), &mut reported);
                    match changed {
                        Ok(true) => {
                            #[cfg(target_os = "macos")]
                            if system_dns.is_some() {
                                dns_pending = true;
                            }
                            core.network_changed().await;
                            tracing::info!(network = ?desktop.as_ref().unwrap().hooks.network(), "physical egress changed; sessions closed for reconnect");
                        },
                        Ok(false) => {},
                        Err(error) => break Err(error.context("cannot update TUN routing")),
                    }
                    // Sleep, Wi-Fi roaming and DHCP renewals briefly leave no IPv4
                    // exit or address. Keep the TUN running and retry every tick
                    // instead of stopping the core; the system DNS keeps pointing
                    // at the previous listener until the network is back.
                    #[cfg(target_os = "macos")]
                    if dns_pending && let Some(dns) = &mut system_dns {
                        let synced = async {
                            let interface = desktop.as_ref().and_then(|tun| tun.hooks.network().ipv4).context("no IPv4 physical exit")?;
                            let address = clyntis_platform::desktop::local_ipv4_address(&interface)?;
                            if Some(address) != system_dns_address {
                                running.rebind_system_dns(std::net::SocketAddr::new(address.into(), 53)).await?;
                                system_dns_address = Some(address);
                            }
                            dns.refresh(&interface.name, address)?;
                            Ok::<_, anyhow::Error>(interface.name)
                        }.await;
                        match synced {
                            Ok(interface) => {
                                dns_pending = false;
                                dns_waiting = false;
                                tracing::info!(%interface, "macOS system DNS updated after network change");
                            }
                            Err(error) if !dns_waiting => {
                                dns_waiting = true;
                                tracing::warn!(error = %format!("{error:#}"), "automatic DNS waits for the network; retrying");
                            }
                            Err(error) => tracing::debug!(error = %format!("{error:#}"), "automatic DNS still waiting for the network"),
                        }
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
        let mut dns = clyntis_config::Dns {
            nameserver: vec!["223.5.5.5".into(), "udp://119.29.29.29:53".into()],
            default_nameserver: vec!["223.5.5.5".into()],
            proxy_server_nameserver: vec!["https://doh.pub/dns-query".into()],
            ..clyntis_config::Dns::default()
        };
        dns.nameserver_policy.insert(
            "*.example.com".into(),
            clyntis_config::Strings::Many(vec![
                "https://223.6.6.6/dns-query".into(),
                "192.168.2.50".into(),
            ]),
        );
        assert_eq!(
            physical_dns_upstreams(&dns, &[]),
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
        let wifi = [false, false];
        assert_eq!(best_egress_index(&[0, 1], &[2, 1], &wifi, None), Some(1));
        assert_eq!(best_egress_index(&[1, 1], &[0, 2], &wifi, None), Some(1));
        assert_eq!(best_egress_index(&[0, 0], &[1, 1], &wifi, None), Some(0));
        assert_eq!(best_egress_index(&[0, 0], &[0, 0], &wifi, None), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn wired_egress_wins_when_equally_reachable() {
        // Wi-Fi (index 0) listed before Ethernet (index 1).
        let kinds = [false, true];
        assert_eq!(best_egress_index(&[2, 2], &[1, 1], &kinds, None), Some(1));
        // Plugging in a working cable moves off Wi-Fi.
        assert_eq!(
            best_egress_index(&[2, 2], &[1, 1], &kinds, Some(0)),
            Some(1)
        );
        // One lost public probe on the cable does not.
        assert_eq!(
            best_egress_index(&[2, 1], &[1, 1], &kinds, Some(1)),
            Some(1)
        );
        // A cable without internet or proxy access loses to Wi-Fi.
        assert_eq!(best_egress_index(&[2, 0], &[1, 1], &kinds, None), Some(0));
        assert_eq!(
            best_egress_index(&[2, 2], &[1, 0], &kinds, Some(1)),
            Some(0)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn current_egress_survives_a_lost_public_probe() {
        // en7 (current) lost one of two public probes; en0 reached both.
        assert_eq!(
            best_egress_index(&[1, 2], &[1, 1], &[true, true], Some(0)),
            Some(0)
        );
        // Ties keep the current interface rather than the first one.
        assert_eq!(
            best_egress_index(&[2, 2], &[1, 1], &[true, true], Some(1)),
            Some(1)
        );
        // Switch when the current one loses the internet or a proxy.
        assert_eq!(
            best_egress_index(&[0, 2], &[1, 1], &[true, true], Some(0)),
            Some(1)
        );
        assert_eq!(
            best_egress_index(&[2, 2], &[0, 1], &[true, true], Some(0)),
            Some(1)
        );
        // A vanished current interface falls back to the best candidate.
        assert_eq!(best_egress_index(&[2], &[1], &[false], Some(3)), Some(0));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_flapping_interface_stays_out_longer_each_time() {
        use std::time::{Duration, Instant};
        let mut cooldowns = EgressCooldowns::default();
        let start = Instant::now();
        assert_eq!(cooldowns.lost("en7", start), Duration::from_secs(30));
        assert_eq!(cooldowns.active(start + Duration::from_secs(29)), ["en7"]);
        assert!(cooldowns.active(start + Duration::from_secs(31)).is_empty());
        // Lost again soon after coming back: twice as long.
        let again = start + Duration::from_secs(40);
        assert_eq!(cooldowns.lost("en7", again), Duration::from_secs(60));
        let mut at = again;
        for _ in 0..5 {
            at += Duration::from_secs(1);
            cooldowns.lost("en7", at);
        }
        assert_eq!(cooldowns.lost("en7", at), Duration::from_secs(300));
        // Stable for long enough: forgotten, the next loss starts over.
        let later = at + Duration::from_secs(300 * 3 + 1);
        assert!(cooldowns.active(later).is_empty());
        assert_eq!(cooldowns.lost("en7", later), Duration::from_secs(30));
    }
}

#[cfg(test)]
mod prefetch_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn prefetch_downloads_missing_files_and_then_reuses_them() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            // Exactly one request: the second prefetch must use the local copy.
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let _ = socket.read(&mut request).await;
            let body = "payload:\n  - DOMAIN-SUFFIX,ads.example\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        let directory = tempfile::tempdir().unwrap();
        let yaml = format!(
            "mixed-port: 0\nrule-providers:\n  ads:\n    type: http\n    behavior: classical\n    format: yaml\n    url: http://{address}/ads.yaml\n    path: ./rule_provider/ads.yaml\n    interval: 600\nrules:\n  - RULE-SET,ads,REJECT\n  - MATCH,DIRECT\ntun:\n  enable: true\n"
        );
        let mut config = Config::parse(yaml.as_bytes()).unwrap();
        config.directory = directory.path().into();
        prefetch_resources(config.clone()).await.unwrap();
        server.await.unwrap();
        let saved =
            std::fs::read_to_string(directory.path().join("rule_provider/ads.yaml")).unwrap();
        assert!(saved.contains("ads.example"));
        prefetch_resources(config).await.unwrap();
    }
}
