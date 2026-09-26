//! Desktop routing policy. The embeddable core never owns system configuration.
use crate::{PlatformHooks, native::NativeTun};
use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use route_manager::{Route, RouteManager};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitInterface {
    pub index: u32,
    pub name: String,
    pub gateway: Option<IpAddr>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Network {
    pub ipv4: Option<ExitInterface>,
    pub ipv6: Option<ExitInterface>,
    pub dns_servers: Vec<IpAddr>,
    pub local_networks: Vec<IpNet>,
}

#[cfg(target_os = "macos")]
pub fn local_ipv4_address(interface: &ExitInterface) -> Result<std::net::Ipv4Addr> {
    let device = netdev::get_interfaces()
        .into_iter()
        .find(|device| device.index == interface.index && device.name == interface.name)
        .context("physical DNS interface disappeared")?;
    ensure!(device.is_up() && !device.is_loopback() && !device.is_tun(), "invalid physical DNS interface");
    device
        .ipv4
        .iter()
        .map(|network| network.addr())
        .find(|address| !address.is_unspecified() && !address.is_link_local())
        .context("physical DNS interface has no usable IPv4 address")
}

#[cfg(windows)]
fn interface_metric(index: u32, ipv6: bool) -> Result<u32> {
    use windows_sys::Win32::{
        NetworkManagement::IpHelper::{
            GetIpInterfaceEntry, InitializeIpInterfaceEntry, MIB_IPINTERFACE_ROW,
        },
        Networking::WinSock::{AF_INET, AF_INET6},
    };
    let mut row = MIB_IPINTERFACE_ROW::default();
    // Initialize/query only: this does not change interface configuration.
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.InterfaceIndex = index;
    row.Family = if ipv6 { AF_INET6 } else { AF_INET };
    let result = unsafe { GetIpInterfaceEntry(&mut row) };
    if result != 0 {
        return Err(std::io::Error::from_raw_os_error(result as i32).into());
    }
    Ok(row.Metric)
}

#[cfg(windows)]
fn order_windows_routes(routes: &mut Vec<Route>, mut metric: impl FnMut(u32, bool) -> Option<u32>) {
    let mut ordered: Vec<_> = routes
        .drain(..)
        .filter_map(|route| {
            let interface = metric(route.if_index()?, route.destination().is_ipv6())?;
            let cost = u64::from(route.metric()?) + u64::from(interface);
            Some((cost, route))
        })
        .collect();
    ordered.sort_by_key(|(cost, _)| *cost);
    routes.extend(ordered.into_iter().map(|(_, route)| route));
}

pub fn discover(interface: Option<&str>, excluded_index: Option<u32>) -> Result<Network> {
    let interfaces = netdev::get_interfaces();
    let mut routes = RouteManager::new()?.list()?;
    routes.retain(|r| r.prefix() == 0 && r.if_index() != excluded_index);
    #[cfg(windows)]
    order_windows_routes(&mut routes, |index, ipv6| {
        match interface_metric(index, ipv6) {
            Ok(metric) => Some(metric),
            Err(error) => {
                tracing::debug!(index, ipv6, %error, "skipping unavailable egress interface");
                None
            }
        }
    });
    #[cfg(not(windows))]
    routes.sort_by_key(|r| {
        #[cfg(target_os = "linux")]
        {
            r.metric().unwrap_or(u32::MAX)
        }
        #[cfg(target_os = "macos")]
        {
            let _ = r;
            0
        }
    });
    let choose = |v6| -> Option<ExitInterface> {
        routes
            .iter()
            .filter(|r| r.destination().is_ipv6() == v6)
            .find_map(|r| {
                let index = r.if_index()?;
                let device = interfaces.iter().find(|i| i.index == index)?;
                if !device.is_up() || device.is_loopback() || device.is_tun() {
                    return None;
                }
                if let Some(name) = interface {
                    if device.name != name
                        && device.friendly_name.as_deref() != Some(name)
                        && index.to_string() != name
                    {
                        return None;
                    }
                } else if !device.is_physical() {
                    return None;
                }
                Some(ExitInterface {
                    index,
                    name: device.name.clone(),
                    gateway: r.gateway().filter(|ip| !ip.is_unspecified()),
                })
            })
    };
    let ipv4 = choose(false);
    let ipv6 = choose(true);
    let mut local_networks = Vec::new();
    for interface in &interfaces {
        if ipv4
            .as_ref()
            .is_some_and(|exit| exit.index == interface.index)
        {
            local_networks.extend(
                interface
                    .ipv4
                    .iter()
                    .copied()
                    .map(IpNet::V4)
                    .map(|prefix| prefix.trunc()),
            );
        }
        if ipv6
            .as_ref()
            .is_some_and(|exit| exit.index == interface.index)
        {
            local_networks.extend(
                interface
                    .ipv6
                    .iter()
                    .copied()
                    .map(IpNet::V6)
                    .map(|prefix| prefix.trunc()),
            );
        }
    }
    local_networks.sort();
    local_networks.dedup();
    let mut network = Network {
        ipv4,
        ipv6,
        dns_servers: interfaces
            .iter()
            .filter(|i| i.is_up() && Some(i.index) != excluded_index)
            .flat_map(|i| i.dns_servers.iter().copied())
            .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
            .collect(),
        local_networks,
    };
    network.dns_servers.sort();
    network.dns_servers.dedup();
    Ok(network)
}

#[cfg(target_os = "macos")]
pub fn ipv4_egress_candidates() -> Result<Vec<ExitInterface>> {
    let interfaces = netdev::get_interfaces();
    let mut candidates = Vec::new();
    for route in RouteManager::new()?.list()? {
        if route.prefix() != 0 || !route.destination().is_ipv4() {
            continue;
        }
        let Some(index) = route.if_index() else {
            continue;
        };
        let Some(device) = interfaces.iter().find(|device| device.index == index) else {
            continue;
        };
        if !device.is_up() || !device.is_physical() || device.is_loopback() || device.is_tun() {
            continue;
        }
        if candidates
            .iter()
            .any(|candidate: &ExitInterface| candidate.index == index)
        {
            continue;
        }
        candidates.push(ExitInterface {
            index,
            name: device.name.clone(),
            gateway: route.gateway().filter(|ip| !ip.is_unspecified()),
        });
    }
    Ok(candidates)
}

#[derive(Debug)]
pub struct EgressHooks {
    network: RwLock<Network>,
}
impl EgressHooks {
    pub fn new(network: Network) -> Self {
        Self {
            network: RwLock::new(network),
        }
    }
    pub fn network(&self) -> Network {
        self.network.read().unwrap().clone()
    }
    fn replace(&self, network: Network) {
        *self.network.write().unwrap() = network;
    }
}
impl PlatformHooks for EgressHooks {
    fn egress_description(&self, destination: SocketAddr) -> Option<String> {
        let network = self.network.read().unwrap();
        let interface = if destination.is_ipv4() { &network.ipv4 } else { &network.ipv6 };
        interface.as_ref().map(|interface| format!("{} index={} gateway={:?}", interface.name, interface.index, interface.gateway))
    }
    fn protect_socket(&self, socket: &socket2::Socket) -> Result<()> {
        self.prepare_socket(socket, None)
    }
    fn prepare_socket(
        &self,
        socket: &socket2::Socket,
        destination: Option<SocketAddr>,
    ) -> Result<()> {
        if destination.is_some_and(|d| d.ip().is_loopback()) {
            return Ok(());
        }
        let v6 = destination
            .context("physical egress requires a socket destination")?
            .is_ipv6();
        let network = self.network.read().unwrap();
        let interface = if v6 { &network.ipv6 } else { &network.ipv4 };
        let interface = interface
            .as_ref()
            .context("no physical egress for this address family")?;
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            use windows_sys::Win32::Networking::WinSock::{
                IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, WSAGetLastError,
                setsockopt,
            };
            let (level, option, index) = if v6 {
                (IPPROTO_IPV6, IPV6_UNICAST_IF, interface.index)
            } else {
                (IPPROTO_IP, IP_UNICAST_IF, interface.index.to_be())
            };
            // Winsock expects a network-order IPv4 interface index, host-order IPv6.
            let result = unsafe {
                setsockopt(
                    socket.as_raw_socket() as usize,
                    level,
                    option,
                    (&index as *const u32).cast(),
                    4,
                )
            };
            if result != 0 {
                return Err(std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() }).into());
            }
        }
        #[cfg(target_os = "macos")]
        {
            let index = std::num::NonZeroU32::new(interface.index)
                .context("invalid egress interface index")?;
            if v6 {
                socket.bind_device_by_index_v6(Some(index))?;
            } else {
                socket.bind_device_by_index_v4(Some(index))?;
            }
        }
        #[cfg(target_os = "linux")]
        socket.bind_device(Some(interface.name.as_bytes()))?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RouteSpec {
    network: IpNet,
    interface: ExitInterface,
}
impl RouteSpec {
    fn route(&self) -> Route {
        let mut route = Route::new(self.network.network(), self.network.prefix_len())
            .with_if_index(self.interface.index);
        if let Some(gateway) = self.interface.gateway {
            route = route.with_gateway(gateway);
        }
        #[cfg(any(windows, target_os = "linux"))]
        {
            route = route.with_metric(7);
        }
        #[cfg(target_os = "linux")]
        {
            route = route.with_table(254);
        }
        route
    }
    fn matches(&self, route: &Route) -> bool {
        #[cfg(any(windows, target_os = "linux"))]
        if route.metric() != Some(7) {
            return false;
        }
        self.network.network() == route.network()
            && self.network.prefix_len() == route.prefix()
            && route.if_index() == Some(self.interface.index)
            && route.gateway().filter(|ip| !ip.is_unspecified()) == self.interface.gateway
    }
}

trait Routes {
    fn list(&mut self) -> Result<Vec<Route>>;
    fn add(&mut self, route: &Route) -> Result<()>;
    fn delete(&mut self, route: &Route) -> Result<()>;
}
impl Routes for RouteManager {
    fn list(&mut self) -> Result<Vec<Route>> {
        Ok(RouteManager::list(self)?)
    }
    fn add(&mut self, route: &Route) -> Result<()> {
        Ok(RouteManager::add(self, route)?)
    }
    fn delete(&mut self, route: &Route) -> Result<()> {
        Ok(RouteManager::delete(self, route)?)
    }
}
#[derive(Serialize, Deserialize)]
struct Journal {
    format: u32,
    platform: String,
    routes: Vec<RouteSpec>,
    dns_servers: Vec<IpAddr>,
}
struct Transaction {
    path: PathBuf,
    journal: Journal,
    _lock: File,
}
impl Transaction {
    fn open(directory: &Path) -> Result<Self> {
        std::fs::create_dir_all(directory)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("clyntis-tun.lock"))?;
        lock.try_lock()
            .context("another TUN instance owns this state directory")?;
        let path = directory.join("clyntis-tun-state.json");
        let journal = if path.exists() {
            let mut bytes = vec![];
            File::open(&path)?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 1024 * 1024, "TUN journal size limit");
            let journal: Journal =
                serde_json::from_slice(&bytes).context("invalid TUN recovery journal")?;
            ensure!(
                journal.format == 1
                    && journal.platform == std::env::consts::OS
                    && journal.routes.len() <= 4096,
                "unsupported TUN journal"
            );
            journal
        } else {
            Journal {
                format: 1,
                platform: std::env::consts::OS.into(),
                routes: vec![],
                dns_servers: vec![],
            }
        };
        Ok(Self {
            path,
            journal,
            _lock: lock,
        })
    }
    fn save(&self) -> Result<()> {
        let temporary = self
            .path
            .with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(&self.journal)?)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, &self.path)?;
        #[cfg(unix)]
        File::open(self.path.parent().context("TUN state directory missing")?)?.sync_all()?;
        Ok(())
    }
    fn apply(&mut self, desired: Vec<RouteSpec>, backend: &mut impl Routes) -> Result<()> {
        let present = backend.list()?;
        for spec in &desired {
            if present.iter().any(|r| spec.matches(r)) {
                continue;
            }
            if !self.journal.routes.contains(spec) {
                ensure!(self.journal.routes.len() < 4096, "TUN journal route limit");
                self.journal.routes.push(spec.clone());
                self.save()?;
            }
            backend
                .add(&spec.route())
                .with_context(|| format!("cannot add TUN route {}", spec.network))?;
        }
        let obsolete: Vec<_> = self
            .journal
            .routes
            .iter()
            .filter(|r| !desired.contains(r))
            .cloned()
            .collect();
        for spec in obsolete {
            self.remove(&spec, backend)?;
            self.journal.routes.retain(|r| r != &spec);
            self.save()?;
        }
        Ok(())
    }
    fn remove(&self, spec: &RouteSpec, backend: &mut impl Routes) -> Result<()> {
        for route in backend.list()?.into_iter().filter(|r| spec.matches(r)) {
            backend.delete(&route)?;
        }
        Ok(())
    }
    fn restore(&mut self, backend: &mut impl Routes) -> Result<()> {
        for spec in self.journal.routes.clone().into_iter().rev() {
            self.remove(&spec, backend)?;
            self.journal.routes.retain(|r| r != &spec);
            self.save()?;
        }
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}

pub struct DesktopTun {
    pub device: Arc<NativeTun>,
    pub hooks: Arc<EgressHooks>,
    transaction: Transaction,
    tunnel: ExitInterface,
    selected_interface: Option<String>,
    exclusions: Vec<IpNet>,
    auto_route: bool,
    ipv6: bool,
    capture_dns: bool,
    upstream_dns: Vec<IpAddr>,
}
pub struct Options<'a> {
    pub name: &'a str,
    pub mtu: u16,
    pub ipv6: bool,
    pub auto_route: bool,
    pub interface: Option<&'a str>,
    pub exclusions: &'a [IpNet],
    pub capture_dns: bool,
    pub upstream_dns: &'a [IpAddr],
    pub directory: &'a Path,
}

fn built_in_local_exclusions(network: &Network, ipv6: bool) -> Result<Vec<IpNet>> {
    let mut prefixes: Vec<_> = network.local_networks.iter().map(IpNet::trunc).collect();
    for prefix in [
        "169.254.0.0/16",
        "224.0.0.0/4",
        "255.255.255.255/32",
        "fe80::/10",
        "ff00::/8",
    ] {
        let prefix: IpNet = prefix.parse()?;
        if prefix.addr().is_ipv4() || ipv6 {
            prefixes.push(prefix);
        }
    }
    prefixes.retain(|prefix| prefix.addr().is_ipv4() || ipv6);
    prefixes.sort();
    prefixes.dedup();
    Ok(prefixes)
}

fn tun_capture_prefixes(ipv6: bool) -> Result<Vec<IpNet>> {
    // XNU's SA_DEFAULT/rt_primary_default checks the destination address,
    // not the prefix length. A 0.0.0.0/1 or ::/1 route can therefore alter the
    // primary scope and shadow node_lookup_default for IP_BOUND_IF sockets.
    // Match sing-tun's Darwin BuildAutoRouteRanges: leave 0/8 and ::/8 alone
    // and cover the remaining space without any zero-address route key.
    #[cfg(target_os = "macos")]
    let prefixes = &[
        "1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5",
        "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1",
        "100::/8", "200::/7", "400::/6", "800::/5",
        "1000::/4", "2000::/3", "4000::/2", "8000::/1",
    ][..];
    #[cfg(not(target_os = "macos"))]
    let prefixes = &["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"][..];
    let prefixes = prefixes.iter().map(|prefix| prefix.parse()).collect::<Result<Vec<IpNet>, _>>()?;
    Ok(prefixes.into_iter().filter(|prefix| ipv6 || prefix.addr().is_ipv4()).collect())
}

impl DesktopTun {
    pub fn open(options: Options<'_>) -> Result<Self> {
        let transaction = Transaction::open(options.directory)?;
        ensure!(
            transaction.journal.routes.is_empty(),
            "unfinished TUN state exists; run --recover-tun before starting"
        );
        let network = discover(options.interface, None)?;
        ensure!(
            network.ipv4.is_some() || network.ipv6.is_some(),
            "no physical exit found; configure tun.interface explicitly"
        );
        let device = Arc::new(NativeTun::open(options.name, options.mtu, options.ipv6)?);
        let index = device.index()?;
        let name = netdev::get_interfaces()
            .into_iter()
            .find(|i| i.index == index)
            .context("created TUN interface missing")?
            .name;
        let mut desktop = Self {
            device,
            hooks: Arc::new(EgressHooks::new(network)),
            transaction,
            tunnel: ExitInterface {
                index,
                name,
                gateway: None,
            },
            selected_interface: options.interface.map(str::to_owned),
            exclusions: options.exclusions.to_vec(),
            auto_route: options.auto_route,
            ipv6: options.ipv6,
            capture_dns: options.capture_dns,
            upstream_dns: options.upstream_dns.to_vec(),
        };
        let desired = desktop.desired_routes()?;
        desktop.transaction.journal.dns_servers = desktop.hooks.network().dns_servers;
        desktop
            .transaction
            .apply(desired, &mut RouteManager::new()?)?;
        Ok(desktop)
    }
    fn desired_routes(&self) -> Result<Vec<RouteSpec>> {
        if !self.auto_route {
            return Ok(vec![]);
        }
        let network = self.hooks.network();
        let mut routes = vec![];
        for prefix in tun_capture_prefixes(self.ipv6)? {
            routes.push(RouteSpec {
                network: prefix,
                interface: self.tunnel.clone(),
            });
        }
        if self.capture_dns {
            for ip in network.dns_servers.iter().copied() {
                if ip.is_ipv6() && !self.ipv6 {
                    continue;
                }
                routes.push(RouteSpec {
                    network: IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 })?,
                    interface: self.tunnel.clone(),
                });
            }
        }
        #[cfg(target_os = "macos")]
        for ip in self.upstream_dns.iter().copied() {
            let interface = if ip.is_ipv4() {
                &network.ipv4
            } else {
                &network.ipv6
            };
            if let Some(interface) = interface {
                routes.push(RouteSpec {
                    network: IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 })?,
                    interface: interface.clone(),
                });
            }
        }
        for prefix in built_in_local_exclusions(&network, self.ipv6)? {
            let interface = if prefix.addr().is_ipv4() {
                &network.ipv4
            } else {
                &network.ipv6
            };
            let Some(interface) = interface else {
                continue;
            };
            let mut interface = interface.clone();
            // These destinations are on-link. Sending them through the default
            // gateway can break limited broadcast and neighbor discovery.
            interface.gateway = None;
            routes.push(RouteSpec {
                network: prefix,
                interface,
            });
        }
        for prefix in &self.exclusions {
            let interface = if prefix.addr().is_ipv4() {
                &network.ipv4
            } else {
                &network.ipv6
            };
            let Some(interface) = interface else {
                continue;
            };
            routes.push(RouteSpec {
                network: *prefix,
                interface: interface.clone(),
            });
        }
        routes.dedup();
        Ok(routes)
    }
    pub fn refresh(&mut self) -> Result<bool> {
        let mut network = discover(self.selected_interface.as_deref(), Some(self.tunnel.index))?;
        let previous = self.hooks.network();
        // DNS settings may change when the macOS service is pointed at our
        // local listener. Without DNS host routes this is not an egress change.
        if !self.capture_dns {
            network.dns_servers = previous.dns_servers.clone();
        }
        if network == previous {
            return Ok(false);
        }
        self.hooks.replace(network.clone());
        self.transaction.journal.dns_servers = network.dns_servers;
        self.transaction
            .apply(self.desired_routes()?, &mut RouteManager::new()?)?;
        Ok(true)
    }
    pub fn select_interface(&mut self, interface: &str) -> Result<bool> {
        self.selected_interface = Some(interface.to_owned());
        self.refresh()
    }
    pub fn restore(&mut self) -> Result<()> {
        self.transaction.restore(&mut RouteManager::new()?)
    }
}
impl Drop for DesktopTun {
    fn drop(&mut self) {
        if !self.transaction.journal.routes.is_empty()
            && let Err(error) = self.restore()
        {
            tracing::error!(%error, "TUN restore failed; recovery journal retained");
        }
    }
}
pub fn recover(directory: &Path) -> Result<()> {
    let mut transaction = Transaction::open(directory)?;
    let interfaces = netdev::get_interfaces();
    // Interface indices can be reused after reboot. Never touch a new adapter.
    transaction.journal.routes.retain(|r| {
        interfaces
            .iter()
            .any(|i| i.index == r.interface.index && i.name == r.interface.name)
    });
    transaction.restore(&mut RouteManager::new()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_capture_preserves_default_route_keys_and_has_no_gaps() {
        let prefixes = tun_capture_prefixes(true).unwrap();
        assert!(prefixes.iter().all(|prefix| !prefix.network().is_unspecified()));
        let v4: Vec<_> = prefixes.iter().filter_map(|prefix| match prefix {
            IpNet::V4(net) => Some(*net), _ => None,
        }).collect();
        assert_eq!(v4.first().unwrap().network(), "1.0.0.0".parse::<std::net::Ipv4Addr>().unwrap());
        assert_eq!(v4.last().unwrap().broadcast(), std::net::Ipv4Addr::BROADCAST);
        for pair in v4.windows(2) {
            assert_eq!(u32::from(pair[0].broadcast()).checked_add(1), Some(u32::from(pair[1].network())));
        }
        let v6: Vec<_> = prefixes.iter().filter_map(|prefix| match prefix {
            IpNet::V6(net) => Some(*net), _ => None,
        }).collect();
        assert_eq!(v6.first().unwrap().network(), "100::".parse::<std::net::Ipv6Addr>().unwrap());
        assert_eq!(u128::from(v6.last().unwrap().broadcast()), u128::MAX);
        for pair in v6.windows(2) {
            assert_eq!(u128::from(pair[0].broadcast()).checked_add(1), Some(u128::from(pair[1].network())));
        }
        let v4_only = tun_capture_prefixes(false).unwrap();
        assert_eq!(v4_only.len(), v4.len());
        for target in ["17.137.162.3", "173.242.123.155", "28.0.0.52", "106.11.35.100"] {
            let target: IpAddr = target.parse().unwrap();
            assert_eq!(v4_only.iter().filter(|net| net.contains(&target)).count(), 1);
        }
    }
    #[cfg(windows)]
    #[test]
    fn windows_route_order_includes_family_specific_interface_metrics() {
        let a = Route::new("0.0.0.0".parse().unwrap(), 0)
            .with_if_index(1)
            .with_metric(1);
        let b = Route::new("0.0.0.0".parse().unwrap(), 0)
            .with_if_index(2)
            .with_metric(20);
        let v6 = Route::new("::".parse().unwrap(), 0)
            .with_if_index(1)
            .with_metric(1);
        let missing = Route::new("::".parse().unwrap(), 0)
            .with_if_index(3)
            .with_metric(0);
        let large = Route::new("::".parse().unwrap(), 0)
            .with_if_index(2)
            .with_metric(u32::MAX);
        let mut routes = vec![a.clone(), b.clone(), missing, large.clone(), v6.clone()];
        order_windows_routes(&mut routes, |index, ipv6| match (index, ipv6) {
            (1, false) => Some(100),
            (1, true) => Some(2),
            (2, _) => Some(5),
            _ => None,
        });
        assert_eq!(routes, vec![v6, b, a, large]);
    }
    #[cfg(windows)]
    #[test]
    fn windows_interface_metric_query_uses_live_os_interface() {
        let loopback = netdev::get_interfaces()
            .into_iter()
            .find(|i| i.is_loopback())
            .unwrap();
        assert!(interface_metric(loopback.index, false).is_ok());
        assert!(interface_metric(u32::MAX, false).is_err());
    }
    #[test]
    fn local_routes_are_excluded_from_tun_by_default() {
        let network = Network {
            local_networks: vec![
                "192.168.2.60/24".parse::<IpNet>().unwrap(),
                "2001:db8:1::20/64".parse::<IpNet>().unwrap(),
            ],
            ..Network::default()
        };
        let ipv4 = built_in_local_exclusions(&network, false).unwrap();
        assert!(ipv4.contains(&"192.168.2.0/24".parse().unwrap()));
        assert!(ipv4.contains(&"169.254.0.0/16".parse().unwrap()));
        assert!(ipv4.contains(&"224.0.0.0/4".parse().unwrap()));
        assert!(ipv4.contains(&"255.255.255.255/32".parse().unwrap()));
        assert!(!ipv4.iter().any(|prefix| prefix.addr().is_ipv6()));

        let dual_stack = built_in_local_exclusions(&network, true).unwrap();
        assert!(dual_stack.contains(&"2001:db8:1::/64".parse().unwrap()));
        assert!(dual_stack.contains(&"fe80::/10".parse().unwrap()));
        assert!(dual_stack.contains(&"ff00::/8".parse().unwrap()));
    }
    #[derive(Default)]
    struct MemoryRoutes {
        routes: Vec<Route>,
        fail_after: usize,
    }
    impl Routes for MemoryRoutes {
        fn list(&mut self) -> Result<Vec<Route>> {
            Ok(self.routes.clone())
        }
        fn add(&mut self, route: &Route) -> Result<()> {
            ensure!(self.routes.len() < self.fail_after, "injected add failure");
            self.routes.push(route.clone());
            Ok(())
        }
        fn delete(&mut self, route: &Route) -> Result<()> {
            self.routes.retain(|r| r != route);
            Ok(())
        }
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_route_transaction_preserves_physical_default() {
        let directory = std::env::temp_dir().join(format!("clyntis-default-route-{}", uuid::Uuid::new_v4()));
        let default = Route::new("0.0.0.0".parse().unwrap(), 0)
            .with_gateway("192.168.2.1".parse().unwrap()).with_if_index(14);
        let mut backend = MemoryRoutes { routes: vec![default.clone()], fail_after: usize::MAX };
        let mut transaction = Transaction::open(&directory).unwrap();
        let desired = tun_capture_prefixes(false).unwrap().into_iter().map(|network| RouteSpec {
            network, interface: ExitInterface { index: 99, name: "test-tun".into(), gateway: None },
        }).collect();
        transaction.apply(desired, &mut backend).unwrap();
        let zero_keys: Vec<_> = backend.routes.iter().filter(|route| route.destination().is_unspecified()).collect();
        assert_eq!(zero_keys, vec![&default]);
        transaction.restore(&mut backend).unwrap();
        assert_eq!(backend.routes, vec![default]);
        drop(transaction);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn route_failure_recovery_and_exclusive_lifecycle() {
        let directory =
            std::env::temp_dir().join(format!("clyntis-routes-{}", uuid::Uuid::new_v4()));
        let interface = ExitInterface {
            index: 999,
            name: "test-tun".into(),
            gateway: None,
        };
        let desired: Vec<_> = ["0.0.0.0/1", "128.0.0.0/1"]
            .into_iter()
            .map(|s| RouteSpec {
                network: s.parse().unwrap(),
                interface: interface.clone(),
            })
            .collect();
        let mut backend = MemoryRoutes {
            routes: vec![Route::new("192.0.2.0".parse().unwrap(), 24).with_if_index(1)],
            fail_after: 2,
        };
        let mut transaction = Transaction::open(&directory).unwrap();
        assert!(Transaction::open(&directory).is_err());
        assert!(transaction.apply(desired, &mut backend).is_err());
        assert_eq!(backend.routes.len(), 2);
        drop(transaction);
        let mut recovered = Transaction::open(&directory).unwrap();
        recovered.restore(&mut backend).unwrap();
        assert_eq!(backend.routes.len(), 1);
        assert_eq!(
            backend.routes[0].destination(),
            "192.0.2.0".parse::<IpAddr>().unwrap()
        );
        assert!(!recovered.path.exists());
        drop(recovered);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
