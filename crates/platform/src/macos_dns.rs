use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::Ipv4Addr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::Command,
};

const LEGACY_MANAGED_SERVER: &str = "127.0.0.1";
const STATE_FILE: &str = "clyntis-dns-state.json";

fn legacy_managed_server() -> String {
    LEGACY_MANAGED_SERVER.into()
}

#[derive(Deserialize, Serialize)]
struct State {
    service: String,
    servers: Vec<String>,
    #[serde(default = "legacy_managed_server")]
    managed_server: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SavedState {
    Services(Vec<State>),
    Legacy(State),
}

fn managed_services(list: &str, interfaces: &[String]) -> Vec<String> {
    let mut services: Vec<_> = interfaces.iter()
        .filter_map(|interface| service_for_interface(list, interface))
        .collect();
    services.sort();
    services.dedup();
    services
}

fn networksetup(args: &[&str]) -> Result<String> {
    let output = Command::new("/usr/sbin/networksetup")
        .args(args)
        .output()
        .context("cannot run networksetup")?;
    ensure!(
        output.status.success(),
        "networksetup {} failed: {}",
        args.first().copied().unwrap_or_default(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8(output.stdout)?)
}

fn service_for_interface(list: &str, interface: &str) -> Option<String> {
    let mut service = None;
    for line in list.lines().map(str::trim) {
        if let Some((number, name)) = line.strip_prefix('(').and_then(|s| s.split_once(") ")) {
            service = (number.chars().all(|c| c.is_ascii_digit()) && !name.starts_with('*'))
                .then(|| name.to_owned());
        } else if let Some(device) = line
            .strip_prefix("(Hardware Port: ")
            .and_then(|s| s.rsplit_once(", Device: "))
            .and_then(|(_, device)| device.strip_suffix(')'))
            && device == interface
        {
            return service;
        }
    }
    None
}

fn configured_servers(service: &str) -> Result<Vec<String>> {
    let output = networksetup(&["-getdnsservers", service])?;
    if output
        .trim()
        .starts_with("There aren't any DNS Servers set on ")
    {
        return Ok(vec![]);
    }
    let servers: Vec<_> = output.lines().map(str::trim).map(str::to_owned).collect();
    ensure!(
        !servers.is_empty()
            && servers
                .iter()
                .all(|s| s.parse::<std::net::IpAddr>().is_ok()),
        "unexpected networksetup DNS response"
    );
    Ok(servers)
}

fn set_servers(service: &str, servers: &[String]) -> Result<()> {
    let mut args = vec!["-setdnsservers", service];
    if servers.is_empty() {
        args.push("Empty");
    } else {
        args.extend(servers.iter().map(String::as_str));
    }
    networksetup(&args)?;
    Ok(())
}

fn flush_system_dns_cache() {
    // networksetup changes the resolver configuration, but mDNSResponder may
    // retain answers from the previous server. Both commands are the standard
    // macOS cache refresh sequence; failure is non-fatal because the resolver
    // will eventually observe the new service configuration.
    for (program, args) in [
        ("/usr/bin/dscacheutil", ["-flushcache"].as_slice()),
        ("/usr/bin/killall", ["-HUP", "mDNSResponder"].as_slice()),
    ] {
        match Command::new(program).args(args).status() {
            Ok(status) if status.success() => {}
            Ok(status) => tracing::debug!(%program, ?status, "macOS DNS cache refresh command failed"),
            Err(error) => tracing::debug!(%program, %error, "macOS DNS cache refresh command unavailable"),
        }
    }
}

fn state_path(directory: &Path) -> PathBuf {
    directory.join(STATE_FILE)
}

fn save(path: &Path, state: &impl Serialize) -> Result<()> {
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec(state)?)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temporary, path)?;
    File::open(path.parent().context("DNS state directory missing")?)?.sync_all()?;
    Ok(())
}

fn restore_state_with(
    path: &Path,
    mut get: impl FnMut(&str) -> Result<Vec<String>>,
    mut set: impl FnMut(&str, &[String]) -> Result<()>,
) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let mut bytes = vec![];
    File::open(path)?
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 64 * 1024, "DNS state size limit");
    let states = match serde_json::from_slice(&bytes).context("invalid DNS recovery state")? {
        SavedState::Services(states) => states,
        SavedState::Legacy(state) => vec![state],
    };
    ensure!(!states.is_empty() && states.len() <= 64, "invalid DNS recovery service count");
    for state in &states {
    ensure!(
        !state.service.is_empty()
            && state.service.len() <= 256
            && !state.service.chars().any(char::is_control)
            && state.servers.len() <= 16
            && state
                .servers
                .iter()
                .all(|server| server.parse::<std::net::IpAddr>().is_ok())
            && (state.managed_server == LEGACY_MANAGED_SERVER
                || state.managed_server == crate::MACOS_TUN_DNS_IP.to_string()
                || state.managed_server.parse::<Ipv4Addr>().is_ok_and(|address| {
                    !address.is_unspecified() && !address.is_multicast() && !address.is_broadcast()
                })),
        "invalid DNS recovery state"
    );
    }
    for state in states {
        if get(&state.service)? == [state.managed_server.clone()] {
            set(&state.service, &state.servers)?;
        }
    }
    std::fs::remove_file(path)?;
    Ok(())
}

fn restore_state(path: &Path) -> Result<()> {
    if !path.exists() { return Ok(()); }
    let result = restore_state_with(path, configured_servers, set_servers);
    flush_system_dns_cache();
    result
}

pub fn recover(directory: &Path) -> Result<()> {
    restore_state(&state_path(directory))
}

pub struct MacDns {
    directory: PathBuf,
    interface: String,
    server: Ipv4Addr,
    active: bool,
}

impl MacDns {
    pub fn start(directory: &Path, interface: &str, server: Ipv4Addr) -> Result<Self> {
        let path = state_path(directory);
        ensure!(
            !path.exists(),
            "unfinished DNS state exists; run --recover-tun before starting"
        );
        let list = networksetup(&["-listnetworkserviceorder"])?;
        let service = service_for_interface(&list, interface)
            .with_context(|| format!("no enabled network service for {interface}"))?;
        // macOS's primary DNS service follows service order, independently of
        // the egress selected by our socket probes. Cover enabled physical
        // services so an unusable Ethernet default cannot retain stale DNS.
        let mut interfaces: Vec<_> = netdev::get_interfaces().into_iter()
            .filter(|device| device.is_up() && !device.is_loopback() && !device.is_tun() && !device.ipv4.is_empty())
            .map(|device| device.name).collect();
        interfaces.push(interface.to_owned());
        let mut services = managed_services(&list, &interfaces);
        if !services.contains(&service) { services.push(service); }
        let states: Vec<_> = services.into_iter().map(|service| {
            Ok(State { servers: configured_servers(&service)?, service, managed_server: server.to_string() })
        }).collect::<Result<_>>()?;
        save(&path, &states)?;
        let mut dns = Self {
            directory: directory.to_owned(),
            interface: interface.to_owned(),
            server,
            active: true,
        };
        for state in &states {
            if let Err(error) = set_servers(&state.service, std::slice::from_ref(&state.managed_server)) {
                let _ = dns.restore();
                return Err(error);
            }
            tracing::info!(service = %state.service, server = %state.managed_server, "macOS physical service DNS configured");
        }
        flush_system_dns_cache();
        Ok(dns)
    }

    pub fn refresh(&mut self, interface: &str, server: Ipv4Addr) -> Result<()> {
        if interface != self.interface || server != self.server {
            self.restore()?;
            *self = Self::start(&self.directory, interface, server)?;
        }
        Ok(())
    }

    pub fn restore(&mut self) -> Result<()> {
        if self.active {
            restore_state(&state_path(&self.directory))?;
            self.active = false;
        }
        Ok(())
    }
}

impl Drop for MacDns {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            tracing::error!(%error, "DNS restore failed; recovery state retained");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn chooses_only_the_enabled_physical_service() {
        let list = "An asterisk (*) denotes that a network service is disabled.\n\
            (1) USB 10/100/1000 LAN\n\
            (Hardware Port: USB 10/100/1000 LAN, Device: en7)\n\
            (2) *Old Wi-Fi\n\
            (Hardware Port: Wi-Fi, Device: en1)\n\
            (3) Wi-Fi\n\
            (Hardware Port: Wi-Fi, Device: en0)\n\
            (4) Tailscale\n\
            (Hardware Port: io.tailscale.ipn.macsys, Device: )\n";
        assert_eq!(
            service_for_interface(list, "en7").as_deref(),
            Some("USB 10/100/1000 LAN")
        );
        assert_eq!(service_for_interface(list, "en0").as_deref(), Some("Wi-Fi"));
        assert_eq!(service_for_interface(list, "en1"), None);
        assert_eq!(service_for_interface(list, "utun5"), None);
        assert_eq!(
            managed_services(list, &["en0".into(), "en7".into(), "en1".into(), "utun10".into()]),
            vec!["USB 10/100/1000 LAN", "Wi-Fi"]
        );
    }

    #[test]
    fn restores_multiple_services_after_partial_failure() {
        let directory = std::env::temp_dir().join(format!("clyntis-dns-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = state_path(&directory);
        let states = vec![
            State { service: "Ethernet".into(), servers: vec!["223.5.5.5".into()], managed_server: "10.0.12.90".into() },
            State { service: "Wi-Fi".into(), servers: vec![], managed_server: "10.0.12.90".into() },
        ];
        save(&path, &states).unwrap();
        let mut current = std::collections::HashMap::from([
            ("Ethernet".to_string(), vec!["10.0.12.90".to_string()]),
            ("Wi-Fi".to_string(), vec!["10.0.12.90".to_string()]),
        ]);
        let initial = current.clone();
        assert!(restore_state_with(&path, |service| Ok(initial[service].clone()), |service, servers| {
            if service == "Wi-Fi" { anyhow::bail!("injected failure"); }
            current.insert(service.to_string(), servers.to_vec());
            Ok(())
        }).is_err());
        assert!(path.exists());
        let initial = current.clone();
        restore_state_with(&path, |service| Ok(initial[service].clone()), |service, servers| {
            assert_eq!(service, "Wi-Fi");
            current.insert(service.to_string(), servers.to_vec());
            Ok(())
        }).unwrap();
        assert_eq!(current["Ethernet"], vec!["223.5.5.5"]);
        assert!(current["Wi-Fi"].is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn recovers_only_dns_still_owned_by_clyntis() {
        let directory = std::env::temp_dir().join(format!("clyntis-dns-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = state_path(&directory);
        let original = State {
            service: "Wi-Fi".into(),
            servers: vec!["223.5.5.5".into()],
            managed_server: crate::MACOS_TUN_DNS_IP.to_string(),
        };
        save(&path, &original).unwrap();
        let restored = Cell::new(false);
        restore_state_with(
            &path,
            |_| Ok(vec![original.managed_server.clone()]),
            |service, servers| {
                assert_eq!(service, "Wi-Fi");
                assert_eq!(servers, original.servers);
                restored.set(true);
                Ok(())
            },
        )
        .unwrap();
        assert!(restored.get());
        assert!(!path.exists());

        save(&path, &original).unwrap();
        restore_state_with(
            &path,
            |_| Ok(vec!["8.8.8.8".into()]),
            |_, _| panic!("must not overwrite a later DNS change"),
        )
        .unwrap();
        assert!(!path.exists());

        save(&path, &original).unwrap();
        assert!(
            restore_state_with(
                &path,
                |_| Ok(vec![original.managed_server.clone()]),
                |_, _| anyhow::bail!("injected failure"),
            )
            .is_err()
        );
        assert!(path.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn old_loopback_recovery_state_remains_supported() {
        let state: State =
            serde_json::from_str(r#"{"service":"Wi-Fi","servers":["223.5.5.5"]}"#).unwrap();
        assert_eq!(state.managed_server, LEGACY_MANAGED_SERVER);
    }
}
