mod logging;

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Parser, ValueEnum};
use meta_config::{Config, ProxyKind, crypto};
use meta_core::Core;
use meta_platform::{
    DefaultHooks,
    desktop::{DesktopTun, Options},
};
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{self, IsTerminal, Read, Write},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    process::ExitCode,
    sync::Arc,
};
use zeroize::Zeroizing;

const INPUT_LIMIT: u64 = 24 * 1024 * 1024;

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
async fn public_egress_targets() -> Vec<SocketAddr> {
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
async fn detect_macos_egress(
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

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Action {
    Encrypt,
    Decrypt,
}

#[derive(Parser)]
#[command(name = "clyntis", version, disable_version_flag = true)]
struct Args {
    /// Load and validate GeoIP/GeoSite and rule providers, without opening listeners.
    #[arg(long,conflicts_with_all=["action","recover_tun"])]
    test_resources: bool,
    /// Probe macOS physical egress interfaces without starting TUN.
    #[cfg(target_os = "macos")]
    #[arg(long, conflicts_with_all = ["action", "recover_tun"])]
    test_egress: bool,
    /// Disable TUN even when the configuration enables it.
    #[arg(long)]
    no_tun: bool,
    /// Temporarily configure macOS system DNS for TUN without editing YAML.
    #[cfg(target_os = "macos")]
    #[arg(long, conflicts_with_all = ["no_tun", "proxy_test_port"])]
    auto_dns: bool,
    /// Run an isolated loopback mixed listener; disables TUN, DNS listener and controller.
    #[arg(long,value_parser=clap::value_parser!(u16).range(1..))]
    proxy_test_port: Option<u16>,
    /// Override VLESS TLS fingerprints during an isolated compatibility test.
    #[arg(long, requires = "proxy_test_port", hide = true)]
    proxy_test_client_fingerprint: Option<String>,
    /// Keep VLESS outbounds; replace unavailable references with REJECT, never DIRECT.
    #[arg(long)]
    vless_only: bool,
    /// Restore routes from the interrupted TUN session in the configuration directory.
    #[arg(long, conflicts_with_all = ["action", "test"])]
    recover_tun: bool,
    /// Show version and exit.
    #[arg(short = 'v', long, action = clap::ArgAction::Version)]
    version: Option<bool>,
    /// Configuration directory (defaults to the current directory).
    #[arg(short = 'd', long, env = "CLASH_HOME_DIR", default_value = ".")]
    directory: PathBuf,
    /// Configuration file; use - to read standard input.
    #[arg(
        short = 'f',
        long,
        env = "CLASH_CONFIG_FILE",
        conflicts_with = "config"
    )]
    file: Option<PathBuf>,
    /// Base64-encoded configuration.
    #[arg(long, env = "CLASH_CONFIG_STRING", hide_env_values = true)]
    config: Option<String>,
    /// Validate configuration and exit without opening listeners.
    #[arg(short = 't', long, conflicts_with = "action")]
    test: bool,
    /// Encrypt or decrypt a configuration using the legacy Alpha format.
    #[arg(long, value_enum)]
    action: Option<Action>,
    /// Configuration password; omitted action passwords are prompted securely.
    #[arg(short = 'p', long)]
    password: Option<String>,
    /// Action output file; use - for standard output. Existing files are refused.
    #[arg(short = 'o', long, requires = "action")]
    output: Option<PathBuf>,
    /// Override the controller address.
    #[arg(long = "ext-ctl", env = "CLASH_OVERRIDE_EXTERNAL_CONTROLLER")]
    external_controller: Option<String>,
    /// Override the controller secret.
    #[arg(long, env = "CLASH_OVERRIDE_SECRET", hide_env_values = true)]
    secret: Option<String>,
}

fn command_line() -> impl Iterator<Item = OsString> {
    // Go's flag package accepts these long options with one dash.
    std::env::args_os().enumerate().map(|(index, arg)| {
        if index > 0
            && let Some(text) = arg.to_str()
        {
            let name = text.split('=').next().unwrap_or(text);
            if matches!(name, "-config" | "-action" | "-ext-ctl" | "-secret") {
                return OsString::from(format!("-{text}"));
            }
        }
        arg
    })
}

fn main() -> ExitCode {
    match run(Args::parse_from(command_line())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("clyntis: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn read_input(args: &mut Args) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(encoded) = args.config.take() {
        let encoded = Zeroizing::new(encoded);
        ensure!(
            encoded.len() as u64 <= INPUT_LIMIT,
            "configuration input exceeds 24 MiB"
        );
        return Ok(Zeroizing::new(
            STANDARD
                .decode(encoded.as_bytes())
                .context("invalid --config base64")?,
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    let path = args
        .file
        .clone()
        .unwrap_or_else(|| args.directory.join("config.yaml"));
    let reader: Box<dyn Read> = if path.as_os_str() == "-" {
        Box::new(io::stdin())
    } else {
        Box::new(File::open(&path).with_context(|| format!("cannot read {}", path.display()))?)
    };
    reader.take(INPUT_LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= INPUT_LIMIT,
        "configuration input exceeds 24 MiB"
    );
    Ok(bytes)
}

fn password(args: &mut Args) -> Result<Option<Zeroizing<String>>> {
    if let Some(password) = args.password.take() {
        return Ok(Some(Zeroizing::new(password)));
    }
    let Some(action) = args.action else {
        return Ok(None);
    };
    ensure!(
        io::stdin().is_terminal(),
        "--password is required for non-interactive actions"
    );
    let password = Zeroizing::new(rpassword::prompt_password("Password: ")?);
    ensure!(!password.is_empty(), "password cannot be empty");
    if action == Action::Encrypt {
        let repeated = Zeroizing::new(rpassword::prompt_password("Repeat password: ")?);
        ensure!(*password == *repeated, "passwords do not match");
    }
    Ok(Some(password))
}

fn write_output(args: &Args, action: Action, bytes: &[u8]) -> Result<()> {
    let path = if let Some(path) = &args.output {
        path.clone()
    } else {
        ensure!(
            args.config.is_none() && args.file.as_ref().is_none_or(|p| p.as_os_str() != "-"),
            "--output is required for --config or standard input actions"
        );
        let source = args
            .file
            .clone()
            .unwrap_or_else(|| args.directory.join("config.yaml"));
        let name = if action == Action::Encrypt {
            "config-encrypt"
        } else {
            "config-decrypt"
        };
        let mut path = source.with_file_name(name);
        if let Some(extension) = source.extension() {
            path.set_extension(extension);
        }
        path
    };
    if path.as_os_str() == "-" {
        io::stdout().lock().write_all(bytes)?;
    } else {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .with_context(|| format!("cannot create {}", path.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        eprintln!("Wrote {}", path.display());
    }
    Ok(())
}

fn run(mut args: Args) -> Result<()> {
    if args.recover_tun {
        meta_platform::desktop::recover(&args.directory)?;
        #[cfg(target_os = "macos")]
        meta_platform::macos_dns::recover(&args.directory)?;
        return Ok(());
    }
    if args.action.is_some() && args.config.is_some() {
        ensure!(
            args.output.is_some(),
            "--output is required for --config actions"
        );
    }
    let input = read_input(&mut args)?;
    let password = password(&mut args)?;
    if let Some(action) = args.action {
        let password = password.as_deref().context("password required")?;
        match action {
            Action::Encrypt => {
                Config::parse(&input)?;
                let ciphertext = crypto::encrypt(&input, password)?;
                write_output(&args, action, ciphertext.as_bytes())?;
            }
            Action::Decrypt => {
                let plaintext = crypto::decrypt(input.trim_ascii(), password)?;
                Config::parse(&plaintext).context("decrypted configuration is invalid")?;
                write_output(&args, action, &plaintext)?;
            }
        }
        return Ok(());
    }
    let plaintext = match password {
        Some(password) => crypto::decrypt(input.trim_ascii(), &password)?,
        None => input,
    };
    let mut config = Config::parse(&plaintext)?;
    config.directory = args.directory.clone();
    if args.no_tun {
        config.tun.enable = false;
    }
    #[cfg(target_os = "macos")]
    if args.auto_dns {
        ensure!(config.tun.enable, "--auto-dns requires tun.enable: true");
        config.tun.auto_dns = true;
    }
    if let Some(port) = args.proxy_test_port {
        config.tun.enable = false;
        config.port = 0;
        config.socks_port = 0;
        config.mixed_port = port;
        config.allow_lan = false;
        config.dns.enable = false;
        config.external_controller = None;
        // Isolated test mode captures stderr and withholds it from the caller.
        // Keep enough detail there for the test harness to report a sanitized
        // failure category without writing private node data to a log file.
        config.log.log_level = "debug".into();
        config.log.log_path.clear();
    }
    if args.vless_only {
        config.retain_vless()?;
    }
    if let Some(address) = args.external_controller {
        config.external_controller = Some(address);
    }
    if let Some(secret) = args.secret {
        config.secret = secret;
    }
    if args.proxy_test_port.is_some() {
        config.external_controller = None;
    }
    config.validate()?;
    #[cfg(target_os = "macos")]
    if args.test_egress {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let interface = runtime.block_on(async {
            let targets = public_egress_targets().await;
            detect_macos_egress(&config, &targets, "without TUN").await
        })?;
        let interface = config.tun.interface.as_deref().or(interface.as_deref());
        let interface = interface.context("no reachable physical egress found")?;
        println!("Physical egress: {interface}");
        return Ok(());
    }
    // Test-only overrides are applied after validating the user document so
    // the internal `native` control profile cannot be selected from YAML.
    if let Some(fingerprint) = &args.proxy_test_client_fingerprint {
        config.internal_allow_native_profile = fingerprint == "native";
        config.global_client_fingerprint.clone_from(fingerprint);
        for proxy in &mut config.proxies {
            if proxy.kind == ProxyKind::Vless {
                proxy.client_fingerprint = Some(fingerprint.clone());
            }
        }
    }
    if args.test {
        println!("Configuration test successful");
        return Ok(());
    }
    if args.test_resources {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let core = Core::new(config, Arc::new(DefaultHooks))?;
            core.prepare_resources(false).await?;
            println!("Routing resource test successful");
            Ok::<_, anyhow::Error>(())
        })?;
        return Ok(());
    }
    ensure!(
        config.port != 0
            || config.tun.enable
            || config.socks_port != 0
            || config.mixed_port != 0
            || config.dns.enable
            || config.external_controller.is_some(),
        "no listeners enabled in configuration"
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        eprintln!("TLS backend: BoringSSL; default client fingerprint: {}", config.global_client_fingerprint);
        if config.tun.enable{eprintln!("Compatibility: TUN uses the native Rust/smoltcp stack; stack labels do not select a Go gVisor implementation.");}
        let automatic_dns = cfg!(target_os = "macos")
            && config.tun.auto_route
            && config.tun.auto_dns
            && config.dns.enable;
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
        let selected_interface = config.tun.interface.as_deref().or(detected_interface.as_deref());
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
                directory: &args.directory,
            })
        };
        let mut desktop = if config.tun.enable {
            Some(open_tun(selected_interface)?)
        } else { None };
        #[cfg(target_os = "macos")]
        if config.tun.enable && config.tun.auto_detect_interface && config.tun.interface.is_none() {
            let after = detect_macos_egress(&config, &public_targets, "after TUN").await?
                .context("no physical egress reachable after TUN routing; set tun.interface explicitly")?;
            let current = desktop.as_ref().and_then(|tun| tun.hooks.network().ipv4)
                .map(|interface| interface.name);
            if current.as_deref() != Some(after.as_str()) {
                let mut previous = desktop.take().unwrap();
                previous.restore()?;
                drop(previous);
                desktop = Some(open_tun(Some(&after))?);
                let verified = detect_macos_egress(&config, &public_targets, "after TUN reselection").await?;
                ensure!(verified.as_deref() == Some(after.as_str()), "physical egress changed during TUN setup; set tun.interface explicitly");
            }
        }
        let hooks: meta_platform::Hooks = desktop.as_ref().map(|d| d.hooks.clone() as meta_platform::Hooks).unwrap_or_else(|| Arc::new(DefaultHooks));
        let packets = desktop.as_ref().map(|d| d.device.clone() as Arc<dyn meta_platform::PacketIo>);
        let core = Core::new(config, hooks)?;
        logging::init(&core.config.log, &args.directory, core.events.clone())?;
        if core.config.log.log_path.is_empty() {
            eprintln!("Logging: {} to stderr", core.config.log.log_level);
        } else {
            eprintln!(
                "Logging: {} to {}",
                core.config.log.log_level,
                args.directory.join(&core.config.log.log_path).display()
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
            let interface = desktop.as_ref().and_then(|tun| tun.hooks.network().ipv4)
                .context("automatic DNS requires an IPv4 physical exit")?;
            Some(meta_platform::desktop::local_ipv4_address(&interface)?)
        } else { None };
        #[cfg(target_os = "macos")]
        let mut running = core.start_with_packets_and_system_dns(
            packets,
            system_dns_address.map(|address| std::net::SocketAddr::new(address.into(), 53)),
        ).await.context("cannot start proxy core")?;
        #[cfg(not(target_os = "macos"))]
        let running = core.start_with_packets(packets).await.context("cannot start proxy core")?;
        #[cfg(target_os = "macos")]
        let mut system_dns = if core.config.tun.enable && core.config.tun.auto_route && core.config.tun.auto_dns && core.config.dns.enable {
            let interface = desktop.as_ref().and_then(|tun| tun.hooks.network().ipv4).context("automatic DNS requires an IPv4 physical exit")?;
            let server = system_dns_address.context("automatic DNS address missing")?;
            let dns = meta_platform::macos_dns::MacDns::start(&args.directory, &interface.name, server)?;
            tracing::info!(interface = %interface.name, %server, "macOS system DNS configured");
            Some(dns)
        } else { None };
        #[cfg(target_os = "macos")]
        if system_dns.is_some() {
            verify_macos_system_dns(&core.config.dns).await?;
        }
        tracing::info!(addresses = ?running.addresses, "proxy core started");
        let mut refresh = tokio::time::interval(std::time::Duration::from_secs(3));
        #[cfg(target_os = "macos")]
        let mut next_egress_probe = tokio::time::Instant::now();
        let signal = shutdown_signal(); tokio::pin!(signal);
        let result = loop {
            tokio::select! {
                result = &mut signal => break result,
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
        };
        #[cfg(target_os = "macos")]
        if let Some(dns) = &mut system_dns { dns.restore()?; }
        running.shutdown().await;
        if let Some(desktop) = &mut desktop { desktop.restore()?; }
        tracing::info!("proxy core stopped");
        result
    })
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}
