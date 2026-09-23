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
    path::PathBuf,
    process::ExitCode,
    sync::Arc,
};
use zeroize::Zeroizing;

const INPUT_LIMIT: u64 = 24 * 1024 * 1024;

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
    /// Disable TUN even when the configuration enables it.
    #[arg(long)]
    no_tun: bool,
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
        return meta_platform::desktop::recover(&args.directory);
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
        let mut desktop = if config.tun.enable {
            Some(DesktopTun::open(Options { name: &config.tun.device, mtu: config.tun.mtu, ipv6: config.ipv6, auto_route: config.tun.auto_route, interface: config.tun.interface.as_deref(), exclusions: &config.tun.route_exclude_address, capture_dns: !config.tun.dns_hijack.is_empty(), directory: &args.directory })?)
        } else { None };
        let hooks: meta_platform::Hooks = desktop.as_ref().map(|d| d.hooks.clone() as meta_platform::Hooks).unwrap_or_else(|| Arc::new(DefaultHooks));
        let packets = desktop.as_ref().map(|d| d.device.clone() as Arc<dyn meta_platform::PacketIo>);
        let core = Core::new(config, hooks)?;
        logging::init(&core.config.log, &args.directory, core.events.clone())?;
        let running = core.start_with_packets(packets).await.context("cannot start proxy core")?;
        tracing::info!(addresses = ?running.addresses, "proxy core started");
        let mut refresh = tokio::time::interval(std::time::Duration::from_secs(3));
        let signal = shutdown_signal(); tokio::pin!(signal);
        let result = loop {
            tokio::select! {
                result = &mut signal => break result,
                _ = core.stop.cancelled() => break Err(anyhow::anyhow!("proxy core stopped unexpectedly")),
                _ = refresh.tick(), if desktop.is_some() => {
                    match desktop.as_mut().unwrap().refresh() {
                        Ok(true) => { core.network_changed().await; tracing::info!("physical egress changed; sessions closed for reconnect"); },
                        Ok(false) => {},
                        Err(error) => break Err(error.context("cannot update TUN routing")),
                    }
                },
            }
        };
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
