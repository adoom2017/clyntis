//! `type: tailscale` proxies: one userspace Tailscale node per proxy, whose
//! control and DERP connections go out like the core's own (physical egress,
//! or `dialer-proxy`).
use crate::Core;
use anyhow::{Context, Result};
use meta_config::{Proxy, ProxyKind};
use meta_protocol::{
    BoxStream, Target,
    tls::{SecureConnector, TlsConnectConfig, TlsFingerprint},
};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Weak},
};

struct CoreDialer {
    core: Weak<Core>,
    via: Option<String>,
}

#[async_trait::async_trait]
impl meta_tailscale::Dialer for CoreDialer {
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

fn options(core: &Core, proxy: &Proxy) -> meta_tailscale::Options {
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
    meta_tailscale::Options {
        name: proxy.name.clone(),
        auth_key: t.auth_key.clone(),
        hostname: t
            .hostname
            .clone()
            .unwrap_or_else(|| format!("clyntis-{}", os().to_ascii_lowercase())),
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
pub(crate) fn start(core: &Arc<Core>) -> Result<HashMap<String, meta_tailscale::Node>> {
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
        let node = meta_tailscale::Node::start(options(core, proxy), dialer, core.stop.clone())
            .with_context(|| format!("cannot start Tailscale proxy {}", proxy.name))?;
        nodes.insert(proxy.name.clone(), node);
    }
    if !nodes.is_empty() {
        let names: Vec<meta_tailscale::Node> = nodes.values().cloned().collect();
        core.resolver
            .set_tailnet_names(Some(Arc::new(move |host: &str| {
                names.iter().find_map(|n| n.resolve(host))
            })));
    }
    Ok(nodes)
}
