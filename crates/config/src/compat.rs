//! Typed Clash configuration additions. Unknown keys remain errors.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Strings {
    One(String),
    Many(Vec<String>),
}
impl Strings {
    pub fn values(&self) -> Vec<String> {
        match self {
            Self::One(v) => vec![v.clone()],
            Self::Many(v) => v.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct RuleProvider {
    #[serde(rename = "type")]
    pub kind: String,
    pub behavior: String,
    pub format: String,
    pub path: String,
    #[serde(skip_serializing)]
    pub url: String,
    pub interval: u64,
    pub payload: Vec<String>,
}
impl Default for RuleProvider {
    fn default() -> Self {
        Self {
            kind: "http".into(),
            behavior: "domain".into(),
            format: "yaml".into(),
            path: String::new(),
            url: String::new(),
            interval: 86400,
            payload: vec![],
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeoUrls {
    #[serde(skip_serializing)]
    pub geoip: String,
    #[serde(skip_serializing)]
    pub geosite: String,
    #[serde(skip_serializing)]
    pub mmdb: String,
}
impl Default for GeoUrls {
    fn default() -> Self {
        Self {
            geoip: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat"
                .into(),
            geosite:
                "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"
                    .into(),
            mmdb:
                "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb"
                    .into(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Profile {
    pub store_selected: bool,
    pub store_fake_ip: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Ntp {
    pub enable: bool,
    pub write_to_system: bool,
    pub server: String,
    pub port: u16,
    pub interval: u64,
}
impl Default for Ntp {
    fn default() -> Self {
        Self {
            enable: false,
            write_to_system: false,
            server: "time.apple.com".into(),
            port: 123,
            interval: 30,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PortRange {
    Number(u16),
    Range(String),
}
impl PortRange {
    pub fn bounds(&self) -> anyhow::Result<(u16, u16)> {
        let (a, b) = match self {
            Self::Number(n) => (*n, *n),
            Self::Range(s) => match s.split_once('-') {
                Some((a, b)) => (a.parse()?, b.parse()?),
                None => {
                    let n = s.parse()?;
                    (n, n)
                }
            },
        };
        anyhow::ensure!(a > 0 && a <= b, "invalid port range");
        Ok((a, b))
    }
    pub fn contains(&self, n: u16) -> bool {
        self.bounds().is_ok_and(|(a, b)| a <= n && n <= b)
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct SniffProtocol {
    pub ports: Vec<PortRange>,
    pub override_destination: bool,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Sniffer {
    pub enable: bool,
    pub sniff: BTreeMap<String, SniffProtocol>,
    pub force_domain: Vec<String>,
    pub skip_domain: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct WsOptions {
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub max_early_data: usize,
    pub early_data_header_name: String,
    pub v2ray_http_upgrade: bool,
    pub v2ray_http_upgrade_fast_open: bool,
}
impl Default for WsOptions {
    fn default() -> Self {
        Self {
            path: "/".into(),
            headers: BTreeMap::new(),
            max_early_data: 0,
            early_data_header_name: String::new(),
            v2ray_http_upgrade: false,
            v2ray_http_upgrade_fast_open: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct GrpcOptions {
    pub grpc_service_name: String,
    pub grpc_user_agent: String,
    pub ping_interval: u64,
    pub max_connections: usize,
    pub min_streams: usize,
    pub max_streams: usize,
}
impl Default for GrpcOptions {
    fn default() -> Self {
        Self {
            grpc_service_name: "GunService".into(),
            grpc_user_agent: "grpc-go/1.36.0".into(),
            ping_interval: 0,
            max_connections: 0,
            min_streams: 0,
            max_streams: 0,
        }
    }
}

pub fn string_or_number<'de, D: serde::Deserializer<'de>>(de: D) -> Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum V {
        S(String),
        N(u64),
    }
    Ok(match V::deserialize(de)? {
        V::S(s) => s,
        V::N(n) => format!("{n}s"),
    })
}
