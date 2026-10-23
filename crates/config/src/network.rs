//! Networks named by what the device sees (Wi-Fi name, address, gateway,
//! interface type), and the hosts and DNS policy that apply on each: the same
//! name can need a LAN resolver at home and a public one elsewhere.

use crate::Strings;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr};

pub const KINDS: [&str; 3] = ["wifi", "cellular", "wired"];

/// What identifies a network. Every condition given must hold; a condition
/// with several values holds when any of them matches. A condition on a fact
/// the platform did not report (the Wi-Fi name on desktops or on a wired
/// link) is skipped, so `ssid` plus `subnet` still matches there by subnet;
/// at least one condition must be checked.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Network {
    /// `wifi`, `cellular` or `wired`.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<Strings>,
    /// Wi-Fi names, compared exactly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssid: Option<Strings>,
    /// Networks containing one of this device's addresses on the network.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet: Option<Strings>,
    /// Gateway addresses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<Strings>,
}

/// Hosts and DNS policy for a network (`network: home`) or for any other
/// (`network: '!home'`), applied over the global ones.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct NetworkOverride {
    pub network: String,
    pub hosts: BTreeMap<String, Strings>,
    pub nameserver_policy: BTreeMap<String, Strings>,
}

/// The network the device is on, as the platform reports it. Unknown facts
/// are left empty: conditions on them are skipped.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct NetworkInfo {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
    pub addresses: Vec<IpAddr>,
    pub gateways: Vec<IpAddr>,
}

impl Network {
    pub fn validate(&self, name: &str) -> Result<()> {
        ensure!(
            !name.is_empty() && !name.starts_with('!'),
            "networks: invalid name {name:?}"
        );
        ensure!(
            self.kind.is_some()
                || self.ssid.is_some()
                || self.subnet.is_some()
                || self.gateway.is_some(),
            "networks.{name}: give at least one of type, ssid, subnet or gateway"
        );
        for (field, values) in [
            ("type", &self.kind),
            ("ssid", &self.ssid),
            ("subnet", &self.subnet),
            ("gateway", &self.gateway),
        ] {
            if let Some(values) = values {
                ensure!(
                    !values.values().is_empty(),
                    "networks.{name}.{field} is empty"
                );
            }
        }
        for kind in self.kind.iter().flat_map(Strings::values) {
            ensure!(
                KINDS.contains(&kind.as_str()),
                "networks.{name}.type: {kind:?} is not one of wifi, cellular, wired"
            );
        }
        for subnet in self.subnet.iter().flat_map(Strings::values) {
            parse_subnet(&subnet).with_context(|| format!("networks.{name}.subnet"))?;
        }
        for gateway in self.gateway.iter().flat_map(Strings::values) {
            gateway
                .parse::<IpAddr>()
                .with_context(|| format!("networks.{name}.gateway: invalid address {gateway:?}"))?;
        }
        Ok(())
    }

    pub fn matches(&self, info: &NetworkInfo) -> bool {
        // None when the condition is absent or its fact unknown.
        let check = |values: &Option<Strings>, known: bool, test: &dyn Fn(&str) -> bool| {
            values
                .as_ref()
                .filter(|_| known)
                .map(|values| values.values().iter().any(|v| test(v)))
        };
        let checks = [
            check(&self.kind, info.kind.is_some(), &|kind| {
                info.kind.as_deref() == Some(kind)
            }),
            check(&self.ssid, info.ssid.is_some(), &|ssid| {
                info.ssid.as_deref() == Some(ssid)
            }),
            check(&self.subnet, !info.addresses.is_empty(), &|subnet| {
                parse_subnet(subnet)
                    .is_ok_and(|net| info.addresses.iter().any(|ip| net.contains(ip)))
            }),
            check(&self.gateway, !info.gateways.is_empty(), &|gateway| {
                gateway
                    .parse::<IpAddr>()
                    .is_ok_and(|gateway| info.gateways.contains(&gateway))
            }),
        ];
        checks.iter().any(Option::is_some) && checks.iter().all(|check| check.unwrap_or(true))
    }
}

/// `192.168.2.0/24`, or a single address.
fn parse_subnet(value: &str) -> Result<ipnet::IpNet> {
    value
        .parse::<ipnet::IpNet>()
        .or_else(|_| value.parse::<IpAddr>().map(ipnet::IpNet::from))
        .with_context(|| format!("invalid subnet {value:?}"))
}

impl NetworkOverride {
    /// The network name, and whether the entry applies when it does not match.
    pub fn target(&self) -> (&str, bool) {
        match self.network.strip_prefix('!') {
            Some(name) => (name, true),
            None => (&self.network, false),
        }
    }
}

/// The names of `networks` that `info` matches.
pub fn matching<'a>(networks: &'a BTreeMap<String, Network>, info: &NetworkInfo) -> Vec<&'a str> {
    networks
        .iter()
        .filter(|(_, network)| network.matches(info))
        .map(|(name, _)| name.as_str())
        .collect()
}

/// The first override that applies to `info`, by position.
pub fn active_override(
    networks: &BTreeMap<String, Network>,
    overrides: &[NetworkOverride],
    info: &NetworkInfo,
) -> Option<usize> {
    let matched = matching(networks, info);
    overrides.iter().position(|entry| {
        let (name, negated) = entry.target();
        matched.contains(&name) != negated
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn networks() -> BTreeMap<String, Network> {
        serde_yaml::from_str(
            "home:\n  ssid: [Home, Home-5G]\n  subnet: 192.168.2.0/24\n\
             phone:\n  type: cellular\n\
             office:\n  gateway: 10.0.12.1\n",
        )
        .unwrap()
    }

    fn info(kind: &str, ssid: Option<&str>, address: &str, gateway: &str) -> NetworkInfo {
        NetworkInfo {
            kind: Some(kind.into()),
            ssid: ssid.map(Into::into),
            addresses: vec![address.parse().unwrap()],
            gateways: vec![gateway.parse().unwrap()],
        }
    }

    #[test]
    fn every_condition_must_hold_and_any_value_does() {
        let networks = networks();
        let home = info("wifi", Some("Home-5G"), "192.168.2.241", "192.168.2.1");
        assert_eq!(matching(&networks, &home), ["home"]);
        // Right Wi-Fi name, other subnet: not home.
        let guest = info("wifi", Some("Home"), "192.168.9.3", "192.168.9.1");
        assert!(matching(&networks, &guest).is_empty());
        // A Wi-Fi name the platform does not report (desktops) or that does
        // not exist (wired) is skipped: the subnet decides.
        let unknown = info("wifi", None, "192.168.2.241", "192.168.2.1");
        assert_eq!(matching(&networks, &unknown), ["home"]);
        let wired = info("wired", None, "192.168.2.128", "192.168.2.1");
        assert_eq!(matching(&networks, &wired), ["home"]);
        // Nothing reported at all: no network matches.
        assert!(matching(&networks, &NetworkInfo::default()).is_empty());
        // Only conditions on unknown facts: not checked, so no match.
        let ssid_only: BTreeMap<String, Network> =
            serde_yaml::from_str("cafe:\n  ssid: Cafe\n").unwrap();
        assert!(matching(&ssid_only, &wired).is_empty());
        let cellular = info("cellular", None, "10.88.1.2", "10.88.1.1");
        assert_eq!(matching(&networks, &cellular), ["phone"]);
        let office = info("wired", None, "10.0.12.122", "10.0.12.1");
        assert_eq!(matching(&networks, &office), ["office"]);
    }

    #[test]
    fn first_applying_override_wins_and_negation_covers_the_rest() {
        let networks = networks();
        let overrides: Vec<NetworkOverride> = serde_yaml::from_str(
            "- network: home\n  hosts: {nas.example: 192.168.2.10}\n\
             - network: '!home'\n  hosts: {nas.example: 203.0.113.7}\n",
        )
        .unwrap();
        let home = info("wifi", Some("Home"), "192.168.2.241", "192.168.2.1");
        let away = info("cellular", None, "10.88.1.2", "10.88.1.1");
        assert_eq!(active_override(&networks, &overrides, &home), Some(0));
        assert_eq!(active_override(&networks, &overrides, &away), Some(1));
        assert_eq!(
            active_override(&networks, &overrides[..1], &away),
            None,
            "no override applies"
        );
    }

    #[test]
    fn rejects_empty_unknown_and_malformed_conditions() {
        let parse = |text: &str| serde_yaml::from_str::<Network>(text).unwrap();
        assert!(Network::default().validate("home").is_err());
        assert!(parse("type: satellite").validate("home").is_err());
        assert!(parse("subnet: 192.168.2.0/33").validate("home").is_err());
        assert!(parse("gateway: router").validate("home").is_err());
        assert!(parse("ssid: []").validate("home").is_err());
        assert!(parse("subnet: 192.168.2.0/24").validate("!home").is_err());
        assert!(parse("subnet: 192.168.2.7").validate("home").is_ok());
        assert!(serde_yaml::from_str::<Network>("bssid: x").is_err());
    }

    #[test]
    fn network_name_rules_need_a_defined_network() {
        let text = |rule: &str| {
            format!("networks: {{home: {{type: wifi}}}}\nrules: ['{rule}', 'MATCH,DIRECT']\n")
        };
        assert!(crate::Config::parse(text("NETWORK-NAME,home,DIRECT").as_bytes()).is_ok());
        assert!(crate::Config::parse(text("NOT,((NETWORK-NAME,home)),REJECT").as_bytes()).is_ok());
        let error =
            crate::Config::parse(text("NETWORK-NAME,office,DIRECT").as_bytes()).unwrap_err();
        assert!(format!("{error:#}").contains("office"), "{error:#}");
    }
}
