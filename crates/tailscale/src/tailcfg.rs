//! The subset of Tailscale's control protocol types (tailcfg) this node uses.
//! Unknown fields are ignored, so newer servers stay compatible.
use crate::key::{NodeKey, Public};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Capability version this client claims: HomeDERP (111), nil AllowedIPs
/// meaning Addresses (112) and DERPRegion.NoMeasureNoHome (115). Later
/// versions promise features (seamless key renewal, peer relays) we lack.
pub const CAPABILITY_VERSION: u16 = 115;

#[derive(Deserialize)]
pub struct OverTlsPublicKey {
    #[serde(rename = "publicKey")]
    pub public_key: Public,
}

#[derive(Serialize, Default, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Hostinfo {
    #[serde(rename = "IPNVersion")]
    pub ipn_version: String,
    #[serde(rename = "OS")]
    pub os: String,
    pub hostname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_info: Option<NetInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
}

#[derive(Serialize, Default, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct NetInfo {
    #[serde(rename = "PreferredDERP")]
    pub preferred_derp: u32,
    #[serde(rename = "DERPLatency", skip_serializing_if = "BTreeMap::is_empty")]
    pub derp_latency: BTreeMap<String, f64>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterRequest {
    pub version: u16,
    pub node_key: NodeKey,
    pub old_node_key: NodeKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<RegisterAuth>,
    pub hostinfo: Hostinfo,
    pub ephemeral: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterAuth {
    pub auth_key: String,
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct RegisterResponse {
    pub node_key_expired: bool,
    pub machine_authorized: bool,
    #[serde(rename = "AuthURL")]
    pub auth_url: String,
    pub error: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MapRequest {
    pub version: u16,
    pub compress: &'static str,
    pub keep_alive: bool,
    pub node_key: NodeKey,
    pub disco_key: String,
    pub stream: bool,
    pub hostinfo: Hostinfo,
    pub omit_peers: bool,
    /// Our UDP candidates ("ip:port") for direct paths, with their kinds.
    pub endpoints: Vec<String>,
    pub endpoint_types: Vec<u8>,
}

/// tailcfg.EndpointType values for the candidates we report.
pub const ENDPOINT_LOCAL: u8 = 1;
pub const ENDPOINT_STUN: u8 = 2;

#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "PascalCase", default)]
pub struct Node {
    #[serde(rename = "ID")]
    pub id: i64,
    pub name: String,
    pub key: Public,
    pub disco_key: Public,
    pub addresses: Vec<ipnet::IpNet>,
    /// `None` means the same as `addresses` (capability version 112).
    #[serde(rename = "AllowedIPs")]
    pub allowed_ips: Option<Vec<ipnet::IpNet>>,
    pub primary_routes: Vec<ipnet::IpNet>,
    /// UDP candidates for direct paths.
    pub endpoints: Vec<String>,
    #[serde(rename = "HomeDERP")]
    pub home_derp: u32,
    /// Legacy home DERP as "127.3.3.40:<region>".
    #[serde(rename = "DERP")]
    pub legacy_derp: String,
    pub online: Option<bool>,
    pub expired: bool,
    pub machine_authorized: bool,
    pub computed_name: String,
    pub hostinfo: Option<serde_json::Value>,
}
impl Node {
    pub fn derp_region(&self) -> u32 {
        if self.home_derp != 0 {
            return self.home_derp;
        }
        self.legacy_derp
            .strip_prefix("127.3.3.40:")
            .and_then(|port| port.parse().ok())
            .unwrap_or(0)
    }
    pub fn allowed(&self) -> &[ipnet::IpNet] {
        self.allowed_ips.as_deref().unwrap_or(&self.addresses)
    }
    /// The MagicDNS name without the trailing dot, for example
    /// `laptop.tail1234.ts.net`.
    pub fn fqdn(&self) -> &str {
        self.name.trim_end_matches('.')
    }
}

#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "PascalCase", default)]
pub struct PeerChange {
    #[serde(rename = "NodeID")]
    pub node_id: i64,
    #[serde(rename = "DERPRegion")]
    pub derp_region: u32,
    pub key: Option<Public>,
    pub disco_key: Option<Public>,
    pub online: Option<bool>,
    pub endpoints: Option<Vec<String>>,
}

#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "PascalCase", default)]
pub struct DerpMap {
    pub regions: BTreeMap<String, DerpRegion>,
}

#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "PascalCase", default)]
pub struct DerpRegion {
    #[serde(rename = "RegionID")]
    pub region_id: u32,
    pub region_code: String,
    pub avoid: bool,
    pub no_measure_no_home: bool,
    pub nodes: Vec<DerpNode>,
}

#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "PascalCase", default)]
pub struct DerpNode {
    pub name: String,
    pub host_name: String,
    #[serde(rename = "IPv4")]
    pub ipv4: String,
    #[serde(rename = "DERPPort")]
    pub derp_port: u16,
    /// 0 means 3478; negative disables STUN on this node.
    #[serde(rename = "STUNPort")]
    pub stun_port: i32,
    #[serde(rename = "STUNOnly")]
    pub stun_only: bool,
}

#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "PascalCase", default)]
pub struct MapResponse {
    pub keep_alive: bool,
    pub node: Option<Node>,
    #[serde(rename = "DERPMap")]
    pub derp_map: Option<DerpMap>,
    pub peers: Option<Vec<Node>>,
    pub peers_changed: Vec<Node>,
    pub peers_removed: Vec<i64>,
    pub peers_changed_patch: Vec<PeerChange>,
    pub online_change: BTreeMap<String, bool>,
    pub domain: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_map_response_and_reads_legacy_derp() {
        let json = r#"{"Node":{"ID":1,"Name":"me.tail.ts.net.","Key":"nodekey:0101010101010101010101010101010101010101010101010101010101010101","Addresses":["100.64.0.1/32"]},
            "Peers":[{"ID":2,"Name":"pc.tail.ts.net.","Key":"nodekey:0202020202020202020202020202020202020202020202020202020202020202","DiscoKey":"discokey:0303030303030303030303030303030303030303030303030303030303030303","Addresses":["100.64.0.2/32","fd7a:115c:a1e0::2/128"],"AllowedIPs":["100.64.0.2/32","0.0.0.0/0"],"DERP":"127.3.3.40:9","Unknown":1}],
            "DERPMap":{"Regions":{"9":{"RegionID":9,"RegionCode":"dfw","Nodes":[{"Name":"9a","HostName":"derp9.tailscale.com","IPv4":"1.2.3.4"}]}}},
            "PeersRemoved":[3],"OnlineChange":{"2":true},"Domain":"tail.ts.net"}"#;
        let map: MapResponse = serde_json::from_str(json).unwrap();
        let peer = &map.peers.unwrap()[0];
        assert_eq!(peer.derp_region(), 9);
        assert_eq!(peer.fqdn(), "pc.tail.ts.net");
        assert_eq!(peer.allowed().len(), 2);
        assert_eq!(map.node.unwrap().allowed().len(), 1);
        assert_eq!(
            map.derp_map.unwrap().regions["9"].nodes[0].host_name,
            "derp9.tailscale.com"
        );
        assert_eq!(map.peers_removed, [3]);
    }
}
