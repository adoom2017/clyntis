import Foundation

/// A proxy's status from the core snapshot (`proxies`).
struct NodeStatus: Decodable, Equatable {
    let type: String
    let connections: Int
    /// The last delay test: milliseconds, or the error, and when (Unix seconds).
    let delay: Int?
    let error: String?
    let checked: Double?
    // VLESS
    let server: String?
    let network: String?
    let security: String?
    let flow: String?
    let udp: Bool?
    let tailscale: TailscaleStatus?

    var checkedAt: Date? { checked.map(Date.init(timeIntervalSince1970:)) }
}

struct TailscaleStatus: Decodable, Equatable {
    let state: String
    let error: String?
    let name: String?
    let addresses: [String]
    let homeDerp: String?
    let endpoints: [String]
    let peers: [TailscalePeer]

    var onlinePeers: Int { peers.filter { $0.online == true }.count }
    var directPeers: Int { peers.filter { $0.path == "direct" }.count }
    var stateText: String {
        switch state {
        case "running": "已连接"
        case "error": "连接失败"
        default: "连接中"
        }
    }
}

struct TailscalePeer: Decodable, Equatable, Identifiable {
    var id: String { name + (address ?? "") }
    let name: String
    let address: String?
    let os: String?
    let online: Bool?
    /// "direct", "derp" or "idle".
    let path: String
    let direct: String?
    let rttMs: Int?
    let derp: String?
    let exitNode: Bool

    var pathText: String {
        switch path {
        case "direct": "直连" + (rttMs.map { " \($0) ms" } ?? "")
        case "derp": "中继" + (derp.map { " \($0)" } ?? "")
        default: online == true ? "空闲" : "离线"
        }
    }
}

extension NodeStatus {
    static func decode(_ object: Any?) -> [String: NodeStatus] {
        guard let object, let data = try? JSONSerialization.data(withJSONObject: object) else { return [:] }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return (try? decoder.decode([String: NodeStatus].self, from: data)) ?? [:]
    }

    /// One line for lists: what matters most for this kind of node.
    var summary: String {
        if let tailscale {
            guard tailscale.state == "running" else { return tailscale.stateText }
            return "\(tailscale.stateText) · \(tailscale.onlinePeers) 台在线"
                + (tailscale.directPeers > 0 ? " · \(tailscale.directPeers) 直连" : "")
        }
        var parts = [type]
        if let delay { parts.append("\(delay) ms") } else if error != nil { parts.append("超时") }
        if connections > 0 { parts.append("\(connections) 连接") }
        return parts.joined(separator: " · ")
    }
}
