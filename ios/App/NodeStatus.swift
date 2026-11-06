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
        case "running": L("已连接")
        case "error": L("连接失败")
        case "disabled": L("已关闭")
        default: L("连接中")
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
        case "direct": L("直连") + (rttMs.map { " \($0) ms" } ?? "")
        case "derp": L("中继") + (derp.map { " \($0)" } ?? "")
        default: online == true ? L("空闲") : L("离线")
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

    /// Outbounds the core can delay-test (a Tailscale node has no URL test).
    var probeable: Bool { type == "VLESS" || type == "Hysteria2" }

    /// The last delay test for lists ("85 ms", "超时"), shown apart from
    /// `summary` so it can carry its own colour.
    var delayText: String? {
        if let delay { return "\(delay) ms" }
        return error != nil && tailscale == nil ? L("超时") : nil
    }

    /// One line for lists: what matters most for this kind of node.
    var summary: String {
        if let tailscale {
            guard tailscale.state == "running" else { return tailscale.stateText }
            return L("{stateText} · {onlinePeers} 台在线", ["stateText": tailscale.stateText, "onlinePeers": tailscale.onlinePeers])
                + (tailscale.directPeers > 0 ? L(" · {directPeers} 直连", ["directPeers": tailscale.directPeers]) : "")
        }
        var parts = [type]
        if connections > 0 { parts.append(L("{connections} 连接", ["connections": connections])) }
        return parts.joined(separator: " · ")
    }
}
