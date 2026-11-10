import Foundation

/// Settings chosen in the app that replace the profile's own values. `nil`
/// keeps the profile's value. Stored in the App Group so the tunnel extension
/// applies them when it starts; the merge itself is the core's, shared with macOS.
struct AppOverrides: Codable, Equatable {
    static let logLevels = ["debug", "info", "warning", "error", "silent"]

    var logLevel: String?
    var ipv6: Bool?
    var sniffing: Bool?
    /// Whether the profile's Tailscale proxies run.
    var tailscale: Bool?
    var adblock: AdblockSettings?
    /// HTTPS decryption; the running tunnel takes changes live.
    var mitm: MitmSettings?

    var isEmpty: Bool { self == AppOverrides() }

    private static var url: URL? {
        ProfileStore.sharedContainer()?.appendingPathComponent("overrides.json")
    }

    static func load() -> AppOverrides {
        guard let url, let data = try? Data(contentsOf: url) else { return AppOverrides() }
        return (try? JSONDecoder().decode(AppOverrides.self, from: data)) ?? AppOverrides()
    }

    func save() throws {
        guard let url = Self.url else { throw ClientError.message(L("无法访问共享存储。")) }
        if let logLevel, !Self.logLevels.contains(logLevel) {
            throw ClientError.message(L("无效日志级别「{logLevel}」。", ["logLevel": logLevel]))
        }
        var stored = self
        // The CA lives in its own files (MitmAuthority).
        stored.mitm = mitm?.withoutAuthority
        try JSONEncoder().encode(stored).write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    /// These settings with the decryption CA filled in, for the core.
    func withMitmAuthority() -> AppOverrides {
        var copy = self
        copy.mitm = mitm?.withAuthority(MitmAuthority.load())
        return copy
    }

    /// The configuration with these settings applied; unchanged when none is set.
    func applied(to configuration: Data) throws -> Data {
        if isEmpty { return configuration }
        return try CoreSession.applyOverrides(JSONEncoder().encode(self), to: configuration)
    }
}

/// Ad blocking settings; the core expands presets (clyntis_config::adblock).
struct AdblockSettings: Codable, Equatable {
    struct List: Codable, Equatable, Hashable {
        var name: String
        var url: String
        var format: String
    }
    var enabled = true
    var presets = ["awavenue"]
    var custom: [List] = []
    var allow: [String] = []
    /// `nil` takes the core's default (on, on, nxdomain); optional so settings
    /// saved before these options still decode.
    var blockHttpdns: Bool?
    var quicFallback: Bool?
    var dnsAnswer: String?

    /// Everything except the allowlist, which the running core takes live.
    var withoutAllow: AdblockSettings {
        var copy = self
        copy.allow = []
        return copy
    }

    static let presetsOffered: [(id: String, name: String, detail: String)] = [
        ("awavenue", "AWAvenue-Ads", L("国内 App 广告接口，约 1,000 条，误杀少")),
        ("anti-ad", "anti-AD", L("覆盖面广，以国内为主，约 10 万条")),
        ("adguard-dns", "AdGuard DNS filter", L("偏海外的广告与追踪，约 18 万条，内存占用较大")),
    ]
}

/// HTTPS decryption settings (clyntis_config::overrides::MitmSettings).
struct MitmSettings: Codable, Equatable {
    var enable = false
    var hostnames: [String] = []
    /// The CA (PEM), filled in from MitmAuthority only on the way to the core.
    var caCert: String?
    var caKey: String?

    var withoutAuthority: MitmSettings {
        var copy = self
        copy.caCert = nil
        copy.caKey = nil
        return copy
    }

    func withAuthority(_ authority: MitmAuthority?) -> MitmSettings {
        var copy = self
        copy.caCert = authority?.cert
        copy.caKey = authority?.key
        return copy
    }

    /// The update meta_update_v1 takes to apply these settings live.
    func coreUpdate() throws -> Data {
        var mitm: [String: Any] = [
            "enable": enable,
            "hostname": hostnames.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty },
        ]
        if let caCert { mitm["ca-cert"] = caCert }
        if let caKey { mitm["ca-key"] = caKey }
        return try JSONSerialization.data(withJSONObject: ["mitm": mitm])
    }
}
