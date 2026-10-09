import Foundation

/// Settings chosen in the app that replace the profile's own values. `nil`
/// keeps the profile's value. Stored in the App Group so the tunnel extension
/// applies them when it starts; the merge itself is the core's, shared with macOS.
struct AppOverrides: Codable, Equatable {
    static let logLevels = ["debug", "info", "warning", "error", "silent"]

    var logLevel: String?
    var ipv6: Bool?
    var sniffing: Bool?
    var adblock: AdblockSettings?

    var isEmpty: Bool { self == AppOverrides() }

    private static var url: URL? {
        ProfileStore.sharedContainer()?.appendingPathComponent("overrides.json")
    }

    static func load() -> AppOverrides {
        guard let url, let data = try? Data(contentsOf: url) else { return AppOverrides() }
        return (try? JSONDecoder().decode(AppOverrides.self, from: data)) ?? AppOverrides()
    }

    func save() throws {
        guard let url = Self.url else { throw ClientError.message("无法访问共享存储。") }
        if let logLevel, !Self.logLevels.contains(logLevel) {
            throw ClientError.message("无效日志级别「\(logLevel)」。")
        }
        try JSONEncoder().encode(self).write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    /// The configuration with these settings applied; unchanged when none is set.
    func applied(to configuration: Data) throws -> Data {
        if isEmpty { return configuration }
        return try CoreSession.applyOverrides(JSONEncoder().encode(self), to: configuration)
    }
}

/// Ad blocking settings; the core expands presets (meta_config::adblock).
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

    /// Everything except the allowlist, which the running core takes live.
    var withoutAllow: AdblockSettings {
        var copy = self
        copy.allow = []
        return copy
    }

    static let presetsOffered: [(id: String, name: String, detail: String)] = [
        ("awavenue", "AWAvenue-Ads", "国内 App 广告接口，约 1,000 条，误杀少"),
        ("anti-ad", "anti-AD", "覆盖面广，以国内为主，约 10 万条"),
        ("adguard-dns", "AdGuard DNS filter", "偏海外的广告与追踪，约 18 万条，内存占用较大"),
    ]
}
