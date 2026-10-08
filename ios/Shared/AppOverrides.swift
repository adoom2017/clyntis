import Foundation

/// Settings chosen in the app that replace the profile's own values. `nil`
/// keeps the profile's value. Stored in the App Group so the tunnel extension
/// applies them when it starts; the merge itself is the core's, shared with macOS.
struct AppOverrides: Codable, Equatable {
    static let logLevels = ["debug", "info", "warning", "error", "silent"]

    var logLevel: String?
    var ipv6: Bool?
    var sniffing: Bool?

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
