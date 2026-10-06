import Foundation

/// Rules added in the app, matched before every profile's own rules. Stored in
/// the App Group so the tunnel extension applies them when it starts.
enum CustomRules {
    static let maximum = 1000

    private static var url: URL? {
        ProfileStore.sharedContainer()?.appendingPathComponent("custom-rules.json")
    }

    static func load() -> [String] {
        guard let url, let data = try? Data(contentsOf: url) else { return [] }
        return (try? JSONDecoder().decode([String].self, from: data)) ?? []
    }

    /// Validates each rule with the core, then saves them in order.
    static func save(_ rules: [String]) throws {
        guard let url else { throw ClientError.message("无法访问共享存储。") }
        guard rules.count <= maximum else { throw ClientError.message("自定义规则不能超过 \(maximum) 条。") }
        let rules = rules.map { $0.trimmingCharacters(in: .whitespaces) }
        for (index, rule) in rules.enumerated() {
            do { try CoreSession.validateRule(rule) } catch {
                throw ClientError.message("第 \(index + 1) 条规则「\(rule)」：\(error.localizedDescription)")
            }
        }
        try JSONEncoder().encode(rules).write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    /// The profile with the custom rules applied; the profile alone when there are none.
    static func applied(to configuration: Data) throws -> (Data, [CoreSession.SkippedRule]) {
        let rules = load()
        if rules.isEmpty { return (configuration, []) }
        return try CoreSession.applyRules(rules, to: configuration)
    }
}
