import Foundation

// Every instance is confined to its owner's serial queue; FFI callbacks only enqueue work.
final class CoreSession {
    private(set) var handle: UInt64 = 0

    init(configuration: Data, directory: URL, hooks: UnsafePointer<meta_hooks_v1>? = nil) throws {
        guard meta_abi_version_v1() == 1 else { throw ClientError.message("内核接口版本不匹配。") }
        let path = Data(directory.path.utf8)
        let result = configuration.withUnsafeBytes { config in
            path.withUnsafeBytes { path in
                meta_create_packet_tunnel_v1(
                    config.bindMemory(to: UInt8.self).baseAddress, config.count,
                    path.bindMemory(to: UInt8.self).baseAddress, path.count, hooks, &handle)
            }
        }
        try Self.check(result)
    }

    deinit { close() }
    func start() throws { try Self.check(meta_start_v1(handle)) }
    func networkChanged() throws { try Self.check(meta_network_changed_v1(handle)) }
    func close() {
        guard handle != 0 else { return }
        _ = meta_destroy_v1(handle) // Stops workers and joins callbacks before invalidating context.
        handle = 0
    }

    /// Downloads missing/expired routing resources into `directory`. Blocking; run
    /// it in the app before starting the tunnel, whose process is memory-limited.
    static func prefetchResources(configuration: Data, directory: URL) throws {
        let path = Data(directory.path.utf8)
        let result = configuration.withUnsafeBytes { config in
            path.withUnsafeBytes { path in
                meta_prefetch_resources_v1(config.bindMemory(to: UInt8.self).baseAddress, config.count,
                                           path.bindMemory(to: UInt8.self).baseAddress, path.count)
            }
        }
        try check(result)
    }

    /// Throws with the core's reason when `rule` is not a valid custom rule.
    static func validateRule(_ rule: String) throws {
        let bytes = Data(rule.utf8)
        try check(bytes.withUnsafeBytes {
            meta_custom_rule_validate_v1($0.bindMemory(to: UInt8.self).baseAddress, $0.count)
        })
    }

    /// Names usable as a rule target in this configuration (DIRECT, REJECT, groups, proxies).
    static func ruleTargets(configuration: Data) throws -> [String] {
        let data = try configuration.withUnsafeBytes { config in
            try read { meta_custom_rule_targets_v1(config.bindMemory(to: UInt8.self).baseAddress, config.count, $0, $1, $2) }
        }
        return try JSONDecoder().decode([String].self, from: data)
    }

    struct SkippedRule: Decodable, Hashable {
        let rule: String
        let reason: String
    }

    /// The configuration with the usable custom rules first, and the rules it cannot use.
    static func applyRules(_ rules: [String], to configuration: Data) throws -> (Data, [SkippedRule]) {
        struct Applied: Decodable {
            let yaml: String
            let skipped: [SkippedRule]
        }
        let json = try JSONEncoder().encode(rules)
        let data = try configuration.withUnsafeBytes { config in
            try json.withUnsafeBytes { rules in
                // The merged configuration can be as large as the profile (16 MiB).
                try read(limit: 24 * 1024 * 1024) {
                    meta_custom_rules_apply_v1(config.bindMemory(to: UInt8.self).baseAddress, config.count,
                                               rules.bindMemory(to: UInt8.self).baseAddress, rules.count, $0, $1, $2)
                }
            }
        }
        let applied = try JSONDecoder().decode(Applied.self, from: data)
        return (Data(applied.yaml.utf8), applied.skipped)
    }

    /// Buffered core log lines of this process (newline-separated JSON), removed once read.
    static func drainLogs() throws -> Data {
        try read { meta_drain_logs_v1($0, $1, $2) }
    }

    /// Top-level `ipv6` of the running configuration; the tunnel routes IPv6
    /// only when it is enabled.
    func enablesIPv6() throws -> Bool {
        let state = try JSONSerialization.jsonObject(with: snapshot()) as? [String: Any]
        return (state?["config"] as? [String: Any])?["ipv6"] as? Bool ?? false
    }

    func snapshot() throws -> Data {
        try Self.read { meta_snapshot_v1(handle, $0, $1, $2) }
    }

    func updateMode(_ mode: String) throws {
        guard ["rule", "global", "direct"].contains(mode) else { throw ClientError.message("无效的代理模式。") }
        let data = try JSONSerialization.data(withJSONObject: ["mode": mode])
        let result = data.withUnsafeBytes {
            meta_update_v1(handle, $0.bindMemory(to: UInt8.self).baseAddress, $0.count)
        }
        try Self.check(result)
    }

    func select(group: String, node: String) throws {
        let group = Data(group.utf8), node = Data(node.utf8)
        let result = group.withUnsafeBytes { group in
            node.withUnsafeBytes { node in
                meta_select_v1(handle, group.bindMemory(to: UInt8.self).baseAddress, group.count,
                               node.bindMemory(to: UInt8.self).baseAddress, node.count)
            }
        }
        try Self.check(result)
    }

    static func check(_ result: Int32) throws {
        guard result == META_OK else {
            let data = try? read { meta_error_v1($0, $1, $2) }
            throw ClientError.message(data.flatMap { String(data: $0, encoding: .utf8) } ?? "内核操作失败。")
        }
    }

    private static func read(limit: Int = 1024 * 1024,
                             _ operation: (UnsafeMutablePointer<UInt8>?, Int, UnsafeMutablePointer<Int>) -> Int32) throws -> Data {
        var data = Data(count: 64 * 1024)
        for _ in 0..<3 {
            var length = 0
            let result = data.withUnsafeMutableBytes {
                operation($0.bindMemory(to: UInt8.self).baseAddress, $0.count, &length)
            }
            if result == META_OK { return data.prefix(length) }
            guard result == META_BUFFER_TOO_SMALL, length > 0, length <= limit else {
                throw ClientError.message("无法读取内核结果。")
            }
            data = Data(count: length)
        }
        throw ClientError.message("内核结果变化过快，请重试。")
    }
}
