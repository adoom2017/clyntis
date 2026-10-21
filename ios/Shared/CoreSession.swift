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
    /// What is known of the device network, as the JSON `meta_set_network_v1` takes.
    func setNetwork(_ json: Data) throws {
        try Self.check(json.withUnsafeBytes { meta_set_network_v1(handle, $0.bindMemory(to: UInt8.self).baseAddress, $0.count) })
    }
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

    enum ResourceState: UInt32 {
        case current = 0
        /// Present but past an update interval: usable, refresh when convenient.
        case expired = 1
        /// The core cannot start without fetching first.
        case missing = 2
    }

    /// Whether the routing files `configuration` references are in `directory`
    /// and current. Cheap: no geo data is parsed.
    static func resourceState(configuration: Data, directory: URL) throws -> ResourceState {
        let path = Data(directory.path.utf8)
        var state: UInt32 = 0
        let result = configuration.withUnsafeBytes { config in
            path.withUnsafeBytes { path in
                meta_resources_state_v1(config.bindMemory(to: UInt8.self).baseAddress, config.count,
                                        path.bindMemory(to: UInt8.self).baseAddress, path.count, &state)
            }
        }
        try check(result)
        return ResourceState(rawValue: state) ?? .missing
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

    /// The first YAML syntax error in an edited configuration (1-based position).
    struct YAMLProblem: Decodable, Equatable {
        let line: Int
        let column: Int
        let message: String
    }

    /// Nil when `text` parses as a YAML mapping; a failed check counts as none,
    /// since saving validates again.
    static func yamlProblem(in text: String) -> YAMLProblem? {
        let bytes = Data(text.utf8)
        guard let data = try? bytes.withUnsafeBytes({ config in
            try read { meta_yaml_check_v1(config.bindMemory(to: UInt8.self).baseAddress, config.count, $0, $1, $2) }
        }) else { return nil }
        return try? JSONDecoder().decode(YAMLProblem?.self, from: data)
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

    /// The configuration with app settings (`AppOverrides` JSON) applied.
    static func applyOverrides(_ overrides: Data, to configuration: Data) throws -> Data {
        try configuration.withUnsafeBytes { config in
            try overrides.withUnsafeBytes { overrides in
                try read(limit: 24 * 1024 * 1024) {
                    meta_overrides_apply_v1(config.bindMemory(to: UInt8.self).baseAddress, config.count,
                                            overrides.bindMemory(to: UInt8.self).baseAddress, overrides.count, $0, $1, $2)
                }
            }
        }
    }

    /// The Tencent COS object behind `url` (a subscription link, say), or nil.
    static func cosTarget(url: String) -> CosTarget? {
        let bytes = Data(url.utf8)
        guard let data = try? bytes.withUnsafeBytes({ url in
            try read { meta_cos_target_v1(url.bindMemory(to: UInt8.self).baseAddress, url.count, $0, $1, $2) }
        }) else { return nil }
        return try? JSONDecoder().decode(CosTarget?.self, from: data)
    }

    /// Uploads `data` to Tencent COS, replacing the object. Blocks up to 30 s.
    static func cosPut(_ data: Data, to target: CosTarget, secretID: String, secretKey: String) throws {
        struct Request: Encodable {
            struct Credentials: Encodable { let secretId: String; let secretKey: String }
            let target: CosTarget
            let credentials: Credentials
            let contentType = "text/plain; charset=utf-8"
        }
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let request = try encoder.encode(Request(
            target: target, credentials: .init(secretId: secretID, secretKey: secretKey)))
        try check(request.withUnsafeBytes { request in
            data.withUnsafeBytes { body in
                meta_cos_put_v1(request.bindMemory(to: UInt8.self).baseAddress, request.count,
                                body.bindMemory(to: UInt8.self).baseAddress, body.count)
            }
        })
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

    /// Whether the core stopped, its connection count and traffic: the cheap
    /// periodic check (the snapshot also serializes the configuration).
    func status() throws -> Data {
        try Self.read { meta_status_v1(handle, $0, $1, $2) }
    }

    /// Delay through `name` in milliseconds; blocks, so never call it on the
    /// packet queue. The outcome also lands in the snapshot's `proxies`.
    func probe(_ name: String, timeoutMs: UInt32 = 8000) throws -> UInt32 {
        let bytes = Data(name.utf8)
        var delay: UInt32 = 0
        let result = bytes.withUnsafeBytes {
            meta_probe_v1(handle, $0.bindMemory(to: UInt8.self).baseAddress, $0.count, timeoutMs, &delay)
        }
        try Self.check(result)
        return delay
    }

    /// Which rule `target` (a domain, address or URL) matches and the node it
    /// would use, as the core's JSON. May resolve the name: never call it on
    /// the packet queue.
    func testRoute(_ target: String, network: String) throws -> Data {
        let request = try JSONSerialization.data(withJSONObject: ["target": target, "network": network])
        return try request.withUnsafeBytes { request in
            try Self.read {
                meta_test_route_v1(handle, request.bindMemory(to: UInt8.self).baseAddress, request.count, $0, $1, $2)
            }
        }
    }

    /// DNS leak detection as the core's JSON (`audit`, and `test` when
    /// `online`). Online blocks for up to ~30 s: never on the packet queue.
    func dnsLeak(online: Bool) throws -> Data {
        try Self.read { meta_dns_leak_v1(handle, online ? 1 : 0, $0, $1, $2) }
    }

    /// Closes connection `id`, or every connection when `id` is nil.
    func closeConnection(_ id: String?) throws {
        guard let id else {
            try Self.check(meta_close_connections_v1(handle))
            return
        }
        let bytes = Data(id.utf8)
        try Self.check(bytes.withUnsafeBytes {
            meta_close_connection_v1(handle, $0.bindMemory(to: UInt8.self).baseAddress, $0.count)
        })
    }

    /// Replaces the ad blocking allowlist without restarting.
    func updateAdblockAllow(_ allow: [String]) throws {
        let data = try JSONSerialization.data(withJSONObject: ["adblock-allow": allow])
        try Self.check(data.withUnsafeBytes {
            meta_update_v1(handle, $0.bindMemory(to: UInt8.self).baseAddress, $0.count)
        })
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

/// A Tencent COS object: `https://<bucket>.cos.<region>.myqcloud.com/<key>`.
struct CosTarget: Codable, Equatable {
    var bucket: String
    var region: String
    var key: String

    var url: String? {
        guard !bucket.isEmpty, !region.isEmpty, !key.isEmpty else { return nil }
        let path = key.split(separator: "/", omittingEmptySubsequences: false)
            .map { $0.addingPercentEncoding(withAllowedCharacters: .urlUnreserved) ?? String($0) }
            .joined(separator: "/")
        return "https://\(bucket).cos.\(region).myqcloud.com/\(path)"
    }
}

private extension CharacterSet {
    /// RFC 3986 unreserved characters, as COS encodes object keys.
    static let urlUnreserved = CharacterSet(charactersIn:
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
}
