import Foundation
import NetworkExtension
import Observation

@MainActor @Observable
final class AppModel {
    var profiles: [Profile] = []
    var selectedID: UUID? {
        didSet { UserDefaults.standard.set(selectedID?.uuidString, forKey: "selectedProfile") }
    }
    var status: NEVPNStatus = .disconnected
    var busy = false
    /// Shown under the status while a slow connect step runs.
    var phase: String?
    var error: String?
    var upload: UInt64 = 0
    var download: UInt64 = 0
    var connectionCount = 0
    var mode = "rule"
    var groups: [ProxyGroup] = []
    /// Proxies outside every group (for example a Tailscale node used only by rules).
    var ungrouped: [String] = []
    var nodeStatus: [String: NodeStatus] = [:]
    /// Open connections from the core snapshot, newest first.
    var connections: [ConnectionInfo] = []
    /// Ad blocking state and counters from the snapshot.
    var adblock: AdblockStatus?
    var probing: Set<String> = []
    /// Rules matched before every profile's own (see CustomRules).
    var customRules: [String] = []
    /// App settings that replace the profile's values (see AppOverrides).
    var overrides = AppOverrides()
    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var store: ProfileStore?
    private var requestInFlight = false

    var connected: Bool { status == .connected || status == .reasserting }
    var active: Bool { connected || status == .connecting || status == .disconnecting }
    var selected: Profile? { profiles.first { $0.id == selectedID } }
    var statusText: String {
        switch status {
        case .connected: "已连接"
        case .connecting: "正在连接"
        case .disconnecting: "正在断开"
        case .reasserting: "正在重连"
        default: "未连接"
        }
    }

    func load() async {
        guard store == nil else { return }
        customRules = CustomRules.load()
        overrides = AppOverrides.load()
        do {
            let store = try ProfileStore.shared()
            self.store = store
            profiles = try store.profiles()
            selectedID = UserDefaults.standard.string(forKey: "selectedProfile").flatMap(UUID.init(uuidString:))
            if selected == nil { selectedID = profiles.first?.id }
            #if !targetEnvironment(simulator)
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = managers.first {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == tunnelIdentifier
            }
            Diagnostics.app.info("load: \(managers.count) VPN configuration(s), ours=\(self.manager != nil)")
            if let manager {
                status = manager.connection.status
                if active, let rawID = (manager.protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerConfiguration?["profileID"] as? String {
                    selectedID = UUID(uuidString: rawID)
                }
            }
            statusObserver = NotificationCenter.default.addObserver(
                forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] notification in
                    Task { @MainActor in
                        guard let self, let connection = notification.object as? NEVPNConnection,
                              connection === self.manager?.connection else { return }
                        self.status = connection.status
                        Diagnostics.app.info("vpn status -> \(connection.status.rawValue)")
                        if connection.status == .disconnected {
                            // Ask the system why the tunnel stopped (start failure, provider error, ...).
                            connection.fetchLastDisconnectError { error in
                                if let error {
                                    Diagnostics.app.error("vpn disconnected: \(Diagnostics.describe(error))")
                                }
                            }
                        }
                        if !self.active {
                            self.upload = 0; self.download = 0; self.connectionCount = 0; self.groups = []
                            self.ungrouped = []; self.nodeStatus = [:]; self.connections = []
                            self.adblock = nil
                        }
                    }
                }
            #endif
        } catch {
            Diagnostics.app.error("load: \(Diagnostics.describe(error))")
            self.error = error.localizedDescription
        }
    }

    private var tunnelIdentifier: String {
        Bundle.main.object(forInfoDictionaryKey: "ClyntisTunnelIdentifier") as? String ?? "org.clyntis.ios.tunnel"
    }

    func toggleConnection() async {
        guard !busy, let store else { return }
        if active { manager?.connection.stopVPNTunnel(); return }
        #if targetEnvironment(simulator)
        error = "模拟器不支持 VPN，请在已签名的真机上运行。"
        return
        #else
        guard let selected else { error = "请先导入配置。"; return }
        busy = true
        defer { busy = false; phase = nil }
        let log = Diagnostics.app
        log.info("connect: begin profile=\(selected.id.uuidString) tunnel=\(self.tunnelIdentifier) existingManager=\(self.manager != nil)")
        var step = "read configuration"
        do {
            // Validate and prefetch what the tunnel will run: the profile with
            // custom rules and app settings.
            let (withRules, skipped) = try CustomRules.applied(to: store.configuration(for: selected.id))
            let bytes = try overrides.applied(to: withRules)
            if !skipped.isEmpty { log.warning("connect: \(skipped.count) custom rule(s) skipped for this profile") }
            step = "validate configuration"
            log.info("connect: \(step) (\(bytes.count) bytes)")
            try await validate(bytes, directory: store.directory(for: selected.id))
            // Fetch GeoIP/GeoSite and rule providers here, where neither the tunnel's
            // ~50 MiB memory limit nor its start timeout applies. Only missing files
            // hold up connecting: expired ones still work and are refreshed after the
            // tunnel is up (the tunnel refreshes rule providers itself; geo files
            // take effect on the next connect).
            step = "check resources"
            let directory = store.directory(for: selected.id)
            let resources = (try? await Task.detached {
                try CoreSession.resourceState(configuration: bytes, directory: directory)
            }.value) ?? .missing
            log.info("connect: routing resources \(String(describing: resources))")
            if resources == .missing {
                step = "prefetch resources"
                phase = "正在下载路由资源…"
                let started = Date()
                do {
                    try await Task.detached {
                        try CoreSession.prefetchResources(configuration: bytes, directory: directory)
                    }.value
                    log.info("connect: resources ready in \(String(format: "%.1f", Date().timeIntervalSince(started)))s")
                } catch {
                    // Not fatal: the tunnel can still fetch what is missing itself.
                    log.warning("connect: prefetch failed: \(Diagnostics.describe(error))")
                }
                phase = nil
            }
            // Validation and prefetch ran a core in this process; keep its logs.
            Diagnostics.collectCoreLogs()
            let manager = self.manager ?? NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = tunnelIdentifier
            proto.serverAddress = "Clyntis"
            proto.providerConfiguration = ["profileID": selected.id.uuidString]
            proto.disconnectOnSleep = false
            proto.includeAllNetworks = false
            manager.protocolConfiguration = proto
            manager.localizedDescription = "Clyntis"
            manager.isEnabled = true
            manager.isOnDemandEnabled = false
            step = "save preferences"
            log.info("connect: \(step)")
            try await manager.saveToPreferences()
            step = "reload preferences"
            log.info("connect: \(step)")
            try await manager.loadFromPreferences()
            self.manager = manager
            step = "start tunnel"
            log.info("connect: \(step) enabled=\(manager.isEnabled) status=\(manager.connection.status.rawValue)")
            try manager.connection.startVPNTunnel()
            status = manager.connection.status
            log.info("connect: start requested, status=\(self.status.rawValue)")
            if resources == .expired { refreshResources(bytes, directory: directory) }
        } catch {
            log.error("connect: failed at \(step): \(Diagnostics.describe(error))")
            self.error = error.localizedDescription
        }
        #endif
    }

    /// An encrypted file waiting for its password; the UI prompts while this is set.
    var pendingEncryptedImport: PendingImport?

    func importFile(_ url: URL) async {
        guard !busy, let store else { return }
        busy = true
        defer { busy = false }
        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }
        do {
            let name = url.deletingPathExtension().lastPathComponent
            let data = try await Task.detached {
                // Base64 ciphertext is larger than the 16 MiB plaintext it decrypts to.
                let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
                guard size > 0, size <= 24 * 1024 * 1024 else {
                    throw ClientError.message("配置为空或超过大小限制。")
                }
                return try Data(contentsOf: url)
            }.value
            if ConfigCrypto.looksEncrypted(data) {
                pendingEncryptedImport = PendingImport(name: name, data: data)
                return
            }
            try await add(name: name, configuration: data, in: store)
        } catch { self.error = error.localizedDescription }
    }

    /// Throws so the password prompt can show the failure and let the user retry.
    func importEncrypted(password: String) async throws {
        guard !busy, let store, let pending = pendingEncryptedImport else { return }
        busy = true
        defer { busy = false }
        let plaintext = try await Task.detached {
            try ConfigCrypto.decrypt(pending.data, password: password)
        }.value
        try await add(name: pending.name, configuration: plaintext, in: store)
        pendingEncryptedImport = nil
    }

    func exportEncrypted(_ profile: Profile, password: String) async throws -> Data {
        guard let store else { throw ClientError.message("配置存储不可用。") }
        return try await Task.detached {
            try ConfigCrypto.encrypt(store.configuration(for: profile.id), password: password)
        }.value
    }

    private func add(name: String, configuration: Data, in store: ProfileStore) async throws {
        let profile = try await Task.detached {
            try store.add(name: name, configuration: configuration) { bytes, directory in
                let session = try CoreSession(configuration: bytes, directory: directory)
                session.close()
            }
        }.value
        profiles = try store.profiles()
        if !active { selectedID = profile.id }
    }

    func remove(_ profile: Profile) {
        guard !active, !busy, let store else { return }
        do {
            try store.remove(profile)
            profiles = try store.profiles()
            if selectedID == profile.id { selectedID = profiles.first?.id }
        } catch { self.error = error.localizedDescription }
    }

    func importRemote(address: String, password: String, name: String) async throws {
        guard !busy, let store else { throw ClientError.message("正在处理其他操作，请稍后再试。") }
        busy = true
        defer { busy = false }
        let url = try RemoteConfigImporter.url(from: address)
        let source = try await RemoteConfigImporter.download(from: url, encrypted: !password.isEmpty)
        try Task.checkCancellation()
        let worker = Task.detached {
            try RemoteConfigImporter.store(source, password: password, name: name, link: url, in: store)
        }
        let profile = try await withTaskCancellationHandler {
            try await worker.value
        } onCancel: { worker.cancel() }
        profiles = try store.profiles()
        if !active { selectedID = profile.id }
    }

    /// Downloads expired routing files in the background for the next connect.
    private func refreshResources(_ configuration: Data, directory: URL) {
        Task.detached(priority: .utility) {
            let started = Date()
            do {
                try CoreSession.prefetchResources(configuration: configuration, directory: directory)
                Diagnostics.app.info("resources refreshed in background in \(String(format: "%.1f", Date().timeIntervalSince(started)))s")
            } catch {
                Diagnostics.app.warning("background resource refresh failed: \(Diagnostics.describe(error))")
            }
            Diagnostics.collectCoreLogs()
        }
    }

    // MARK: Custom rules

    func saveCustomRules(_ rules: [String]) throws {
        try CustomRules.save(rules)
        customRules = CustomRules.load()
        Diagnostics.app.info("custom rules saved (\(customRules.count))")
    }

    /// Saves ad blocking settings. An allowlist-only change reaches the running
    /// tunnel at once; other changes apply on the next connection.
    /// Returns whether a reconnect is needed for them to take effect.
    @discardableResult
    func saveAdblock(_ value: AdblockSettings?) async throws -> Bool {
        let previous = overrides.adblock
        var next = overrides
        next.adblock = value
        try saveOverrides(next)
        guard active else { return false }
        if previous?.withoutAllow != value?.withoutAllow {
            return true
        }
        if previous?.allow != value?.allow, connected {
            try applySnapshot(await send(TunnelMessage(command: "adblock-allow", allow: value?.allow ?? [])))
        }
        return false
    }

    /// The running core's ad blocking compared with the saved settings.
    enum AdblockState { case off, pending, on }
    var adblockState: AdblockState {
        let wanted = overrides.adblock?.enabled == true
        if adblock?.enabled == true { return .on }
        return wanted ? .pending : .off
    }
    var adblockSummary: String {
        switch adblockState {
        case .on: "已拦截 \((adblock?.total ?? 0).formatted()) 次"
        case .pending: "重新连接后生效"
        case .off: "未开启"
        }
    }

    /// Adds `domain` to the allowlist (from the statistics), live.
    /// Adds `domain` to the app's allowlist and applies it to the running core.
    func allowAdblock(_ domain: String) async throws {
        guard var settings = overrides.adblock else {
            throw ClientError.message("去广告由配置文件开启，请在配置的 adblock.allow 中放行，或在本页开启去广告后再放行。")
        }
        guard !settings.allow.contains(domain) else { return }
        settings.allow.append(domain)
        _ = try await saveAdblock(settings)
    }

    func saveOverrides(_ value: AppOverrides) throws {
        try value.save()
        overrides = AppOverrides.load()
        Diagnostics.app.info("app settings saved")
    }

    /// Targets offered by the selected profile; DIRECT and REJECT without one.
    func customRuleTargets() -> [String] {
        guard let store, let selected,
              let configuration = try? store.configuration(for: selected.id),
              let targets = try? CoreSession.ruleTargets(configuration: configuration) else {
            return ["DIRECT", "REJECT"]
        }
        return targets
    }

    /// Custom rules the selected profile cannot use, keyed by rule.
    func skippedCustomRules() -> [String: String] {
        guard let store, let selected, !customRules.isEmpty,
              let configuration = try? store.configuration(for: selected.id),
              let (_, skipped) = try? CoreSession.applyRules(customRules, to: configuration) else { return [:] }
        return Dictionary(skipped.map { ($0.rule, $0.reason) }, uniquingKeysWith: { first, _ in first })
    }

    /// Stops the tunnel and starts it again so changed rules take effect.
    func reconnect() async {
        guard active else { return }
        manager?.connection.stopVPNTunnel()
        for _ in 0..<50 where status != .disconnected && status != .invalid {
            try? await Task.sleep(for: .milliseconds(200))
        }
        await toggleConnection()
    }

    // MARK: Profile details

    func configurationText(for profile: Profile) throws -> String {
        guard let store else { throw ClientError.message("配置存储不可用。") }
        return String(decoding: try store.configuration(for: profile.id), as: UTF8.self)
    }

    /// Validates and saves edited YAML. A running tunnel keeps its loaded copy until reconnected.
    func saveConfiguration(_ text: String, for profile: Profile) async throws {
        guard let store else { throw ClientError.message("配置存储不可用。") }
        let data = Data(text.utf8)
        try await Task.detached {
            _ = try store.replaceConfiguration(profile.id, with: data) { bytes, directory in
                try CoreSession(configuration: bytes, directory: directory).close()
            }
        }.value
        Diagnostics.app.info("profile \(profile.id.uuidString): configuration edited (\(data.count) bytes)")
        profiles = try store.profiles()
    }

    func rename(_ profile: Profile, to name: String) throws {
        guard let store else { throw ClientError.message("配置存储不可用。") }
        _ = try store.rename(profile.id, to: name)
        profiles = try store.profiles()
    }

    /// Downloads the profile's link again and replaces its configuration.
    func updateFromSource(_ profile: Profile, password: String = "") async throws {
        guard let store, let source = profile.source else { throw ClientError.message("此配置不是从链接导入的。") }
        let url = try RemoteConfigImporter.url(from: source)
        let body = try await RemoteConfigImporter.download(from: url, encrypted: !password.isEmpty)
        try await Task.detached {
            let plaintext = try RemoteConfigImporter.plaintext(body, password: password)
            _ = try store.replaceConfiguration(profile.id, with: plaintext) { bytes, directory in
                try CoreSession(configuration: bytes, directory: directory).close()
            }
        }.value
        Diagnostics.app.info("profile \(profile.id.uuidString): updated from \(url.host ?? "link") (\(body.count) bytes)")
        profiles = try store.profiles()
    }

    private func validate(_ data: Data, directory: URL) async throws {
        try await Task.detached {
            let session = try CoreSession(configuration: data, directory: directory)
            session.close()
        }.value
    }

    func refreshSnapshot() async {
        guard connected, !requestInFlight else { return }
        requestInFlight = true
        defer { requestInFlight = false }
        do {
            let data = try await send(TunnelMessage(command: "snapshot"))
            try applySnapshot(data)
        } catch {
            Diagnostics.app.error("snapshot: \(Diagnostics.describe(error))")
            if connected { self.error = error.localizedDescription }
        }
    }

    func setMode(_ value: String) async {
        guard connected, !busy else { return }
        busy = true
        defer { busy = false }
        do { try applySnapshot(await send(TunnelMessage(command: "mode", mode: value))) }
        catch { self.error = error.localizedDescription }
    }

    func select(group: String, node: String) async {
        guard connected, !busy else { return }
        busy = true
        defer { busy = false }
        do { try applySnapshot(await send(TunnelMessage(command: "select", group: group, node: node))) }
        catch { self.error = error.localizedDescription }
    }

    /// Closes one connection, or all of them when `id` is nil.
    func closeConnection(_ id: String?) async {
        guard connected else { return }
        do { try applySnapshot(await send(TunnelMessage(command: "close", id: id))) }
        catch { self.error = error.localizedDescription }
    }

    /// Tests the delay through `node`; the result lands in `nodeStatus`.
    func probe(_ node: String) async {
        guard connected, nodeStatus[node]?.type == "VLESS", !probing.contains(node) else { return }
        probing.insert(node)
        defer { probing.remove(node) }
        do { try applySnapshot(await send(TunnelMessage(command: "probe", node: node), timeout: 15)) }
        catch { Diagnostics.app.warning("probe \(node): \(Diagnostics.describe(error))") }
    }

    /// Tests every VLESS node, two at a time (the core accepts a few at once).
    func probeAll() async {
        var queue = nodeStatus.filter { $0.value.type == "VLESS" }.map(\.key).sorted()
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<2 {
                guard !queue.isEmpty else { break }
                let first = queue.removeFirst()
                group.addTask { await self.probe(first) }
            }
            while await group.next() != nil {
                guard !queue.isEmpty else { continue }
                let next = queue.removeFirst()
                group.addTask { await self.probe(next) }
            }
        }
    }

    /// Which rule `target` matches in the running core and the node it uses.
    func testRoute(_ target: String, network: String) async throws -> RouteTest {
        guard connected else { throw ClientError.message("VPN 未连接。") }
        let data = try await send(TunnelMessage(command: "test-route", target: target, network: network), timeout: 15)
        if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let error = object["error"] as? String {
            throw ClientError.message(error)
        }
        return try JSONDecoder().decode(RouteTest.self, from: data)
    }

    /// The configuration review, plus the online bash.ws test when `online`.
    func dnsLeak(online: Bool) async throws -> DnsLeakResult {
        guard connected else { throw ClientError.message("VPN 未连接。") }
        let data = try await send(TunnelMessage(command: "dns-leak", online: online), timeout: online ? 45 : 5)
        if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let error = object["error"] as? String {
            throw ClientError.message(error)
        }
        return try JSONDecoder().decode(DnsLeakResult.self, from: data)
    }

    private func send(_ message: TunnelMessage, timeout: Double = 5) async throws -> Data {
        guard let session = manager?.connection as? NETunnelProviderSession else {
            throw ClientError.message("VPN 会话不可用。")
        }
        let payload = try JSONEncoder().encode(message)
        return try await withCheckedThrowingContinuation { continuation in
            let reply = MessageReply(continuation)
            DispatchQueue.main.asyncAfter(deadline: .now() + timeout) {
                reply.finish(.failure(ClientError.message("VPN 无响应。")))
            }
            do {
                try session.sendProviderMessage(payload) { data in
                    if let data { reply.finish(.success(data)) }
                    else { reply.finish(.failure(ClientError.message("VPN 已停止或无法响应。"))) }
                }
            } catch { reply.finish(.failure(error)) }
        }
    }

    private func applySnapshot(_ data: Data) throws {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ClientError.message("无效的内核状态。")
        }
        if let error = object["error"] as? String { throw ClientError.message(error) }
        if object["stopped"] as? Bool == true { throw ClientError.message("内核已停止，请重新连接。") }
        upload = (object["upload"] as? NSNumber)?.uint64Value ?? 0
        download = (object["download"] as? NSNumber)?.uint64Value ?? 0
        connectionCount = (object["connections"] as? [Any])?.count ?? 0
        connections = ConnectionInfo.decode(object["connections"])
        adblock = AdblockStatus.decode(object["adblock"])
        if let config = object["config"] as? [String: Any] {
            mode = config["mode"] as? String ?? "rule"
            let selections = object["selections"] as? [String: String] ?? [:]
            groups = (config["proxy-groups"] as? [[String: Any]] ?? []).compactMap { group in
                guard let name = group["name"] as? String, let nodes = group["proxies"] as? [String] else { return nil }
                return ProxyGroup(name: name, nodes: nodes, selected: selections[name])
            }
            let grouped = Set(groups.flatMap(\.nodes))
            ungrouped = (config["proxies"] as? [[String: Any]] ?? [])
                .compactMap { $0["name"] as? String }
                .filter { !grouped.contains($0) }
        }
        nodeStatus = NodeStatus.decode(object["proxies"])
    }
}

struct PendingImport {
    let name: String
    let data: Data
}

struct ProxyGroup: Identifiable {
    var id: String { name }
    let name: String
    let nodes: [String]
    let selected: String?
}

/// How the core would route a domain or address now (see `meta_test_route_v1`).
struct RouteTest: Decodable {
    let host: String
    let port: Int
    let network: String
    /// The address IP rules saw, when a rule needed one.
    let ip: String?
    /// The matching rule as written; nil for ad blocking, modes and fallback.
    let rule: String?
    let index: Int?
    /// Short form: `DomainSuffix(x)`, `Adblock`, `Mode(Global)`, `Fallback`.
    let matched: String
    /// The rule's target, then each group's selection down to `node`.
    let chain: [String]
    let node: String
    /// A rule resolved the name through the core's upstreams before matching.
    let resolvedLocally: Bool

    private enum CodingKeys: String, CodingKey {
        case host, port, network, ip, rule, index, matched, chain, node
        case resolvedLocally = "resolved_locally"
    }
}

/// DNS leak detection (see `meta_dns_leak_v1`).
struct DnsLeakResult: Decodable {
    struct Finding: Decodable {
        /// "risk", "warning" or "info".
        let level: String
        let code: String
        let title: String
        let detail: String
        let items: [String]
    }
    struct Audit: Decodable {
        let leaking: Bool
        let findings: [Finding]
    }
    struct Server: Decodable {
        let ip: String
        let country: String
        let asn: String
    }
    struct Probe: Decodable {
        let resolvers: [Server]
        let conclusion: String?
        let error: String?
    }
    struct Test: Decodable {
        let exit: [Server]
        /// Node and rule bash.ws traffic uses; the test reflects that route.
        let node: String
        let matched: String
        /// Resolvers seen when connecting like an app, and behind the core's upstreams.
        let routed: Probe
        let local: Probe
    }
    let audit: Audit
    let test: Test?
}

private final class MessageReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?
    init(_ continuation: CheckedContinuation<Data, Error>) { self.continuation = continuation }
    func finish(_ result: Result<Data, Error>) {
        lock.lock()
        let continuation = continuation
        self.continuation = nil
        lock.unlock()
        continuation?.resume(with: result)
    }
}
