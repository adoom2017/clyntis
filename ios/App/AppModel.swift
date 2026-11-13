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
    /// A start was requested and iOS has not reacted yet (see `awaitSystemStart`).
    private(set) var startPending = false
    /// Shown under the status while a slow connect step runs.
    var phase: String?
    var error: String?
    var upload: UInt64 = 0
    var download: UInt64 = 0
    var connectionCount = 0
    var mode = "rule"
    var groups: [ProxyGroup] = []
    /// Proxies outside every group (for example a Tailscale node used only by rules).
    /// The profile's `proxies`, in profile order: the servers that carry traffic.
    var proxies: [String] = []
    var nodeStatus: [String: NodeStatus] = [:]
    /// Open connections from the core snapshot, newest first.
    var connections: [ConnectionInfo] = []
    /// Ad blocking state and counters from the snapshot.
    var adblock: AdblockStatus?
    /// The running core's decryption status from the snapshot.
    var mitm: MitmStatus?
    var rewrite: RewriteStatus?
    /// The profile's networks the device is on, while the profile defines
    /// any (see `networks` and `network-overrides`); nil otherwise.
    var currentNetworks: [String]?
    var probing: Set<String> = []
    /// Rules matched before every profile's own (see CustomRules).
    var customRules: [String] = []
    /// App settings that replace the profile's values (see AppOverrides).
    var overrides = AppOverrides()
    /// Whether iOS reconnects the VPN after it ends without the user asking
    /// (connect-on-demand). Off unless the user turns it on.
    private(set) var autoReconnect = UserDefaults.standard.bool(forKey: AppModel.autoReconnectKey)
    private static let autoReconnectKey = "autoReconnect"
    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var startTimeout: Task<Void, Never>?
    private var store: ProfileStore?
    private var requestInFlight = false

    var connected: Bool { status == .connected || status == .reasserting }
    var active: Bool { connected || status == .connecting || status == .disconnecting }
    var selected: Profile? { profiles.first { $0.id == selectedID } }
    var statusText: String {
        switch status {
        case .connected: L("已连接")
        case .connecting: L("正在连接")
        case .disconnecting: L("正在断开")
        case .reasserting: L("正在重连")
        default: L("未连接")
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
                stopRetryingFailedStarts()
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
                        if connection.status != .disconnected { self.endStartWait() }
                        Diagnostics.app.info("vpn status -> \(connection.status.rawValue)")
                        if connection.status == .disconnected {
                            self.stopRetryingFailedStarts()
                            // Ask the system why the tunnel stopped (start failure, provider error, ...).
                            connection.fetchLastDisconnectError { error in
                                if let error {
                                    Diagnostics.app.error("vpn disconnected: \(Diagnostics.describe(error))")
                                }
                            }
                        }
                        if !self.active {
                            self.upload = 0; self.download = 0; self.connectionCount = 0; self.groups = []
                            self.proxies = []; self.nodeStatus = [:]; self.connections = []
                            self.adblock = nil; self.currentNetworks = nil; self.mitm = nil; self.rewrite = nil
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
        guard !busy, !startPending, let store else { return }
        if active { await disconnect(); return }
        #if targetEnvironment(simulator)
        error = L("模拟器不支持 VPN，请在已签名的真机上运行。")
        return
        #else
        guard let selected else { error = L("请先导入配置。"); return }
        busy = true
        defer { busy = false; phase = nil }
        let log = Diagnostics.app
        log.info("connect: begin profile=\(selected.id.uuidString) tunnel=\(self.tunnelIdentifier) existingManager=\(self.manager != nil)")
        var step = "read configuration"
        do {
            // Validate what the tunnel will run: the profile with
            // custom rules and app settings.
            let (withRules, skipped) = try CustomRules.applied(to: store.configuration(for: selected.id))
            let bytes = try overrides.applied(to: withRules)
            if !skipped.isEmpty { log.warning("connect: \(skipped.count) custom rule(s) skipped for this profile") }
            step = "validate configuration"
            log.info("connect: \(step) (\(bytes.count) bytes)")
            try await validate(bytes, directory: store.directory(for: selected.id))
            // The tunnel reads cached resources at startup and downloads missing
            // data after connecting, then applies it without reconnecting.
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
            Self.configureOnDemand(manager, enabled: autoReconnect)
            step = "save preferences"
            log.info("connect: \(step)")
            try await manager.saveToPreferences()
            step = "reload preferences"
            log.info("connect: \(step)")
            try await manager.loadFromPreferences()
            self.manager = manager
            step = "start tunnel"
            log.info("connect: \(step) enabled=\(manager.isEnabled) status=\(manager.connection.status.rawValue)")
            try manager.connection.startVPNTunnel(options: ["source": "app" as NSString])
            status = manager.connection.status
            log.info("connect: start requested, status=\(self.status.rawValue)")
            if !active { awaitSystemStart() }
        } catch {
            log.error("connect: failed at \(step): \(Diagnostics.describe(error))")
            self.error = error.localizedDescription
        }
        #endif
    }

    /// iOS may take minutes to launch the extension, with no error and no
    /// status change meanwhile: after an app update it ignored every start
    /// for about five minutes. Further taps would only save the configuration
    /// again, so they wait; after 10 s the user is told what is happening.
    private func awaitSystemStart() {
        startPending = true
        startTimeout?.cancel()
        startTimeout = Task { [weak self] in
            try? await Task.sleep(for: .seconds(10))
            guard let self, !Task.isCancelled, self.startPending else { return }
            self.startPending = false
            Diagnostics.app.warning("connect: iOS has not started the tunnel 10 s after the request")
            self.error = Self.startWaitMessage
        }
    }

    private static var startWaitMessage: String { L("系统还没有启动 VPN。应用刚更新时 iOS 可能要几分钟后才会启动，请稍候，或在「设置 > VPN」中打开 Clyntis。") }

    private func endStartWait() {
        // The VPN came up after all: the explanation no longer applies.
        if error == Self.startWaitMessage { error = nil }
        startPending = false
        startTimeout?.cancel()
        startTimeout = nil
    }

    /// Stops the tunnel. Connect-on-demand goes off first: left on, iOS would
    /// start the tunnel again at once. Connecting turns it back on.
    func disconnect() async {
        guard let manager else { return }
        if manager.isOnDemandEnabled {
            manager.isOnDemandEnabled = false
            do { try await manager.saveToPreferences() } catch {
                Diagnostics.app.error("disconnect: turning off auto reconnect failed: \(Diagnostics.describe(error))")
            }
        }
        manager.connection.stopVPNTunnel()
    }

    /// Takes effect at once while connected; otherwise on the next connect, so
    /// turning it on while disconnected does not connect by itself.
    func setAutoReconnect(_ enabled: Bool) async {
        autoReconnect = enabled
        UserDefaults.standard.set(enabled, forKey: Self.autoReconnectKey)
        Diagnostics.app.info("auto reconnect \(enabled ? "on" : "off")")
        guard active, let manager else { return }
        Self.configureOnDemand(manager, enabled: enabled)
        do { try await manager.saveToPreferences() } catch {
            self.error = error.localizedDescription
        }
    }

    /// One rule: stay connected on every network. With it enabled, iOS starts
    /// the tunnel whenever it is down and the user did not stop it.
    private static func configureOnDemand(_ manager: NETunnelProviderManager, enabled: Bool) {
        let rule = NEOnDemandRuleConnect()
        rule.interfaceTypeMatch = .any
        manager.onDemandRules = [rule]
        manager.isOnDemandEnabled = enabled
    }

    /// iOS keeps restarting an on-demand tunnel that fails to start (a broken
    /// profile, missing files). After three failed starts within five minutes
    /// automatic reconnection is turned off and the reason shown; connecting
    /// by hand turns it on again.
    private func stopRetryingFailedStarts() {
        guard let manager else { return }
        Task {
            // The system may have changed it (turning the VPN off in Settings).
            try? await manager.loadFromPreferences()
            guard manager.isOnDemandEnabled else { return }
            let failures = StartFailures.recent(within: 300)
            guard failures.count >= 3, let last = failures.last else { return }
            manager.isOnDemandEnabled = false
            do {
                try await manager.saveToPreferences()
                Diagnostics.app.error("auto reconnect paused after \(failures.count) failed starts: \(last.reason)")
                self.error = L("VPN 连续 {count} 次启动失败，已暂停自动重连：{reason}", ["count": failures.count, "reason": last.reason])
            } catch {
                Diagnostics.app.error("pausing auto reconnect failed: \(Diagnostics.describe(error))")
            }
        }
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
                    throw ClientError.message(L("配置为空或超过大小限制。"))
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
        guard let store else { throw ClientError.message(L("配置存储不可用。")) }
        return try await Task.detached {
            try ConfigCrypto.encrypt(store.configuration(for: profile.id), password: password)
        }.value
    }

    /// Encrypts `profile` like `exportEncrypted` and uploads it to Tencent COS;
    /// returns the object's URL and remembers the target for the profile.
    func publish(_ profile: Profile, password: String, to target: CosTarget) async throws -> String {
        guard let store else { throw ClientError.message(L("配置存储不可用。")) }
        var target = target
        target.bucket = target.bucket.trimmingCharacters(in: .whitespaces)
        target.region = target.region.trimmingCharacters(in: .whitespaces)
        target.key = target.key.trimmingCharacters(in: CharacterSet(charactersIn: " /"))
        guard let keys = try CosKeychain.load() else {
            throw ClientError.message(L("请先在「配置 → 远程发布」中填写腾讯云 COS 的 SecretId 和 SecretKey。"))
        }
        let destination = target
        try await Task.detached {
            let encrypted = try ConfigCrypto.encrypt(store.configuration(for: profile.id), password: password)
            try CoreSession.cosPut(encrypted, to: destination, secretID: keys.secretID, secretKey: keys.secretKey)
        }.value
        PublishTargets.set(target, for: profile.id)
        return target.url ?? ""
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
        guard !busy, let store else { throw ClientError.message(L("正在处理其他操作，请稍后再试。")) }
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
        case .on: L("已拦截 {value} 次", ["value": (adblock?.total ?? 0).formatted()])
        case .pending: L("重新连接后生效")
        case .off: L("未开启")
        }
    }

    /// Adds `domain` to the allowlist (from the statistics), live.
    /// Adds `domain` to the app's allowlist and applies it to the running core.
    func allowAdblock(_ domain: String) async throws {
        guard var settings = overrides.adblock else {
            throw ClientError.message(L("去广告由配置文件开启，请在配置的 adblock.allow 中放行，或在本页开启去广告后再放行。"))
        }
        guard !settings.allow.contains(domain) else { return }
        settings.allow.append(domain)
        _ = try await saveAdblock(settings)
    }

    /// Saves the rewrite modules; they apply on the next connection.
    /// Returns whether a reconnect is needed for them to take effect.
    @discardableResult
    func saveRewrite(_ value: RewriteSettings?) throws -> Bool {
        let previous = overrides.rewrite
        var next = overrides
        next.rewrite = value
        try saveOverrides(next)
        return active && previous != value
    }

    // MARK: Capture and HTTPS decryption

    /// Saves the decryption settings; a connected tunnel applies them at once.
    func saveMitm(_ value: MitmSettings) async throws {
        var next = overrides
        next.mitm = value
        try saveOverrides(next)
        if connected {
            try applySnapshot(await send(TunnelMessage(command: "mitm", mitm: value)))
        }
    }

    /// Makes a new CA; a tunnel decrypting with the old one switches to it.
    func generateAuthority() async throws -> MitmAuthority {
        let authority = try await Task.detached { try MitmAuthority.generate() }.value
        if connected, let settings = overrides.mitm {
            try applySnapshot(await send(TunnelMessage(command: "mitm", mitm: settings)))
        }
        return authority
    }

    func clearMitmBypass() async throws {
        try applySnapshot(await send(TunnelMessage(command: "mitm-bypass-clear")))
    }

    /// Request log entries after `after` (see RequestsView).
    func fetchRequests(after: UInt64) async throws -> RequestPage {
        let data = try await send(TunnelMessage(command: "requests", after: after))
        if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let error = object["error"] as? String {
            throw ClientError.message(error)
        }
        return try JSONDecoder().decode(RequestPage.self, from: data)
    }

    func requestDetail(_ id: UInt64) async throws -> RequestDetail {
        let data = try await send(TunnelMessage(command: "request-detail", request: id))
        if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let error = object["error"] as? String {
            throw ClientError.message(error)
        }
        return try JSONDecoder().decode(RequestDetail.self, from: data)
    }

    /// The tunnel's request log as a HAR or CSV file.
    func exportRequests(csv: Bool) async throws -> Data {
        guard connected else { throw ClientError.message(L("VPN 未连接。")) }
        let data = try await send(TunnelMessage(command: "export-requests", format: csv ? "csv" : "har"), timeout: 15)
        // A failure is a small JSON object with "error"; an export never is.
        if data.count < 4096, let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let error = object["error"] as? String {
            throw ClientError.message(error)
        }
        return data
    }

    func clearRequests() async throws {
        try applySnapshot(await send(TunnelMessage(command: "clear-requests")))
    }

    /// Adds a REJECT rule for `host` ahead of the others; it applies on the
    /// next connection.
    func blockDomain(_ host: String, subdomains: Bool) throws {
        let rule = "\(subdomains ? "DOMAIN-SUFFIX" : "DOMAIN"),\(host),REJECT"
        guard !customRules.contains(rule) else { return }
        try saveCustomRules([rule] + customRules)
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
        await disconnect()
        for _ in 0..<50 where status != .disconnected && status != .invalid {
            try? await Task.sleep(for: .milliseconds(200))
        }
        await toggleConnection()
    }

    // MARK: Profile details

    func configurationText(for profile: Profile) throws -> String {
        guard let store else { throw ClientError.message(L("配置存储不可用。")) }
        return String(decoding: try store.configuration(for: profile.id), as: UTF8.self)
    }

    /// Validates and saves edited YAML. A running tunnel keeps its loaded copy until reconnected.
    func saveConfiguration(_ text: String, for profile: Profile) async throws {
        guard let store else { throw ClientError.message(L("配置存储不可用。")) }
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
        guard let store else { throw ClientError.message(L("配置存储不可用。")) }
        _ = try store.rename(profile.id, to: name)
        profiles = try store.profiles()
    }

    /// Downloads the profile's link again and replaces its configuration.
    func updateFromSource(_ profile: Profile, password: String = "") async throws {
        guard let store, let source = profile.source else { throw ClientError.message(L("此配置不是从链接导入的。")) }
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
        guard connected, nodeStatus[node]?.probeable == true, !probing.contains(node) else { return }
        probing.insert(node)
        defer { probing.remove(node) }
        do { try applySnapshot(await send(TunnelMessage(command: "probe", node: node), timeout: 15)) }
        catch { Diagnostics.app.warning("probe \(node): \(Diagnostics.describe(error))") }
    }

    /// Tests every probeable node, two at a time (the core accepts a few at once).
    func probeAll() async {
        var queue = nodeStatus.filter(\.value.probeable).map(\.key).sorted()
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
        guard connected else { throw ClientError.message(L("VPN 未连接。")) }
        let data = try await send(TunnelMessage(command: "test-route", target: target, network: network), timeout: 15)
        if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let error = object["error"] as? String {
            throw ClientError.message(error)
        }
        return try JSONDecoder().decode(RouteTest.self, from: data)
    }

    /// The configuration review, plus the online bash.ws test when `online`.
    func dnsLeak(online: Bool) async throws -> DnsLeakResult {
        guard connected else { throw ClientError.message(L("VPN 未连接。")) }
        let data = try await send(TunnelMessage(command: "dns-leak", online: online), timeout: online ? 45 : 5)
        if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let error = object["error"] as? String {
            throw ClientError.message(error)
        }
        return try JSONDecoder().decode(DnsLeakResult.self, from: data)
    }

    private func send(_ message: TunnelMessage, timeout: Double = 5) async throws -> Data {
        guard let session = manager?.connection as? NETunnelProviderSession else {
            throw ClientError.message(L("VPN 会话不可用。"))
        }
        let payload = try JSONEncoder().encode(message)
        return try await withCheckedThrowingContinuation { continuation in
            let reply = MessageReply(continuation)
            DispatchQueue.main.asyncAfter(deadline: .now() + timeout) {
                reply.finish(.failure(ClientError.message(L("VPN 无响应。"))))
            }
            do {
                try session.sendProviderMessage(payload) { data in
                    if let data { reply.finish(.success(data)) }
                    else { reply.finish(.failure(ClientError.message(L("VPN 已停止或无法响应。")))) }
                }
            } catch { reply.finish(.failure(error)) }
        }
    }

    private func applySnapshot(_ data: Data) throws {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ClientError.message(L("无效的内核状态。"))
        }
        if let error = object["error"] as? String { throw ClientError.message(error) }
        if object["stopped"] as? Bool == true { throw ClientError.message(L("内核已停止，请重新连接。")) }
        upload = (object["upload"] as? NSNumber)?.uint64Value ?? 0
        download = (object["download"] as? NSNumber)?.uint64Value ?? 0
        connectionCount = (object["connections"] as? [Any])?.count ?? 0
        connections = ConnectionInfo.decode(object["connections"])
        adblock = AdblockStatus.decode(object["adblock"])
        mitm = MitmStatus.decode(object["mitm"])
        rewrite = RewriteStatus.decode(object["rewrite"])
        if let config = object["config"] as? [String: Any] {
            mode = config["mode"] as? String ?? "rule"
            let selections = object["selections"] as? [String: String] ?? [:]
            groups = (config["proxy-groups"] as? [[String: Any]] ?? []).compactMap { group in
                guard let name = group["name"] as? String, let nodes = group["proxies"] as? [String] else { return nil }
                return ProxyGroup(name: name, type: group["type"] as? String ?? "", nodes: nodes,
                                  selected: selections[name])
            }
            proxies = (config["proxies"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String }
        }
        nodeStatus = NodeStatus.decode(object["proxies"])
        let defined = ((object["config"] as? [String: Any])?["networks"] as? [String: Any])?.isEmpty == false
        currentNetworks = defined ? ((object["network"] as? [String: Any])?["networks"] as? [String] ?? []) : nil
    }
}

struct PendingImport {
    let name: String
    let data: Data
}

struct ProxyGroup: Identifiable {
    var id: String { name }
    let name: String
    /// As written in the profile: select, url-test, fallback, load-balance.
    let type: String
    let nodes: [String]
    let selected: String?

    var typeText: String {
        ["select": L("手动"), "url-test": L("自动"), "fallback": L("故障转移"), "load-balance": L("负载均衡")][type] ?? type
    }
}

/// The core's built-in outbounds, which route without a server of their own.
enum BuiltinOutbound {
    case direct, reject

    init?(_ name: String) {
        switch name.uppercased() {
        case "DIRECT", "PASS": self = .direct
        case let name where name.hasPrefix("REJECT"): self = .reject
        default: return nil
        }
    }
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
        let error: String?
    }
    struct Test: Decodable {
        let exit: [Server]
        /// Node and rule bash.ws traffic uses; the test reflects that route.
        let node: String
        let matched: String
        /// leak, ok, direct (bash.ws not proxied) or unknown (no resolvers seen).
        let verdict: String
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
