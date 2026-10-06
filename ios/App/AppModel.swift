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
            let bytes = try store.configuration(for: selected.id)
            step = "validate configuration"
            log.info("connect: \(step) (\(bytes.count) bytes)")
            try await validate(bytes, directory: store.directory(for: selected.id))
            // Fetch GeoIP/GeoSite and rule providers here, where neither the tunnel's
            // ~50 MiB memory limit nor its start timeout applies.
            step = "prefetch resources"
            log.info("connect: \(step)")
            phase = "正在准备路由资源…"
            let directory = store.directory(for: selected.id)
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

    private func send(_ message: TunnelMessage) async throws -> Data {
        guard let session = manager?.connection as? NETunnelProviderSession else {
            throw ClientError.message("VPN 会话不可用。")
        }
        let payload = try JSONEncoder().encode(message)
        return try await withCheckedThrowingContinuation { continuation in
            let reply = MessageReply(continuation)
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
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
        if let config = object["config"] as? [String: Any] {
            mode = config["mode"] as? String ?? "rule"
            let selections = object["selections"] as? [String: String] ?? [:]
            groups = (config["proxy-groups"] as? [[String: Any]] ?? []).compactMap { group in
                guard let name = group["name"] as? String, let nodes = group["proxies"] as? [String] else { return nil }
                return ProxyGroup(name: name, nodes: nodes, selected: selections[name])
            }
        }
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
