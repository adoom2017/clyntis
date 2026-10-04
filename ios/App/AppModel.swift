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
                        if !self.active {
                            self.upload = 0; self.download = 0; self.connectionCount = 0; self.groups = []
                        }
                    }
                }
            #endif
        } catch { self.error = error.localizedDescription }
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
        defer { busy = false }
        do {
            let bytes = try store.configuration(for: selected.id)
            try await validate(bytes, directory: store.directory(for: selected.id))
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
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            self.manager = manager
            try manager.connection.startVPNTunnel()
            status = manager.connection.status
        } catch { self.error = error.localizedDescription }
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
            try RemoteConfigImporter.store(source, password: password, name: name, in: store)
        }
        let profile = try await withTaskCancellationHandler {
            try await worker.value
        } onCancel: { worker.cancel() }
        profiles = try store.profiles()
        if !active { selectedID = profile.id }
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
