import Network
import NetworkExtension
import os

private let log = Diagnostics.tunnel
private func memory() -> String { String(format: "%.1f MiB", Diagnostics.footprintMiB()) }

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let queue = DispatchQueue(label: "org.clyntis.ios.packet-tunnel")
    private var core: CoreSession?
    private var epoch = UUID()
    private var monitor: NWPathMonitor?
    private var receivedInitialPath = false
    /// The network the core last adapted to, and the coalescing of path updates.
    private var appliedNetwork: NetworkSnapshot?
    private var pendingNetwork: DispatchWorkItem?
    private var ignoredPathUpdates = 0
    /// Whether the profile enables IPv6, and whether the applied settings route it.
    private var profileIPv6 = false
    private var routesIPv6: Bool?
    private var healthTimer: DispatchSourceTimer?
    private var logTimer: DispatchSourceTimer?
    private let watchdog = TunnelWatchdog()
    /// Packets dropped as malformed; logged at 1, 10, 100… so a flood cannot
    /// fill the log.
    private var droppedPackets = 0

    /// Open descriptors allowed; see `Diagnostics.raiseFileLimit`.
    private static let fileLimit = 4096

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        // The app passes "source"; iOS starts the tunnel without options when
        // connect-on-demand brings it back (after a crash, a kill or a reboot).
        let source = (options?["source"] as? String) ?? "system (on demand)"
        let files = Diagnostics.raiseFileLimit(to: Self.fileLimit)
        log.info("start: begin source=\(source) memory=\(memory()) fileLimit=\(files)")
        watchdog.reportPreviousSession()
        watchdog.start(watching: queue)
        queue.async {
            var step = "read profile"
            do {
                guard self.core == nil,
                      let config = self.protocolConfiguration as? NETunnelProviderProtocol,
                      let rawID = config.providerConfiguration?["profileID"] as? String,
                      let id = UUID(uuidString: rawID) else {
                    throw ClientError.message("缺少有效的 VPN 配置。")
                }
                log.info("start: profile=\(id.uuidString)")
                step = "open profile store"
                let store = try ProfileStore.shared()
                Self.reportCorePanics(in: store.directory(for: id))
                var hooks = meta_hooks_v1()
                hooks.size = UInt32(MemoryLayout<meta_hooks_v1>.size)
                hooks.version = 1
                hooks.context = Unmanaged.passUnretained(self).toOpaque()
                hooks.packet_ready = { context in
                    guard let context else { return }
                    let provider = Unmanaged<PacketTunnelProvider>.fromOpaque(context).takeUnretainedValue()
                    provider.queue.async { provider.drainPackets() }
                }
                step = "apply custom rules"
                let (withRules, skipped) = try CustomRules.applied(to: store.configuration(for: id))
                if !skipped.isEmpty {
                    log.warning("start: \(skipped.count) custom rule(s) not usable with this profile: "
                                + skipped.map { "\($0.rule) (\($0.reason))" }.joined(separator: "; "))
                }
                step = "apply app settings"
                let overrides = AppOverrides.load()
                let configuration = try overrides.applied(to: withRules)
                if !overrides.isEmpty {
                    log.info("start: app settings override the profile: log=\(overrides.logLevel ?? "profile") "
                             + "ipv6=\(overrides.ipv6.map(String.init) ?? "profile") sniffing=\(overrides.sniffing.map(String.init) ?? "profile")")
                }
                step = "create core"
                self.core = try CoreSession(configuration: configuration,
                                            directory: store.directory(for: id), hooks: &hooks)
                log.info("start: core created memory=\(memory())")
                self.collectLogs()
                // Loads routing resources (geoip/geosite/rule providers) and may download them.
                step = "start core"
                try self.core?.start()
                log.info("start: core started memory=\(memory())")
                // Like mihomo, claim IPv6 only when the profile enables it, and only
                // while the device network can route it. Claiming it otherwise makes
                // apps believe IPv6 works: they dial IPv6 literals (WeChat avatars,
                // Meituan's HTTPDNS) that fail with "no route" before falling back.
                self.profileIPv6 = try self.core?.enablesIPv6() ?? false
                let epoch = self.epoch
                step = "wait for network"
                log.info("start: waiting for the device network")
                self.watchNetwork { path in
                    let ipv6 = self.profileIPv6 && path.supportsIPv6
                    log.info("start: applying network settings ipv6=\(ipv6) (profile=\(self.profileIPv6) network=\(path.supportsIPv6))")
                    self.applySettings(ipv6: ipv6) { error in
                        guard self.epoch == epoch, self.core != nil else {
                            completionHandler(ClientError.message("VPN 启动已取消。"))
                            return
                        }
                        if let error {
                            log.error("start: network settings failed: \(Diagnostics.describe(error))")
                            StartFailures.record("network settings: \(error.localizedDescription)")
                            self.shutdown()
                            completionHandler(error)
                            return
                        }
                        self.readPackets(epoch: epoch)
                        self.drainPackets()
                        self.watchCore()
                        log.info("start: tunnel up memory=\(memory())")
                        StartFailures.clear()
                        completionHandler(nil)
                    }
                }
            } catch {
                log.error("start: failed at \(step): \(Diagnostics.describe(error)) memory=\(memory())")
                StartFailures.record("\(step): \(error.localizedDescription)")
                self.shutdown()
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log.info("stop: reason=\(reason.rawValue) memory=\(memory())")
        watchdog.stop()
        queue.async {
            self.shutdown()
            completionHandler()
        }
    }

    /// Moves core logs into the shared log file every 5 s while a core exists.
    /// The core buffers 2000 lines; collecting every second kept the tunnel
    /// waking up for little more than a few lines. The leeway lets iOS
    /// coalesce it with other wakeups.
    private func collectLogs() {
        logTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 5, repeating: 5, leeway: .seconds(1))
        timer.setEventHandler { [watchdog] in watchdog.track("collect logs") { Diagnostics.collectCoreLogs() } }
        logTimer = timer
        timer.resume()
    }

    private func shutdown() {
        watchdog.stop()
        Diagnostics.collectCoreLogs()
        logTimer?.cancel()
        logTimer = nil
        epoch = UUID()
        droppedPackets = 0
        monitor?.cancel()
        monitor = nil
        receivedInitialPath = false
        pendingNetwork?.cancel()
        pendingNetwork = nil
        appliedNetwork = nil
        ignoredPathUpdates = 0
        routesIPv6 = nil
        healthTimer?.cancel()
        healthTimer = nil
        core?.close()
        core = nil
    }

    private func readPackets(epoch: UUID) {
        guard core != nil, self.epoch == epoch else { return }
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            self.queue.async { self.submit(packets, index: 0, epoch: epoch) }
        }
    }

    /// Hands packets to the core. While its input is full the rest wait,
    /// retried after `delay` ms, doubling up to 100 ms: a fixed 2 ms retry
    /// against a stalled core woke the extension 500 times a second.
    private func submit(_ packets: [Data], index: Int, epoch: UUID, delay: Int = 2, waited: Int = 0) {
        guard self.epoch == epoch, let core else { return }
        watchdog.begin("write packets")
        defer { watchdog.end() }
        var index = index
        while index < packets.count {
            let packet = packets[index]
            index += 1
            // One malformed packet must not end the VPN: the core refuses it
            // with the same error as a stopped core, so drop it here.
            guard (20...65_535).contains(packet.count),
                  [4, 6].contains(packet[packet.startIndex] >> 4) else {
                dropped("malformed packet from the system (\(packet.count) bytes)")
                continue
            }
            let result = packet.withUnsafeBytes {
                meta_write_packet_v1(core.handle, $0.bindMemory(to: UInt8.self).baseAddress, $0.count)
            }
            if result == META_WOULD_BLOCK {
                // Keep unread packets rather than silently dropping a saturated batch.
                let retry = index - 1, total = waited + delay
                if waited < 5_000, total >= 5_000 {
                    log.warning("core packet input full for 5 s; still retrying memory=\(memory())")
                }
                queue.asyncAfter(deadline: .now() + .milliseconds(delay)) {
                    self.submit(packets, index: retry, epoch: epoch, delay: min(delay * 2, 100), waited: total)
                }
                return
            }
            if result != META_OK {
                self.fail(ClientError.message("无法向内核写入 IP 数据包。"))
                return
            }
        }
        readPackets(epoch: epoch)
    }

    private func dropped(_ reason: String) {
        droppedPackets += 1
        var power = 1
        while power < droppedPackets { power *= 10 }
        if power == droppedPackets {
            log.warning("dropped \(droppedPackets) packet(s) so far; latest: \(reason)")
        }
    }

    private func drainPackets() {
        guard let core else { return }
        watchdog.begin("read packets")
        defer { watchdog.end() }
        var packets: [Data] = [], protocols: [NSNumber] = []
        var buffer = Data(count: 65_535)
        var emptied = false
        for _ in 0..<64 {
            var length = 0
            let result = buffer.withUnsafeMutableBytes {
                meta_read_packet_v1(core.handle, $0.bindMemory(to: UInt8.self).baseAddress, $0.count, &length)
            }
            if result == META_WOULD_BLOCK {
                emptied = true
                break
            }
            guard result == META_OK else {
                fail(ClientError.message("无法读取内核 IP 数据包。"))
                return
            }
            guard length > 0 else { continue }
            let packet = Data(buffer.prefix(length))
            let version = packet[packet.startIndex] >> 4
            guard version == 4 || version == 6 else {
                dropped("invalid packet from the core (version \(version))")
                continue
            }
            packets.append(packet)
            protocols.append(NSNumber(value: version == 4 ? AF_INET : AF_INET6))
        }
        if !packets.isEmpty, !packetFlow.writePackets(packets, withProtocols: protocols) {
            // The flow refuses while it is being torn down; stopTunnel follows.
            dropped("the system refused \(packets.count) packet(s)")
        }
        if !emptied { queue.async { self.drainPackets() } }
    }

    /// Routes for the tunnel; IPv6 only when `ipv6`. Completes on `queue`.
    private func applySettings(ipv6: Bool, completion: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "198.18.0.1")
        settings.mtu = 1280
        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.2"], subnetMasks: ["255.255.255.252"])
        ipv4.includedRoutes = [.default()]
        settings.ipv4Settings = ipv4
        if ipv6 {
            let v6 = NEIPv6Settings(addresses: ["fdfe:dcba:9876::2"], networkPrefixLengths: [126])
            v6.includedRoutes = [.default()]
            settings.ipv6Settings = v6
        }
        let dns = NEDNSSettings(servers: ["198.18.0.1"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        setTunnelNetworkSettings(settings) { error in
            self.queue.async {
                if error == nil { self.routesIPv6 = ipv6 }
                completion(error)
            }
        }
    }

    private static let pathSettleDelay: DispatchTimeInterval = .seconds(1)

    /// Tells the core about a settled path only when sockets bound to the old
    /// one may no longer work. NWPathMonitor also reports updates that change
    /// none of that (IPv6 temporary address rotation, DNS or cost changes,
    /// every ~25 s on some Wi-Fi networks); each closed every connection,
    /// re-tested url-test groups and reconnected Tailscale's DERP relay.
    private func pathSettled(_ path: Network.NWPath) {
        guard let core, receivedInitialPath else { return }
        watchdog.begin("network change")
        defer { watchdog.end() }
        let snapshot = NetworkSnapshot(path)
        let changes = appliedNetwork.map { snapshot.changes(from: $0) } ?? ["initial"]
        guard !changes.isEmpty else {
            ignoredPathUpdates += 1
            return
        }
        appliedNetwork = snapshot
        let line = "network changed: \(changes.joined(separator: ", ")) (\(ignoredPathUpdates) unchanged updates ignored) \(snapshot)"
        // Nothing gets through while iOS reports the network unusable.
        if snapshot.usable { log.info(line) } else { log.warning(line) }
        ignoredPathUpdates = 0
        // Returns at once; fails only when the core already stopped, which
        // the health check reports.
        do { try core.networkChanged() } catch {
            log.warning("network change not delivered: \(Diagnostics.describe(error))")
        }
        let ipv6 = profileIPv6 && path.supportsIPv6
        guard let routed = routesIPv6, routed != ipv6 else { return }
        let epoch = self.epoch
        applySettings(ipv6: ipv6) { error in
            guard self.epoch == epoch, self.core != nil else { return }
            if let error {
                log.error("network settings update failed: \(Diagnostics.describe(error))")
            } else {
                log.info("IPv6 \(ipv6 ? "now routed through the tunnel" : "left on the device network") after network change")
            }
        }
    }

    /// Calls `ready` with the first device path, then reacts to changes. Only
    /// physical interfaces count: this tunnel and other VPNs are `.other`, and
    /// our own IPv6 route must not look like IPv6 connectivity.
    private func watchNetwork(ready: @escaping (Network.NWPath) -> Void) {
        let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other])
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self, self.core != nil else { return }
            guard self.receivedInitialPath else {
                self.receivedInitialPath = true
                self.appliedNetwork = NetworkSnapshot(path)
                ready(path)
                return
            }
            // A switch emits several updates within a second: settle first, then
            // compare with what the core last adapted to.
            self.pendingNetwork?.cancel()
            let work = DispatchWorkItem { [weak self] in self?.pathSettled(path) }
            self.pendingNetwork = work
            self.queue.asyncAfter(deadline: .now() + Self.pathSettleDelay, execute: work)
        }
        monitor.start(queue: queue)
        self.monitor = monitor
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        log.info("sleep memory=\(memory())")
        completionHandler()
    }

    override func wake() {
        log.info("wake memory=\(memory())")
    }

    /// Logs core panics recorded by a previous run (`panic.log`, written by the
    /// core's panic hook even when the process died right after).
    private static func reportCorePanics(in directory: URL) {
        let file = directory.appendingPathComponent("panic.log")
        guard let text = try? String(contentsOf: file, encoding: .utf8), !text.isEmpty else { return }
        log.error("start: the core panicked in an earlier run:\n\(text.suffix(8_000))")
        try? FileManager.default.removeItem(at: file)
    }

    private func fail(_ error: Error) {
        log.error("fail: \(Diagnostics.describe(error)) memory=\(memory())")
        shutdown()
        cancelTunnelWithError(error)
    }

    private func watchCore() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 5, repeating: 5)
        var ticks = 0
        timer.setEventHandler { [weak self] in
            guard let self, let core = self.core else { return }
            self.watchdog.begin("health check")
            defer { self.watchdog.end() }
            do {
                let state = try JSONSerialization.jsonObject(with: core.status()) as? [String: Any]
                if state?["stopped"] as? Bool == true {
                    self.fail(ClientError.message("代理内核已停止，请重新连接。"))
                    return
                }
                // Memory against the ~50 MiB extension limit, with the load behind it.
                ticks += 1
                if ticks % 6 == 0 {
                    let connections = (state?["connections"] as? NSNumber)?.intValue ?? 0
                    let files = Diagnostics.openFileDescriptors()
                    let limit = Diagnostics.fileLimit()
                    let line = "running: memory=\(memory()) connections=\(connections) files=\(files)/\(limit)"
                    // Near the limit new sockets fail; say so above the routine line.
                    if limit > 0, files * 10 >= limit * 8 { log.warning(line) } else { log.info(line) }
                }
            } catch { self.fail(error) }
        }
        healthTimer = timer
        timer.resume()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        queue.async {
            do {
                guard messageData.count <= 16 * 1024, let core = self.core else {
                    throw ClientError.message("VPN 未连接。")
                }
                let message = try JSONDecoder().decode(TunnelMessage.self, from: messageData)
                self.watchdog.begin("app message \(message.command)")
                defer { self.watchdog.end() }
                switch message.command {
                case "snapshot": break
                case "mode":
                    guard let mode = message.mode else { throw ClientError.message("缺少模式。") }
                    try core.updateMode(mode)
                case "select":
                    guard let group = message.group, let node = message.node else { throw ClientError.message("缺少节点。") }
                    try core.select(group: group, node: node)
                case "adblock-allow":
                    try core.updateAdblockAllow(message.allow ?? [])
                case "close":
                    try core.closeConnection(message.id)
                case "probe":
                    guard let node = message.node else { throw ClientError.message("缺少节点。") }
                    // Seconds of network I/O: off the packet queue. A failed probe is
                    // a result too; the snapshot carries it in the node's status.
                    DispatchQueue.global(qos: .utility).async {
                        _ = try? core.probe(node)
                        self.queue.async {
                            let reply = try? self.core?.snapshot()
                            completionHandler?(reply ?? (try? JSONSerialization.data(withJSONObject: ["error": "VPN 未连接。"])))
                        }
                    }
                    return
                case "test-route":
                    guard let target = message.target else { throw ClientError.message("缺少测试目标。") }
                    // A rule may resolve the name: off the packet queue.
                    DispatchQueue.global(qos: .userInitiated).async {
                        do {
                            completionHandler?(try core.testRoute(target, network: message.network ?? "tcp"))
                        } catch {
                            completionHandler?(try? JSONSerialization.data(withJSONObject: ["error": error.localizedDescription]))
                        }
                    }
                    return
                case "dns-leak":
                    let online = message.online ?? false
                    // The online test takes seconds of network I/O: off the packet queue.
                    DispatchQueue.global(qos: .userInitiated).async {
                        do {
                            completionHandler?(try core.dnsLeak(online: online))
                        } catch {
                            completionHandler?(try? JSONSerialization.data(withJSONObject: ["error": error.localizedDescription]))
                        }
                    }
                    return
                default: throw ClientError.message("不支持的内核命令。")
                }
                completionHandler?(try core.snapshot())
            } catch {
                completionHandler?(try? JSONSerialization.data(withJSONObject: ["error": error.localizedDescription]))
            }
        }
    }
}

/// What a network change must alter before sockets need rebinding: status,
/// the usable interfaces in preference order, their gateways, IPv4/IPv6
/// reachability and the interfaces' IPv4 addresses (an address can change on
/// the same interface and gateway). IPv6 addresses are left out: temporary
/// ones rotate without breaking anything.
private struct NetworkSnapshot: Equatable, CustomStringConvertible {
    let status: String
    let interfaces: [String]
    let gateways: [String]
    let ipv4: Bool
    let ipv6: Bool
    let addresses: [String]

    init(_ path: Network.NWPath) {
        // iOS says why a path is unusable: cellular data turned off for the
        // app, no network at all, ...; part of the status so a new reason is
        // logged as a change.
        status = path.status == .satisfied ? "satisfied" : "\(path.status)(\(Self.reason(path.unsatisfiedReason)))"
        // availableInterfaces still lists this tunnel (utun, `.other`) and may
        // repeat an interface; only distinct physical ones matter.
        var seen = Set<String>()
        let physical = path.availableInterfaces.filter { $0.type != .other && seen.insert($0.name).inserted }
        interfaces = physical.map { "\($0.name)(\(Self.kind($0.type)))" }
        gateways = path.gateways.map { "\($0)" }.sorted()
        ipv4 = path.supportsIPv4
        ipv6 = path.supportsIPv6
        addresses = Self.ipv4Addresses(on: Set(physical.map(\.name)))
    }

    /// Names of the fields that differ from `old`; empty when nothing that
    /// matters to sockets changed.
    func changes(from old: NetworkSnapshot) -> [String] {
        var changed: [String] = []
        if status != old.status { changed.append("status") }
        if interfaces != old.interfaces { changed.append("interfaces") }
        if gateways != old.gateways { changed.append("gateways") }
        if ipv4 != old.ipv4 || ipv6 != old.ipv6 { changed.append("ip-versions") }
        if addresses != old.addresses { changed.append("addresses") }
        return changed
    }

    var description: String {
        "status=\(status) interfaces=\(interfaces) ipv4=\(ipv4) ipv6=\(ipv6) addresses=\(addresses)"
    }

    var usable: Bool { status == "satisfied" }

    private static func reason(_ reason: Network.NWPath.UnsatisfiedReason) -> String {
        switch reason {
        case .notAvailable: "no-network"
        case .cellularDenied: "cellular-denied"
        case .wifiDenied: "wifi-denied"
        case .localNetworkDenied: "local-network-denied"
        case .vpnInactive: "vpn-inactive"
        @unknown default: "unknown"
        }
    }

    private static func kind(_ type: NWInterface.InterfaceType) -> String {
        switch type {
        case .wifi: "wifi"
        case .cellular: "cellular"
        case .wiredEthernet: "wired"
        case .loopback: "loopback"
        default: "other"
        }
    }

    private static func ipv4Addresses(on names: Set<String>) -> [String] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var result: [String] = []
        for entry in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let name = String(cString: entry.pointee.ifa_name)
            guard names.contains(name), let address = entry.pointee.ifa_addr,
                  address.pointee.sa_family == UInt8(AF_INET) else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count),
                           nil, 0, NI_NUMERICHOST) == 0 {
                result.append("\(name)=\(String(cString: host))")
            }
        }
        return result.sorted()
    }
}

/// Watches the tunnel queue from its own queue. Everything on the tunnel
/// queue (packets, timers, log collection) stops together when it blocks, so
/// the watchdog reports what it is stuck in, and keeps a heartbeat file so the
/// next start can tell an exit without `stopTunnel` (a crash or a kill by the
/// system) and when it happened.
private final class TunnelWatchdog {
    private let queue = DispatchQueue(label: "org.clyntis.ios.tunnel-watchdog")
    private let lock = NSLock()
    private var operation = "starting"
    private var operationSince = Date()
    private var answered = Date()
    private var reported: Date?
    private var timer: DispatchSourceTimer?
    private let heartbeat = ProfileStore.sharedContainer()?.appendingPathComponent("tunnel-heartbeat.json")

    /// Called on the tunnel queue around work that could block it.
    func begin(_ name: String) {
        lock.lock()
        operation = name
        operationSince = Date()
        lock.unlock()
    }

    func end() { begin("idle") }

    func track(_ name: String, _ body: () -> Void) {
        begin(name)
        defer { end() }
        body()
    }

    /// Logs how the previous session ended when it never stopped cleanly.
    func reportPreviousSession() {
        guard let heartbeat, let data = try? Data(contentsOf: heartbeat),
              let beat = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
        log.warning("start: the previous session ended without stopping (crash or killed by iOS); "
                    + "last heartbeat \(beat["time"] ?? "?") operation=\(beat["operation"] ?? "?") "
                    + "memory=\(beat["memory"] ?? "?") queue_blocked_s=\(beat["blocked"] ?? "?")")
        try? FileManager.default.removeItem(at: heartbeat)
    }

    func start(watching tunnelQueue: DispatchQueue) {
        queue.sync {
            timer?.cancel()
            lock.lock()
            answered = Date()
            reported = nil
            lock.unlock()
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now() + 5, repeating: 5)
            timer.setEventHandler { [weak self] in self?.tick(tunnelQueue) }
            self.timer = timer
            timer.resume()
        }
    }

    /// A clean stop: no heartbeat is left for the next start to report.
    func stop() {
        queue.sync {
            timer?.cancel()
            timer = nil
            if let heartbeat { try? FileManager.default.removeItem(at: heartbeat) }
        }
    }

    private func tick(_ tunnelQueue: DispatchQueue) {
        tunnelQueue.async { [weak self] in
            guard let self else { return }
            self.lock.lock()
            self.answered = Date()
            self.lock.unlock()
        }
        let now = Date()
        lock.lock()
        let blocked = now.timeIntervalSince(answered)
        let operation = self.operation
        let busy = now.timeIntervalSince(operationSince)
        let report = blocked > 10 && reported.map { now.timeIntervalSince($0) >= 30 } ?? true
        if report { reported = now }
        if blocked <= 10 { reported = nil }
        lock.unlock()
        let footprint = String(format: "%.1f", Diagnostics.footprintMiB())
        if report {
            log.warning("tunnel queue blocked for \(Int(blocked)) s in \(operation) (\(Int(busy)) s) memory=\(footprint) MiB")
        }
        guard let heartbeat else { return }
        let beat: [String: Any] = [
            "time": ISO8601DateFormatter().string(from: now),
            "operation": operation,
            "memory": footprint,
            "blocked": Int(blocked),
        ]
        if let data = try? JSONSerialization.data(withJSONObject: beat) {
            try? data.write(to: heartbeat, options: .atomic)
        }
    }
}
