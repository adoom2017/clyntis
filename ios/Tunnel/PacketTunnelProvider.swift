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
    /// Whether the profile enables IPv6, and whether the applied settings route it.
    private var profileIPv6 = false
    private var routesIPv6: Bool?
    private var healthTimer: DispatchSourceTimer?
    private var logTimer: DispatchSourceTimer?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        log.info("start: begin memory=\(memory())")
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
                            self.shutdown()
                            completionHandler(error)
                            return
                        }
                        self.readPackets(epoch: epoch)
                        self.drainPackets()
                        self.watchCore()
                        log.info("start: tunnel up memory=\(memory())")
                        completionHandler(nil)
                    }
                }
            } catch {
                log.error("start: failed at \(step): \(Diagnostics.describe(error)) memory=\(memory())")
                self.shutdown()
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log.info("stop: reason=\(reason.rawValue) memory=\(memory())")
        queue.async {
            self.shutdown()
            completionHandler()
        }
    }

    /// Moves core logs into the shared log file every second while a core exists.
    private func collectLogs() {
        logTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 1, repeating: 1)
        timer.setEventHandler { Diagnostics.collectCoreLogs() }
        logTimer = timer
        timer.resume()
    }

    private func shutdown() {
        Diagnostics.collectCoreLogs()
        logTimer?.cancel()
        logTimer = nil
        epoch = UUID()
        monitor?.cancel()
        monitor = nil
        receivedInitialPath = false
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

    private func submit(_ packets: [Data], index: Int, epoch: UUID) {
        guard self.epoch == epoch, let core else { return }
        var index = index
        while index < packets.count {
            let packet = packets[index]
            let result = packet.withUnsafeBytes {
                meta_write_packet_v1(core.handle, $0.bindMemory(to: UInt8.self).baseAddress, $0.count)
            }
            if result == META_WOULD_BLOCK {
                // Keep unread packets rather than silently dropping a saturated batch.
                let nextIndex = index
                queue.asyncAfter(deadline: .now() + .milliseconds(2)) {
                    self.submit(packets, index: nextIndex, epoch: epoch)
                }
                return
            }
            if result != META_OK {
                self.fail(ClientError.message("无法向内核写入 IP 数据包。"))
                return
            }
            index += 1
        }
        readPackets(epoch: epoch)
    }

    private func drainPackets() {
        guard let core else { return }
        var packets: [Data] = [], protocols: [NSNumber] = []
        var buffer = Data(count: 65_535)
        for _ in 0..<64 {
            var length = 0
            let result = buffer.withUnsafeMutableBytes {
                meta_read_packet_v1(core.handle, $0.bindMemory(to: UInt8.self).baseAddress, $0.count, &length)
            }
            if result == META_WOULD_BLOCK { break }
            guard result == META_OK, length > 0 else {
                fail(ClientError.message("无法读取内核 IP 数据包。"))
                return
            }
            let packet = Data(buffer.prefix(length))
            let version = packet[packet.startIndex] >> 4
            guard version == 4 || version == 6 else {
                fail(ClientError.message("内核返回了无效 IP 数据包。"))
                return
            }
            packets.append(packet)
            protocols.append(NSNumber(value: version == 4 ? AF_INET : AF_INET6))
        }
        guard !packets.isEmpty else { return }
        guard packetFlow.writePackets(packets, withProtocols: protocols) else {
            fail(ClientError.message("系统无法接收 VPN 数据包。"))
            return
        }
        if packets.count == 64 { queue.async { self.drainPackets() } }
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

    /// Calls `ready` with the first device path, then reacts to changes. Only
    /// physical interfaces count: this tunnel and other VPNs are `.other`, and
    /// our own IPv6 route must not look like IPv6 connectivity.
    private func watchNetwork(ready: @escaping (Network.NWPath) -> Void) {
        let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other])
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self, let core = self.core else { return }
            guard self.receivedInitialPath else {
                self.receivedInitialPath = true
                ready(path)
                return
            }
            // Even an address change on the same interface invalidates old sockets.
            // NWPathMonitor already emits changes; an interface-name comparison
            // would miss transitions between Wi-Fi and cellular with both present.
            log.info("network path changed ipv6=\(path.supportsIPv6)")
            do { try core.networkChanged() } catch { self.fail(error); return }
            let ipv6 = self.profileIPv6 && path.supportsIPv6
            guard let routed = self.routesIPv6, routed != ipv6 else { return }
            let epoch = self.epoch
            self.applySettings(ipv6: ipv6) { error in
                guard self.epoch == epoch, self.core != nil else { return }
                if let error {
                    log.error("network settings update failed: \(Diagnostics.describe(error))")
                } else {
                    log.info("IPv6 \(ipv6 ? "now routed through the tunnel" : "left on the device network") after network change")
                }
            }
        }
        monitor.start(queue: queue)
        self.monitor = monitor
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
            do {
                let state = try JSONSerialization.jsonObject(with: core.snapshot()) as? [String: Any]
                if state?["stopped"] as? Bool == true {
                    self.fail(ClientError.message("代理内核已停止，请重新连接。"))
                    return
                }
                // Memory against the ~50 MiB extension limit, with the load behind it.
                ticks += 1
                if ticks % 6 == 0 {
                    let connections = (state?["connections"] as? [Any])?.count ?? 0
                    log.info("running: memory=\(memory()) connections=\(connections)")
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
                switch message.command {
                case "snapshot": break
                case "mode":
                    guard let mode = message.mode else { throw ClientError.message("缺少模式。") }
                    try core.updateMode(mode)
                case "select":
                    guard let group = message.group, let node = message.node else { throw ClientError.message("缺少节点。") }
                    try core.select(group: group, node: node)
                default: throw ClientError.message("不支持的内核命令。")
                }
                completionHandler?(try core.snapshot())
            } catch {
                completionHandler?(try? JSONSerialization.data(withJSONObject: ["error": error.localizedDescription]))
            }
        }
    }
}
