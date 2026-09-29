import Foundation
import ServiceManagement
import Security
import SystemConfiguration

@main
struct ServiceManager {
    static let proxyKeys = ["HTTPEnable", "HTTPProxy", "HTTPPort", "HTTPSEnable", "HTTPSProxy", "HTTPSPort", "SOCKSEnable", "SOCKSProxy", "SOCKSPort", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"]
    static func proxy(_ args: [String]) throws {
        guard geteuid() == 0, let preferences = SCPreferencesCreate(nil, "Clyntis" as CFString, nil),
              let services = SCNetworkServiceCopyAll(preferences) as? [SCNetworkService] else {
            throw NSError(domain: "Clyntis", code: 3, userInfo: [NSLocalizedDescriptionKey: "系统代理需要授权的后台服务"])
        }
        if args[1] == "proxy-list" {
            let ids = services.filter { service in
                guard SCNetworkServiceGetEnabled(service), let interface = SCNetworkServiceGetInterface(service),
                      let name = SCNetworkInterfaceGetBSDName(interface) as String? else { return false }
                return name.hasPrefix("en")
            }.compactMap { SCNetworkServiceGetServiceID($0) as String? }
            FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: ids)); return
        }
        guard args.count == 3, let service = services.first(where: { (SCNetworkServiceGetServiceID($0) as String?) == args[2] }) else {
            throw NSError(domain: "Clyntis", code: 4, userInfo: [NSLocalizedDescriptionKey: "网络服务已移除，原设置保留在恢复记录中"])
        }
        guard let protocolConfig = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies) else {
            throw NSError(domain: "Clyntis", code: 5, userInfo: [NSLocalizedDescriptionKey: "无法读取网络服务的代理设置"])
        }
        if args[1] == "proxy-read" {
            let current = SCNetworkProtocolGetConfiguration(protocolConfig) as? [String: Any] ?? [:]
            var result: [String: Any] = [:]
            for key in proxyKeys { result[key] = current[key] ?? NSNull() }
            FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: result)); return
        }
        guard args[1] == "proxy-write", SCPreferencesLock(preferences, true) else {
            throw NSError(domain: "Clyntis", code: 6, userInfo: [NSLocalizedDescriptionKey: "无法锁定系统网络配置"])
        }
        defer { SCPreferencesUnlock(preferences) }
        SCPreferencesSynchronize(preferences)
        guard let refreshed = SCNetworkServiceCopy(preferences, args[2] as CFString),
              let refreshedProtocol = SCNetworkServiceCopyProtocol(refreshed, kSCNetworkProtocolTypeProxies),
              let target = try JSONSerialization.jsonObject(with: FileHandle.standardInput.readDataToEndOfFile()) as? [String: Any],
              Set(target.keys).isSubset(of: Set(proxyKeys)) else {
            throw NSError(domain: "Clyntis", code: 7, userInfo: [NSLocalizedDescriptionKey: "无效代理配置"])
        }
        var current = SCNetworkProtocolGetConfiguration(refreshedProtocol) as? [String: Any] ?? [:]
        for (key, value) in target { if value is NSNull { current.removeValue(forKey: key) } else { current[key] = value } }
        guard SCNetworkProtocolSetConfiguration(refreshedProtocol, current as CFDictionary),
              SCPreferencesCommitChanges(preferences), SCPreferencesApplyChanges(preferences) else {
            throw NSError(domain: "Clyntis", code: 8, userInfo: [NSLocalizedDescriptionKey: "无法保存系统代理配置"])
        }
    }
    static func check(_ code: OSStatus) throws {
        if code != errSecSuccess { throw NSError(domain: NSOSStatusErrorDomain, code: Int(code)) }
    }
    static func verifyPeer(_ pid: pid_t) throws {
        var own: SecCode?
        try check(SecCodeCopySelf([], &own))
        var ownStatic: SecStaticCode?
        try check(SecCodeCopyStaticCode(own!, [], &ownStatic))
        var info: CFDictionary?
        try check(SecCodeCopySigningInformation(ownStatic!, SecCSFlags(rawValue: kSecCSSigningInformation), &info))
        guard let team = (info as? [String: Any])?[kSecCodeInfoTeamIdentifier as String] as? String,
              team.range(of: "^[A-Z0-9]+$", options: .regularExpression) != nil else {
            throw NSError(domain: "Clyntis", code: 1, userInfo: [NSLocalizedDescriptionKey: "后台服务需要 Developer ID 签名的应用"])
        }
        var guest: SecCode?
        try check(SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid as String: pid] as CFDictionary, [], &guest))
        var requirement: SecRequirement?
        let expression = "anchor apple generic and identifier \"org.clyntis.desktop\" and certificate leaf[subject.OU] = \"\(team)\""
        try check(SecRequirementCreateWithString(expression as CFString, [], &requirement))
        try check(SecCodeCheckValidity(guest!, SecCSFlags(rawValue: kSecCSStrictValidate), requirement))
    }
    static func restartService() throws {
        // SIGTERM lets the daemon restore routes/DNS before KeepAlive starts the new bundle binary.
        let restart = Process()
        restart.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        restart.arguments = ["kill", "SIGTERM", "system/org.clyntis.desktop.service"]
        restart.standardError = Pipe()
        try restart.run()
        restart.waitUntilExit()
        if restart.terminationStatus == 0 { return }
        let authorization = Process()
        authorization.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        authorization.arguments = ["-e", "do shell script \"/bin/launchctl kill SIGTERM system/org.clyntis.desktop.service || /bin/launchctl kickstart system/org.clyntis.desktop.service\" with administrator privileges with prompt \"Clyntis 需要重新启动网络辅助服务以完成更新。该服务用于创建 TUN 虚拟网卡、设置路由、DNS 和系统代理；退出代理时恢复网络设置。\""]
        let errors = Pipe()
        authorization.standardError = errors
        try authorization.run()
        authorization.waitUntilExit()
        guard authorization.terminationStatus == 0 else {
            let detail = String(data: errors.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            throw NSError(domain: "Clyntis", code: 10, userInfo: [NSLocalizedDescriptionKey: "辅助服务更新未完成，管理员授权被取消或系统拒绝操作。\n\(detail)"])
        }
    }
    static func main() async {
        do {
            let args = CommandLine.arguments
            if args.count >= 2 && args[1].hasPrefix("proxy-") { try proxy(args); return }
            if args.count == 3 && args[1] == "verify-peer", let pid = Int32(args[2]), pid > 0 {
                try verifyPeer(pid); return
            }
            let service = SMAppService.daemon(plistName: "org.clyntis.desktop.service.plist")
            switch args.dropFirst().first {
            case "install", "update":
                let wasEnabled = service.status == .enabled
                // Registration is idempotent. Unregistering an enabled daemon
                // here can disable its BTM entry and leave it unable to bootstrap.
                if service.status != .enabled && service.status != .requiresApproval {
                    do { try service.register() }
                    catch {
                        if (error as NSError).code == Int(EPERM) {
                            SMAppService.openSystemSettingsLoginItems()
                            throw NSError(domain: "Clyntis", code: 9, userInfo: [NSLocalizedDescriptionKey: "macOS 禁止启动该后台项目。请在系统设置 → 通用 → 登录项与扩展中允许 Clyntis（可能显示为证书开发者名称）在后台运行，然后重试。"])
                        }
                        throw error
                    }
                }
                if service.status == .requiresApproval { SMAppService.openSystemSettingsLoginItems() }
                if args[1] == "update" && wasEnabled { try restartService() }
            case "uninstall":
                if service.status != .notRegistered { try await service.unregister() }
            case "status": break
            default: throw NSError(domain: "Clyntis", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid command"])
            }
            switch service.status {
            case .enabled: print("enabled")
            case .requiresApproval: print("requires_approval")
            case .notRegistered: print("not_registered")
            case .notFound: print("not_installed")
            @unknown default: print("unknown")
            }
        } catch {
            FileHandle.standardError.write(Data(error.localizedDescription.utf8)); exit(1)
        }
    }
}
