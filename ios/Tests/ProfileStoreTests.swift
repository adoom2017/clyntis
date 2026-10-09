import XCTest
@testable import Clyntis

final class ProfileStoreTests: XCTestCase {
    func testFailedValidationDoesNotPersistCredentials() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try ProfileStore(root: root)
        XCTAssertThrowsError(try store.add(name: "Invalid", configuration: Data("uuid: secret".utf8)) { _, _ in
            throw ClientError.message("invalid")
        })
        XCTAssertTrue(try store.profiles().isEmpty)
    }
    func testSourceBytesSurviveImportAndRemoval() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try ProfileStore(root: root)
        let bytes = Data("# original comments\npassword: secret\n".utf8)
        let profile = try store.add(name: "Source", configuration: bytes) { _, _ in }
        XCTAssertEqual(try store.configuration(for: profile.id), bytes)
        XCTAssertEqual(try store.profiles(), [profile])
        try store.remove(profile)
        XCTAssertTrue(try store.profiles().isEmpty)
    }
    func testEditingValidatesAndKeepsTheOldConfigurationOnFailure() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try ProfileStore(root: root)
        let original = Data("mode: rule\nrules: ['MATCH,DIRECT']\n".utf8)
        let profile = try store.add(name: "Edit", configuration: original, source: "https://example.com/c?token=x",
                                    encrypted: true) { _, _ in }
        XCTAssertEqual(profile.sourceHost, "example.com")
        XCTAssertEqual(profile.encrypted, true)
        let validate: (Data, URL) throws -> Void = { bytes, directory in
            try CoreSession(configuration: bytes, directory: directory).close()
        }
        XCTAssertThrowsError(try store.replaceConfiguration(profile.id, with: Data("proxies: [{name: bad, type: socks5}]\n".utf8),
                                                            validate: validate))
        XCTAssertEqual(try store.configuration(for: profile.id), original)
        let edited = Data("mode: global\nrules: ['MATCH,DIRECT']\n".utf8)
        let updated = try store.replaceConfiguration(profile.id, with: edited, validate: validate)
        XCTAssertEqual(try store.configuration(for: profile.id), edited)
        XCTAssertNotNil(updated.updatedAt)
        XCTAssertEqual(try store.rename(profile.id, to: "  Renamed ").name, "Renamed")
        XCTAssertThrowsError(try store.rename(profile.id, to: "   "))
        XCTAssertEqual(try store.profiles().first?.name, "Renamed")
        XCTAssertEqual(try store.profiles().first?.source, "https://example.com/c?token=x")
    }

    func testProfilesWrittenBeforeSourceTrackingStillLoad() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try ProfileStore(root: root)
        let profile = try store.add(name: "Old", configuration: Data("mode: rule\n".utf8)) { _, _ in }
        let legacy = #"{"id":"\#(profile.id.uuidString)","name":"Old","createdAt":700000000}"#
        try Data(legacy.utf8).write(to: store.directory(for: profile.id).appendingPathComponent("profile.json"))
        let loaded = try XCTUnwrap(try store.profiles().first)
        XCTAssertEqual(loaded.name, "Old")
        XCTAssertNil(loaded.source)
        XCTAssertNil(loaded.sourceHost)
    }

    func testCustomRulesValidateAndLeadTheProfile() throws {
        let saved = CustomRules.load()
        defer { try? CustomRules.save(saved) }
        XCTAssertThrowsError(try CustomRules.save(["MATCH,DIRECT"]))
        XCTAssertThrowsError(try CustomRules.save(["NOPE,x,DIRECT"]))
        try CustomRules.save([" DOMAIN-SUFFIX,ads.test,REJECT ", "DOMAIN,x.test,Missing"])
        XCTAssertEqual(CustomRules.load(), ["DOMAIN-SUFFIX,ads.test,REJECT", "DOMAIN,x.test,Missing"])
        let profile = Data("proxy-groups:\n  - {name: Auto, type: select, proxies: [DIRECT]}\nrules:\n  - MATCH,Auto\n".utf8)
        XCTAssertEqual(try CoreSession.ruleTargets(configuration: profile), ["DIRECT", "REJECT", "Auto"])
        let (merged, skipped) = try CustomRules.applied(to: profile)
        XCTAssertEqual(skipped.map(\.rule), ["DOMAIN,x.test,Missing"])
        let text = String(decoding: merged, as: UTF8.self)
        let ads = try XCTUnwrap(text.range(of: "DOMAIN-SUFFIX,ads.test,REJECT"))
        let match = try XCTUnwrap(text.range(of: "MATCH,Auto"))
        XCTAssertLessThan(ads.lowerBound, match.lowerBound)
        // The merged profile is a valid tunnel configuration.
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try CoreSession(configuration: merged, directory: root).close()
    }

    func testTunnelReadsWhetherTheProfileEnablesIPv6() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        // Absent means the core default (enabled), as in mihomo.
        for (yaml, expected) in [("ipv6: true\n", true), ("ipv6: false\n", false), ("mode: rule\n", true)] {
            let session = try CoreSession(configuration: Data((yaml + "rules: ['MATCH,DIRECT']\n").utf8), directory: root)
            defer { session.close() }
            XCTAssertEqual(try session.enablesIPv6(), expected, yaml)
        }
    }

    func testAppSettingsOverrideTheProfileInTheTunnel() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let profile = Data("ipv6: false\nlog-level: debug\nrules: ['MATCH,DIRECT']\n".utf8)
        XCTAssertEqual(try AppOverrides().applied(to: profile), profile)
        let overrides = AppOverrides(logLevel: "warning", ipv6: true, sniffing: nil)
        let session = try CoreSession(configuration: try overrides.applied(to: profile), directory: root)
        defer { session.close() }
        XCTAssertTrue(try session.enablesIPv6())
        let state = try JSONSerialization.jsonObject(with: session.snapshot()) as? [String: Any]
        XCTAssertEqual((state?["config"] as? [String: Any])?["log-level"] as? String, "warning")
        XCTAssertThrowsError(try AppOverrides(logLevel: "loud").applied(to: profile))
    }

    func testSnapshotCarriesNodeStatusForVLESSAndTailscale() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let yaml = "proxies:\n  - {name: node, type: vless, server: 127.0.0.1, port: 9, uuid: 11111111-1111-4111-8111-111111111111, tls: true}\nrules: ['MATCH,node']\n"
        let session = try CoreSession(configuration: Data(yaml.utf8), directory: root)
        defer { session.close() }
        let object = try JSONSerialization.jsonObject(with: session.snapshot()) as? [String: Any]
        let status = try XCTUnwrap(NodeStatus.decode(object?["proxies"])["node"])
        XCTAssertEqual(status.type, "VLESS")
        XCTAssertEqual(status.server, "127.0.0.1:9")
        XCTAssertEqual(status.security, "tls")
        XCTAssertNil(status.delay)
        XCTAssertEqual(status.summary, "VLESS")
        // Tailscale status as the core serializes it (snake_case keys).
        let tailscale: [String: Any] = ["ts": ["type": "Tailscale", "connections": 0, "tailscale": [
            "state": "running", "name": "me.tail.ts.net", "addresses": ["100.64.0.1"], "home_derp": "sfo", "endpoints": [],
            "peers": [["name": "pi5", "address": "100.104.16.87", "online": true, "path": "direct", "direct": "1.2.3.4:41641",
                       "rtt_ms": 9, "derp": "sfo", "exit_node": false]]]]]
        let ts = try XCTUnwrap(NodeStatus.decode(tailscale)["ts"]?.tailscale)
        XCTAssertEqual(ts.homeDerp, "sfo")
        XCTAssertEqual(ts.peers.first?.pathText, "直连 9 ms")
        XCTAssertEqual(NodeStatus.decode(tailscale)["ts"]?.summary, "已连接 · 1 台在线 · 1 直连")
    }

    func testConnectionsDecodeFromTheCoreSnapshotNewestFirst() throws {
        let snapshot: [[String: Any]] = [
            ["id": "a", "metadata": ["host": "www.google.com", "port": 443], "network": "tcp",
             "chains": ["vless-vision"], "upload": 10, "download": 2048, "start": "100"],
            ["id": "b", "metadata": ["host": "2001:db8::1", "port": 53], "network": "udp",
             "chains": ["DIRECT"], "upload": 1, "download": 1, "start": "200"],
        ]
        let list = ConnectionInfo.decode(snapshot)
        XCTAssertEqual(list.map(\.id), ["b", "a"])
        XCTAssertEqual(list[1].target, "www.google.com:443")
        XCTAssertEqual(list[0].target, "[2001:db8::1]:53")
        XCTAssertEqual(list[0].started, Date(timeIntervalSince1970: 200))
        XCTAssertTrue(ConnectionInfo.decode(nil).isEmpty)
    }

    func testAdblockSettingsReachTheCoreAndItsStatus() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root.appendingPathComponent("adblock"), withIntermediateDirectories: true)
        // A fresh cached copy of the preset list: nothing is downloaded.
        try Data("payload:\n  - '+.ads.test'\n".utf8).write(to: root.appendingPathComponent("adblock/awavenue-ads.list"))
        let overrides = AppOverrides(adblock: AdblockSettings(enabled: true, presets: ["awavenue"], allow: ["keep.ads.test"]))
        let profile = Data("rules: ['MATCH,DIRECT']\n".utf8)
        let session = try CoreSession(configuration: try overrides.applied(to: profile), directory: root)
        defer { session.close() }
        try session.start()
        let object = try JSONSerialization.jsonObject(with: session.snapshot()) as? [String: Any]
        let status = try XCTUnwrap(AdblockStatus.decode(object?["adblock"]))
        XCTAssertTrue(status.enabled)
        XCTAssertEqual(status.lists.first?.name, "AWAvenue-Ads")
        XCTAssertEqual(status.lists.first?.entries, 1)
        XCTAssertEqual(status.total, 0)
        XCTAssertNoThrow(try session.updateAdblockAllow(["ads.test"]))
        XCTAssertThrowsError(try session.updateAdblockAllow([""]))
    }

    @MainActor
    func testAdblockSummaryExplainsMissingStatistics() throws {
        let model = AppModel()
        XCTAssertEqual(model.adblockSummary, "未开启")
        model.overrides.adblock = AdblockSettings()
        // Turned on in settings, not yet in the running core.
        XCTAssertEqual(model.adblockState, .pending)
        XCTAssertEqual(model.adblockSummary, "重新连接后生效")
        model.adblock = AdblockStatus.decode([
            "enabled": true, "entries": 961, "since": 0, "total": 1234, "dns": 1200, "connections": 34,
            "domains": 20, "lists": [], "top": [], "recent": [],
        ])
        XCTAssertEqual(model.adblockState, .on)
        XCTAssertEqual(model.adblockSummary, "已拦截 \(1234.formatted()) 次")
    }

    func testLogFileRedactsCredentialsAndRoundTrips() throws {
        let log = LogFile.shared
        log.clear()
        defer { log.clear() }
        log.append(level: "warning", source: "test",
                   message: "user 11111111-2222-4333-8444-555555555555 fetched https://sub.example/x?token=abc\nnext")
        let entry = try XCTUnwrap(log.entries().last)
        XCTAssertEqual(entry.level, "warning")
        XCTAssertEqual(entry.source, "test")
        XCTAssertEqual(entry.message, "user <uuid> fetched https://sub.example/x?… next")
        log.clear()
        XCTAssertTrue(log.entries().isEmpty)
    }

    func testPacketTunnelConfigRejectsUnsupportedProtocols() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        XCTAssertThrowsError(try CoreSession(configuration: Data("proxies: [{name: bad, type: socks5}]\n".utf8), directory: root))
    }

    func testPacketTunnelSessionDisablesListenersAndReportsLivePolicy() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let source = Data("""
        mixed-port: 17891
        authentication: ['user:secret']
        proxy-groups:
          - {name: Route, type: select, proxies: [DIRECT, REJECT]}
        rules: ['MATCH,Route']
        """.utf8)
        let data = try await Task.detached {
            let session = try CoreSession(configuration: source, directory: root)
            defer { session.close() }
            try session.start()
            try session.updateMode("direct")
            try session.select(group: "Route", node: "REJECT")
            return try session.snapshot()
        }.value
        let snapshot = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let config = try XCTUnwrap(snapshot["config"] as? [String: Any])
        XCTAssertEqual(config["mixed-port"] as? Int, 0)
        XCTAssertEqual(config["mode"] as? String, "direct")
        XCTAssertNil(config["authentication"])
        XCTAssertEqual((snapshot["selections"] as? [String: String])?["Route"], "REJECT")
        XCTAssertEqual(snapshot["stopped"] as? Bool, false)
    }
}
