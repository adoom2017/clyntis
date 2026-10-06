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
