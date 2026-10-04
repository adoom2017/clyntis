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
