import XCTest
@testable import Clyntis

final class RemoteConfigImportTests: XCTestCase {
    private static let plaintext = Data("mixed-port: 7890\nmode: rule\nrules: ['MATCH,DIRECT']\n".utf8)
    private static let encrypted = Data("fzpHye22WU1hKPevr2RwfVJhLri0X0NMDQS3D4iMfGPUsXSwpivnmPeok4ej8i4i8P8bgw==".utf8)
    private static let responseStarted = Notification.Name("ClyntisRemoteImportTestResponseStarted")

    func testPlaintextWithoutPasswordIsStoredWithoutModification() async throws {
        let store = try temporaryStore()
        defer { try? FileManager.default.removeItem(at: store.root) }
        let source = Data("# preserve comments\nauthentication: ['user:secret']\n".utf8) + Self.plaintext
        let profile = try await Task.detached {
            try RemoteConfigImporter.store(source, password: "", name: " Plain ", in: store)
        }.value
        XCTAssertEqual(try store.configuration(for: profile.id), source)
        XCTAssertEqual(profile.name, "Plain")
    }

    func testEncryptedGoldenVectorImportsAndDoesNotPersistPassword() async throws {
        let store = try temporaryStore()
        defer { try? FileManager.default.removeItem(at: store.root) }
        let wrapped = Data(" \n\(String(decoding: Self.encrypted, as: UTF8.self))\r\n".utf8)
        let profile = try await Task.detached {
            try RemoteConfigImporter.store(wrapped, password: "test-password", name: "", in: store)
        }.value
        XCTAssertEqual(profile.name, "远程配置")
        XCTAssertEqual(try store.configuration(for: profile.id), Self.plaintext)
        let directory = store.directory(for: profile.id)
        XCTAssertEqual(Set(try FileManager.default.contentsOfDirectory(atPath: directory.path)), ["config.yaml", "profile.json"])
        let metadata = try String(contentsOf: directory.appendingPathComponent("profile.json"), encoding: .utf8)
        XCTAssertFalse(metadata.contains("test-password"))
    }

    func testPasswordChoiceIsExplicitAndFailuresLeaveNoProfiles() async throws {
        let store = try temporaryStore()
        defer { try? FileManager.default.removeItem(at: store.root) }
        for (data, password) in [(Self.encrypted, "wrong"), (Self.encrypted, ""), (Self.plaintext, "test-password")] {
            do {
                _ = try await Task.detached {
                    try RemoteConfigImporter.store(data, password: password, name: "Invalid", in: store)
                }.value
                XCTFail("Invalid configuration unexpectedly imported")
            } catch { }
            XCTAssertTrue(try store.profiles().isEmpty)
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: store.root.path).isEmpty)
        }
    }

    func testEncryptedExportRoundTripsAndIsDetected() throws {
        let yaml = Data("mixed-port: 7890\nmode: rule\nrules: ['MATCH,DIRECT']\n".utf8)
        let encrypted = try ConfigCrypto.encrypt(yaml, password: "导出密码")
        XCTAssertTrue(ConfigCrypto.looksEncrypted(encrypted))
        XCTAssertFalse(ConfigCrypto.looksEncrypted(yaml))
        XCTAssertEqual(try ConfigCrypto.decrypt(encrypted, password: "导出密码"), yaml)
        XCTAssertThrowsError(try ConfigCrypto.decrypt(encrypted, password: "wrong"))
        XCTAssertThrowsError(try ConfigCrypto.encrypt(yaml, password: ""))
        XCTAssertThrowsError(try ConfigCrypto.encrypt(Data("not: [valid".utf8), password: "p"))
    }

    func testURLValidationRequiresHTTPSExceptLoopback() throws {
        XCTAssertEqual(try RemoteConfigImporter.url(from: " https://unit.invalid/config?token=abc \n").host, "unit.invalid")
        XCTAssertEqual(try RemoteConfigImporter.url(from: "http://127.0.0.1/config").scheme, "http")
        XCTAssertEqual(try RemoteConfigImporter.url(from: "http://localhost:8080/config").host, "localhost")
        for address in ["http://unit.invalid/config", "http://192.168.1.2/config", "", "config.yaml", "file:///tmp/config.yaml", "ftp://unit.invalid/config", "https://user:secret@unit.invalid/config", "https://"] {
            XCTAssertThrowsError(try RemoteConfigImporter.url(from: address))
        }
    }

    func testDownloadStreamsHTTPBodyAndPreservesBytes() async throws {
        let session = stubSession()
        defer { session.invalidateAndCancel() }
        let data = try await RemoteConfigImporter.download(from: URL(string: "https://unit.invalid/plain")!,
                                                          maximumBytes: 1024, session: session)
        XCTAssertEqual(data, Self.plaintext)
        let encrypted = try await RemoteConfigImporter.download(from: URL(string: "https://unit.invalid/encrypted")!,
                                                               maximumBytes: 1024, session: session)
        XCTAssertEqual(encrypted, Self.encrypted)
    }

    func testDownloadRejectsHTTPErrorEmptyAndOversizeBodies() async throws {
        let session = stubSession()
        defer { session.invalidateAndCancel() }
        for path in ["error", "empty", "large-header", "plain"] {
            do {
                _ = try await RemoteConfigImporter.download(from: URL(string: "https://unit.invalid/\(path)")!,
                                                           maximumBytes: 8, session: session)
                XCTFail("Invalid response unexpectedly accepted")
            } catch { }
        }
    }

    func testCancellationDoesNotCreateAProfile() async throws {
        let store = try temporaryStore()
        defer { try? FileManager.default.removeItem(at: store.root) }
        let worker = Task.detached {
            withUnsafeCurrentTask { $0?.cancel() }
            return try RemoteConfigImporter.store(Self.encrypted, password: "test-password", name: "Cancelled", in: store)
        }
        do { _ = try await worker.value; XCTFail("Cancelled import unexpectedly saved") }
        catch is CancellationError { }
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: store.root.path).isEmpty)
    }

    func testCancellationInterruptsAStalledDownload() async throws {
        let session = stubSession()
        defer { session.invalidateAndCancel() }
        let started = expectation(description: "Response headers received")
        let observer = NotificationCenter.default.addObserver(forName: Self.responseStarted, object: nil, queue: nil) { _ in
            started.fulfill()
        }
        defer { NotificationCenter.default.removeObserver(observer) }
        let worker = Task {
            try await RemoteConfigImporter.download(from: URL(string: "https://unit.invalid/stalled")!,
                                                    maximumBytes: 1024, session: session)
        }
        await fulfillment(of: [started], timeout: 3)
        worker.cancel()
        do { _ = try await worker.value; XCTFail("Cancelled download unexpectedly succeeded") }
        catch is CancellationError { }
        catch let error as URLError { XCTAssertEqual(error.code, .cancelled) }
    }

    private func temporaryStore() throws -> ProfileStore {
        try ProfileStore(root: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString))
    }

    private func stubSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [ConfigURLProtocol.self]
        return URLSession(configuration: configuration)
    }

    private final class ConfigURLProtocol: URLProtocol {
        override class func canInit(with request: URLRequest) -> Bool { request.url?.host == "unit.invalid" }
        override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
        override func startLoading() {
            let path = request.url!.lastPathComponent
            let data = path == "encrypted" ? RemoteConfigImportTests.encrypted : RemoteConfigImportTests.plaintext
            let response = HTTPURLResponse(url: request.url!, statusCode: path == "error" ? 404 : 200,
                httpVersion: "HTTP/1.1", headerFields: path == "large-header" ? ["Content-Length": "200"] : [:])!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            if path == "stalled" {
                NotificationCenter.default.post(name: RemoteConfigImportTests.responseStarted, object: nil)
                return
            }
            if path != "empty" { client?.urlProtocol(self, didLoad: data) }
            client?.urlProtocolDidFinishLoading(self)
        }
        override func stopLoading() { }
    }
}
