import XCTest
@testable import Clyntis

final class MitmTests: XCTestCase {
    /// The settings the app saves reach the core's profile, CA included only
    /// when filled in.
    func testSettingsApplyThroughTheCore() throws {
        let (cert, key) = try CoreSession.generateAuthority()
        var overrides = AppOverrides()
        overrides.mitm = MitmSettings(enable: true, hostnames: ["*.ads.test"])
        overrides.mitm = overrides.mitm?.withAuthority(MitmAuthority(cert: cert, key: key))
        let yaml = try XCTUnwrap(String(data: overrides.applied(to: Data("mode: rule\n".utf8)), encoding: .utf8))
        XCTAssertTrue(yaml.contains("*.ads.test"), yaml)
        XCTAssertTrue(yaml.contains("BEGIN CERTIFICATE"))
        XCTAssertTrue(yaml.contains("PRIVATE KEY"))
        let saved = try JSONEncoder().encode(overrides.mitm?.withoutAuthority)
        XCTAssertFalse(String(decoding: saved, as: UTF8.self).contains("caKey"))

        let update = try JSONSerialization.jsonObject(with: XCTUnwrap(overrides.mitm).coreUpdate()) as? [String: [String: Any]]
        XCTAssertEqual(update?["mitm"]?["hostname"] as? [String], ["*.ads.test"])
        XCTAssertEqual(update?["mitm"]?["ca-key"] as? String, key)
    }

    /// A CA nobody installed is not trusted, and its profile is a valid plist
    /// carrying the certificate.
    func testUntrustedAuthorityAndItsProfile() throws {
        let (cert, key) = try CoreSession.generateAuthority()
        let check = try MitmAuthority(cert: cert, key: key).check()
        XCTAssertTrue(check.ca.name.hasPrefix("Clyntis Inspection CA"))
        XCTAssertFalse(MitmAuthority.trusted(check))
        let profile = try MitmAuthority.profile(check)
        let plist = try XCTUnwrap(PropertyListSerialization.propertyList(from: profile, format: nil) as? [String: Any])
        XCTAssertEqual(plist["PayloadType"] as? String, "Configuration")
        let payload = try XCTUnwrap((plist["PayloadContent"] as? [[String: Any]])?.first)
        XCTAssertEqual(payload["PayloadType"] as? String, "com.apple.security.root")
        XCTAssertEqual(payload["PayloadContent"] as? Data, Data(base64Encoded: check.caDer))
    }

    func testRequestLogEntriesDecode() throws {
        let json = #"{"requests":[{"id":3,"time":1700000000000,"network":"tcp","source":"","host":"ads.test","port":443,"rule":"Match","chain":"DIRECT","status":"http","duration":12,"upload":0,"download":5,"connection":"c","requests":0,"http":{"method":"GET","url":"https://ads.test/a?b=1","decrypted":true,"status":200,"requestSize":0,"responseSize":5}}],"next":3}"#
        let page = try JSONDecoder().decode(RequestPage.self, from: Data(json.utf8))
        XCTAssertEqual(page.next, 3)
        XCTAssertEqual(page.requests.first?.http?.url, "https://ads.test/a?b=1")
    }
}
