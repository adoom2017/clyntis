import Foundation
import Security

/// The HTTPS decryption CA, kept in the App Group apart from the settings so
/// the tunnel can read it and the key is written only once. The core makes
/// it; iOS trusts it only after the user installs it as a profile and turns
/// on full trust for it.
struct MitmAuthority: Equatable {
    let cert: String
    let key: String

    /// What the core reports about the CA, plus a server certificate it
    /// signed, for asking iOS whether it trusts the CA.
    struct Check: Decodable, Equatable {
        struct Info: Decodable, Equatable {
            let name: String
            let fingerprint: String
            let notAfter: String
        }
        let ca: Info
        let caDer: String
        let leaf: String
        let host: String
    }

    private static func url(_ name: String) -> URL? {
        ProfileStore.sharedContainer()?.appendingPathComponent(name)
    }

    static func load() -> MitmAuthority? {
        guard let certURL = url("mitm-ca.pem"), let keyURL = url("mitm-ca.key"),
              let cert = try? String(contentsOf: certURL, encoding: .utf8),
              let key = try? String(contentsOf: keyURL, encoding: .utf8) else { return nil }
        return MitmAuthority(cert: cert, key: key)
    }

    /// Makes and saves a new CA, replacing any earlier one.
    static func generate() throws -> MitmAuthority {
        let (cert, key) = try CoreSession.generateAuthority()
        guard let certURL = url("mitm-ca.pem"), let keyURL = url("mitm-ca.key") else {
            throw ClientError.message(L("无法访问共享存储。"))
        }
        // The tunnel reads it while the device may be locked (after first unlock).
        let protection: Data.WritingOptions = [.atomic, .completeFileProtectionUntilFirstUserAuthentication]
        try Data(key.utf8).write(to: keyURL, options: protection)
        try Data(cert.utf8).write(to: certURL, options: protection)
        return MitmAuthority(cert: cert, key: key)
    }

    func check() throws -> Check {
        try JSONDecoder().decode(Check.self, from: CoreSession.checkAuthority(cert: cert, key: key))
    }

    /// Whether iOS trusts the CA for TLS servers: installed and fully trusted.
    static func trusted(_ check: Check) -> Bool {
        guard let leafData = Data(base64Encoded: check.leaf), let caData = Data(base64Encoded: check.caDer),
              let leaf = SecCertificateCreateWithData(nil, leafData as CFData),
              let ca = SecCertificateCreateWithData(nil, caData as CFData) else { return false }
        var trust: SecTrust?
        let policy = SecPolicyCreateSSL(true, check.host as CFString)
        guard SecTrustCreateWithCertificates([leaf, ca] as CFArray, policy, &trust) == errSecSuccess,
              let trust else { return false }
        // Only certificates already in the store count; never fetch issuers.
        SecTrustSetNetworkFetchAllowed(trust, false)
        return SecTrustEvaluateWithError(trust, nil)
    }

    /// A configuration profile carrying the CA, for Settings to install.
    static func profile(_ check: Check) throws -> Data {
        guard let der = Data(base64Encoded: check.caDer) else {
            throw ClientError.message(L("无法读取内核结果。"))
        }
        let certificate: [String: Any] = [
            "PayloadCertificateFileName": "clyntis-ca.cer",
            "PayloadContent": der,
            "PayloadDescription": "Clyntis HTTPS",
            "PayloadDisplayName": check.ca.name,
            "PayloadIdentifier": "org.clyntis.ios.mitm-ca.certificate",
            "PayloadType": "com.apple.security.root",
            "PayloadUUID": UUID().uuidString,
            "PayloadVersion": 1,
        ]
        let profile: [String: Any] = [
            "PayloadContent": [certificate],
            "PayloadDescription": L("Clyntis 抓包用于解密 HTTPS 的根证书。只在分析时信任，用完可在设置里删除。"),
            "PayloadDisplayName": check.ca.name,
            "PayloadIdentifier": "org.clyntis.ios.mitm-ca",
            "PayloadRemovalDisallowed": false,
            "PayloadType": "Configuration",
            "PayloadUUID": UUID().uuidString,
            "PayloadVersion": 1,
        ]
        return try PropertyListSerialization.data(fromPropertyList: profile, format: .xml, options: 0)
    }
}
