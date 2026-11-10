import Foundation

struct TunnelMessage: Codable {
    let command: String
    var mode: String?
    var group: String?
    var node: String?
    /// A connection id for "close"; nil closes all.
    var id: String?
    /// The ad blocking allowlist for "adblock-allow".
    var allow: [String]?
    /// The domain, address or URL for "test-route", and "tcp" or "udp".
    var target: String?
    var network: String?
    /// "dns-leak": also run the online bash.ws test.
    var online: Bool?
    /// "requests": entries after this id.
    var after: UInt64?
    /// "request-detail": the entry's id.
    var request: UInt64?
    /// "export-requests": "har" or "csv".
    var format: String?
    /// "mitm": the decryption settings; the tunnel adds the CA.
    var mitm: MitmSettings?
}
