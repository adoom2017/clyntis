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
}
