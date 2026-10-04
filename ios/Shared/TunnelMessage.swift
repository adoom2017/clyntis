import Foundation

struct TunnelMessage: Codable {
    let command: String
    var mode: String?
    var group: String?
    var node: String?
}
