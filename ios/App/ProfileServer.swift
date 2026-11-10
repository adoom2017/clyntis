import Network
import UIKit

/// Serves a configuration profile on loopback for a short while and opens it
/// in Safari: iOS installs profiles that Safari downloads, not ones an app
/// hands over. The app keeps running in the background long enough for
/// Safari to fetch it.
@MainActor
final class ProfileServer {
    private let listener: NWListener
    private let profile: Data
    private var background: UIBackgroundTaskIdentifier = .invalid
    private var stopTask: Task<Void, Never>?

    init(profile: Data) throws {
        self.profile = profile
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        parameters.allowLocalEndpointReuse = true
        listener = try NWListener(using: parameters)
    }

    /// Starts serving and opens the profile's URL in Safari.
    func open() async throws {
        let port: UInt16 = try await withCheckedThrowingContinuation { continuation in
            var resumed = false
            listener.stateUpdateHandler = { [listener] state in
                guard !resumed else { return }
                switch state {
                case .ready:
                    resumed = true
                    continuation.resume(returning: listener.port?.rawValue ?? 0)
                case .failed(let error):
                    resumed = true
                    continuation.resume(throwing: error)
                default: break
                }
            }
            let body = profile
            listener.newConnectionHandler = { connection in
                connection.start(queue: .global(qos: .userInitiated))
                // The request itself does not matter: answer once it arrives.
                connection.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { _, _, _, _ in
                    let head = "HTTP/1.1 200 OK\r\nContent-Type: application/x-apple-aspen-config\r\n"
                        + "Content-Disposition: attachment; filename=\"clyntis-ca.mobileconfig\"\r\n"
                        + "Content-Length: \(body.count)\r\nConnection: close\r\n\r\n"
                    connection.send(content: Data(head.utf8) + body, completion: .contentProcessed { _ in
                        connection.cancel()
                    })
                }
            }
            listener.start(queue: .global(qos: .userInitiated))
        }
        guard port != 0, let url = URL(string: "http://127.0.0.1:\(port)/clyntis-ca.mobileconfig") else {
            stop()
            throw ClientError.message(L("无法启动证书下载。"))
        }
        background = UIApplication.shared.beginBackgroundTask { [weak self] in self?.stop() }
        stopTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(60))
            self?.stop()
        }
        await UIApplication.shared.open(url)
    }

    func stop() {
        listener.cancel()
        stopTask?.cancel()
        if background != .invalid {
            UIApplication.shared.endBackgroundTask(background)
            background = .invalid
        }
    }
}
