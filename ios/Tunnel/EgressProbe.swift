import Darwin
import Foundation
import Network

/// Whether the extension can still reach the device network, asked three
/// ways at once: a BSD UDP socket and a BSD TCP connect (what the core uses)
/// and an NWConnection (Network.framework). Each sends a DNS query for
/// apple.com to public resolvers. The errno tells a dead network
/// (ENETUNREACH, a timeout) from iOS refusing this process (EPIPE at once,
/// as when the tunnel stayed down after a Wi-Fi switch until reconnected).
enum EgressProbe {
    static let servers = ["119.29.29.29", "223.5.5.5", "1.1.1.1"]

    struct Result: CustomStringConvertible {
        var udp: [String] = []
        var tcp: [String] = []
        var network: [String] = []
        var udpOK = false, tcpOK = false, networkOK = false
        /// Any probe sent with EPIPE: the system refuses this process's sockets.
        var refused = false

        var reachable: Bool { udpOK || tcpOK || networkOK }

        var description: String {
            "bsd-udp=[\(udp.joined(separator: ", "))] bsd-tcp=[\(tcp.joined(separator: ", "))] "
                + "nw-udp=[\(network.joined(separator: ", "))]"
        }
    }

    /// Runs off the caller's queue; `completion` is called once, on `queue`.
    static func run(queue: DispatchQueue, completion: @escaping (Result) -> Void) {
        let work = DispatchQueue(label: "org.clyntis.ios.egress-probe", attributes: .concurrent)
        let group = DispatchGroup()
        let lock = NSLock()
        var result = Result()
        for server in servers {
            group.enter()
            work.async {
                let (ok, detail, refused) = udp(server)
                lock.lock()
                result.udp.append("\(server) \(detail)")
                result.udpOK = result.udpOK || ok
                result.refused = result.refused || refused
                lock.unlock()
                group.leave()
            }
            group.enter()
            work.async {
                let (ok, detail, refused) = tcp(server)
                lock.lock()
                result.tcp.append("\(server) \(detail)")
                result.tcpOK = result.tcpOK || ok
                result.refused = result.refused || refused
                lock.unlock()
                group.leave()
            }
            group.enter()
            network(server, queue: work) { ok, detail in
                lock.lock()
                result.network.append("\(server) \(detail)")
                result.networkOK = result.networkOK || ok
                lock.unlock()
                group.leave()
            }
        }
        group.notify(queue: queue) {
            lock.lock()
            let final = result
            lock.unlock()
            completion(final)
        }
    }

    /// A DNS query for apple.com A, with `id`.
    private static func query(id: UInt16) -> [UInt8] {
        var bytes: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xff), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in ["apple", "com"] {
            bytes.append(UInt8(label.utf8.count))
            bytes.append(contentsOf: label.utf8)
        }
        bytes.append(contentsOf: [0, 0, 1, 0, 1])
        return bytes
    }

    private static func describe(_ code: Int32) -> String {
        "\(String(cString: strerror(code))) (errno \(code))"
    }

    private static func address(_ server: String, port: UInt16) -> sockaddr_in {
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        inet_pton(AF_INET, server, &address.sin_addr)
        return address
    }

    /// The local address the kernel picked for `fd`: which interface it used.
    private static func local(_ fd: Int32) -> String {
        var address = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let result = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        guard result == 0 else { return "?" }
        var host = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        inet_ntop(AF_INET, &address.sin_addr, &host, socklen_t(host.count))
        return "\(String(cString: host)):\(UInt16(bigEndian: address.sin_port))"
    }

    private static func connect(_ fd: Int32, _ server: String, port: UInt16) -> Int32 {
        var target = address(server, port: port)
        return withUnsafePointer(to: &target) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
    }

    /// (answered, detail, refused with EPIPE)
    private static func udp(_ server: String) -> (Bool, String, Bool) {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return (false, "socket: \(describe(errno))", false) }
        defer { close(fd) }
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        guard connect(fd, server, port: 53) == 0 else {
            let code = errno
            return (false, "connect: \(describe(code))", code == EPIPE)
        }
        let id = UInt16.random(in: 1...UInt16.max)
        let bytes = query(id: id)
        guard send(fd, bytes, bytes.count, 0) == bytes.count else {
            let code = errno
            return (false, "send from \(local(fd)): \(describe(code))", code == EPIPE)
        }
        var reply = [UInt8](repeating: 0, count: 512)
        let count = recv(fd, &reply, reply.count, 0)
        guard count >= 2 else {
            let code = errno
            return (false, "recv from \(local(fd)): \(count < 0 ? describe(code) : "empty")", code == EPIPE)
        }
        let matches = UInt16(reply[0]) << 8 | UInt16(reply[1]) == id
        return (matches, "\(matches ? "answered" : "mismatched id") via \(local(fd))", false)
    }

    /// Connects only: reaching the resolver's port 53 is the question.
    private static func tcp(_ server: String) -> (Bool, String, Bool) {
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else { return (false, "socket: \(describe(errno))", false) }
        defer { close(fd) }
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        if connect(fd, server, port: 53) != 0 {
            let code = errno
            guard code == EINPROGRESS else {
                return (false, "connect: \(describe(code))", code == EPIPE)
            }
            var poller = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            guard poll(&poller, 1, 3_000) > 0 else { return (false, "connect timed out after 3 s", false) }
            var failure: Int32 = 0
            var length = socklen_t(MemoryLayout<Int32>.size)
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &failure, &length)
            guard failure == 0 else {
                return (false, "connect: \(describe(failure))", failure == EPIPE)
            }
        }
        return (true, "connected via \(local(fd))", false)
    }

    private static func network(_ server: String, queue: DispatchQueue,
                                completion: @escaping (Bool, String) -> Void) {
        let connection = NWConnection(host: NWEndpoint.Host(server), port: 53, using: .udp)
        let lock = NSLock()
        var done = false
        var last = "setup"
        let finish: (Bool, String) -> Void = { ok, detail in
            lock.lock()
            let first = !done
            done = true
            lock.unlock()
            guard first else { return }
            connection.cancel()
            completion(ok, detail)
        }
        let id = UInt16.random(in: 1...UInt16.max)
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                let path = connection.currentPath?.availableInterfaces.first.map(\.name) ?? "?"
                lock.lock(); last = "ready on \(path)"; lock.unlock()
                connection.send(content: Data(query(id: id)), completion: .contentProcessed { error in
                    if let error { finish(false, "send: \(error)") }
                })
                connection.receiveMessage { data, _, _, error in
                    if let data, data.count >= 2, UInt16(data[data.startIndex]) << 8 | UInt16(data[data.startIndex + 1]) == id {
                        finish(true, "answered on \(path)")
                    } else {
                        finish(false, "receive on \(path): \(error.map { "\($0)" } ?? "no answer")")
                    }
                }
            case let .waiting(error):
                lock.lock(); last = "waiting: \(error)"; lock.unlock()
            case let .failed(error):
                finish(false, "failed: \(error)")
            default:
                break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 3) {
            lock.lock(); let state = last; lock.unlock()
            finish(false, "timed out after 3 s (\(state))")
        }
    }
}
