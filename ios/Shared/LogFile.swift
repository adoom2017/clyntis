import Foundation

/// One log line shown in the app's log page.
struct LogEntry: Identifiable, Hashable {
    let id: Int
    let date: String
    let level: String
    let source: String
    let message: String
}

/// Log shared by the app and the tunnel extension, in the App Group container.
/// Lines are appended with O_APPEND so both processes can write safely; the
/// file rotates at 1 MiB, keeping one previous generation.
final class LogFile: @unchecked Sendable {
    static let shared = LogFile()

    let url: URL?
    private var previousURL: URL? { url?.deletingPathExtension().appendingPathExtension("1.log") }
    private let lock = NSLock()
    private let limit = 1 << 20
    private let formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        return formatter
    }()

    private init() {
        guard let root = ProfileStore.sharedContainer() else { url = nil; return }
        let directory = root.appendingPathComponent("Logs", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        url = directory.appendingPathComponent("clyntis.log")
    }

    func append(level: String, source: String, message: String, date: Date = Date()) {
        guard let url else { return }
        let text = Self.redact(message).replacingOccurrences(of: "\n", with: " ")
        lock.lock()
        defer { lock.unlock() }
        let line = "\(formatter.string(from: date))\t\(level)\t\(source)\t\(text)\n"
        let fd = open(url.path, O_WRONLY | O_APPEND | O_CREAT, 0o600)
        guard fd >= 0 else { return }
        defer { close(fd) }
        var size = stat()
        if fstat(fd, &size) == 0, size.st_size > limit, let previous = previousURL {
            try? FileManager.default.removeItem(at: previous)
            try? FileManager.default.moveItem(at: url, to: previous)
            let fresh = open(url.path, O_WRONLY | O_APPEND | O_CREAT, 0o600)
            guard fresh >= 0 else { return }
            defer { close(fresh) }
            write(fresh, line)
            return
        }
        write(fd, line)
    }

    /// Newest entries last; reads at most `maxBytes` from the end of the log.
    func entries(maxBytes: Int = 512 * 1024) -> [LogEntry] {
        guard let url else { return [] }
        var data = tail(of: url, maxBytes: maxBytes)
        if data.count < maxBytes, let previous = previousURL {
            data = tail(of: previous, maxBytes: maxBytes - data.count) + data
        }
        let text = String(decoding: data, as: UTF8.self)
        return text.split(separator: "\n").enumerated().compactMap { index, line in
            let parts = line.split(separator: "\t", maxSplits: 3, omittingEmptySubsequences: false)
            guard parts.count == 4 else { return nil }
            return LogEntry(id: index, date: String(parts[0]), level: String(parts[1]),
                            source: String(parts[2]), message: String(parts[3]))
        }
    }

    func clear() {
        lock.lock()
        defer { lock.unlock() }
        for file in [url, previousURL].compactMap({ $0 }) { try? FileManager.default.removeItem(at: file) }
    }

    private func write(_ fd: Int32, _ line: String) {
        _ = line.utf8CString.withUnsafeBufferPointer { Foundation.write(fd, $0.baseAddress, $0.count - 1) }
    }

    private func tail(of url: URL, maxBytes: Int) -> Data {
        guard maxBytes > 0, let handle = try? FileHandle(forReadingFrom: url) else { return Data() }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        let start = size > UInt64(maxBytes) ? size - UInt64(maxBytes) : 0
        try? handle.seek(toOffset: start)
        var data = (try? handle.readToEnd()) ?? Data()
        // Drop a partial first line when starting mid-file.
        if start > 0, let newline = data.firstIndex(of: UInt8(ascii: "\n")) {
            data = data[data.index(after: newline)...]
        }
        return Data(data)
    }

    /// UUIDs are VLESS credentials and URL queries usually hold subscription tokens.
    static func redact(_ text: String) -> String {
        var text = text.replacingOccurrences(
            of: "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            with: "<uuid>", options: .regularExpression)
        text = text.replacingOccurrences(of: "(https?://[^\\s?#]+)[?#][^\\s]*", with: "$1?…",
                                         options: .regularExpression)
        return text
    }
}
