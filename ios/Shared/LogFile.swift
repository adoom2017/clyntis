import CoreTransferable
import Foundation
import UniformTypeIdentifiers

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
/// file rotates at 4 MiB into `clyntis.1.log` … `clyntis.5.log`. At a busy
/// phone's 0.5 MiB an hour that is about two days; 2 MiB held four hours,
/// too little to look back at a problem noticed the next morning.
final class LogFile: @unchecked Sendable {
    static let shared = LogFile()

    let url: URL?
    private let lock = NSLock()
    private let limit = 4 << 20
    private static let generations = 5
    /// `clyntis.<n>.log`, n = 1 newest.
    private func generation(_ n: Int) -> URL? {
        url?.deletingPathExtension().appendingPathExtension("\(n).log")
    }
    /// Every file, oldest first.
    private var files: [URL] {
        (1...Self.generations).reversed().compactMap(generation(_:)) + [url].compactMap { $0 }
    }
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
        if fstat(fd, &size) == 0, size.st_size > limit {
            rotate()
            let fresh = open(url.path, O_WRONLY | O_APPEND | O_CREAT, 0o600)
            guard fresh >= 0 else { return }
            defer { close(fresh) }
            write(fresh, line)
            return
        }
        write(fd, line)
    }

    /// Called with the lock held: drops the oldest file and shifts the rest.
    private func rotate() {
        let manager = FileManager.default
        if let oldest = generation(Self.generations) { try? manager.removeItem(at: oldest) }
        for n in stride(from: Self.generations - 1, through: 1, by: -1) {
            if let from = generation(n), let to = generation(n + 1) { try? manager.moveItem(at: from, to: to) }
        }
        if let url, let newest = generation(1) { try? manager.moveItem(at: url, to: newest) }
    }

    /// Newest entries last; reads at most `maxBytes` from the end of the log.
    func entries(maxBytes: Int = 512 * 1024) -> [LogEntry] {
        var data = Data()
        for file in files.reversed() where data.count < maxBytes {
            data = tail(of: file, maxBytes: maxBytes - data.count) + data
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
        for file in files { try? FileManager.default.removeItem(at: file) }
    }

    /// Every file joined, oldest first, in a temporary file for sharing.
    func export() throws -> URL {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        let target = FileManager.default.temporaryDirectory
            .appendingPathComponent("clyntis-\(formatter.string(from: Date())).log")
        FileManager.default.createFile(atPath: target.path, contents: nil)
        let output = try FileHandle(forWritingTo: target)
        defer { try? output.close() }
        lock.lock()
        defer { lock.unlock() }
        for file in files {
            guard let input = try? FileHandle(forReadingFrom: file) else { continue }
            defer { try? input.close() }
            while let chunk = try input.read(upToCount: 1 << 20), !chunk.isEmpty {
                try output.write(contentsOf: chunk)
            }
        }
        return target
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

/// Shares every log file as one, built when the share sheet asks for it.
struct LogExport: Transferable {
    static var transferRepresentation: some TransferRepresentation {
        FileRepresentation(exportedContentType: .plainText) { _ in
            SentTransferredFile(try LogFile.shared.export())
        }
    }
}
