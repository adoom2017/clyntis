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

    struct Record: Sendable {
        let level: String
        let source: String
        let message: String
        let date: Date
    }

    /// Cheap fingerprint of the active log file (modification timestamp, byte size, inode)
    /// so polling UIs skip reading and parsing when nothing changed.
    struct Stamp: Equatable, Sendable {
        let modifiedSeconds: Int
        let modifiedNanoseconds: Int
        let size: Int64
        let inode: UInt64
    }

    private static let uuidRegex = try! NSRegularExpression(
        pattern: "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
    private static let urlQueryRegex = try! NSRegularExpression(
        pattern: "(https?://[^\\s?#]+)[?#][^\\s]*")

    func append(level: String, source: String, message: String, date: Date = Date()) {
        appendBatch([Record(level: level, source: source, message: message, date: date)])
    }

    /// Formats, redacts, and writes multiple structured log records in a single
    /// open/fstat/write/close cycle.
    func appendBatch(_ records: [Record]) {
        guard let url, !records.isEmpty else { return }
        let prepared = records.map { record in
            (record.date, record.level, record.source,
             Self.redact(record.message).replacingOccurrences(of: "\n", with: " "))
        }
        lock.lock()
        defer { lock.unlock() }
        var payload = ""
        payload.reserveCapacity(prepared.count * 128)
        for (date, level, source, text) in prepared {
            payload += "\(formatter.string(from: date))\t\(level)\t\(source)\t\(text)\n"
        }
        writeLocked(payload, to: url)
    }

    /// Appends pre-formatted log lines in a single open/fstat/write/close cycle.
    func appendBatch(_ lines: [String]) {
        guard let url, !lines.isEmpty else { return }
        var payload = ""
        payload.reserveCapacity(lines.reduce(0) { $0 + $1.utf8.count + 1 })
        for line in lines {
            payload += line
            if !line.hasSuffix("\n") { payload += "\n" }
        }
        lock.lock()
        defer { lock.unlock() }
        writeLocked(payload, to: url)
    }

    /// Called with `lock` held.
    private func writeLocked(_ payload: String, to url: URL) {
        let fd = open(url.path, O_WRONLY | O_APPEND | O_CREAT, 0o600)
        guard fd >= 0 else { return }
        defer { close(fd) }
        var size = stat()
        if fstat(fd, &size) == 0, size.st_size > limit {
            rotate()
            let fresh = open(url.path, O_WRONLY | O_APPEND | O_CREAT, 0o600)
            guard fresh >= 0 else { return }
            defer { close(fresh) }
            write(fresh, payload)
            return
        }
        write(fd, payload)
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

    /// Current modification timestamp, byte size, and inode of the active log file.
    func stamp() -> Stamp? {
        guard let url else { return nil }
        var info = stat()
        guard stat(url.path, &info) == 0 else { return nil }
        return Stamp(
            modifiedSeconds: info.st_mtimespec.tv_sec,
            modifiedNanoseconds: info.st_mtimespec.tv_nsec,
            size: info.st_size,
            inode: info.st_ino
        )
    }

    /// Returns updated entries and the current stamp when the active log file changed
    /// since `previous` (or when `force` is true); returns `nil` when unchanged.
    func entries(since previous: Stamp?, force: Bool = false, maxBytes: Int = 512 * 1024) -> (entries: [LogEntry], stamp: Stamp?)? {
        let current = stamp()
        if !force, current == previous { return nil }
        return (entries(maxBytes: maxBytes), current)
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

    private func write(_ fd: Int32, _ text: String) {
        var copy = text
        copy.withUTF8 { buffer in
            guard let base = buffer.baseAddress else { return }
            var written = 0
            while written < buffer.count {
                let n = Foundation.write(fd, base.advanced(by: written), buffer.count - written)
                if n > 0 {
                    written += n
                } else if n < 0 && errno == EINTR {
                    continue
                } else {
                    break
                }
            }
        }
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
        var result = text
        if result.contains("-") {
            let range = NSRange(result.startIndex..., in: result)
            result = uuidRegex.stringByReplacingMatches(in: result, range: range, withTemplate: "<uuid>")
        }
        if result.contains("://") {
            let range = NSRange(result.startIndex..., in: result)
            result = urlQueryRegex.stringByReplacingMatches(in: result, range: range, withTemplate: "$1?…")
        }
        return result
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
