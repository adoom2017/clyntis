import Foundation
import os

/// Diagnostics go to the unified log (Console.app, or
/// `log show --predicate 'subsystem == "org.clyntis.ios"' --info`) and to the
/// shared log file shown on the app's log page.
/// Never log configuration contents, server addresses or passwords.
enum Diagnostics {
    static let app = DiagnosticLog(category: "app")
    static let tunnel = DiagnosticLog(category: "tunnel")

    /// Moves buffered core log lines into the shared log file.
    static func collectCoreLogs() {
        guard let data = try? CoreSession.drainLogs(), !data.isEmpty else { return }
        for line in data.split(separator: UInt8(ascii: "\n")) {
            guard let object = try? JSONSerialization.jsonObject(with: Data(line)) as? [String: Any],
                  let message = object["payload"] as? String else { continue }
            let date = (object["time"] as? Double).map(Date.init(timeIntervalSince1970:)) ?? Date()
            LogFile.shared.append(level: object["type"] as? String ?? "info", source: "core",
                                  message: message, date: date)
        }
    }

    /// Localized text plus NSError domain/code, which identify system failures
    /// (for example NEVPNErrorDomain codes) that the message alone hides.
    static func describe(_ error: Error) -> String {
        let ns = error as NSError
        var text = "\(ns.domain)#\(ns.code): \(error.localizedDescription)"
        if let underlying = ns.userInfo[NSUnderlyingErrorKey] as? NSError {
            text += " (underlying \(underlying.domain)#\(underlying.code))"
        }
        return text
    }

    /// Physical memory footprint in MiB, the figure jetsam compares against the
    /// Network Extension limit.
    static func footprintMiB() -> Double {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return result == KERN_SUCCESS ? Double(info.phys_footprint) / 1_048_576 : -1
    }
}

struct DiagnosticLog {
    let category: String
    private var logger: Logger { Logger(subsystem: "org.clyntis.ios", category: category) }

    func info(_ message: String) {
        logger.info("\(message, privacy: .public)")
        LogFile.shared.append(level: "info", source: category, message: message)
    }
    func warning(_ message: String) {
        logger.warning("\(message, privacy: .public)")
        LogFile.shared.append(level: "warning", source: category, message: message)
    }
    func error(_ message: String) {
        logger.error("\(message, privacy: .public)")
        LogFile.shared.append(level: "error", source: category, message: message)
    }
}
