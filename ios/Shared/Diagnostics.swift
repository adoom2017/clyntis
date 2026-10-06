import Foundation
import os

/// Unified-log diagnostics, readable with Console.app or
/// `log show --predicate 'subsystem == "org.clyntis.ios"' --info`.
/// Never log configuration contents, server addresses or passwords.
enum Diagnostics {
    static let app = Logger(subsystem: "org.clyntis.ios", category: "app")
    static let tunnel = Logger(subsystem: "org.clyntis.ios", category: "tunnel")

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
