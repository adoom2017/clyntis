import SwiftUI

/// Shared app/tunnel/core log, newest first.
struct LogView: View {
    private enum Level: String, CaseIterable, Identifiable {
        case all = "全部", info = "信息", warning = "警告", error = "错误"
        var id: Self { self }
        func includes(_ level: String) -> Bool {
            switch self {
            case .all: true
            case .info: level != "debug"
            case .warning: level == "warning" || level == "error"
            case .error: level == "error"
            }
        }
    }

    @State private var entries: [LogEntry] = []
    @State private var level = Level.all
    @State private var query = ""
    @State private var confirmClear = false

    private var visible: [LogEntry] {
        entries.reversed().filter { entry in
            level.includes(entry.level)
                && (query.isEmpty || entry.message.localizedCaseInsensitiveContains(query)
                    || entry.source.localizedCaseInsensitiveContains(query))
        }
    }

    var body: some View {
        NavigationStack {
            List(visible) { entry in
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 6) {
                        Text(entry.date.dropFirst(11)).monospacedDigit()
                        Text(entry.source)
                        Spacer()
                        Text(entry.level.uppercased()).foregroundStyle(color(entry.level))
                    }
                    .font(.caption2).foregroundStyle(.secondary)
                    Text(entry.message)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                }
                .padding(.vertical, 2)
            }
            .listStyle(.plain)
            .overlay {
                if visible.isEmpty {
                    ContentUnavailableView(entries.isEmpty ? "暂无日志" : "无匹配日志",
                                           systemImage: "doc.text.magnifyingglass")
                }
            }
            .searchable(text: $query, prompt: "搜索日志")
            .navigationTitle("日志")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Picker("级别", selection: $level) {
                        ForEach(Level.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.menu)
                }
                ToolbarItemGroup(placement: .topBarTrailing) {
                    if let url = LogFile.shared.url, !entries.isEmpty {
                        ShareLink(item: url) { Image(systemName: "square.and.arrow.up") }
                    }
                    Button("清空", systemImage: "trash") { confirmClear = true }
                        .disabled(entries.isEmpty)
                }
            }
            .confirmationDialog("清空所有日志？", isPresented: $confirmClear, titleVisibility: .visible) {
                Button("清空", role: .destructive) {
                    LogFile.shared.clear()
                    entries = []
                }
            }
            .refreshable { await reload() }
            .task {
                // Live view while the page is visible; the tunnel appends every second.
                while !Task.isCancelled {
                    await reload()
                    try? await Task.sleep(for: .seconds(2))
                }
            }
        }
    }

    private func reload() async {
        entries = await Task.detached { LogFile.shared.entries() }.value
    }

    private func color(_ level: String) -> Color {
        switch level {
        case "error": .red
        case "warning": .orange
        default: .secondary
        }
    }
}
