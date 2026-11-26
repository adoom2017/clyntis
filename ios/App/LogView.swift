import SwiftUI

/// Shared app/tunnel/core log, newest first.
struct LogView: View {
    private enum Level: String, CaseIterable, Identifiable {
        case all, info, warning, error
        var id: Self { self }
        var title: String {
            switch self {
            case .all: L("全部")
            case .info: L("信息")
            case .warning: L("警告")
            case .error: L("错误")
            }
        }
        func includes(_ level: String) -> Bool {
            switch self {
            case .all: true
            case .info: level != "debug"
            case .warning: level == "warning" || level == "error"
            case .error: level == "error"
            }
        }
    }

    @Environment(\.scenePhase) private var scenePhase
    @State private var isVisible = false
    @State private var entries: [LogEntry] = []
    @State private var lastStamp: LogFile.Stamp?
    @State private var loaded = false
    @State private var level = Level.all
    @State private var query = ""

    private static let renderLimit = 500

    private var visibleResult: (rows: [LogEntry], total: Int) {
        var rows: [LogEntry] = []
        rows.reserveCapacity(Self.renderLimit)
        var total = 0
        for entry in entries.reversed() {
            guard level.includes(entry.level)
                && (query.isEmpty || entry.message.localizedCaseInsensitiveContains(query)
                    || entry.source.localizedCaseInsensitiveContains(query)) else {
                continue
            }
            total += 1
            if rows.count < Self.renderLimit {
                rows.append(entry)
            }
        }
        return (rows, total)
    }

    var body: some View {
        let result = self.visibleResult
        NavigationStack {
            List {
                ForEach(result.rows) { entry in
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
                if result.total > Self.renderLimit {
                    Text(L("显示最近 500 条，共 {count} 条", ["count": result.total]))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .listStyle(.plain)
            .overlay {
                if result.rows.isEmpty {
                    ContentUnavailableView(entries.isEmpty ? L("暂无日志") : L("无匹配日志"),
                                           systemImage: "doc.text.magnifyingglass")
                }
            }
            .searchable(text: $query, prompt: L("搜索日志"))
            .navigationTitle(L("日志"))
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Picker(L("级别"), selection: $level) {
                        ForEach(Level.allCases) { Text($0.title).tag($0) }
                    }
                    .pickerStyle(.menu)
                }
                ToolbarItemGroup(placement: .topBarTrailing) {
                    if LogFile.shared.url != nil, !entries.isEmpty {
                        ShareLink(item: LogExport(), preview: SharePreview("clyntis.log")) {
                            Image(systemName: "square.and.arrow.up")
                        }
                    }
                    Button(L("清空"), systemImage: "trash") {
                        LogFile.shared.clear()
                        entries = []
                        lastStamp = nil
                    }
                    .disabled(entries.isEmpty)
                }
            }
            .refreshable { await reload(force: true) }
            .onAppear { isVisible = true }
            .onDisappear { isVisible = false }
            .task(id: isVisible && scenePhase == .active) {
                guard isVisible, scenePhase == .active else { return }
                // Live view while the page is visible and app is active.
                while !Task.isCancelled {
                    await reload(force: !loaded)
                    do { try await Task.sleep(for: .seconds(2)) } catch { break }
                }
            }
        }
    }

    private func reload(force: Bool = false) async {
        let previous = lastStamp
        let result = await Task.detached {
            LogFile.shared.entries(since: previous, force: force)
        }.value
        loaded = true
        if let result {
            entries = result.entries
            lastStamp = result.stamp
        }
    }

    private func color(_ level: String) -> Color {
        switch level {
        case "error": .red
        case "warning": .orange
        default: .secondary
        }
    }
}
