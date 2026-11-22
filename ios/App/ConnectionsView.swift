import SwiftUI

/// An open connection from the core snapshot.
struct ConnectionInfo: Decodable, Identifiable, Equatable {
    struct Metadata: Decodable, Equatable {
        let host: String
        let port: Int
    }
    let id: String
    let metadata: Metadata
    let network: String
    let chains: [String]
    let rule: String?
    let upload: Int64
    let download: Int64
    /// Unix seconds, as a string.
    let start: String

    var target: String {
        metadata.host.contains(":") ? "[\(metadata.host)]:\(metadata.port)" : "\(metadata.host):\(metadata.port)"
    }
    var started: Date? { Double(start).map(Date.init(timeIntervalSince1970:)) }

    static func sorted(_ list: [ConnectionInfo]) -> [ConnectionInfo] {
        list.sorted {
            let lhs = $0.download + $0.upload
            let rhs = $1.download + $1.upload
            if lhs != rhs { return lhs > rhs }
            let lhsDate = $0.started ?? .distantPast
            let rhsDate = $1.started ?? .distantPast
            if lhsDate != rhsDate { return lhsDate > rhsDate }
            return $0.id < $1.id
        }
    }

    static func decode(_ object: Any?) -> [ConnectionInfo] {
        guard let object, let data = try? JSONSerialization.data(withJSONObject: object),
              let list = try? JSONDecoder().decode([ConnectionInfo].self, from: data) else { return [] }
        return sorted(list)
    }
}

struct HostTraffic: Decodable, Equatable, Identifiable {
    var id: String { host }
    let host: String
    let upload: UInt64
    let download: UInt64
    let activeConnections: Int
    let totalConnections: UInt64
    let chains: [String]
    let rule: String
    let lastSeen: UInt64

    var total: UInt64 { upload &+ download }
}

struct ConnectionTraffic: Decodable, Equatable, Identifiable {
    let id: String
    let host: String
    let port: Int
    let network: String
    let chains: [String]
    let rule: String
    let source: String
    let upload: UInt64
    let download: UInt64
    let start: UInt64
    let duration: UInt64
    let active: Bool

    var target: String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }
    var total: UInt64 { upload &+ download }
}

struct TrafficDetails: Decodable, Equatable {
    let since: UInt64
    let uploadTotal: UInt64
    let downloadTotal: UInt64
    let activeConnections: Int
    let totalConnections: UInt64
    let totalHosts: Int
    let hostsEvicted: Bool?
    let connectionHost: String?
    let matchingActiveConnections: Int?
    let matchingClosedConnections: UInt64?
    let retainedClosedConnections: Int?
    let closedConnectionCap: Int?
    let hosts: [HostTraffic]
    let otherUpload: UInt64
    let otherDownload: UInt64
    let otherConnections: UInt64
    let connections: [ConnectionTraffic]

    static func normalizeHost(_ host: String) -> String {
        var value = host.lowercased()
        while value.hasSuffix(".") { value.removeLast() }
        return value
    }
}

/// Open connections, like the desktop's connection page.
struct ConnectionsView: View {
    @Bindable var model: AppModel
    @State private var query = ""
    @State private var confirmCloseAll = false

    private var visible: [ConnectionInfo] {
        let query = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !query.isEmpty else { return model.connections }
        return model.connections.filter {
            "\($0.metadata.host) \($0.chains.joined(separator: " "))".lowercased().contains(query)
        }
    }

    var body: some View {
        List {
            if model.connections.isEmpty {
                ContentUnavailableView(model.connected ? L("没有连接") : L("未连接"), systemImage: "arrow.left.arrow.right",
                                       description: Text(model.connected ? L("当前没有打开的连接") : L("连接后显示网络连接")))
            }
            ForEach(visible) { connection in
                VStack(alignment: .leading, spacing: 4) {
                    Text(connection.target).font(.subheadline.monospaced()).lineLimit(1).truncationMode(.middle)
                    HStack(spacing: 6) {
                        Text(connection.network.uppercased())
                            .font(.caption2.weight(.semibold)).foregroundStyle(.tint)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(.tint.opacity(0.12), in: .capsule)
                        Text(connection.chains.joined(separator: " → ")).lineLimit(1)
                        Spacer()
                        Text("↓ \(bytes(connection.download))  ↑ \(bytes(connection.upload))").monospacedDigit()
                    }
                    .font(.caption).foregroundStyle(.secondary)
                    if let started = connection.started {
                        Text(started, style: .relative).font(.caption2).foregroundStyle(.tertiary)
                    }
                }
                .swipeActions {
                    Button(L("关闭"), role: .destructive) { Task { await model.closeConnection(connection.id) } }
                }
            }
        }
        .searchable(text: $query, prompt: L("搜索目标或代理链"))
        .navigationTitle(L("连接（{count}）", ["count": model.connections.count]))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if !model.connections.isEmpty {
                Button(L("全部关闭"), systemImage: "xmark.circle") { confirmCloseAll = true }
            }
        }
        .confirmationDialog(L("关闭全部 {count} 个连接？", ["count": model.connections.count]), isPresented: $confirmCloseAll, titleVisibility: .visible) {
            Button(L("全部关闭"), role: .destructive) { Task { await model.closeConnection(nil) } }
        }
    }

    private func bytes(_ value: Int64) -> String {
        value.formatted(.byteCount(style: .binary, spellsOutZero: false))
    }
}

struct TrafficDetailsView: View {
    @Bindable var model: AppModel
    @Environment(\.scenePhase) private var scenePhase

    private enum Tab: String, CaseIterable {
        case hosts, connections
    }

    private struct PollKey: Equatable {
        let connected: Bool
        let active: Bool
        let host: String?
    }

    @State private var details: TrafficDetails?
    @State private var failure: String?
    @State private var requestSeq = 0
    @State private var tab: Tab = .hosts
    @State private var selectedHost: String?
    @State private var query = ""

    private var activeHost: String? {
        tab == .connections ? selectedHost : nil
    }

    private var trimmedQuery: String {
        query.trimmingCharacters(in: .whitespaces).lowercased()
    }

    private func isScopeReady(_ current: TrafficDetails) -> Bool {
        if let activeHost {
            return TrafficDetails.normalizeHost(current.connectionHost ?? "") == TrafficDetails.normalizeHost(activeHost)
        }
        return current.connectionHost == nil
    }

    private func visibleHosts(in current: TrafficDetails) -> [HostTraffic] {
        let q = trimmedQuery
        guard !q.isEmpty else { return current.hosts }
        return current.hosts.filter {
            "\($0.host) \($0.rule) \($0.chains.joined(separator: " "))".lowercased().contains(q)
        }
    }

    private func visibleConnections(in current: TrafficDetails) -> [ConnectionTraffic] {
        let q = trimmedQuery
        let targetHost = selectedHost.map(TrafficDetails.normalizeHost)
        return current.connections.filter { conn in
            if let targetHost, TrafficDetails.normalizeHost(conn.host) != targetHost {
                return false
            }
            guard !q.isEmpty else { return true }
            return "\(conn.host):\(conn.port) \(conn.network) \(conn.rule) \(conn.chains.joined(separator: " "))".lowercased().contains(q)
        }
    }

    var body: some View {
        List {
            if let failure {
                Text(failure).font(.footnote).foregroundStyle(.red)
            }
            if !model.connected && details == nil {
                ContentUnavailableView(L("未连接"), systemImage: "chart.bar.xaxis",
                                       description: Text(L("连接后显示流量详情")))
            } else if let current = details {
                let totalBytes = current.uploadTotal &+ current.downloadTotal
                let otherTotal = current.otherUpload &+ current.otherDownload
                let hosts = visibleHosts(in: current)
                let ready = isScopeReady(current)
                let connections = ready ? visibleConnections(in: current) : []

                Section {
                    LabeledContent(L("总流量"), value: bytes(totalBytes))
                    LabeledContent(L("下载"), value: bytes(current.downloadTotal))
                    LabeledContent(L("上传"), value: bytes(current.uploadTotal))
                    LabeledContent(L("连接"), value: L("活跃 {active} / 共 {total}", ["active": current.activeConnections, "total": Int(clamping: current.totalConnections)]))
                } footer: {
                    if let footer = hostsSummaryFooter(for: current) {
                        Text(footer)
                    }
                }

                Section {
                    Picker(L("视图"), selection: $tab) {
                        Text(L("按目标")).tag(Tab.hosts)
                        Text(L("按连接")).tag(Tab.connections)
                    }
                    .pickerStyle(.segmented)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets())
                }

                if tab == .hosts {
                    Section {
                        if hosts.isEmpty && (otherTotal == 0 || !trimmedQuery.isEmpty) {
                            Text(current.hosts.isEmpty ? L("暂无流量记录") : L("无匹配结果"))
                                .foregroundStyle(.secondary)
                        }
                        ForEach(hosts) { host in
                            Button {
                                selectedHost = host.host
                                tab = .connections
                            } label: {
                                VStack(alignment: .leading, spacing: 6) {
                                    HStack {
                                        Text(host.host).font(.subheadline.monospaced()).foregroundStyle(.primary)
                                            .lineLimit(1).truncationMode(.middle)
                                        Spacer()
                                        Text("\(bytes(host.total)) · \(shareText(host.total, of: totalBytes))")
                                            .font(.subheadline.weight(.medium)).monospacedDigit().foregroundStyle(.primary)
                                    }
                                    shareBar(host.total, of: totalBytes)
                                    HStack(spacing: 6) {
                                        Text(host.rule.isEmpty ? host.chains.joined(separator: " → ") : "\(host.rule) → \(host.chains.joined(separator: " → "))")
                                            .lineLimit(1)
                                        Spacer()
                                        Text("↓ \(bytes(host.download))  ↑ \(bytes(host.upload))").monospacedDigit()
                                    }
                                    .font(.caption).foregroundStyle(.secondary)
                                    Text(host.activeConnections > 0
                                         ? L("活跃 {active} / 共 {total}", ["active": host.activeConnections, "total": Int(clamping: host.totalConnections)])
                                         : L("{count} 个连接", ["count": Int(clamping: host.totalConnections)]))
                                        .font(.caption2).foregroundStyle(.tertiary)
                                }
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }
                        if trimmedQuery.isEmpty && otherTotal > 0 {
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text(L("其他目标")).font(.subheadline)
                                    Spacer()
                                    Text("\(bytes(otherTotal)) · \(shareText(otherTotal, of: totalBytes))")
                                        .font(.subheadline).monospacedDigit()
                                }
                                HStack {
                                    if current.otherConnections > 0 {
                                        Text(L("{count} 个连接", ["count": Int(clamping: current.otherConnections)]))
                                    }
                                    Spacer()
                                    Text("↓ \(bytes(current.otherDownload))  ↑ \(bytes(current.otherUpload))").monospacedDigit()
                                }
                                .font(.caption)
                            }
                            .foregroundStyle(.secondary)
                        }
                    }
                } else {
                    Section {
                        if let selectedHost {
                            HStack {
                                Text(L("目标：{host}", ["host": selectedHost]))
                                    .font(.caption).foregroundStyle(.secondary)
                                Spacer()
                                Button(L("显示全部")) { self.selectedHost = nil }
                                    .font(.caption)
                            }
                        }
                        if !ready {
                            HStack {
                                Spacer()
                                ProgressView()
                                Spacer()
                            }
                        } else if connections.isEmpty {
                            Text(current.connections.isEmpty ? L("暂无流量记录") : L("无匹配结果"))
                                .foregroundStyle(.secondary)
                        }
                        ForEach(connections) { conn in
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text(conn.target).font(.subheadline.monospaced()).lineLimit(1).truncationMode(.middle)
                                    Spacer()
                                    Text(conn.active ? L("活跃") : L("已结束"))
                                        .font(.caption2.weight(.medium))
                                        .foregroundStyle(conn.active ? Color.accentColor : Color.secondary)
                                        .padding(.horizontal, 6).padding(.vertical, 2)
                                        .background((conn.active ? Color.accentColor : Color.secondary).opacity(0.12), in: .capsule)
                                }
                                HStack(spacing: 6) {
                                    Text(conn.network.uppercased())
                                        .font(.caption2.weight(.semibold)).foregroundStyle(.tint)
                                        .padding(.horizontal, 5).padding(.vertical, 1)
                                        .background(.tint.opacity(0.12), in: .capsule)
                                    Text(conn.chains.joined(separator: " → ")).lineLimit(1)
                                    Spacer()
                                    Text(bytes(conn.total)).fontWeight(.medium).monospacedDigit()
                                }
                                .font(.caption).foregroundStyle(.secondary)
                                Text("↓ \(bytes(conn.download))  ↑ \(bytes(conn.upload))")
                                    .font(.caption2).foregroundStyle(.tertiary).monospacedDigit()
                            }
                            .swipeActions {
                                if conn.active {
                                    Button(L("关闭"), role: .destructive) {
                                        Task {
                                            requestSeq += 1
                                            await model.closeConnection(conn.id)
                                            await refresh(host: activeHost)
                                        }
                                    }
                                }
                            }
                        }
                    } footer: {
                        if ready, let note = scopeNote(for: current) {
                            Text(note)
                        }
                    }
                }
            } else {
                Section {
                    HStack {
                        Spacer()
                        ProgressView()
                        Spacer()
                    }
                }
            }
        }
        .searchable(text: $query, prompt: L("搜索目标、规则或代理"))
        .navigationTitle(L("流量详情"))
        .navigationBarTitleDisplayMode(.inline)
        .task(id: PollKey(connected: model.connected, active: scenePhase == .active, host: activeHost)) {
            guard model.connected else {
                requestSeq += 1
                details = nil
                failure = nil
                return
            }
            guard scenePhase == .active else { return }
            while !Task.isCancelled {
                await refresh(host: activeHost)
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    private static func sameHost(_ a: String?, _ b: String?) -> Bool {
        switch (a, b) {
        case (nil, nil): true
        case let (a?, b?): TrafficDetails.normalizeHost(a) == TrafficDetails.normalizeHost(b)
        default: false
        }
    }

    @MainActor
    private func refresh(host: String?) async {
        requestSeq += 1
        let seq = requestSeq
        do {
            let next = try await model.fetchTrafficDetails(host: host)
            guard !Task.isCancelled, seq == requestSeq, Self.sameHost(host, activeHost) else { return }
            details = next
            failure = nil
        } catch {
            guard !Task.isCancelled, seq == requestSeq, Self.sameHost(host, activeHost) else { return }
            failure = error.localizedDescription
        }
    }

    private func hostsSummaryFooter(for current: TrafficDetails) -> String? {
        guard current.since > 0 else { return nil }
        let sinceText = Date(timeIntervalSince1970: TimeInterval(current.since))
            .formatted(date: .abbreviated, time: .shortened)
        if current.hostsEvicted == true {
            return L("自 {since} 起，当前保留 {hosts} 个主要目标（其余归入「其他目标」）", ["since": sinceText, "hosts": current.totalHosts])
        }
        return L("自 {since} 起，共统计 {hosts} 个目标", ["since": sinceText, "hosts": current.totalHosts])
    }

    private func scopeNote(for current: TrafficDetails) -> String? {
        let returnedActive = current.connections.filter(\.active).count
        let returnedClosed = current.connections.filter { !$0.active }.count
        let matchingActive = current.matchingActiveConnections ?? returnedActive
        let matchingClosed = Int(clamping: current.matchingClosedConnections ?? UInt64(returnedClosed))
        var parts: [String] = []
        if matchingActive > returnedActive {
            parts.append(L("活跃连接按流量显示前 {shown} / {total} 条", ["shown": returnedActive, "total": matchingActive]))
        }
        if matchingClosed > returnedClosed {
            parts.append(L("已结束连接仅保留高流量记录，显示 {shown} / {total} 条", ["shown": returnedClosed, "total": matchingClosed]))
        }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    private func bytes(_ value: UInt64) -> String {
        Int64(clamping: value).formatted(.byteCount(style: .binary, spellsOutZero: false))
    }

    private func shareText(_ part: UInt64, of total: UInt64) -> String {
        guard total > 0, part > 0 else { return "0%" }
        let pct = Double(part) / Double(total) * 100
        return pct < 0.1 ? "<0.1%" : String(format: "%.1f%%", pct)
    }

    private func shareBar(_ part: UInt64, of total: UInt64) -> some View {
        let ratio = total > 0 && part > 0 ? min(1.0, max(0.02, Double(part) / Double(total))) : 0
        return GeometryReader { proxy in
            ZStack(alignment: .leading) {
                Capsule().fill(Color.secondary.opacity(0.15))
                Capsule().fill(Color.accentColor).frame(width: proxy.size.width * ratio)
            }
        }
        .frame(height: 4)
    }
}
