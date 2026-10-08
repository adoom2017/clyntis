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
    let upload: Int64
    let download: Int64
    /// Unix seconds, as a string.
    let start: String

    var target: String {
        metadata.host.contains(":") ? "[\(metadata.host)]:\(metadata.port)" : "\(metadata.host):\(metadata.port)"
    }
    var started: Date? { Double(start).map(Date.init(timeIntervalSince1970:)) }

    static func decode(_ object: Any?) -> [ConnectionInfo] {
        guard let object, let data = try? JSONSerialization.data(withJSONObject: object),
              let list = try? JSONDecoder().decode([ConnectionInfo].self, from: data) else { return [] }
        return list.sorted { ($0.started ?? .distantPast) > ($1.started ?? .distantPast) }
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
                ContentUnavailableView(model.connected ? "没有连接" : "未连接", systemImage: "arrow.left.arrow.right",
                                       description: Text(model.connected ? "当前没有打开的连接" : "连接后显示网络连接"))
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
                    Button("关闭", role: .destructive) { Task { await model.closeConnection(connection.id) } }
                }
            }
        }
        .searchable(text: $query, prompt: "搜索目标或代理链")
        .navigationTitle("连接（\(model.connections.count)）")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if !model.connections.isEmpty {
                Button("全部关闭", systemImage: "xmark.circle") { confirmCloseAll = true }
            }
        }
        .confirmationDialog("关闭全部 \(model.connections.count) 个连接？", isPresented: $confirmCloseAll, titleVisibility: .visible) {
            Button("全部关闭", role: .destructive) { Task { await model.closeConnection(nil) } }
        }
    }

    private func bytes(_ value: Int64) -> String {
        value.formatted(.byteCount(style: .binary, spellsOutZero: false))
    }
}
