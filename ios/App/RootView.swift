import SwiftUI
import UniformTypeIdentifiers

struct RootView: View {
    @Bindable var model: AppModel
    @Environment(\.scenePhase) private var scenePhase
    var body: some View {
        TabView {
            ConnectionView(model: model).tabItem { Label("连接", systemImage: "network") }
            ProfilesView(model: model).tabItem { Label("配置", systemImage: "square.stack.3d.up") }
            NodesView(model: model).tabItem { Label("节点", systemImage: "point.3.connected.trianglepath.dotted") }
        }
        .alert("Clyntis", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
            Button("知道了") { model.error = nil }
        } message: { Text(model.error ?? "") }
        .task(id: scenePhase) {
            guard scenePhase == .active else { return }
            while !Task.isCancelled {
                await model.refreshSnapshot()
                do { try await Task.sleep(for: .seconds(2)) } catch { break }
            }
        }
    }
}

private struct ConnectionView: View {
    @Bindable var model: AppModel
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    VStack(spacing: 20) {
                        Button {
                            Task { await model.toggleConnection() }
                        } label: {
                            ZStack {
                                Circle().fill(model.connected ? Color.brand : Color(.tertiarySystemFill))
                                if model.busy || (model.active && !model.connected) {
                                    ProgressView().controlSize(.large)
                                        .tint(model.connected ? .white : .secondary)
                                } else {
                                    Image(systemName: "power").font(.system(size: 40, weight: .medium))
                                        .foregroundStyle(model.connected ? Color.white : Color.secondary)
                                }
                            }
                            .frame(width: 104, height: 104)
                        }
                        .buttonStyle(.plain)
                        .disabled(model.busy || (!model.active && model.selected == nil))
                        .accessibilityLabel(model.active ? "断开 VPN" : "连接 VPN")
                        .sensoryFeedback(.impact, trigger: model.connected)
                        VStack(spacing: 4) {
                            Text(model.statusText).font(.title3.weight(.semibold))
                                .foregroundStyle(model.connected ? Color.connected : Color.primary)
                            Text(model.phase ?? model.selected?.name ?? "未选择配置")
                                .font(.subheadline).foregroundStyle(.secondary)
                        }
                    }
                    .frame(maxWidth: .infinity).padding(.vertical, 32)
                    .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 20))
                    HStack(spacing: 12) {
                        TrafficStat(title: "上传", value: Int64(clamping: model.upload).formatted(.byteCount(style: .binary, spellsOutZero: false)))
                        TrafficStat(title: "下载", value: Int64(clamping: model.download).formatted(.byteCount(style: .binary, spellsOutZero: false)))
                        TrafficStat(title: "连接", value: "\(model.connectionCount)")
                    }
                    VStack(alignment: .leading, spacing: 10) {
                        Text("路由模式").font(.subheadline).foregroundStyle(.secondary)
                        Picker("路由模式", selection: Binding(get: { model.mode }, set: { value in
                            Task { await model.setMode(value) }
                        })) {
                            Text("规则").tag("rule")
                            Text("全局").tag("global")
                            Text("直连").tag("direct")
                        }.pickerStyle(.segmented).disabled(!model.connected || model.busy)
                    }
                    .padding(.top, 4)
                }
                .padding(20).frame(maxWidth: 620).frame(maxWidth: .infinity)
            }
            .background(Color(.systemGroupedBackground)).navigationTitle("Clyntis")
        }
    }
}

private struct TrafficStat: View {
    let title: String
    let value: String
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.headline).monospacedDigit()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14).background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 14))
    }
}

private struct ProfilesView: View {
    @Bindable var model: AppModel
    @State private var importing = false
    @State private var importingLink = false
    @State private var exporting: Profile?
    var body: some View {
        NavigationStack {
            List {
                if model.profiles.isEmpty {
                    ContentUnavailableView("还没有配置", systemImage: "doc.badge.plus",
                                           description: Text("点右上角 + 导入 Clash YAML 文件或链接"))
                }
                ForEach(model.profiles) { profile in
                    Button {
                        model.selectedID = profile.id
                    } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 6) {
                                Text(profile.name).foregroundStyle(.primary)
                                Text(profile.createdAt, style: .date).font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Image(systemName: "checkmark").foregroundStyle(.tint).opacity(model.selectedID == profile.id ? 1 : 0)
                        }
                    }
                    .disabled(model.active || model.busy)
                    .swipeActions {
                        Button("删除", role: .destructive) { model.remove(profile) }.disabled(model.active || model.busy)
                        Button("加密导出", systemImage: "lock.doc") { exporting = profile }.tint(.brand)
                    }
                    .contextMenu {
                        Button("加密导出", systemImage: "lock.doc") { exporting = profile }
                    }
                }
                if model.active && !model.profiles.isEmpty {
                    Section { } footer: { Text("断开后才能切换或删除配置") }
                }
            }
            .navigationTitle("配置")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu("导入", systemImage: "plus") {
                        Button("从文件导入", systemImage: "doc") { importing = true }
                        Button("从链接导入", systemImage: "link") { importingLink = true }
                    }.disabled(model.busy)
                }
            }
            .fileImporter(isPresented: $importing,
                          allowedContentTypes: [.yaml, .plainText, .json], allowsMultipleSelection: false) { result in
                switch result {
                case .success(let urls):
                    if let url = urls.first { Task { await model.importFile(url) } }
                case .failure(let error): model.error = error.localizedDescription
                }
            }
            .sheet(isPresented: $importingLink) { RemoteImportView(model: model) }
            .sheet(item: $exporting) { EncryptedExportView(model: model, profile: $0) }
            .sheet(isPresented: Binding(get: { model.pendingEncryptedImport != nil },
                                        set: { if !$0 { model.pendingEncryptedImport = nil } })) {
                ConfigPasswordView(title: "导入加密配置", message: "此文件已加密，输入密码后导入。",
                                   actionTitle: "导入") { password in
                    try await model.importEncrypted(password: password)
                }
            }
        }
    }
}

private struct NodesView: View {
    @Bindable var model: AppModel
    var body: some View {
        NavigationStack {
            List {
                if model.groups.isEmpty {
                    ContentUnavailableView(model.connected ? "没有代理组" : "未连接", systemImage: "network",
                        description: Text(model.connected ? "当前配置未定义代理组" : "连接后可选择节点"))
                }
                ForEach(model.groups) { group in
                    Section(group.name) {
                        ForEach(group.nodes, id: \.self) { node in
                            Button {
                                Task { await model.select(group: group.name, node: node) }
                            } label: {
                                HStack {
                                    Text(node).foregroundStyle(.primary)
                                    Spacer()
                                    Image(systemName: "checkmark").foregroundStyle(.tint).opacity(group.selected == node ? 1 : 0)
                                }
                            }.disabled(model.busy || !model.connected)
                        }
                    }
                }
            }
            .navigationTitle("节点")
        }
    }
}
