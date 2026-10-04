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
                VStack(spacing: 24) {
                    HStack(spacing: 12) {
                        Image("Brand").resizable().frame(width: 48, height: 48)
                            .clipShape(.rect(cornerRadius: 14)).accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Clyntis").font(.title2.bold())
                            Text("连接更自由").font(.subheadline).foregroundStyle(.secondary)
                        }
                        Spacer()
                    }
                    VStack(spacing: 18) {
                        Label(model.statusText, systemImage: model.connected ? "checkmark.shield.fill" : "shield")
                            .font(.headline).foregroundStyle(model.connected ? Color.green : Color.secondary)
                        Button {
                            Task { await model.toggleConnection() }
                        } label: {
                            Image(systemName: "power").font(.system(size: 44, weight: .medium))
                                .frame(width: 112, height: 112).background(.tint.opacity(0.1), in: Circle())
                        }
                        .disabled(model.busy || (!model.active && model.selected == nil))
                        .accessibilityLabel(model.active ? "断开 VPN" : "连接 VPN")
                        Text(model.selected?.name ?? "先添加一个配置，开始连接")
                            .font(.subheadline).foregroundStyle(.secondary).multilineTextAlignment(.center)
                        if model.busy { ProgressView() }
                    }
                    .frame(maxWidth: .infinity).padding(28)
                    .background(.background, in: .rect(cornerRadius: 24))
                    HStack {
                        TrafficStat(title: "累计上传", value: Int64(clamping: model.upload).formatted(.byteCount(style: .binary, spellsOutZero: false)))
                        TrafficStat(title: "累计下载", value: Int64(clamping: model.download).formatted(.byteCount(style: .binary, spellsOutZero: false)))
                        TrafficStat(title: "连接数", value: "\(model.connectionCount)")
                    }
                    VStack(alignment: .leading, spacing: 12) {
                        Text("路由模式").font(.headline)
                        Picker("路由模式", selection: Binding(get: { model.mode }, set: { value in
                            Task { await model.setMode(value) }
                        })) {
                            Text("规则").tag("rule")
                            Text("全局").tag("global")
                            Text("直连").tag("direct")
                        }.pickerStyle(.segmented).disabled(!model.connected || model.busy)
                    }
                    Label("配置保存在本机，连接由系统 VPN 管理。", systemImage: "lock.shield")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                .padding(20).frame(maxWidth: 620).frame(maxWidth: .infinity)
            }
            .background(Color(.systemGroupedBackground)).navigationTitle("连接")
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
        .padding(14).background(.background, in: .rect(cornerRadius: 16))
    }
}

private struct ProfilesView: View {
    @Bindable var model: AppModel
    @State private var importing = false
    @State private var importingLink = false
    var body: some View {
        NavigationStack {
            List {
                if model.profiles.isEmpty {
                    ContentUnavailableView("从一个配置开始", systemImage: "doc.badge.plus",
                                           description: Text("导入兼容的 Clash YAML 配置。"))
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
                            Image(systemName: "checkmark.circle.fill").opacity(model.selectedID == profile.id ? 1 : 0)
                        }
                    }
                    .disabled(model.active || model.busy)
                    .swipeActions {
                        Button("删除", role: .destructive) { model.remove(profile) }.disabled(model.active || model.busy)
                    }
                }
                Section {
                    Text("连接期间不能切换或删除配置。新的配置导入后不会自动重连。")
                        .font(.footnote).foregroundStyle(.secondary)
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
        }
    }
}

private struct NodesView: View {
    @Bindable var model: AppModel
    var body: some View {
        NavigationStack {
            List {
                if model.groups.isEmpty {
                    ContentUnavailableView("暂无可选节点", systemImage: "network",
                        description: Text(model.connected ? "当前配置没有代理组。" : "连接后可查看代理组并选择节点。"))
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
                                    Image(systemName: "checkmark").opacity(group.selected == node ? 1 : 0)
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
