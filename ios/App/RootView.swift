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
            LogView().tabItem { Label("日志", systemImage: "doc.text.magnifyingglass") }
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
    @State private var detail: Profile?
    var body: some View {
        NavigationStack {
            List {
                Section {
                    NavigationLink {
                        RulesView(model: model)
                    } label: {
                        LabeledContent {
                            Text("\(model.customRules.count)")
                        } label: {
                            Label("自定义规则", systemImage: "list.bullet.indent")
                        }
                    }
                    NavigationLink {
                        OverridesView(model: model)
                    } label: {
                        LabeledContent {
                            Text(model.overrides.isEmpty ? "跟随配置" : "已修改")
                        } label: {
                            Label("覆盖配置文件", systemImage: "slider.horizontal.3")
                        }
                    }
                } footer: {
                    Text("对所有配置生效，优先于配置文件自身的规则和设置")
                }
                if model.profiles.isEmpty {
                    ContentUnavailableView("还没有配置", systemImage: "doc.badge.plus",
                                           description: Text("点右上角 + 导入 Clash YAML 文件或链接"))
                }
                ForEach(model.profiles) { profile in
                    HStack(spacing: 12) {
                        Button {
                            model.selectedID = profile.id
                        } label: {
                            HStack {
                                Image(systemName: "checkmark").foregroundStyle(.tint)
                                    .opacity(model.selectedID == profile.id ? 1 : 0)
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(profile.name).foregroundStyle(.primary)
                                    Text("\(profile.sourceHost ?? "本地文件") · \(profile.createdAt.formatted(date: .abbreviated, time: .omitted))")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                            }
                            .contentShape(.rect)
                        }
                        .buttonStyle(.plain)
                        .disabled(model.active || model.busy)
                        // Viewing details stays available while connected.
                        Button { detail = profile } label: {
                            Image(systemName: "info.circle").imageScale(.large)
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("\(profile.name) 详情")
                    }
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
            .navigationDestination(item: $detail) { ProfileDetailView(model: model, id: $0.id) }
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
                if model.groups.isEmpty && model.ungrouped.isEmpty {
                    ContentUnavailableView(model.connected ? "没有节点" : "未连接", systemImage: "network",
                        description: Text(model.connected ? "当前配置未定义节点" : "连接后可选择节点"))
                }
                ForEach(model.groups) { group in
                    Section(group.name) {
                        ForEach(group.nodes, id: \.self) { node in
                            NodeRow(model: model, name: node, selected: group.selected == node) {
                                Task { await model.select(group: group.name, node: node) }
                            }
                        }
                    }
                }
                if !model.ungrouped.isEmpty {
                    Section {
                        ForEach(model.ungrouped, id: \.self) { node in
                            NodeRow(model: model, name: node, selected: false, select: nil)
                        }
                    } header: { Text("其他节点") } footer: { Text("未放入代理组，由规则直接使用") }
                }
            }
            .navigationTitle("节点")
            .toolbar {
                if model.connected && model.nodeStatus.values.contains(where: { $0.type == "VLESS" }) {
                    Button("测速", systemImage: "bolt") { Task { await model.probeAll() } }
                        .disabled(!model.probing.isEmpty)
                }
            }
            .navigationDestination(for: String.self) { NodeDetailView(model: model, name: $0) }
        }
    }
}

private struct NodeRow: View {
    @Bindable var model: AppModel
    let name: String
    let selected: Bool
    let select: (() -> Void)?
    var body: some View {
        HStack(spacing: 12) {
            Button {
                select?()
            } label: {
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(name).foregroundStyle(.primary)
                        if let status = model.nodeStatus[name] {
                            Text(status.summary).font(.caption).foregroundStyle(tone(status))
                        }
                    }
                    Spacer()
                    if model.probing.contains(name) { ProgressView().controlSize(.small) }
                    Image(systemName: "checkmark").foregroundStyle(.tint).opacity(selected ? 1 : 0)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.borderless)
            .disabled(select == nil || model.busy || !model.connected)
            if model.nodeStatus[name] != nil {
                NavigationLink(value: name) {
                    Image(systemName: "info.circle").foregroundStyle(.tint)
                }
                .fixedSize()
                .accessibilityLabel("\(name) 状态")
            }
        }
    }
    private func tone(_ status: NodeStatus) -> Color {
        if let tailscale = status.tailscale { return tailscale.state == "error" ? .red : .secondary }
        if status.delay == nil && status.error != nil { return .red }
        return .secondary
    }
}

private struct NodeDetailView: View {
    @Bindable var model: AppModel
    let name: String
    var body: some View {
        List {
            if let status = model.nodeStatus[name] {
                Section {
                    LabeledContent("类型", value: status.type)
                    LabeledContent("当前连接", value: "\(status.connections)")
                    if let server = status.server { LabeledContent("服务器", value: server) }
                    if let network = status.network { LabeledContent("传输", value: network) }
                    if let security = status.security { LabeledContent("安全", value: security.uppercased()) }
                    if let flow = status.flow { LabeledContent("Flow", value: flow) }
                    if let udp = status.udp { LabeledContent("UDP", value: udp ? "开启" : "关闭") }
                }
                if status.type == "VLESS" {
                    Section("延迟") {
                        if let delay = status.delay {
                            LabeledContent("最近一次", value: "\(delay) ms")
                        } else if let error = status.error {
                            Text(error).font(.footnote).foregroundStyle(.red)
                        } else {
                            Text("尚未测速").foregroundStyle(.secondary)
                        }
                        if let checked = status.checkedAt {
                            LabeledContent("测试时间", value: checked.formatted(date: .omitted, time: .standard))
                        }
                        Button(model.probing.contains(name) ? "测速中…" : "测速") { Task { await model.probe(name) } }
                            .disabled(model.probing.contains(name) || !model.connected)
                    }
                }
                if let tailscale = status.tailscale { TailscaleSections(status: tailscale) }
            } else {
                ContentUnavailableView("没有状态", systemImage: "questionmark.circle", description: Text("连接后显示节点状态"))
            }
        }
        .navigationTitle(name)
        .navigationBarTitleDisplayMode(.inline)
        .refreshable { await model.refreshSnapshot() }
    }
}

private struct TailscaleSections: View {
    let status: TailscaleStatus
    var body: some View {
        Section("Tailscale") {
            LabeledContent("状态", value: status.stateText)
            if let error = status.error { Text(error).font(.footnote).foregroundStyle(.red) }
            if let name = status.name { LabeledContent("本机名称", value: name) }
            ForEach(status.addresses, id: \.self) { LabeledContent("地址", value: $0) }
            if let derp = status.homeDerp { LabeledContent("DERP 主区域", value: derp) }
            LabeledContent("公网候选", value: status.endpoints.isEmpty ? "无" : status.endpoints.joined(separator: "\n"))
        }
        Section("节点（\(status.onlinePeers)/\(status.peers.count) 在线）") {
            ForEach(status.peers) { peer in
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Circle().fill(peer.online == true ? Color.connected : Color.secondary.opacity(0.4)).frame(width: 8, height: 8)
                        Text(peer.name)
                        if peer.exitNode { Text("出口").font(.caption2).padding(.horizontal, 5).background(.tint.opacity(0.15), in: .capsule) }
                        Spacer()
                        Text(peer.pathText).font(.caption).foregroundStyle(peer.path == "direct" ? Color.connected : .secondary)
                    }
                    Text([peer.address, peer.os, peer.direct].compactMap { $0 }.joined(separator: " · "))
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }
}
