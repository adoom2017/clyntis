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
                                if model.busy || model.startPending || (model.active && !model.connected) {
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
                        .disabled(model.busy || model.startPending || (!model.active && model.selected == nil))
                        .accessibilityLabel(model.active ? "断开 VPN" : "连接 VPN")
                        .sensoryFeedback(.impact, trigger: model.connected)
                        VStack(spacing: 4) {
                            Text(model.statusText).font(.title3.weight(.semibold))
                                .foregroundStyle(model.connected ? Color.connected : Color.primary)
                            Text(model.phase ?? (model.startPending ? "正在等待系统启动 VPN…" : nil)
                                 ?? model.selected?.name ?? "未选择配置")
                                .font(.subheadline).foregroundStyle(.secondary)
                        }
                    }
                    .frame(maxWidth: .infinity).padding(.vertical, 32)
                    .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 20))
                    HStack(spacing: 12) {
                        TrafficStat(title: "上传", value: Int64(clamping: model.upload).formatted(.byteCount(style: .binary, spellsOutZero: false)))
                        TrafficStat(title: "下载", value: Int64(clamping: model.download).formatted(.byteCount(style: .binary, spellsOutZero: false)))
                        NavigationLink { ConnectionsView(model: model) } label: {
                            TrafficStat(title: "连接", value: "\(model.connectionCount)", disclosure: true)
                        }
                        .buttonStyle(.plain)
                    }
                    if model.connected {
                        NavigationLink { AdblockView(model: model) } label: {
                            HStack {
                                Label("去广告", systemImage: "nosign").foregroundStyle(.secondary)
                                Spacer()
                                Text(model.adblockSummary).monospacedDigit()
                                Image(systemName: "chevron.right").imageScale(.small).foregroundStyle(.tertiary)
                            }
                            .font(.subheadline)
                            .padding(14)
                            .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 14))
                        }
                        .buttonStyle(.plain)
                    }
                    if model.connected, let networks = model.currentNetworks {
                        HStack {
                            Label("当前网络", systemImage: "wifi").foregroundStyle(.secondary)
                            Spacer()
                            Text(networks.isEmpty ? "未匹配" : networks.joined(separator: "、"))
                        }
                        .font(.subheadline)
                        .padding(14)
                        .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 14))
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
    var disclosure = false
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 2) {
                Text(title)
                if disclosure { Image(systemName: "chevron.right").imageScale(.small) }
            }
            .font(.caption).foregroundStyle(.secondary)
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
    @State private var publishing: Profile?
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
                    NavigationLink {
                        AdblockView(model: model)
                    } label: {
                        LabeledContent {
                            Text(model.overrides.adblock?.enabled == true ? "已开启" : "未开启")
                        } label: {
                            Label("去广告", systemImage: "nosign")
                        }
                    }
                } footer: {
                    Text("对所有配置生效，优先于配置文件自身的规则和设置")
                }
                Section {
                    NavigationLink {
                        CosSettingsView()
                    } label: {
                        Label("远程发布", systemImage: "icloud.and.arrow.up")
                    }
                } footer: {
                    Text("「发布」把加密后的配置上传到腾讯云 COS")
                }
                Section {
                    Toggle(isOn: Binding(get: { model.autoReconnect },
                                         set: { enabled in Task { await model.setAutoReconnect(enabled) } })) {
                        Label("断开后自动重连", systemImage: "arrow.clockwise.circle")
                    }
                } footer: {
                    Text("VPN 意外断开（异常退出、被系统结束、网络恢复或重启手机）后由系统自动重新连接。"
                         + "在 App 里断开不会触发；在系统设置里关闭 VPN 时，系统通常也会暂停自动重连。")
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
                        Button("发布", systemImage: "icloud.and.arrow.up") { publishing = profile }.tint(.blue)
                    }
                    .contextMenu {
                        Button("加密导出", systemImage: "lock.doc") { exporting = profile }
                        Button("发布到 COS", systemImage: "icloud.and.arrow.up") { publishing = profile }
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
            .sheet(item: $publishing) { CosPublishView(model: model, profile: $0) }
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
    /// Groups switch, proxies are probed; remembered across launches.
    @AppStorage("nodes-view") private var view = "groups"
    private func isPolicy(_ name: String) -> Bool {
        BuiltinOutbound(name) != nil || model.groups.contains { $0.name == name }
    }
    private var shown: String { model.groups.isEmpty ? "proxies" : view }
    var body: some View {
        NavigationStack {
            List {
                if !model.groups.isEmpty {
                    Picker("视图", selection: $view) {
                        Text("代理组 \(model.groups.count)").tag("groups")
                        Text("节点 \(model.proxies.count)").tag("proxies")
                    }
                    .pickerStyle(.segmented)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets())
                }
                if model.groups.isEmpty && model.proxies.isEmpty {
                    ContentUnavailableView(model.connected ? "没有节点" : "未连接", systemImage: "network",
                        description: Text(model.connected ? "当前配置未定义节点" : "连接后可选择节点"))
                } else if shown == "groups" {
                    groupSections
                } else {
                    Section {
                        ForEach(model.proxies, id: \.self) { ProxyRow(model: model, name: $0) }
                    } footer: {
                        Text("点按节点测试延迟。")
                    }
                }
            }
            .navigationTitle("节点")
            .toolbar {
                if shown == "proxies" && model.connected
                    && model.nodeStatus.values.contains(where: \.probeable) {
                    Button("测速", systemImage: "bolt") { Task { await model.probeAll() } }
                        .disabled(!model.probing.isEmpty)
                }
            }
            .navigationDestination(for: String.self) { NodeDetailView(model: model, name: $0) }
        }
    }

    @ViewBuilder private var groupSections: some View {
        ForEach(model.groups) { group in
            // Groups and built-in outbounds route traffic; proxies carry it.
            let policies = group.nodes.filter(isPolicy)
            let proxies = group.nodes.filter { !isPolicy($0) }
            Section {
                if !policies.isEmpty && !proxies.isEmpty { MemberLabel(title: "策略", count: policies.count) }
                ForEach(policies, id: \.self) { node in
                    PolicyRow(model: model, name: node, group: model.groups.first { $0.name == node },
                              selected: group.selected == node) {
                        Task { await model.select(group: group.name, node: node) }
                    }
                }
                if !policies.isEmpty && !proxies.isEmpty { MemberLabel(title: "节点", count: proxies.count) }
                ForEach(proxies, id: \.self) { node in
                    MemberRow(model: model, name: node, selected: group.selected == node) {
                        Task { await model.select(group: group.name, node: node) }
                    }
                }
            } header: {
                HStack {
                    Text(group.name)
                    Spacer()
                    Text(group.typeText)
                }
            }
        }
    }
}

private struct MemberLabel: View {
    let title: String
    let count: Int
    var body: some View {
        Text("\(title) \(count)")
            .font(.caption.weight(.medium))
            .foregroundStyle(.secondary)
            .listRowSeparator(.hidden)
            .listRowInsets(EdgeInsets(top: 10, leading: 20, bottom: 2, trailing: 20))
    }
}

/// Another group or a built-in outbound inside a group: icon, what it does,
/// and no delay or server details.
private struct PolicyRow: View {
    @Bindable var model: AppModel
    let name: String
    let group: ProxyGroup?
    let selected: Bool
    let select: () -> Void
    var body: some View {
        let builtin = BuiltinOutbound(name)
        Button(action: select) {
            HStack(spacing: 12) {
                Image(systemName: group != nil ? "square.stack.3d.up" : builtin == .reject ? "nosign" : "arrow.right")
                    .foregroundStyle(builtin == .reject ? Color.red : Color.accentColor)
                    .frame(width: 22)
                VStack(alignment: .leading, spacing: 3) {
                    Text(name).foregroundStyle(.primary)
                    Text(detail(builtin)).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "checkmark").foregroundStyle(.tint).opacity(selected ? 1 : 0)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .disabled(model.busy || !model.connected)
    }
    private func detail(_ builtin: BuiltinOutbound?) -> String {
        if let group {
            return ["代理组", group.typeText, group.selected.map { "当前 \($0)" }]
                .compactMap { $0 }.joined(separator: " · ")
        }
        return builtin == .reject ? "拒绝连接" : "直连，不经过代理"
    }
}

/// A proxy inside a group: tapping switches to it; probing lives on the
/// proxies view.
private struct MemberRow: View {
    @Bindable var model: AppModel
    let name: String
    let selected: Bool
    let select: () -> Void
    var body: some View {
        Button(action: select) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text(name).foregroundStyle(.primary)
                    if let status = model.nodeStatus[name] {
                        Text(status.summary).font(.caption).foregroundStyle(NodeTone.summary(status))
                    }
                }
                Spacer()
                Image(systemName: "checkmark").foregroundStyle(.tint).opacity(selected ? 1 : 0)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .disabled(model.busy || !model.connected)
    }
}

/// A proxy server: tapping probes it, and its delay and details show.
private struct ProxyRow: View {
    @Bindable var model: AppModel
    let name: String
    var body: some View {
        let status = model.nodeStatus[name]
        HStack(spacing: 12) {
            Button {
                Task { await model.probe(name) }
            } label: {
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(name).foregroundStyle(.primary)
                        if let status {
                            Text(status.summary).font(.caption).foregroundStyle(NodeTone.summary(status))
                        }
                    }
                    Spacer()
                    if model.probing.contains(name) {
                        ProgressView().controlSize(.small)
                    } else if let status, let delay = status.delayText {
                        Text(delay).font(.caption.monospacedDigit()).foregroundStyle(NodeTone.delay(status))
                    }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.borderless)
            .disabled(status?.probeable != true || !model.connected || model.probing.contains(name))
            .accessibilityHint("测试延迟")
            if status != nil {
                NavigationLink(value: name) {
                    Image(systemName: "info.circle").foregroundStyle(.tint)
                }
                .fixedSize()
                .accessibilityLabel("\(name) 状态")
            }
        }
    }
}

private enum NodeTone {
    static func summary(_ status: NodeStatus) -> Color {
        if let tailscale = status.tailscale { return tailscale.state == "error" ? .red : .secondary }
        return .secondary
    }
    /// The desktop's tiers: under 150 ms good, under 300 ms fair, else slow.
    static func delay(_ status: NodeStatus) -> Color {
        guard let delay = status.delay else { return .red }
        return delay < 150 ? .green : delay < 300 ? .orange : .red
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
                if status.probeable {
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
