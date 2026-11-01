import SwiftUI

/// Ad blocking state from the core snapshot (`adblock`).
struct AdblockStatus: Decodable, Equatable {
    struct ListInfo: Decodable, Equatable {
        let name: String
        let entries: Int
        let updated: Double?
        let error: String?
    }
    struct Top: Decodable, Equatable, Identifiable {
        var id: String { domain }
        let domain: String
        let count: Int
    }
    struct Blocked: Decodable, Equatable {
        let time: Double
        let domain: String
        let via: String
    }
    let enabled: Bool
    let entries: Int
    let since: Double
    let total: Int
    let dns: Int
    let connections: Int
    let domains: Int
    let lists: [ListInfo]
    let top: [Top]
    let recent: [Blocked]

    static func decode(_ object: Any?) -> AdblockStatus? {
        guard let object, let data = try? JSONSerialization.data(withJSONObject: object) else { return nil }
        return try? JSONDecoder().decode(AdblockStatus.self, from: data)
    }
}

/// Settings and statistics for domain-level ad blocking.
struct AdblockView: View {
    @Bindable var model: AppModel
    @State private var failure: String?
    @State private var allowFailure: String?
    @State private var needsReconnect = false
    @State private var addingList = false
    @State private var newAllow = ""

    private var settings: AdblockSettings? { model.overrides.adblock }

    var body: some View {
        List {
            // Settings first; statistics and recent blocks below them.
            Section {
                Toggle(L("启用去广告"), isOn: Binding(get: { settings?.enabled ?? false }, set: { on in
                    var next = settings ?? AdblockSettings()
                    next.enabled = on
                    save(next)
                }))
            } footer: {
                Text(L("广告、追踪和统计域名在 DNS 查询时直接拒绝，并优先于所有规则。"))
            }
            if let settings, settings.enabled {
                Section(L("列表")) {
                    ForEach(AdblockSettings.presetsOffered, id: \.id) { preset in
                        Toggle(isOn: Binding(get: { settings.presets.contains(preset.id) }, set: { on in
                            var next = settings
                            next.presets = on ? next.presets + [preset.id] : next.presets.filter { $0 != preset.id }
                            save(next)
                        })) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(preset.name)
                                Text(listLine(preset.name) ?? preset.detail).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    ForEach(settings.custom, id: \.self) { list in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(list.name)
                            Text(listLine(list.name) ?? list.url).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        }
                        .swipeActions {
                            Button(L("移除"), role: .destructive) {
                                var next = settings
                                next.custom.removeAll { $0 == list }
                                save(next)
                            }
                        }
                    }
                    Button(L("添加列表"), systemImage: "plus") { addingList = true }
                }
                Section {
                    Toggle(isOn: Binding(get: { settings.blockHttpdns ?? true }, set: { on in
                        var next = settings
                        next.blockHttpdns = on
                        save(next)
                    })) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(L("拦截 HTTPDNS 和加密 DNS"))
                            Text(L("App 自带的 HTTPDNS、DoH 会绕过 DNS 过滤，拦截后退回系统 DNS"))
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    Toggle(isOn: Binding(get: { settings.quicFallback ?? true }, set: { on in
                        var next = settings
                        next.quicFallback = on
                        save(next)
                    })) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(L("QUIC 回退到 TCP"))
                            Text(L("拒绝不知道域名的 QUIC，App 改用 TCP 后即可按域名拦截"))
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    Picker(L("拦截应答"), selection: Binding(get: { settings.dnsAnswer ?? "nxdomain" }, set: { answer in
                        var next = settings
                        next.dnsAnswer = answer
                        save(next)
                    })) {
                        Text(L("域名不存在")).tag("nxdomain")
                        Text("0.0.0.0").tag("null")
                    }
                } header: {
                    Text(L("防绕过"))
                } footer: {
                    Text(L("个别 App 收到「域名不存在」会反复重试，可把拦截应答改为 0.0.0.0。"))
                }
                Section {
                    ForEach(settings.allow, id: \.self) { domain in
                        Text(domain).font(.body.monospaced())
                            .swipeActions {
                                Button(L("删除"), role: .destructive) {
                                    var next = settings
                                    next.allow.removeAll { $0 == domain }
                                    save(next)
                                }
                            }
                    }
                    HStack {
                        TextField(L("添加域名，如 wechat.com"), text: $newAllow)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            .onSubmit(addAllow)
                        Button(L("添加"), action: addAllow).disabled(newAllow.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                } header: { Text(L("白名单")) } footer: { Text(L("包含子域名；修改后立即生效。")) }
            }
            if needsReconnect && model.active && !(model.adblockState == .pending && model.connected) {
                Section {
                    Button(L("重新连接以生效")) {
                        Task { await model.reconnect(); needsReconnect = false }
                    }
                    .disabled(model.busy)
                } footer: { Text(L("开关和列表的修改需要重新连接。")) }
            }
            if let failure { Section { Text(failure).foregroundStyle(.red) } }
            statusSection
        }
        .navigationTitle(L("去广告"))
        .alert(L("无法放行"), isPresented: Binding(get: { allowFailure != nil }, set: { if !$0 { allowFailure = nil } })) {
            Button(L("好"), role: .cancel) {}
        } message: { Text(allowFailure ?? "") }
        .sheet(isPresented: $addingList) { AddListView { list in
            var next = settings ?? AdblockSettings()
            next.custom.append(list)
            save(next)
        } }
    }

    /// Statistics and recent blocks; otherwise why there are none yet.
    @ViewBuilder private var statusSection: some View {
        if let status = model.adblock, status.enabled {
            statistics(status)
        } else if model.adblockState == .pending && model.connected {
            Section(L("统计")) {
                Text(L("去广告已开启，重新连接后开始拦截并统计。")).foregroundStyle(.secondary)
                Button(L("重新连接")) { Task { await model.reconnect(); needsReconnect = false } }
                    .disabled(model.busy)
            }
        } else if !model.connected && settings?.enabled == true {
            Section(L("统计")) {
                Text(L("连接后显示拦截统计。")).foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder private func statistics(_ status: AdblockStatus) -> some View {
        Section {
            LabeledContent(L("拦截次数"), value: status.total.formatted())
            LabeledContent(L("DNS / 连接"), value: "\(status.dns.formatted()) / \(status.connections.formatted())")
            LabeledContent(L("涉及域名"), value: status.domains.formatted())
            LabeledContent(L("规则条数"), value: status.entries.formatted())
        } header: {
            Text(L("统计"))
        } footer: {
            Text(L("自 {date} 本次连接以来", ["date": Date(timeIntervalSince1970: status.since).formatted(date: .abbreviated, time: .shortened)]))
        }
        if !status.top.isEmpty {
            Section(L("拦截最多")) {
                ForEach(status.top) { item in
                    HStack {
                        Text(item.domain).lineLimit(1)
                        Spacer()
                        Text(L("{count} 次", ["count": item.count])).foregroundStyle(.secondary)
                        allowButton(item.domain)
                    }
                    .swipeActions { Button(L("放行")) { allow(item.domain) }.tint(.green) }
                }
            }
        }
        if !status.recent.isEmpty {
            Section {
                ForEach(Array(status.recent.enumerated()), id: \.offset) { _, item in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.domain).font(.subheadline.monospaced()).lineLimit(1)
                            Text("\(Date(timeIntervalSince1970: item.time).formatted(date: .omitted, time: .standard)) · \(item.via == "dns" ? "DNS" : L("连接"))")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        allowButton(item.domain)
                    }
                    .swipeActions { Button(L("放行")) { allow(item.domain) }.tint(.green) }
                }
            } header: { Text(L("最近拦截")) } footer: { Text(L("点「放行」把域名加入白名单，立即生效。")) }
        }
    }

    /// One tap adds the domain to the allowlist; allowed ones say so.
    @ViewBuilder private func allowButton(_ domain: String) -> some View {
        if settings?.allow.contains(domain) == true {
            Text(L("已放行")).font(.caption).foregroundStyle(.green)
        } else {
            Button(L("放行")) { allow(domain) }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .tint(.green)
        }
    }

    private func allow(_ domain: String) {
        Task {
            do { try await model.allowAdblock(domain) } catch { allowFailure = error.localizedDescription }
        }
    }

    private func listLine(_ name: String) -> String? {
        guard let info = model.adblock?.lists.first(where: { $0.name == name }) else { return nil }
        if let error = info.error { return L("不可用：{error}", ["error": error]) }
        return L("{entries} 条", ["entries": info.entries.formatted()]) + (info.updated.map { L(" · 更新于 {date}", ["date": Date(timeIntervalSince1970: $0).formatted(date: .abbreviated, time: .shortened)]) } ?? "")
    }

    private func addAllow() {
        let domain = newAllow.trimmingCharacters(in: .whitespaces).lowercased()
        guard !domain.isEmpty, var next = settings, !next.allow.contains(domain) else { return }
        next.allow.append(domain)
        newAllow = ""
        save(next)
    }

    private func save(_ next: AdblockSettings) {
        Task {
            do {
                if try await model.saveAdblock(next) { needsReconnect = true }
                failure = nil
            } catch { failure = error.localizedDescription }
        }
    }
}

private struct AddListView: View {
    let add: (AdblockSettings.List) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var url = ""
    @State private var format = "clash"
    var body: some View {
        NavigationStack {
            Form {
                TextField(L("名称"), text: $name)
                TextField("https://…", text: $url)
                    .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                Picker(L("格式"), selection: $format) {
                    Text(L("Clash 规则集")).tag("clash")
                    Text("hosts").tag("hosts")
                    Text("AdGuard").tag("adguard")
                }
            }
            .navigationTitle(L("添加列表")).navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L("取消")) { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(L("添加")) {
                        add(.init(name: name.trimmingCharacters(in: .whitespaces), url: url.trimmingCharacters(in: .whitespaces), format: format))
                        dismiss()
                    }
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty
                              || !(url.hasPrefix("https://") || url.hasPrefix("http://")))
                }
            }
        }
    }
}
