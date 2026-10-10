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
            statusSection
            Section {
                Toggle("启用去广告", isOn: Binding(get: { settings?.enabled ?? false }, set: { on in
                    var next = settings ?? AdblockSettings()
                    next.enabled = on
                    save(next)
                }))
            } footer: {
                Text("广告、追踪和统计域名在 DNS 查询时直接拒绝，并优先于所有规则。")
            }
            if let settings, settings.enabled {
                Section("列表") {
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
                            Button("移除", role: .destructive) {
                                var next = settings
                                next.custom.removeAll { $0 == list }
                                save(next)
                            }
                        }
                    }
                    Button("添加列表", systemImage: "plus") { addingList = true }
                }
                Section {
                    ForEach(settings.allow, id: \.self) { domain in
                        Text(domain).font(.body.monospaced())
                            .swipeActions {
                                Button("删除", role: .destructive) {
                                    var next = settings
                                    next.allow.removeAll { $0 == domain }
                                    save(next)
                                }
                            }
                    }
                    HStack {
                        TextField("添加域名，如 wechat.com", text: $newAllow)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            .onSubmit(addAllow)
                        Button("添加", action: addAllow).disabled(newAllow.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                } header: { Text("白名单") } footer: { Text("包含子域名；修改后立即生效。") }
            }
            if needsReconnect && model.active && !(model.adblockState == .pending && model.connected) {
                Section {
                    Button("重新连接以生效") {
                        Task { await model.reconnect(); needsReconnect = false }
                    }
                    .disabled(model.busy)
                } footer: { Text("开关和列表的修改需要重新连接。") }
            }
            if let failure { Section { Text(failure).foregroundStyle(.red) } }
        }
        .navigationTitle("去广告")
        .alert("无法放行", isPresented: Binding(get: { allowFailure != nil }, set: { if !$0 { allowFailure = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(allowFailure ?? "") }
        .sheet(isPresented: $addingList) { AddListView { list in
            var next = settings ?? AdblockSettings()
            next.custom.append(list)
            save(next)
        } }
    }

    /// Statistics first; otherwise why there are none yet.
    @ViewBuilder private var statusSection: some View {
        if let status = model.adblock, status.enabled {
            statistics(status)
        } else if model.adblockState == .pending && model.connected {
            Section("统计") {
                Text("去广告已开启，重新连接后开始拦截并统计。").foregroundStyle(.secondary)
                Button("重新连接") { Task { await model.reconnect(); needsReconnect = false } }
                    .disabled(model.busy)
            }
        } else if !model.connected && settings?.enabled == true {
            Section("统计") {
                Text("连接后显示拦截统计。").foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder private func statistics(_ status: AdblockStatus) -> some View {
        Section {
            LabeledContent("拦截次数", value: status.total.formatted())
            LabeledContent("DNS / 连接", value: "\(status.dns.formatted()) / \(status.connections.formatted())")
            LabeledContent("涉及域名", value: status.domains.formatted())
            LabeledContent("规则条数", value: status.entries.formatted())
        } header: {
            Text("统计")
        } footer: {
            Text("自 \(Date(timeIntervalSince1970: status.since).formatted(date: .abbreviated, time: .shortened)) 本次连接以来")
        }
        if !status.top.isEmpty {
            Section("拦截最多") {
                ForEach(status.top) { item in
                    HStack {
                        Text(item.domain).lineLimit(1)
                        Spacer()
                        Text("\(item.count) 次").foregroundStyle(.secondary)
                        allowButton(item.domain)
                    }
                    .swipeActions { Button("放行") { allow(item.domain) }.tint(.green) }
                }
            }
        }
        if !status.recent.isEmpty {
            Section {
                ForEach(Array(status.recent.enumerated()), id: \.offset) { _, item in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.domain).font(.subheadline.monospaced()).lineLimit(1)
                            Text("\(Date(timeIntervalSince1970: item.time).formatted(date: .omitted, time: .standard)) · \(item.via == "dns" ? "DNS" : "连接")")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        allowButton(item.domain)
                    }
                    .swipeActions { Button("放行") { allow(item.domain) }.tint(.green) }
                }
            } header: { Text("最近拦截") } footer: { Text("点「放行」把域名加入白名单，立即生效。") }
        }
    }

    /// One tap adds the domain to the allowlist; allowed ones say so.
    @ViewBuilder private func allowButton(_ domain: String) -> some View {
        if settings?.allow.contains(domain) == true {
            Text("已放行").font(.caption).foregroundStyle(.green)
        } else {
            Button("放行") { allow(domain) }
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
        if let error = info.error { return "不可用：\(error)" }
        return "\(info.entries.formatted()) 条" + (info.updated.map { " · 更新于 \(Date(timeIntervalSince1970: $0).formatted(date: .abbreviated, time: .shortened))" } ?? "")
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
                TextField("名称", text: $name)
                TextField("https://…", text: $url)
                    .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                Picker("格式", selection: $format) {
                    Text("Clash 规则集").tag("clash")
                    Text("hosts").tag("hosts")
                    Text("AdGuard").tag("adguard")
                }
            }
            .navigationTitle("添加列表").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("添加") {
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
