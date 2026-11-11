import SwiftUI

/// Rewrite modules as the core loaded them, from the snapshot (`rewrite`).
struct RewriteStatus: Decodable, Equatable {
    struct Skipped: Decodable, Equatable {
        let line: Int
        let text: String
    }
    struct Module: Decodable, Equatable {
        let name: String
        let title: String?
        let rules: Int
        let scripts: Int
        let hostnames: Int
        let skipped: [Skipped]
        let missing: [String]
        let updated: Double?
        let error: String?
    }
    let enabled: Bool
    let decrypting: Bool
    let rules: Int
    let total: Int
    let hostnames: [String]
    let hits: [String: Int]
    let modules: [Module]

    static func decode(_ object: Any?) -> RewriteStatus? {
        guard let object, let data = try? JSONSerialization.data(withJSONObject: object) else { return nil }
        return try? JSONDecoder().decode(RewriteStatus.self, from: data)
    }
}

/// Surge, Loon and Quantumult X modules that rewrite decrypted HTTP to remove
/// ads: settings, and what the running core loaded.
struct RewriteView: View {
    @Bindable var model: AppModel
    @State private var failure: String?
    @State private var needsReconnect = false
    @State private var addingModule = false

    private var settings: RewriteSettings? { model.overrides.rewrite }
    private var decrypting: Bool { model.overrides.mitm?.enable == true }

    var body: some View {
        List {
            Section {
                Toggle(L("启用重写模块"), isOn: Binding(get: { settings?.enabled ?? false }, set: { on in
                    var next = settings ?? RewriteSettings()
                    next.enabled = on
                    save(next)
                }))
            } footer: {
                Text(decrypting
                     ? L("用 Surge、Loon、Quantumult X 的模块去广告：拦截广告 URL、改写返回内容、运行脚本。模块里的主机名自动加入 HTTPS 解密。")
                     : L("只作用于 HTTPS 解密的流量：先开启 HTTPS 解密并在系统设置里完全信任证书。"))
            }
            if let settings, settings.enabled {
                Section {
                    ForEach(settings.modules, id: \.self) { module in
                        Toggle(isOn: Binding(get: { module.enabled }, set: { on in
                            var next = settings
                            if let index = next.modules.firstIndex(of: module) { next.modules[index].enabled = on }
                            save(next)
                        })) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(module.name)
                                Text(moduleLine(module.name) ?? module.url)
                                    .font(.caption).foregroundStyle(moduleFailed(module.name) ? .red : .secondary)
                                    .lineLimit(2)
                            }
                        }
                        .swipeActions {
                            Button(L("移除"), role: .destructive) {
                                var next = settings
                                next.modules.removeAll { $0 == module }
                                save(next)
                            }
                        }
                    }
                    Button(L("添加模块"), systemImage: "plus") { addingModule = true }
                    NavigationLink {
                        CustomRewriteView(text: settings.custom) { custom in
                            var next = settings
                            next.custom = custom
                            save(next)
                        }
                    } label: {
                        LabeledContent(L("自定义规则"), value: customSummary(settings.custom))
                    }
                } header: {
                    Text(L("模块"))
                } footer: {
                    Text(L("支持 Surge 模块（.sgmodule）、Loon 插件（.plugin）和 Quantumult X 重写。模块和脚本连接时下载，之后每天更新。脚本能读取和修改所匹配请求的内容，只添加信任的来源。"))
                }
            }
            if needsReconnect && model.active {
                Section {
                    Button(L("重新连接以生效")) {
                        Task { await model.reconnect(); needsReconnect = false }
                    }
                    .disabled(model.busy)
                } footer: { Text(L("模块的修改需要重新连接。")) }
            }
            if let failure { Section { Text(failure).foregroundStyle(.red) } }
            statusSection
        }
        .navigationTitle(L("重写模块"))
        .sheet(isPresented: $addingModule) {
            AddModuleView(taken: settings?.modules.map(\.name) ?? []) { module in
                var next = settings ?? RewriteSettings()
                next.modules.append(module)
                save(next)
            }
        }
    }

    @ViewBuilder private var statusSection: some View {
        if let status = model.rewrite, status.enabled {
            Section {
                LabeledContent(L("规则"), value: status.rules.formatted())
                LabeledContent(L("生效次数"), value: status.total.formatted())
                LabeledContent(L("模块主机名"), value: status.hostnames.count.formatted())
                if !status.decrypting {
                    Text(L("HTTPS 解密未开启，模块不生效")).foregroundStyle(.orange)
                }
            } header: {
                Text(L("本次连接"))
            }
            let problems = status.modules.filter { !$0.skipped.isEmpty }
            if !problems.isEmpty {
                Section {
                    ForEach(problems, id: \.name) { module in
                        DisclosureGroup(L("{name}：{count} 行不支持，已跳过", ["name": displayName(module.name), "count": module.skipped.count])) {
                            ForEach(Array(module.skipped.enumerated()), id: \.offset) { _, line in
                                Text("\(line.line): \(line.text)").font(.caption.monospaced()).foregroundStyle(.secondary)
                            }
                        }
                    }
                } footer: {
                    Text(L("这些行用到了本应用不支持的功能，其余规则照常生效。"))
                }
            }
        } else if !model.connected && settings?.enabled == true {
            Section {
                Text(L("连接后显示模块的加载情况。")).foregroundStyle(.secondary)
            }
        }
    }

    private func displayName(_ name: String) -> String {
        name == "custom" ? L("自定义规则") : name
    }

    private func moduleFailed(_ name: String) -> Bool {
        guard let info = model.rewrite?.modules.first(where: { $0.name == name }) else { return false }
        return info.error != nil || !info.missing.isEmpty
    }

    private func moduleLine(_ name: String) -> String? {
        guard let info = model.rewrite?.modules.first(where: { $0.name == name }) else { return nil }
        if let error = info.error { return L("不可用：{error}", ["error": error]) }
        var line = L("{rules} 条规则 · {scripts} 个脚本 · 生效 {hits} 次", [
            "rules": info.rules, "scripts": info.scripts, "hits": model.rewrite?.hits[name] ?? 0,
        ])
        if !info.missing.isEmpty {
            line += " · " + L("{count} 个脚本下载失败", ["count": info.missing.count])
        }
        return line
    }

    private func customSummary(_ text: String) -> String {
        let lines = text.split(separator: "\n").filter {
            let line = $0.trimmingCharacters(in: .whitespaces)
            return !line.isEmpty && !line.hasPrefix("#")
        }
        return lines.isEmpty ? L("无") : L("{count} 行", ["count": lines.count])
    }

    private func save(_ next: RewriteSettings) {
        do {
            if try model.saveRewrite(next) { needsReconnect = true }
            failure = nil
        } catch { failure = error.localizedDescription }
    }
}

private struct AddModuleView: View {
    let taken: [String]
    let add: (RewriteSettings.Module) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var url = ""

    private var trimmedName: String { name.trimmingCharacters(in: .whitespaces) }
    private var duplicate: Bool { taken.contains(trimmedName) || trimmedName == "custom" }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField(L("名称"), text: $name)
                    TextField("https://…", text: $url)
                        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                } footer: {
                    if duplicate { Text(L("已有同名模块。")).foregroundStyle(.red) }
                }
            }
            .navigationTitle(L("添加模块")).navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L("取消")) { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(L("添加")) {
                        add(.init(name: trimmedName, url: url.trimmingCharacters(in: .whitespaces)))
                        dismiss()
                    }
                    .disabled(trimmedName.isEmpty || trimmedName.count > 64 || duplicate
                              || !(url.hasPrefix("https://") || url.hasPrefix("http://")))
                }
            }
        }
    }
}

private struct CustomRewriteView: View {
    @State var text: String
    let save: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            Section {
                TextEditor(text: $text)
                    .font(.footnote.monospaced())
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .frame(minHeight: 260)
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    Text(L("用模块的写法，例如："))
                    Text(verbatim: #"""
                    [URL Rewrite]
                    ^https?:\/\/api\.example\.com\/ad - reject-dict
                    [MITM]
                    hostname = api.example.com
                    """#).font(.caption.monospaced())
                }
            }
        }
        .navigationTitle(L("自定义规则")).navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button(L("保存")) { save(text); dismiss() }
            }
        }
    }
}
