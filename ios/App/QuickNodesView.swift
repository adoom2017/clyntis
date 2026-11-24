import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

/// Sheet for creating a new auto-routed profile from node share links (`vless://`,
/// `hysteria2://`, `hy2://`, or Base64 subscription text).
struct QuickAddNodesView: View {
    @Bindable var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var links = ""
    @State private var autoRouting = "whitelist"
    @State private var importing = false
    @State private var errorMessage: String?
    @State private var skippedMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                Section(L("节点链接")) {
                    TextEditor(text: $links)
                        .font(.footnote.monospaced())
                        .frame(minHeight: 130)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .disabled(importing)
                    #if canImport(UIKit)
                    Button(L("从剪贴板粘贴")) {
                        if let text = UIPasteboard.general.string {
                            links = text
                        }
                    }
                    .disabled(importing)
                    #endif
                }
                Section(L("名称")) {
                    TextField(L("留空则使用首个节点名称"), text: $name)
                        .disabled(importing)
                }
                Section {
                    Picker(L("自动分流模式"), selection: $autoRouting) {
                        Text(L("白名单（推荐）")).tag("whitelist")
                        Text(L("黑名单")).tag("blacklist")
                    }
                    .pickerStyle(.segmented)
                    .disabled(importing)
                } header: {
                    Text(L("自动分流模式"))
                } footer: {
                    Text(autoRouting == "whitelist"
                         ? L("国内与局域网直连，其余流量全部走代理，无需手写规则。")
                         : L("仅海外站点列表走代理，其余流量默认直连，更省代理流量。"))
                }
                if let errorMessage {
                    Section { Text(errorMessage).foregroundStyle(.red) }
                }
            }
            .navigationTitle(L("快速添加节点"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(L("取消")) { dismiss() }
                        .disabled(importing)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(L("导入")) {
                        Task { await submit() }
                    }
                    .disabled(importing || model.busy || links.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            .interactiveDismissDisabled(importing)
            .alert(
                L("部分链接已跳过"),
                isPresented: Binding(
                    get: { skippedMessage != nil },
                    set: { if !$0 { skippedMessage = nil; dismiss() } }
                )
            ) {
                Button(L("好")) {
                    skippedMessage = nil
                    dismiss()
                }
            } message: {
                if let skippedMessage { Text(skippedMessage) }
            }
        }
    }

    private func submit() async {
        errorMessage = nil
        importing = true
        defer { importing = false }
        do {
            let result = try await model.importNodeLinks(name: name, text: links, mode: autoRouting)
            if result.skipped.isEmpty {
                dismiss()
            } else {
                skippedMessage = L("已导入 {count} 个节点，跳过 {skipped} 条不支持或无效的链接。", ["count": result.nodes.count, "skipped": result.skipped.count])
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

/// Manages nodes and automatic GeoIP/GeoSite routing mode for a profile.
struct ProfileNodesView: View {
    @Bindable var model: AppModel
    let profile: Profile
    @State private var info: CoreSession.ProfileNodes?
    @State private var autoRouting = "whitelist"
    @State private var addingLinks = false
    @State private var newLinks = ""
    @State private var working = false
    @State private var message: String?
    @State private var failure: String?
    @State private var appendError: String?

    private var inUse: Bool { model.active && model.selectedID == profile.id }

    var body: some View {
        List {
            if let info {
                if info.isAuto {
                    Section {
                        Picker(L("自动分流模式"), selection: $autoRouting) {
                            Text(L("白名单（推荐）")).tag("whitelist")
                            Text(L("黑名单")).tag("blacklist")
                        }
                        .pickerStyle(.segmented)
                        .disabled(working || model.busy)
                        .onChange(of: autoRouting) { _, next in
                            guard next != info.autoRouting else { return }
                            Task { await updateMode(next) }
                        }
                    } header: {
                        Text(L("自动分流模式"))
                    } footer: {
                        Text(autoRouting == "whitelist"
                             ? L("国内与局域网直连，其余流量全部走代理，无需手写规则。")
                             : L("仅海外站点列表走代理，其余流量默认直连，更省代理流量。"))
                    }
                } else {
                    Section(L("自动分流模式")) {
                        Text(L("此配置已定义自定义 rules，自动分流模式不会生效。"))
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
                Section(L("节点列表")) {
                    ForEach(info.nodes) { node in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(node.name).font(.body)
                            Text("\(node.kind) · \(node.server):\(node.port)")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        .swipeActions {
                            Button(L("删除"), role: .destructive) {
                                Task { await removeNode(node.name) }
                            }
                            .disabled(working || model.busy || (info.isAuto && info.nodes.count <= 1))
                        }
                    }
                }
                Section {
                    Button(L("添加节点链接")) {
                        appendError = nil
                        addingLinks = true
                    }
                    .disabled(working || model.busy)
                } footer: {
                    if inUse { Text(L("连接中修改的内容会在重新连接后生效")) }
                }
            }
            if let message { Section { Text(message).foregroundStyle(.secondary) } }
            if let failure { Section { Text(failure).foregroundStyle(.red) } }
        }
        .navigationTitle(L("节点与自动分流"))
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { load() }
        .sheet(isPresented: $addingLinks) {
            NavigationStack {
                Form {
                    Section(L("节点链接")) {
                        TextEditor(text: $newLinks)
                            .font(.footnote.monospaced())
                            .frame(minHeight: 130)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .disabled(working)
                        #if canImport(UIKit)
                        Button(L("从剪贴板粘贴")) {
                            if let text = UIPasteboard.general.string {
                                newLinks = text
                            }
                        }
                        .disabled(working)
                        #endif
                    }
                    if let appendError {
                        Section { Text(appendError).foregroundStyle(.red) }
                    }
                }
                .navigationTitle(L("添加节点链接"))
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button(L("取消")) { addingLinks = false }
                            .disabled(working)
                    }
                    ToolbarItem(placement: .confirmationAction) {
                        Button(L("添加")) {
                            Task { await appendLinks() }
                        }
                        .disabled(working || model.busy || newLinks.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                }
                .interactiveDismissDisabled(working)
            }
        }
    }

    private func load() {
        do {
            let loaded = try model.profileNodes(for: profile)
            info = loaded
            if let mode = loaded.autoRouting { autoRouting = mode }
            failure = nil
        } catch {
            failure = error.localizedDescription
        }
    }

    private func updateMode(_ mode: String) async {
        working = true
        failure = nil
        message = nil
        defer { working = false }
        do {
            try await model.updateProfileNodes(for: profile, removeNames: [], autoRouting: mode)
            load()
            message = L("分流模式已更新")
        } catch {
            failure = error.localizedDescription
            if let old = info?.autoRouting { autoRouting = old }
        }
    }

    private func removeNode(_ name: String) async {
        working = true
        failure = nil
        message = nil
        defer { working = false }
        do {
            try await model.updateProfileNodes(for: profile, removeNames: [name], autoRouting: nil)
            load()
            message = L("节点已移除")
        } catch {
            failure = error.localizedDescription
        }
    }

    private func appendLinks() async {
        working = true
        appendError = nil
        message = nil
        defer { working = false }
        do {
            let res = try await model.addNodeLinks(newLinks, to: profile)
            newLinks = ""
            addingLinks = false
            load()
            message = res.skipped.isEmpty
                ? L("已添加 {count} 个节点", ["count": res.nodes.count])
                : L("已添加 {count} 个节点，跳过 {skipped} 条", ["count": res.nodes.count, "skipped": res.skipped.count])
        } catch {
            appendError = error.localizedDescription
        }
    }
}
