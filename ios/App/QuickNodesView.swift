import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

private func isV2EncryptedLinks(_ raw: String) -> Bool {
    let compact = raw.filter { !$0.isWhitespace }
    return compact.count >= 24 && !compact.contains("://") && compact.hasPrefix("Q0xZTlRJ")
}

private func needsPasswordField(_ raw: String) -> Bool {
    let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    return !trimmed.isEmpty && !trimmed.contains("://")
}

/// Sheet for creating a new auto-routed profile from node share links (`vless://`,
/// `hysteria2://`, `hy2://`, Base64 subscription text, or CLYNTISE encrypted links).
struct QuickAddNodesView: View {
    @Bindable var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var links = ""
    @State private var password = ""
    @State private var autoRouting = "whitelist"
    @State private var importing = false
    @State private var errorMessage: String?
    @State private var skippedMessage: String?

    private var encryptedDetected: Bool { isV2EncryptedLinks(links) }
    private var showPassword: Bool { needsPasswordField(links) }

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
                if showPassword {
                    Section {
                        SecureField(encryptedDetected ? L("解密密码") : L("解密密码（可选）"), text: $password)
                            .textContentType(.password)
                            .disabled(importing)
                    } header: {
                        Text(L("解密密码"))
                    } footer: {
                        Text(encryptedDetected ? L("检测到加密节点链接，请输入密码解密。") : L("未加密的 Base64 订阅可留空。"))
                    }
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
                    .disabled(importing || model.busy || links.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || (encryptedDetected && password.isEmpty))
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
            let pw = password.isEmpty ? nil : password
            let result = try await model.importNodeLinks(name: name, text: links, mode: autoRouting, password: pw)
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
    @State private var exportingLinks = false
    @State private var newLinks = ""
    @State private var appendPassword = ""
    @State private var working = false
    @State private var message: String?
    @State private var failure: String?
    @State private var appendError: String?

    private var inUse: Bool { model.active && model.selectedID == profile.id }
    private var appendEncryptedDetected: Bool { isV2EncryptedLinks(newLinks) }
    private var showAppendPassword: Bool { needsPasswordField(newLinks) }
    private var hasExportableNodes: Bool {
        info?.nodes.contains(where: { $0.kind == "vless" || $0.kind == "hysteria2" }) ?? false
    }

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
                        appendPassword = ""
                        addingLinks = true
                    }
                    .disabled(working || model.busy)
                    if hasExportableNodes {
                        Button(L("导出节点链接")) { exportingLinks = true }
                            .disabled(working || model.busy)
                    }
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
                    if showAppendPassword {
                        Section {
                            SecureField(appendEncryptedDetected ? L("解密密码") : L("解密密码（可选）"), text: $appendPassword)
                                .textContentType(.password)
                                .disabled(working)
                        } header: {
                            Text(L("解密密码"))
                        } footer: {
                            Text(appendEncryptedDetected ? L("检测到加密节点链接，请输入密码解密。") : L("未加密的 Base64 订阅可留空。"))
                        }
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
                        .disabled(working || model.busy || newLinks.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || (appendEncryptedDetected && appendPassword.isEmpty))
                    }
                }
                .interactiveDismissDisabled(working)
            }
        }
        .sheet(isPresented: $exportingLinks) {
            ExportNodeLinksView(model: model, profile: profile)
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
            let pw = appendPassword.isEmpty ? nil : appendPassword
            let res = try await model.addNodeLinks(newLinks, to: profile, password: pw)
            newLinks = ""
            appendPassword = ""
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

/// Exports VLESS/Hysteria2 node share links in plaintext or password-encrypted format.
struct ExportNodeLinksView: View {
    let model: AppModel
    let profile: Profile
    @Environment(\.dismiss) private var dismiss
    @State private var useEncryption = false
    @State private var password = ""
    @State private var repeated = ""
    @State private var exportedText = ""
    @State private var exportedCount = 0
    @State private var working = false
    @State private var notice: String?
    @State private var errorMessage: String?

    private var mismatch: Bool { useEncryption && !repeated.isEmpty && repeated != password }
    private var canEncryptExport: Bool { !password.isEmpty && repeated == password }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Toggle(L("使用密码加密"), isOn: $useEncryption)
                        .disabled(working)
                        .onChange(of: useEncryption) { _, encrypted in
                            notice = nil
                            errorMessage = nil
                            exportedText = ""
                            if !encrypted {
                                Task { await exportPlain() }
                            }
                        }
                }
                if useEncryption {
                    Section {
                        SecureField(L("密码"), text: $password)
                            .textContentType(.newPassword)
                            .disabled(working)
                        SecureField(L("确认密码"), text: $repeated)
                            .textContentType(.newPassword)
                            .disabled(working)
                    } footer: {
                        Text(mismatch ? L("两次输入的密码不一致") : L("加密后的链接可直接粘贴到「快速添加节点」或「添加节点链接」中，输入密码即可解密导入。"))
                            .foregroundStyle(mismatch ? Color.red : Color.secondary)
                    }
                    Section {
                        Button {
                            Task { await exportEncrypted() }
                        } label: {
                            HStack {
                                Text(L("生成并复制加密链接"))
                                if working { Spacer(); ProgressView() }
                            }
                        }
                        .disabled(working || !canEncryptExport)
                    }
                }
                if !exportedText.isEmpty {
                    Section(L("节点链接")) {
                        TextEditor(text: .constant(exportedText))
                            .font(.footnote.monospaced())
                            .frame(minHeight: 110)
                        #if canImport(UIKit)
                        Button(L("复制链接")) {
                            UIPasteboard.general.string = exportedText
                            notice = useEncryption ? L("已复制加密节点链接") : L("已复制 {count} 个节点链接", ["count": exportedCount])
                        }
                        #endif
                        ShareLink(item: exportedText)
                    }
                }
                if let notice {
                    Section { Text(notice).foregroundStyle(.secondary) }
                }
                if let errorMessage {
                    Section { Text(errorMessage).foregroundStyle(.red) }
                }
            }
            .navigationTitle(L("导出节点链接"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(L("完成")) { dismiss() }
                        .disabled(working)
                }
            }
            .task {
                if !useEncryption && exportedText.isEmpty {
                    await exportPlain()
                }
            }
        }
    }

    private func exportPlain() async {
        working = true
        errorMessage = nil
        defer { working = false }
        do {
            let res = try await model.exportNodeLinks(for: profile, password: nil)
            exportedText = res.text
            exportedCount = res.count
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func exportEncrypted() async {
        working = true
        errorMessage = nil
        notice = nil
        defer { working = false }
        do {
            let res = try await model.exportNodeLinks(for: profile, password: password)
            exportedText = res.text
            exportedCount = res.count
            #if canImport(UIKit)
            UIPasteboard.general.string = res.text
            #endif
            notice = L("已复制加密节点链接")
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
