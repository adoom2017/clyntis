import SwiftUI

/// Name, source and actions for one profile, reached from the ⓘ button in the list.
struct ProfileDetailView: View {
    @Bindable var model: AppModel
    let id: UUID
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var working = false
    @State private var message: String?
    @State private var failure: String?
    @State private var askPassword = false
    @State private var exporting = false
    @State private var publishing = false
    @State private var confirmDelete = false

    private var profile: Profile? { model.profiles.first { $0.id == id } }
    private var inUse: Bool { model.active && model.selectedID == id }

    var body: some View {
        Form {
            if let profile {
                Section(L("名称")) {
                    TextField(L("名称"), text: $name)
                        .submitLabel(.done)
                        .onSubmit { rename(profile) }
                }
                Section(L("信息")) {
                    LabeledContent(L("来源"), value: profile.sourceHost ?? L("本地文件"))
                    if profile.encrypted == true { LabeledContent(L("内容"), value: L("已加密")) }
                    LabeledContent(L("导入时间"), value: profile.createdAt.formatted(date: .abbreviated, time: .shortened))
                    if let updated = profile.updatedAt {
                        LabeledContent(L("更新时间"), value: updated.formatted(date: .abbreviated, time: .shortened))
                    }
                }
                Section {
                    NavigationLink(L("查看与编辑配置")) { ConfigEditorView(model: model, profile: profile) }
                    if profile.source != nil {
                        Button {
                            if profile.encrypted == true { askPassword = true } else { update(profile) }
                        } label: {
                            HStack {
                                Text(L("从链接更新"))
                                if working { Spacer(); ProgressView() }
                            }
                        }
                        .disabled(working)
                    }
                    Button(L("使用此配置")) { model.selectedID = id }
                        .disabled(model.selectedID == id || model.active || model.busy)
                    Button(L("加密导出")) { exporting = true }
                    Button(L("发布到 COS")) { publishing = true }
                } footer: {
                    if inUse { Text(L("连接中修改的内容会在重新连接后生效")) }
                }
                if let message { Section { Text(message).foregroundStyle(.secondary) } }
                if let failure { Section { Text(failure).foregroundStyle(.red) } }
                Section {
                    Button(L("删除配置"), role: .destructive) { confirmDelete = true }
                        .disabled(inUse || model.busy)
                }
            } else {
                ContentUnavailableView(L("配置已删除"), systemImage: "doc")
            }
        }
        .navigationTitle(profile?.name ?? L("配置"))
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { name = profile?.name ?? "" }
        .sheet(isPresented: $askPassword) {
            ConfigPasswordView(title: L("从链接更新"), message: L("此链接的配置已加密，输入密码后更新。"),
                               actionTitle: L("更新")) { password in
                guard let profile else { return }
                try await model.updateFromSource(profile, password: password)
                askPassword = false
                message = L("已从链接更新")
            }
        }
        .sheet(isPresented: $exporting) {
            if let profile { EncryptedExportView(model: model, profile: profile) }
        }
        .sheet(isPresented: $publishing) {
            if let profile { CosPublishView(model: model, profile: profile) }
        }
        .confirmationDialog(L("删除「{name}」？", ["name": profile?.name ?? ""]), isPresented: $confirmDelete, titleVisibility: .visible) {
            Button(L("删除"), role: .destructive) {
                guard let profile else { return }
                model.remove(profile)
                dismiss()
            }
        } message: { Text(L("配置及其路由资源将从本机删除。")) }
    }

    private func rename(_ profile: Profile) {
        guard name != profile.name else { return }
        do {
            try model.rename(profile, to: name)
            failure = nil
        } catch {
            failure = error.localizedDescription
            name = profile.name
        }
    }

    private func update(_ profile: Profile) {
        working = true
        failure = nil
        message = nil
        Task {
            do {
                try await model.updateFromSource(profile)
                message = L("已从链接更新")
            } catch { failure = error.localizedDescription }
            working = false
        }
    }
}

/// Plain-text YAML editor. The core checks the syntax while typing and the
/// error line turns red; saving validates fully and keeps the old file on failure.
struct ConfigEditorView: View {
    @Bindable var model: AppModel
    let profile: Profile
    @State private var text = ""
    @State private var original = ""
    @State private var loaded = false
    @State private var saving = false
    @State private var failure: String?
    @State private var saved = false
    @State private var problem: CoreSession.YAMLProblem?
    @State private var reveal = 0

    var body: some View {
        VStack(spacing: 0) {
            if let failure {
                Text(failure).font(.footnote).foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(12)
                    .background(Color.red.opacity(0.08))
            }
            YAMLTextView(text: $text, errorLine: problem?.line, revealRequest: reveal)
                .padding(.horizontal, 4)
            if let problem {
                Button { reveal += 1 } label: {
                    Label {
                        Text(L("第 {line} 行第 {column} 列：{message}", ["line": problem.line, "column": problem.column, "message": problem.message]))
                            .multilineTextAlignment(.leading)
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill")
                    }
                    .font(.footnote).foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(12)
                .background(Color.red.opacity(0.08))
                .accessibilityHint(L("移到出错位置"))
            }
        }
        .task(id: text) {
            // Check after a pause in typing; a newer edit cancels this one.
            guard loaded else { return }
            try? await Task.sleep(for: .milliseconds(250))
            guard !Task.isCancelled else { return }
            let snapshot = text
            let found = await Task.detached { CoreSession.yamlProblem(in: snapshot) }.value
            if !Task.isCancelled { problem = found }
        }
        .background(Color(.systemBackground))
        .navigationTitle(L("配置内容"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                if saving {
                    ProgressView()
                } else {
                    Button(saved && text == original ? L("已保存") : L("保存")) { save() }
                        .disabled(!loaded || text == original || problem != nil)
                }
            }
        }
        .task {
            guard !loaded else { return }
            do {
                original = try model.configurationText(for: profile)
                text = original
                loaded = true
            } catch { failure = error.localizedDescription }
        }
    }

    private func save() {
        saving = true
        failure = nil
        Task {
            do {
                try await model.saveConfiguration(text, for: profile)
                original = text
                saved = true
            } catch { failure = error.localizedDescription }
            saving = false
        }
    }
}
