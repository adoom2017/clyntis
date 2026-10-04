import SwiftUI
import UniformTypeIdentifiers

/// Password prompt shared by encrypted import (single field) and encrypted export (confirmed).
struct ConfigPasswordView: View {
    let title: String
    let message: String
    let actionTitle: String
    var confirm = false
    let action: (String) async throws -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var repeated = ""
    @State private var working = false
    @State private var errorMessage: String?

    private var mismatch: Bool { confirm && !repeated.isEmpty && repeated != password }
    private var ready: Bool { !password.isEmpty && (!confirm || repeated == password) }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("密码", text: $password).textContentType(confirm ? .newPassword : .password)
                    if confirm {
                        SecureField("确认密码", text: $repeated).textContentType(.newPassword)
                    }
                } footer: {
                    Text(mismatch ? "两次输入的密码不一致" : message)
                        .foregroundStyle(mismatch ? Color.red : Color.secondary)
                }
                if working { Section { ProgressView() } }
                if let errorMessage { Section { Text(errorMessage).foregroundStyle(.red) } }
            }
            .disabled(working)
            .navigationTitle(title).navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(actionTitle) {
                        working = true
                        errorMessage = nil
                        Task {
                            do { try await action(password) }
                            catch { errorMessage = error.localizedDescription }
                            working = false
                        }
                    }.disabled(!ready || working)
                }
            }
            .interactiveDismissDisabled(working)
        }
        .onDisappear { password = ""; repeated = "" }
    }
}

/// Encrypt, then hand the Base64 text to the system file exporter.
struct EncryptedExportView: View {
    let model: AppModel
    let profile: Profile
    @Environment(\.dismiss) private var dismiss
    @State private var document: EncryptedConfigDocument?

    var body: some View {
        ConfigPasswordView(title: "加密导出", message: "导入此文件时需要输入该密码。",
                           actionTitle: "导出", confirm: true) { password in
            document = EncryptedConfigDocument(data: try await model.exportEncrypted(profile, password: password))
        }
        .fileExporter(isPresented: Binding(get: { document != nil }, set: { if !$0 { document = nil } }),
                      document: document, contentType: .plainText,
                      defaultFilename: "\(profile.name).txt") { result in
            if case .success = result { dismiss() }
        }
    }
}

struct EncryptedConfigDocument: FileDocument {
    static let readableContentTypes: [UTType] = [.plainText]
    let data: Data
    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws {
        data = configuration.file.regularFileContents ?? Data()
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}
