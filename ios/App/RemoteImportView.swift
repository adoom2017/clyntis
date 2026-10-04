import SwiftUI

struct RemoteImportView: View {
    let model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var address = ""
    @State private var name = ""
    @State private var password = ""
    @State private var attempt: UUID?
    @State private var importing = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("链接") {
                    TextField("https://example.com/config.yaml", text: $address)
                        .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                        .accessibilityLabel("配置链接")
                        .disabled(importing)
                }
                Section("名称") {
                    TextField("可选", text: $name).disabled(importing)
                }
                Section {
                    SecureField("可选", text: $password)
                        .textInputAutocapitalization(.never).autocorrectionDisabled().disabled(importing)
                } header: { Text("解密密码") }
                footer: { Text("仅用于加密配置，不会保存") }
                if importing {
                    Section { ProgressView("正在导入…") }
                }
                if let errorMessage {
                    Section { Text(errorMessage).foregroundStyle(.red) }
                }
            }
            .navigationTitle("从链接导入").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { password = ""; dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("导入") {
                        errorMessage = nil
                        importing = true
                        attempt = UUID()
                    }.disabled(importing || model.busy || address.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            .interactiveDismissDisabled(importing)
            .task(id: attempt) {
                guard attempt != nil else { return }
                do {
                    try await model.importRemote(address: address, password: password, name: name)
                    password = ""
                    dismiss()
                } catch is CancellationError { }
                catch let error as URLError where error.code == .cancelled { }
                catch { errorMessage = error.localizedDescription }
                importing = false
            }
            .onDisappear { password = "" }
        }
    }
}
