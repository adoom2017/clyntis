import Security
import SwiftUI

/// Tencent COS keys in the Keychain (this device only, readable after the
/// first unlock). Entered once in settings; the SecretKey is never shown.
enum CosKeychain {
    struct Keys: Codable { let secretID: String; let secretKey: String }

    private static let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "org.clyntis.ios.cos",
        kSecAttrAccount as String: "default",
    ]

    static func load() throws -> Keys? {
        var item: CFTypeRef?
        var search = query
        search[kSecReturnData as String] = true
        let status = SecItemCopyMatching(search as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else { throw failure(status, "读取") }
        return try JSONDecoder().decode(Keys.self, from: data)
    }

    static func save(_ keys: Keys) throws {
        let data = try JSONEncoder().encode(keys)
        let update = [kSecValueData as String: data,
                      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly] as [String: Any]
        var status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(query.merging(update) { $1 } as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw failure(status, "保存") }
    }

    static func delete() throws {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw failure(status, "删除") }
    }

    private static func failure(_ status: OSStatus, _ action: String) -> Error {
        ClientError.message("无法\(action)钥匙串中的 COS 密钥（\(status)）。")
    }
}

/// Where each profile was last published (not secret, so in UserDefaults).
enum PublishTargets {
    private static func key(_ id: UUID) -> String { "cosTarget.\(id.uuidString)" }

    static func get(_ id: UUID) -> CosTarget? {
        UserDefaults.standard.data(forKey: key(id)).flatMap { try? JSONDecoder().decode(CosTarget.self, from: $0) }
    }

    static func set(_ target: CosTarget, for id: UUID) {
        UserDefaults.standard.set(try? JSONEncoder().encode(target), forKey: key(id))
    }
}

/// Encrypts a profile and uploads it to Tencent COS, replacing the object
/// that subscribed devices update from.
struct CosPublishView: View {
    let model: AppModel
    let profile: Profile
    @Environment(\.dismiss) private var dismiss
    @State private var target = CosTarget(bucket: "", region: "", key: "")
    @State private var hasKeys = true
    @State private var password = ""
    @State private var repeated = ""
    @State private var working = false
    @State private var errorMessage: String?
    @State private var published: String?

    private var ready: Bool {
        target.url != nil && !password.isEmpty && repeated == password && hasKeys
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("存储桶，如 examplebucket-1250000000", text: $target.bucket)
                    TextField("地域，如 ap-shanghai", text: $target.region)
                    TextField("文件路径，如 config/home.txt", text: $target.key)
                } header: {
                    Text("腾讯云 COS")
                } footer: {
                    if let url = target.url { Text(url).textSelection(.enabled) }
                }
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                Section {
                    SecureField("加密密码", text: $password).textContentType(.newPassword)
                    SecureField("确认密码", text: $repeated).textContentType(.newPassword)
                } footer: {
                    Text(!repeated.isEmpty && repeated != password
                         ? "两次输入的密码不一致"
                         : "加密后上传并覆盖同名文件，订阅了该地址的设备下次更新即拿到新配置。")
                        .foregroundStyle(!repeated.isEmpty && repeated != password ? Color.red : Color.secondary)
                }
                if !hasKeys {
                    Section {
                        NavigationLink("填写 COS 密钥") { CosSettingsView { hasKeys = true } }
                    } footer: {
                        Text("尚未保存 COS 密钥。")
                    }
                }
                if working { Section { ProgressView() } }
                if let errorMessage { Section { Text(errorMessage).foregroundStyle(.red) } }
            }
            .disabled(working)
            .navigationTitle("发布到 COS").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("发布") {
                        working = true
                        errorMessage = nil
                        Task {
                            do { published = try await model.publish(profile, password: password, to: target) }
                            catch { errorMessage = error.localizedDescription }
                            working = false
                        }
                    }.disabled(!ready || working)
                }
            }
            .interactiveDismissDisabled(working)
            .alert("已发布", isPresented: Binding(get: { published != nil }, set: { if !$0 { dismiss() } })) {
                Button("好") { dismiss() }
            } message: {
                Text(published ?? "")
            }
        }
        .onAppear {
            target = PublishTargets.get(profile.id)
                ?? profile.source.flatMap { CoreSession.cosTarget(url: $0) }
                ?? target
            hasKeys = (try? CosKeychain.load()) != nil
        }
        .onDisappear { password = ""; repeated = "" }
    }
}

/// The COS keys used by 发布, kept in the Keychain.
struct CosSettingsView: View {
    var onSaved: () -> Void = {}
    @Environment(\.dismiss) private var dismiss
    @State private var saved: String?
    @State private var secretID = ""
    @State private var secretKey = ""
    @State private var failure: String?

    var body: some View {
        Form {
            Section {
                TextField("SecretId", text: $secretID)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                SecureField(saved == nil ? "SecretKey" : "SecretKey（已保存，留空则不修改）", text: $secretKey)
            } footer: {
                Text("建议使用只授予该存储桶 PutObject 权限的子用户密钥。密钥只保存在本机钥匙串中。")
            }
            Section {
                Button("保存") { save() }
                    .disabled(secretID.trimmingCharacters(in: .whitespaces).isEmpty
                              || (saved == nil && secretKey.isEmpty))
                if saved != nil {
                    Button("删除密钥", role: .destructive) {
                        do { try CosKeychain.delete(); load() } catch { failure = error.localizedDescription }
                    }
                }
            }
            if let failure { Section { Text(failure).foregroundStyle(.red) } }
        }
        .navigationTitle("远程发布")
        .onAppear(perform: load)
    }

    private func load() {
        saved = (try? CosKeychain.load())?.secretID
        secretID = saved ?? ""
        secretKey = ""
    }

    private func save() {
        do {
            let id = secretID.trimmingCharacters(in: .whitespaces)
            let key = secretKey.isEmpty ? try CosKeychain.load()?.secretKey : secretKey
            guard let key, !key.isEmpty else { throw ClientError.message("请填写 SecretKey。") }
            try CosKeychain.save(.init(secretID: id, secretKey: key))
            failure = nil
            load()
            onSaved()
            dismiss()
        } catch {
            failure = error.localizedDescription
        }
    }
}
