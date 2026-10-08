import SwiftUI

/// App settings that replace the profile's values on every profile.
struct OverridesView: View {
    @Bindable var model: AppModel
    @State private var failure: String?

    var body: some View {
        Form {
            Section {
                Picker("日志级别", selection: binding(\.logLevel)) {
                    Text("跟随配置文件").tag(String?.none)
                    ForEach(AppOverrides.logLevels, id: \.self) { Text($0).tag(String?.some($0)) }
                }
                OverrideToggle(title: "IPv6", value: binding(\.ipv6))
                OverrideToggle(title: "域名嗅探", value: binding(\.sniffing))
            } footer: {
                Text(model.active ? "已连接：修改后需要重新连接才会生效。"
                                  : "选「跟随配置文件」时使用配置自己的值。debug 日志较多，平时用 info。")
            }
            if model.active {
                Section {
                    Button("重新连接以生效") { Task { await model.reconnect() } }
                        .disabled(model.busy)
                }
            }
            if let failure { Section { Text(failure).foregroundStyle(.red) } }
        }
        .navigationTitle("覆盖配置文件")
    }

    private func binding<Value>(_ key: WritableKeyPath<AppOverrides, Value>) -> Binding<Value> {
        Binding(get: { model.overrides[keyPath: key] }, set: { value in
            var overrides = model.overrides
            overrides[keyPath: key] = value
            do {
                try model.saveOverrides(overrides)
                failure = nil
            } catch { failure = error.localizedDescription }
        })
    }
}

private struct OverrideToggle: View {
    let title: String
    @Binding var value: Bool?
    var body: some View {
        Picker(title, selection: $value) {
            Text("跟随配置文件").tag(Bool?.none)
            Text("开启").tag(Bool?.some(true))
            Text("关闭").tag(Bool?.some(false))
        }
    }
}
