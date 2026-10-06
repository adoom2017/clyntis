import SwiftUI

/// Rule types offered when adding a custom rule.
private let ruleTypes: [(type: String, label: String, placeholder: String)] = [
    ("DOMAIN-SUFFIX", "域名后缀", "example.com"),
    ("DOMAIN", "完整域名", "www.example.com"),
    ("DOMAIN-KEYWORD", "域名关键字", "example"),
    ("IP-CIDR", "IPv4 段", "10.0.0.0/8"),
    ("IP-CIDR6", "IPv6 段", "2001:db8::/32"),
    ("GEOSITE", "GeoSite", "cn"),
    ("GEOIP", "GeoIP", "CN"),
    ("DST-PORT", "目标端口", "443 或 8000-9000"),
]

/// `TYPE,VALUE,TARGET[,no-resolve]` split for display; logical rules stay whole.
private struct RuleParts {
    let type: String, value: String, target: String, noResolve: Bool
    init(_ rule: String) {
        var fields = rule.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        noResolve = fields.last?.trimmingCharacters(in: .whitespaces) == "no-resolve"
        if noResolve { fields.removeLast() }
        type = fields.first ?? ""
        target = fields.count > 1 ? fields.removeLast() : ""
        value = fields.dropFirst().joined(separator: ",")
    }
    var label: String { ruleTypes.first { $0.type == type }?.label ?? type }
}

/// Rules matched before every profile's own rules.
struct RulesView: View {
    @Bindable var model: AppModel
    @State private var adding = false
    @State private var bulk = false
    @State private var failure: String?
    @State private var skipped: [String: String] = [:]

    var body: some View {
        List {
            if model.customRules.isEmpty {
                ContentUnavailableView("还没有自定义规则", systemImage: "list.bullet.indent",
                                       description: Text("自定义规则对所有配置生效，并优先于配置自带的规则。"))
            } else {
                Section {
                    ForEach(Array(model.customRules.enumerated()), id: \.offset) { _, rule in
                        RuleRow(parts: RuleParts(rule), reason: skipped[rule])
                    }
                    .onDelete { offsets in
                        var rules = model.customRules
                        rules.remove(atOffsets: offsets)
                        save(rules)
                    }
                    .onMove { from, to in
                        var rules = model.customRules
                        rules.move(fromOffsets: from, toOffset: to)
                        save(rules)
                    }
                } footer: {
                    Text(model.active ? "已连接：修改后需要重新连接才会生效。" : "越靠前优先级越高；点「编辑」可拖动排序。")
                }
            }
            if model.active {
                Section {
                    Button("重新连接以生效") { Task { await model.reconnect() } }
                        .disabled(model.busy)
                }
            }
            if let failure { Section { Text(failure).foregroundStyle(.red) } }
        }
        .navigationTitle("自定义规则")
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                if !model.customRules.isEmpty { EditButton() }
                Menu("添加", systemImage: "plus") {
                    Button("添加规则", systemImage: "plus") { adding = true }
                    Button("批量编辑", systemImage: "text.alignleft") { bulk = true }
                }
            }
        }
        .sheet(isPresented: $adding) {
            AddRuleView(targets: model.customRuleTargets()) { rule in
                try model.saveCustomRules([rule] + model.customRules)
                refresh()
            }
        }
        .sheet(isPresented: $bulk) {
            BulkRulesView(rules: model.customRules) { rules in
                try model.saveCustomRules(rules)
                refresh()
            }
        }
        .onAppear(perform: refresh)
    }

    private func save(_ rules: [String]) {
        do {
            try model.saveCustomRules(rules)
            failure = nil
            refresh()
        } catch { failure = error.localizedDescription }
    }

    private func refresh() {
        skipped = model.skippedCustomRules()
    }
}

private struct RuleRow: View {
    let parts: RuleParts
    let reason: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(parts.value).font(.body.monospaced()).lineLimit(2)
                Spacer()
                Text(parts.target).foregroundStyle(.secondary)
            }
            HStack(spacing: 6) {
                Text(parts.label)
                if parts.noResolve { Text("· 不解析域名") }
            }
            .font(.caption).foregroundStyle(.secondary)
            if let reason {
                Text("\(reason)，当前配置下不生效").font(.caption).foregroundStyle(.red)
            }
        }
    }
}

private struct AddRuleView: View {
    let targets: [String]
    let save: (String) throws -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var type = ruleTypes[0].type
    @State private var value = ""
    @State private var target = ""
    @State private var noResolve = false
    @State private var failure: String?

    private var acceptsNoResolve: Bool { ["IP-CIDR", "IP-CIDR6", "GEOIP"].contains(type) }

    var body: some View {
        NavigationStack {
            Form {
                Picker("类型", selection: $type) {
                    ForEach(ruleTypes, id: \.type) { Text($0.label).tag($0.type) }
                }
                TextField(ruleTypes.first { $0.type == type }?.placeholder ?? "", text: $value)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .font(.body.monospaced())
                Picker("目标", selection: $target) {
                    ForEach(targets, id: \.self) { Text($0).tag($0) }
                }
                if acceptsNoResolve { Toggle("不解析域名", isOn: $noResolve) }
                if let failure { Text(failure).foregroundStyle(.red) }
            }
            .navigationTitle("添加规则").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("添加") {
                        let parts = [type, value.trimmingCharacters(in: .whitespaces), target]
                            + (acceptsNoResolve && noResolve ? ["no-resolve"] : [])
                        do {
                            try save(parts.joined(separator: ","))
                            dismiss()
                        } catch { failure = error.localizedDescription }
                    }
                    .disabled(value.trimmingCharacters(in: .whitespaces).isEmpty || target.isEmpty)
                }
            }
            .onAppear { if target.isEmpty { target = targets.first ?? "DIRECT" } }
        }
    }
}

private struct BulkRulesView: View {
    let rules: [String]
    let save: ([String]) throws -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""
    @State private var failure: String?

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if let failure {
                    Text(failure).font(.footnote).foregroundStyle(.red)
                        .frame(maxWidth: .infinity, alignment: .leading).padding(12)
                }
                TextEditor(text: $text)
                    .font(.system(.footnote, design: .monospaced))
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .padding(.horizontal, 8)
                Text("每行一条，格式为「类型,值,目标」，越靠前优先级越高。")
                    .font(.caption).foregroundStyle(.secondary).padding(12)
            }
            .navigationTitle("批量编辑").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") {
                        let lines = text.split(whereSeparator: \.isNewline)
                            .map { $0.trimmingCharacters(in: .whitespaces) }
                            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
                        do {
                            try save(lines)
                            dismiss()
                        } catch { failure = error.localizedDescription }
                    }
                }
            }
            .onAppear { text = rules.joined(separator: "\n") }
        }
    }
}
