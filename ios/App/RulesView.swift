import SwiftUI

/// Rule types offered when adding a custom rule.
private let ruleTypes: [(type: String, label: String, placeholder: String)] = [
    ("DOMAIN-SUFFIX", L("域名后缀"), "example.com"),
    ("DOMAIN", L("完整域名"), "www.example.com"),
    ("DOMAIN-KEYWORD", L("域名关键字"), "example"),
    ("DOMAIN-WILDCARD", L("域名通配符"), "*cdn*.example.com"),
    ("IP-CIDR", L("IPv4 段"), "10.0.0.0/8"),
    ("IP-CIDR6", L("IPv6 段"), "2001:db8::/32"),
    ("GEOSITE", "GeoSite", "cn"),
    ("GEOIP", "GeoIP", "CN"),
    ("DST-PORT", L("目标端口"), L("443 或 8000-9000")),
    ("NETWORK-NAME", L("所在网络"), L("配置 networks 中的名称，如 home")),
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
            RouteTestSection(model: model)
            DnsLeakSection(model: model)
            if model.customRules.isEmpty {
                ContentUnavailableView(L("还没有自定义规则"), systemImage: "list.bullet.indent",
                                       description: Text(L("自定义规则对所有配置生效，并优先于配置自带的规则。")))
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
                    Text(model.active ? L("已连接：修改后需要重新连接才会生效。") : L("越靠前优先级越高；点「编辑」可拖动排序。"))
                }
            }
            if model.active {
                Section {
                    Button(L("重新连接以生效")) { Task { await model.reconnect() } }
                        .disabled(model.busy)
                }
            }
            if let failure { Section { Text(failure).foregroundStyle(.red) } }
        }
        .navigationTitle(L("自定义规则"))
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                if !model.customRules.isEmpty { EditButton() }
                Menu(L("添加"), systemImage: "plus") {
                    Button(L("添加规则"), systemImage: "plus") { adding = true }
                    Button(L("批量编辑"), systemImage: "text.alignleft") { bulk = true }
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

/// Which rule a domain or address matches in the running core and the node
/// it leaves through.
private struct RouteTestSection: View {
    let model: AppModel
    @State private var target = ""
    @State private var network = "tcp"
    @State private var testing = false
    @State private var result: RouteTest?
    @State private var failure: String?

    private static let matchText = [
        "Adblock": L("去广告拦截（优先于所有规则）"),
        "Adblock(HTTPDNS)": L("去广告：HTTPDNS / 加密 DNS 入口"),
        "Adblock(IP)": L("去广告：列表中的 IP"),
        "Adblock(QUIC)": L("去广告：没有域名的 QUIC，回退到 TCP"),
        "Mode(Global)": L("全局模式"),
        "Mode(Direct)": L("直连模式"),
        "Fallback": L("没有规则匹配，默认直连"),
    ]

    private var trimmed: String { target.trimmingCharacters(in: .whitespaces) }

    var body: some View {
        Section {
            TextField(L("域名或 IP，如 www.google.com"), text: $target)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                .keyboardType(.URL).font(.body.monospaced())
                .submitLabel(.search).onSubmit(test)
            Picker(L("网络"), selection: $network) {
                Text("TCP").tag("tcp")
                Text("UDP").tag("udp")
            }
            .pickerStyle(.segmented)
            Button(action: test) {
                HStack {
                    Text(L("测试"))
                    if testing { Spacer(); ProgressView() }
                }
            }
            .disabled(!model.connected || testing || trimmed.isEmpty)
            if let failure { Text(failure).foregroundStyle(.red) }
            if let result {
                LabeledContent(L("目标")) {
                    VStack(alignment: .trailing, spacing: 2) {
                        Text("\(result.host.contains(":") ? "[\(result.host)]" : result.host):\(result.port)")
                        if let ip = result.ip, ip != result.host {
                            Text(L("解析为 {ip}", ["ip": ip])).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                LabeledContent(L("匹配规则")) {
                    VStack(alignment: .trailing, spacing: 2) {
                        Text(result.rule ?? Self.matchText[result.matched] ?? result.matched)
                            .font(result.rule == nil ? .body : .footnote.monospaced())
                            .multilineTextAlignment(.trailing)
                        if let rule = result.rule, let index = result.index {
                            Text(L("第 {index} 条", ["index": index + 1]) + (model.customRules.contains(rule) ? L(" · 自定义规则") : ""))
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                LabeledContent(L("出站节点")) {
                    VStack(alignment: .trailing, spacing: 2) {
                        Text(result.node).fontWeight(.semibold)
                            .foregroundStyle(result.node == "REJECT" ? .red : .primary)
                        if result.chain.count > 1 {
                            Text(result.chain.joined(separator: " → "))
                                .font(.caption).foregroundStyle(.secondary)
                                .multilineTextAlignment(.trailing)
                        }
                        if result.resolvedLocally, !["DIRECT", "REJECT"].contains(result.node) {
                            Text(L("匹配前已在本地解析域名，存在 DNS 泄露"))
                                .font(.caption).foregroundStyle(.red)
                                .multilineTextAlignment(.trailing)
                        }
                    }
                }
            }
        } header: {
            Text(L("路由测试"))
        } footer: {
            if !model.connected { Text(L("连接 VPN 后可测试域名或 IP 会匹配哪条规则、从哪个节点出站。")) }
        }
    }

    private func test() {
        guard model.connected, !testing, !trimmed.isEmpty else { return }
        testing = true
        failure = nil
        Task {
            defer { testing = false }
            do { result = try await model.testRoute(trimmed, network: network) }
            catch {
                result = nil
                failure = error.localizedDescription
            }
        }
    }
}

/// Configuration review and the online bash.ws test.
private struct DnsLeakSection: View {
    let model: AppModel
    @State private var audit: DnsLeakResult.Audit?
    @State private var test: DnsLeakResult.Test?
    @State private var testing = false
    @State private var failure: String?

    var body: some View {
        Section {
            if let audit {
                Label(audit.leaking ? L("配置检查发现 DNS 泄露风险")
                        : audit.findings.isEmpty ? L("配置检查未发现问题") : L("配置检查未发现泄露，但有以下提示"),
                      systemImage: audit.leaking ? "exclamationmark.shield" : "checkmark.shield")
                    .foregroundStyle(audit.leaking ? .red : .primary)
                ForEach(audit.findings, id: \.code) { finding in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 6) {
                            Text(Self.levelText[finding.level] ?? finding.level)
                                .font(.caption.bold()).foregroundStyle(Self.levelColor(finding.level))
                            Text(finding.title).font(.subheadline.weight(.semibold))
                        }
                        Text(finding.detail).font(.caption).foregroundStyle(.secondary)
                        ForEach(finding.items, id: \.self) { item in
                            Text(item).font(.caption.monospaced()).lineLimit(2)
                        }
                    }
                }
            }
            Button(action: runTest) {
                HStack {
                    Text(testing ? L("检测中…") : L("在线检测"))
                    if testing { Spacer(); ProgressView() }
                }
            }
            .disabled(!model.connected || testing)
            if let failure { Text(failure).foregroundStyle(.red) }
            if let test {
                LabeledContent(L("出口 IP")) {
                    VStack(alignment: .trailing, spacing: 2) {
                        ForEach(test.exit, id: \.ip) { server in
                            Text(server.ip)
                            Text(Self.place(server)).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                Text(test.node == "DIRECT"
                     ? L("bash.ws 当前经「{node}」（{matched}）访问，结果反映直连时的情况。", ["node": test.node, "matched": test.matched])
                     : L("bash.ws 当前经「{node}」（{matched}）访问。", ["node": test.node, "matched": test.matched]))
                    .font(.caption).foregroundStyle(.secondary)
                probe(L("应用访问时的解析器"), test.routed, verdict: test.verdict)
                probe(L("内核上游 DNS 的解析器"), test.local)
            }
        } header: {
            Text(L("DNS 泄露检测"))
        } footer: {
            Text(model.connected
                 ? L("配置检查在本地完成；在线检测会向 bash.ws 发送随机域名，并暴露出口和解析器的 IP。")
                 : L("连接 VPN 后可检测。"))
        }
        .task(id: model.connected) { await check() }
    }

    private static var levelText: [String: String] { ["risk": L("泄露"), "warning": L("注意"), "info": L("提示")] }

    private static func levelColor(_ level: String) -> Color {
        switch level {
        case "risk": .red
        case "warning": .orange
        default: .secondary
        }
    }

    private static func place(_ server: DnsLeakResult.Server) -> String {
        [server.country, server.asn].filter { !$0.isEmpty }.joined(separator: " · ")
    }

    private static let verdictText = [
        "leak": L("存在泄露：本地上游看到了走代理的域名"),
        "ok": L("未发现泄露"),
        "direct": L("直连，无代理路径可检查"),
        "unknown": L("无法判断"),
    ]

    /// `verdict` judges the routed probe; the local one only lists who resolves locally.
    private func probe(_ title: String, _ probe: DnsLeakResult.Probe, verdict: String? = nil) -> some View {
        let leaking = probe.error != nil || verdict == "leak"
        let status = probe.error
            ?? verdict.map { Self.verdictText[$0] ?? $0 }
            ?? (probe.resolvers.isEmpty ? L("没有结果") : L("本地解析由这些服务器完成"))
        return VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(title).font(.subheadline.weight(.semibold))
                Spacer()
                Text(status).font(.caption).foregroundStyle(leaking ? .red : .secondary)
            }
            ForEach(probe.resolvers, id: \.ip) { server in
                HStack(alignment: .firstTextBaseline) {
                    Text(server.ip).font(.caption.monospaced())
                    Spacer()
                    Text(Self.place(server)).font(.caption).foregroundStyle(.secondary)
                        .multilineTextAlignment(.trailing)
                }
            }
        }
    }

    private func check() async {
        guard model.connected else {
            audit = nil
            test = nil
            return
        }
        do { audit = try await model.dnsLeak(online: false).audit }
        catch { failure = error.localizedDescription }
    }

    private func runTest() {
        guard model.connected, !testing else { return }
        testing = true
        failure = nil
        Task {
            defer { testing = false }
            do {
                let result = try await model.dnsLeak(online: true)
                audit = result.audit
                test = result.test
            } catch { failure = error.localizedDescription }
        }
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
                if parts.noResolve { Text(L("· 不解析域名")) }
            }
            .font(.caption).foregroundStyle(.secondary)
            if let reason {
                Text(L("{reason}，当前配置下不生效", ["reason": reason])).font(.caption).foregroundStyle(.red)
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
                Picker(L("类型"), selection: $type) {
                    ForEach(ruleTypes, id: \.type) { Text($0.label).tag($0.type) }
                }
                TextField(ruleTypes.first { $0.type == type }?.placeholder ?? "", text: $value)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .font(.body.monospaced())
                Picker(L("目标"), selection: $target) {
                    ForEach(targets, id: \.self) { Text($0).tag($0) }
                }
                if acceptsNoResolve { Toggle(L("不解析域名"), isOn: $noResolve) }
                if let failure { Text(failure).foregroundStyle(.red) }
            }
            .navigationTitle(L("添加规则")).navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L("取消")) { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(L("添加")) {
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
                Text(L("每行一条，格式为「类型,值,目标」，越靠前优先级越高。"))
                    .font(.caption).foregroundStyle(.secondary).padding(12)
            }
            .navigationTitle(L("批量编辑")).navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L("取消")) { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(L("保存")) {
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
