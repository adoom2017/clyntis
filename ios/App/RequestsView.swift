import SwiftUI
import UniformTypeIdentifiers

/// One entry of the core's request log (`meta_requests_v1`).
struct RequestEntry: Decodable, Equatable {
    struct Http: Decodable, Equatable {
        let method: String
        let url: String
        let decrypted: Bool
        let status: Int?
        let contentType: String?
        let requestSize: Int64
        let responseSize: Int64
        let error: String?
        /// Rewrite rules that acted: `action (module)`, comma-separated.
        let rewrite: String?
    }
    let id: UInt64
    /// Unix milliseconds.
    let time: Double
    let network: String
    let source: String
    let host: String
    let port: Int
    let rule: String
    let chain: String
    /// rejected, closed or http.
    let status: String
    /// Milliseconds.
    let duration: Double
    let upload: Int64
    let download: Int64
    let connection: String
    let reason: String?
    let requests: Int
    let http: Http?

    var date: Date { Date(timeIntervalSince1970: time / 1000) }
    var target: String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }
}

struct RequestPage: Decodable {
    let requests: [RequestEntry]
    let next: UInt64
}

struct RequestDetail: Decodable {
    struct Body: Decodable, Equatable {
        let size: Int64
        let truncated: Bool
        let decoded: Bool
        let text: String?
        let base64: String?
    }
    let requestHeaders: [[String]]?
    let responseHeaders: [[String]]?
    let requestBody: Body?
    let responseBody: Body?
}

/// The running core's decryption status (the snapshot's `mitm`).
struct MitmStatus: Decodable, Equatable {
    let enable: Bool
    let active: Bool
    let error: String?
    let bypassed: [String]

    static func decode(_ object: Any?) -> MitmStatus? {
        guard let object, let data = try? JSONSerialization.data(withJSONObject: object) else { return nil }
        return try? JSONDecoder().decode(MitmStatus.self, from: data)
    }
}

private struct Row: Identifiable, Equatable {
    /// The core generation and the entry id: ids start over with a new core.
    let id: String
    let entry: RequestEntry
    let generation: Int
}

private enum Filter: String, CaseIterable {
    case all, http, rejected, connections
    var title: String {
        switch self {
        case .all: L("全部")
        case .http: "HTTP"
        case .rejected: L("已拦截")
        case .connections: L("连接")
        }
    }
    func matches(_ entry: RequestEntry) -> Bool {
        switch self {
        case .all: true
        case .http: entry.status == "http"
        case .rejected: entry.status == "rejected"
        case .connections: entry.status == "closed"
        }
    }
}

private func duration(_ ms: Double) -> String {
    ms < 1000 ? "\(Int(ms)) ms" : String(format: ms < 10_000 ? "%.1f s" : "%.0f s", ms / 1000)
}

private func bytes(_ value: Int64) -> String {
    value.formatted(.byteCount(style: .binary, spellsOutZero: false))
}

/// Recent requests through the tunnel: connections, refused ones and, for
/// decrypted or plain HTTP hosts, each HTTP request.
struct RequestsView: View {
    @Bindable var model: AppModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var rows: [Row] = []
    @State private var cursor: UInt64 = 0
    @State private var generation = 0
    @State private var paused = false
    @State private var filter = Filter.all
    @State private var query = ""
    @State private var failure: String?
    @State private var confirmClear = false

    /// Rows kept in the app; the tunnel keeps 500 itself.
    private static let limit = 2000

    private var visible: [Row] {
        let words = query.lowercased().split(separator: " ").map(String.init)
        return rows.reversed().filter { row in
            guard filter.matches(row.entry) else { return false }
            guard !words.isEmpty else { return true }
            let e = row.entry
            let text = "\(e.host) \(e.http?.url ?? "") \(e.rule) \(e.chain) \(e.http?.contentType ?? "")".lowercased()
            return words.allSatisfy(text.contains)
        }
    }

    var body: some View {
        List {
            Section {
                NavigationLink { MitmView(model: model) } label: {
                    LabeledContent {
                        Text(mitmSummary)
                    } label: {
                        Label(L("HTTPS 解密"), systemImage: "lock.open")
                    }
                }
            }
            Section {
                Picker(L("筛选"), selection: $filter) {
                    ForEach(Filter.allCases, id: \.self) { Text($0.title).tag($0) }
                }
                .pickerStyle(.segmented)
                .listRowBackground(Color.clear)
                .listRowInsets(EdgeInsets())
            }
            if let failure {
                Text(failure).font(.footnote).foregroundStyle(.red)
            }
            if !model.connected && rows.isEmpty {
                ContentUnavailableView(L("未连接"), systemImage: "waveform.badge.magnifyingglass",
                                       description: Text(L("连接后记录经过代理的请求。")))
            } else if visible.isEmpty {
                ContentUnavailableView(rows.isEmpty ? L("暂无请求") : L("无匹配结果"),
                                       systemImage: "waveform.badge.magnifyingglass")
            }
            Section {
                ForEach(visible.prefix(500)) { row in
                    NavigationLink {
                        RequestDetailView(model: model, entry: row.entry, current: row.generation == generation)
                    } label: {
                        RequestRow(entry: row.entry)
                    }
                }
            } footer: {
                if visible.count > 500 {
                    Text(L("显示最近 500 条，共 {count} 条", ["count": visible.count]))
                }
            }
        }
        .searchable(text: $query, prompt: L("搜索域名、URL 或规则"))
        .navigationTitle(L("抓包"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            Button(paused ? L("继续") : L("暂停"), systemImage: paused ? "play.fill" : "pause.fill") {
                paused.toggle()
            }
            if model.connected {
                Menu(L("导出"), systemImage: "square.and.arrow.up") {
                    ShareLink(item: RequestExport(csv: false, model: model),
                              preview: SharePreview(L("HAR（HTTP 请求和内容）"))) {
                        Label(L("HAR（HTTP 请求和内容）"), systemImage: "doc.text")
                    }
                    ShareLink(item: RequestExport(csv: true, model: model),
                              preview: SharePreview(L("CSV（全部记录）"))) {
                        Label(L("CSV（全部记录）"), systemImage: "tablecells")
                    }
                }
            }
            Button(L("清空"), systemImage: "trash") { confirmClear = true }
                .disabled(rows.isEmpty)
        }
        .confirmationDialog(L("清空所有记录？"), isPresented: $confirmClear, titleVisibility: .visible) {
            Button(L("清空"), role: .destructive) {
                Task {
                    if model.connected { try? await model.clearRequests() }
                    rows = []
                }
            }
        }
        .task(id: model.connected && !paused && scenePhase == .active) {
            guard model.connected, !paused, scenePhase == .active else { return }
            while !Task.isCancelled {
                await poll()
                try? await Task.sleep(for: .seconds(1.5))
            }
        }
    }

    private var mitmSummary: String {
        guard model.overrides.mitm?.enable == true else { return L("未开启") }
        if let error = model.mitm?.error { return error }
        return model.mitm?.active == true ? L("已开启") : L("重新连接后生效")
    }

    private func poll() async {
        do {
            // A full log arrives in pages.
            for _ in 0..<4 {
                let page = try await model.fetchRequests(after: cursor)
                if page.next < cursor {
                    // A new core: its ids start over. Keep what is shown.
                    generation += 1
                    cursor = 0
                    continue
                }
                cursor = page.next
                if !page.requests.isEmpty {
                    rows += page.requests.map { Row(id: "\(generation):\($0.id)", entry: $0, generation: generation) }
                    if rows.count > Self.limit { rows.removeFirst(rows.count - Self.limit) }
                }
                if page.requests.count < 300 { break }
            }
            failure = nil
        } catch {
            if model.connected { failure = error.localizedDescription }
        }
    }
}

/// The tunnel's request log as a file to share: fetched when the user picks
/// where it goes. HAR opens in Charles, Proxyman and browser tools; CSV in
/// spreadsheets.
private struct RequestExport: Transferable {
    let csv: Bool
    let model: AppModel

    static var transferRepresentation: some TransferRepresentation {
        FileRepresentation(exportedContentType: .data) { item in
            let data = try await item.model.exportRequests(csv: item.csv)
            let stamp = Date().formatted(.iso8601.year().month().day().time(includingFractionalSeconds: false)
                .dateSeparator(.omitted).timeSeparator(.omitted).dateTimeSeparator(.standard))
            let url = FileManager.default.temporaryDirectory
                .appendingPathComponent("clyntis-requests-\(stamp).\(item.csv ? "csv" : "har")")
            try data.write(to: url, options: .atomic)
            return SentTransferredFile(url)
        }
    }
}

private struct RequestRow: View {
    let entry: RequestEntry

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if let http = entry.http, let url = URL(string: http.url) {
                Text(url.host() ?? entry.host).font(.subheadline.weight(.medium)).lineLimit(1)
                Text(url.path() + (url.query().map { "?" + $0 } ?? ""))
                    .font(.caption.monospaced()).foregroundStyle(.secondary)
                    .lineLimit(2).truncationMode(.middle)
            } else {
                Text(entry.target).font(.subheadline.monospaced()).lineLimit(1).truncationMode(.middle)
                    .foregroundStyle(entry.status == "rejected" ? .red : .primary)
            }
            HStack(spacing: 6) {
                Text(tag)
                    .font(.caption2.weight(.semibold)).foregroundStyle(.tint)
                    .padding(.horizontal, 5).padding(.vertical, 1)
                    .background(.tint.opacity(0.12), in: .capsule)
                Text(state).foregroundStyle(stateColor)
                if entry.http?.rewrite != nil {
                    Text(L("已重写")).foregroundStyle(.tint)
                }
                Text("\(entry.rule) → \(entry.chain)").lineLimit(1)
                Spacer()
                Text(entry.date, format: .dateTime.hour().minute().second()).monospacedDigit()
            }
            .font(.caption).foregroundStyle(.secondary)
        }
    }

    private var tag: String {
        guard let http = entry.http else { return entry.network.uppercased() }
        return http.decrypted ? "\(http.method) 🔓" : http.method
    }
    private var state: String {
        if let http = entry.http {
            if let status = http.status { return "\(status) · \(bytes(http.responseSize))" }
            return http.error == nil ? "—" : L("失败")
        }
        if entry.status == "rejected" { return L("已拦截") }
        if entry.requests > 0 { return L("{count} 个请求", ["count": entry.requests]) }
        return bytes(entry.download + entry.upload)
    }
    private var stateColor: Color {
        if entry.status == "rejected" || entry.http?.error != nil || (entry.http?.status ?? 0) >= 400 { return .red }
        return .secondary
    }
}

/// One request: what it asked for, how it was routed, and for HTTP its
/// headers and bodies.
struct RequestDetailView: View {
    @Bindable var model: AppModel
    let entry: RequestEntry
    /// Whether the entry is from the running core (else details are gone).
    let current: Bool
    @State private var detail: RequestDetail?
    @State private var failure: String?
    @State private var confirmBlock = false
    @State private var blocked: String?

    var body: some View {
        List {
            Section {
                if let http = entry.http {
                    Text(http.url).font(.footnote.monospaced()).textSelection(.enabled)
                }
                LabeledContent(L("时间"), value: entry.date.formatted(date: .abbreviated, time: .standard))
                LabeledContent(L("规则"), value: "\(entry.rule) → \(entry.chain)")
                if !entry.source.isEmpty { LabeledContent(L("来源"), value: entry.source) }
                if let status = entry.http?.status { LabeledContent(L("状态码"), value: "\(status)") }
                if let type = entry.http?.contentType { LabeledContent(L("内容类型"), value: type) }
                if let rewrite = entry.http?.rewrite { LabeledContent(L("重写"), value: rewrite) }
                if let reason = entry.http?.error ?? entry.reason {
                    LabeledContent(L("结束原因"), value: reason)
                }
                if entry.status != "rejected" { LabeledContent(L("耗时"), value: duration(entry.duration)) }
            }
            Section {
                if let http = entry.http {
                    Button(L("复制 URL"), systemImage: "doc.on.doc") { UIPasteboard.general.string = http.url }
                }
                if entry.chain != "REJECT" {
                    Button(L("屏蔽此域名"), systemImage: "nosign", role: .destructive) { confirmBlock = true }
                }
            } footer: {
                if let blocked { Text(blocked) }
            }
            if entry.http != nil {
                if let failure {
                    Text(failure).font(.footnote).foregroundStyle(.secondary)
                } else if !current {
                    Text(L("内核已重启或记录已被清理，详情不可用。")).font(.footnote).foregroundStyle(.secondary)
                } else if let detail {
                    HeadersSection(title: L("请求头"), headers: detail.requestHeaders)
                    BodySection(title: L("请求内容"), content: detail.requestBody)
                    HeadersSection(title: L("响应头"), headers: detail.responseHeaders)
                    BodySection(title: L("响应内容"), content: detail.responseBody)
                } else {
                    ProgressView()
                }
            }
        }
        .navigationTitle(entry.http.map { "\($0.method) \(entry.host)" } ?? entry.host)
        .navigationBarTitleDisplayMode(.inline)
        .confirmationDialog(L("屏蔽此域名"), isPresented: $confirmBlock, titleVisibility: .visible) {
            Button("DOMAIN,\(entry.host)", role: .destructive) { block(subdomains: false) }
            Button("DOMAIN-SUFFIX,\(entry.host)", role: .destructive) { block(subdomains: true) }
        } message: {
            Text(L("添加为自定义 REJECT 规则，重新连接后生效。"))
        }
        .task {
            guard entry.http != nil, current, model.connected else { return }
            do { detail = try await model.requestDetail(entry.id) }
            catch { failure = error.localizedDescription }
        }
    }

    private func block(subdomains: Bool) {
        do {
            try model.blockDomain(entry.host, subdomains: subdomains)
            blocked = L("已添加规则，重新连接后生效。")
        } catch {
            blocked = error.localizedDescription
        }
    }
}

private struct HeadersSection: View {
    let title: String
    let headers: [[String]]?
    var body: some View {
        Section(title) {
            if let headers, !headers.isEmpty {
                ForEach(Array(headers.enumerated()), id: \.offset) { _, pair in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(pair.first ?? "").font(.caption).foregroundStyle(.secondary)
                        Text(pair.count > 1 ? pair[1] : "").font(.footnote.monospaced()).textSelection(.enabled)
                    }
                }
            } else {
                Text(L("无")).foregroundStyle(.secondary)
            }
        }
    }
}

private struct BodySection: View {
    let title: String
    let content: RequestDetail.Body?
    @State private var pretty = true

    private var shown: String {
        guard let body = content else { return "" }
        if let text = body.text {
            if pretty, let data = text.data(using: .utf8),
               let object = try? JSONSerialization.jsonObject(with: data),
               let formatted = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .withoutEscapingSlashes]),
               let string = String(data: formatted, encoding: .utf8) {
                return string
            }
            return text
        }
        return L("二进制内容（base64）") + "\n" + String((body.base64 ?? "").prefix(20_000))
    }

    var body: some View {
        Section {
            if let body = content, body.size > 0 {
                Text(String(shown.prefix(100_000))).font(.caption.monospaced()).textSelection(.enabled)
            } else {
                Text(L("无内容")).foregroundStyle(.secondary)
            }
        } header: {
            HStack {
                Text(title)
                Spacer()
                if content?.text != nil {
                    Button(pretty ? L("原文") : L("格式化")) { pretty.toggle() }.font(.caption).textCase(nil)
                }
            }
        } footer: {
            if let body = content, body.size > 0 {
                Text([bytes(body.size), body.decoded ? L("已解压") : nil, body.truncated ? L("只保留了开头部分") : nil]
                    .compactMap { $0 }.joined(separator: " · "))
            }
        }
    }
}

/// HTTPS decryption: the switch, the hosts, and the certificate iOS must
/// trust.
struct MitmView: View {
    @Bindable var model: AppModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var authority = MitmAuthority.load()
    @State private var check: MitmAuthority.Check?
    @State private var trusted = false
    @State private var hosts = ""
    @State private var failure: String?
    @State private var confirmRegenerate = false
    @State private var server: ProfileServer?

    private var settings: MitmSettings { model.overrides.mitm ?? MitmSettings() }

    var body: some View {
        List {
            Section {
                Toggle(L("HTTPS 解密"), isOn: Binding(get: { settings.enable }, set: { on in
                    Task {
                        await run {
                            // Turning it on the first time makes the certificate too.
                            if on && authority == nil { try await generate() }
                            var next = settings
                            next.enable = on
                            try await model.saveMitm(next)
                        }
                    }
                }))
                if settings.enable {
                    LabeledContent(L("状态"), value: status)
                }
            } footer: {
                Text(L("对下面列出的域名做中间人解密，记录完整的 URL、请求头和内容。需要先生成证书并让系统信任它。使用证书固定（pinning）的应用会拒绝解密，这些域名会自动改为直接转发。只在分析时开启，用完关掉。"))
            }
            Section {
                if let check {
                    LabeledContent(L("名称"), value: check.ca.name)
                    LabeledContent("SHA-256", value: String(check.ca.fingerprint.prefix(23)) + "…")
                    LabeledContent(L("系统信任")) {
                        Text(trusted ? L("已信任") : L("未信任")).foregroundStyle(trusted ? Color.green : .red)
                    }
                    if !trusted {
                        Button(L("安装描述文件"), systemImage: "arrow.down.doc") { Task { await install(check) } }
                        Button(L("检查信任状态"), systemImage: "checkmark.shield") { refresh() }
                    }
                    Button(L("重新生成"), systemImage: "arrow.clockwise", role: .destructive) { confirmRegenerate = true }
                } else {
                    Button(L("生成证书"), systemImage: "key") { Task { await run { try await generate() } } }
                }
            } header: {
                Text(L("CA 证书"))
            } footer: {
                if check != nil && !trusted {
                    Text(L("安装：点「安装描述文件」，在 Safari 中允许下载，然后到 设置 → 通用 → VPN 与设备管理 安装。信任：再到 设置 → 通用 → 关于本机 → 证书信任设置，打开它的完全信任。"))
                }
            }
            Section {
                TextEditor(text: $hosts)
                    .font(.footnote.monospaced())
                    .frame(minHeight: 100)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button(L("保存")) {
                    Task {
                        await run {
                            var next = settings
                            next.hostnames = list(hosts)
                            try await model.saveMitm(next)
                        }
                    }
                }
                .disabled(list(hosts) == settings.hostnames)
            } header: {
                Text(L("解密的域名（每行一个）"))
            } footer: {
                Text(L("* 匹配任意字符，以 - 开头表示排除。填 * 会解密所有 HTTPS 流量，不建议长期使用。"))
            }
            if let bypassed = model.mitm?.bypassed, !bypassed.isEmpty {
                Section {
                    ForEach(bypassed, id: \.self) { Text($0).font(.footnote.monospaced()) }
                    Button(L("重试这些域名")) { Task { await run { try await model.clearMitmBypass() } } }
                } header: {
                    Text(L("拒绝解密、已改为直接转发的域名"))
                }
            }
            if let failure {
                Text(failure).font(.footnote).foregroundStyle(.red)
            }
        }
        .navigationTitle(L("HTTPS 解密"))
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            hosts = settings.hostnames.joined(separator: "\n")
            refresh()
        }
        // Back from Settings after installing or trusting the certificate.
        .onChange(of: scenePhase) { _, phase in if phase == .active { refresh() } }
        .confirmationDialog(L("重新生成证书？"), isPresented: $confirmRegenerate, titleVisibility: .visible) {
            Button(L("重新生成"), role: .destructive) { Task { await run { try await generate() } } }
        } message: {
            Text(L("旧证书将失效，需要重新安装并信任新证书。"))
        }
    }

    private var status: String {
        if authority == nil { return L("需要先生成证书") }
        if let error = model.mitm?.error { return error }
        if !trusted { return L("证书未被系统信任") }
        if settings.hostnames.isEmpty { return L("还没有填写要解密的域名") }
        if !model.connected { return L("连接后生效") }
        return model.mitm?.active == true ? L("已开启") : L("重新连接后生效")
    }

    private func list(_ text: String) -> [String] {
        text.split(whereSeparator: { $0 == "\n" || $0 == "," })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    private func refresh() {
        authority = MitmAuthority.load()
        check = authority.flatMap { try? $0.check() }
        trusted = check.map(MitmAuthority.trusted) ?? false
    }

    private func generate() async throws {
        _ = try await model.generateAuthority()
        refresh()
    }

    private func install(_ check: MitmAuthority.Check) async {
        await run {
            let server = try ProfileServer(profile: try MitmAuthority.profile(check))
            self.server = server
            try await server.open()
        }
    }

    private func run(_ action: () async throws -> Void) async {
        do {
            try await action()
            failure = nil
        } catch {
            failure = error.localizedDescription
        }
    }
}
