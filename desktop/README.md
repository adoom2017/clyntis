# Clyntis Desktop

Windows 10/11 x64 与 macOS 13+（Apple Silicon / Intel）的 Tauri 2 桌面客户端。
界面使用 React、TypeScript、Vite；本目录是独立的 npm / Cargo workspace。
原 CLI 和 C ABI 的构建入口不变。

## 开发

需要 Node.js 22.12+、Rust 1.93.1，以及根 README 中列出的 BoringSSL 原生工具链。
macOS 需要 Xcode command-line tools / Swift；Windows 需要 MSVC、CMake、NASM、LLVM/libclang
和 WebView2。Windows 构建环境可参考 `../scripts/check-boringssl-toolchain.ps1`。

在本目录执行：

```sh
npm ci
npm run desktop:dev
```

`desktop:dev` 先构建 runner、辅助服务及 macOS 原生适配程序，再启动 Tauri。
仅运行 `npm run dev` 会启动网页开发服务器，网页没有桌面宿主，不能管理真实内核。
普通代理模式可直接在开发环境使用；macOS 辅助服务需要完整的 Developer ID 签名并公证的应用包。
不提供跳过签名检查或以 root 启动 WebView 的开发后门。

## 功能与配置行为

- 六个页面：概览、代理节点、配置管理、网络连接、运行日志、设置；简体中文、浅色/深色/系统主题。
- 手动代理、系统代理、TUN 为互斥接管方式。默认手动代理，登录启动和自动连接默认关闭。
- 导入本地 YAML，或下载 HTTPS 完整 YAML 订阅；不转换 Base64 列表和单节点链接。
- 严格使用现有内核支持范围。Trojan、Hysteria2 及未知字段会拒绝启用，不自动降级或删除节点。
- 原始 YAML、待应用版本、上一版本保存在同一原子写入文档中；运行副本从 YAML 文档生成，
  不使用会省略凭据的 `Serialize(Config)`。原文注释保留；运行副本的格式可能变化。
- 桌面设置覆盖混合监听端口、LAN 开关、接管方式、物理接口、TUN 自动 DNS；
  控制接口固定回环随机端口与随机凭据，不开放外部 UI。
- 每个配置单独保存资源和内核状态。导入会复制配置目录内已存在的 GeoIP/GeoSite 与规则资源。
  TUN 启动将现有资源按受限相对路径传给辅助服务，最多 128 MiB；服务存储与普通模式隔离。
- 订阅默认每 24 小时检查，应用启动补查过期项；下载超时 30 秒、上限 24 MiB，失败保留旧版本。
  更新仅标记“待应用”，不会自动断开现有连接。应用或切换配置时重启，启动失败恢复上次运行配置。
- 代理模式即时生效并保存；节点选择由内核配置缓存持久化。
- 关闭窗口隐藏到托盘。托盘退出和系统正常退出先恢复代理/TUN/DNS，再终止内核。
- 日志最多保留 2,000 条，显示和导出前隐藏 URL、UUID 与常见凭据字段。

应用数据：macOS 的 `~/Library/Application Support/org.clyntis.desktop`；Windows 的
`%APPDATA%\org.clyntis.desktop`（以 Tauri `app_data_dir()` 为准）。配置包含凭据，属于本地私有数据，
不是加密保险库；不要提交该目录。删除配置会一并删除其本地历史和普通模式缓存。

## 进程与接口

```text
React → Tauri commands/events → Rust desktop host
                                ├─ private stdio → unprivileged runner
                                └─ authenticated local IPC → service → TUN runner
```

`../crates/runtime` 复用 CLI 的 TUN、DNS、出口切换和退出生命周期。
每个 runner 只承载一个内核，避免全局日志订阅器与运行实例相互影响。
普通 runner 通过继承的 stdin 接收版本化 JSON 帧，stdout 仅用于握手/结果；stdin EOF 即停止。
宿主用 Rust HTTP/WebSocket 客户端访问回环控制接口，前端不接触控制令牌。

服务 IPC v1 提供状态、心跳、停止、启动、代理接管和受限资源传输。
Windows 使用拒绝远程客户端的命名管道，仅允许交互用户/管理员/System 连接，
并要求调用进程来自 Program Files 下同一安装目录的桌面程序。
macOS 使用 Unix socket，要求调用者为当前桌面用户，且其**运行中进程**通过同 Team ID、
指定 bundle identifier 的 Apple 代码签名校验。服务不接受任意可执行文件或任意文件路径。
服务单会话持有网络状态，独立心跳每 5 秒发送；30 秒失联或连接关闭即清理。

Windows 系统代理在用户 runner 中通过 WinINet/当前用户注册表操作；macOS 由服务通过
SystemConfiguration 操作物理网络服务。修改前写入恢复日志，崩溃后恢复；发现外部修改时
保留该网络服务的完整当前设置并报告冲突。服务启动时恢复残留 TUN/DNS 日志。

## 安装、签名与发布

```sh
npm run desktop:build
```

产物位于 `target/release/bundle/`：Windows NSIS 安装包、macOS `.app` / DMG。
脚本按宿主架构构建；交叉构建时，先安装对应 Rust target，运行
`CLYNTIS_DESKTOP_TARGET=<target> node packaging/prepare.mjs`，再将同一 `--target` 传给 Tauri。
推荐按平台/架构分别使用本机构建机器。

Windows 安装到 Program Files；首次在设置页安装服务时触发 UAC。
打包脚本下载固定版本官方 Wintun 0.14.1，校验 SHA-256，并附带其许可证。
升级/卸载钩子先停止和卸载服务，网络恢复失败时中止操作。
NSIS 使用 Tauri 的 `bundle.windows` 签名配置（证书、时间戳或 `signCommand`）；凭据由发布环境注入。

macOS 将应用移至 `/Applications` 后，在设置页安装后台服务；SMAppService 可能要求在系统设置中
允许后台运行。正式构建设置 Tauri 的 `APPLE_SIGNING_IDENTITY`，并提供
`APPLE_ID` / `APPLE_PASSWORD` / `APPLE_TEAM_ID` 或 App Store Connect API 凭据完成公证。
服务、runner、原生适配程序和主应用必须使用同一个 Developer ID Team。
构建时还需设置公开的 `CLYNTIS_SIGNING_TEAM_ID`（打包脚本默认取 `APPLE_TEAM_ID`）；
服务将 runner 和原生适配程序复制到 root 私有目录，校验固定 Team ID 与程序 identifier 后才执行，
防止应用目录被替换后导致提权执行未经验证的程序。
未签名 CI 包仅用于构建与普通代理验证，不能视为已验证的 TUN 发行版。
删除 macOS 应用前先在设置中卸载后台服务，完成网络恢复。

## 验证

```sh
npm test
npm run build
node packaging/prepare.mjs --debug
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
python3 tests/runner_integration.py target/debug/clyntis-runner
```

Windows 的最后一条命令使用 `python` 和 `clyntis-runner.exe`。
回环集成测试覆盖真实进程握手、认证、模式切换、HTTP 代理、正常停止和宿主 EOF，
不需要真实节点，也不修改系统代理或 TUN。根目录原有测试仍需单独运行。
`.github/workflows/desktop.yml` 在 Windows x64、macOS arm64/x64 上构建并测试。

发布前必须在两平台完成：首次授权/拒绝授权、系统代理与 TUN 接管、端口冲突、配置回滚、
强制关闭宿主、强制关闭 runner、服务重启、休眠唤醒、切换网络、DNS/路由恢复、外部代理设置冲突、
全新安装、升级、卸载，以及使用真实 VLESS 测试节点的连通性验证。
这些检查会改变系统网络，应在测试机执行，不能用回环测试或 CI 成功代替。

首版不包含 Linux GUI、Windows ARM64、自动升级、云同步、订阅转换、新协议或可视化规则编辑器。
