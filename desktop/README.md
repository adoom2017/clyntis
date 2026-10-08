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

- 七个页面：概览、节点、配置、规则、连接、日志、设置；简体中文、浅色/深色/系统主题，
  配色采用 Apple 系统色。已连接时 macOS 状态栏图标缓慢旋转，并随浅色/深色菜单栏切换颜色。
- 手动代理、系统代理、TUN 为互斥接管方式。默认手动代理，登录启动和自动连接默认关闭。
- 导入本地 YAML，或下载 HTTPS 完整 YAML 订阅；不转换 Base64 列表和单节点链接。
- 配置可加密导出（设置密码）；导入加密文件或添加加密订阅时输入密码，订阅密码随配置保存，
  每次更新自动解密。
- 导入文件或新增订阅时，只保留兼容项（VLESS 与 Tailscale 节点）并生成独立的新配置，不覆盖原文件或已有配置。Trojan、Hysteria2、未知字段和无效项会被跳过，并立即显示清单；失效的代理组成员与规则引用也会清理。兼容节点的凭据及规则集 URL 保留。无法解析的 YAML 仍会报错。
- 编辑、启用及订阅更新继续严格校验内核支持范围。
- 原始 YAML、待应用版本、上一版本保存在同一原子写入文档中；运行副本从 YAML 文档生成，
  不使用会省略凭据的 `Serialize(Config)`。原文注释保留；运行副本的格式可能变化。
- 桌面设置覆盖混合监听端口、LAN 开关、接管方式、物理接口、TUN 自动 DNS（默认开启：
  局域网 DNS 走物理网卡、不经过 TUN，不接管时配置里的 DNS 不生效）；
  控制接口固定回环随机端口与随机凭据，不开放外部 UI。
- 「覆盖配置文件」设置：日志级别、IPv6、域名嗅探，选「跟随配置文件」时使用配置自身的值；
  修改后自动重启内核生效。合并逻辑在内核中，与 iOS 一致。
- 规则页的自定义规则对所有配置生效，排在配置自带规则之前；可单条添加、拖动排序或批量编辑。
  当前配置缺少目标代理/代理组或规则集的规则会被跳过并标注原因，不影响启动。
- 节点页显示每个节点的状态：VLESS 的服务器、传输、TLS/REALITY、最近一次测速结果或失败原因
  及当前连接数；Tailscale 的登录状态、本机名称与地址、DERP 主区域、公网候选，以及每个
  tailnet 节点是否在线、直连（含往返延迟）还是经 DERP 中继。打开时每 3 秒刷新，点开查看详情。
- Tailscale 节点（`type: tailscale`）由内核的 Rust 实现直接加入 tailnet，无需安装 Tailscale
  App，可与代理同时使用；字段与限制见根 README。登录状态保存在配置的资源目录中。
- 每个配置单独保存资源和内核状态。导入会复制配置目录内已存在的 GeoIP/GeoSite 与规则资源。
  TUN 启动将现有资源按受限相对路径传给辅助服务，最多 128 MiB；服务存储与普通模式隔离。
- TUN 模式下多个网络同时可用时优先使用有线连接；当前出口仍可用就不切换，避免偶发的探测失败
  导致全部连接断开。休眠唤醒或 Wi-Fi 切换导致短暂没有出口时，内核保持运行并在网络恢复后重新
  设置 DNS。配置开启 IPv6 时，只有物理网卡有 IPv6 出口才接管 IPv6。
- 订阅默认每 24 小时检查，应用启动补查过期项；下载超时 30 秒、上限 24 MiB，失败保留旧版本。
  更新仅标记“待应用”，不会自动断开现有连接。应用或切换配置时重启，启动失败恢复上次运行配置。
- 代理模式即时生效并保存；节点选择由内核配置缓存持久化。
- 关闭窗口隐藏到托盘。托盘退出和系统正常退出先恢复代理/TUN/DNS，再终止内核。
- 日志最多保留 2,000 条，显示和导出前隐藏 URL、UUID 与常见凭据字段。
- 启动失败等桌面错误写入应用数据目录下的 `clyntis-runner.log`；普通模式的内核标准错误写入
  `profiles/<配置 ID>/runtime/clyntis-runner.log`，TUN 模式则写入服务配置目录。日志脱敏后按 1 MiB
  轮转并保留一份历史日志。内核退出时优先显示退出码和实际错误，便于区分路由失败与进程崩溃。

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
脚本按宿主架构构建；交叉构建时，先安装对应 Rust target，再运行
`npm run desktop:build -- --target <target>`，辅助程序和主应用会使用同一目标架构。
推荐按平台/架构分别使用本机构建机器。

Windows 安装到 Program Files；首次在设置页安装服务时触发 UAC。
打包脚本下载固定版本官方 Wintun 0.14.1，校验 SHA-256，并附带其许可证。
升级/卸载钩子先停止和卸载服务，网络恢复失败时中止操作。
NSIS 使用 Tauri 的 `bundle.windows` 签名配置（证书、时间戳或 `signCommand`）；凭据由发布环境注入。

macOS 的 `desktop:build` 自动从本机钥匙串选择唯一的有效 **Developer ID Application**
证书（需要对应私钥），提取 Team ID 并写入辅助服务构建环境；不选择 Apple Development 或
Mac App Store 证书。如果有多张证书，用 `APPLE_SIGNING_IDENTITY` 指定完整名称或 SHA-1 指纹：

```sh
APPLE_SIGNING_IDENTITY='Developer ID Application: Your Name (YOURTEAMID)' npm run desktop:build
```

脚本先签名服务、runner 和原生适配程序，再由 Tauri 签名主应用及 DMG，启用 Hardened Runtime
和安全时间戳；打包结束后校验各程序的固定 identifier 与同一 Team ID。已设置的
`CLYNTIS_SIGNING_TEAM_ID` 或 `APPLE_TEAM_ID` 必须与证书一致，否则构建立即报错。
时间戳需要能连接 Apple 签名服务器。无证书的 CI/普通代理验证显式使用
`npm run desktop:build -- --unsigned`，该包不支持 macOS 系统代理和 TUN。

签名与公证是独立步骤。对外分发时，还需提供
`APPLE_ID` / `APPLE_PASSWORD` / `APPLE_TEAM_ID` 或 App Store Connect API 凭据，由 Tauri 完成公证。
将签名应用移至 `/Applications` 后，在设置页安装后台服务；SMAppService 可能要求在系统设置中
允许后台运行。安装按钮不会注销已启用的服务。更新应用包后，已运行的服务仍可能持有旧内核；
需要在系统设置中关闭再开启对应后台项目，或由管理员执行
`sudo launchctl kickstart -k system/org.clyntis.desktop.service` 重启已注册的服务。
服务以 `ProcessType: Interactive` 运行：后台级别（`Background`）的进程会被 macOS 限制 TCP
接收窗口，TUN 下载会降到约 100 KB/s。launchd 缓存已注册的 plist，修改其中的
`ProcessType` 后需要重启 Mac 或在设置页卸载再安装服务才会生效；更新应用包本身不会重新注册。
如果提示 `Operation not permitted` 且服务未注册，先重新允许后台项目，再安装；此时 kickstart 不适用。
服务、runner、原生适配程序和主应用必须使用同一个 Developer ID Team；
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
全新安装、升级、卸载，以及使用真实 VLESS 测试节点与 Tailscale tailnet（直连与 DERP 中继）的连通性验证。
这些检查会改变系统网络，应在测试机执行，不能用回环测试或 CI 成功代替。

首版不包含 Linux GUI、Windows ARM64、自动升级、云同步、订阅转换，以及 VLESS、Tailscale 以外的出站协议。

### 辅助服务自动更新

应用启动时会检查已安装的后台服务；首次使用 TUN 或 macOS 系统代理时自动安装。
应用与运行中的服务通过 IPC 比较构建指纹，旧版服务缺少指纹也会触发更新。
指纹由共享 Rust 模型的 build.rs 根据内核、服务、runner、平台脚本和依赖锁文件生成，
同一套源码构建的主应用及 sidecar 必须一起分发；可通过 CLYNTIS_BUILD_ID 区分发布构建。

更新与连接操作串行执行，先停止当前内核并恢复网络。macOS 保留 SMAppService 注册，
发送 SIGTERM 让服务完成清理，再由 launchd KeepAlive 启动新版并刷新受保护的辅助程序副本；
权限不足时弹出带用途说明的管理员授权。Windows 经 UAC 停止服务、更新注册路径并启动。
界面同时说明授权用于虚拟网卡、路由、DNS 和系统代理。若 macOS 要求允许后台项目，
会打开系统设置并提示授权后再次启动；取消授权不再继续连接，也不会循环弹窗。
只有重连确认构建指纹一致才允许使用服务，最长等待 75 秒；无需手动卸载重装。

验证发布包时，应从旧版已运行服务覆盖升级，检查启动时更新、授权取消、后台项目禁用、
服务启动失败，以及第二次启动不再更新。未签名开发包不能验证 macOS 特权更新流程。
