# 桌面客户端自动更新

## 用户行为

支持 Windows x64（NSIS 安装版）、macOS Apple Silicon 和 Intel（macOS 13 及以上）。

- 默认在启动约 20 秒后检查，之后每 6 小时检查一次。离线等检查失败会在约 15 分钟后重试。
- 在“设置 → 通用”关闭“自动检查客户端更新”后点击“保存”，即可停止后续后台检查。手动检查仍可使用。
- 检测到新版本后，主界面提示“查看更新”；“设置 → 客户端更新”显示当前版本、上次检查时间和版本说明。
- 用户点击“下载更新”后显示下载进度。下载和签名校验均通过后，才显示“安装并重启”。
- 安装前明确确认连接会中断。确认后停止内核并恢复代理、路由和 DNS，再调用原生安装流程。
- 下载失败、签名不匹配或版本签名不匹配不会停止当前代理；可以重试。
- 网络恢复失败会取消安装，并阻止本次进程继续尝试安装。先重启客户端，排查并确认网络恢复，再重试。
- 安装失败时保留应用并显示错误。代理可能已经停止，需要用户重新连接。

自动化部分是定时检查；下载和安装由用户控制，以免后台升级中断 TUN、流媒体或其他连接。

## 更新链路与安全边界

后端使用 Tauri 2 updater。前端仅调用本项目的四个命令：`app_update_state`、`check_app_update`、`download_app_update`、`install_app_update`。不开放 updater 插件的直接安装权限。

更新公钥和清单 URL 在构建时嵌入应用，不接受前端或普通用户配置覆盖。默认更新地址：

```text
https://github.com/adoom2017/clyntis/releases/latest/download/latest.json
```

构建时可以通过 `CLYNTIS_UPDATER_ENDPOINT` 指定其他 HTTPS 地址。官方工作流使用默认地址；fork 仓库发布时，应修改默认地址或在构建步骤中设置该变量。

更新包使用独立的 minisign 密钥签名，客户端强制验证签名及签名中绑定的版本号（`requireSignedVersion: true`）。清单的版本必须大于当前版本；不允许通过更新入口降级。生成包要求 Tauri CLI >= 2.12.0，updater >= 2.13.1。

所有检查、下载和安装使用同一把后端互斥锁。安装还持有内核生命周期锁，避免开始代理、切换配置或退出与应用替换交错。下载时不持有内核锁。下载事件最多约每 150ms 推送一次，避免高速下载频繁刷新 UI。

Windows 仍走已有 NSIS per-machine 安装器及 `hooks.nsh`：恢复网络、移除旧服务、保护安装目录、替换文件并重新注册原有服务。可能出现管理员授权；安装器负责完成安装并重新启动客户端。启动安装器失败时不提前运行 Tauri 的退出清理。

macOS 替换完整 `.app` 并重启。主程序和辅助程序继续使用相同 Developer ID Team ID；启动后已有的辅助服务版本检查负责更新服务，必要时由系统请求授权。请先把应用从 DMG 移到可正常安装的位置（通常是 `/Applications`）。

更新包保存在当前进程内存中，退出后需重新下载；不提供断点续传。检查请求超时 30 秒，单次下载总超时 15 分钟。更新请求沿用系统/环境代理设置，可以在 Clyntis 连接期间下载，随后再恢复网络并安装。

## 首次配置签名

更新包签名密钥与 Apple Developer ID 证书相互独立，二者都不能用占位内容代替。不要把私钥放进仓库。

在受控开发机执行一次（以下使用 PowerShell 示例，密钥写入仓库以外的位置）：

```powershell
cd desktop
npx tauri signer generate --write-keys "$env:USERPROFILE/clyntis-updater.key"
```

妥善备份生成的私钥及密码。公钥在旁边的 `.pub` 文件中，是一整行 base64 文本；需要保留外层 base64 编码，不要解码后填写。已有客户端内置固定公钥，后续发布必须继续使用同一私钥；更换密钥需要先设计信任迁移，不能直接替换仓库变量。

在 GitHub 仓库配置以下 Actions variables / secrets：

| 类型 | 名称 | 内容 |
| --- | --- | --- |
| Variable | `CLYNTIS_UPDATER_PUBLIC_KEY` | `.pub` 文件的完整一行公钥 |
| Secret | `TAURI_SIGNING_PRIVATE_KEY` | 私钥文件的完整内容 |
| Secret | `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | 私钥密码；无密码密钥可留空 |
| Secret | `APPLE_CERTIFICATE` | 含私钥的 Developer ID Application `.p12` 文件的 base64 |
| Secret | `APPLE_CERTIFICATE_PASSWORD` | `.p12` 密码 |
| Variable | `APPLE_SIGNING_IDENTITY` | 完整 Developer ID Application 证书名称或 SHA-1 指纹；单一身份时可留空 |
| Variable | `APPLE_TEAM_ID` | 签名证书的 Team ID |
| Secret | `APPLE_ID` | 用于公证的 Apple ID |
| Secret | `APPLE_PASSWORD` | 此 Apple ID 的应用专用密码 |

macOS 发布工作流导入临时钥匙串，签名、公证后删除临时钥匙串和证书文件。Windows 更新签名使用 minisign；这不等同于 Windows Authenticode 签名，现有 Windows 代码签名策略保持不变。

## 构建与发布

普通验证包不要求更新密钥，并关闭 updater artifacts 和自动更新入口：

```powershell
node packaging/build.mjs --unsigned
```

本地生成可更新的 Windows 安装器：

```powershell
$env:CLYNTIS_UPDATER_PUBLIC_KEY = (Get-Content "$env:USERPROFILE/clyntis-updater.key.pub" -Raw).Trim()
$env:TAURI_SIGNING_PRIVATE_KEY = "$env:USERPROFILE/clyntis-updater.key"
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = "<私钥密码>"
node packaging/build.mjs --updater --bundles nsis
```

macOS 在已导入并解锁 Developer ID 证书、设置公钥/更新私钥及 Apple 公证环境变量后执行：

```sh
node packaging/build.mjs --updater --target aarch64-apple-darwin --bundles app,dmg
node packaging/build.mjs --updater --target x86_64-apple-darwin --bundles app,dmg
```

`--updater` 控制更新包生成。Tauri 的 `--no-sign` 会同时跳过平台代码签名和更新包签名，因此脚本在所有平台拒绝 `--unsigned/--no-sign` 与 `--updater` 组合。Windows 不配置 Authenticode 证书时仍可生成 minisign 签名的更新包；macOS 更新发布还必须使用 Developer ID 签名。缺少更新公钥或私钥时，`--updater` 会在构建前报错。

带参数的构建示例直接调用 Node 脚本，避免部分 Windows PowerShell/npm shim 吞掉 `--` 分隔符而丢失签名选项。

正式发布使用 `.github/workflows/release-desktop.yml`，替代原来的 Windows 单平台发布工作流：

1. 使用现有 `scripts/set-version.sh` 同步应用和 Rust crate 版本，再创建对应的稳定 `vX.Y.Z` tag。
2. 三个构建任务生成 Windows x64 NSIS、macOS arm64、macOS x64 更新包及 `.sig`。macOS 主包和辅助程序使用同一 Team ID 签名并公证；Windows CLI/C 库压缩包仍保留。
3. 收集器将同名的两个 macOS `.app.tar.gz` 重命名为包含架构的文件，避免覆盖；同时保留 `.dmg` 手动安装包。
4. 只有三个任务全部成功，才执行汇总发布。生成器检查三种平台的包和签名都存在且非空，生成统一 `latest.json`。
5. 上传全部产物，再上传清单，最后发布 draft release。不会在任一平台构建失败时发布部分平台的新清单。

清单的平台键是 `windows-x86_64`、`darwin-aarch64`、`darwin-x86_64`。URL 指向固定版本 tag 的附件；只有清单入口使用 `latest`。重新运行失败的工作流可覆盖同一版本附件，已经正式使用的版本应保持不可变，优先递增 patch 版本发布修复。

首次带更新能力的版本需要手动安装。旧版客户端不包含此入口，无法自行升级为支持自动更新的版本。未配置正式签名凭据时，普通本地构建仍可运行，但不能成为正式更新分发包。

## 验证与验收

自动化检查：

```sh
cd desktop
npm test
npm run build
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

新增测试覆盖旧设置兼容与关闭自动检查、事件和初始状态竞争、失败重试、下载进度、重复点击互斥、安装必须确认、版本说明按纯文本展示、签名配置检查、架构包重命名与不完整发布拒绝。

本次 Windows 开发机验证结果：43 项前端测试、39 项 Rust 测试、TypeScript/Vite 生产构建、Rust fmt/Clippy 和发布工作流 actionlint 均通过。已使用临时测试密钥生成 Windows NSIS 安装器及 `.sig`，使用与客户端相同的 `minisign-verify` 库验证签名和绑定版本，并确认篡改安装器会被拒绝；包收集器已在真实产物上执行通过。临时私钥已删除，测试包不可作为正式发布包。未执行实际覆盖安装，也未在此 Windows 环境验证 macOS 签名、公证和设备升级。

正式启用前需要在三种目标平台，用相同正式密钥签名的连续两个版本进行真实升级验收：

| 场景 | 预期 |
| --- | --- |
| 手动检查、启动后台检查 | 正确识别版本和本机架构；相同版本不提示更新 |
| 关闭自动检查并重启 | 不发送后台检查；手动检查可用 |
| 下载时断网、超时 | 显示错误并可重试，当前代理保持运行 |
| 篡改更新包、签名或清单版本 | 校验失败，不出现安装按钮、不停止代理 |
| 手动代理、系统代理、TUN 三种状态安装 | 安装前恢复网络，安装后配置和订阅保留，自动连接沿用原设置 |
| 网络恢复失败 | 阻止安装，显示错误；须重启并排查后再试 |
| Windows 管理员授权取消/安装器启动失败 | 显示失败；当前应用仍可使用；可重新连接代理 |
| Windows 辅助服务已安装/未安装 | 保留既有服务使用状态，安装目录 ACL 校验通过 |
| macOS 从 DMG、只读目录运行 | 安装失败应显示错误；迁移到正常安装目录后重试 |
| macOS 两种架构升级 | app、runner、service 和 service manager 签名及 Team ID 一致；服务版本可更新 |

本文件描述了实现和验收流程；配置工作流不代表已发布正式版本，也不代表已完成 macOS 设备或系统安装器的真实升级验收。
