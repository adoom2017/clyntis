# macOS 迁移与验证交接

> 历史记录：以下分支、构建产物和命令保留迁移时的真实名称；当前项目名称为
> `clyntis`。现行操作请参阅 [README](../README.md) 和 [平台说明](platform-runtime.md)。

更新时间：2026-09-23（Asia/Shanghai）

这份文件记录 `meta-rust` 分支迁移到 macOS 前的实际状态、已验证边界和
Mac 上应执行的验收步骤。它不包含任何正式节点地址、UUID、密码、REALITY
密钥或控制器密钥。

## 1. 固定源码状态

- 分支：`meta-rust`
- 本文档编写前的实现基线：`adebb14b0962cac51770ba002e85d9f30c4e61b7`
- Rust：`rustc 1.93.1 (01f6ddf75 2026-02-11)`
- Cargo：`cargo 1.93.1 (083ac5135 2025-12-15)`
- `Cargo.lock` SHA-256：
  `3a284db911c6bf0b5bc51f4c7918872f0375e79544a72eb009ab0855538c3515`
- 编写本文档前工作区干净。
- `rustls`、`tokio-rustls`、`quinn`、`h3`、`h3-quinn` 不在 workspace
  依赖树中。TLS 后端只有仓库补丁版 BoringSSL 5.2.0。

最近关键提交：

| 提交 | 内容 |
| --- | --- |
| `adebb14b` | 默认让物理直连网段、广播、组播和链路本地地址绕过 TUN |
| `df6c4794` | Clash 风格逻辑连接日志和真实物理远端 IP 日志 |
| `3a211d64` | 多个 XUDP 逻辑流复用 VLESS 物理连接 |
| `49ca7513` | 补齐 VLESS transport 兼容性 |
| `807ade80` | BoringSSL-only VLESS、REALITY、Vision 和浏览器指纹基础 |
| `fea93302` | Windows TUN 手工验收说明和配置 |

迁移后先执行：

```bash
git branch --show-current
git log -8 --oneline
git status --short
shasum -a 256 Cargo.lock
```

分支应为 `meta-rust`，工作区应为空，锁文件哈希应与上面一致。本文档本身
可能位于实现基线之后的交接提交中，因此最终 `HEAD` 可以晚于 `adebb14b`。

## 2. 当前支持范围

### 2.1 运行时协议

- VLESS TCP
- VLESS WebSocket，包括 path、headers、early-data 和 HTTP Upgrade
- VLESS gRPC/Gun，包括 service name、user-agent、ping 和连接池限制
- 普通 TLS（BoringSSL）
- REALITY
- `xtls-rprx-vision`，仅允许 `network: tcp`
- UDP over VLESS 和 XUDP
- XUDP 物理连接池

Trojan 和 Hysteria2 仅允许配置解析和分组引用。实际选中时会返回“协议不可用”，
没有 QUIC/H3 运行代码。

### 2.2 TLS 指纹

- Chrome 149、Chrome Android 149
- Firefox 151
- Safari 26.4、iOS Safari 26.4
- Edge 148
- Mihomo/uTLS 的 360 和 QQ preset
- `random` 和受约束的 `randomized`

配置接受 `chrome`、`firefox`、`safari`、`ios`、`android`、`edge`、`360`、
`qq`、`random`、`randomized`。`rustls` 会返回配置错误。Chrome 和 Firefox
ClientHello 有冻结 fixture 测试。V1 只承诺 TLS ClientHello 指纹，不承诺
WebSocket HTTP/1 header 顺序或 gRPC HTTP/2 SETTINGS 与浏览器一致。

### 2.3 入口、规则和 DNS

- HTTP、HTTP CONNECT、SOCKS5、mixed 和显式启用的 TUN
- Rule、Global、Direct 模式
- DOMAIN、DOMAIN-SUFFIX、DOMAIN-KEYWORD、DOMAIN-REGEX
- IP-CIDR/IP-CIDR6、DST-PORT、NETWORK
- GEOIP、GEOSITE、RULE-SET、AND/OR/NOT、MATCH
- `rule-providers`、GeoIP/GeoSite 资源下载和更新
- UDP/TCP DNS、DoT、DoH、缓存、hosts、Fake-IP 和 DNS hijack
- select 和 url-test 分组
- 带 Bearer secret 的精简控制接口、连接列表、流量和日志 WebSocket

不支持完整 Mihomo 功能集，例如 VMess、Shadowsocks、TUIC、XHTTP、订阅型
proxy providers 和进程规则。

### 2.4 TUN 和局域网绕过

TUN 数据面是 Rust/smoltcp，不包含 Go gVisor。配置中的 `stack` 名称可以兼容
读取，但不会切换到 Go 实现。

自动路由默认绕过：

- 当前物理出口接口的所有直接连接前缀
- `169.254.0.0/16`
- `224.0.0.0/4`
- `255.255.255.255/32`
- `fe80::/10`
- `ff00::/8`

这些流量留在操作系统网络栈中，不进入用户态 TUN 转发。
`tun.route-exclude-address` 会在默认集合上继续追加用户范围。

## 3. 已完成验证

在实现基线 `adebb14b` 上：

- `cargo test --workspace --locked` 通过：77 项通过，3 项因需要管理员原生
  TUN 或外部 Xray oracle 而忽略。
- `cargo clippy --workspace --all-targets --locked -- -D warnings` 通过。
- `cargo fmt --all -- --check` 通过。
- 正式私有配置通过 `-t --vless-only`，但文件本身未提交。
- BoringSSL Chrome 149 和 Firefox 151 ClientHello fixture 测试通过。
- 本地 TLS、VLESS TCP、WS、gRPC、UDP/XUDP、session resumption 和
  REALITY/Vision 冻结测试通过。

Windows 实机已验证过：

- mixed 端口同时支持 HTTP 和 SOCKS5。
- HTTP CONNECT 和 SOCKS5h 访问 Google HTTPS 返回 204。
- TUN 接管后，不显式配置代理也能访问 Google HTTPS。
- `meta-rust Tunnel` 网卡正常启用，Fake-IP 能恢复域名并转发。
- 控制器 secret 生效，未认证请求返回 401。
- `df6c4794` 日志版本能显示 `[TCP]`、`[UDP]` 和 `[OUTBOUND]` 的真实远端。

最新 `adebb14b` 的默认本地网络绕过已通过单元、workspace 和 Clippy 验证，
但尚未由用户在 Windows 或 macOS 上完成特权 TUN 实机验收。

## 4. macOS 代码准备情况

代码已经包含以下 macOS 路径：

- `tun-rs` 创建原生 `utun`。
- 默认设备名让 macOS 自动选择可用 `utunN`；显式设备名必须是 `utunN`。
- `route_manager` 添加、删除和恢复系统路由。
- `netdev` 使用 Apple SystemConfiguration 获取接口、网关和 DNS。
- 出站 TCP/UDP 使用接口索引绑定物理出口。
- 路由事务在修改前写入 journal，正常退出恢复；异常退出可用
  `--recover-tun` 清理。
- BoringSSL build script 包含 `x86_64-apple-darwin`、
  `aarch64-apple-darwin` 和 Apple CMake 参数。
- release 脚本会生成 CLI、`libmeta_ffi.dylib` 和 `libmeta_ffi.a`。
- 默认 `MACOSX_DEPLOYMENT_TARGET=12.0`。

当前仓库虽然配置了 macOS 14 Apple Silicon 和 macOS Intel CI matrix，但本次
Windows 会话没有真实 Mac、Xcode 或 CI 运行结果，不能把“存在 macOS 代码路径”
当作“已通过 macOS 验收”。

## 5. 将仓库复制到 Mac

推荐使用本次交接生成的 Git bundle：

```bash
git clone /path/to/meta-rust-macos-handoff.bundle Clash.Meta
cd Clash.Meta
git switch meta-rust
```

如果从远端仓库克隆，必须确认远端 `origin/meta-rust` 已包含本文档和上述提交：

```bash
git clone --branch meta-rust https://github.com/adoom2017/Clash.Meta.git
cd Clash.Meta
git rev-parse HEAD
git log -8 --oneline
```

正式配置没有进入 Git。请单独使用加密介质或安全通道复制，并在 Mac 上限制权限：

```bash
chmod 600 /private/path/config-new.yaml
```

不要把正式配置、日志中的节点凭据或解密文件提交回仓库。

## 6. macOS 构建环境

建议使用 macOS 12 或更高版本，在 Intel 和 Apple Silicon 上分别做原生构建。

```bash
xcode-select --install
brew install cmake llvm powershell

export PATH="$(brew --prefix llvm)/bin:$PATH"
export LIBCLANG_PATH="$(brew --prefix llvm)/lib"
export MACOSX_DEPLOYMENT_TARGET=12.0

rustup toolchain install 1.93.1 \
  --profile minimal \
  --component rustfmt,clippy
rustup override set 1.93.1
```

先执行完整质量检查：

```bash
cargo fetch --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --release --locked
```

定向确认指纹：

```bash
cargo test -p meta-protocol \
  tls::tests::chrome_149_client_hello_matches_official_capture -- --exact
cargo test -p meta-protocol \
  tls::tests::firefox_151_client_hello_matches_catalog -- --exact
```

创建本机 release 包使用 Bash 和 Python 3，无需 PowerShell：

```bash
bash scripts/package-release.sh
```

脚本按当前架构生成单架构包。仓库尚未自动创建 Universal Binary，也未执行
Apple codesign/notarization；对外分发前必须单独补充这些步骤。

## 7. 分阶段运行验证

以下命令假设正式配置位于 `/private/path/config-new.yaml`。

### 7.1 配置与规则资源

不需要 root：

```bash
./target/release/meta-rust \
  -f /private/path/config-new.yaml \
  -t \
  --vless-only

./target/release/meta-rust \
  -f /private/path/config-new.yaml \
  --test-resources \
  --vless-only
```

第二条会访问配置指定的 GeoIP、GeoSite 和 rule-provider 资源。

### 7.2 先验证 HTTP/SOCKS，不启用 TUN

```bash
./target/release/meta-rust \
  -f /private/path/config-new.yaml \
  --no-tun \
  --vless-only
```

另开终端，按配置实际 mixed 端口测试。下例使用 `7892`：

```bash
curl --proxy http://127.0.0.1:7892 \
  --connect-timeout 10 --max-time 30 \
  -o /dev/null -w 'http status=%{http_code} total=%{time_total}\n' \
  https://www.google.com/generate_204

curl --proxy socks5h://127.0.0.1:7892 \
  --connect-timeout 10 --max-time 30 \
  -o /dev/null -w 'socks status=%{http_code} total=%{time_total}\n' \
  https://www.google.com/generate_204
```

两项都应返回 204。

### 7.3 启动原生 utun

先正常停止 `--no-tun` 实例。为路由恢复 journal 创建固定目录：

```bash
sudo mkdir -p /var/db/meta-rust
sudo ./target/release/meta-rust \
  -f /private/path/config-new.yaml \
  -d /var/db/meta-rust \
  --vless-only
```

不要添加 `--no-tun`。默认设备配置应让系统自动分配 `utunN`，不要依赖固定编号。

另开终端检查：

```bash
ifconfig | grep -A 6 '^utun'
netstat -rn -f inet
netstat -rn -f inet6
scutil --dns

curl --noproxy '*' --connect-timeout 10 --max-time 30 \
  -o /dev/null -w 'tun status=%{http_code} total=%{time_total}\n' \
  https://www.google.com/generate_204
```

TUN 请求应返回 204，日志应显示逻辑目标、命中规则、选中分组/节点，以及
VLESS 物理服务器的真实 IP。

## 8. macOS 必做验收矩阵

### 8.1 路由与本地绕过

- 记录启动前后的 `netstat -rn -f inet` 和 `inet6`。
- 确认默认 split route 指向 utun。
- 确认当前物理接口直连网段仍走 `en0`/`en1` 等物理接口。
- 确认 `255.255.255.255`、IPv4/IPv6 组播和链路本地不进入 TUN 日志。
- 检查 `tun.route-exclude-address` 的自定义范围。
- DNS hijack 开启时，确认系统 DNS 的专用主机路由仍按配置进入 TUN。

示例：

```bash
route -n get 255.255.255.255
route -n get 192.168.1.1
route -n get 8.8.8.8
```

前两项应选择物理接口，普通公网目标应按 TUN 配置选择 utun。

### 8.2 协议

- VLESS TCP + TLS
- VLESS TCP + REALITY
- VLESS TCP + `xtls-rprx-vision`
- VLESS WebSocket
- VLESS gRPC
- UDP 和 XUDP
- Chrome、Firefox 各至少一个真实远端节点

缺少相应公网节点时，使用本地 Xray oracle。需要设置 `XRAY_BIN` 后运行被忽略的
interop 测试；不要把远端凭据写入测试源码。

### 8.3 生命周期

- `Ctrl+C` 正常停止后，新增路由全部删除。
- Wi-Fi 切换、有线/无线切换后，约 3–10 秒内重新发现物理出口并重连。
- 睡眠/唤醒后新连接可用。
- 与其他 VPN 按不同启动顺序测试，确认不删除对方路由。
- 在维护窗口测试异常终止；若保留 journal，运行：

```bash
sudo ./target/release/meta-rust \
  -d /var/db/meta-rust \
  --recover-tun
```

恢复后再次检查 IPv4/IPv6 路由。不要手工删除 journal 后跳过恢复。

## 9. 日志和控制接口

`log-level: info` 已包含 Clash 风格连接信息：

```text
[OUTBOUND] local-ip:port --> real-server-ip:port connecting node(server:port) for target
[TCP] source --> target match Rule using Group[node]
[UDP] source --> target match Rule using Group[node]
```

如果配置没有 `log.log-path`，日志写入启动终端。活动连接可通过带 Bearer secret 的
`GET /connections` 查看。`GET /logs` 是 WebSocket。不要在 shell history 中直接写
控制器 secret。

## 10. 当前未完成与风险

- 尚无真实 macOS 构建成功记录。
- 尚无 macOS utun、路由、DNS、切网、睡眠和异常恢复验收记录。
- 尚无 Intel/Apple Silicon 双架构包对比。
- 尚未生成 Universal Binary。
- 尚未 codesign 或 notarize。
- macOS 与第三方 VPN、企业 DNS、NetworkExtension 产品共存情况未知。
- TUN 原生集成测试默认 ignored，需要 root 且会修改隔离测试路由。
- Xray REALITY/Vision 外部 oracle 测试需要明确提供 `XRAY_BIN`。
- 当前只支持 VLESS 运行时；正式配置中若某个可选择分支最终指向
  Trojan/Hysteria2，会在选择时失败。

## 11. macOS 验收完成条件

只有同时满足以下条件，才能把状态从“可迁移”改为“macOS 已支持”：

1. Intel 或 Apple Silicon 原生 workspace test、Clippy 和 release build 通过。
2. 对应架构的无 TUN HTTP/SOCKS 验证通过。
3. root utun 下 IPv4/IPv6、DNS/Fake-IP、TCP 和 UDP/XUDP 通过。
4. 局域网、广播、组播默认绕过真实生效。
5. 正常退出、切网和异常恢复不会残留或误删路由。
6. 至少 Chrome 和 Firefox ClientHello fixture 在 Mac 上通过。
7. 记录 Mac 型号、CPU 架构、macOS/Xcode/Rust 版本、提交 SHA、测试命令和日志。

完成后更新本文件、`docs/platform-runtime.md` 和 `docs/continuation.md`，明确区分
编译验证、协议验证和特权 TUN 实机验证。
