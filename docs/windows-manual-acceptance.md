# Windows 手动验收说明与记录

本文供你自行验证 Windows 10/11 x64。先验证 DIRECT + TUN，再验证真实
Reality/Vision 节点，最后测试切网和恢复。测试配置验证通过不等于运行验收通过。
当前 Windows TUN 尚未实测；请按实际结果填写文末表格，未测试的项目填“未测”。

## 1. 准备管理员窗口、程序和驱动

打开两个 **管理员 PowerShell** 窗口：开始菜单搜索 PowerShell → 右键 →
以管理员身份运行 → 确认 UAC。窗口 A 运行程序，窗口 B 执行检查。
不用重新启动 Codex，也不要在远程连接是唯一管理通道时进行断网或崩溃测试。

在两个窗口分别执行以下变量设置。将 `$Repo` 改为当前仓库路径，并将
`$Package` 指向新构建的 Windows 发布目录（参见 [发布说明](release.md)）：

```powershell
$Repo = 'C:\path\to\clyntis'
$Package = 'C:\path\to\clyntis\dist\clyntis-VERSION-x86_64-pc-windows-msvc-ID'
$Exe = Join-Path $Package 'clyntis.exe'
$State = Join-Path $Repo 'target\windows-manual-acceptance'
$Config = Join-Path $State 'config.yaml'
$Headers = @{ Authorization = 'Bearer local-manual-test-only' }
$Api = 'http://127.0.0.1:19090'

[Security.Principal.WindowsPrincipal]::new(
  [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

最后一项必须输出 `True`。确认二进制哈希：

```powershell
Get-FileHash -LiteralPath $Exe -Algorithm SHA256
```

记录当前构建的版本与哈希，并与对应发布包的 `release-manifest.json` 核对。
旧版发布包的哈希不能用于校验更名后重新构建的程序。

从 [Wintun 官方网站](https://www.wintun.net/)下载 0.14.1 压缩包。
官方 ZIP SHA256 为
`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`。
用 `Get-FileHash` 校验 ZIP，然后解压，把 **bin\amd64\wintun.dll** 和其许可证
放入 `$Package`，与 `clyntis.exe` 同级。不要选 x86 或 arm64，不需要 regsvr32。

```powershell
Get-AuthenticodeSignature (Join-Path $Package 'wintun.dll') |
  Format-List Status,StatusMessage,SignerCertificate
```

应显示有效签名；若不是 `Valid`，先处理文件或签名校验问题，不继续运行。

首次测试先关闭其他代理软件的 TUN/VPN 模式和浏览器专用代理。
记录原有系统代理设置；下面的 curl 命令显式不使用 HTTP 代理。

## 2. 保存基线，准备配置

在窗口 B 执行。若已有同名测试配置，保留它或手动备份，不覆盖真实节点配置：

```powershell
New-Item -ItemType Directory -Force $State | Out-Null
if (-not (Test-Path $Config)) {
  Copy-Item (Join-Path $Repo 'examples\windows-tun-test.yaml') $Config
}
Get-NetAdapter -IncludeHidden | Export-Clixml (Join-Path $State 'adapters-before.xml')
Get-NetRoute | Export-Clixml (Join-Path $State 'routes-before.xml')
Get-DnsClientServerAddress | Export-Clixml (Join-Path $State 'dns-before.xml')
& $Exe -v
& $Exe -f $Config -d $State -t
```

预期配置检查成功、退出码 `$LASTEXITCODE` 为 0；`-t` 不创建 TUN、不修改路由。
模板为 DIRECT，暂不需要任何节点。DNS 上游为 Cloudflare DoH，需当前网络可达；
不可达时在副本中替换成可用 DNS 上游，再进行配置检查。

模板默认关闭 IPv6，使用 mixed 17890、控制接口 19090、DNS 11053。
检查这些端口未被其他程序占用。密钥仅供本地测试；不要开放控制端口到局域网。

## 3. 启动并检查 TUN、路由与控制 API

窗口 A 执行并保持运行：

```powershell
& $Exe -f $Config -d $State
```

窗口 B 执行：

```powershell
Get-NetAdapter -IncludeHidden | Where-Object Name -Like '*clyntis-test*'
Get-NetRoute | Where-Object DestinationPrefix -In @('0.0.0.0/1','128.0.0.0/1') |
  Format-Table DestinationPrefix,InterfaceAlias,InterfaceIndex,NextHop,RouteMetric
Invoke-RestMethod "$Api/version" -Headers $Headers
Invoke-RestMethod "$Api/configs" -Headers $Headers
curl.exe --noproxy '*' -s -o NUL -w '%{http_code}' "$Api/version"
```

通过标准：TUN 创建成功；两条 split-default 路由指向测试 TUN；API 返回
clyntis 版本；不带令牌的最后一条请求返回 401。程序持续运行，没有反复新增路由错误。
网卡可能在退出后保持为未连接状态，这不等于恢复失败，重点检查路由和联网。

## 4. TCP、DNS 与 fake-IP

```powershell
curl.exe --noproxy '*' -4 --connect-timeout 10 --max-time 30 -I https://example.com
```

下面向非回环 DNS 的 53 端口查询，测试 TUN 的 DNS 劫持。
Windows 的 Resolve-DnsName 不支持自定义端口，所以这里不直接查询 11053 监听端口：

```powershell
Resolve-DnsName example.com -Server 1.1.1.1 -Type A -DnsOnly
Resolve-DnsName example.com -Server 1.1.1.1 -Type A -DnsOnly -TcpOnly
```

返回的 A 地址应位于 `198.18.0.0/16`，UDP 和 TCP DNS 均应成功。
取返回的 fake-IP，强制 HTTPS 使用它，同时保持正确的 SNI：

```powershell
$Fake = Resolve-DnsName example.com -Server 1.1.1.1 -Type A -DnsOnly |
  Where-Object { $_.Type -eq 'A' } | Select-Object -First 1 -ExpandProperty IPAddress
curl.exe --noproxy '*' -4 --resolve "example.com:443:$Fake" --max-time 30 -I https://example.com
Invoke-RestMethod "$Api/connections" -Headers $Headers | ConvertTo-Json -Depth 8
```

通过标准：获得合法 HTTP 响应，TLS 无证书错误，无卡死；域名可由 fake-IP 还原后访问。
短连接可能在查询 API 前已结束，空列表不能单独判为失败；下载大文件时再查看连接。
DNS 上游流量不能反复进入自身隧道；日志不应连续报 DNS 超时，空闲 CPU/流量应平稳。

## 5. Reality/Vision 实际节点

窗口 A 按 Ctrl+C，等待退出。在 `$Config` 中添加自己的节点，并把原来的
`rules` 替换为下列规则。不要重复定义 YAML 键，也不要把真实 UUID/地址提交到仓库。

```yaml
proxies:
  - name: RealityTest
    type: vless
    server: 填实际服务器地址
    port: 443
    uuid: 填实际UUID
    tls: true
    servername: 填服务端要求的SNI
    flow: xtls-rprx-vision
    udp: true
    packet-encoding: xudp
    reality-opts:
      public-key: 填实际公钥
      short-id: 填实际short-id
rules:
  - MATCH,RealityTest
```

可以使用 `client-fingerprint: chrome`（缺省值）或 `firefox`；两者已经与
官方浏览器 ClientHello 采集结果对比。此片段的占位值不能通过校验，必须替换。
保持证书验证开启。
重新执行 `-t`，通过后启动，重复第 4 节的 HTTPS、fake-IP 和下载测试。
从你信任的出口 IP 查询服务或服务端日志确认出口是节点服务器；下载期间
`/connections` 中链路应显示 RealityTest。仅看到“连接成功”不算 Vision 数据传输通过。

用副本更换错误的公钥/short-id 再测试：应失败，不能悄悄 DIRECT；恢复正确配置后重测。
记录失败报错，分享时隐藏服务器标识和凭据。

## 6. 普通 UDP 与 IPv6

DNS 成功不能代替普通 UDP/XUDP 验收。准备自己控制的远端 UDP echo 服务，
仅在验收期间允许测试来源访问对应 UDP 端口。若没有这种服务，本项记录“未测”。
在该服务器可用以下 Python 代码监听 23457：

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 23457))
while True:
    data, peer = s.recvfrom(65535)
    s.sendto(data, peer)
```

Windows 窗口 B 测试 4000 字节往返（替换地址）：

```powershell
$EchoHost = '填远端UDP服务IP'
$Udp = [System.Net.Sockets.UdpClient]::new()
try {
  $Udp.Client.ReceiveTimeout = 10000
  $Udp.Connect($EchoHost, 23457)
  $Payload = New-Object byte[] 4000
  [System.Random]::new().NextBytes($Payload)
  [void]$Udp.Send($Payload, $Payload.Length)
  $Peer = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
  $Reply = $Udp.Receive([ref]$Peer)
  [Convert]::ToBase64String($Reply) -eq [Convert]::ToBase64String($Payload)
} finally { $Udp.Dispose() }
```

应输出 True。分别在 DIRECT 和 Reality/Vision 配置下运行，后者验证 XUDP 路径。
记录服务端实际看到的源地址；不能把访问本机回环地址算作远端 UDP 验收。

物理网络和节点都支持 IPv6 时，将顶层 `ipv6` 改成 `true`，重启后检查
`::/1`、`8000::/1` 路由；使用 `curl.exe --noproxy '*' -6` 访问已确认可达的 IPv6 HTTPS 站点。
用 `Resolve-DnsName ... -Type AAAA` 检查 `fdfe:dcba:9876::/64` fake-IP。
没有 IPv6 上游时记录“环境不支持”，不要关闭证书验证或将失败当成已通过。

## 7. 切网、局域网直连与共存

1. 保持程序运行，从 Wi-Fi 切到有线或另一可用热点，等待约 3–10 秒。
2. 日志应报告出口改变。旧连接可以中断，新请求必须重新成功；重复 HTTPS、DNS 和 UDP。
3. 若配置了 `tun.interface`，它固定出口，不应期待自动切到另一个名字的接口。
4. 需要测试局域网排除时，在 `tun.route-exclude-address` 中添加**实际局域网网段**，
   重启后用 `Find-NetRoute -RemoteIPAddress 实际局域网IP` 核实物理出口，并访问已知服务。
   不要把所有目标都排除，否则无法验证 TUN。
5. 单独运行全部通过后，再测试你实际使用的其他 VPN。先启动另一 VPN，保存路由快照，
   再启动 clyntis。检查预期业务可用；clyntis 停止后，另一 VPN 的路由及业务仍正常。
   记录 VPN 名称、版本、启动顺序和目标路由。不承诺两个全局 VPN 的策略能自动合并。

## 8. 正常停止及崩溃恢复

正常停止：窗口 A 按 Ctrl+C，等待程序退出。窗口 B 检查：

```powershell
Test-Path (Join-Path $State 'clyntis-tun-state.json')
Get-NetRoute | Where-Object InterfaceAlias -Like '*clyntis-test*'
curl.exe --noproxy '*' -4 --max-time 30 -I https://example.com
Get-DnsClientServerAddress | Export-Clixml (Join-Path $State 'dns-after.xml')
Get-NetRoute | Export-Clixml (Join-Path $State 'routes-after.xml')
```

正常停止后 journal 应不存在，程序添加的路由应撤销，普通联网恢复。
本程序不直接修改系统 DNS 地址；网络没切换时应与基线一致。网卡切换带来的 DHCP
变化可能正常，不能要求整份系统路由快照逐字相同，也不要手动清空路由表。

崩溃测试：重新启动后，在窗口 B 精确选择本次测试程序，不终止其他同名程序：

```powershell
$TestProcesses = @(Get-CimInstance Win32_Process |
  Where-Object { $_.ExecutablePath -eq $Exe })
if ($TestProcesses.Count -ne 1) { throw '必须只有一个该路径的测试进程，请先核对' }
$TestProcesses | Select-Object ProcessId,ExecutablePath,CommandLine
Stop-Process -Id $TestProcesses[0].ProcessId -Force
Test-Path (Join-Path $State 'clyntis-tun-state.json')
& $Exe -d $State --recover-tun
$LASTEXITCODE
Test-Path (Join-Path $State 'clyntis-tun-state.json')
```

强制终止后 journal 应保留；恢复命令退出码应为 0，随后 journal 应消失。
检查联网和其他 VPN 路由仍正常，再执行一次恢复命令，应安全成功。
**始终使用同一个 `$State`。恢复前不要删除 journal。**
如恢复失败，保存报错和日志；不要反复启动、手动批量删除系统路由。

## 9. 结果记录（复制此表填写）

日期：____　Windows 版本/Build：____　CPU 架构：____
程序 SHA256：____　Wintun 版本/签名状态：____
物理网络/网卡：____　节点协议及服务端版本（不填凭据）：____

| 项目 | 通过/失败/未测 | 证据、错误或环境限制 |
| --- | --- | --- |
| 管理员、Wintun、配置校验 | | |
| TUN 创建与 IPv4 路由 | | |
| API 令牌校验 | | |
| DIRECT HTTPS 与持续下载 | | |
| UDP/TCP DNS、fake-IP 还原 | | |
| Reality/Vision 实际传输及出口 | | |
| 错误认证不回退 DIRECT | | |
| DIRECT 普通 UDP 4000 字节 | | |
| Reality/Vision XUDP 4000 字节 | | |
| IPv6 路由、HTTPS、fake-IP | | |
| 切网重连与局域网排除 | | |
| 另一 VPN 共存和路由保留 | | |
| Ctrl+C 正常恢复 | | |
| 强制终止、恢复命令及再次恢复 | | |

记录目录：`target\windows-manual-acceptance`；日志位于其中的 `logs`。
反馈时提供填写后的表格、失败时间、错误输出和相关日志即可。
路由/API 数据包含网络信息，配置可能含 UUID、公钥、short-id 等；发送前按需脱敏，
不要直接打包整个配置目录或在公开仓库提交真实配置。
