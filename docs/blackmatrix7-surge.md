# blackmatrix7 的 Surge 去广告规则在 Clyntis 中的用法

来源：<https://github.com/blackmatrix7/ios_rule_script>（提交 `0b6897d`，2026-10-27），只收集 Surge 版本里与去广告有关的部分。

所有数据都是实测：列表逐个加载进 Clyntis 内核的去广告功能，读取实际条数和内存（桌面版 release 构建，内核空载约 16 MB）；模块逐个加载进重写功能，读取解析结果。

链接前缀（下文简写为 `…/`）：

```
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/
```

## 一、去广告列表

添加位置：设置 → 去广告 → 自定义列表，格式选「Clash 规则集」。不需要开启 HTTPS 解密，按域名在 DNS 和连接层拦截。

| 列表 | 链接 | 条数 | 内存增加 | 说明 |
|---|---|---|---|---|
| AdvertisingLite_All | `…/rule/Surge/AdvertisingLite/AdvertisingLite_All.list` | 38,066 | 约 2 MB | **推荐，尤其是 iOS**。精简版，体积小 |
| Advertising_All | `…/rule/Surge/Advertising/Advertising_All.list` | 291,159 | 约 14 MB | 桌面端推荐。覆盖最全；iOS 网络扩展只有约 50 MB，慎用 |
| EasyPrivacy_All | `…/rule/Surge/EasyPrivacy/EasyPrivacy_All.list` | 39,947 | 约 2 MB | 可选。追踪和统计域名（EasyPrivacy） |
| Privacy_All | `…/rule/Surge/Privacy/Privacy_All.list` | 39,936 | 约 2 MB | 可选。隐私追踪域名，和 EasyPrivacy 大量重复，二选一 |
| Hijacking | `…/rule/Surge/Hijacking/Hijacking.list` | 228 | 可忽略 | 可选。运营商劫持、流量劫持域名 |
| AdvertisingMiTV | `…/rule/Surge/AdvertisingMiTV/AdvertisingMiTV.list` | 165 | 可忽略 | 只在有小米电视时用 |
| MIUIPrivacy | `…/rule/Surge/MIUIPrivacy/MIUIPrivacy.list` | 29 | 可忽略 | 只在有小米设备时用 |

不建议的：

| 列表 | 原因 |
|---|---|
| AdvertisingTest_All（315,848 条，约 15 MB） | 作者说明“不考虑误拦截”，测试用 |
| AdGuardSDNSFilter_All（109,050 条） | 应用内置的预设「AdGuard DNS filter」就是同一数据源，开预设即可 |
| BlockHttpDNS（63 条） | 去广告设置里的「拦截 HTTPDNS 和加密 DNS」已内置同类功能 |
| ZhihuAds（5 条） | 作者说明要配合知乎脚本使用，单独用作用很小 |

**要用 `_All.list` 或 `.list`，不要用 `_Domain.list`。** `_Domain.list` 里的域名写成 `.cnzz.com`，Surge 认为它包括 `cnzz.com` 本身，而 Clyntis 按 Clash 的规则只把它当作子域名。实测加载 `Advertising_Domain.list` 后，`s4.cnzz.com` 被拦截，`cnzz.com` 却没有；`Advertising_All.list` 两个都拦截（它写的是 `DOMAIN-SUFFIX,cnzz.com`）。两者条数几乎一样。

`_All.list` 里少量的 USER-AGENT、URL-REGEX、PROCESS-NAME 行，去广告功能会自动跳过，不影响加载。

## 二、解密去广告模块

添加位置：设置 → 重写模块 → 添加模块。需要开启 HTTPS 解密并信任证书。可以处理按域名拦不掉的广告：同一个域名下既有正常接口又有广告接口，或者开屏广告藏在正常接口的返回内容里。

| 模块 | 链接 | 规则 | 脚本 | 解密主机名 | 说明 |
|---|---|---|---|---|---|
| AdvertisingLite | `…/rewrite/Surge/AdvertisingLite/AdvertisingLite.sgmodule` | 1,229 | 0 | 902 | **推荐**，作者推荐的版本：每条规则都有能推导出来的解密主机名 |
| AdvertisingScript | `…/rewrite/Surge/AdvertisingScript/AdvertisingScript.sgmodule` | 37 | 26 | 21 | **推荐**，和上面一起用。开屏去广告脚本：知乎、B 站、爱奇艺、美团、多点等 |
| Advertising | `…/rewrite/Surge/Advertising/Advertising.sgmodule` | 740 | 0 | 698 | 可选。和 AdvertisingLite 大量重复，二选一 |
| AllInOne | `…/rewrite/Surge/AllInOne/AllInOne.sgmodule` | 831 | 24 | 831 | 上面几个的合集。单独使用，不要和上面的同时开 |
| BlockHTTPDNS | `…/rewrite/Surge/BlockHTTPDNS/BlockHTTPDNS.sgmodule` | 21 | 0 | 17 | 可选。拦截 App 自带的 HTTPDNS；与去广告设置里的「拦截 HTTPDNS 和加密 DNS」作用相近 |

全部能被完整解析（跳过 0 行），脚本都能下载。

**`_Mock` 版本**：Advertising、AdvertisingLite、AdvertisingScript、AllInOne 各有一个 `_Mock` 版，把文件名换成 `XXX_Mock.sgmodule` 即可。普通版拦截时返回 404，`_Mock` 版返回空白内容。个别 App 收到 404 会反复重试或报错，换成 `_Mock` 版即可；同一个模块的两个版本不要同时开。

**与喜马拉雅相关**：Advertising、AdvertisingLite、AllInOne 都有一条 `(?i)\b\/api\/v\d\/adRealTime - reject`，正好拦截抓包里的 `adbehavior.wsa.ximalaya.com/api/v1/adRealTime`。前提是这个域名在解密范围内，例如在 HTTPS 解密的域名里填 `*.ximalaya.com`。

仓库里另外几个模块与去广告无关，没有收录：Redirect / SafeRedirect（网址重定向）、Upgrade（屏蔽 App 升级提示）、GetCookie（抓取登录 Cookie 给签到脚本，有隐私风险）、General（只有 Surge 自身的设置）。

## 三、推荐组合

- **iOS**：去广告列表用 AdvertisingLite_All，模块用 AdvertisingLite 加 AdvertisingScript。
- **桌面端**：去广告列表用 Advertising_All（可再加 EasyPrivacy_All），模块用 AdvertisingLite 加 AdvertisingScript。

两边都建议保留应用内置的 AWAvenue-Ads 预设，它专门针对国内 App 的广告接口。

列表和模块都可能误拦截，作者也建议搭配放行规则。某个 App 出问题时：被去广告列表误拦的，在抓包页找到对应域名，到 去广告 → 白名单 放行；被模块误拦的，关掉对应模块，或在抓包页的「已重写」筛选里确认是哪条规则。
