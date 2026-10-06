# Clyntis app icon v3 — 流动之结

采用独立图案：珍珠白与浅蓝流线交织为四片风翼，表达网络路径交汇、连接与流动。
配色对齐 Apple 系统蓝（systemBlue `#0A84FF` → `#0050C8` 渐变），保留轻微材质层次与统一轮廓。
原始绿色版本由 `scripts/icon-variants.swift recolor` 重新着色得到（绿色原图见 git 历史）。

- `icon.icns`：macOS 多尺寸图标。
- `icon.ico`：Windows 图标，包含 16、24、32、48、64、256px 图层。
- `icon.png` 与各尺寸 PNG：桌面展示资源，圆角外缘透明。
- `brand-128.png`：前端侧栏与右上角使用的方形图案，由主图缩小导出；圆角由界面样式应用。
- `tray-template.png`：macOS 菜单栏使用的 44px 单色透明图案，启用 Tauri 模板图标以适应系统明暗外观；`tray-template-22.png` 为小尺寸预览。
- Windows 托盘复用 `64x64.png` 的彩色版本。
- `ios/AppIcon.appiconset`：与 `ios/Assets.xcassets/AppIcon.appiconset` 相同；包含不透明的 1024px 方形 PNG，由系统应用圆角，
  另含 iOS 18 深色（`AppIcon-1024-dark.png`，近黑渐变底）与着色（`AppIcon-1024-tinted.png`，灰度，由系统着色）外观。
- `source/clyntis-master.png`：方形原始主图（蓝色）。
- `source/clyntis-master-dark.png` / `source/clyntis-master-tinted.png`：iOS 深色与着色外观主图。
- `source/clyntis-desktop.png`：桌面原始主图。
- `source/clyntis-tray-template.png`：内置 image_gen 生成的单色托盘原始主图。
- `source/tray-prompt.json`：托盘版本的生成提示词。
- `source/prompts.json`：内置 image_gen 使用的完整生成与编辑提示词。

桌面 Tauri 打包配置、系统托盘、前端侧栏已引用本目录；iOS 工程使用 `ios/Assets.xcassets` 中的同名副本。
此交付为静态位图，不包含 Icon Composer 分层文件。

重新导出：在仓库根目录执行以下命令，再从临时目录复制桌面 PNG、ICO 与 ICNS，
并把 `ios/AppIcon.appiconset` 与 `brand-128.png` 同步到 `ios/Assets.xcassets`：

```sh
# 仅在从绿色原图重新生成时需要；dark/tinted 依赖原图的高饱和背景做分割
swiftc -O scripts/icon-variants.swift -o /tmp/icon-variants
/tmp/icon-variants recolor <绿色 master.png> desktop/src-tauri/icons/clyntis-v3/source/clyntis-master.png
/tmp/icon-variants recolor <绿色 desktop.png> desktop/src-tauri/icons/clyntis-v3/source/clyntis-desktop.png
/tmp/icon-variants dark <绿色 master.png> desktop/src-tauri/icons/clyntis-v3/source/clyntis-master-dark.png
/tmp/icon-variants tinted <绿色 master.png> desktop/src-tauri/icons/clyntis-v3/source/clyntis-master-tinted.png
rtk proxy sips -z 1024 1024 desktop/src-tauri/icons/clyntis-v3/source/clyntis-master-dark.png --out desktop/src-tauri/icons/clyntis-v3/ios/AppIcon.appiconset/AppIcon-1024-dark.png
rtk proxy sips -z 1024 1024 desktop/src-tauri/icons/clyntis-v3/source/clyntis-master-tinted.png --out desktop/src-tauri/icons/clyntis-v3/ios/AppIcon.appiconset/AppIcon-1024-tinted.png
rtk proxy desktop/node_modules/.bin/tauri icon desktop/src-tauri/icons/clyntis-v3/source/clyntis-desktop.png --output /tmp/clyntis-icons-v3
rtk proxy sips -z 1024 1024 desktop/src-tauri/icons/clyntis-v3/source/clyntis-master.png --out desktop/src-tauri/icons/clyntis-v3/ios/AppIcon.appiconset/AppIcon-1024.png
rtk proxy sips -z 128 128 desktop/src-tauri/icons/clyntis-v3/source/clyntis-master.png --out desktop/src-tauri/icons/clyntis-v3/brand-128.png
rtk proxy sips -z 44 44 desktop/src-tauri/icons/clyntis-v3/source/clyntis-tray-template.png --out desktop/src-tauri/icons/clyntis-v3/tray-template.png
rtk proxy sips -z 22 22 desktop/src-tauri/icons/clyntis-v3/source/clyntis-tray-template.png --out desktop/src-tauri/icons/clyntis-v3/tray-template-22.png
```

平台模板模式参考：[Tauri TrayIconBuilder](https://docs.rs/tauri/latest/tauri/tray/struct.TrayIconBuilder.html#method.icon_as_template)。
