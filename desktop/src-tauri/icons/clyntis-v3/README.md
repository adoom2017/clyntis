# Clyntis app icon v3 — 流动之结

采用独立图案：珍珠白与薄荷绿流线交织为四片风翼，表达网络路径交汇、连接与流动。
背景沿用项目翡翠绿，使用轻微材质层次与统一轮廓。

- `icon.icns`：macOS 多尺寸图标。
- `icon.ico`：Windows 图标，包含 16、24、32、48、64、256px 图层。
- `icon.png` 与各尺寸 PNG：桌面展示资源，圆角外缘透明。
- `brand-128.png`：前端侧栏与右上角使用的方形图案，由主图缩小导出；圆角由界面样式应用。
- `tray-template.png`：macOS 菜单栏使用的 44px 单色透明图案，启用 Tauri 模板图标以适应系统明暗外观；`tray-template-22.png` 为小尺寸预览。
- Windows 托盘复用 `64x64.png` 的彩色版本。
- `ios/AppIcon.appiconset`：可复制到 Xcode `Assets.xcassets` 的静态图标资源；包含不透明的 1024px 方形 PNG，由系统应用圆角。
- `source/clyntis-master.png`：方形原始主图。
- `source/clyntis-desktop.png`：桌面原始主图。
- `source/clyntis-tray-template.png`：内置 image_gen 生成的单色托盘原始主图。
- `source/tray-prompt.json`：托盘版本的生成提示词。
- `source/prompts.json`：内置 image_gen 使用的完整生成与编辑提示词。

桌面 Tauri 打包配置、系统托盘、前端侧栏和右上角已引用本目录；iOS 暂无应用宿主，提供待接入资源。
此交付为静态位图，不包含 Icon Composer 分层文件。

重新导出：在仓库根目录执行以下命令，再从临时目录复制桌面 PNG、ICO 与 ICNS：

```sh
rtk proxy desktop/node_modules/.bin/tauri icon desktop/src-tauri/icons/clyntis-v3/source/clyntis-desktop.png --output /tmp/clyntis-icons-v3
rtk proxy sips -z 1024 1024 desktop/src-tauri/icons/clyntis-v3/source/clyntis-master.png --out desktop/src-tauri/icons/clyntis-v3/ios/AppIcon.appiconset/AppIcon-1024.png
rtk proxy sips -z 128 128 desktop/src-tauri/icons/clyntis-v3/source/clyntis-master.png --out desktop/src-tauri/icons/clyntis-v3/brand-128.png
rtk proxy sips -z 44 44 desktop/src-tauri/icons/clyntis-v3/source/clyntis-tray-template.png --out desktop/src-tauri/icons/clyntis-v3/tray-template.png
rtk proxy sips -z 22 22 desktop/src-tauri/icons/clyntis-v3/source/clyntis-tray-template.png --out desktop/src-tauri/icons/clyntis-v3/tray-template-22.png
```

平台模板模式参考：[Tauri TrayIconBuilder](https://docs.rs/tauri/latest/tauri/tray/struct.TrayIconBuilder.html#method.icon_as_template)。
