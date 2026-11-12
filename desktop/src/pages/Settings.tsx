import { useEffect, useRef, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ShieldCheck } from "lucide-react";
import { UpdatesPanel, type UpdateController } from "../Updates";
import { t, tx, type Language } from "../i18n";
import {
  captureText,
  type Capture,
  type Settings,
  type LogLevel,
  type Overrides,
  type Snapshot,
} from "../types";
import { Confirm, type Perform, Setting, Toggle } from "../components/common";
import { AdblockSettingsSection } from "../features/Adblock";
import { RewriteSettingsSection } from "../features/Rewrite";

/** COS keys, kept in the system keychain; the SecretKey is never shown. */
function CosSettingsSection({ perform }: { perform: Perform }) {
  const [saved, setSaved] = useState<string | null>(null);
  const [secretId, setSecretId] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const load = () =>
    void invoke<string | null>("cos_credentials")
      .then((id) => {
        setSaved(id);
        setSecretId(id ?? "");
        setSecretKey("");
      })
      .catch(() => setSaved(null));
  useEffect(load, []);
  return (
    <>
      <Setting
        label={t("腾讯云 COS 密钥")}
        text={t(
          "用于「发布」配置。建议使用只授予该存储桶 PutObject 权限的子用户密钥，密钥保存在系统钥匙串中。",
        )}
      >
        <span className="tiny-tag">{saved ? t("已保存") : t("未设置")}</span>
      </Setting>
      <div className="cos-keys">
        <label className="field">
          SecretId
          <input
            value={secretId}
            autoComplete="off"
            spellCheck={false}
            onChange={(e) => setSecretId(e.target.value)}
          />
        </label>
        <label className="field">
          SecretKey
          <input
            type="password"
            value={secretKey}
            autoComplete="off"
            placeholder={saved ? t("已保存，留空则不修改") : ""}
            onChange={(e) => setSecretKey(e.target.value)}
          />
        </label>
        <div className="service-actions">
          <button
            className="button secondary"
            disabled={!secretId.trim() || (!saved && !secretKey.trim())}
            onClick={() =>
              void perform(
                () => invoke("save_cos_credentials", { secretId, secretKey }),
                t("COS 密钥已保存"),
              ).then(load)
            }
          >
            {t("保存密钥")}
          </button>
          {saved && (
            <button
              className="text-button danger"
              onClick={() =>
                void perform(
                  () => invoke("delete_cos_credentials"),
                  t("COS 密钥已删除"),
                ).then(load)
              }
            >
              {t("删除")}
            </button>
          )}
        </div>
      </div>
    </>
  );
}
function OverrideSwitch({
  value,
  onChange,
}: {
  value: boolean | null | undefined;
  onChange: (value: boolean | null) => void;
}) {
  return (
    <select
      value={value == null ? "" : String(value)}
      onChange={(e) =>
        onChange(e.target.value === "" ? null : e.target.value === "true")
      }
    >
      <option value="">{t("跟随配置文件")}</option>
      <option value="true">{t("开启")}</option>
      <option value="false">{tx("switch", "关闭")}</option>
    </select>
  );
}

export function SettingsPage({
  updates,
  state,
  busy,
  perform,
  confirm,
}: {
  updates: UpdateController;
  state: Snapshot;
  busy: boolean;
  perform: Perform;
  confirm: (modal: ReactNode) => void;
}) {
  const [settings, setSettings] = useState<Settings>(state.settings);
  const base = useRef(state.settings);
  const persistedSettings = JSON.stringify(state.settings);
  // Take backend changes only for fields the user has not edited locally, so a
  // capture switch on the overview page does not wipe unsaved edits here.
  useEffect(() => {
    const next = JSON.parse(persistedSettings) as Settings;
    const previous = base.current;
    base.current = next;
    setSettings((local) => {
      const merged = { ...local };
      for (const key of Object.keys(next) as (keyof Settings)[])
        if (JSON.stringify(local[key]) === JSON.stringify(previous[key]))
          (merged as Record<keyof Settings, unknown>)[key] = next[key];
      return merged;
    });
  }, [persistedSettings]);
  const update = <K extends keyof Settings>(key: K, value: Settings[K]) =>
    setSettings((s) => ({ ...s, [key]: value }));
  const override = <K extends keyof Overrides>(key: K, value: Overrides[K]) =>
    setSettings((s) => ({ ...s, overrides: { ...s.overrides, [key]: value } }));
  const dirty = JSON.stringify(settings) !== JSON.stringify(state.settings);
  const portInvalid = settings.mixedPort < 1024 || settings.mixedPort > 65535;
  return (
    <>
      <h3 className="settings-heading">{t("网络")}</h3>
      <section className="panel settings-section">
        <Setting label={t("接管方式")} text={t("运行中切换会重启内核")}>
          <select
            value={settings.capture}
            onChange={(e) => update("capture", e.target.value as Capture)}
          >
            {Object.entries(captureText).map(([k, v]) => (
              <option key={k} value={k}>
                {v}
              </option>
            ))}
          </select>
        </Setting>
        <Setting label={t("代理端口")} text={t("HTTP / SOCKS 共用")}>
          <input
            type="number"
            min={1024}
            max={65535}
            value={settings.mixedPort}
            onChange={(e) => update("mixedPort", Number(e.target.value))}
          />
        </Setting>
        <Setting
          label={t("允许局域网访问")}
          text={t("同一网络的设备可连接此端口")}
        >
          <Toggle
            checked={settings.allowLan}
            onChange={(v) => update("allowLan", v)}
            label={t("允许局域网访问")}
          />
        </Setting>
        <Setting label={t("TUN 自动 DNS")} text={t("接管系统 DNS，断开后恢复")}>
          <Toggle
            checked={settings.autoDns}
            onChange={(v) => update("autoDns", v)}
            label={t("TUN 自动 DNS")}
          />
        </Setting>
        <Setting label={t("出口网卡")} text={t("留空自动选择，如 en0")}>
          <input
            value={settings.tunInterface ?? ""}
            placeholder={t("自动")}
            onChange={(e) => update("tunInterface", e.target.value || null)}
          />
        </Setting>
      </section>
      <h3 className="settings-heading">{t("覆盖配置文件")}</h3>
      <section className="panel settings-section">
        <Setting label={t("日志级别")} text={t("debug 日志多，平时用 info")}>
          <select
            value={settings.overrides.logLevel ?? ""}
            onChange={(e) =>
              override("logLevel", (e.target.value || null) as LogLevel | null)
            }
          >
            <option value="">{t("跟随配置文件")}</option>
            {(["debug", "info", "warning", "error", "silent"] as const).map(
              (level) => (
                <option key={level} value={level}>
                  {level}
                </option>
              ),
            )}
          </select>
        </Setting>
        <Setting label="IPv6">
          <OverrideSwitch
            value={settings.overrides.ipv6}
            onChange={(v) => override("ipv6", v)}
          />
        </Setting>
        <Setting label={t("域名嗅探")} text={t("从 TLS / HTTP 识别域名")}>
          <OverrideSwitch
            value={settings.overrides.sniffing}
            onChange={(v) => override("sniffing", v)}
          />
        </Setting>
        <Setting
          label="Tailscale"
          text={t("关闭后不连接 tailnet，发往 Tailscale 节点的连接会失败")}
        >
          <OverrideSwitch
            value={settings.overrides.tailscale}
            onChange={(v) => override("tailscale", v)}
          />
        </Setting>
      </section>
      <h3 className="settings-heading">{t("去广告")}</h3>
      <section className="panel settings-section">
        <AdblockSettingsSection
          value={settings.overrides.adblock}
          onChange={(adblock) => override("adblock", adblock)}
        />
      </section>
      <h3 className="settings-heading">{t("重写模块")}</h3>
      <section className="panel settings-section">
        <RewriteSettingsSection
          value={settings.overrides.rewrite}
          decrypting={!!settings.overrides.mitm?.enable}
          onChange={(rewrite) => override("rewrite", rewrite)}
        />
      </section>
      <h3 className="settings-heading">{t("辅助服务")}</h3>
      <section className="panel settings-section">
        <div className="panel-title">
          <span className="service-note">{t("TUN 和系统代理依赖此服务")}</span>
          <span className="tiny-tag">
            {{
              checking: t("检查中"),
              current: t("已是最新"),
              updating: t("更新中"),
              update_failed: t("更新失败"),
              installed: t("已安装"),
              enabled: t("已启用"),
              requires_approval: t("待授权"),
              not_installed: t("未安装"),
              not_registered: t("未安装"),
            }[state.serviceStatus] ?? state.serviceStatus}
          </span>
        </div>
        <div className="service-actions">
          <button
            className="button secondary"
            disabled={busy}
            onClick={() =>
              void perform(
                () => invoke("install_service"),
                t("请在系统弹窗中授权"),
              )
            }
          >
            <ShieldCheck size={16} />
            {t("安装或更新")}
          </button>
          <button
            className="text-button danger"
            disabled={busy}
            onClick={() =>
              confirm(
                <Confirm
                  title={t("卸载辅助服务？")}
                  text={t("会先断开连接并恢复网络设置。")}
                  onClose={() => confirm(null)}
                  onConfirm={async () => {
                    confirm(null);
                    await perform(() => invoke("uninstall_service"));
                  }}
                />,
              )
            }
          >
            {t("卸载")}
          </button>
        </div>
      </section>
      <h3 className="settings-heading">{t("远程发布")}</h3>
      <section className="panel settings-section">
        <CosSettingsSection perform={perform} />
      </section>
      <h3 className="settings-heading">{t("通用")}</h3>
      <section className="panel settings-section">
        <Setting label={t("外观")}>
          <select
            value={settings.theme}
            onChange={(e) =>
              update("theme", e.target.value as Settings["theme"])
            }
          >
            <option value="system">{t("跟随系统")}</option>
            <option value="light">{t("浅色")}</option>
            <option value="dark">{t("深色")}</option>
          </select>
        </Setting>
        <Setting label={t("语言")}>
          <select
            value={settings.language}
            onChange={(e) => update("language", e.target.value as Language)}
          >
            <option value="system">{t("跟随系统")}</option>
            {/* Each language is named in itself. */}
            <option value="zh">中文</option>
            <option value="en">English</option>
          </select>
        </Setting>
        <Setting label={t("登录时启动")}>
          <Toggle
            checked={settings.launchAtLogin}
            onChange={(v) => update("launchAtLogin", v)}
            label={t("登录时启动")}
          />
        </Setting>
        <Setting label={t("打开应用后自动连接")} text={t("使用上次的配置")}>
          <Toggle
            checked={settings.autoConnect}
            onChange={(v) => update("autoConnect", v)}
            label={t("打开应用后自动连接")}
          />
        </Setting>
        <Setting
          label={t("自动检查客户端更新")}
          text={t("启动后和每 6 小时检查；安装前会征求确认")}
        >
          <Toggle
            checked={settings.autoCheckUpdates}
            onChange={(v) => update("autoCheckUpdates", v)}
            label={t("自动检查客户端更新")}
          />
        </Setting>
        <Setting label={t("订阅更新间隔")} text={t("0 为仅手动更新")}>
          <div className="input-suffix">
            <input
              type="number"
              min={0}
              max={720}
              value={settings.subscriptionIntervalHours}
              onChange={(e) =>
                update("subscriptionIntervalHours", Number(e.target.value))
              }
            />
            <span>{t("小时")}</span>
          </div>
        </Setting>
      </section>
      <h3 className="settings-heading">{t("客户端更新")}</h3>
      <UpdatesPanel
        updates={updates}
        busy={busy || dirty}
        onInstall={() =>
          confirm(
            <Confirm
              title={t("安装客户端更新")}
              text={t(
                "安装将停止代理、恢复网络设置并重启 Clyntis。正在进行的连接会中断，是否继续？",
              )}
              onClose={() => confirm(null)}
              onConfirm={async () => {
                confirm(null);
                await updates.run("install_app_update");
              }}
            />,
          )
        }
      />
      {/* Changes wait for 保存: switching capture or the port restarts the
          core, so nothing applies while a value is half typed. */}
      {dirty && (
        <div className="save-bar" role="region" aria-label={t("未保存的设置")}>
          <span>
            {portInvalid
              ? t("代理端口需在 1024–65535 之间")
              : t("有未保存的更改")}
          </span>
          <button
            className="button secondary"
            disabled={busy}
            onClick={() => setSettings(state.settings)}
          >
            {t("撤销")}
          </button>
          <button
            className="button primary"
            disabled={busy || portInvalid}
            onClick={() =>
              void perform(
                () => invoke("save_settings", { settings }),
                t("设置已保存"),
              )
            }
          >
            {t("保存")}
          </button>
        </div>
      )}
    </>
  );
}
