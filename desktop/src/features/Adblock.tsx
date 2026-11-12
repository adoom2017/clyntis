import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Plus, Ban, X } from "lucide-react";
import { locale, t } from "../i18n";
import {
  type Settings,
  type AdblockSettings,
  type AdblockStatus,
  type AdListFormat,
  adblockPresets,
  defaultAdblock,
} from "../types";
import { usePageVisible } from "../visibility";
import { Modal, type Perform, Setting, Toggle } from "../components/common";

export function AdblockPanel({
  settings,
  perform,
}: {
  settings: Settings;
  perform: Perform;
}) {
  const [status, setStatus] = useState<AdblockStatus | null>(null);
  const [open, setOpen] = useState(false);
  const visible = usePageVisible();
  useEffect(() => {
    if (!visible) return;
    const load = () =>
      void invoke<AdblockStatus>("adblock_status")
        .then(setStatus)
        .catch(() => setStatus(null));
    load();
    const timer = window.setInterval(load, 3000);
    return () => window.clearInterval(timer);
  }, [visible]);
  const allow = (domain: string) => {
    const adblock = settings.overrides.adblock ?? defaultAdblock;
    if (adblock.allow.includes(domain)) return;
    const next: Settings = {
      ...settings,
      overrides: {
        ...settings.overrides,
        adblock: { ...adblock, allow: [...adblock.allow, domain] },
      },
    };
    void perform(
      () => invoke("save_settings", { settings: next }),
      t("已放行 {domain}", { domain }),
    );
  };
  if (!status) return null;
  return (
    <section className="panel adblock-panel">
      <div className="panel-title">
        <h3>
          <Ban size={15} /> {t("去广告")}
        </h3>
        {status.enabled ? (
          <button className="text-button" onClick={() => setOpen(true)}>
            {t("详情")}
          </button>
        ) : (
          <span className="muted small">{t("未开启，可在设置中启用")}</span>
        )}
      </div>
      {status.enabled && (
        <div className="adblock-summary">
          <div className="adblock-metrics">
            <div>
              <strong>{status.total.toLocaleString()}</strong>
              <small>{t("次拦截")}</small>
            </div>
            <div>
              <strong>{status.dns.toLocaleString()}</strong>
              <small>DNS</small>
            </div>
            <div>
              <strong>{status.connections.toLocaleString()}</strong>
              <small>{t("连接")}</small>
            </div>
            <div>
              <strong>{status.entries.toLocaleString()}</strong>
              <small>{t("条规则")}</small>
            </div>
          </div>
          <div className="adblock-top">
            <small>{t("拦截最多")}</small>
            {status.top.length ? (
              <ul>
                {status.top.slice(0, 3).map((item) => (
                  <li key={item.domain}>
                    <span>{item.domain}</span>
                    <small>{item.count}</small>
                  </li>
                ))}
              </ul>
            ) : (
              <span className="muted">{t("暂无拦截")}</span>
            )}
          </div>
        </div>
      )}
      {open && (
        <Modal title={t("去广告统计")} onClose={() => setOpen(false)} wide>
          <AdblockDetail status={status} onAllow={allow} />
        </Modal>
      )}
    </section>
  );
}
function AdblockDetail({
  status,
  onAllow,
}: {
  status: AdblockStatus;
  onAllow: (domain: string) => void;
}) {
  const time = (seconds: number) =>
    new Date(seconds * 1000).toLocaleTimeString(locale());
  return (
    <div className="node-detail">
      <p className="muted small">
        {t(
          "自 {since} 起，共拦截 {total} 次（DNS {dns}，连接 {connections}），涉及 {domains} 个域名。误拦时点「放行」加入白名单，立即生效。",
          {
            since: new Date(status.since * 1000).toLocaleString(locale()),
            total: status.total,
            dns: status.dns,
            connections: status.connections,
            domains: status.domains,
          },
        )}
      </p>
      <dl className="detail-list">
        {status.lists.map((list) => (
          <div key={list.name}>
            <dt>{list.name}</dt>
            <dd className={list.error ? "danger-text" : ""}>
              {list.error
                ? t("不可用：{error}", { error: list.error })
                : t("{count} 条", {
                    count: list.entries.toLocaleString(locale()),
                  }) +
                  (list.updated
                    ? ` · ${t("更新于 {time}", {
                        time: new Date(list.updated * 1000).toLocaleString(
                          locale(),
                        ),
                      })}`
                    : "")}
            </dd>
          </div>
        ))}
      </dl>
      <h4 className="detail-heading">{t("拦截最多")}</h4>
      <div className="peer-list">
        {status.top.length === 0 && (
          <div className="peer-row muted">{t("暂无拦截")}</div>
        )}
        {status.top.map((item) => (
          <div className="peer-row" key={item.domain}>
            <span className="peer-name">
              <strong>{item.domain}</strong>
            </span>
            <span className="peer-path">
              {t("{count} 次", { count: item.count })}
            </span>
            <button
              className="text-button"
              onClick={() => onAllow(item.domain)}
            >
              {t("放行")}
            </button>
          </div>
        ))}
      </div>
      <h4 className="detail-heading">{t("最近拦截")}</h4>
      <div className="peer-list">
        {status.recent.length === 0 && (
          <div className="peer-row muted">{t("暂无拦截")}</div>
        )}
        {status.recent.map((item, index) => (
          <div
            className="peer-row"
            key={`${item.time}-${item.domain}-${index}`}
          >
            <span className="peer-name">
              <strong>{item.domain}</strong>
              <small>
                {time(item.time)} · {item.via === "dns" ? "DNS" : t("连接")}
              </small>
            </span>
            <button
              className="text-button"
              onClick={() => onAllow(item.domain)}
            >
              {t("放行")}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
export function AdblockSettingsSection({
  value,
  onChange,
}: {
  value: AdblockSettings | null | undefined;
  onChange: (value: AdblockSettings | null) => void;
}) {
  const adblock = value ?? { ...defaultAdblock, enabled: false };
  const [dialog, setDialog] = useState<"list" | "allow" | null>(null);
  const update = (patch: Partial<AdblockSettings>) =>
    onChange({ ...adblock, ...patch });
  return (
    <>
      <Setting
        label={t("启用去广告")}
        text={t("广告域名在 DNS 层直接拒绝，并优先于所有规则")}
      >
        <Toggle
          checked={adblock.enabled}
          onChange={(enabled) =>
            onChange(
              enabled && !value
                ? { ...defaultAdblock }
                : { ...adblock, enabled },
            )
          }
          label={t("启用去广告")}
        />
      </Setting>
      {adblock.enabled && (
        <>
          {adblockPresets.map((preset) => (
            <Setting
              key={preset.id}
              label={preset.name}
              text={preset.description}
            >
              <Toggle
                checked={adblock.presets.includes(preset.id)}
                onChange={(on) =>
                  update({
                    presets: on
                      ? [...adblock.presets, preset.id]
                      : adblock.presets.filter((id) => id !== preset.id),
                  })
                }
                label={preset.name}
              />
            </Setting>
          ))}
          {adblock.custom.map((list) => (
            <Setting
              key={list.name}
              label={list.name}
              text={`${list.format === "adguard" ? "AdGuard" : list.format === "hosts" ? "hosts" : "Clash"} · ${list.url}`}
            >
              <button
                className="text-button danger"
                onClick={() =>
                  update({
                    custom: adblock.custom.filter((l) => l.name !== list.name),
                  })
                }
              >
                {t("移除")}
              </button>
            </Setting>
          ))}
          <Setting
            label={t("拦截 HTTPDNS 和加密 DNS")}
            text={t(
              "不少 App 自带 HTTPDNS 或 DoH，绕过了 DNS 过滤；拦截后它们会退回系统 DNS",
            )}
          >
            <Toggle
              checked={adblock.blockHttpdns ?? true}
              onChange={(blockHttpdns) => update({ blockHttpdns })}
              label={t("拦截 HTTPDNS 和加密 DNS")}
            />
          </Setting>
          <Setting
            label={t("QUIC 回退到 TCP")}
            text={t(
              "拒绝不知道域名的 QUIC 连接，App 改用 TCP 后即可按域名拦截",
            )}
          >
            <Toggle
              checked={adblock.quicFallback ?? true}
              onChange={(quicFallback) => update({ quicFallback })}
              label={t("QUIC 回退到 TCP")}
            />
          </Setting>
          <Setting
            label={t("拦截应答")}
            text={t(
              "个别 App 收到「域名不存在」会反复重试，可改为返回 0.0.0.0",
            )}
          >
            <select
              aria-label={t("拦截应答")}
              value={adblock.dnsAnswer ?? "nxdomain"}
              onChange={(e) =>
                update({
                  dnsAnswer: e.target.value as AdblockSettings["dnsAnswer"],
                })
              }
            >
              <option value="nxdomain">{t("域名不存在")}</option>
              <option value="null">0.0.0.0</option>
            </select>
          </Setting>
          <Setting
            label={t("自定义列表")}
            text={t("Clash 规则集（域名或 IP）、hosts 或 AdGuard 格式的链接")}
          >
            <button
              className="button secondary"
              onClick={() => setDialog("list")}
            >
              <Plus size={14} />
              {t("添加")}
            </button>
          </Setting>
          <Setting
            label={t("白名单")}
            text={
              adblock.allow.length
                ? t("{count} 个域名，包含其子域名；保存后立即生效，无需重启", {
                    count: adblock.allow.length,
                  })
                : t(
                    "误拦的域名加入这里，包含其子域名；也可在概览的统计里一键放行",
                  )
            }
          >
            <button
              className="button secondary"
              onClick={() => setDialog("allow")}
            >
              {t("管理")}
            </button>
          </Setting>
        </>
      )}
      {dialog === "list" && (
        <AdListDialog
          taken={adblock.custom.map((l) => l.name)}
          onClose={() => setDialog(null)}
          onAdd={(list) => {
            update({ custom: [...adblock.custom, list] });
            setDialog(null);
          }}
        />
      )}
      {dialog === "allow" && (
        <AllowDialog
          value={adblock.allow}
          onChange={(allow) => update({ allow })}
          onClose={() => setDialog(null)}
        />
      )}
    </>
  );
}
function AdListDialog({
  taken,
  onAdd,
  onClose,
}: {
  taken: string[];
  onAdd: (list: { name: string; url: string; format: AdListFormat }) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [format, setFormat] = useState<AdListFormat>("clash");
  const duplicate = taken.includes(name.trim());
  const valid =
    !!name.trim() && !duplicate && /^https?:\/\/\S+$/.test(url.trim());
  return (
    <Modal title={t("添加自定义列表")} onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (valid) onAdd({ name: name.trim(), url: url.trim(), format });
        }}
      >
        <label className="field">
          {t("名称")}
          <input
            autoFocus
            maxLength={64}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t("例如：我的广告列表")}
          />
        </label>
        <label className="field">
          {t("链接")}
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/ads.yaml"
            autoComplete="off"
            spellCheck={false}
          />
        </label>
        <label className="field">
          {t("格式")}
          <select
            value={format}
            onChange={(e) => setFormat(e.target.value as AdListFormat)}
          >
            <option value="clash">{t("Clash 规则集（yaml 或 text）")}</option>
            <option value="hosts">{t("hosts（0.0.0.0 域名）")}</option>
            <option value="adguard">{t("AdGuard（||域名^）")}</option>
          </select>
        </label>
        {duplicate && (
          <p role="alert" className="inline-error">
            {t("已有同名列表。")}
          </p>
        )}
        <p className="small muted">{t("保存设置后下载，之后每天自动更新。")}</p>
        <div className="modal-actions">
          <button type="button" className="button secondary" onClick={onClose}>
            {t("取消")}
          </button>
          <button className="button primary" disabled={!valid}>
            {t("添加")}
          </button>
        </div>
      </form>
    </Modal>
  );
}
function AllowDialog({
  value,
  onChange,
  onClose,
}: {
  value: string[];
  onChange: (value: string[]) => void;
  onClose: () => void;
}) {
  const [domain, setDomain] = useState("");
  const entry = domain.trim().toLowerCase().replace(/\.$/, "");
  const valid =
    /^(\+\.|\.)?[a-z0-9*]([a-z0-9*-]*[a-z0-9*])?(\.[a-z0-9*]([a-z0-9*-]*[a-z0-9*])?)+$/.test(
      entry,
    ) && !value.includes(entry);
  return (
    <Modal title={t("白名单")} onClose={onClose}>
      <form
        className="allow-add"
        onSubmit={(e) => {
          e.preventDefault();
          if (!valid) return;
          onChange([...value, entry]);
          setDomain("");
        }}
      >
        <input
          autoFocus
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder={t("例如：wechat.com")}
          autoComplete="off"
          spellCheck={false}
        />
        <button className="button secondary" disabled={!valid}>
          <Plus size={14} />
          {t("添加")}
        </button>
      </form>
      <div className="allow-list">
        {value.length === 0 && (
          <div className="allow-row muted">{t("还没有放行的域名")}</div>
        )}
        {value.map((item) => (
          <div className="allow-row" key={item}>
            <span>{item}</span>
            <button
              className="icon-button"
              aria-label={t("移除 {item}", { item })}
              onClick={() => onChange(value.filter((d) => d !== item))}
            >
              <X size={14} />
            </button>
          </div>
        ))}
      </div>
      <p className="small muted">
        {t(
          "包含子域名。记得点设置页底部的「保存」，保存后立即生效，无需重启。",
        )}
      </p>
      <div className="modal-actions">
        <button className="button primary" onClick={onClose}>
          {t("完成")}
        </button>
      </div>
    </Modal>
  );
}
