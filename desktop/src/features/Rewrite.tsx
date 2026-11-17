import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Check, CircleAlert, Copy, Plus, Wand2 } from "lucide-react";
import { locale, t } from "../i18n";
import { type RewriteStatus, type RewriteSettings } from "../types";
import { usePageVisible } from "../visibility";
import { Modal, type Perform, Setting, Toggle } from "../components/common";

type HitFilter = "all" | "reject" | "rewrite";

export function isRejectAction(action: string): boolean {
  const normalized = action.trim().toLowerCase();
  return normalized.startsWith("reject") || normalized === "module-reject";
}

export function rewriteActionLabel(action: string): string {
  const normalized = action.trim().toLowerCase();
  if (normalized === "module-reject") return t("域名拦截");
  if (normalized === "reject") return t("拦截 404");
  if (normalized === "reject-200") return t("拦截 200");
  if (normalized === "reject-img") return t("拦截图片");
  if (normalized === "reject-dict") return t("拦截 JSON");
  if (normalized === "reject-array") return t("拦截数组");
  if (normalized === "reject-drop") return t("断开连接");
  if (normalized === "302" || normalized === "307") return t("重定向");
  if (normalized === "mock") return t("本地映射");
  if (normalized === "header") return t("请求头改写");
  if (normalized === "body") return t("正文改写");
  if (normalized === "json") return t("JSON 改写");
  if (normalized === "jq") return t("JQ 改写");
  if (normalized === "script" || normalized.startsWith("script "))
    return t("脚本改写");
  return action;
}

export function describeRewrite(
  rewriteActions?: string[],
  rewrite?: string,
): {
  kind: "reject" | "rewrite";
  label: string;
  reject: boolean;
} | null {
  if (rewriteActions?.length) {
    const rejectAction = rewriteActions.find(isRejectAction);
    const primary = rejectAction ?? rewriteActions[0];
    return {
      kind: rejectAction ? "reject" : "rewrite",
      label: rewriteActionLabel(primary),
      reject: Boolean(rejectAction),
    };
  }
  if (rewrite) {
    return {
      kind: "rewrite",
      label: "",
      reject: false,
    };
  }
  return null;
}

function moduleLabel(name: string) {
  return name === "custom" ? t("自定义规则") : name;
}

function formatHitTime(seconds: number) {
  if (!seconds) return "—";
  return new Date(seconds * 1000).toLocaleTimeString(locale(), {
    hour12: false,
  });
}

function RewriteModulesList({
  modules,
  hits,
}: {
  modules: RewriteStatus["modules"];
  hits: RewriteStatus["hits"];
}) {
  return (
    <div className="module-cards">
      {modules.map((module) => {
        const failed = !!module.error || module.missing.length > 0;
        return (
          <div className="module-card" key={module.name}>
            <div className="module-card-head">
              <span className="module-card-name">
                <span className={`module-dot ${failed ? "error" : "ok"}`} />
                <strong>{moduleLabel(module.name)}</strong>
                {module.title && module.title !== module.name && (
                  <span className="muted small">{module.title}</span>
                )}
              </span>
              {!module.error && (
                <span className="tiny-tag">
                  {t("生效 {hits} 次", { hits: hits[module.name] ?? 0 })}
                </span>
              )}
            </div>
            {module.error ? (
              <p className="danger-text small">{module.error}</p>
            ) : (
              <div className="module-card-stats">
                {t(
                  "{rules} 条重写规则 · {rejects} 条域名拦截 · {scripts} 个脚本 · {hosts} 个主机名",
                  {
                    rules: module.rules,
                    rejects: module.reject ?? 0,
                    scripts: module.scripts,
                    hosts: module.hostnames,
                  },
                )}
                {module.updated
                  ? ` · ${t("更新于 {time}", {
                      time: new Date(module.updated * 1000).toLocaleString(
                        locale(),
                      ),
                    })}`
                  : ""}
              </div>
            )}
            {module.missing.length > 0 && (
              <p className="danger-text small" style={{ marginTop: 4 }}>
                {t("下载失败：{list}", { list: module.missing.join("、") })}
              </p>
            )}
            {module.skipped.length > 0 && (
              <details className="module-skipped">
                <summary className="muted">
                  {t("{count} 行不支持，已跳过", {
                    count: module.skipped.length,
                  })}
                </summary>
                <pre className="rule-preview">
                  {module.skipped.map((s) => `${s.line}: ${s.text}`).join("\n")}
                </pre>
              </details>
            )}
          </div>
        );
      })}
    </div>
  );
}

function RecentHitsList({
  recent,
  filter,
  onFilterChange,
  copiedUrl,
  onCopy,
}: {
  recent: RewriteStatus["recent"];
  filter: HitFilter;
  onFilterChange: (next: HitFilter) => void;
  copiedUrl: string | null;
  onCopy: (url: string) => void;
}) {
  const filtered = recent.filter((hit) => {
    if (filter === "reject") return isRejectAction(hit.action);
    if (filter === "rewrite") return !isRejectAction(hit.action);
    return true;
  });
  return (
    <div>
      <div className="rewrite-hits-header">
        <span className="sub-heading">{t("最近生效记录")}</span>
        <div className="segmented" role="group" aria-label={t("筛选生效类型")}>
          {(
            [
              ["all", t("全部")],
              ["reject", t("仅拦截")],
              ["rewrite", t("仅改写")],
            ] as [HitFilter, string][]
          ).map(([id, label]) => (
            <button
              key={id}
              aria-pressed={filter === id}
              className={filter === id ? "selected" : ""}
              onClick={() => onFilterChange(id)}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
      <div className="hits-list">
        {filtered.length === 0 ? (
          <div className="hit-item muted">{t("暂无命中记录")}</div>
        ) : (
          filtered.map((hit, index) => (
            <div
              className="hit-item"
              key={`${hit.time}-${hit.module}-${hit.url}-${index}`}
            >
              <span
                className={`action-badge ${
                  isRejectAction(hit.action) ? "reject" : "rewrite"
                }`}
              >
                {rewriteActionLabel(hit.action)}
              </span>
              <div className="hit-item-main">
                <div className="hit-item-url mono" title={hit.url}>
                  {hit.url}
                </div>
                <div className="hit-item-sub">
                  {formatHitTime(hit.time)} · {moduleLabel(hit.module)} ·{" "}
                  {hit.action}
                </div>
              </div>
              <button
                className="text-button"
                onClick={() => onCopy(hit.url)}
                aria-label={t("复制目标 {url}", { url: hit.url })}
              >
                {copiedUrl === hit.url ? (
                  <Check size={13} />
                ) : (
                  <Copy size={13} />
                )}
                {copiedUrl === hit.url ? t("已复制") : t("复制")}
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export function RewritePanel({
  compact = false,
  perform,
}: {
  compact?: boolean;
  perform?: Perform;
}) {
  const [status, setStatus] = useState<RewriteStatus | null>(null);
  const [expanded, setExpanded] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [hitFilter, setHitFilter] = useState<HitFilter>("all");
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null);
  const shown = usePageVisible();

  const load = useCallback(
    () =>
      void invoke<RewriteStatus>("rewrite_status")
        .then(setStatus)
        .catch(() => setStatus(null)),
    [],
  );

  useEffect(() => {
    load();
    if (!shown) return;
    const timer = window.setInterval(load, 3000);
    return () => window.clearInterval(timer);
  }, [shown, load]);

  if (!status?.enabled) return null;

  const decrypting = status.decrypting;

  const rejectCount =
    status.rejects ??
    status.recent.filter((hit) => isRejectAction(hit.action)).length;
  const rewriteCount =
    status.rewrites ?? Math.max(0, status.total - rejectCount);
  const rejectRules =
    status.rejectRules ??
    status.modules.reduce((sum, m) => sum + (m.reject ?? 0), 0);
  const bypassed = status.bypassed ?? [];
  const problems = status.modules.filter(
    (m) => m.error || m.missing.length || m.skipped.length,
  ).length;
  const quickHits = status.recent.slice(0, 3);

  const copyUrl = (url: string) => {
    void navigator.clipboard?.writeText(url).then(() => {
      setCopiedUrl(url);
      window.setTimeout(() => {
        setCopiedUrl((current) => (current === url ? null : current));
      }, 1500);
    });
  };

  const retryBypass = () => {
    const run = async () => {
      await invoke("clear_mitm_bypass");
      load();
    };
    if (perform) {
      void perform(run, t("已清空绕过记录，下次连接将重新尝试解密"));
    } else {
      void run().catch(() => {});
    }
  };

  return (
    <section className="panel rewrite-hero">
      <div className="panel-title">
        <h3>
          <Wand2 size={15} /> {t("重写模块")}
          <span className={`status-chip ${decrypting ? "" : "warning"}`}>
            {decrypting
              ? t("已加载 {count} 个模块", { count: status.modules.length })
              : t("HTTPS 解密未开启")}
          </span>
          {problems > 0 && (
            <span className="tiny-tag danger">
              {t("{count} 个有问题", { count: problems })}
            </span>
          )}
        </h3>
        <div className="mitm-title-actions">
          <button className="text-button" onClick={() => setModalOpen(true)}>
            {t("查看详情")}
          </button>
          {!compact && (
            <button
              className="text-button"
              onClick={() => setExpanded((o) => !o)}
            >
              {expanded ? t("收起") : t("展开模块与记录")}
            </button>
          )}
        </div>
      </div>

      <div className="rewrite-hero-grid">
        <div className="rewrite-metrics">
          <div>
            <strong>{status.total.toLocaleString(locale())}</strong>
            <small>{t("总生效次数")}</small>
          </div>
          <div>
            <strong className="danger-text">
              {rejectCount.toLocaleString(locale())}
            </strong>
            <small>{t("URL / 域名拦截")}</small>
          </div>
          <div>
            <strong className="accent">
              {rewriteCount.toLocaleString(locale())}
            </strong>
            <small>{t("内容 / 脚本改写")}</small>
          </div>
          <div>
            <strong>
              {status.rules.toLocaleString(locale())} /{" "}
              {rejectRules.toLocaleString(locale())}
            </strong>
            <small>{t("重写 / 域名规则")}</small>
          </div>
        </div>

        <div className="rewrite-recent-quick">
          <header>
            <span>{t("最近生效")}</span>
            <span>
              {t("解密主机名 {count} 个", { count: status.hostnames.length })}
            </span>
          </header>
          {!decrypting && (
            <p className="muted small">
              {t(
                "HTTPS 解密未开启，URL / 内容重写不生效（模块域名拦截仍生效）",
              )}
            </p>
          )}
          {quickHits.length > 0
            ? quickHits.map((hit, index) => (
                <div
                  className="quick-hit-row"
                  key={`${hit.time}-${hit.url}-${index}`}
                  onClick={() => copyUrl(hit.url)}
                  title={hit.url}
                >
                  <span
                    className={`action-badge ${
                      isRejectAction(hit.action) ? "reject" : "rewrite"
                    }`}
                  >
                    {rewriteActionLabel(hit.action)}
                  </span>
                  <span className="quick-hit-url mono">{hit.url}</span>
                  <span className="quick-hit-meta">
                    {moduleLabel(hit.module)} · {formatHitTime(hit.time)}
                  </span>
                </div>
              ))
            : decrypting && (
                <span className="muted small">{t("暂无命中记录")}</span>
              )}
        </div>
      </div>

      {decrypting && bypassed.length > 0 && (
        <div className="bypass-banner">
          <div className="bypass-banner-copy">
            <CircleAlert size={15} />
            <span>
              {t(
                "有 {count} 个模块关联域名（{hosts}）因证书校验或解密握手失败未能解密，已改为直接转发。",
                { count: bypassed.length, hosts: bypassed.join("、") },
              )}
            </span>
          </div>
          <button className="button secondary compact" onClick={retryBypass}>
            {t("重试解密")}
          </button>
        </div>
      )}

      {!compact && expanded && (
        <div className="rewrite-expanded">
          <div>
            <div className="sub-heading">
              {t("模块状态（{count}）", { count: status.modules.length })}
            </div>
            <RewriteModulesList modules={status.modules} hits={status.hits} />
          </div>
          <RecentHitsList
            recent={status.recent}
            filter={hitFilter}
            onFilterChange={setHitFilter}
            copiedUrl={copiedUrl}
            onCopy={copyUrl}
          />
        </div>
      )}

      {modalOpen && (
        <Modal
          title={t("重写模块详情")}
          onClose={() => setModalOpen(false)}
          wide
        >
          <div className="node-detail">
            <p className="muted small">
              {t(
                "本次连接共生效 {total} 次（URL / 域名拦截 {rejects} 次，内容 / 脚本改写 {rewrites} 次），覆盖 {hosts} 个解密主机名。",
                {
                  total: status.total,
                  rejects: rejectCount,
                  rewrites: rewriteCount,
                  hosts: status.hostnames.length,
                },
              )}
            </p>
            <div className="sub-heading">
              {t("已加载模块（{count}）", { count: status.modules.length })}
            </div>
            <RewriteModulesList modules={status.modules} hits={status.hits} />
            <RecentHitsList
              recent={status.recent}
              filter={hitFilter}
              onFilterChange={setHitFilter}
              copiedUrl={copiedUrl}
              onCopy={copyUrl}
            />
          </div>
        </Modal>
      )}
    </section>
  );
}

export function RewriteSettingsSection({
  value,
  decrypting,
  onChange,
}: {
  value: RewriteSettings | null | undefined;
  decrypting: boolean;
  onChange: (value: RewriteSettings | null) => void;
}) {
  const rewrite = value ?? { enabled: false, modules: [], custom: "" };
  const [dialog, setDialog] = useState<"module" | "custom" | null>(null);
  const update = (patch: Partial<RewriteSettings>) =>
    onChange({ ...rewrite, ...patch });
  const customLines = rewrite.custom
    .split("\n")
    .filter((l) => l.trim() && !l.trim().startsWith("#")).length;
  return (
    <>
      <Setting
        label={t("启用重写模块")}
        text={
          decrypting
            ? t(
                "用 Surge、Loon、Quantumult X 的模块去广告：拦截广告 URL、改写返回内容、运行脚本。模块里的主机名自动加入 HTTPS 解密",
              )
            : t(
                "只作用于 HTTPS 解密的流量：先在「抓包」页开启 HTTPS 解密并信任证书",
              )
        }
      >
        <Toggle
          checked={rewrite.enabled}
          onChange={(enabled) => update({ enabled })}
          label={t("启用重写模块")}
        />
      </Setting>
      {rewrite.enabled && (
        <>
          {rewrite.modules.map((module) => (
            <Setting key={module.name} label={module.name} text={module.url}>
              <div className="service-actions">
                <Toggle
                  checked={module.enabled}
                  onChange={(enabled) =>
                    update({
                      modules: rewrite.modules.map((m) =>
                        m.name === module.name ? { ...m, enabled } : m,
                      ),
                    })
                  }
                  label={module.name}
                />
                <button
                  className="text-button danger"
                  onClick={() =>
                    update({
                      modules: rewrite.modules.filter(
                        (m) => m.name !== module.name,
                      ),
                    })
                  }
                >
                  {t("移除")}
                </button>
              </div>
            </Setting>
          ))}
          <Setting
            label={t("添加模块")}
            text={t(
              "Surge 模块（.sgmodule）、Loon 插件（.plugin）或 Quantumult X 重写的链接",
            )}
          >
            <button
              className="button secondary"
              onClick={() => setDialog("module")}
            >
              <Plus size={14} />
              {t("添加")}
            </button>
          </Setting>
          <Setting
            label={t("自定义规则")}
            text={
              customLines
                ? t("{count} 行，排在所有模块之前", { count: customLines })
                : t("用模块的写法手写规则，排在所有模块之前")
            }
          >
            <button
              className="button secondary"
              onClick={() => setDialog("custom")}
            >
              {t("编辑")}
            </button>
          </Setting>
        </>
      )}
      {dialog === "module" && (
        <ModuleDialog
          taken={rewrite.modules.map((m) => m.name)}
          onClose={() => setDialog(null)}
          onAdd={(module) => {
            update({ modules: [...rewrite.modules, module] });
            setDialog(null);
          }}
        />
      )}
      {dialog === "custom" && (
        <CustomRewriteDialog
          value={rewrite.custom}
          onClose={() => setDialog(null)}
          onSave={(custom) => {
            update({ custom });
            setDialog(null);
          }}
        />
      )}
    </>
  );
}
function ModuleDialog({
  taken,
  onAdd,
  onClose,
}: {
  taken: string[];
  onAdd: (module: { name: string; url: string; enabled: boolean }) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const duplicate = taken.includes(name.trim()) || name.trim() === "custom";
  const valid =
    !!name.trim() && !duplicate && /^https?:\/\/\S+$/.test(url.trim());
  return (
    <Modal title={t("添加模块")} onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (valid)
            onAdd({ name: name.trim(), url: url.trim(), enabled: true });
        }}
      >
        <label className="field">
          {t("名称")}
          <input
            autoFocus
            maxLength={64}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t("例如：某 App 去广告")}
          />
        </label>
        <label className="field">
          {t("链接")}
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/ads.sgmodule"
            autoComplete="off"
            spellCheck={false}
          />
        </label>
        {duplicate && (
          <p role="alert" className="inline-error">
            {t("已有同名模块。")}
          </p>
        )}
        <p className="small muted">
          {t(
            "保存设置后下载模块和其中的脚本，之后每天自动更新。脚本能读取和修改所匹配请求的内容，只添加信任的来源。",
          )}
        </p>
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
const CUSTOM_REWRITE_EXAMPLE = `[URL Rewrite]
^https?:\\/\\/api\\.example\\.com\\/ad - reject-dict

[Body Rewrite]
http-response-jq ^https?:\\/\\/api\\.example\\.com\\/feed 'del(.data.ads)'

[MITM]
hostname = api.example.com`;
function CustomRewriteDialog({
  value,
  onSave,
  onClose,
}: {
  value: string;
  onSave: (value: string) => void;
  onClose: () => void;
}) {
  const [text, setText] = useState(value);
  return (
    <Modal title={t("自定义规则")} onClose={onClose} wide>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          onSave(text);
        }}
      >
        <p className="small muted">
          {t(
            "支持 Surge 模块、Loon 插件和 Quantumult X 重写的写法：URL 拦截（reject、reject-200、reject-img、reject-dict、reject-array）、重定向、Map Local、请求头和返回内容改写、JSON 字段删除、脚本，以及 [MITM] 主机名。",
          )}
        </p>
        <textarea
          className="code-input"
          rows={16}
          value={text}
          spellCheck={false}
          placeholder={CUSTOM_REWRITE_EXAMPLE}
          onChange={(e) => setText(e.target.value)}
        />
        <div className="modal-actions">
          <button type="button" className="button secondary" onClick={onClose}>
            {t("取消")}
          </button>
          <button className="button primary">{t("保存")}</button>
        </div>
      </form>
    </Modal>
  );
}
