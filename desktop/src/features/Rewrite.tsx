import { useState } from "react";
import { Plus } from "lucide-react";
import { t } from "../i18n";
import { type RewriteSettings } from "../types";
import { Modal, Setting, Toggle } from "../components/common";

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
