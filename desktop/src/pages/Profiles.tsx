import { useEffect, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  Check,
  Copy,
  FileCode2,
  FileLock2,
  FolderOpen,
  Layers3,
  Link2,
  LoaderCircle,
  Lock,
  Plus,
  RefreshCw,
  Trash2,
  CloudUpload,
  Undo2,
  PencilLine,
} from "lucide-react";
import { Editor } from "../components/Editor";
import { type Perform, Empty, Modal, Confirm } from "../components/common";
import { locale, t } from "../i18n";
import {
  type AutoRouting,
  type ImportResult,
  type NodeImportResult,
  type NodesExport,
  type Profile,
  type ProfileNodes,
  type ProfileSummary,
  type PublishTarget,
  type Snapshot,
} from "../types";

function isV2EncryptedLinks(raw: string): boolean {
  const compact = raw.replace(/\s+/g, "");
  return (
    compact.length >= 24 &&
    !compact.includes("://") &&
    compact.startsWith("Q0xZTlRJ")
  );
}

function needsPasswordInput(raw: string): boolean {
  const trimmed = raw.trim();
  return trimmed.length > 0 && !trimmed.includes("://");
}

export function PasswordForm({
  title,
  text,
  submitLabel,
  confirm = false,
  onClose,
  onSubmit,
}: {
  title: string;
  text: string;
  submitLabel: string;
  confirm?: boolean;
  onClose: () => void;
  /** Resolves to an error message, "" to stay open silently, or null on success. */
  onSubmit: (password: string) => Promise<string | null>;
}) {
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [saving, setSaving] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const mismatch = confirm && repeat !== "" && repeat !== password;
  return (
    <Modal title={title} onClose={onClose}>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          setSaving(true);
          setFailure(null);
          void onSubmit(password)
            .then((message) => setFailure(message || null))
            .finally(() => setSaving(false));
        }}
      >
        <p className="small muted">{text}</p>
        <label className="field">
          {t("密码")}
          <input
            autoFocus
            required
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={confirm ? "new-password" : "current-password"}
          />
        </label>
        {confirm && (
          <label className="field">
            {t("确认密码")}
            <input
              required
              type="password"
              value={repeat}
              onChange={(e) => setRepeat(e.target.value)}
              autoComplete="new-password"
            />
          </label>
        )}
        {mismatch && (
          <p className="inline-error">{t("两次输入的密码不一致")}</p>
        )}
        {failure && (
          <p role="alert" className="inline-error">
            {failure}
          </p>
        )}
        <div className="modal-actions">
          <button type="button" className="button secondary" onClick={onClose}>
            {t("取消")}
          </button>
          <button
            className="button primary"
            disabled={saving || !password || (confirm && repeat !== password)}
          >
            {saving && <LoaderCircle className="spin" size={16} />}
            {submitLabel}
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function PublishForm({
  profile,
  onClose,
  onPublished,
}: {
  profile: ProfileSummary;
  onClose: () => void;
  onPublished: (url: string) => void;
}) {
  const [target, setTarget] = useState<PublishTarget>({
    bucket: "",
    region: "",
    key: "",
  });
  const [secretId, setSecretId] = useState<string | null | undefined>();
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [saving, setSaving] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  useEffect(() => {
    void invoke<PublishTarget | null>("publish_target", { id: profile.id })
      .then((saved) => saved && setTarget(saved))
      .catch(() => {});
    void invoke<string | null>("cos_credentials")
      .then(setSecretId)
      .catch(() => setSecretId(null));
  }, [profile.id]);
  const field = (key: keyof PublishTarget) => (value: string) =>
    setTarget((current) => ({ ...current, [key]: value }));
  const url =
    target.bucket && target.region && target.key
      ? `https://${target.bucket}.cos.${target.region}.myqcloud.com/${target.key.replace(/^\/+/, "")}`
      : null;
  return (
    <Modal
      title={t("发布「{name}」到腾讯云 COS", { name: profile.name })}
      onClose={onClose}
    >
      <form
        onSubmit={(event) => {
          event.preventDefault();
          setSaving(true);
          setFailure(null);
          void invoke<string>("publish_encrypted", {
            id: profile.id,
            password,
            target,
          })
            .then(onPublished)
            .catch((e) => setFailure(String(e)))
            .finally(() => setSaving(false));
        }}
      >
        <p className="small muted">
          {t(
            "加密后上传并覆盖同名文件，订阅了该地址的设备下次更新即拿到新配置。",
          )}
        </p>
        {secretId === null && (
          <p className="inline-error">
            {t("尚未保存 COS 密钥，请先在「设置 → 远程发布」中填写。")}
          </p>
        )}
        <label className="field">
          {t("存储桶")}
          <input
            required
            placeholder="examplebucket-1250000000"
            value={target.bucket}
            onChange={(e) => field("bucket")(e.target.value)}
          />
        </label>
        <label className="field">
          {t("地域")}
          <input
            required
            placeholder="ap-shanghai"
            value={target.region}
            onChange={(e) => field("region")(e.target.value)}
          />
        </label>
        <label className="field">
          {t("文件路径")}
          <input
            required
            placeholder="config/home.txt"
            value={target.key}
            onChange={(e) => field("key")(e.target.value)}
          />
        </label>
        {url && <p className="small muted publish-url">{url}</p>}
        <label className="field">
          {t("加密密码")}
          <input
            required
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
          />
        </label>
        <label className="field">
          {t("确认密码")}
          <input
            required
            type="password"
            value={repeat}
            onChange={(e) => setRepeat(e.target.value)}
            autoComplete="new-password"
          />
        </label>
        {repeat !== "" && repeat !== password && (
          <p className="inline-error">{t("两次输入的密码不一致")}</p>
        )}
        {failure && (
          <p role="alert" className="inline-error">
            {failure}
          </p>
        )}
        <div className="modal-actions">
          <button type="button" className="button secondary" onClick={onClose}>
            {t("取消")}
          </button>
          <button
            className="button primary"
            disabled={
              saving || !password || repeat !== password || secretId === null
            }
          >
            {saving && <LoaderCircle className="spin" size={16} />}
            {t("加密并发布")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function SubscriptionForm({
  onClose,
  onSubmit,
}: {
  onClose: () => void;
  onSubmit: (name: string, url: string, password: string) => Promise<boolean>;
}) {
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [password, setPassword] = useState("");
  const [saving, setSaving] = useState(false);
  const [failed, setFailed] = useState(false);
  return (
    <Modal title={t("添加订阅")} onClose={onClose}>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          setSaving(true);
          void onSubmit(name, url, password)
            .then((ok) => setFailed(!ok))
            .finally(() => setSaving(false));
        }}
      >
        <label className="field">
          {t("配置名称")}
          <input
            autoFocus
            required
            maxLength={100}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t("例如：日常使用")}
          />
        </label>
        <label className="field">
          {t("订阅 URL")}
          <input
            required
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/subscribe"
            autoComplete="off"
            spellCheck={false}
          />
        </label>
        <label className="field">
          {t("解密密码（可选）")}
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={t("订阅内容未加密时留空")}
            autoComplete="off"
          />
        </label>
        <p className="small muted">
          {t("仅支持 HTTPS。密码保存在本机，用于之后自动更新时解密。")}
        </p>
        {failed && (
          <p role="alert" className="inline-error">
            {t("添加失败，关闭此窗口查看原因。")}
          </p>
        )}
        <div className="modal-actions">
          <button type="button" className="button secondary" onClick={onClose}>
            {t("取消")}
          </button>
          <button
            className="button primary"
            disabled={saving || !name.trim() || !url.startsWith("https://")}
          >
            {saving ? (
              <LoaderCircle className="spin" size={16} />
            ) : (
              <Link2 size={16} />
            )}
            {t("添加")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function NodeLinksModal({
  onClose,
  onSubmit,
}: {
  onClose: () => void;
  onSubmit: (
    name: string,
    links: string,
    autoRouting: AutoRouting,
    password: string | null,
  ) => Promise<string | null>;
}) {
  const [name, setName] = useState("");
  const [links, setLinks] = useState("");
  const [password, setPassword] = useState("");
  const [autoRouting, setAutoRouting] = useState<AutoRouting>("whitelist");
  const [saving, setSaving] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const encryptedDetected = isV2EncryptedLinks(links);
  const showPassword = needsPasswordInput(links);
  return (
    <Modal title={t("添加节点")} onClose={onClose}>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          setSaving(true);
          setErrorMsg(null);
          void onSubmit(name, links, autoRouting, password || null)
            .then((err) => setErrorMsg(err))
            .finally(() => setSaving(false));
        }}
      >
        <label className="field">
          {t("配置名称（可选）")}
          <input
            value={name}
            maxLength={100}
            onChange={(e) => setName(e.target.value)}
            placeholder={t("留空则使用首个节点名称")}
          />
        </label>
        <label className="field">
          {t("节点链接")}
          <textarea
            autoFocus
            required
            rows={5}
            value={links}
            onChange={(e) => setLinks(e.target.value)}
            placeholder={t("粘贴 vless:// 或 hysteria2:// / hy2:// 链接，支持多行或 Base64")}
            spellCheck={false}
          />
        </label>
        {showPassword && (
          <label className="field">
            {encryptedDetected ? t("解密密码") : t("解密密码（可选）")}
            <input
              type="password"
              required={encryptedDetected}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="off"
            />
            <span className="small muted">
              {encryptedDetected
                ? t("检测到加密节点链接，请输入密码解密。")
                : t("未加密的 Base64 订阅可留空。")}
            </span>
          </label>
        )}
        <div className="field">
          <span>{t("自动分流模式")}</span>
          <div className="segmented" role="group" aria-label={t("自动分流模式")}>
            <button
              type="button"
              className={autoRouting === "whitelist" ? "selected" : ""}
              onClick={() => setAutoRouting("whitelist")}
            >
              {t("白名单（推荐）")}
            </button>
            <button
              type="button"
              className={autoRouting === "blacklist" ? "selected" : ""}
              onClick={() => setAutoRouting("blacklist")}
            >
              {t("黑名单")}
            </button>
          </div>
          <p className="small muted">
            {autoRouting === "whitelist"
              ? t("国内与局域网直连，其余流量全部走代理，无需手写规则。")
              : t("仅海外站点列表走代理，其余流量默认直连，更省代理流量。")}
          </p>
        </div>
        {errorMsg && (
          <p role="alert" className="inline-error">
            {errorMsg}
          </p>
        )}
        <div className="modal-actions">
          <button type="button" className="button secondary" onClick={onClose}>
            {t("取消")}
          </button>
          <button
            className="button primary"
            disabled={
              saving || !links.trim() || (encryptedDetected && !password)
            }
          >
            {saving ? (
              <LoaderCircle className="spin" size={16} />
            ) : (
              <Plus size={16} />
            )}
            {t("导入并启用")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function ManageNodesModal({
  profile,
  initial,
  perform,
  onClose,
  onNotice,
}: {
  profile: ProfileSummary;
  initial: ProfileNodes;
  perform: Perform;
  onClose: () => void;
  onNotice: (msg: string) => void;
}) {
  const [info, setInfo] = useState<ProfileNodes>(initial);
  const [autoRouting, setAutoRouting] = useState<AutoRouting>(
    initial.autoRouting ?? "whitelist",
  );
  const [links, setLinks] = useState("");
  const [addPassword, setAddPassword] = useState("");
  const [exportEncrypted, setExportEncrypted] = useState(false);
  const [exportPassword, setExportPassword] = useState("");
  const [exportRepeat, setExportRepeat] = useState("");
  const [exportedText, setExportedText] = useState("");
  const [working, setWorking] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);

  const addEncryptedDetected = isV2EncryptedLinks(links);
  const showAddPassword = needsPasswordInput(links);
  const hasExportable = info.nodes.some(
    (n) => n.kind === "vless" || n.kind === "hysteria2",
  );
  const exportMismatch =
    exportEncrypted && exportRepeat !== "" && exportRepeat !== exportPassword;

  const reload = async () => {
    const next = await invoke<ProfileNodes>("profile_nodes", { id: profile.id });
    setInfo(next);
    if (next.autoRouting) setAutoRouting(next.autoRouting);
  };

  const changeMode = async (nextMode: AutoRouting) => {
    if (nextMode === autoRouting) return;
    const prevMode = autoRouting;
    setAutoRouting(nextMode);
    setModalError(null);
    setWorking(true);
    try {
      const ok = await perform(async () => {
        try {
          await invoke("update_profile_nodes", {
            id: profile.id,
            removeNames: [],
            autoRouting: nextMode,
          });
        } catch (e) {
          setModalError(String(e));
          throw e;
        }
      }, t("分流模式已更新，待应用"));
      if (ok) {
        await reload();
      } else {
        setAutoRouting(info.autoRouting ?? prevMode);
      }
    } finally {
      setWorking(false);
    }
  };

  const removeNode = async (name: string) => {
    setModalError(null);
    setWorking(true);
    try {
      const ok = await perform(async () => {
        try {
          await invoke("update_profile_nodes", {
            id: profile.id,
            removeNames: [name],
            autoRouting: null,
          });
        } catch (e) {
          setModalError(String(e));
          throw e;
        }
      }, t("节点已移除，待应用"));
      if (ok) await reload();
    } finally {
      setWorking(false);
    }
  };

  const addLinks = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!links.trim()) return;
    setModalError(null);
    setWorking(true);
    try {
      const ok = await perform(async () => {
        try {
          const res = await invoke<NodeImportResult>("add_profile_links", {
            id: profile.id,
            links,
            password: addPassword || null,
          });
          setLinks("");
          setAddPassword("");
          onNotice(
            res.skipped.length
              ? t("已添加 {count} 个节点，跳过 {skipped} 条", {
                  count: res.nodes.length,
                  skipped: res.skipped.length,
                })
              : t("已添加 {count} 个节点，待应用", { count: res.nodes.length }),
          );
        } catch (e) {
          setModalError(String(e));
          throw e;
        }
      });
      if (ok) await reload();
    } finally {
      setWorking(false);
    }
  };

  const exportLinks = async () => {
    setModalError(null);
    setWorking(true);
    try {
      const res = await invoke<NodesExport>("export_profile_links", {
        id: profile.id,
        password: exportEncrypted ? exportPassword : null,
      });
      setExportedText(res.text);
      void navigator.clipboard?.writeText(res.text).catch(() => {});
      onNotice(
        res.encrypted
          ? t("已生成并复制加密节点链接")
          : t("已复制 {count} 个节点链接", { count: res.count }),
      );
    } catch (e) {
      setModalError(String(e));
    } finally {
      setWorking(false);
    }
  };

  return (
    <Modal title={t("节点管理「{name}」", { name: profile.name })} onClose={onClose}>
      <div className="field">
        <span>{t("自动分流模式")}</span>
        <div className="segmented" role="group" aria-label={t("自动分流模式")}>
          <button
            type="button"
            disabled={working || !info.isAuto}
            className={info.isAuto && autoRouting === "whitelist" ? "selected" : ""}
            onClick={() => void changeMode("whitelist")}
          >
            {t("白名单（推荐）")}
          </button>
          <button
            type="button"
            disabled={working || !info.isAuto}
            className={info.isAuto && autoRouting === "blacklist" ? "selected" : ""}
            onClick={() => void changeMode("blacklist")}
          >
            {t("黑名单")}
          </button>
        </div>
        <p className="small muted">
          {!info.isAuto
            ? t("此配置已定义自定义 rules，自动分流模式不会生效。")
            : autoRouting === "whitelist"
              ? t("国内与局域网直连，其余流量全部走代理，无需手写规则。")
              : t("仅海外站点列表走代理，其余流量默认直连，更省代理流量。")}
        </p>
      </div>
      <div className="field">
        <span>{t("节点列表 ({count})", { count: info.nodes.length })}</span>
        <div className="warning-list">
          {info.nodes.map((node, idx) => (
            <div key={`${node.name}-${idx}`} className="warning-row" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
              <div>
                <strong>{node.name}</strong>
                <div className="small muted">
                  {node.kind} · {node.server}:{node.port}
                </div>
              </div>
              <button
                type="button"
                className="icon-button danger"
                disabled={working || (info.isAuto && info.nodes.length <= 1)}
                title={t("移除节点")}
                aria-label={t("移除节点 {name}", { name: node.name })}
                onClick={() => void removeNode(node.name)}
              >
                <Trash2 size={14} />
              </button>
            </div>
          ))}
        </div>
      </div>
      {hasExportable && (
        <div className="field">
          <span>{t("导出节点链接")}</span>
          <div className="segmented" role="group" aria-label={t("导出节点链接")}>
            <button
              type="button"
              disabled={working}
              className={!exportEncrypted ? "selected" : ""}
              onClick={() => {
                setExportEncrypted(false);
                setExportedText("");
              }}
            >
              {t("明文链接")}
            </button>
            <button
              type="button"
              disabled={working}
              className={exportEncrypted ? "selected" : ""}
              onClick={() => {
                setExportEncrypted(true);
                setExportedText("");
              }}
            >
              {t("使用密码加密")}
            </button>
          </div>
          {exportEncrypted && (
            <>
              <label className="field">
                {t("加密密码")}
                <input
                  type="password"
                  value={exportPassword}
                  onChange={(e) => setExportPassword(e.target.value)}
                  autoComplete="new-password"
                />
              </label>
              <label className="field">
                {t("确认密码")}
                <input
                  type="password"
                  value={exportRepeat}
                  onChange={(e) => setExportRepeat(e.target.value)}
                  autoComplete="new-password"
                />
              </label>
              {exportMismatch && (
                <p className="inline-error">{t("两次输入的密码不一致")}</p>
              )}
            </>
          )}
          <div>
            <button
              type="button"
              className="button secondary"
              disabled={
                working ||
                (exportEncrypted &&
                  (!exportPassword || exportRepeat !== exportPassword))
              }
              onClick={() => void exportLinks()}
            >
              <Copy size={14} />
              {exportEncrypted ? t("加密并复制") : t("复制节点链接")}
            </button>
          </div>
          {exportedText && (
            <textarea rows={3} readOnly value={exportedText} spellCheck={false} />
          )}
        </div>
      )}
      <form onSubmit={(e) => void addLinks(e)}>
        <label className="field">
          {t("追加节点链接")}
          <textarea
            rows={3}
            value={links}
            onChange={(e) => setLinks(e.target.value)}
            placeholder={t("粘贴 vless:// 或 hysteria2:// / hy2:// 链接，支持多行或 Base64")}
            spellCheck={false}
          />
        </label>
        {showAddPassword && (
          <label className="field">
            {addEncryptedDetected ? t("解密密码") : t("解密密码（可选）")}
            <input
              type="password"
              required={addEncryptedDetected}
              value={addPassword}
              onChange={(e) => setAddPassword(e.target.value)}
              autoComplete="off"
            />
            <span className="small muted">
              {addEncryptedDetected
                ? t("检测到加密节点链接，请输入密码解密。")
                : t("未加密的 Base64 订阅可留空。")}
            </span>
          </label>
        )}
        {modalError && (
          <p role="alert" className="inline-error">
            {modalError}
          </p>
        )}
        <div className="modal-actions">
          <button type="button" className="button secondary" onClick={onClose}>
            {t("完成")}
          </button>
          <button
            className="button primary"
            disabled={
              working ||
              !links.trim() ||
              (addEncryptedDetected && !addPassword)
            }
          >
            {working ? (
              <LoaderCircle className="spin" size={16} />
            ) : (
              <Plus size={16} />
            )}
            {t("添加节点")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

/** The profiles page: import, subscriptions, editing and encrypted export. */
export function ProfilesPage({
  state,
  disabled,
  perform,
  refresh,
  setModal,
  setNotice,
}: {
  state: Snapshot;
  disabled: boolean;
  perform: Perform;
  refresh: () => Promise<Snapshot>;
  setModal: (modal: ReactNode) => void;
  setNotice: (notice: string) => void;
}) {
  const showImportResult = (result: ImportResult) => {
    if (result.warnings.length) {
      setModal(
        <Modal title={t("导入完成")} onClose={() => setModal(null)}>
          <p>
            {t("已创建「{name}」，跳过 {count} 项不兼容内容：", {
              name: result.profile.name,
              count: result.warnings.length,
            })}
          </p>
          <ul className="import-warnings">
            {result.warnings.map((warning, index) => (
              <li key={index}>
                <strong>{warning.path}</strong>
                <span>{warning.reason}</span>
              </li>
            ))}
          </ul>
          <div className="modal-actions">
            <button className="button primary" onClick={() => setModal(null)}>
              {t("知道了")}
            </button>
          </div>
        </Modal>,
      );
    } else {
      setModal(null);
      setNotice(t("已导入「{name}」", { name: result.profile.name }));
    }
  };
  const importFile = async () => {
    const path = await open({
      multiple: false,
      filters: [{ name: t("配置文件"), extensions: ["yaml", "yml", "txt"] }],
    });
    if (typeof path !== "string") return;
    const { encrypted } = await invoke<{ encrypted: boolean }>(
      "inspect_profile_file",
      { path },
    );
    if (!encrypted) {
      showImportResult(await invoke<ImportResult>("import_profile", { path }));
      return;
    }
    setModal(
      <PasswordForm
        title={t("导入加密配置")}
        text={t("此文件已加密，输入密码后导入。")}
        submitLabel={t("解密并导入")}
        onClose={() => setModal(null)}
        onSubmit={async (password) => {
          try {
            const result = await invoke<ImportResult>("import_profile", {
              path,
              password,
            });
            await refresh();
            showImportResult(result);
            return null;
          } catch (e) {
            return String(e);
          }
        }}
      />,
    );
  };
  const exportEncrypted = (profile: ProfileSummary) =>
    setModal(
      <PasswordForm
        title={t("加密导出「{name}」", { name: profile.name })}
        text={t("导出的文件需要此密码才能导入。导出的是当前生效的版本。")}
        submitLabel={t("选择位置并导出")}
        confirm
        onClose={() => setModal(null)}
        onSubmit={async (password) => {
          try {
            const path = await save({
              defaultPath: `${profile.name}.txt`,
              filters: [{ name: t("加密配置"), extensions: ["txt"] }],
            });
            if (!path) return "";
            await invoke("export_encrypted", {
              id: profile.id,
              password,
              path,
            });
            setModal(null);
            setNotice(t("已加密导出"));
            return null;
          } catch (e) {
            return String(e);
          }
        }}
      />,
    );
  const publishEncrypted = (profile: ProfileSummary) =>
    setModal(
      <PublishForm
        profile={profile}
        onClose={() => setModal(null)}
        onPublished={(url) => {
          setModal(null);
          setNotice(t("已发布到 {url}", { url }));
        }}
      />,
    );
  const addSubscription = () =>
    setModal(
      <SubscriptionForm
        onClose={() => setModal(null)}
        onSubmit={async (name, url, password) => {
          const ok = await perform(async () => {
            showImportResult(
              await invoke<ImportResult>("add_subscription", {
                name,
                url,
                password: password || null,
              }),
            );
          });
          return ok;
        }}
      />,
    );
  const addNodeLinks = () =>
    setModal(
      <NodeLinksModal
        onClose={() => setModal(null)}
        onSubmit={async (name, links, autoRouting, password) => {
          let errMsg: string | null = null;
          await perform(async () => {
            try {
              const res = await invoke<NodeImportResult>("import_node_links", {
                name,
                links,
                autoRouting,
                password,
              });
              setModal(null);
              setNotice(
                res.skipped.length
                  ? t("已导入 {count} 个节点，跳过 {skipped} 条", {
                      count: res.nodes.length,
                      skipped: res.skipped.length,
                    })
                  : t("已导入 {count} 个节点并启用自动分流", {
                      count: res.nodes.length,
                    }),
              );
            } catch (e) {
              errMsg = String(e);
              throw e;
            }
          });
          return errMsg;
        }}
      />,
    );
  return (
    <>
      <div className="toolbar">
        <span className="muted small">
          {t("{count} 个配置", { count: state.profiles.length })}
        </span>
        <div>
          <button
            className="button secondary"
            disabled={disabled}
            onClick={() => void perform(importFile)}
          >
            <FolderOpen size={16} />
            {t("导入文件")}
          </button>
          <button
            className="button secondary"
            disabled={disabled}
            onClick={addSubscription}
          >
            <Link2 size={16} />
            {t("添加订阅")}
          </button>
          <button
            className="button primary"
            disabled={disabled}
            onClick={addNodeLinks}
          >
            <Plus size={16} />
            {t("添加节点")}
          </button>
        </div>
      </div>
      {!state.profiles.length ? (
        <Empty
          icon={<Layers3 />}
          title={t("还没有配置")}
          text={t("粘贴节点链接即可自动分流，或导入 YAML 文件 / 订阅。")}
        />
      ) : (
        <div className="profile-list">
          {state.profiles.map((profile) => (
            <section
              className={`panel profile-card ${profile.id === state.selected ? "chosen" : ""}`}
              key={profile.id}
            >
              <div className="profile-card-top">
                <span className="profile-symbol">
                  <FileCode2 size={22} />
                </span>
                <div>
                  <h3>{profile.name}</h3>
                  <p>
                    {profile.encrypted && (
                      <Lock
                        size={11}
                        className="inline-icon"
                        aria-label={t("加密订阅")}
                      />
                    )}
                    {profile.source} ·{" "}
                    {t("检查于 {time}", {
                      time: new Date(profile.lastChecked * 1000).toLocaleString(
                        locale(),
                        {
                          dateStyle: "short",
                          timeStyle: "short",
                        },
                      ),
                    })}
                  </p>
                </div>
                {profile.pending && (
                  <span className="pending-tag">{t("待应用")}</span>
                )}
              </div>
              {profile.lastError && (
                <p className="inline-error">{profile.lastError}</p>
              )}
              <div className="profile-actions">
                {profile.id === state.selected ? (
                  <span className="current-tag">
                    <Check size={13} />
                    {t("当前")}
                  </span>
                ) : (
                  <button
                    className="button secondary compact"
                    disabled={disabled}
                    onClick={() =>
                      void perform(() =>
                        invoke("select_profile", { id: profile.id }),
                      )
                    }
                  >
                    {t("使用")}
                  </button>
                )}
                {profile.subscription && (
                  <button
                    className="action-button"
                    disabled={disabled}
                    aria-label={t("更新 {name}", {
                      name: profile.name,
                    })}
                    onClick={() =>
                      void perform(
                        () =>
                          invoke("update_subscription", {
                            id: profile.id,
                          }),
                        t("已检查更新"),
                      )
                    }
                  >
                    <RefreshCw size={14} />
                    {t("检查更新")}
                  </button>
                )}
                <button
                  className="action-button"
                  disabled={disabled}
                  onClick={() =>
                    void perform(async () => {
                      const nodes = await invoke<ProfileNodes>(
                        "profile_nodes",
                        { id: profile.id },
                      );
                      setModal(
                        <ManageNodesModal
                          profile={profile}
                          initial={nodes}
                          perform={perform}
                          onClose={() => setModal(null)}
                          onNotice={setNotice}
                        />,
                      );
                    })
                  }
                >
                  <Layers3 size={14} />
                  {t("节点管理")}
                </button>
                <button
                  className="action-button"
                  disabled={disabled}
                  onClick={() =>
                    void perform(async () => {
                      const data = await invoke<Profile>("read_profile", {
                        id: profile.id,
                      });
                      setModal(
                        <Editor
                          profile={data}
                          onClose={() => setModal(null)}
                          onSave={async (yaml) => {
                            const ok = await perform(
                              () =>
                                invoke("save_profile", {
                                  id: profile.id,
                                  yaml,
                                }),
                              t("已保存，待应用"),
                            );
                            if (ok) setModal(null);
                            return ok;
                          }}
                        />,
                      );
                    })
                  }
                >
                  <PencilLine size={14} />
                  {t("编辑")}
                </button>
                {profile.pending && (
                  <button
                    className="button primary compact"
                    disabled={disabled}
                    onClick={() =>
                      void perform(
                        () => invoke("apply_pending", { id: profile.id }),
                        t("配置已应用"),
                      )
                    }
                  >
                    {t("应用更新")}
                  </button>
                )}
                <button
                  className="action-button"
                  disabled={disabled}
                  title={t("回滚到上一版本")}
                  aria-label={t("回滚 {name}", { name: profile.name })}
                  onClick={() =>
                    setModal(
                      <Confirm
                        title={t("回滚到上一版本？")}
                        text={t("运行中会重启内核，现有连接将断开。")}
                        onClose={() => setModal(null)}
                        onConfirm={async () => {
                          setModal(null);
                          await perform(() =>
                            invoke("rollback_profile", {
                              id: profile.id,
                            }),
                          );
                        }}
                      />,
                    )
                  }
                >
                  <Undo2 size={14} />
                  {t("回滚")}
                </button>
                <button
                  className="action-button"
                  disabled={disabled}
                  aria-label={t("加密导出 {name}", {
                    name: profile.name,
                  })}
                  onClick={() => exportEncrypted(profile)}
                >
                  <FileLock2 size={14} />
                  {t("加密导出")}
                </button>
                <button
                  className="action-button"
                  disabled={disabled}
                  aria-label={t("发布 {name} 到 COS", {
                    name: profile.name,
                  })}
                  onClick={() => publishEncrypted(profile)}
                >
                  <CloudUpload size={14} />
                  {t("发布")}
                </button>
                <button
                  className="icon-button danger"
                  disabled={disabled}
                  title={t("删除配置")}
                  aria-label={t("删除 {name}", { name: profile.name })}
                  onClick={() =>
                    setModal(
                      <Confirm
                        title={t("删除「{name}」？", {
                          name: profile.name,
                        })}
                        text={t("配置及其历史版本将被删除。")}
                        danger
                        onClose={() => setModal(null)}
                        onConfirm={async () => {
                          setModal(null);
                          await perform(() =>
                            invoke("delete_profile", {
                              id: profile.id,
                            }),
                          );
                        }}
                      />,
                    )
                  }
                >
                  <Trash2 size={16} />
                </button>
              </div>
            </section>
          ))}
        </div>
      )}
      <p className="hint">
        {t(
          "支持 VLESS、Hysteria2 和 Tailscale 节点，导入时会跳过不兼容的项，不会改动原文件。",
        )}
      </p>
    </>
  );
}
