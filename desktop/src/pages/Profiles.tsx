import { useEffect, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  Check,
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
  type ImportResult,
  type Profile,
  type ProfileSummary,
  type PublishTarget,
  type Snapshot,
} from "../types";

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
/** Encrypts a profile and uploads it to Tencent COS, replacing the object. */
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
            className="button primary"
            disabled={disabled}
            onClick={addSubscription}
          >
            <Plus size={16} />
            {t("添加订阅")}
          </button>
        </div>
      </div>
      {!state.profiles.length ? (
        <Empty
          icon={<Layers3 />}
          title={t("还没有配置")}
          text={t("导入 YAML 文件或添加订阅链接。")}
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
