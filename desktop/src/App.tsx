import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import brandIcon from "../src-tauri/icons/clyntis-v3/brand-128.png";
import {
  locale,
  resolveLanguage,
  setLanguage,
  t,
  tx,
  type Language,
} from "./i18n";
import {
  Activity,
  ArrowDown,
  ArrowUp,
  ArrowRight,
  Check,
  ChevronRight,
  CircleAlert,
  Download,
  FileCode2,
  FileLock2,
  FolderOpen,
  Gauge,
  Globe2,
  Info,
  Layers3,
  Link2,
  LoaderCircle,
  Lock,
  Network,
  Pause,
  Play,
  Plus,
  Ban,
  Power,
  Wifi,
  RefreshCw,
  Route,
  Search,
  Settings2,
  ShieldCheck,
  Terminal,
  Trash2,
  CloudUpload,
  Undo2,
  ListFilter,
  ChevronUp,
  ChevronDown,
  PencilLine,
  X,
  Zap,
} from "lucide-react";
import {
  bytes,
  captureText,
  initial,
  modeText,
  statusText,
  type Capture,
  type Connection,
  type Connections,
  type Log,
  type ImportResult,
  type Mode,
  type Profile,
  type ProfileSummary,
  type Proxy,
  type Settings,
  type NodeStatus,
  nodeSummary,
  peerPathText,
  tailscaleStateText,
  type LogLevel,
  type Overrides,
  type AdblockSettings,
  type AdblockStatus,
  type NetworkStatus,
  type PublishTarget,
  type AdListFormat,
  adblockPresets,
  defaultAdblock,
  type CustomRules,
  type RouteTest,
  type DnsLeakAudit,
  type DnsLeakTest,
  type LeakProbe,
  ruleTypes,
  splitRule,
  type Snapshot,
  type Traffic,
} from "./types";

type Page =
  | "overview"
  | "proxies"
  | "profiles"
  | "rules"
  | "connections"
  | "logs"
  | "settings";
const pages: {
  id: Page;
  label: string;
  icon: typeof Gauge;
}[] = [
  {
    id: "overview",
    get label() {
      return t("概览");
    },
    icon: Gauge,
  },
  {
    id: "proxies",
    get label() {
      return t("节点");
    },
    icon: Globe2,
  },
  {
    id: "profiles",
    get label() {
      return t("配置");
    },
    icon: Layers3,
  },
  {
    id: "rules",
    get label() {
      return t("规则");
    },
    icon: ListFilter,
  },
  {
    id: "connections",
    get label() {
      return t("连接");
    },
    icon: Network,
  },
  {
    id: "logs",
    get label() {
      return t("日志");
    },
    icon: Terminal,
  },
  {
    id: "settings",
    get label() {
      return t("设置");
    },
    icon: Settings2,
  },
];

export default function App() {
  const [page, setPage] = useState<Page>("overview");
  const [state, setState] = useState<Snapshot>(initial);
  const [traffic, setTraffic] = useState<Traffic[]>([]);
  const [logs, setLogs] = useState<Log[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [modal, setModal] = useState<ReactNode>(null);
  // "Follow the system" re-renders when the system language changes.
  const [, setSystemLanguage] = useState(0);
  useEffect(() => {
    const changed = () => setSystemLanguage((n) => n + 1);
    window.addEventListener("languagechange", changed);
    return () => window.removeEventListener("languagechange", changed);
  }, []);
  // Set before any child renders, so every t() call below uses it.
  const interfaceLanguage = resolveLanguage(state.settings.language);
  setLanguage(interfaceLanguage);
  useEffect(() => {
    // The tray menu and the backend's messages follow the window.
    void invoke("set_language", { language: interfaceLanguage }).catch(
      () => {},
    );
  }, [interfaceLanguage]);
  const refresh = useCallback(async () => {
    const next = await invoke<Snapshot>("snapshot");
    setState(next);
    return next;
  }, []);
  const perform = useCallback(
    async (action: () => Promise<unknown>, success?: string) => {
      setBusy(true);
      setError(null);
      try {
        await action();
        await refresh();
        if (success) setNotice(success);
        return true;
      } catch (e) {
        setError(String(e));
        return false;
      } finally {
        setBusy(false);
      }
    },
    [refresh],
  );
  useEffect(() => {
    let alive = true;
    const unlisten: (() => void)[] = [];
    const register = async <T,>(
      event: string,
      handler: (payload: T) => void,
    ) => {
      const off = await listen<T>(event, ({ payload }) => {
        if (alive) handler(payload);
      });
      if (alive) unlisten.push(off);
      else off();
    };
    void (async () => {
      await Promise.all([
        register<Snapshot>("state", (next) => setState(next)),
        register<Traffic>("traffic", (tick) =>
          setTraffic((values) => [...values.slice(-59), tick]),
        ),
        register<Log>("log", (entry) =>
          setLogs((values) => [...values.slice(-1999), entry]),
        ),
      ]);
      const next = await invoke<Snapshot>("snapshot");
      if (alive) {
        setState(next);
        setLogs(next.logs);
        setLoaded(true);
      }
    })().catch(() => {
      if (alive) setError(t("无法连接 Clyntis 后台，请从桌面应用打开。"));
    });
    return () => {
      alive = false;
      unlisten.forEach((off) => off());
    };
  }, []);
  useEffect(() => {
    document.documentElement.dataset.theme = state.settings.theme;
  }, [state.settings.theme]);
  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(null), 4000);
    return () => clearTimeout(timer);
  }, [notice]);
  useEffect(() => {
    if (state.status === "stopped" || state.status === "failed") setTraffic([]);
  }, [state.status]);
  const running = state.status === "running";
  const transitioning =
    state.serviceStatus === "updating" ||
    ["starting", "stopping", "recovering"].includes(state.status);
  const disabled = busy || transitioning || !loaded;
  const selected = state.profiles.find((p) => p.id === state.selected);
  const currentPage = pages.find((p) => p.id === page)!;
  const showImportResult = (result: ImportResult) => {
    setPage("profiles");
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
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <img className="brand-icon" src={brandIcon} alt="" />
          <span>Clyntis</span>
        </div>
        <nav aria-label={t("主导航")}>
          {pages.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              className={`nav-item ${page === id ? "active" : ""}`}
              aria-label={label}
              title={label}
              onClick={() => setPage(id)}
              aria-current={page === id ? "page" : undefined}
            >
              <Icon size={19} />
              <span>{label}</span>
              {id === "profiles" && state.profiles.some((p) => p.pending) && (
                <span className="nav-dot" />
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">v{__APP_VERSION__}</div>
      </aside>
      <main>
        <header className="topbar">
          <h1>{currentPage.label}</h1>
          <span className={`status-pill ${running ? "connected" : ""}`}>
            <span className={`status-dot ${running ? "online" : ""}`} />
            {statusText[state.status]}
          </span>
        </header>
        <div className="content">
          {state.serviceStatus === "updating" && (
            <div className="alert info" role="status">
              <LoaderCircle size={16} className="spin" />
              <span>
                {t(
                  "正在更新辅助服务。请在系统弹窗中授权，用于配置虚拟网卡、路由、DNS 和系统代理，断开后会恢复网络设置。",
                )}
              </span>
            </div>
          )}
          {(error || state.error) && (
            <div className="alert" role="alert">
              <CircleAlert size={16} />
              <span>{error || state.error}</span>
              {error && (
                <button
                  className="icon-button"
                  aria-label={t("关闭")}
                  onClick={() => setError(null)}
                >
                  <X size={16} />
                </button>
              )}
            </div>
          )}
          {notice && (
            <div className="toast" role="status">
              <Check size={16} />
              {notice}
            </div>
          )}
          {page === "overview" && (
            <>
              <section
                className={`panel connect-card ${running ? "is-running" : ""}`}
              >
                <div className="connection-copy">
                  <h2>{statusText[state.status]}</h2>
                  {selected ? (
                    <p>{selected.name}</p>
                  ) : (
                    <button
                      className="text-button"
                      onClick={() => setPage("profiles")}
                    >
                      {t("添加配置")}
                      <ChevronRight size={14} />
                    </button>
                  )}
                  <div className="connection-details">
                    <div
                      className="segmented"
                      role="group"
                      aria-label={t("接管方式")}
                    >
                      {(["manual", "system", "tun"] as Capture[]).map(
                        (capture) => (
                          <button
                            key={capture}
                            disabled={disabled}
                            aria-pressed={state.settings.capture === capture}
                            className={
                              state.settings.capture === capture
                                ? "selected"
                                : ""
                            }
                            onClick={() =>
                              void perform(() =>
                                invoke("set_capture", { capture }),
                              )
                            }
                          >
                            {captureText[capture]}
                          </button>
                        ),
                      )}
                    </div>
                    <span>{modeText[state.mode]}</span>
                    <span>127.0.0.1:{state.settings.mixedPort}</span>
                  </div>
                </div>
                <button
                  className={`power-button ${running ? "on" : ""}`}
                  disabled={disabled || !selected}
                  aria-label={running ? t("停止连接") : t("启动连接")}
                  title={running ? t("断开") : t("连接")}
                  onClick={() =>
                    void perform(() => invoke(running ? "stop" : "start"))
                  }
                >
                  {transitioning ? (
                    <LoaderCircle size={26} className="spin" />
                  ) : (
                    <Power size={26} />
                  )}
                </button>
              </section>
              <div className="stat-grid">
                <Stat
                  label={t("下载")}
                  value={`${bytes(traffic.at(-1)?.down ?? 0)}/s`}
                  icon={<ArrowDown size={14} />}
                  tone="green"
                />
                <Stat
                  label={t("上传")}
                  value={`${bytes(traffic.at(-1)?.up ?? 0)}/s`}
                  icon={<ArrowUp size={14} />}
                  tone="blue"
                />
                <ConnectionStats running={running} />
              </div>
              <div className="overview-grid">
                <section className="panel traffic-panel">
                  <div className="panel-title">
                    <h3>{t("流量")}</h3>
                    <div className="chart-legend">
                      <span>
                        <i className="legend-dot green" />
                        {t("下载")}
                        <b>{bytes(traffic.at(-1)?.down ?? 0)}/s</b>
                      </span>
                      <span>
                        <i className="legend-dot blue" />
                        {t("上传")}
                        <b>{bytes(traffic.at(-1)?.up ?? 0)}/s</b>
                      </span>
                    </div>
                  </div>
                  <TrafficChart values={traffic} />
                  <div className="chart-axis">
                    <span>60s</span>
                    <span>30s</span>
                    <span>{t("现在")}</span>
                  </div>
                </section>
                <section className="panel routing-panel">
                  <div className="panel-title">
                    <h3>{t("路由模式")}</h3>
                  </div>
                  {(["rule", "global", "direct"] as Mode[]).map((mode) => (
                    <button
                      key={mode}
                      className={`mode-option ${state.mode === mode ? "selected" : ""}`}
                      disabled={disabled || !selected}
                      onClick={() =>
                        void perform(() => invoke("set_mode", { mode }))
                      }
                    >
                      <span className="radio-mark">
                        {state.mode === mode && <span />}
                      </span>
                      <span>
                        <strong>{modeText[mode]}</strong>
                        <small>
                          {
                            {
                              rule: t("按规则分流"),
                              global: t("全部走代理"),
                              direct: t("全部直连"),
                            }[mode]
                          }
                        </small>
                      </span>
                    </button>
                  ))}
                </section>
              </div>
              {running && <NetworkPanel />}
              {running && (
                <AdblockPanel settings={state.settings} perform={perform} />
              )}
            </>
          )}
          {page === "profiles" && (
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
                              time: new Date(
                                profile.lastChecked * 1000,
                              ).toLocaleString(locale(), {
                                dateStyle: "short",
                                timeStyle: "short",
                              }),
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
                              const data = await invoke<Profile>(
                                "read_profile",
                                { id: profile.id },
                              );
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
                                () =>
                                  invoke("apply_pending", { id: profile.id }),
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
          )}
          {page === "proxies" && (
            <Proxies
              running={running}
              mode={state.mode}
              busy={disabled}
              perform={perform}
            />
          )}
          {page === "rules" && (
            <RulesPage busy={disabled} running={running} confirm={setModal} />
          )}
          {page === "connections" && (
            <ConnectionPage running={running} perform={perform} />
          )}
          {page === "logs" && <LogPage logs={logs} perform={perform} />}
          {page === "settings" && (
            <SettingsPage
              state={state}
              busy={disabled}
              perform={perform}
              confirm={setModal}
            />
          )}
        </div>
      </main>
      {modal}
    </div>
  );
}

function delayTone(delay: number | null | undefined) {
  if (delay === null) return "unavailable";
  if (delay === undefined) return "";
  return delay < 150 ? "fast" : delay < 300 ? "medium" : "slow";
}
/** The core's built-in outbounds, by name or by the type it reports. */
function builtinOutbound(
  name: string,
  proxy: Proxy | undefined,
): "direct" | "reject" | null {
  const kind = (proxy?.type ?? name).toLowerCase();
  if (kind === "direct" || kind === "pass") return "direct";
  if (kind.startsWith("reject")) return "reject";
  return null;
}
/** A group member that routes rather than carries traffic: another group
 * or a built-in outbound. Everything else is a proxy server. */
function isPolicy(name: string, proxy: Proxy | undefined) {
  return !!proxy?.all || builtinOutbound(name, proxy) !== null;
}
const groupTypeText: Record<string, string> = {
  Selector: t("手动"),
  URLTest: t("自动"),
  Fallback: t("故障转移"),
  LoadBalance: t("负载均衡"),
};
/** Proxy groups folded on the nodes page; a per-viewer convenience. */
const collapsedKey = "clyntis.collapsed-groups";
function loadCollapsed(): string[] {
  try {
    const value = JSON.parse(localStorage.getItem(collapsedKey) ?? "[]");
    return Array.isArray(value) ? value : [];
  } catch {
    return [];
  }
}

/** Which half of the nodes page is shown; a per-viewer convenience. */
type NodesView = "groups" | "proxies";
const nodesViewKey = "clyntis.nodes-view";
function loadNodesView(): NodesView {
  try {
    return localStorage.getItem(nodesViewKey) === "proxies"
      ? "proxies"
      : "groups";
  } catch {
    return "groups";
  }
}

type Perform = (
  action: () => Promise<unknown>,
  success?: string,
) => Promise<boolean>;
function Stat({
  label,
  value,
  icon,
  tone = "neutral",
}: {
  label: string;
  value: string;
  icon: ReactNode;
  tone?: string;
}) {
  return (
    <section className="panel stat">
      <span>
        <span className={`stat-icon ${tone}`}>{icon}</span>
        {label}
      </span>
      <strong>{value}</strong>
    </section>
  );
}
function ConnectionStats({ running }: { running: boolean }) {
  const [value, setValue] = useState<Connections>({
    connections: [],
    uploadTotal: 0,
    downloadTotal: 0,
  });
  useEffect(() => {
    let live = true;
    if (!running) {
      setValue({ connections: [], uploadTotal: 0, downloadTotal: 0 });
      return;
    }
    const update = () =>
      void invoke<Connections>("connections")
        .then((v) => {
          if (live) setValue(v);
        })
        .catch(() => {});
    update();
    const timer = setInterval(update, 2000);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [running]);
  return (
    <>
      <Stat
        label={t("连接数")}
        value={String(value.connections.length)}
        icon={<Network size={14} />}
      />
      <Stat
        label={t("总流量")}
        value={bytes(value.uploadTotal + value.downloadTotal)}
        icon={<Activity size={14} />}
      />
    </>
  );
}
function TrafficChart({ values }: { values: Traffic[] }) {
  const max = Math.max(1024, ...values.flatMap((v) => [v.up, v.down]));
  const line = (key: keyof Traffic) =>
    Array.from({ length: 60 }, (_, i) => {
      const value = values[i - (60 - values.length)]?.[key] ?? 0;
      return `${(i * 600) / 59},${132 - (value / max) * 110}`;
    }).join(" ");
  return (
    <div className="traffic-chart">
      <span className="chart-max">{bytes(max)}/s</span>
      <span className="chart-max half">{bytes(max / 2)}/s</span>
      <svg
        viewBox="0 0 600 150"
        preserveAspectRatio="none"
        role="img"
        aria-label={t("最近 60 秒上传和下载速率")}
      >
        <defs>
          <linearGradient id="download-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity=".16" />
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
          </linearGradient>
          <linearGradient id="upload-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--upload)" stopOpacity=".22" />
            <stop offset="100%" stopColor="var(--upload)" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[22, 77, 132].map((y) => (
          <line
            key={y}
            x1="0"
            x2="600"
            y1={y}
            y2={y}
            stroke="var(--border)"
            vectorEffect="non-scaling-stroke"
          />
        ))}
        <polygon
          points={`0,150 ${line("down")} 600,150`}
          fill="url(#download-fill)"
        />
        <polyline
          points={line("down")}
          fill="none"
          stroke="var(--accent)"
          strokeWidth="1.5"
          strokeLinejoin="round"
          vectorEffect="non-scaling-stroke"
        />
        <polygon
          points={`0,132 ${line("up")} 600,132`}
          fill="url(#upload-fill)"
        />
        <polyline
          points={line("up")}
          fill="none"
          stroke="var(--upload)"
          strokeWidth="2"
          strokeLinejoin="round"
          vectorEffect="non-scaling-stroke"
        />
      </svg>
    </div>
  );
}
function Empty({
  icon,
  title,
  text,
  children,
}: {
  icon: ReactNode;
  title: string;
  text?: string;
  children?: ReactNode;
}) {
  return (
    <section className="panel empty">
      <span className="empty-icon">{icon}</span>
      <h2>{title}</h2>
      {text && <p>{text}</p>}
      {children}
    </section>
  );
}
export function Modal({
  title,
  onClose,
  children,
  wide = false,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  // Callers pass a new onClose on every render; reading it through a ref keeps
  // the effect below to mount and unmount. Re-running it on each parent render
  // moved focus back to the dialog, closing an open <select> and interrupting
  // typing.
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    const previous = document.activeElement as HTMLElement;
    // Leave focus on an autoFocus field inside the dialog.
    if (!ref.current?.contains(document.activeElement)) ref.current?.focus();
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") close.current();
      if (event.key === "Tab") {
        const items = ref.current?.querySelectorAll<HTMLElement>(
          'button:not(:disabled),input,textarea,select,[tabindex="0"]',
        );
        if (!items?.length) return;
        const first = items[0],
          last = items[items.length - 1];
        if (
          event.shiftKey &&
          (document.activeElement === first ||
            document.activeElement === ref.current)
        ) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", handler);
    return () => {
      document.removeEventListener("keydown", handler);
      previous?.focus();
    };
  }, []);
  return (
    <div className="modal-backdrop">
      <div
        className={`modal ${wide ? "wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        ref={ref}
      >
        <div className="modal-heading">
          <h2>{title}</h2>
          <button
            className="icon-button"
            aria-label={t("关闭")}
            onClick={onClose}
          >
            <X size={18} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
function Confirm({
  title,
  text,
  danger,
  onClose,
  onConfirm,
}: {
  title: string;
  text: string;
  danger?: boolean;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}) {
  return (
    <Modal title={title} onClose={onClose}>
      <p className="muted">{text}</p>
      <div className="modal-actions">
        <button className="button secondary" onClick={onClose}>
          {t("取消")}
        </button>
        <button
          className={`button ${danger ? "destructive" : "primary"}`}
          onClick={() => void onConfirm()}
        >
          {t("确认")}
        </button>
      </div>
    </Modal>
  );
}
function PasswordForm({
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
function PublishForm({
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
function SubscriptionForm({
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
type YamlProblem = { line: number; column: number; message: string };
/** Editor text metrics, kept in step with `.yaml-editor` in styles.css. */
const editorPadding = 1 + 12; // border + padding
const editorLine = 12 * 1.6;
export function Editor({
  profile,
  onClose,
  onSave,
}: {
  profile: Profile;
  onClose: () => void;
  onSave: (yaml: string) => Promise<boolean>;
}) {
  const [yaml, setYaml] = useState(profile.pending ?? profile.yaml);
  const [saving, setSaving] = useState(false);
  const [failed, setFailed] = useState(false);
  const [problem, setProblem] = useState<YamlProblem | null>(null);
  const [scroll, setScroll] = useState(0);
  const area = useRef<HTMLTextAreaElement>(null);
  // Check while typing, after a short pause; a stale answer is ignored.
  useEffect(() => {
    let current = true;
    const timer = setTimeout(() => {
      invoke<YamlProblem | null>("check_yaml", { yaml })
        .then((found) => current && setProblem(found ?? null))
        .catch(() => current && setProblem(null));
    }, 250);
    return () => {
      current = false;
      clearTimeout(timer);
    };
  }, [yaml]);
  const reveal = () => {
    const editor = area.current;
    if (!problem || !editor) return;
    const lines = yaml.split("\n");
    const offset =
      lines.slice(0, problem.line - 1).reduce((n, l) => n + l.length + 1, 0) +
      Math.min(problem.column - 1, lines[problem.line - 1]?.length ?? 0);
    editor.focus();
    editor.setSelectionRange(offset, offset);
    editor.scrollTop = Math.max(
      0,
      (problem.line - 1) * editorLine - editor.clientHeight / 2,
    );
  };
  return (
    <Modal
      title={t("编辑 · {name}", { name: profile.name })}
      onClose={onClose}
      wide
    >
      <p className="small muted">
        {t("保存时会校验，点「应用更新」后生效。内容含节点凭据，注意保密。")}
      </p>
      <div className={`yaml-field${problem ? " invalid" : ""}`}>
        {problem && (
          <div
            className="yaml-error-line"
            aria-hidden="true"
            style={{
              top: editorPadding + (problem.line - 1) * editorLine - scroll,
              height: editorLine,
            }}
          />
        )}
        <textarea
          ref={area}
          className="yaml-editor"
          aria-label={t("YAML 配置")}
          aria-invalid={problem ? true : undefined}
          aria-describedby={problem ? "yaml-problem" : undefined}
          value={yaml}
          onChange={(e) => setYaml(e.target.value)}
          onScroll={(e) => setScroll(e.currentTarget.scrollTop)}
          spellCheck={false}
          wrap="off"
        />
      </div>
      {problem && (
        <p className="inline-error yaml-problem" id="yaml-problem" role="alert">
          <button type="button" className="link-button" onClick={reveal}>
            {t("第 {line} 行第 {column} 列", {
              line: problem.line,
              column: problem.column,
            })}
          </button>
          {t("：{message}", { message: problem.message })}
        </p>
      )}
      {failed && (
        <p className="inline-error" role="alert">
          {t("保存失败，原配置未改动。关闭此窗口查看原因。")}
        </p>
      )}
      <div className="modal-actions">
        <button className="button secondary" onClick={onClose}>
          {t("取消")}
        </button>
        <button
          className="button primary"
          disabled={saving || problem !== null}
          title={problem ? t("先修正 YAML 格式错误") : undefined}
          onClick={() => {
            setSaving(true);
            void onSave(yaml)
              .then((ok) => setFailed(!ok))
              .finally(() => setSaving(false));
          }}
        >
          {saving && <LoaderCircle className="spin" size={16} />}
          {t("保存")}
        </button>
      </div>
    </Modal>
  );
}

/** The profile's networks the device is on, while the profile defines any. */
function NetworkPanel() {
  const [status, setStatus] = useState<NetworkStatus | null>(null);
  useEffect(() => {
    const load = () =>
      void invoke<NetworkStatus>("network_status")
        .then(setStatus)
        .catch(() => setStatus(null));
    load();
    const timer = window.setInterval(load, 5000);
    return () => window.clearInterval(timer);
  }, []);
  if (!status?.defined) return null;
  const facts = [
    status.info.type &&
      { wifi: "Wi-Fi", wired: t("有线"), cellular: t("蜂窝") }[
        status.info.type
      ],
    status.info.addresses.find((address) => !address.includes(":")),
    status.info.gateways.length > 0 &&
      t("网关 {gateways}", { gateways: status.info.gateways[0] }),
  ].filter(Boolean);
  return (
    <section className="panel network-panel">
      <div className="panel-title">
        <h3>
          <Wifi size={15} /> {t("当前网络")}
        </h3>
        <strong>
          {status.networks.length ? status.networks.join(t("、")) : t("未匹配")}
        </strong>
      </div>
      <p className="muted small">
        {facts.join(" · ")}
        {status.override &&
          ` · ${t("生效的覆盖：{override}", { override: status.override })}`}
      </p>
    </section>
  );
}

function AdblockPanel({
  settings,
  perform,
}: {
  settings: Settings;
  perform: Perform;
}) {
  const [status, setStatus] = useState<AdblockStatus | null>(null);
  const [open, setOpen] = useState(false);
  useEffect(() => {
    const load = () =>
      void invoke<AdblockStatus>("adblock_status")
        .then(setStatus)
        .catch(() => setStatus(null));
    load();
    const timer = window.setInterval(load, 3000);
    return () => window.clearInterval(timer);
  }, []);
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
function AdblockSettingsSection({
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
function Proxies({
  running,
  mode,
  busy,
  perform,
}: {
  running: boolean;
  mode: Mode;
  busy: boolean;
  perform: Perform;
}) {
  const [nodes, setNodes] = useState<Record<string, Proxy>>({});
  const [query, setQuery] = useState("");
  const [probing, setProbing] = useState<string[]>([]);
  const [delays, setDelays] = useState<Record<string, number | null>>({});
  const [detail, setDetail] = useState<string | null>(null);
  const [collapsed, setCollapsed] = useState(loadCollapsed);
  const [view, setView] = useState(loadNodesView);
  const chooseView = (next: NodesView) => {
    setView(next);
    setQuery("");
    try {
      localStorage.setItem(nodesViewKey, next);
    } catch {
      // The choice still holds for this session.
    }
  };
  const toggleGroup = (name: string) =>
    setCollapsed((current) => {
      const next = current.includes(name)
        ? current.filter((n) => n !== name)
        : [...current, name];
      try {
        localStorage.setItem(collapsedKey, JSON.stringify(next));
      } catch {
        // Folding still works for this session.
      }
      return next;
    });
  const refresh = useCallback(async () => {
    const data = await invoke<{ proxies: Record<string, Proxy> }>("proxies");
    setNodes(data.proxies);
  }, []);
  // Status (connections, Tailscale paths) changes on its own: poll while shown.
  useEffect(() => {
    if (!running) return;
    void refresh().catch(() => {});
    const timer = window.setInterval(
      () => void refresh().catch(() => {}),
      3000,
    );
    return () => window.clearInterval(timer);
  }, [running, refresh]);
  const probe = async (name: string) => {
    setProbing((p) => (p.includes(name) ? p : [...p, name]));
    try {
      const { delay } = await invoke<{ delay: number }>("probe_proxy", {
        name,
      });
      setDelays((d) => ({ ...d, [name]: delay }));
    } catch {
      setDelays((d) => ({ ...d, [name]: null }));
    } finally {
      setProbing((p) => p.filter((n) => n !== name));
    }
  };
  // Probes run outside `perform` so the rest of the UI stays usable; a small
  // pool keeps a large subscription from opening hundreds of probes at once.
  const probeAll = async () => {
    const queue = Object.values(nodes)
      .filter((p) => !isPolicy(p.name, p) && p.type !== "Tailscale")
      .map((p) => p.name);
    setProbing([...queue]);
    const worker = async () => {
      for (let name = queue.shift(); name; name = queue.shift())
        await probe(name);
    };
    await Promise.all(Array.from({ length: 6 }, worker));
  };
  if (!running)
    return (
      <Empty
        icon={<Globe2 />}
        title={t("未连接")}
        text={t("连接后可选择节点和测速。")}
      />
    );
  // GLOBAL only routes traffic in global mode; elsewhere it is noise.
  const groups = Object.values(nodes).filter(
    (p) => p.all && (p.name !== "GLOBAL" || mode === "global"),
  );
  const matches = (name: string) =>
    name.toLowerCase().includes(query.toLowerCase());
  // The profile's `proxies`: servers that carry traffic and can be probed.
  const servers = Object.values(nodes).filter((p) => !isPolicy(p.name, p));
  const shown = groups.length ? view : "proxies";
  const icon = (name: string) => {
    const builtin = builtinOutbound(name, nodes[name]);
    return nodes[name]?.all ? (
      <span className="node-icon" title={t("代理组")}>
        <Layers3 size={16} />
      </span>
    ) : builtin === "reject" ? (
      <span className="node-icon reject" title={t("拒绝")}>
        <Ban size={16} />
      </span>
    ) : builtin === "direct" ? (
      <span className="node-icon" title={t("直连")}>
        <ArrowRight size={16} />
      </span>
    ) : null;
  };
  const summary = (name: string) => {
    const node = nodes[name];
    const builtin = builtinOutbound(name, node);
    if (node?.all)
      return (
        t("代理组 · {type}", { type: groupTypeText[node.type] ?? node.type }) +
        (node.now ? ` · ${t("当前 {now}", { now: node.now })}` : "")
      );
    if (builtin === "direct") return t("直连，不经过代理");
    if (builtin === "reject") return t("拒绝连接");
    return nodeSummary(node?.status, node?.type);
  };
  const label = (name: string) => (
    <span>
      <strong>{name}</strong>
      <small
        className={
          nodes[name]?.status?.tailscale?.state === "error" ? "danger-text" : ""
        }
      >
        {summary(name)}
      </small>
    </span>
  );
  return (
    <>
      <div className="toolbar">
        <div>
          {groups.length > 0 && (
            <div className="segmented" role="group" aria-label={t("节点视图")}>
              {(["groups", "proxies"] as NodesView[]).map((v) => (
                <button
                  key={v}
                  aria-pressed={shown === v}
                  className={shown === v ? "selected" : ""}
                  onClick={() => chooseView(v)}
                >
                  {v === "groups" ? t("代理组") : t("节点")}
                  <span className="segment-count">
                    {v === "groups" ? groups.length : servers.length}
                  </span>
                </button>
              ))}
            </div>
          )}
          <label className="search">
            <Search size={16} />
            <input
              aria-label={t("搜索节点")}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={
                shown === "groups" ? t("搜索代理组或成员") : t("搜索节点")
              }
            />
          </label>
        </div>
        {shown === "proxies" && (
          <button
            className="button secondary"
            disabled={busy || !!probing.length}
            onClick={() => void probeAll()}
          >
            <Zap size={16} />
            {t("测速")}
          </button>
        )}
      </div>
      {shown === "groups" &&
        groups.map((group) => {
          // A search shows matches in every group, folded or not.
          const folded = !query && collapsed.includes(group.name);
          const members = (group.all ?? []).filter(
            (name) => matches(name) || matches(group.name),
          );
          if (query && !members.length) return null;
          // Groups and built-in outbounds route traffic; proxies carry it.
          const policies = members.filter((name) =>
            isPolicy(name, nodes[name]),
          );
          const proxies = members.filter(
            (name) => !isPolicy(name, nodes[name]),
          );
          const card = (name: string) => (
            <div
              className={`node-card ${isPolicy(name, nodes[name]) ? "policy" : ""} ${group.now === name ? "selected" : ""}`}
              key={name}
            >
              <button
                className="node-select"
                disabled={busy || group.type !== "Selector"}
                onClick={() =>
                  void perform(async () => {
                    await invoke("select_proxy", { group: group.name, name });
                    await refresh();
                  })
                }
              >
                {icon(name)}
                {label(name)}
                {group.now === name && <Check size={16} className="accent" />}
              </button>
            </div>
          );
          return (
            <section
              className={`panel proxy-group ${folded ? "folded" : ""}`}
              key={group.name}
            >
              <button
                className="group-header"
                aria-expanded={!folded}
                onClick={() => toggleGroup(group.name)}
              >
                <ChevronDown size={16} className="group-chevron" />
                <h3>
                  {group.name}
                  <span className="count-tag">{group.all?.length}</span>
                </h3>
                {folded && group.now && (
                  <span className="group-now">{group.now}</span>
                )}
                <span className="muted small">
                  {groupTypeText[group.type] ?? ""}
                </span>
              </button>
              {!folded && (
                <>
                  {policies.length > 0 && (
                    <>
                      <div className="member-label">
                        {t("策略")}
                        <span>{policies.length}</span>
                      </div>
                      <div className="node-grid">{policies.map(card)}</div>
                    </>
                  )}
                  {proxies.length > 0 && (
                    <>
                      {policies.length > 0 && (
                        <div className="member-label">
                          {t("节点")}
                          <span>{proxies.length}</span>
                        </div>
                      )}
                      <div className="node-grid">{proxies.map(card)}</div>
                    </>
                  )}
                </>
              )}
            </section>
          );
        })}
      {shown === "proxies" &&
        (() => {
          const list = servers.filter((p) => matches(p.name));
          if (!servers.length)
            return (
              <Empty
                icon={<Globe2 />}
                title={t("没有节点")}
                text={t("当前配置没有代理节点。")}
              />
            );
          if (!list.length)
            return (
              <Empty
                icon={<Search />}
                title={t("没有匹配的节点")}
                text={t("换个关键词试试。")}
              />
            );
          return (
            <section className="panel proxy-list">
              <div className="node-grid">
                {list.map(({ name }) => {
                  const delay =
                    name in delays
                      ? delays[name]
                      : nodes[name]?.history.at(-1)?.delay;
                  return (
                    <div className="node-card" key={name}>
                      <div className="node-select">{label(name)}</div>
                      {nodes[name]?.status && (
                        <button
                          className="node-info"
                          aria-label={t("{name} 状态", { name })}
                          onClick={() => setDetail(name)}
                        >
                          <Info size={15} />
                        </button>
                      )}
                      {nodes[name]?.type !== "Tailscale" && (
                        <button
                          className={`delay ${delayTone(delay)}`}
                          aria-label={t("测试 {name} 延迟", { name })}
                          disabled={busy || probing.includes(name)}
                          onClick={() => void probe(name)}
                        >
                          {probing.includes(name) ? (
                            <LoaderCircle className="spin" size={13} />
                          ) : delay === null ? (
                            t("超时")
                          ) : delay === undefined ? (
                            t("测速")
                          ) : (
                            `${delay} ms`
                          )}
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            </section>
          );
        })()}
      {detail && nodes[detail]?.status && (
        <Modal title={detail} onClose={() => setDetail(null)} wide>
          <NodeDetail
            status={nodes[detail].status!}
            probing={probing.includes(detail)}
            onProbe={() => void probe(detail).then(refresh)}
          />
        </Modal>
      )}
    </>
  );
}
function NodeDetail({
  status,
  probing,
  onProbe,
}: {
  status: NodeStatus;
  probing: boolean;
  onProbe: () => void;
}) {
  const ts = status.tailscale;
  const rows: [string, string][] = [
    [t("类型"), status.type],
    [t("当前连接"), String(status.connections)],
  ];
  if (status.server) rows.push([t("服务器"), status.server]);
  if (status.network) rows.push([t("传输"), status.network]);
  if (status.security) rows.push([t("安全"), status.security.toUpperCase()]);
  if (status.flow) rows.push(["Flow", status.flow]);
  if (status.udp !== undefined)
    rows.push(["UDP", status.udp ? t("开启") : t("关闭")]);
  if (ts) {
    rows.push([t("状态"), tailscaleStateText[ts.state]]);
    if (ts.name) rows.push([t("本机名称"), ts.name]);
    if (ts.addresses.length) rows.push([t("地址"), ts.addresses.join("、")]);
    if (ts.home_derp) rows.push([t("DERP 主区域"), ts.home_derp]);
    rows.push([t("公网候选"), ts.endpoints.join("、") || t("无")]);
  }
  return (
    <div className="node-detail">
      <dl className="detail-list">
        {rows.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
      {ts?.error && <p className="danger-text small">{ts.error}</p>}
      {status.type === "VLESS" && (
        <div className="detail-probe">
          <span
            className={
              status.error && status.delay == null ? "danger-text" : ""
            }
          >
            {status.delay != null
              ? t("最近一次 {delay} ms", { delay: status.delay })
              : status.error
                ? t("测速失败：{error}", { error: status.error })
                : t("尚未测速")}
            {status.checked
              ? ` · ${new Date(status.checked * 1000).toLocaleTimeString(locale())}`
              : ""}
          </span>
          <button
            className="button secondary"
            disabled={probing}
            onClick={onProbe}
          >
            {probing ? (
              <LoaderCircle className="spin" size={14} />
            ) : (
              <Zap size={14} />
            )}
            {t("测速")}
          </button>
        </div>
      )}
      {ts && (
        <>
          <h4 className="detail-heading">
            {t("节点（{online}/{total} 在线）", {
              online: ts.peers.filter((p) => p.online).length,
              total: ts.peers.length,
            })}
          </h4>
          <div className="peer-list">
            {ts.peers.map((peer) => (
              <div className="peer-row" key={`${peer.name}-${peer.address}`}>
                <span className={`peer-dot ${peer.online ? "online" : ""}`} />
                <span className="peer-name">
                  <strong>{peer.name}</strong>
                  {peer.exit_node && (
                    <span className="tiny-tag">{t("出口")}</span>
                  )}
                  <small>
                    {[peer.address, peer.os, peer.direct]
                      .filter(Boolean)
                      .join(" · ")}
                  </small>
                </span>
                <span className={`peer-path ${peer.path}`}>
                  {peerPathText(peer)}
                </span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
function ConnectionPage({
  running,
  perform,
}: {
  running: boolean;
  perform: Perform;
}) {
  const [items, setItems] = useState<Connection[]>([]);
  const [query, setQuery] = useState("");
  const [failed, setFailed] = useState(false);
  const refresh = useCallback(async () => {
    const value = await invoke<Connections>("connections");
    setItems(value.connections);
    setFailed(false);
  }, []);
  useEffect(() => {
    if (!running) return;
    let alive = true;
    const tick = () =>
      void refresh().catch(() => {
        if (alive) setFailed(true);
      });
    tick();
    const timer = setInterval(tick, 2000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [running, refresh]);
  if (!running)
    return (
      <Empty
        icon={<Network />}
        title={t("未连接")}
        text={t("连接后显示活跃连接。")}
      />
    );
  const visible = items.filter((item) =>
    `${item.metadata.host} ${item.chains.join(" ")}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  return (
    <>
      <div className="toolbar">
        <label className="search">
          <Search size={16} />
          <input
            placeholder={t("搜索目标或代理链")}
            aria-label={t("搜索连接")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </label>
        <button
          className="button secondary"
          disabled={!items.length}
          onClick={() =>
            void perform(async () => {
              await invoke("close_connection", { id: null });
              await refresh();
            })
          }
        >
          {t("全部断开")}
        </button>
      </div>
      {failed && (
        <p className="inline-error" role="alert">
          {t("刷新失败，正在重试。")}
        </p>
      )}
      <div className="panel table-wrap">
        <table className="connection-table">
          <thead>
            <tr>
              <th>{t("目标地址")}</th>
              <th>{t("协议 / 代理链")}</th>
              <th className="num">{t("下载")}</th>
              <th className="num">{t("上传")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {visible.map((item) => (
              <tr key={item.id}>
                <td>
                  <strong>{item.metadata.host}</strong>
                  <span className="muted">:{item.metadata.port}</span>
                </td>
                <td>
                  <span className="route-line">
                    <span className="tiny-tag">
                      {item.network.toUpperCase()}
                    </span>
                    <span className="muted">{item.chains.join(" → ")}</span>
                  </span>
                </td>
                <td className="num">{bytes(item.download)}</td>
                <td className="num">{bytes(item.upload)}</td>
                <td>
                  <button
                    className="icon-button"
                    aria-label={t("关闭 {host} 连接", {
                      host: item.metadata.host,
                    })}
                    onClick={() =>
                      void perform(async () => {
                        await invoke("close_connection", { id: item.id });
                        await refresh();
                      })
                    }
                  >
                    <X size={15} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!visible.length && (
          <div className="table-empty">
            {items.length ? t("无匹配结果") : t("暂无连接")}
          </div>
        )}
      </div>
      <p className="small muted table-note">
        {t("{count} 个连接", { count: items.length })}
      </p>
    </>
  );
}
function RulesPage({
  busy,
  running,
  confirm,
}: {
  busy: boolean;
  running: boolean;
  confirm: (modal: ReactNode) => void;
}) {
  const [data, setData] = useState<CustomRules | null>(null);
  const [type, setType] = useState(ruleTypes[0].type);
  const [value, setValue] = useState("");
  const [target, setTarget] = useState("");
  const [noResolve, setNoResolve] = useState(false);
  const [saving, setSaving] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  useEffect(() => {
    void invoke<CustomRules>("custom_rules")
      .then((next) => {
        setData(next);
        setTarget((current) => current || next.targets[0] || "DIRECT");
      })
      .catch((e) => setFailure(String(e)));
  }, []);
  const save = async (rules: string[]) => {
    setSaving(true);
    setFailure(null);
    try {
      setData(await invoke<CustomRules>("save_custom_rules", { rules }));
      return true;
    } catch (e) {
      setFailure(String(e));
      return false;
    } finally {
      setSaving(false);
    }
  };
  if (!data) return failure ? <p className="inline-error">{failure}</p> : null;
  const ip = type === "IP-CIDR" || type === "IP-CIDR6" || type === "GEOIP";
  const placeholder = ruleTypes.find((rule) => rule.type === type)?.placeholder;
  const add = async () => {
    const rule = [
      type,
      value.trim(),
      target,
      ...(ip && noResolve ? ["no-resolve"] : []),
    ].join(",");
    if (await save([rule, ...data.rules])) setValue("");
  };
  const move = (index: number, delta: number) => {
    const rules = [...data.rules];
    const [rule] = rules.splice(index, 1);
    rules.splice(index + delta, 0, rule);
    void save(rules);
  };
  const skipped = new Map(data.skipped.map((s) => [s.rule, s.reason]));
  const disabled = busy || saving;
  return (
    <>
      <h3 className="settings-heading">{t("自定义规则")}</h3>
      <section className="panel settings-section rule-form">
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void add();
          }}
        >
          <select
            aria-label={t("规则类型")}
            value={type}
            onChange={(e) => setType(e.target.value)}
          >
            {ruleTypes.map((rule) => (
              <option key={rule.type} value={rule.type}>
                {rule.label}
              </option>
            ))}
          </select>
          <input
            aria-label={t("规则值")}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={placeholder}
            spellCheck={false}
            autoComplete="off"
          />
          <select
            aria-label={t("目标")}
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          >
            {data.targets.map((target) => (
              <option key={target}>{target}</option>
            ))}
          </select>
          {ip && (
            <label className="rule-check">
              <input
                type="checkbox"
                checked={noResolve}
                onChange={(e) => setNoResolve(e.target.checked)}
              />
              {t("不解析域名")}
            </label>
          )}
          <button
            className="button primary"
            disabled={disabled || !value.trim()}
          >
            {saving ? (
              <LoaderCircle className="spin" size={16} />
            ) : (
              <Plus size={16} />
            )}
            {t("添加")}
          </button>
        </form>
      </section>
      {failure && (
        <p className="inline-error" role="alert">
          {failure}
        </p>
      )}
      <div className="toolbar">
        <span className="muted small">
          {t("{count} 条规则 · 优先于配置中的规则，按顺序匹配", {
            count: data.rules.length,
          })}
          {running ? ` · ${t("修改后立即生效")}` : ""}
        </span>
        <button
          className="button secondary"
          disabled={disabled}
          onClick={() =>
            confirm(
              <BulkRules
                rules={data.rules}
                onClose={() => confirm(null)}
                onSave={async (rules) => {
                  const ok = await save(rules);
                  if (ok) confirm(null);
                  return ok;
                }}
              />,
            )
          }
        >
          <PencilLine size={16} />
          {t("批量编辑")}
        </button>
      </div>
      {!data.rules.length ? (
        <Empty
          icon={<ListFilter />}
          title={t("还没有自定义规则")}
          text={t("自定义规则对所有配置生效，并且优先于配置自带的规则。")}
        />
      ) : (
        <div className="panel table-wrap">
          <table className="rule-table">
            <thead>
              <tr>
                <th>{t("类型")}</th>
                <th>{t("值")}</th>
                <th>{t("目标")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data.rules.map((rule, index) => {
                const parts = splitRule(rule);
                const reason = skipped.get(rule);
                return (
                  <tr key={`${index}-${rule}`}>
                    <td>
                      <span className="tiny-tag">
                        {ruleTypes.find((rule) => rule.type === parts.type)
                          ?.label ?? parts.type}
                      </span>
                    </td>
                    <td>
                      <strong>{parts.value}</strong>
                      {parts.noResolve && (
                        <span className="chain">{t("不解析域名")}</span>
                      )}
                      {reason && (
                        <span className="chain danger">
                          {t("{reason}，当前配置下不生效", { reason })}
                        </span>
                      )}
                    </td>
                    <td>{parts.target}</td>
                    <td className="rule-actions">
                      <button
                        className="icon-button"
                        aria-label={t("上移 {rule}", { rule })}
                        disabled={disabled || index === 0}
                        onClick={() => move(index, -1)}
                      >
                        <ChevronUp size={15} />
                      </button>
                      <button
                        className="icon-button"
                        aria-label={t("下移 {rule}", { rule })}
                        disabled={disabled || index === data.rules.length - 1}
                        onClick={() => move(index, 1)}
                      >
                        <ChevronDown size={15} />
                      </button>
                      <button
                        className="icon-button danger"
                        aria-label={t("删除 {rule}", { rule })}
                        disabled={disabled}
                        onClick={() =>
                          void save(data.rules.filter((_, i) => i !== index))
                        }
                      >
                        <Trash2 size={15} />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {data.profile && (
        <p className="hint">
          {t(
            "目标列表来自当前配置「{profile}」；切换到没有该代理组的配置时，对应规则会被跳过。",
            { profile: data.profile },
          )}
        </p>
      )}
      <h3 className="settings-heading spaced">{t("诊断")}</h3>
      <RouteTester running={running} customRules={data.rules} />
      <DnsLeakPanel running={running} rules={data.rules} />
    </>
  );
}
const routeMatchText: Record<string, string> = {
  Adblock: t("去广告拦截（优先于所有规则）"),
  "Adblock(HTTPDNS)": t("去广告：HTTPDNS / 加密 DNS 入口"),
  "Adblock(IP)": t("去广告：列表中的 IP"),
  "Adblock(QUIC)": t("去广告：没有域名的 QUIC，回退到 TCP"),
  "Mode(Global)": t("全局模式"),
  "Mode(Direct)": t("直连模式"),
  Fallback: t("没有规则匹配，默认直连"),
};
function RouteTester({
  running,
  customRules,
}: {
  running: boolean;
  customRules: string[];
}) {
  const [target, setTarget] = useState("");
  const [network, setNetwork] = useState<"tcp" | "udp">("tcp");
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<RouteTest | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const test = async () => {
    setTesting(true);
    setFailure(null);
    try {
      setResult(
        await invoke<RouteTest>("test_route", {
          target: target.trim(),
          network,
        }),
      );
    } catch (e) {
      setResult(null);
      setFailure(String(e));
    } finally {
      setTesting(false);
    }
  };
  return (
    <section className="panel settings-section route-test">
      <div className="panel-title">
        <h3>
          <Route size={16} />
          {t("路由测试")}
        </h3>
      </div>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void test();
        }}
      >
        <input
          aria-label={t("测试目标")}
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder={t("测试域名或 IP，如 www.google.com、8.8.8.8:53")}
          spellCheck={false}
          autoComplete="off"
        />
        <select
          aria-label={t("网络")}
          value={network}
          onChange={(e) => setNetwork(e.target.value as "tcp" | "udp")}
        >
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
        </select>
        <button
          className="button secondary"
          disabled={!running || testing || !target.trim()}
          title={running ? undefined : t("启动内核后可测试")}
        >
          {testing ? (
            <LoaderCircle className="spin" size={16} />
          ) : (
            <Search size={16} />
          )}
          {t("测试")}
        </button>
      </form>
      {!running && <p className="small muted">{t("启动内核后可测试路由。")}</p>}
      {failure && (
        <p className="inline-error" role="alert">
          {failure}
        </p>
      )}
      {result && (
        <dl className="route-result" aria-label={t("路由测试结果")}>
          <dt>{t("目标")}</dt>
          <dd>
            {result.host.includes(":") ? `[${result.host}]` : result.host}:
            {result.port} · {result.network.toUpperCase()}
            {result.ip && result.ip !== result.host && (
              <span className="chain">
                {t("解析为 {ip}", { ip: result.ip })}
              </span>
            )}
          </dd>
          <dt>{t("匹配规则")}</dt>
          <dd>
            {result.rule ? (
              <>
                <strong>{result.rule}</strong>
                <span className="chain">
                  {t("第 {index} 条", { index: (result.index ?? 0) + 1 })}
                  {customRules.includes(result.rule)
                    ? ` · ${t("自定义规则")}`
                    : ""}
                </span>
              </>
            ) : (
              <strong>
                {routeMatchText[result.matched] ?? result.matched}
              </strong>
            )}
          </dd>
          <dt>{t("出站节点")}</dt>
          <dd>
            <strong
              className={result.node === "REJECT" ? "danger-text" : undefined}
            >
              {result.node}
            </strong>
            {result.chain.length > 1 && (
              <span className="chain">{result.chain.join(" → ")}</span>
            )}
            {result.resolved_locally &&
              result.node !== "DIRECT" &&
              result.node !== "REJECT" && (
                <span className="chain danger">
                  {t("匹配前已在本地解析域名，存在 DNS 泄露")}
                </span>
              )}
          </dd>
        </dl>
      )}
    </section>
  );
}
const findingLevelText = {
  risk: t("泄露"),
  warning: t("注意"),
  info: t("提示"),
};
const leakVerdictText = {
  leak: t("存在泄露：本地上游看到了走代理的域名"),
  ok: t("未发现泄露"),
  direct: t("直连，无代理路径可检查"),
  unknown: t("无法判断"),
};
function LeakResolvers({
  title,
  probe,
  verdict,
}: {
  title: string;
  probe: LeakProbe;
  verdict?: DnsLeakTest["verdict"];
}) {
  const status =
    probe.error ??
    (verdict
      ? leakVerdictText[verdict]
      : probe.resolvers.length
        ? t("本地解析由这些服务器完成")
        : t("没有结果"));
  return (
    <div className="leak-probe">
      <div className="leak-probe-title">
        <strong>{title}</strong>
        <span
          className={
            probe.error || verdict === "leak" ? "danger-text" : "muted"
          }
        >
          {status}
        </span>
      </div>
      {probe.resolvers.map((server) => (
        <div key={server.ip} className="leak-server">
          <code>{server.ip}</code>
          <span className="muted">
            {[server.country, server.asn].filter(Boolean).join(" · ")}
          </span>
        </div>
      ))}
    </div>
  );
}
function DnsLeakPanel({
  running,
  rules,
}: {
  running: boolean;
  rules: string[];
}) {
  const [audit, setAudit] = useState<DnsLeakAudit | null>(null);
  const [test, setTest] = useState<DnsLeakTest | null>(null);
  const [testing, setTesting] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const check = useCallback(() => {
    setFailure(null);
    void invoke<DnsLeakAudit>("dns_leak_audit")
      .then(setAudit)
      .catch((e) => setFailure(String(e)));
  }, []);
  useEffect(() => {
    // Custom rules apply at once while running: review them again.
    if (running) check();
    else setAudit(null);
  }, [running, rules, check]);
  const runTest = async () => {
    setTesting(true);
    setFailure(null);
    try {
      setTest(await invoke<DnsLeakTest>("dns_leak_test"));
      check();
    } catch (e) {
      setFailure(String(e));
    } finally {
      setTesting(false);
    }
  };
  return (
    <section className="panel settings-section dns-leak">
      <div className="panel-title">
        <h3>
          <ShieldCheck size={16} />
          {t("DNS 泄露检测")}
        </h3>
        <button
          className="button secondary"
          disabled={!running || testing}
          onClick={() => void runTest()}
        >
          {testing ? (
            <LoaderCircle className="spin" size={16} />
          ) : (
            <Globe2 size={16} />
          )}
          {testing ? t("检测中…") : t("在线检测")}
        </button>
      </div>
      {!running && <p className="small muted">{t("启动内核后可检测。")}</p>}
      {failure && (
        <p className="inline-error" role="alert">
          {failure}
        </p>
      )}
      {audit && (
        <>
          <p className={audit.leaking ? "danger-text" : "muted small"}>
            {audit.leaking
              ? t("配置检查发现 DNS 泄露风险")
              : audit.findings.length
                ? t("配置检查未发现泄露，但有以下提示")
                : t("配置检查未发现问题")}
          </p>
          {audit.findings.map((finding) => (
            <div key={finding.code} className={`leak-finding ${finding.level}`}>
              <div>
                <span className="leak-level">
                  {findingLevelText[finding.level]}
                </span>
                <strong>{finding.title}</strong>
              </div>
              <p className="small muted">{finding.detail}</p>
              {finding.items.length > 0 && (
                <ul>
                  {finding.items.map((item) => (
                    <li key={item}>
                      <code>{item}</code>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </>
      )}
      {test && (
        <div className="leak-test" aria-label={t("在线检测结果")}>
          <div className="leak-server">
            <strong>{t("出口 IP")}</strong>
            <span>
              {test.exit.length
                ? test.exit
                    .map((e) =>
                      [e.ip, e.country, e.asn].filter(Boolean).join(" · "),
                    )
                    .join("，")
                : t("未知")}
            </span>
          </div>
          <p className="small muted">
            {test.node === "DIRECT"
              ? t(
                  "bash.ws 当前经「{node}」（{matched}）访问，结果反映直连时的情况；让 bash.ws 走代理后再测可检查代理路径。",
                  { node: test.node, matched: test.matched },
                )
              : t("bash.ws 当前经「{node}」（{matched}）访问。", {
                  node: test.node,
                  matched: test.matched,
                })}
          </p>
          <LeakResolvers
            title={t("应用访问时的解析器")}
            probe={test.routed}
            verdict={test.verdict}
          />
          <LeakResolvers
            title={t("内核上游 DNS 的解析器")}
            probe={test.local}
          />
        </div>
      )}
      <p className="hint">
        {t(
          "配置检查在本地完成；在线检测会向 bash.ws 发送随机域名，并暴露出口和解析器的 IP。",
        )}
      </p>
    </section>
  );
}
function BulkRules({
  rules,
  onClose,
  onSave,
}: {
  rules: string[];
  onClose: () => void;
  onSave: (rules: string[]) => Promise<boolean>;
}) {
  const [text, setText] = useState(rules.join("\n"));
  const [saving, setSaving] = useState(false);
  return (
    <Modal title={t("批量编辑规则")} onClose={onClose} wide>
      <p className="small muted">
        {t(
          "每行一条，格式为「类型,值,目标」，越靠前优先级越高。保存时会校验每一条。",
        )}
      </p>
      <textarea
        className="yaml-editor"
        aria-label={t("自定义规则")}
        value={text}
        onChange={(e) => setText(e.target.value)}
        spellCheck={false}
        placeholder={
          "DOMAIN-SUFFIX,example.com,DIRECT\nIP-CIDR,10.0.0.0/8,DIRECT,no-resolve"
        }
      />
      <div className="modal-actions">
        <button className="button secondary" onClick={onClose}>
          {t("取消")}
        </button>
        <button
          className="button primary"
          disabled={saving}
          onClick={() => {
            setSaving(true);
            const lines = text
              .split("\n")
              .map((l) => l.trim())
              .filter((l) => l && !l.startsWith("#"));
            void onSave(lines).finally(() => setSaving(false));
          }}
        >
          {saving && <LoaderCircle className="spin" size={16} />}
          {t("保存")}
        </button>
      </div>
    </Modal>
  );
}
/** Quiet the parts of a log line the eye skips (network tags, local
 * addresses, arrows) so destinations and rules stand out. */
const quietLogPart =
  /(\[(?:TCP|UDP)\]|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b|-->)/;
function LogPayload({ text }: { text: string }) {
  return (
    <span>
      {text.split(quietLogPart).map((part, i) =>
        i % 2 ? (
          <span key={i} className="log-quiet">
            {part}
          </span>
        ) : (
          part
        ),
      )}
    </span>
  );
}
function LogPage({ logs, perform }: { logs: Log[]; perform: Perform }) {
  const [level, setLevel] = useState("all");
  const [paused, setPaused] = useState(false);
  const [frozen, setFrozen] = useState<Log[]>([]);
  const [query, setQuery] = useState("");
  // Newest first: logs arrive oldest-first, so reverse the filtered copy.
  const visible = (paused ? frozen : logs)
    .filter(
      (log) =>
        (level === "all" || log.type === level) &&
        log.payload.toLowerCase().includes(query.toLowerCase()),
    )
    .reverse();
  return (
    <>
      <div className="toolbar">
        <div>
          <select
            aria-label={t("日志级别")}
            value={level}
            onChange={(e) => setLevel(e.target.value)}
          >
            <option value="all">{t("全部")}</option>
            {["debug", "info", "warning", "error"].map((v) => (
              <option key={v}>{v}</option>
            ))}
          </select>
          <label className="search">
            <Search size={16} />
            <input
              aria-label={t("搜索日志")}
              placeholder={t("搜索日志")}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </label>
        </div>
        <div>
          <button
            className="button secondary"
            onClick={() => {
              if (!paused) setFrozen(logs);
              setPaused(!paused);
            }}
          >
            {paused ? <Play size={15} /> : <Pause size={15} />}
            {paused ? t("继续") : t("暂停")}
          </button>
          <button
            className="button secondary"
            onClick={() =>
              void perform(async () => {
                const path = await save({
                  defaultPath: "clyntis-logs.jsonl",
                  filters: [{ name: t("日志"), extensions: ["jsonl"] }],
                });
                if (path) await invoke("export_logs", { path });
              })
            }
          >
            <Download size={15} />
            {t("导出")}
          </button>
        </div>
      </div>
      <div className="panel logs-panel" role="log" aria-live="off">
        {visible.length ? (
          visible.map((log, i) => (
            <div className={`log-row ${log.type}`} key={`${log.time}-${i}`}>
              <time>
                {new Date(log.time * 1000).toLocaleTimeString(locale(), {
                  hour12: false,
                })}
              </time>
              <span className={`log-level ${log.type}`}>
                {log.type === "warning" ? "WARN" : log.type.toUpperCase()}
              </span>
              <LogPayload text={log.payload} />
            </div>
          ))
        ) : (
          <div className="table-empty">{t("暂无日志")}</div>
        )}
      </div>
      <p className="small muted table-note">
        {t("保留最近 2000 条，URL、UUID 和凭据已脱敏。")}
      </p>
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

function SettingsPage({
  state,
  busy,
  perform,
  confirm,
}: {
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
function Setting({
  label,
  text,
  children,
}: {
  label: string;
  text?: string;
  children: ReactNode;
}) {
  return (
    <div className="setting-row">
      <div>
        <strong>{label}</strong>
        {text && <p>{text}</p>}
      </div>
      <div className="setting-control">{children}</div>
    </div>
  );
}
function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      className={`toggle ${checked ? "checked" : ""}`}
      onClick={() => onChange(!checked)}
    >
      <span />
    </button>
  );
}
