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
  Activity,
  ArrowDown,
  ArrowUp,
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
  RefreshCw,
  Search,
  Settings2,
  ShieldCheck,
  Terminal,
  Trash2,
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
    label: "概览",
    icon: Gauge,
  },
  {
    id: "proxies",
    label: "节点",
    icon: Globe2,
  },
  {
    id: "profiles",
    label: "配置",
    icon: Layers3,
  },
  {
    id: "rules",
    label: "规则",
    icon: ListFilter,
  },
  {
    id: "connections",
    label: "连接",
    icon: Network,
  },
  {
    id: "logs",
    label: "日志",
    icon: Terminal,
  },
  {
    id: "settings",
    label: "设置",
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
      if (alive) setError("无法连接 Clyntis 后台，请从桌面应用打开。");
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
        <Modal title="导入完成" onClose={() => setModal(null)}>
          <p>
            已创建「{result.profile.name}」，跳过 {result.warnings.length}{" "}
            项不兼容内容：
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
              知道了
            </button>
          </div>
        </Modal>,
      );
    } else {
      setModal(null);
      setNotice(`已导入「${result.profile.name}」`);
    }
  };
  const importFile = async () => {
    const path = await open({
      multiple: false,
      filters: [{ name: "配置文件", extensions: ["yaml", "yml", "txt"] }],
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
        title="导入加密配置"
        text="此文件已加密，输入密码后导入。"
        submitLabel="解密并导入"
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
        title={`加密导出「${profile.name}」`}
        text="导出的文件需要此密码才能导入。导出的是当前生效的版本。"
        submitLabel="选择位置并导出"
        confirm
        onClose={() => setModal(null)}
        onSubmit={async (password) => {
          try {
            const path = await save({
              defaultPath: `${profile.name}.txt`,
              filters: [{ name: "加密配置", extensions: ["txt"] }],
            });
            if (!path) return "";
            await invoke("export_encrypted", {
              id: profile.id,
              password,
              path,
            });
            setModal(null);
            setNotice("已加密导出");
            return null;
          } catch (e) {
            return String(e);
          }
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
        <nav aria-label="主导航">
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
                正在更新辅助服务。请在系统弹窗中授权，用于配置虚拟网卡、路由、DNS
                和系统代理，断开后会恢复网络设置。
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
                  aria-label="关闭"
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
                      添加配置 <ChevronRight size={14} />
                    </button>
                  )}
                  <div className="connection-details">
                    <span>{captureText[state.settings.capture]}</span>
                    <span>{modeText[state.mode]}</span>
                    <span>127.0.0.1:{state.settings.mixedPort}</span>
                  </div>
                </div>
                <button
                  className={`power-button ${running ? "on" : ""}`}
                  disabled={disabled || !selected}
                  aria-label={running ? "停止连接" : "启动连接"}
                  title={running ? "断开" : "连接"}
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
                  label="下载"
                  value={`${bytes(traffic.at(-1)?.down ?? 0)}/s`}
                  icon={<ArrowDown size={14} />}
                  tone="green"
                />
                <Stat
                  label="上传"
                  value={`${bytes(traffic.at(-1)?.up ?? 0)}/s`}
                  icon={<ArrowUp size={14} />}
                  tone="blue"
                />
                <ConnectionStats running={running} />
              </div>
              <div className="overview-grid">
                <section className="panel traffic-panel">
                  <div className="panel-title">
                    <h3>流量</h3>
                    <div className="chart-legend">
                      <span>
                        <i className="legend-dot green" />
                        下载
                      </span>
                      <span>
                        <i className="legend-dot blue" />
                        上传
                      </span>
                    </div>
                  </div>
                  <TrafficChart values={traffic} />
                  <div className="chart-axis">
                    <span>60s</span>
                    <span>30s</span>
                    <span>现在</span>
                  </div>
                </section>
                <section className="panel routing-panel">
                  <div className="panel-title">
                    <h3>路由模式</h3>
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
                              rule: "按规则分流",
                              global: "全部走代理",
                              direct: "全部直连",
                            }[mode]
                          }
                        </small>
                      </span>
                    </button>
                  ))}
                </section>
              </div>
              {running && (
                <AdblockPanel settings={state.settings} perform={perform} />
              )}
              <div className="capture-strip">
                <span className="muted">接管</span>
                <div className="segmented">
                  {(["manual", "system", "tun"] as Capture[]).map((capture) => (
                    <button
                      key={capture}
                      disabled={disabled}
                      className={
                        state.settings.capture === capture ? "selected" : ""
                      }
                      onClick={() =>
                        void perform(() => invoke("set_capture", { capture }))
                      }
                    >
                      {captureText[capture]}
                    </button>
                  ))}
                </div>
                <button
                  className="text-button"
                  onClick={() => setPage("settings")}
                >
                  辅助服务 <ChevronRight size={14} />
                </button>
              </div>
            </>
          )}
          {page === "profiles" && (
            <>
              <div className="toolbar">
                <span className="muted small">
                  {state.profiles.length} 个配置
                </span>
                <div>
                  <button
                    className="button secondary"
                    disabled={disabled}
                    onClick={() => void perform(importFile)}
                  >
                    <FolderOpen size={16} />
                    导入文件
                  </button>
                  <button
                    className="button primary"
                    disabled={disabled}
                    onClick={addSubscription}
                  >
                    <Plus size={16} />
                    添加订阅
                  </button>
                </div>
              </div>
              {!state.profiles.length ? (
                <Empty
                  icon={<Layers3 />}
                  title="还没有配置"
                  text="导入 YAML 文件或添加订阅链接。"
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
                                aria-label="加密订阅"
                              />
                            )}
                            {profile.source} · 检查于{" "}
                            {new Date(
                              profile.lastChecked * 1000,
                            ).toLocaleString("zh-CN", {
                              dateStyle: "short",
                              timeStyle: "short",
                            })}
                          </p>
                        </div>
                        {profile.pending && (
                          <span className="pending-tag">待应用</span>
                        )}
                      </div>
                      {profile.lastError && (
                        <p className="inline-error">{profile.lastError}</p>
                      )}
                      <div className="profile-actions">
                        <button
                          className="button secondary compact"
                          disabled={disabled || profile.id === state.selected}
                          onClick={() =>
                            void perform(() =>
                              invoke("select_profile", { id: profile.id }),
                            )
                          }
                        >
                          {profile.id === state.selected ? "使用中" : "使用"}
                        </button>
                        {profile.subscription && (
                          <button
                            className="icon-button"
                            disabled={disabled}
                            title="检查更新"
                            aria-label={`更新 ${profile.name}`}
                            onClick={() =>
                              void perform(
                                () =>
                                  invoke("update_subscription", {
                                    id: profile.id,
                                  }),
                                "已检查更新",
                              )
                            }
                          >
                            <RefreshCw size={16} />
                          </button>
                        )}
                        <button
                          className="text-button"
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
                                      "已保存，待应用",
                                    );
                                    if (ok) setModal(null);
                                    return ok;
                                  }}
                                />,
                              );
                            })
                          }
                        >
                          编辑
                        </button>
                        {profile.pending && (
                          <button
                            className="button primary compact"
                            disabled={disabled}
                            onClick={() =>
                              void perform(
                                () =>
                                  invoke("apply_pending", { id: profile.id }),
                                "配置已应用",
                              )
                            }
                          >
                            应用更新
                          </button>
                        )}
                        <button
                          className="icon-button"
                          disabled={disabled}
                          title="回滚到上一版本"
                          aria-label={`回滚 ${profile.name}`}
                          onClick={() =>
                            setModal(
                              <Confirm
                                title="回滚到上一版本？"
                                text="运行中会重启内核，现有连接将断开。"
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
                          <Undo2 size={16} />
                        </button>
                        <button
                          className="icon-button"
                          disabled={disabled}
                          title="加密导出"
                          aria-label={`加密导出 ${profile.name}`}
                          onClick={() => exportEncrypted(profile)}
                        >
                          <FileLock2 size={16} />
                        </button>
                        <button
                          className="icon-button danger"
                          disabled={disabled}
                          title="删除配置"
                          aria-label={`删除 ${profile.name}`}
                          onClick={() =>
                            setModal(
                              <Confirm
                                title={`删除「${profile.name}」？`}
                                text="配置及其历史版本将被删除。"
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
                支持 VLESS 和 Tailscale
                节点，导入时会跳过不兼容的项，不会改动原文件。
              </p>
            </>
          )}
          {page === "proxies" && (
            <Proxies running={running} busy={disabled} perform={perform} />
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
  return delay < 300 ? "fast" : "slow";
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
        label="连接数"
        value={String(value.connections.length)}
        icon={<Network size={14} />}
      />
      <Stat
        label="总流量"
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
      <svg
        viewBox="0 0 600 150"
        preserveAspectRatio="none"
        role="img"
        aria-label="最近 60 秒上传和下载速率"
      >
        <defs>
          <linearGradient id="download-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity=".16" />
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[22, 58, 95, 132].map((y) => (
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
        <polyline
          points={line("up")}
          fill="none"
          stroke="var(--upload)"
          strokeWidth="1.5"
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
          <button className="icon-button" aria-label="关闭" onClick={onClose}>
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
          取消
        </button>
        <button
          className={`button ${danger ? "destructive" : "primary"}`}
          onClick={() => void onConfirm()}
        >
          确认
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
          密码
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
            确认密码
            <input
              required
              type="password"
              value={repeat}
              onChange={(e) => setRepeat(e.target.value)}
              autoComplete="new-password"
            />
          </label>
        )}
        {mismatch && <p className="inline-error">两次输入的密码不一致</p>}
        {failure && (
          <p role="alert" className="inline-error">
            {failure}
          </p>
        )}
        <div className="modal-actions">
          <button type="button" className="button secondary" onClick={onClose}>
            取消
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
    <Modal title="添加订阅" onClose={onClose}>
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
          配置名称
          <input
            autoFocus
            required
            maxLength={100}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="例如：日常使用"
          />
        </label>
        <label className="field">
          订阅 URL
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
          解密密码（可选）
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="订阅内容未加密时留空"
            autoComplete="off"
          />
        </label>
        <p className="small muted">
          仅支持 HTTPS。密码保存在本机，用于之后自动更新时解密。
        </p>
        {failed && (
          <p role="alert" className="inline-error">
            添加失败，关闭此窗口查看原因。
          </p>
        )}
        <div className="modal-actions">
          <button type="button" className="button secondary" onClick={onClose}>
            取消
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
            添加
          </button>
        </div>
      </form>
    </Modal>
  );
}
function Editor({
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
  return (
    <Modal title={`编辑 · ${profile.name}`} onClose={onClose} wide>
      <p className="small muted">
        保存时会校验，点「应用更新」后生效。内容含节点凭据，注意保密。
      </p>
      <textarea
        className="yaml-editor"
        aria-label="YAML 配置"
        value={yaml}
        onChange={(e) => setYaml(e.target.value)}
        spellCheck={false}
      />
      {failed && (
        <p className="inline-error" role="alert">
          保存失败，原配置未改动。关闭此窗口查看原因。
        </p>
      )}
      <div className="modal-actions">
        <button className="button secondary" onClick={onClose}>
          取消
        </button>
        <button
          className="button primary"
          disabled={saving}
          onClick={() => {
            setSaving(true);
            void onSave(yaml)
              .then((ok) => setFailed(!ok))
              .finally(() => setSaving(false));
          }}
        >
          {saving && <LoaderCircle className="spin" size={16} />}
          保存
        </button>
      </div>
    </Modal>
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
      `已放行 ${domain}`,
    );
  };
  if (!status) return null;
  return (
    <section className="panel adblock-panel">
      <div className="panel-title">
        <h3>
          <Ban size={15} /> 去广告
        </h3>
        {status.enabled ? (
          <button className="text-button" onClick={() => setOpen(true)}>
            详情
          </button>
        ) : (
          <span className="muted small">未开启，可在设置中启用</span>
        )}
      </div>
      {status.enabled && (
        <div className="adblock-summary">
          <div className="adblock-metrics">
            <div>
              <strong>{status.total.toLocaleString()}</strong>
              <small>次拦截</small>
            </div>
            <div>
              <strong>{status.dns.toLocaleString()}</strong>
              <small>DNS</small>
            </div>
            <div>
              <strong>{status.connections.toLocaleString()}</strong>
              <small>连接</small>
            </div>
            <div>
              <strong>{status.entries.toLocaleString()}</strong>
              <small>条规则</small>
            </div>
          </div>
          <div className="adblock-top">
            <small>拦截最多</small>
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
              <span className="muted">暂无拦截</span>
            )}
          </div>
        </div>
      )}
      {open && (
        <Modal title="去广告统计" onClose={() => setOpen(false)} wide>
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
    new Date(seconds * 1000).toLocaleTimeString();
  return (
    <div className="node-detail">
      <p className="muted small">
        自 {new Date(status.since * 1000).toLocaleString()} 起，共拦截{" "}
        {status.total} 次（DNS {status.dns}，连接 {status.connections}），涉及{" "}
        {status.domains} 个域名。误拦时点「放行」加入白名单，立即生效。
      </p>
      <dl className="detail-list">
        {status.lists.map((list) => (
          <div key={list.name}>
            <dt>{list.name}</dt>
            <dd className={list.error ? "danger-text" : ""}>
              {list.error
                ? `不可用：${list.error}`
                : `${list.entries.toLocaleString()} 条${list.updated ? ` · 更新于 ${new Date(list.updated * 1000).toLocaleString()}` : ""}`}
            </dd>
          </div>
        ))}
      </dl>
      <h4 className="detail-heading">拦截最多</h4>
      <div className="peer-list">
        {status.top.length === 0 && (
          <div className="peer-row muted">暂无拦截</div>
        )}
        {status.top.map((item) => (
          <div className="peer-row" key={item.domain}>
            <span className="peer-name">
              <strong>{item.domain}</strong>
            </span>
            <span className="peer-path">{item.count} 次</span>
            <button
              className="text-button"
              onClick={() => onAllow(item.domain)}
            >
              放行
            </button>
          </div>
        ))}
      </div>
      <h4 className="detail-heading">最近拦截</h4>
      <div className="peer-list">
        {status.recent.length === 0 && (
          <div className="peer-row muted">暂无拦截</div>
        )}
        {status.recent.map((item, index) => (
          <div
            className="peer-row"
            key={`${item.time}-${item.domain}-${index}`}
          >
            <span className="peer-name">
              <strong>{item.domain}</strong>
              <small>
                {time(item.time)} · {item.via === "dns" ? "DNS" : "连接"}
              </small>
            </span>
            <button
              className="text-button"
              onClick={() => onAllow(item.domain)}
            >
              放行
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
        label="启用去广告"
        text="广告域名在 DNS 层直接拒绝，并优先于所有规则"
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
          label="启用去广告"
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
                移除
              </button>
            </Setting>
          ))}
          <Setting
            label="自定义列表"
            text="Clash 规则集、hosts 或 AdGuard 格式的链接"
          >
            <button
              className="button secondary"
              onClick={() => setDialog("list")}
            >
              <Plus size={14} />
              添加
            </button>
          </Setting>
          <Setting
            label="白名单"
            text={
              adblock.allow.length
                ? `${adblock.allow.length} 个域名，包含其子域名；保存后立即生效，无需重启`
                : "误拦的域名加入这里，包含其子域名；也可在概览的统计里一键放行"
            }
          >
            <button
              className="button secondary"
              onClick={() => setDialog("allow")}
            >
              管理
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
    <Modal title="添加自定义列表" onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (valid) onAdd({ name: name.trim(), url: url.trim(), format });
        }}
      >
        <label className="field">
          名称
          <input
            autoFocus
            maxLength={64}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="例如：我的广告列表"
          />
        </label>
        <label className="field">
          链接
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
          格式
          <select
            value={format}
            onChange={(e) => setFormat(e.target.value as AdListFormat)}
          >
            <option value="clash">Clash 规则集（yaml 或 text）</option>
            <option value="hosts">hosts（0.0.0.0 域名）</option>
            <option value="adguard">AdGuard（||域名^）</option>
          </select>
        </label>
        {duplicate && (
          <p role="alert" className="inline-error">
            已有同名列表。
          </p>
        )}
        <p className="small muted">保存设置后下载，之后每天自动更新。</p>
        <div className="modal-actions">
          <button type="button" className="button secondary" onClick={onClose}>
            取消
          </button>
          <button className="button primary" disabled={!valid}>
            添加
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
    <Modal title="白名单" onClose={onClose}>
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
          placeholder="例如：wechat.com"
          autoComplete="off"
          spellCheck={false}
        />
        <button className="button secondary" disabled={!valid}>
          <Plus size={14} />
          添加
        </button>
      </form>
      <div className="allow-list">
        {value.length === 0 && (
          <div className="allow-row muted">还没有放行的域名</div>
        )}
        {value.map((item) => (
          <div className="allow-row" key={item}>
            <span>{item}</span>
            <button
              className="icon-button"
              aria-label={`移除 ${item}`}
              onClick={() => onChange(value.filter((d) => d !== item))}
            >
              <X size={14} />
            </button>
          </div>
        ))}
      </div>
      <p className="small muted">
        包含子域名。记得点设置页底部的「保存」，保存后立即生效，无需重启。
      </p>
      <div className="modal-actions">
        <button className="button primary" onClick={onClose}>
          完成
        </button>
      </div>
    </Modal>
  );
}
function Proxies({
  running,
  busy,
  perform,
}: {
  running: boolean;
  busy: boolean;
  perform: Perform;
}) {
  const [nodes, setNodes] = useState<Record<string, Proxy>>({});
  const [query, setQuery] = useState("");
  const [probing, setProbing] = useState<string[]>([]);
  const [delays, setDelays] = useState<Record<string, number | null>>({});
  const [detail, setDetail] = useState<string | null>(null);
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
      .filter((p) => p.type === "VLESS")
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
      <Empty icon={<Globe2 />} title="未连接" text="连接后可选择节点和测速。" />
    );
  const groups = Object.values(nodes).filter((p) => p.all);
  return (
    <>
      <div className="toolbar">
        <label className="search">
          <Search size={16} />
          <input
            aria-label="搜索节点"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="搜索节点"
          />
        </label>
        <button
          className="button secondary"
          disabled={busy || !!probing.length}
          onClick={() => void probeAll()}
        >
          <Zap size={16} />
          测速
        </button>
      </div>
      {(groups.length
        ? groups
        : [
            {
              name: "全部节点",
              type: "readOnly",
              all: Object.keys(nodes),
              history: [],
            } as Proxy,
          ]
      ).map((group) => (
        <section className="panel proxy-group" key={group.name}>
          <div className="panel-title">
            <h3>
              {group.name}
              <span className="count-tag">{group.all?.length}</span>
            </h3>
            <span className="muted small">
              {group.type === "Selector"
                ? "手动"
                : group.type === "URLTest"
                  ? "自动"
                  : ""}
            </span>
          </div>
          <div className="node-grid">
            {group.all
              ?.filter((name) =>
                name.toLowerCase().includes(query.toLowerCase()),
              )
              .map((name) => {
                const delay =
                  name in delays
                    ? delays[name]
                    : nodes[name]?.history.at(-1)?.delay;
                return (
                  <div
                    className={`node-card ${group.now === name ? "selected" : ""}`}
                    key={name}
                  >
                    <button
                      className="node-select"
                      disabled={busy || group.type !== "Selector"}
                      onClick={() =>
                        void perform(async () => {
                          await invoke("select_proxy", {
                            group: group.name,
                            name,
                          });
                          await refresh();
                        })
                      }
                    >
                      <span className="node-icon">
                        <Globe2 size={18} />
                      </span>
                      <span>
                        <strong>{name}</strong>
                        <small
                          className={
                            nodes[name]?.status?.tailscale?.state === "error"
                              ? "danger-text"
                              : ""
                          }
                        >
                          {nodeSummary(nodes[name]?.status, nodes[name]?.type)}
                        </small>
                      </span>
                      {group.now === name && (
                        <Check size={16} className="accent" />
                      )}
                    </button>
                    {nodes[name]?.status && (
                      <button
                        className="node-info"
                        aria-label={`${name} 状态`}
                        onClick={() => setDetail(name)}
                      >
                        <Info size={15} />
                      </button>
                    )}
                    {nodes[name]?.type === "Tailscale" ? null : (
                      <button
                        className={`delay ${delayTone(delay)}`}
                        aria-label={`测试 ${name} 延迟`}
                        disabled={
                          busy ||
                          probing.includes(name) ||
                          ["DIRECT", "REJECT"].includes(name)
                        }
                        onClick={() => void probe(name)}
                      >
                        {probing.includes(name) ? (
                          <LoaderCircle className="spin" size={13} />
                        ) : delay === null ? (
                          "超时"
                        ) : delay === undefined ? (
                          "测速"
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
      ))}
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
    ["类型", status.type],
    ["当前连接", String(status.connections)],
  ];
  if (status.server) rows.push(["服务器", status.server]);
  if (status.network) rows.push(["传输", status.network]);
  if (status.security) rows.push(["安全", status.security.toUpperCase()]);
  if (status.flow) rows.push(["Flow", status.flow]);
  if (status.udp !== undefined)
    rows.push(["UDP", status.udp ? "开启" : "关闭"]);
  if (ts) {
    rows.push(["状态", tailscaleStateText[ts.state]]);
    if (ts.name) rows.push(["本机名称", ts.name]);
    if (ts.addresses.length) rows.push(["地址", ts.addresses.join("、")]);
    if (ts.home_derp) rows.push(["DERP 主区域", ts.home_derp]);
    rows.push(["公网候选", ts.endpoints.join("、") || "无"]);
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
              ? `最近一次 ${status.delay} ms`
              : status.error
                ? `测速失败：${status.error}`
                : "尚未测速"}
            {status.checked
              ? ` · ${new Date(status.checked * 1000).toLocaleTimeString()}`
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
            测速
          </button>
        </div>
      )}
      {ts && (
        <>
          <h4 className="detail-heading">
            节点（{ts.peers.filter((p) => p.online).length}/{ts.peers.length}{" "}
            在线）
          </h4>
          <div className="peer-list">
            {ts.peers.map((peer) => (
              <div className="peer-row" key={`${peer.name}-${peer.address}`}>
                <span className={`peer-dot ${peer.online ? "online" : ""}`} />
                <span className="peer-name">
                  <strong>{peer.name}</strong>
                  {peer.exit_node && <span className="tiny-tag">出口</span>}
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
      <Empty icon={<Network />} title="未连接" text="连接后显示活跃连接。" />
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
            placeholder="搜索目标或代理链"
            aria-label="搜索连接"
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
          全部断开
        </button>
      </div>
      {failed && (
        <p className="inline-error" role="alert">
          刷新失败，正在重试。
        </p>
      )}
      <div className="panel table-wrap">
        <table>
          <thead>
            <tr>
              <th>目标地址</th>
              <th>协议 / 代理链</th>
              <th>下载</th>
              <th>上传</th>
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
                  <span className="tiny-tag">{item.network.toUpperCase()}</span>
                  <span className="chain">{item.chains.join(" → ")}</span>
                </td>
                <td>{bytes(item.download)}</td>
                <td>{bytes(item.upload)}</td>
                <td>
                  <button
                    className="icon-button"
                    aria-label={`关闭 ${item.metadata.host} 连接`}
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
            {items.length ? "无匹配结果" : "暂无连接"}
          </div>
        )}
      </div>
      <p className="small muted table-note">{items.length} 个连接</p>
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
  const placeholder = ruleTypes.find((t) => t.type === type)?.placeholder;
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
      <RouteTester running={running} customRules={data.rules} />
      <DnsLeakPanel running={running} rules={data.rules} />
      <section className="panel settings-section rule-form">
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void add();
          }}
        >
          <select
            aria-label="规则类型"
            value={type}
            onChange={(e) => setType(e.target.value)}
          >
            {ruleTypes.map((t) => (
              <option key={t.type} value={t.type}>
                {t.label}
              </option>
            ))}
          </select>
          <input
            aria-label="规则值"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={placeholder}
            spellCheck={false}
            autoComplete="off"
          />
          <select
            aria-label="目标"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          >
            {data.targets.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
          {ip && (
            <label className="rule-check">
              <input
                type="checkbox"
                checked={noResolve}
                onChange={(e) => setNoResolve(e.target.checked)}
              />
              不解析域名
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
            添加
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
          {data.rules.length} 条规则 · 优先于配置中的规则，按顺序匹配
          {running ? " · 修改后立即生效" : ""}
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
          批量编辑
        </button>
      </div>
      {!data.rules.length ? (
        <Empty
          icon={<ListFilter />}
          title="还没有自定义规则"
          text="自定义规则对所有配置生效，并且优先于配置自带的规则。"
        />
      ) : (
        <div className="panel table-wrap">
          <table className="rule-table">
            <thead>
              <tr>
                <th>类型</th>
                <th>值</th>
                <th>目标</th>
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
                        {ruleTypes.find((t) => t.type === parts.type)?.label ??
                          parts.type}
                      </span>
                    </td>
                    <td>
                      <strong>{parts.value}</strong>
                      {parts.noResolve && (
                        <span className="chain">不解析域名</span>
                      )}
                      {reason && (
                        <span className="chain danger">
                          {reason}，当前配置下不生效
                        </span>
                      )}
                    </td>
                    <td>{parts.target}</td>
                    <td className="rule-actions">
                      <button
                        className="icon-button"
                        aria-label={`上移 ${rule}`}
                        disabled={disabled || index === 0}
                        onClick={() => move(index, -1)}
                      >
                        <ChevronUp size={15} />
                      </button>
                      <button
                        className="icon-button"
                        aria-label={`下移 ${rule}`}
                        disabled={disabled || index === data.rules.length - 1}
                        onClick={() => move(index, 1)}
                      >
                        <ChevronDown size={15} />
                      </button>
                      <button
                        className="icon-button danger"
                        aria-label={`删除 ${rule}`}
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
          目标列表来自当前配置「{data.profile}
          」；切换到没有该代理组的配置时，对应规则会被跳过。
        </p>
      )}
    </>
  );
}
const routeMatchText: Record<string, string> = {
  Adblock: "去广告拦截（优先于所有规则）",
  "Mode(Global)": "全局模式",
  "Mode(Direct)": "直连模式",
  Fallback: "没有规则匹配，默认直连",
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
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void test();
        }}
      >
        <input
          aria-label="测试目标"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="测试域名或 IP，如 www.google.com、8.8.8.8:53"
          spellCheck={false}
          autoComplete="off"
        />
        <select
          aria-label="网络"
          value={network}
          onChange={(e) => setNetwork(e.target.value as "tcp" | "udp")}
        >
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
        </select>
        <button
          className="button secondary"
          disabled={!running || testing || !target.trim()}
          title={running ? undefined : "启动内核后可测试"}
        >
          {testing ? (
            <LoaderCircle className="spin" size={16} />
          ) : (
            <Search size={16} />
          )}
          测试
        </button>
      </form>
      {!running && <p className="small muted">启动内核后可测试路由。</p>}
      {failure && (
        <p className="inline-error" role="alert">
          {failure}
        </p>
      )}
      {result && (
        <dl className="route-result" aria-label="路由测试结果">
          <dt>目标</dt>
          <dd>
            {result.host.includes(":") ? `[${result.host}]` : result.host}:
            {result.port} · {result.network.toUpperCase()}
            {result.ip && result.ip !== result.host && (
              <span className="chain">解析为 {result.ip}</span>
            )}
          </dd>
          <dt>匹配规则</dt>
          <dd>
            {result.rule ? (
              <>
                <strong>{result.rule}</strong>
                <span className="chain">
                  第 {(result.index ?? 0) + 1} 条
                  {customRules.includes(result.rule) ? " · 自定义规则" : ""}
                </span>
              </>
            ) : (
              <strong>
                {routeMatchText[result.matched] ?? result.matched}
              </strong>
            )}
          </dd>
          <dt>出站节点</dt>
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
                  匹配前已在本地解析域名，存在 DNS 泄露
                </span>
              )}
          </dd>
        </dl>
      )}
    </section>
  );
}
const findingLevelText = { risk: "泄露", warning: "注意", info: "提示" };
function leakConclusion(probe: LeakProbe) {
  if (probe.error) return probe.error;
  const text = probe.conclusion ?? "";
  if (/not leaking/i.test(text)) return "未发现泄露";
  if (/leak/i.test(text)) return "可能存在泄露";
  return text || "没有结果";
}
function LeakResolvers({ title, probe }: { title: string; probe: LeakProbe }) {
  return (
    <div className="leak-probe">
      <div className="leak-probe-title">
        <strong>{title}</strong>
        <span
          className={
            probe.error ||
            /may be leaking|leak detected/i.test(probe.conclusion ?? "")
              ? "danger-text"
              : "muted"
          }
        >
          {leakConclusion(probe)}
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
          DNS 泄露检测
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
          {testing ? "检测中…" : "在线检测"}
        </button>
      </div>
      {!running && <p className="small muted">启动内核后可检测。</p>}
      {failure && (
        <p className="inline-error" role="alert">
          {failure}
        </p>
      )}
      {audit && (
        <>
          <p className={audit.leaking ? "danger-text" : "muted small"}>
            {audit.leaking
              ? "配置检查发现 DNS 泄露风险"
              : audit.findings.length
                ? "配置检查未发现泄露，但有以下提示"
                : "配置检查未发现问题"}
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
        <div className="leak-test" aria-label="在线检测结果">
          <div className="leak-server">
            <strong>出口 IP</strong>
            <span>
              {test.exit.length
                ? test.exit
                    .map((e) =>
                      [e.ip, e.country, e.asn].filter(Boolean).join(" · "),
                    )
                    .join("，")
                : "未知"}
            </span>
          </div>
          <p className="small muted">
            bash.ws 当前经「{test.node}」（{test.matched}）访问
            {test.node === "DIRECT"
              ? "，结果反映直连时的情况；让 bash.ws 走代理后再测可检查代理路径。"
              : "。"}
          </p>
          <LeakResolvers title="应用访问时的解析器" probe={test.routed} />
          <LeakResolvers title="内核上游 DNS 的解析器" probe={test.local} />
        </div>
      )}
      <p className="hint">
        配置检查在本地完成；在线检测会向 bash.ws
        发送随机域名，并暴露出口和解析器的 IP。
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
    <Modal title="批量编辑规则" onClose={onClose} wide>
      <p className="small muted">
        每行一条，格式为「类型,值,目标」，越靠前优先级越高。保存时会校验每一条。
      </p>
      <textarea
        className="yaml-editor"
        aria-label="自定义规则"
        value={text}
        onChange={(e) => setText(e.target.value)}
        spellCheck={false}
        placeholder={
          "DOMAIN-SUFFIX,example.com,DIRECT\nIP-CIDR,10.0.0.0/8,DIRECT,no-resolve"
        }
      />
      <div className="modal-actions">
        <button className="button secondary" onClick={onClose}>
          取消
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
          保存
        </button>
      </div>
    </Modal>
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
            aria-label="日志级别"
            value={level}
            onChange={(e) => setLevel(e.target.value)}
          >
            <option value="all">全部</option>
            {["debug", "info", "warning", "error"].map((v) => (
              <option key={v}>{v}</option>
            ))}
          </select>
          <label className="search">
            <Search size={16} />
            <input
              aria-label="搜索日志"
              placeholder="搜索日志"
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
            {paused ? "继续" : "暂停"}
          </button>
          <button
            className="button secondary"
            onClick={() =>
              void perform(async () => {
                const path = await save({
                  defaultPath: "clyntis-logs.jsonl",
                  filters: [{ name: "日志", extensions: ["jsonl"] }],
                });
                if (path) await invoke("export_logs", { path });
              })
            }
          >
            <Download size={15} />
            导出
          </button>
        </div>
      </div>
      <div className="panel logs-panel" role="log" aria-live="off">
        {visible.length ? (
          visible.map((log, i) => (
            <div className="log-row" key={`${log.time}-${i}`}>
              <time>
                {new Date(log.time * 1000).toLocaleTimeString("zh-CN", {
                  hour12: false,
                })}
              </time>
              <span className={`log-level ${log.type}`}>
                {log.type.toUpperCase()}
              </span>
              <span>{log.payload}</span>
            </div>
          ))
        ) : (
          <div className="table-empty">暂无日志</div>
        )}
      </div>
      <p className="small muted table-note">
        保留最近 2000 条，URL、UUID 和凭据已脱敏。
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
      <option value="">跟随配置文件</option>
      <option value="true">开启</option>
      <option value="false">关闭</option>
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
  return (
    <>
      <h3 className="settings-heading">网络</h3>
      <section className="panel settings-section">
        <Setting label="接管方式" text="运行中切换会重启内核">
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
        <Setting label="代理端口" text="HTTP / SOCKS 共用">
          <input
            type="number"
            min={1024}
            max={65535}
            value={settings.mixedPort}
            onChange={(e) => update("mixedPort", Number(e.target.value))}
          />
        </Setting>
        <Setting label="允许局域网访问" text="同一网络的设备可连接此端口">
          <Toggle
            checked={settings.allowLan}
            onChange={(v) => update("allowLan", v)}
            label="允许局域网访问"
          />
        </Setting>
        <Setting label="TUN 自动 DNS" text="接管系统 DNS，断开后恢复">
          <Toggle
            checked={settings.autoDns}
            onChange={(v) => update("autoDns", v)}
            label="TUN 自动 DNS"
          />
        </Setting>
        <Setting label="出口网卡" text="留空自动选择，如 en0">
          <input
            value={settings.tunInterface ?? ""}
            placeholder="自动"
            onChange={(e) => update("tunInterface", e.target.value || null)}
          />
        </Setting>
      </section>
      <h3 className="settings-heading">覆盖配置文件</h3>
      <section className="panel settings-section">
        <Setting label="日志级别" text="debug 日志多，平时用 info">
          <select
            value={settings.overrides.logLevel ?? ""}
            onChange={(e) =>
              override("logLevel", (e.target.value || null) as LogLevel | null)
            }
          >
            <option value="">跟随配置文件</option>
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
        <Setting label="域名嗅探" text="从 TLS / HTTP 识别域名">
          <OverrideSwitch
            value={settings.overrides.sniffing}
            onChange={(v) => override("sniffing", v)}
          />
        </Setting>
      </section>
      <h3 className="settings-heading">去广告</h3>
      <section className="panel settings-section">
        <AdblockSettingsSection
          value={settings.overrides.adblock}
          onChange={(adblock) => override("adblock", adblock)}
        />
      </section>
      <h3 className="settings-heading">辅助服务</h3>
      <section className="panel settings-section">
        <div className="panel-title">
          <span className="service-note">TUN 和系统代理依赖此服务</span>
          <span className="tiny-tag">
            {{
              checking: "检查中",
              current: "已是最新",
              updating: "更新中",
              update_failed: "更新失败",
              installed: "已安装",
              enabled: "已启用",
              requires_approval: "待授权",
              not_installed: "未安装",
              not_registered: "未安装",
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
                "请在系统弹窗中授权",
              )
            }
          >
            <ShieldCheck size={16} />
            安装或更新
          </button>
          <button
            className="text-button danger"
            disabled={busy}
            onClick={() =>
              confirm(
                <Confirm
                  title="卸载辅助服务？"
                  text="会先断开连接并恢复网络设置。"
                  onClose={() => confirm(null)}
                  onConfirm={async () => {
                    confirm(null);
                    await perform(() => invoke("uninstall_service"));
                  }}
                />,
              )
            }
          >
            卸载
          </button>
        </div>
      </section>
      <h3 className="settings-heading">通用</h3>
      <section className="panel settings-section">
        <Setting label="外观">
          <select
            value={settings.theme}
            onChange={(e) =>
              update("theme", e.target.value as Settings["theme"])
            }
          >
            <option value="system">跟随系统</option>
            <option value="light">浅色</option>
            <option value="dark">深色</option>
          </select>
        </Setting>
        <Setting label="登录时启动">
          <Toggle
            checked={settings.launchAtLogin}
            onChange={(v) => update("launchAtLogin", v)}
            label="登录时启动"
          />
        </Setting>
        <Setting label="打开应用后自动连接" text="使用上次的配置">
          <Toggle
            checked={settings.autoConnect}
            onChange={(v) => update("autoConnect", v)}
            label="打开应用后自动连接"
          />
        </Setting>
        <Setting label="订阅更新间隔" text="0 为仅手动更新">
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
            <span>小时</span>
          </div>
        </Setting>
      </section>
      <div className="save-bar">
        {dirty && <span className="small muted">有未保存的更改</span>}
        <button
          className="button primary"
          disabled={
            busy ||
            !dirty ||
            settings.mixedPort < 1024 ||
            settings.mixedPort > 65535
          }
          onClick={() =>
            void perform(
              () => invoke("save_settings", { settings }),
              "设置已保存",
            )
          }
        >
          保存
        </button>
      </div>
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
