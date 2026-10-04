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
  FolderOpen,
  Gauge,
  Globe2,
  Layers3,
  Link2,
  LoaderCircle,
  Network,
  Pause,
  Play,
  Plus,
  Power,
  RefreshCw,
  Search,
  Settings2,
  ShieldCheck,
  Terminal,
  Trash2,
  Undo2,
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
  type Proxy,
  type Settings,
  type Snapshot,
  type Traffic,
} from "./types";

type Page =
  | "overview"
  | "proxies"
  | "profiles"
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
      filters: [{ name: "YAML 配置", extensions: ["yaml", "yml"] }],
    });
    if (typeof path === "string")
      showImportResult(await invoke<ImportResult>("import_profile", { path }));
  };
  const addSubscription = () =>
    setModal(
      <SubscriptionForm
        onClose={() => setModal(null)}
        onSubmit={async (name, url) => {
          const ok = await perform(async () => {
            showImportResult(
              await invoke<ImportResult>("add_subscription", { name, url }),
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
                仅支持 VLESS 节点，导入时会跳过不兼容的项，不会改动原文件。
              </p>
            </>
          )}
          {page === "proxies" && (
            <Proxies running={running} busy={disabled} perform={perform} />
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
function Modal({
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
  useEffect(() => {
    const previous = document.activeElement as HTMLElement;
    ref.current?.focus();
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
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
  }, [onClose]);
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
function SubscriptionForm({
  onClose,
  onSubmit,
}: {
  onClose: () => void;
  onSubmit: (name: string, url: string) => Promise<boolean>;
}) {
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [saving, setSaving] = useState(false);
  const [failed, setFailed] = useState(false);
  return (
    <Modal title="添加订阅" onClose={onClose}>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          setSaving(true);
          void onSubmit(name, url)
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
        <p className="small muted">
          仅支持 HTTPS。链接通常含访问令牌，请勿外传。
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
  const refresh = useCallback(async () => {
    const data = await invoke<{ proxies: Record<string, Proxy> }>("proxies");
    setNodes(data.proxies);
  }, []);
  useEffect(() => {
    if (running) void refresh().catch(() => {});
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
                        <small>{nodes[name]?.type ?? "—"}</small>
                      </span>
                      {group.now === name && (
                        <Check size={16} className="accent" />
                      )}
                    </button>
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
                  </div>
                );
              })}
          </div>
        </section>
      ))}
    </>
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
function LogPage({ logs, perform }: { logs: Log[]; perform: Perform }) {
  const [level, setLevel] = useState("all");
  const [paused, setPaused] = useState(false);
  const [frozen, setFrozen] = useState<Log[]>([]);
  const [query, setQuery] = useState("");
  const visible = (paused ? frozen : logs).filter(
    (log) =>
      (level === "all" || log.type === level) &&
      log.payload.toLowerCase().includes(query.toLowerCase()),
  );
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
        if (local[key] === previous[key])
          (merged as Record<keyof Settings, unknown>)[key] = next[key];
      return merged;
    });
  }, [persistedSettings]);
  const update = <K extends keyof Settings>(key: K, value: Settings[K]) =>
    setSettings((s) => ({ ...s, [key]: value }));
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
