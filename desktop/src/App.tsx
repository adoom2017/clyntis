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
import {
  Activity,
  ArrowDown,
  ArrowUp,
  ArrowUpRight,
  Check,
  ChevronRight,
  CircleHelp,
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
  subtitle: string;
}[] = [
  {
    id: "overview",
    label: "概览",
    icon: Gauge,
    subtitle: "你的网络，一目了然。",
  },
  {
    id: "proxies",
    label: "代理节点",
    icon: Globe2,
    subtitle: "选择适合你的连接线路。",
  },
  {
    id: "profiles",
    label: "配置管理",
    icon: Layers3,
    subtitle: "管理配置文件与订阅更新。",
  },
  {
    id: "connections",
    label: "网络连接",
    icon: Network,
    subtitle: "查看流经 Clyntis 的每一次连接。",
  },
  {
    id: "logs",
    label: "运行日志",
    icon: Terminal,
    subtitle: "查看内核运行状态，定位连接问题。",
  },
  {
    id: "settings",
    label: "设置",
    icon: Settings2,
    subtitle: "让 Clyntis 按照你的习惯工作。",
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
      if (alive)
        setError("无法连接桌面宿主。请从 Clyntis 桌面应用打开此界面。");
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
  const transitioning = ["starting", "stopping", "recovering"].includes(
    state.status,
  );
  const disabled = busy || transitioning || !loaded;
  const selected = state.profiles.find((p) => p.id === state.selected);
  const currentPage = pages.find((p) => p.id === page)!;
  const importFile = async () => {
    const path = await open({
      multiple: false,
      filters: [{ name: "YAML 配置", extensions: ["yaml", "yml"] }],
    });
    if (typeof path === "string") await invoke("import_profile", { path });
  };
  const addSubscription = () =>
    setModal(
      <SubscriptionForm
        onClose={() => setModal(null)}
        onSubmit={async (name, url) => {
          const ok = await perform(
            () => invoke("add_subscription", { name, url }),
            "订阅已添加",
          );
          if (ok) setModal(null);
          return ok;
        }}
      />,
    );
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-icon">c</span>
          <span>
            Clyntis<span className="brand-caption">DESKTOP</span>
          </span>
        </div>
        <div className="nav-label">工作空间</div>
        <nav aria-label="主导航">
          {pages.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              className={`nav-item ${page === id ? "active" : ""}`}
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
        <div className="sidebar-bottom">
          <div className="local-label">
            <span className={`status-dot ${running ? "online" : ""}`} />
            本地内核 <span>{statusText[state.status]}</span>
          </div>
          <div className="version">
            Clyntis <span>v0.1.0</span>
          </div>
        </div>
      </aside>
      <main>
        <header className="topbar">
          <span>
            <span className="muted">工作空间</span>
            <ChevronRight size={14} />
            {currentPage.label}
          </span>
          <div className="topbar-right">
            <span className="local-badge">
              <ShieldCheck size={13} />
              本地运行
            </span>
            <span className="avatar">C</span>
          </div>
        </header>
        <div className="content">
          <div className="page-heading">
            <div>
              <h1>{currentPage.label}</h1>
              <p>{currentPage.subtitle}</p>
            </div>
            <span className={`status-pill ${running ? "connected" : ""}`}>
              <span className={`status-dot ${running ? "online" : ""}`} />
              {statusText[state.status]}
            </span>
          </div>
          {(error || state.error) && (
            <div className="alert" role="alert">
              <CircleHelp size={18} />
              <span>{error || state.error}</span>
              {error && (
                <button
                  className="icon-button"
                  aria-label="关闭错误提示"
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
                className={`connect-card ${running ? "is-running" : ""}`}
              >
                <div className="connection-copy">
                  <span className="eyebrow">YOUR CONNECTION</span>
                  <h2>
                    {running
                      ? "连接已就绪"
                      : transitioning
                        ? statusText[state.status]
                        : "准备好，连接更自由"}
                  </h2>
                  <p>
                    {running
                      ? `正在使用「${selected?.name ?? "当前配置"}」，${captureText[state.settings.capture]}已启用。`
                      : selected
                        ? `已选择「${selected.name}」，随时可以开始连接。`
                        : "导入你的配置或添加订阅，开始使用 Clyntis。"}
                  </p>
                  <div className="connection-details">
                    <span>
                      <ShieldCheck size={14} />
                      {captureText[state.settings.capture]}
                    </span>
                    <span>
                      <Network size={14} />
                      127.0.0.1:{state.settings.mixedPort}
                    </span>
                  </div>
                </div>
                <div className="power-wrap">
                  <button
                    className={`power-button ${running ? "on" : ""}`}
                    disabled={disabled || !selected}
                    aria-label={running ? "停止连接" : "启动连接"}
                    onClick={() =>
                      void perform(() => invoke(running ? "stop" : "start"))
                    }
                  >
                    {transitioning ? (
                      <LoaderCircle size={31} className="spin" />
                    ) : (
                      <Power size={31} />
                    )}
                  </button>
                  <span>
                    {transitioning
                      ? "请稍候"
                      : running
                        ? "点击断开"
                        : "点击连接"}
                  </span>
                </div>
              </section>
              <div className="stat-grid">
                <Stat
                  label="实时下载"
                  value={`${bytes(traffic.at(-1)?.down ?? 0)}/s`}
                  icon={<ArrowDown size={19} />}
                  tone="green"
                />
                <Stat
                  label="实时上传"
                  value={`${bytes(traffic.at(-1)?.up ?? 0)}/s`}
                  icon={<ArrowUp size={19} />}
                  tone="blue"
                />
                <ConnectionStats running={running} />
              </div>
              <div className="overview-grid">
                <section className="panel traffic-panel">
                  <div className="panel-title">
                    <h3>流量趋势</h3>
                    <span className="muted small">最近 60 秒</span>
                  </div>
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
                  <TrafficChart values={traffic} />
                  <div className="chart-axis">
                    <span>60 秒前</span>
                    <span>30 秒前</span>
                    <span>现在</span>
                  </div>
                </section>
                <section className="panel routing-panel">
                  <div className="panel-title">
                    <h3>路由模式</h3>
                    <Network size={16} className="muted" />
                  </div>
                  <p className="small muted">决定流量如何通过代理</p>
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
                        <strong>{modeText[mode]}模式</strong>
                        <small>
                          {
                            {
                              rule: "根据配置规则智能分流",
                              global: "所有流量通过全局代理组",
                              direct: "所有流量直接连接",
                            }[mode]
                          }
                        </small>
                      </span>
                      {mode === "rule" && (
                        <span className="tiny-tag">推荐</span>
                      )}
                    </button>
                  ))}
                </section>
              </div>
              <section className="panel current-profile">
                <div className="profile-symbol">
                  <FileCode2 size={24} />
                </div>
                <div>
                  <h3>{selected?.name ?? "还没有配置"}</h3>
                  <p>
                    {selected
                      ? `${selected.source} · ${selected.pending ? "有更新待应用" : "当前使用的配置"}`
                      : "支持本地 YAML 配置和 HTTPS 订阅"}
                  </p>
                </div>
                <button
                  className="button secondary"
                  onClick={() => setPage("profiles")}
                >
                  {selected ? "管理配置" : "添加配置"}
                  <ArrowUpRight size={15} />
                </button>
              </section>
              <div className="capture-strip">
                <span className="muted">接管方式</span>
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
                  服务与权限 <ChevronRight size={14} />
                </button>
              </div>
            </>
          )}
          {page === "profiles" && (
            <>
              <div className="toolbar">
                <span className="muted small">
                  {state.profiles.length} 个配置 · 更新后手动应用
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
                  title="从一个配置开始"
                  text="导入 YAML 文件，或添加订阅 URL。配置会在使用前完成兼容性校验。"
                >
                  <button
                    className="button primary"
                    disabled={disabled}
                    onClick={() => void perform(importFile)}
                  >
                    <FolderOpen size={16} />
                    导入配置
                  </button>
                </Empty>
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
                          <p>{profile.source}</p>
                        </div>
                        {profile.id === state.selected && (
                          <span className="tiny-tag">使用中</span>
                        )}
                        {profile.pending && (
                          <span className="pending-tag">待应用</span>
                        )}
                      </div>
                      <div className="profile-meta">
                        上次检查：
                        {new Date(profile.lastChecked * 1000).toLocaleString(
                          "zh-CN",
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
                          使用此配置
                        </button>
                        {profile.source !== "本地文件" && (
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
                                "订阅检查完成",
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
                                      "校验通过，配置待应用",
                                    );
                                    if (ok) setModal(null);
                                    return ok;
                                  }}
                                />,
                              );
                            })
                          }
                        >
                          编辑 YAML
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
                                title="回滚配置？"
                                text="恢复上一个版本。若正在运行，内核将重启，现有连接会断开。"
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
                                text="此操作会删除该配置及其本地历史记录。"
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
              <div className="hint">
                <CircleHelp size={16} />
                <span>
                  支持 VLESS
                  配置。未实现的协议或未知字段会显示具体错误，不会自动修改你的节点与规则。
                </span>
              </div>
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
          <footer>
            <span>
              <ShieldCheck size={13} />
              配置与运行数据保存在本机
            </span>
            <span>Clyntis Desktop</span>
          </footer>
        </div>
      </main>
      {modal}
    </div>
  );
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
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
      <span className={`stat-icon ${tone}`}>{icon}</span>
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
        label="活跃连接"
        value={String(value.connections.length)}
        icon={<Network size={19} />}
      />
      <Stat
        label="累计流量"
        value={bytes(value.uploadTotal + value.downloadTotal)}
        icon={<Activity size={19} />}
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
            <stop offset="0%" stopColor="var(--accent)" stopOpacity=".2" />
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
            strokeDasharray="4 5"
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
          strokeWidth="2"
          vectorEffect="non-scaling-stroke"
        />
        <polyline
          points={line("up")}
          fill="none"
          stroke="var(--blue)"
          strokeWidth="2"
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
  text: string;
  children?: ReactNode;
}) {
  return (
    <section className="panel empty">
      <span className="empty-icon">{icon}</span>
      <h2>{title}</h2>
      <p>{text}</p>
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
          <button
            className="icon-button"
            aria-label="关闭对话框"
            onClick={onClose}
          >
            <X size={20} />
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
          仅支持 HTTPS YAML 订阅。订阅链接可能包含私密令牌，请勿分享。
        </p>
        {failed && (
          <p role="alert" className="inline-error">
            添加失败，请检查链接和配置兼容性。关闭此窗口可查看详细错误。
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
            下载并校验
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
        保存时校验配置；应用更新后生效。编辑器包含节点凭据。
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
          校验或保存失败，原配置未被替换。关闭此窗口可查看详细错误。
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
          {saving && <LoaderCircle className="spin" size={16} />}校验并保存
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
    setProbing((p) => [...p, name]);
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
  if (!running)
    return (
      <Empty
        icon={<Globe2 />}
        title="连接后查看代理节点"
        text="请先在概览页启动内核，然后选择线路或进行延迟测试。"
      />
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
            placeholder="搜索节点…"
          />
        </label>
        <button
          className="button secondary"
          disabled={busy || !!probing.length}
          onClick={() =>
            void perform(async () => {
              for (const node of Object.values(nodes).filter(
                (p) => p.type === "VLESS",
              ))
                await probe(node.name);
            })
          }
        >
          <Zap size={16} />
          全部测速
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
                ? "手动选择"
                : group.type === "URLTest"
                  ? "自动测速选择"
                  : "节点列表"}
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
                        <small>{nodes[name]?.type ?? "代理节点"}</small>
                      </span>
                      {group.now === name && (
                        <Check size={16} className="accent" />
                      )}
                    </button>
                    <button
                      className={`delay ${delay === null ? "unavailable" : ""}`}
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
      <Empty
        icon={<Network />}
        title="暂无网络连接"
        text="内核启动后，可以在这里查看和关闭活跃连接。"
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
            placeholder="搜索目标或代理链…"
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
          关闭全部连接
        </button>
      </div>
      {failed && (
        <p className="inline-error" role="alert">
          连接列表刷新失败，正在重试。
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
          <div className="table-empty">暂无匹配的活跃连接</div>
        )}
      </div>
      <p className="small muted">共 {items.length} 个连接 · 每 2 秒刷新</p>
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
            <option value="all">全部级别</option>
            {["debug", "info", "warning", "error"].map((v) => (
              <option key={v}>{v}</option>
            ))}
          </select>
          <label className="search">
            <Search size={16} />
            <input
              aria-label="搜索日志"
              placeholder="搜索日志…"
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
      <p className="small muted">
        保留最近 2,000 条日志。URL、UUID 与常见凭据字段会在显示及导出前隐藏。
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
  const persistedSettings = JSON.stringify(state.settings);
  useEffect(
    () => setSettings(JSON.parse(persistedSettings) as Settings),
    [persistedSettings],
  );
  const update = <K extends keyof Settings>(key: K, value: Settings[K]) =>
    setSettings((s) => ({ ...s, [key]: value }));
  const dirty = JSON.stringify(settings) !== JSON.stringify(state.settings);
  return (
    <>
      <section className="panel settings-section">
        <h3>连接与网络</h3>
        <Setting label="接管方式" text="切换正在运行的接管方式时，会重启内核。">
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
        <Setting label="本地代理端口" text="HTTP 与 SOCKS 共用一个端口。">
          <input
            type="number"
            min={1024}
            max={65535}
            value={settings.mixedPort}
            onChange={(e) => update("mixedPort", Number(e.target.value))}
          />
        </Setting>
        <Setting
          label="允许局域网访问"
          text="开启后，同一网络中的设备可以连接代理端口。"
        >
          <Toggle
            checked={settings.allowLan}
            onChange={(v) => update("allowLan", v)}
            label="允许局域网访问"
          />
        </Setting>
        <Setting
          label="TUN 自动 DNS"
          text="在 macOS 上临时接管物理网络服务的 DNS，退出时恢复。"
        >
          <Toggle
            checked={settings.autoDns}
            onChange={(v) => update("autoDns", v)}
            label="TUN 自动 DNS"
          />
        </Setting>
        <Setting label="物理网络接口" text="留空使用内核自动选择；例如 en0。">
          <input
            value={settings.tunInterface ?? ""}
            placeholder="自动选择"
            onChange={(e) => update("tunInterface", e.target.value || null)}
          />
        </Setting>
      </section>
      <section className="panel settings-section">
        <div className="panel-title">
          <h3>后台辅助服务</h3>
          <span className="tiny-tag">
            {{
              checking: "检查中",
              installed: "已安装",
              enabled: "已启用",
              requires_approval: "等待系统授权",
              not_installed: "未安装",
              not_registered: "未安装",
            }[state.serviceStatus] ?? state.serviceStatus}
          </span>
        </div>
        <p className="muted small">
          TUN 和 macOS
          系统代理需要辅助服务。首次安装由操作系统请求授权；界面始终以普通用户运行。
        </p>
        <div className="service-actions">
          <button
            className="button secondary"
            disabled={busy}
            onClick={() =>
              void perform(
                () => invoke("install_service"),
                "请按系统提示允许后台服务",
              )
            }
          >
            <ShieldCheck size={16} />
            安装 / 授权服务
          </button>
          <button
            className="text-button danger"
            disabled={busy}
            onClick={() =>
              confirm(
                <Confirm
                  title="卸载辅助服务？"
                  text="将先停止内核并恢复网络设置。以后启用 TUN 时需要重新安装。"
                  onClose={() => confirm(null)}
                  onConfirm={async () => {
                    confirm(null);
                    await perform(() => invoke("uninstall_service"));
                  }}
                />,
              )
            }
          >
            卸载服务
          </button>
        </div>
      </section>
      <section className="panel settings-section">
        <h3>偏好设置</h3>
        <Setting label="外观" text="选择浅色、深色或跟随系统。">
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
        <Setting label="登录时启动" text="登录系统后打开 Clyntis。">
          <Toggle
            checked={settings.launchAtLogin}
            onChange={(v) => update("launchAtLogin", v)}
            label="登录时启动"
          />
        </Setting>
        <Setting
          label="打开应用后自动连接"
          text="使用上次选择的配置和接管方式。"
        >
          <Toggle
            checked={settings.autoConnect}
            onChange={(v) => update("autoConnect", v)}
            label="打开应用后自动连接"
          />
        </Setting>
        <Setting
          label="订阅检查间隔"
          text="应用运行期间定时检查；0 表示仅手动更新。"
        >
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
        <span className="small muted">
          {dirty ? "有尚未保存的设置" : "设置已保存"} · 关闭窗口后继续在托盘运行
        </span>
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
          <Check size={16} />
          保存设置
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
  text: string;
  children: ReactNode;
}) {
  return (
    <div className="setting-row">
      <div>
        <strong>{label}</strong>
        <p>{text}</p>
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
