import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  Check,
  CircleAlert,
  Download,
  Gauge,
  Globe2,
  Layers3,
  LoaderCircle,
  Network,
  ScanSearch,
  Settings2,
  Terminal,
  ListFilter,
  X,
} from "lucide-react";
import { RequestsPage } from "./pages/Requests";
import { useUpdates } from "./Updates";
import { resolveLanguage, setLanguage, t } from "./i18n";
import { ConnectionPage } from "./pages/Connections";
import { LogPage } from "./pages/Logs";
import { OverviewPage } from "./pages/Overview";
import { ProfilesPage } from "./pages/Profiles";
import { Proxies } from "./pages/Proxies";
import { RulesPage } from "./pages/Rules";
import { SettingsPage } from "./pages/Settings";
import {
  initial,
  statusText,
  type Log,
  type Snapshot,
  type Traffic,
} from "./types";
import { pageVisible, usePageVisible } from "./visibility";
import brandIcon from "../src-tauri/icons/clyntis-v3/brand-128.png";

type Page =
  | "overview"
  | "proxies"
  | "profiles"
  | "rules"
  | "connections"
  | "requests"
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
    id: "requests",
    get label() {
      return t("抓包");
    },
    icon: ScanSearch,
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
  const updates = useUpdates();
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
  // Ticks and log lines that arrive while the page is hidden are kept here
  // and applied when it is shown, instead of re-rendering every second.
  const hidden = useRef<{ traffic: Traffic[]; logs: Log[] }>({
    traffic: [],
    logs: [],
  });
  const visible = usePageVisible();
  useEffect(() => {
    if (!visible) return;
    const { traffic, logs } = hidden.current;
    hidden.current = { traffic: [], logs: [] };
    if (traffic.length)
      setTraffic((values) => [...values, ...traffic].slice(-60));
    if (logs.length) setLogs((values) => [...values, ...logs].slice(-2000));
  }, [visible]);
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
        register<Traffic>("traffic", (tick) => {
          if (pageVisible())
            setTraffic((values) => [...values.slice(-59), tick]);
          else {
            const held = hidden.current;
            held.traffic = [...held.traffic.slice(-59), tick];
          }
        }),
        register<Log>("log", (entry) => {
          if (pageVisible())
            setLogs((values) => [...values.slice(-1999), entry]);
          else {
            const held = hidden.current;
            held.logs = [...held.logs.slice(-1999), entry];
          }
        }),
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
    if (state.status === "stopped" || state.status === "failed") {
      setTraffic([]);
      hidden.current.traffic = [];
    }
  }, [state.status]);
  const running = state.status === "running";
  const transitioning =
    state.serviceStatus === "updating" ||
    ["starting", "stopping", "recovering"].includes(state.status);
  const disabled = busy || transitioning || !loaded;
  const selected = state.profiles.find((p) => p.id === state.selected);
  const currentPage = pages.find((p) => p.id === page)!;
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
          {page !== "settings" &&
            ["available", "ready"].includes(updates.state?.phase ?? "") && (
              <div className="alert info" role="status">
                <Download size={16} />
                <span>
                  {t("发现客户端新版本 {version}", {
                    version: updates.state?.version ?? "",
                  })}
                </span>
                <button
                  className="button secondary compact"
                  onClick={() => setPage("settings")}
                >
                  {t("查看更新")}
                </button>
              </div>
            )}
          {page === "overview" && (
            <OverviewPage
              state={state}
              traffic={traffic}
              selected={selected}
              running={running}
              transitioning={transitioning}
              disabled={disabled}
              perform={perform}
              onAddProfile={() => setPage("profiles")}
            />
          )}
          {page === "profiles" && (
            <ProfilesPage
              state={state}
              disabled={disabled}
              perform={perform}
              refresh={refresh}
              setModal={setModal}
              setNotice={setNotice}
            />
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
          {page === "requests" && (
            <RequestsPage
              running={running}
              settings={state.settings}
              perform={perform}
              confirm={setModal}
            />
          )}
          {page === "logs" && <LogPage logs={logs} perform={perform} />}
          {page === "settings" && (
            <SettingsPage
              updates={updates}
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
