import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Search, X } from "lucide-react";
import { Modal, type Perform } from "../components/common";
import { locale, t } from "../i18n";
import {
  bytes,
  type ConnectionTraffic,
  type HostTraffic,
  type TrafficDetails,
} from "../types";
import { usePageVisible } from "../visibility";

type Tab = "hosts" | "connections";
type StatusFilter = "all" | "active" | "closed";

function normalizeHost(host: string): string {
  return host.replace(/\.+$/, "").toLowerCase();
}

function sameHost(a: string | null, b: string | null): boolean {
  return (
    a === b || (a !== null && b !== null && normalizeHost(a) === normalizeHost(b))
  );
}

function formatShare(part: number, total: number): string {
  if (total <= 0 || part <= 0) return "0%";
  const pct = (part / total) * 100;
  return pct < 0.1 ? "<0.1%" : `${pct.toFixed(1)}%`;
}

function shareWidth(part: number, total: number): number {
  if (total <= 0 || part <= 0) return 0;
  return Math.max(2, Math.min(100, (part / total) * 100));
}

function matchesHost(item: HostTraffic, query: string): boolean {
  if (!query) return true;
  const hay = `${item.host} ${item.rule} ${item.chains.join(" ")}`.toLowerCase();
  return hay.includes(query);
}

function matchesConnection(
  item: ConnectionTraffic,
  selectedHost: string | null,
  statusFilter: StatusFilter,
  query: string,
): boolean {
  if (selectedHost && normalizeHost(item.host) !== normalizeHost(selectedHost)) {
    return false;
  }
  if (statusFilter === "active" && !item.active) return false;
  if (statusFilter === "closed" && item.active) return false;
  if (!query) return true;
  const hay =
    `${item.host}:${item.port} ${item.network} ${item.rule} ${item.chains.join(" ")}`.toLowerCase();
  return hay.includes(query);
}

export function TrafficDetailsModal({
  running,
  perform,
  onClose,
}: {
  running: boolean;
  perform: Perform;
  onClose: () => void;
}) {
  const [data, setData] = useState<TrafficDetails | null>(null);
  const [failed, setFailed] = useState(false);
  const [tab, setTab] = useState<Tab>("hosts");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const visible = usePageVisible();
  const requestSeq = useRef(0);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      requestSeq.current += 1;
    };
  }, []);

  const activeHost = tab === "connections" ? selectedHost : null;
  const activeHostRef = useRef<string | null>(activeHost);
  activeHostRef.current = activeHost;

  const refresh = useCallback(async (host: string | null) => {
    const seq = ++requestSeq.current;
    try {
      const next = await invoke<TrafficDetails>(
        "traffic_details",
        host ? { host } : { host: null },
      );
      if (
        !mountedRef.current ||
        seq !== requestSeq.current ||
        !sameHost(host, activeHostRef.current)
      ) {
        return;
      }
      setData(next);
      setFailed(false);
    } catch {
      if (
        !mountedRef.current ||
        seq !== requestSeq.current ||
        !sameHost(host, activeHostRef.current)
      ) {
        return;
      }
      setFailed(true);
    }
  }, []);

  useEffect(() => {
    if (!running || !visible) return;
    let alive = true;
    let timer: number | undefined;
    const loop = async () => {
      await refresh(activeHost);
      if (alive) {
        timer = window.setTimeout(() => void loop(), 2000);
      }
    };
    void loop();
    return () => {
      alive = false;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [running, visible, activeHost, refresh]);

  const scopeReady =
    Boolean(data) &&
    (activeHost
      ? normalizeHost(data?.connectionHost ?? "") === normalizeHost(activeHost)
      : !data?.connectionHost);

  const trimmedQuery = query.trim().toLowerCase();
  const totalBytes = data ? data.uploadTotal + data.downloadTotal : 0;

  const hosts = useMemo(
    () => (data?.hosts ?? []).filter((item) => matchesHost(item, trimmedQuery)),
    [data, trimmedQuery],
  );
  const connections = useMemo(() => {
    if (!scopeReady || !data) return [];
    return data.connections.filter((item) =>
      matchesConnection(item, selectedHost, statusFilter, trimmedQuery),
    );
  }, [scopeReady, data, selectedHost, statusFilter, trimmedQuery]);

  const scopeNote = useMemo(() => {
    if (!scopeReady || !data) return "";
    const returnedActive = data.connections.filter((c) => c.active).length;
    const returnedClosed = data.connections.filter((c) => !c.active).length;
    const matchingActive = data.matchingActiveConnections ?? returnedActive;
    const matchingClosed = data.matchingClosedConnections ?? returnedClosed;
    const parts: string[] = [];
    if (matchingActive > returnedActive) {
      parts.push(
        t("活跃连接按流量显示前 {shown} / {total} 条", {
          shown: returnedActive,
          total: matchingActive,
        }),
      );
    }
    if (matchingClosed > returnedClosed) {
      parts.push(
        t("已结束连接仅保留高流量记录，显示 {shown} / {total} 条", {
          shown: returnedClosed,
          total: matchingClosed,
        }),
      );
    }
    return parts.join(" · ");
  }, [scopeReady, data]);

  const otherTotal = data ? data.otherUpload + data.otherDownload : 0;

  return (
    <Modal title={t("流量详情")} onClose={onClose} wide>
      <div className="traffic-details-modal">
        {data && (
          <>
            <div className="traffic-summary">
              <div>
                <strong>{bytes(totalBytes)}</strong>
                <small>{t("总流量")}</small>
              </div>
              <div>
                <strong>{bytes(data.downloadTotal)}</strong>
                <small>{t("下载")}</small>
              </div>
              <div>
                <strong>{bytes(data.uploadTotal)}</strong>
                <small>{t("上传")}</small>
              </div>
              <div>
                <strong>
                  {data.activeConnections} / {data.totalConnections}
                </strong>
                <small>
                  {t("活跃 {active} / 共 {total}", {
                    active: data.activeConnections,
                    total: data.totalConnections,
                  })}
                </small>
              </div>
            </div>
            <p className="muted small">
              {data.hostsEvicted
                ? t(
                    "自 {since} 起，当前保留 {hosts} 个主要目标（其余归入「其他目标」）",
                    {
                      since: new Date(data.since * 1000).toLocaleString(
                        locale(),
                      ),
                      hosts: data.totalHosts,
                    },
                  )
                : t("自 {since} 起，共统计 {hosts} 个目标", {
                    since: new Date(data.since * 1000).toLocaleString(locale()),
                    hosts: data.totalHosts,
                  })}
            </p>
          </>
        )}

        <div className="toolbar traffic-toolbar">
          <div className="traffic-filters">
            <div className="segmented" role="group" aria-label={t("流量详情")}>
              <button
                type="button"
                aria-pressed={tab === "hosts"}
                className={tab === "hosts" ? "selected" : ""}
                onClick={() => setTab("hosts")}
              >
                {t("按目标")}
              </button>
              <button
                type="button"
                aria-pressed={tab === "connections"}
                className={tab === "connections" ? "selected" : ""}
                onClick={() => setTab("connections")}
              >
                {t("按连接")}
              </button>
            </div>
            {tab === "connections" && (
              <div className="segmented" role="group" aria-label={t("状态")}>
                {(
                  [
                    ["all", t("全部")],
                    ["active", t("活跃")],
                    ["closed", t("已结束")],
                  ] as [StatusFilter, string][]
                ).map(([id, label]) => (
                  <button
                    key={id}
                    type="button"
                    aria-pressed={statusFilter === id}
                    className={statusFilter === id ? "selected" : ""}
                    onClick={() => setStatusFilter(id)}
                  >
                    {label}
                  </button>
                ))}
              </div>
            )}
          </div>
          <label className="search">
            <Search size={16} />
            <input
              placeholder={t("搜索目标、规则或代理")}
              aria-label={t("搜索流量记录")}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </label>
        </div>

        {tab === "connections" && selectedHost && (
          <div className="traffic-filter-chip">
            <span>{t("目标：{host}", { host: selectedHost })}</span>
            <button
              type="button"
              className="icon-button"
              aria-label={t("清除目标筛选")}
              onClick={() => setSelectedHost(null)}
            >
              <X size={14} />
            </button>
          </div>
        )}

        {failed && (
          <p className="inline-error" role="alert">
            {t("刷新失败，正在重试。")}
          </p>
        )}

        {!data ? (
          <div className="table-empty">{t("正在读取流量详情…")}</div>
        ) : tab === "hosts" ? (
          <div className="table-wrap traffic-table-wrap">
            <table className="traffic-table">
              <thead>
                <tr>
                  <th>{t("目标")}</th>
                  <th>{t("规则 / 代理")}</th>
                  <th className="num">{t("连接")}</th>
                  <th className="num">{t("下载")}</th>
                  <th className="num">{t("上传")}</th>
                  <th className="num">{t("总计")}</th>
                </tr>
              </thead>
              <tbody>
                {hosts.map((item) => {
                  const itemTotal = item.download + item.upload;
                  const openHostConnections = () => {
                    setSelectedHost(item.host);
                    setTab("connections");
                  };
                  return (
                    <tr
                      key={item.host}
                      className="traffic-host-row"
                      tabIndex={0}
                      onClick={openHostConnections}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          openHostConnections();
                        }
                      }}
                    >
                      <td>
                        <strong>{item.host}</strong>
                        <div className="traffic-bar" aria-hidden="true">
                          <div
                            className="traffic-bar-fill"
                            style={{
                              width: `${shareWidth(itemTotal, totalBytes)}%`,
                            }}
                          />
                        </div>
                      </td>
                      <td>
                        <span className="muted">
                          {item.rule ? `${item.rule} → ` : ""}
                          {item.chains.join(" → ")}
                        </span>
                      </td>
                      <td className="num">
                        {item.activeConnections > 0
                          ? `${item.activeConnections} / ${item.totalConnections}`
                          : item.totalConnections}
                      </td>
                      <td className="num">{bytes(item.download)}</td>
                      <td className="num">{bytes(item.upload)}</td>
                      <td className="num">
                        <strong>{bytes(itemTotal)}</strong>
                        <span className="muted traffic-share">
                          {formatShare(itemTotal, totalBytes)}
                        </span>
                      </td>
                    </tr>
                  );
                })}
                {!trimmedQuery && otherTotal > 0 && (
                  <tr className="traffic-other-row muted">
                    <td>{t("其他目标")}</td>
                    <td>—</td>
                    <td className="num">{data.otherConnections}</td>
                    <td className="num">{bytes(data.otherDownload)}</td>
                    <td className="num">{bytes(data.otherUpload)}</td>
                    <td className="num">
                      {bytes(otherTotal)}
                      <span className="traffic-share">
                        {formatShare(otherTotal, totalBytes)}
                      </span>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
            {!hosts.length && (!otherTotal || Boolean(trimmedQuery)) && (
              <div className="table-empty">
                {data.hosts.length ? t("无匹配结果") : t("暂无流量记录")}
              </div>
            )}
          </div>
        ) : !scopeReady ? (
          <div className="table-empty">{t("正在读取流量详情…")}</div>
        ) : (
          <>
            <div className="table-wrap traffic-table-wrap">
              <table className="connection-table traffic-table">
                <thead>
                  <tr>
                    <th>{t("目标地址")}</th>
                    <th>{t("协议 / 代理链")}</th>
                    <th>{t("状态")}</th>
                    <th className="num">{t("下载")}</th>
                    <th className="num">{t("上传")}</th>
                    <th className="num">{t("总计")}</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {connections.map((item) => {
                    const itemTotal = item.download + item.upload;
                    return (
                      <tr key={item.id}>
                        <td>
                          <strong>{item.host}</strong>
                          <span className="muted">:{item.port}</span>
                        </td>
                        <td>
                          <span className="route-line" title={item.rule}>
                            <span className="tiny-tag">
                              {item.network.toUpperCase()}
                            </span>
                            <span className="muted">
                              {item.chains.join(" → ")}
                            </span>
                            {item.rule && (
                              <span className="muted">· {item.rule}</span>
                            )}
                          </span>
                        </td>
                        <td>
                          <span
                            className={`traffic-status-tag ${item.active ? "active" : ""}`}
                          >
                            {item.active ? t("活跃") : t("已结束")}
                          </span>
                        </td>
                        <td className="num">{bytes(item.download)}</td>
                        <td className="num">{bytes(item.upload)}</td>
                        <td className="num">
                          <strong>{bytes(itemTotal)}</strong>
                        </td>
                        <td>
                          {item.active && (
                            <button
                              type="button"
                              className="icon-button"
                              aria-label={t("关闭 {host} 连接", {
                                host: item.host,
                              })}
                              onClick={() =>
                                void perform(async () => {
                                  requestSeq.current += 1;
                                  await invoke("close_connection", {
                                    id: item.id,
                                  });
                                  if (mountedRef.current) {
                                    await refresh(activeHostRef.current);
                                  }
                                })
                              }
                            >
                              <X size={15} />
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {!connections.length && (
                <div className="table-empty">
                  {data.connections.length ? t("无匹配结果") : t("暂无流量记录")}
                </div>
              )}
            </div>
            {scopeNote && (
              <p className="small muted traffic-scope-note">{scopeNote}</p>
            )}
          </>
        )}
      </div>
    </Modal>
  );
}
