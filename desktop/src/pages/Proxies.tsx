import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  ArrowRight,
  Check,
  Globe2,
  Info,
  Layers3,
  LoaderCircle,
  Ban,
  Search,
  ChevronDown,
  Zap,
} from "lucide-react";
import { locale, t } from "../i18n";
import {
  type Mode,
  type Proxy,
  type NodeStatus,
  nodeSummary,
  peerPathText,
  tailscaleStateText,
} from "../types";
import { usePageVisible } from "../visibility";
import { Empty, Modal, type Perform } from "../components/common";

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

export function Proxies({
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
  const visible = usePageVisible();
  useEffect(() => {
    if (!running || !visible) return;
    void refresh().catch(() => {});
    const timer = window.setInterval(
      () => void refresh().catch(() => {}),
      3000,
    );
    return () => window.clearInterval(timer);
  }, [running, visible, refresh]);
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
